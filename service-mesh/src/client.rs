use anyhow::{bail, Context, Result};
use dstack_types::dstack_agent_address;
use heck::ToPascalCase;
use ra_tls::traits::CertExt as _;
use reqwest::redirect::Policy;
use reqwest::tls::TlsInfo;
use reqwest::Client;
use rocket::figment::providers::Serialized;
use rocket::figment::Figment;
use rocket::http::uri::fmt::Path;
use rocket::http::uri::Segments;
use rocket::http::Status;
use rocket::request::{self, FromRequest};
use rocket::response::{Responder, Response};
use rocket::tokio::io::AsyncRead;
use rocket::{get, post, routes, Data, Request, State};
use std::error::Error;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::io::AsyncReadExt;
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::config::TargetInfo;

pub struct ClientState {
    gateway_domain: String,
    http_client: Client,
}

pub struct ReqwestStreamReader {
    stream: Pin<
        Box<dyn futures_util::Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Send + 'static>,
    >,
    current_chunk: Option<bytes::Bytes>,
    chunk_pos: usize,
}

impl ReqwestStreamReader {
    fn new(response: reqwest::Response) -> Self {
        let stream = response.bytes_stream();
        Self {
            stream: Box::pin(stream),
            current_chunk: None,
            chunk_pos: 0,
        }
    }
}

impl AsyncRead for ReqwestStreamReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            // If we have a current chunk, try to read from it
            if let Some(chunk) = &self.current_chunk {
                if self.chunk_pos < chunk.len() {
                    let to_read = std::cmp::min(buf.remaining(), chunk.len() - self.chunk_pos);
                    let end_pos = self.chunk_pos + to_read;
                    buf.put_slice(&chunk[self.chunk_pos..end_pos]);
                    self.chunk_pos = end_pos;
                    return Poll::Ready(Ok(()));
                } else {
                    // Finished reading current chunk
                    self.current_chunk = None;
                    self.chunk_pos = 0;
                }
            }

            // Try to get next chunk
            match self.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    self.current_chunk = Some(chunk);
                    self.chunk_pos = 0;
                    // Continue loop to read from the new chunk
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)));
                }
                Poll::Ready(None) => {
                    // End of stream
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }
    }
}

pub enum ProxyResponse {
    Stream(StreamingProxyResponse),
    Json(serde_json::Value),
    Error(ErrorResponse),
}

pub struct ErrorResponse {
    status: Status,
    status_text: String,
    error_type: String,
    message: String,
    details: Option<String>,
}

pub struct StreamingProxyResponse {
    response: reqwest::Response,
}

impl<'r> Responder<'r, 'static> for ProxyResponse {
    fn respond_to(self, request: &'r rocket::Request<'_>) -> rocket::response::Result<'static> {
        match self {
            ProxyResponse::Stream(streaming) => streaming.respond_to(request),
            ProxyResponse::Json(json) => {
                let json_string = serde_json::to_string(&json).unwrap_or_default();
                Response::build()
                    .header(rocket::http::ContentType::JSON)
                    .sized_body(json_string.len(), std::io::Cursor::new(json_string))
                    .ok()
            }
            ProxyResponse::Error(error) => error.respond_to(request),
        }
    }
}

impl<'r> Responder<'r, 'static> for ErrorResponse {
    fn respond_to(self, _: &'r rocket::Request<'_>) -> rocket::response::Result<'static> {
        let error_json = serde_json::json!({
            "status": self.status.code,
            "status_text": self.status_text,
            "error": self.error_type,
            "message": self.message,
            "details": self.details,
        });
        let json_string = serde_json::to_string(&error_json).unwrap_or_default();

        Response::build()
            .status(self.status)
            .header(rocket::http::ContentType::JSON)
            .sized_body(json_string.len(), std::io::Cursor::new(json_string))
            .ok()
    }
}

impl<'r> Responder<'r, 'static> for StreamingProxyResponse {
    fn respond_to(self, _: &'r rocket::Request<'_>) -> rocket::response::Result<'static> {
        // Capture status code before moving the response
        let status_code = self.response.status();

        // Collect all headers before moving the response
        let headers: Vec<(String, String)> = self
            .response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|v| (name.to_string(), v.to_string()))
            })
            .collect();
        let reader = ReqwestStreamReader::new(self.response);

        let mut response_builder = Response::build();

        // Set the upstream status code
        response_builder.status(Status::from_code(status_code.as_u16()).unwrap_or(Status::Ok));

        // Add all headers from the upstream response
        for (name, value) in headers {
            response_builder.raw_header(name, value);
        }

        response_builder.streamed_body(reader).ok()
    }
}

/// Custom request guard for extracting request information we need
pub struct DstackRequest {
    pub target_app: Option<String>,
    pub target_port: Option<String>,
    pub target_instance: Option<String>,
    pub target_gateway: Option<String>,
    pub target_host: Option<String>,
    pub all_headers: Vec<(String, String)>,
    pub query_string: Option<String>,
    pub path: String,
    pub method: String,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for DstackRequest {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let headers = request.headers();
        let target_app = headers
            .get_one("x-dstack-target-app")
            .map(|s| s.to_string());
        let target_port = headers
            .get_one("x-dstack-target-port")
            .map(|s| s.to_string());
        let target_instance = headers
            .get_one("x-dstack-target-instance")
            .map(|s| s.to_string());
        let target_gateway = headers
            .get_one("x-dstack-target-gateway")
            .map(|s| s.to_string());
        let target_host = headers.get_one("host").map(|s| s.to_string());

        let all_headers = headers
            .iter()
            .map(|h| (h.name().to_string(), h.value().to_string()))
            .collect();

        let query_string = request.uri().query().map(|q| q.to_string());

        // Extract path from URI
        let path = request.uri().path().to_string();

        // Extract HTTP method
        let method = request.method().to_string();

        request::Outcome::Success(DstackRequest {
            target_app,
            target_port,
            target_instance,
            target_gateway,
            target_host,
            all_headers,
            query_string,
            path,
            method,
        })
    }
}

/// Run client proxy with configuration from main figment
pub async fn run_client_proxy(main_figment: &Figment, config: &Config) -> Result<()> {
    // Create mTLS-enabled HTTP client
    let http_client = create_mtls_client(config).context("Failed to create mTLS HTTP client")?;

    let state = ClientState {
        gateway_domain: config.dstack.gateway_domain.clone(),
        http_client,
    };

    info!("Client proxy starting with Figment configuration");

    // Create Rocket figment for client service using the client section
    let figment = Figment::new()
        .merge(rocket::Config::default())
        .merge(Serialized::defaults(
            main_figment
                .find_value("client")
                .context("client section not found")?,
        ));

    // Launch Rocket server
    let _rocket = rocket::custom(figment)
        .manage(state)
        .mount(
            "/",
            routes![
                proxy_get_handler,
                proxy_post_handler,
                proxy_put_handler,
                proxy_patch_handler,
                proxy_delete_handler,
                health_handler,
            ],
        )
        .launch()
        .await
        .map_err(|e| anyhow::anyhow!("Rocket launch error: {}", e))?;

    Ok(())
}

/// Handle GET requests
#[get("/<_path..>")]
async fn proxy_get_handler(
    _path: Segments<'_, Path>,
    request: DstackRequest,
    state: &State<ClientState>,
) -> Result<ProxyResponse, Status> {
    proxy_request(&request, state, None).await
}

/// Handle POST requests
#[post("/<_path..>", data = "<body>")]
async fn proxy_post_handler(
    _path: Segments<'_, Path>,
    request: DstackRequest,
    body: Data<'_>,
    state: &State<ClientState>,
) -> Result<ProxyResponse, Status> {
    proxy_request(&request, state, Some(body)).await
}

/// Handle PUT requests
#[rocket::put("/<_path..>", data = "<body>")]
async fn proxy_put_handler(
    _path: Segments<'_, Path>,
    request: DstackRequest,
    body: Data<'_>,
    state: &State<ClientState>,
) -> Result<ProxyResponse, Status> {
    proxy_request(&request, state, Some(body)).await
}

/// Handle PATCH requests
#[rocket::patch("/<_path..>", data = "<body>")]
async fn proxy_patch_handler(
    _path: Segments<'_, Path>,
    request: DstackRequest,
    body: Data<'_>,
    state: &State<ClientState>,
) -> Result<ProxyResponse, Status> {
    proxy_request(&request, state, Some(body)).await
}

/// Handle DELETE requests
#[rocket::delete("/<_path..>")]
async fn proxy_delete_handler(
    _path: Segments<'_, Path>,
    request: DstackRequest,
    state: &State<ClientState>,
) -> Result<ProxyResponse, Status> {
    proxy_request(&request, state, None).await
}

/// Health check endpoint
#[get("/health")]
fn health_handler() -> Status {
    Status::Ok
}

/// Proxy request to dstack.sock when no target headers are present
async fn proxy_to_dstack_sock(
    request: &DstackRequest,
    body: Option<Data<'_>>,
    state: &State<ClientState>,
) -> Result<ProxyResponse, Status> {
    let path = request.path.trim_start_matches('/');

    if path.trim_start_matches('/').eq_ignore_ascii_case("gateway") {
        let gateway_info = serde_json::json!({
            "gateway_domain": state.gateway_domain
        });
        return Ok(ProxyResponse::Json(gateway_info));
    }

    let path = {
        let segments: Vec<&str> = path.split('/').collect();
        if segments.is_empty() {
            path.to_string()
        } else {
            let mut result = segments[..segments.len() - 1].join("/");
            if !result.is_empty() {
                result.push('/');
            }
            result.push_str(&segments[segments.len() - 1].to_pascal_case());
            result
        }
    };

    let full_path = match &request.query_string {
        Some(query) => format!("{}?{}", path, query),
        None => path.to_string(),
    };
    let agent_address = dstack_agent_address();
    let agent_url;
    let agent_sock;

    if agent_address.starts_with("unix:") {
        agent_url = format!("http://localhost/{full_path}");
        agent_sock = Some(agent_address.trim_start_matches("unix:").to_string());
    } else {
        agent_url = agent_address;
        agent_sock = None;
    };

    let mut client_builder = Client::builder();

    if let Some(agent_sock) = agent_sock {
        client_builder = client_builder.unix_socket(agent_sock);
    }

    let client = client_builder
        .build()
        .map_err(|_| Status::InternalServerError)?;

    // Parse HTTP method
    let http_method = match reqwest::Method::from_bytes(request.method.as_bytes()) {
        Ok(m) => m,
        Err(_) => return Err(Status::MethodNotAllowed),
    };

    let mut request_builder = client.request(http_method, &agent_url);
    if let Some(body_data) = body {
        const MAX_BODY_SIZE: u64 = 1024 * 1024;
        let mut reader = body_data.open(rocket::data::ByteUnit::Byte(MAX_BODY_SIZE));
        let mut buffer = Vec::new();
        if reader.read_to_end(&mut buffer).await.is_ok() {
            request_builder = request_builder.body(buffer);
        } else {
            return Err(Status::BadRequest);
        }
    }
    match request_builder.send().await {
        Ok(response) => Ok(ProxyResponse::Stream(StreamingProxyResponse { response })),
        Err(e) => {
            tracing::error!("Request to dstack.sock failed: {}", e);
            Err(Status::BadGateway)
        }
    }
}

async fn proxy_request(
    request: &DstackRequest,
    state: &State<ClientState>,
    body: Option<Data<'_>>,
) -> Result<ProxyResponse, Status> {
    // Extract target info from headers
    let target = match extract_target_info(request) {
        Some(t) => t,
        None => {
            debug!("Missing x-dstack-target-app header, delegating to dstack.sock");
            return proxy_to_dstack_sock(request, body, state).await;
        }
    };

    // Validate connection target before proceeding
    validate_connection_target(&target)?;

    // Build target URL
    let url = {
        let path = request.path.trim_start_matches('/');
        let full_path = match &request.query_string {
            Some(query) => format!("{}?{}", path, query),
            None => path.to_string(),
        };

        // Priority 1: Use Host header if provided
        if let Some(host) = &request.target_host {
            debug!("Using Host header for target: {}", host);
            format!("https://{host}/{full_path}")
        } else {
            // Priority 2: Use custom gateway or default gateway
            let gateway_domain = request
                .target_gateway
                .as_deref()
                .unwrap_or(&state.gateway_domain)
                .trim_end_matches("/");

            if let Some(custom_gw) = &request.target_gateway {
                debug!(
                    "Using custom gateway '{}' (overriding default '{}')",
                    custom_gw, state.gateway_domain
                );
            }

            if gateway_domain.starts_with("fixed/") {
                let domain = gateway_domain.trim_start_matches("fixed/");
                format!("https://{domain}/{full_path}")
            } else {
                let id = if target.instance_id.is_empty() {
                    &target.app_id
                } else {
                    &target.instance_id
                };
                let port = &target.port;
                format!("https://{id}-{port}s.{gateway_domain}/{full_path}")
            }
        }
    };

    // Create HTTP client with TLS config
    // Note: For now using simple HTTP client, would need to configure mTLS properly
    let http_method = match reqwest::Method::from_bytes(request.method.as_bytes()) {
        Ok(m) => m,
        Err(_) => return Err(Status::MethodNotAllowed),
    };

    let mut request_builder = state.http_client.request(http_method, &url);

    // Handle body for methods that support it with streaming
    if let Some(body_data) = body {
        // Use a reasonable limit to prevent OOM (100MB)
        const MAX_BODY_SIZE: u64 = 100 * 1024 * 1024;
        let mut reader = body_data.open(rocket::data::ByteUnit::Byte(MAX_BODY_SIZE));

        // Read in chunks to avoid OOM
        let mut buffer = Vec::new();
        const CHUNK_SIZE: usize = 64 * 1024; // 64KB chunks
        let mut chunk = vec![0u8; CHUNK_SIZE];

        loop {
            match reader.read(&mut chunk).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    buffer.extend_from_slice(&chunk[..n]);
                    // Check if we're getting too large
                    if buffer.len() > MAX_BODY_SIZE as usize {
                        return Err(Status::PayloadTooLarge);
                    }
                }
                Err(_) => return Err(Status::BadRequest),
            }
        }

        request_builder = request_builder.body(buffer);
    }

    // Copy relevant headers (excluding routing headers)
    for (name, value) in &request.all_headers {
        if !name.starts_with("x-dstack-target-") {
            request_builder = request_builder.header(name, value);
        }
    }

    // Execute request
    match request_builder.send().await {
        Ok(response) => {
            let status = response.status();

            // Log successful connection with status code
            debug!(
                "Received response from app_id '{}' - status: {}, url: '{}'",
                target.app_id, status, url
            );

            // TODO: It should be verified before sending the request. But reqwest doesn't support it.
            if let Err(err) = verify_response_security(&response, &target)
                .context("Failed to verify response security")
            {
                warn!(
                    "Failed to verify response security for app_id '{}': {err:?}",
                    target.app_id
                );
                return Ok(ProxyResponse::Error(ErrorResponse {
                    status: Status::new(526),
                    status_text: "Invalid SSL Certificate".to_string(),
                    error_type: "SSL_VERIFICATION_FAILED".to_string(),
                    message: "Failed to verify peer certificate".to_string(),
                    details: Some(format!("{:#}", err)),
                }));
            }

            // Log if upstream returned an error status
            if status.is_client_error() || status.is_server_error() {
                warn!(
                    "Upstream returned error status - app_id: '{}', status: {}, url: '{}'",
                    target.app_id, status, url
                );
            }

            // Return the response directly for streaming - no buffering!
            Ok(ProxyResponse::Stream(StreamingProxyResponse { response }))
        }
        Err(e) => {
            // Collect all error messages in the chain
            let mut error_chain = Vec::new();
            let mut source = Some(&e as &dyn Error);
            while let Some(err) = source {
                error_chain.push(err.to_string());
                source = err.source();
                if error_chain.len() > 10 {
                    break; // Prevent infinite loops
                }
            }

            // Classify error type
            let (error_type, user_message, status_code, status_text) = if e.is_timeout() {
                (
                    "TIMEOUT",
                    "Request timeout",
                    Status::GatewayTimeout,
                    "Gateway Timeout".to_string(),
                )
            } else if e.is_connect() {
                // Check if it's a TLS/certificate error
                let error_str = error_chain.join(" | ");
                if error_str.contains("certificate")
                    || error_str.contains("SSL")
                    || error_str.contains("TLS")
                {
                    if error_str.contains("UnknownIssuer") {
                        (
                            "SSL_UNKNOWN_ISSUER",
                            "SSL certificate verification failed: Unknown certificate issuer",
                            Status::new(526),
                            "Invalid SSL Certificate".to_string(),
                        )
                    } else if error_str.contains("CertExpired") || error_str.contains("expired") {
                        (
                            "SSL_CERT_EXPIRED",
                            "SSL certificate has expired",
                            Status::new(526),
                            "Invalid SSL Certificate".to_string(),
                        )
                    } else {
                        (
                            "SSL_HANDSHAKE_FAILED",
                            "SSL/TLS handshake failed",
                            Status::new(525),
                            "SSL Handshake Failed".to_string(),
                        )
                    }
                } else {
                    (
                        "CONNECTION_FAILED",
                        "Failed to connect to upstream server",
                        Status::BadGateway,
                        "Bad Gateway".to_string(),
                    )
                }
            } else if e.is_request() {
                (
                    "REQUEST_ERROR",
                    "Request construction failed",
                    Status::BadRequest,
                    "Bad Request".to_string(),
                )
            } else if let Some(status) = e.status() {
                let rocket_status =
                    Status::from_code(status.as_u16()).unwrap_or(Status::BadGateway);
                let status_text = rocket_status.reason().unwrap_or("Unknown").to_string();
                (
                    "HTTP_ERROR",
                    "Upstream HTTP error",
                    rocket_status,
                    status_text,
                )
            } else {
                (
                    "UNKNOWN",
                    "Unknown error occurred",
                    Status::BadGateway,
                    "Bad Gateway".to_string(),
                )
            };

            // Find the root cause (last error in chain)
            let root_cause = error_chain.last().unwrap_or(&error_chain[0]);

            // Log error with clean format
            tracing::error!(
                "mTLS request failed [{}]: {} (app_id: '{}', url: '{}')",
                error_type,
                root_cause,
                target.app_id,
                url
            );

            // Additional debug info with full chain
            if error_chain.len() > 1 {
                tracing::debug!("Error chain: {}", error_chain.join(" → "));
            }
            tracing::debug!("Full error details: {:#?}", e);

            Ok(ProxyResponse::Error(ErrorResponse {
                status: status_code,
                status_text,
                error_type: error_type.to_string(),
                message: user_message.to_string(),
                details: Some(error_chain.join(" → ")),
            }))
        }
    }
}

fn extract_target_info(request: &DstackRequest) -> Option<TargetInfo> {
    // Extract app_id (required)
    let app_id = request.target_app.as_ref()?.clone();

    // Extract port (optional, default 443)
    let port = request
        .target_port
        .as_ref()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8089);

    // Extract instance (optional)
    let instance = request.target_instance.clone().unwrap_or_default();

    Some(TargetInfo {
        app_id,
        instance_id: instance,
        port,
    })
}

/// Create an HTTP client configured with mTLS using certificates from files
fn create_mtls_client(config: &Config) -> Result<Client> {
    use fs_err as fs;

    info!(
        "Loading mTLS certificates - key: '{}', cert: '{}', ca: '{}'",
        config.tls.key_file, config.tls.cert_file, config.tls.ca_file
    );

    let key_pem = fs::read_to_string(&config.tls.key_file)
        .with_context(|| format!("Failed to read key file: {}", config.tls.key_file))?;
    let cert_pem = fs::read_to_string(&config.tls.cert_file)
        .with_context(|| format!("Failed to read cert file: {}", config.tls.cert_file))?;
    let ca_pem = fs::read_to_string(&config.tls.ca_file)
        .with_context(|| format!("Failed to read CA file: {}", config.tls.ca_file))?;

    // Parse and log client certificate info
    for pem in x509_parser::pem::Pem::iter_from_buffer(cert_pem.as_bytes()).flatten() {
        if let Ok((_, client_cert)) = x509_parser::parse_x509_certificate(&pem.contents) {
            let subject = client_cert.subject().to_string();
            let issuer = client_cert.issuer().to_string();
            info!(
                "Client certificate loaded - subject: '{}', issuer: '{}'",
                subject, issuer
            );
            break;
        }
    }

    // Parse and log CA certificate info
    let ca_certs: Vec<_> = x509_parser::pem::Pem::iter_from_buffer(ca_pem.as_bytes())
        .filter_map(|p| p.ok())
        .collect();
    info!("Loaded {} CA certificate(s)", ca_certs.len());

    for (i, ca_cert_pem) in ca_certs.iter().enumerate() {
        if let Ok((_, ca_cert)) = x509_parser::parse_x509_certificate(&ca_cert_pem.contents) {
            let subject = ca_cert.subject().to_string();
            let issuer = ca_cert.issuer().to_string();
            let not_before = ca_cert.validity().not_before;
            let not_after = ca_cert.validity().not_after;
            info!(
                "CA certificate [{}] - subject: '{}', issuer: '{}', valid: {} to {}",
                i + 1,
                subject,
                issuer,
                not_before,
                not_after
            );
        }
    }

    // Try using the full certificate chain instead of just the leaf certificate
    let identity_pem = format!("{}\n{}", cert_pem, key_pem);
    let identity = reqwest::Identity::from_pem(identity_pem.as_bytes())?;
    let ca = reqwest::Certificate::from_pem(ca_pem.as_bytes())?;

    info!("Building mTLS HTTP client with custom CA trust");

    let client = Client::builder()
        .use_rustls_tls() // Force rustls backend
        .identity(identity)
        .tls_info(true)
        .https_only(true)
        .danger_accept_invalid_hostnames(true)
        .danger_accept_invalid_certs(false)
        .tls_built_in_root_certs(false)
        .tls_built_in_webpki_certs(false)
        .add_root_certificate(ca)
        .redirect(Policy::none())
        .hickory_dns(true)
        .build()
        .context("Failed to build mTLS HTTP client")?;

    info!("mTLS HTTP client created successfully");

    Ok(client)
}

/// Validate that we should connect to the specified target
fn validate_connection_target(target: &TargetInfo) -> Result<(), Status> {
    // Ensure app_id is present and valid
    if target.app_id.is_empty() {
        tracing::error!("Target app_id cannot be empty");
        return Err(Status::BadRequest);
    }

    // Validate app_id format (should be hex string for dstack)
    if !target.app_id.chars().all(|c| c.is_ascii_hexdigit()) {
        warn!(
            "Target app_id '{}' is not in expected hex format",
            target.app_id
        );
    }
    // Log connection attempt for audit trail
    info!(
        "Validated mTLS connection target - app_id: {}, port: {}, instance: '{}'",
        target.app_id, target.port, target.instance_id
    );
    Ok(())
}

/// Verify response security and log connection info
fn verify_response_security(response: &reqwest::Response, target: &TargetInfo) -> Result<()> {
    let Some(tls_info) = response.extensions().get::<TlsInfo>() else {
        bail!("No TLS info in response");
    };
    let Some(cert) = tls_info.peer_certificate() else {
        bail!("No peer certificate in response");
    };

    let (_, parsed_cert) =
        x509_parser::parse_x509_certificate(cert).context("Failed to parse certificate")?;

    // Extract certificate information for logging
    let subject = parsed_cert.subject().to_string();
    let issuer = parsed_cert.issuer().to_string();
    let not_before = parsed_cert.validity().not_before;
    let not_after = parsed_cert.validity().not_after;

    debug!(
        "Server certificate info - subject: '{}', issuer: '{}', valid: {} to {}",
        subject, issuer, not_before, not_after
    );

    let app_id = parsed_cert
        .get_app_id()
        .context("Failed to get app id")?
        .context("Missing app id in server certificate")?;
    let cert_app_id = hex::encode(app_id);

    debug!(
        "Certificate app_id verification - expected: '{}', got: '{}'",
        target.app_id, cert_app_id
    );

    if cert_app_id.to_lowercase() != target.app_id.to_lowercase() {
        bail!(
            "Server app_id mismatch: expected '{}', got '{}' (subject: '{}', issuer: '{}')",
            target.app_id,
            cert_app_id,
            subject,
            issuer
        );
    }

    // Log successful mTLS connection with verification details
    info!(
        "mTLS connection verified - app_id: {}, port: {}, status: {}, cert_subject: '{}'",
        target.app_id,
        target.port,
        response.status(),
        subject
    );

    Ok(())
}
