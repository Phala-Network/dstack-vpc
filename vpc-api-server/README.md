# VPC API Server

The VPC API Server acts as the central control plane for the VPC infrastructure. It serves two distinct user roles with different authentication mechanisms:

1. **VPC Nodes** - Register and manage their Headscale connections through dstack mesh
2. **VPC Administrators** - Manage the allowlist and monitor nodes using Ethereum wallet signatures

## Architecture Overview

| Role | Traffic Flow | TLS Handling | Authentication | Purpose |
|------|--------------|--------------|----------------|---------|
| **VPC Node** | `vpc-node → dstack gateway (TLS transparency) → nginx (mTLS) → dstack-mesh (auth) → vpc-api-server` | dstack gateway: TLS transparency<br>nginx: mTLS verification | Client certificate verification + `x-dstack-app-id` header (injected by dstack-mesh) + allowlist | Node registration, pre-auth key retrieval, Headscale sync |
| **VPC Admin** | `Admin → dstack gateway (TLS termination) → nginx → vpc-api-server` | dstack gateway: TLS termination<br>nginx: HTTP proxy | Ethereum wallet signature + nonce + timestamp | Allowlist management, node monitoring |

**Security Notes:**
- **dstack gateway** handles TLS differently for each role:
  - **VPC Node**: TLS transparency (passes through encrypted traffic for mTLS verification by nginx)
  - **VPC Admin**: TLS termination (decrypts HTTPS to HTTP)
- **nginx** receives:
  - From VPC Nodes: TLS-encrypted connections for mTLS verification
  - From VPC Admins: Plain HTTP requests (already decrypted by gateway)
- **VPC Node authentication flow:**
  1. dstack gateway forwards TLS connection transparently to nginx
  2. nginx performs mTLS verification with client certificates
  3. nginx forwards to dstack-mesh `/auth` endpoint for authentication
  4. dstack-mesh validates the client certificate and injects `x-dstack-app-id` header
  5. vpc-api-server validates `x-dstack-app-id` against the allowlist (managed by admins)
- **VPC Admin authentication:** Ethereum signature verification (no client certificates required)
- **app_id format**: Ethereum address without 0x prefix (40 hex characters, case-insensitive)

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OWNER_ADDRESS` | ✅ | - | Administrator Ethereum address (case-insensitive, with or without 0x prefix) |
| `HEADSCALE_INTERNAL_URL` | ❌ | `http://headscale:8080` | Internal Headscale API endpoint URL (auto-configured in docker-compose) |
| `HEADSCALE_API_KEY` | ❌ | (auto-generated) | Headscale API key (auto-injected by headscale container at startup) |
| `DSTACK_MESH_URL` | ❌ | `http://dstack-mesh:8091` | dstack-mesh service URL (auto-configured in docker-compose) |
| `PORT` | ❌ | `8000` | API server listening port |
| `DATA_DIR` | ❌ | `/data` | Data directory for allowlist and nonce database |
| `GIN_MODE` | ❌ | - | Set to `release` for production deployments |

**Note:** When using docker-compose, only `OWNER_ADDRESS` needs to be configured. All other variables are automatically set via the compose configuration.

---

## VPC Admin API (via dstack gateway)

Administrators use Ethereum wallet signatures to authenticate requests. All admin endpoints are proxied through the dstack gateway.

**Base URL:** Use `${API_BASE_URL}` throughout this documentation. Replace with your actual endpoint (e.g., `http://localhost:8000` for local development).

### Authentication Flow

1. **Obtain a nonce** (valid for 24 hours, reusable until expiration):
   ```bash
   curl ${API_BASE_URL}/admin/nonce
   ```

   **Response:**
   ```json
   {
     "nonce": "3fba2c4e5d7a9b1c3e5f7a9b1c3e5f7a",
     "expires_at": "2025-11-21T12:00:00Z",
     "owner": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
   }
   ```
2. **Construct the payload** for signing (format varies by request type):

   | Request | Payload Format |
   |---------|----------------|
   | `POST /admin/allowlist` | Compact JSON string of request body, e.g., `{"app_id":"f39fd6e51aad88f6f4ce6ab8827279cfffb92266"}` |
   | `GET /admin/allowlist` | `GET:/admin/allowlist` |
   | `DELETE /admin/allowlist/{app_id}` | `DELETE:/admin/allowlist/<app_id>` (e.g., `DELETE:/admin/allowlist/f39fd6e51aad88f6f4ce6ab8827279cfffb92266`) |
   | `GET /admin/nodes` | `GET:/admin/nodes` |

3. **Generate UTC timestamp** (must be within 30 seconds of server time):
   ```bash
   UTC_TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
   ```
   ⚠️ **Warning:** Generate a fresh timestamp for each request to avoid timeout errors.

4. **Sign the message** (format: `nonce:timestamp:payload`):
   ```bash
   SIGN_INPUT="${NONCE}:${UTC_TS}:${PAYLOAD}"
   SIG=$(cast wallet sign --private-key <ADMIN_PRIVATE_KEY> "$SIGN_INPUT")
   ```

5. **Send the request** with required headers:
   ```
   Authorization: Bearer <SIG>
   X-Nonce: <NONCE>
   X-UTC-Timestamp: <UTC_TS>
   Content-Type: application/json  # POST requests only
   ```

### Admin Endpoints

- `GET /admin/nonce` - Obtain a new nonce for signing requests
- `POST /admin/allowlist` - Add an app to the allowlist (Body: `{"app_id":"..."}`)
- `GET /admin/allowlist` - List all apps in the allowlist
- `DELETE /admin/allowlist/{app_id}` - Remove an app from the allowlist
- `GET /admin/nodes` - List all registered nodes (server injects Headscale API key automatically)

### Example Scripts

**Initial setup:**
```bash
API_BASE_URL="http://localhost:8000"  # Replace with your endpoint
PRIV=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
NONCE=$(curl -s ${API_BASE_URL}/admin/nonce | jq -r '.nonce')
```

**Add app to allowlist:**
```bash
# app_id is an Ethereum address without 0x prefix (40 hex characters)
APP_ID="f39fd6e51aad88f6f4ce6ab8827279cfffb92266"
UTC_TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
curl -X POST ${API_BASE_URL}/admin/allowlist \
  -H "Content-Type: application/json" \
  -H "X-Nonce: $NONCE" \
  -H "X-UTC-Timestamp: $UTC_TS" \
  -H "Authorization: Bearer $(cast wallet sign --private-key $PRIV "$NONCE:$UTC_TS:{\"app_id\":\"$APP_ID\"}")" \
  -d "{\"app_id\":\"$APP_ID\"}"
```

**Response:**
```json
{
  "success": true,
  "app_id": "f39fd6e51aad88f6f4ce6ab8827279cfffb92266"
}
```

**List allowlist:**
```bash
UTC_TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
curl ${API_BASE_URL}/admin/allowlist \
  -H "X-Nonce: $NONCE" \
  -H "X-UTC-Timestamp: $UTC_TS" \
  -H "Authorization: Bearer $(cast wallet sign --private-key $PRIV "$NONCE:$UTC_TS:GET:/admin/allowlist")"
```

**Response:**
```json
{
  "allowed_apps": [
    "f39fd6e51aad88f6f4ce6ab8827279cfffb92266",
    "70997970c51812dc3a010c7d01b50e0d17dc79c8"
  ],
  "count": 2,
  "owner": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
}
```

**Delete app from allowlist:**
```bash
APP_ID="f39fd6e51aad88f6f4ce6ab8827279cfffb92266"
UTC_TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
curl -X DELETE "${API_BASE_URL}/admin/allowlist/$APP_ID" \
  -H "X-Nonce: $NONCE" \
  -H "X-UTC-Timestamp: $UTC_TS" \
  -H "Authorization: Bearer $(cast wallet sign --private-key $PRIV "$NONCE:$UTC_TS:DELETE:/admin/allowlist/$APP_ID")"
```

**Response:**
```json
{
  "success": true,
  "app_id": "f39fd6e51aad88f6f4ce6ab8827279cfffb92266"
}
```

**List nodes:**
```bash
UTC_TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
curl ${API_BASE_URL}/admin/nodes \
  -H "X-Nonce: $NONCE" \
  -H "X-UTC-Timestamp: $UTC_TS" \
  -H "Authorization: Bearer $(cast wallet sign --private-key $PRIV "$NONCE:$UTC_TS:GET:/admin/nodes")"
```

**Response:**
```json
{
  "nodes": [
    {
      "id": "1",
      "name": "node-instance-001",
      "user": "default",
      "ipAddresses": ["100.64.0.1"],
      "online": true,
      "app_id": "f39fd6e51aad88f6f4ce6ab8827279cfffb92266"
    }
  ]
}
```

---

## VPC Node Communication (via dstack gateway + nginx + dstack-mesh)

VPC nodes authenticate using client certificates verified by nginx, with dstack-mesh injecting the `x-dstack-app-id` header based on certificate validation. The `app_id` values (Ethereum addresses without 0x prefix) are managed by VPC administrators through the allowlist API.

**Authentication Flow:**
1. dstack gateway receives VPC node connection and passes through TLS transparently
2. VPC node presents client certificate to nginx
3. nginx performs mTLS verification and forwards the certificate to dstack-mesh `/auth` endpoint
4. dstack-mesh validates the client certificate and determines the corresponding `app_id`
5. dstack-mesh injects `x-dstack-app-id` header into the request
6. vpc-api-server validates the `x-dstack-app-id` against the allowlist (managed by admins)
7. If the `app_id` is in the allowlist, the request is authorized (no additional signature required)

### Node Registration Test

For testing purposes (production requests must go through the dstack gateway → nginx → dstack-mesh authentication chain):

```bash
# Direct API access for development/testing only
# app_id is an Ethereum address without 0x prefix
curl "${API_BASE_URL}/api/register?instance_id=test-001&node_name=my-node" \
  -H "x-dstack-app-id: f39fd6e51aad88f6f4ce6ab8827279cfffb92266"
```

**Response (success):**
```json
{
  "pre_auth_key": "nodekey:abc123...",
  "shared_key": "c2hhcmVka2V5...",
  "server_url": "https://app-id-8080.gateway-domain.example.com"
}
```

**Response (forbidden):**
```json
{
  "error": "Forbidden"
}
```

**Note:**
- If the `app_id` is not in the allowlist, the server returns `403 Forbidden`
- In production, the `x-dstack-app-id` header is automatically injected by dstack-mesh after successful mTLS verification
- Admins must add the `app_id` (Ethereum address without 0x prefix) to the allowlist using the admin API before nodes can register

---

## Headscale API Proxy (for operations)

The VPC API Server proxies requests to the Headscale control server. This allows administrators to manage the Headscale infrastructure through a unified endpoint.

**Reference:** [Headscale API Documentation](https://github.com/juanfont/headscale/blob/main/docs/ref/api.md)

### Endpoints

- `GET /api/v1/node` - Proxy to Headscale node list with `app_id` injection
- `ANY /api/v1/*` - Transparent proxy to any Headscale API endpoint

All proxied requests require Headscale API key authentication:

```bash
HS_KEY=$(docker compose exec headscale cat /shared/headscale_api_key)
curl ${API_BASE_URL}/api/v1/node \
  -H "Authorization: Bearer $HS_KEY"
```

**Response:**
```json
{
  "nodes": [
    {
      "id": "1",
      "name": "node-instance-001",
      "user": "default",
      "ipAddresses": ["100.64.0.1"],
      "online": true,
      "app_id": "f39fd6e51aad88f6f4ce6ab8827279cfffb92266"
    }
  ]
}
```

**Note:** The `app_id` field is injected by vpc-api-server and is not part of the standard Headscale API response.

---

## Troubleshooting

**Nonce Issues:**
- **Expired nonce**: Request a new nonce from `/admin/nonce` (valid for 24 hours)
- Each nonce can be reused for multiple requests until expiration

**Timestamp Issues:**
- **Clock skew error**: Ensure `X-UTC-Timestamp` is in UTC RFC3339 format and within 30 seconds of server time
- Generate a fresh timestamp for each request to avoid timeout errors

**Signature Verification Failed:**
- Verify the signing payload format matches the request type (see payload table above)
- Ensure wallet address matches `OWNER_ADDRESS` environment variable
- Error format: `signer 0x... is not owner 0x...` indicates address mismatch

**Allowlist Issues:**
- Allowlist is persisted in `${DATA_DIR}/allowlist.json`
- Check file permissions and ensure the directory is writable
- Use `GET /admin/allowlist` to verify current state
