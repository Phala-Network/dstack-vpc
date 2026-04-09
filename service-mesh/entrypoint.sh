#!/bin/bash
set -e

# ============================================================================
# Environment Variables Validation
# ============================================================================
if [ -z "$DSTACK_GATEWAY_DOMAIN" ]; then
    echo "ERROR: DSTACK_GATEWAY_DOMAIN environment variable is not set"
    exit 1
fi

# ============================================================================
# Initialization State Check
# ============================================================================
DATA_DIR="/var/lib/dstack-mesh"
STATE_FILE="$DATA_DIR/.service-mesh-state"
CONFIG_FILE="/etc/dstack/dstack-mesh.toml"
CERT_KEY="/etc/ssl/private/server.key"
CERT_FILE="/etc/ssl/certs/server.crt"
CA_FILE="/etc/ssl/certs/ca.crt"

# Create data directory if it doesn't exist
mkdir -p "$DATA_DIR"

# Check if we need to initialize
NEEDS_INIT=true

if [ -f "$STATE_FILE" ]; then
    echo "Found existing state file, checking..."

    # Read saved state
    SAVED_GATEWAY_DOMAIN=$(grep "DSTACK_GATEWAY_DOMAIN=" "$STATE_FILE" | cut -d'=' -f2-)

    echo "  Saved DSTACK_GATEWAY_DOMAIN: $SAVED_GATEWAY_DOMAIN"
    echo "  Current DSTACK_GATEWAY_DOMAIN: $DSTACK_GATEWAY_DOMAIN"

    # Check if DSTACK_GATEWAY_DOMAIN is the same
    if [ "$SAVED_GATEWAY_DOMAIN" = "$DSTACK_GATEWAY_DOMAIN" ]; then
        # Check if all required files exist in volume
        if [ -f "$DATA_DIR/dstack-mesh.toml" ] && \
           [ -f "$DATA_DIR/server.key" ] && \
           [ -f "$DATA_DIR/server.crt" ] && \
           [ -f "$DATA_DIR/ca.crt" ]; then
            echo "✓ Configuration is up-to-date, skipping initialization"
            NEEDS_INIT=false
        else
            echo "⚠ Some configuration files are missing, re-initializing..."
        fi
    else
        echo "⚠ DSTACK_GATEWAY_DOMAIN changed, re-initializing..."
    fi
else
    echo "No previous state found, initializing..."
fi

# ============================================================================
# Phase 1: Generate Configuration and Certificates (if needed)
# ============================================================================
if [ "$NEEDS_INIT" = true ]; then
    echo "=========================================="
    echo "dstack-mesh Bootstrap"
    echo "  Gateway Domain: $DSTACK_GATEWAY_DOMAIN"
    echo "=========================================="

    # Generate dstack-mesh.toml configuration
    echo "Generating dstack-mesh configuration..."
    cat > "$DATA_DIR/dstack-mesh.toml" <<EOF
[client]
enabled = true
address = "0.0.0.0"
port = 8091

[auth]
enabled = true
address = "0.0.0.0"
port = 8092

[dstack]
gateway_domain = "${DSTACK_GATEWAY_DOMAIN}"

[tls]
cert_file = "/etc/ssl/certs/server.crt"
key_file = "/etc/ssl/private/server.key"
ca_file = "/etc/ssl/certs/ca.crt"
EOF

    echo "✓ Configuration written to $DATA_DIR/dstack-mesh.toml"

    # Check if dstack.sock is available
    if [ ! -S /var/run/dstack.sock ]; then
        echo "ERROR: /var/run/dstack.sock not found or not a socket"
        exit 1
    fi

    # Generate server certificate using dstack.sock HTTP API
    echo "Generating server certificate using dstack.sock HTTP API..."
    CERT_URL='http://localhost/GetTlsKey?subject=localhost&usage_server_auth=true&usage_client_auth=true'

    if ! curl -s --unix-socket /var/run/dstack.sock "$CERT_URL" > /tmp/server_response.json; then
        echo "ERROR: Failed to generate certificates - dstack.sock may not be available"
        exit 1
    fi

    # Validate JSON response
    if ! jq -e . /tmp/server_response.json >/dev/null 2>&1; then
        echo "ERROR: Invalid JSON response from dstack.sock"
        exit 1
    fi

    # Extract server key and certificates to volume
    echo "Extracting server key and certificates..."
    jq -r '.key' /tmp/server_response.json > "$DATA_DIR/server.key"
    jq -r '.certificate_chain[]' /tmp/server_response.json > "$DATA_DIR/server.crt"
    jq -r '.certificate_chain[-1]' /tmp/server_response.json > "$DATA_DIR/ca.crt"

    # Verify certificates were created
    if [ ! -f "$DATA_DIR/server.key" ] || [ ! -s "$DATA_DIR/server.key" ]; then
        echo "ERROR: Failed to extract server key"
        exit 1
    fi

    if [ ! -f "$DATA_DIR/server.crt" ] || [ ! -s "$DATA_DIR/server.crt" ]; then
        echo "ERROR: Failed to extract server certificate"
        exit 1
    fi

    if [ ! -f "$DATA_DIR/ca.crt" ] || [ ! -s "$DATA_DIR/ca.crt" ]; then
        echo "ERROR: Failed to extract CA certificate"
        exit 1
    fi

    echo "✓ Certificates generated and saved to $DATA_DIR"

    # Save state
    cat > "$STATE_FILE" <<EOF
DSTACK_GATEWAY_DOMAIN=$DSTACK_GATEWAY_DOMAIN
INITIALIZED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
EOF

    rm -f /tmp/server_response.json

    echo "✓ Configuration saved to $DATA_DIR"
else
    echo "Using existing configuration from $DATA_DIR"
fi

# ============================================================================
# Phase 2: Prepare runtime configuration
# ============================================================================
mkdir -p /etc/dstack /etc/ssl/private /etc/ssl/certs

# Copy config and certificates from volume to runtime locations
cp "$DATA_DIR/dstack-mesh.toml" "$CONFIG_FILE"
cp "$DATA_DIR/server.key" "$CERT_KEY"
cp "$DATA_DIR/server.crt" "$CERT_FILE"
cp "$DATA_DIR/ca.crt" "$CA_FILE"

# Set file permissions
chmod 644 "$CERT_KEY" "$CERT_FILE" "$CA_FILE"

echo "✓ Runtime configuration ready"

# Display configuration summary
echo "=========================================="
echo "dstack-mesh configuration:"
echo "  Gateway Domain: $DSTACK_GATEWAY_DOMAIN"
echo "  Client Port: 8091"
echo "  Auth Port: 8092"
echo "  Config File: $CONFIG_FILE"
echo "=========================================="

# ============================================================================
# Phase 3: Start dstack-mesh
# ============================================================================
echo "Starting dstack-mesh..."
exec /usr/local/bin/dstack-mesh --config "$CONFIG_FILE"
