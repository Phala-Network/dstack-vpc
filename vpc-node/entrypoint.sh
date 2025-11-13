#!/bin/sh
set -e

# ============================================================================
# Environment Variables Validation
# ============================================================================
if [ -z "$NODE_NAME" ]; then
    echo "ERROR: NODE_NAME environment variable is not set"
    exit 1
fi

if [ -z "$VPC_SERVER_HOST" ]; then
    echo "ERROR: VPC_SERVER_HOST environment variable is not set"
    exit 1
fi

# Set default DSTACK_MESH_URL if not provided
DSTACK_MESH_URL=${DSTACK_MESH_URL:-"http://localhost:8091"}

# ============================================================================
# Initialization State Check
# ============================================================================
DATA_DIR="/var/lib/vpc-node"
STATE_FILE="$DATA_DIR/.vpc-node-state"
CONFIG_FILE="/etc/tailscale/config.json"

# Create data directory if it doesn't exist
mkdir -p "$DATA_DIR"

# Check if we need to initialize
NEEDS_INIT=true

if [ -f "$STATE_FILE" ]; then
    echo "Found existing state file, checking..."

    # Read saved state
    SAVED_NODE_NAME=$(grep "NODE_NAME=" "$STATE_FILE" | cut -d'=' -f2-)
    SAVED_VPC_SERVER_HOST=$(grep "VPC_SERVER_HOST=" "$STATE_FILE" | cut -d'=' -f2-)

    echo "  Saved NODE_NAME: $SAVED_NODE_NAME"
    echo "  Current NODE_NAME: $NODE_NAME"

    # Check if NODE_NAME or VPC_SERVER_HOST changed
    if [ "$SAVED_NODE_NAME" = "$NODE_NAME" ] && [ "$SAVED_VPC_SERVER_HOST" = "$VPC_SERVER_HOST" ]; then
        # Check if all required files exist
        if [ -f "$DATA_DIR/config.json" ] && \
           [ -f "$DATA_DIR/pre_auth_key" ] && \
           [ -f "$DATA_DIR/server_url" ]; then
            echo "✓ Configuration is up-to-date, skipping initialization"
            NEEDS_INIT=false
        else
            echo "⚠ Some configuration files are missing, re-initializing..."
        fi
    else
        echo "⚠ NODE_NAME or VPC_SERVER_HOST changed, re-initializing..."
    fi
else
    echo "No previous state found, initializing..."
fi

# ============================================================================
# Phase 1: Bootstrap - Fetch VPC credentials (if needed)
# ============================================================================
if [ "$NEEDS_INIT" = true ]; then
    echo "=========================================="
    echo "VPC Node Bootstrap"
    echo "  Node Name: $NODE_NAME"
    echo "  VPC Server Host: $VPC_SERVER_HOST"
    echo "  Mesh URL: $DSTACK_MESH_URL"
    echo "=========================================="

    echo "Fetching instance info from dstack-mesh..."
    INFO=$(curl -s "$DSTACK_MESH_URL/info")
    INSTANCE_ID=$(echo "$INFO" | jq -r .instance_id)

    if [ -z "$INSTANCE_ID" ] || [ "$INSTANCE_ID" = "null" ]; then
        echo "ERROR: Failed to get instance_id from mesh"
        echo "Response: $INFO"
        exit 1
    fi

    echo "Instance ID: $INSTANCE_ID"

    echo "Registering with VPC server..."
    echo "  URL: $DSTACK_MESH_URL/api/register?instance_id=$INSTANCE_ID&node_name=$NODE_NAME"
    echo "  Host Header: $VPC_SERVER_HOST"

    RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" \
        -H "Host: $VPC_SERVER_HOST" \
        "$DSTACK_MESH_URL/api/register?instance_id=$INSTANCE_ID&node_name=$NODE_NAME")

    # Extract HTTP code and body
    HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE:" | cut -d':' -f2)
    BODY=$(echo "$RESPONSE" | sed '/HTTP_CODE:/d')

    echo "Response Status: $HTTP_CODE"

    # Check HTTP status code
    if [ "$HTTP_CODE" != "200" ]; then
        echo "ERROR: HTTP request failed with status $HTTP_CODE"
        exit 1
    fi

    # Check if response is valid JSON
    if ! echo "$BODY" | jq -e . >/dev/null 2>&1; then
        echo "ERROR: Response is not valid JSON"
        exit 1
    fi

    PRE_AUTH_KEY=$(echo "$BODY" | jq -r .pre_auth_key)
    SHARED_KEY=$(echo "$BODY" | jq -r .shared_key)
    VPC_SERVER_URL=$(echo "$BODY" | jq -r .server_url)

    if [ -z "$PRE_AUTH_KEY" ] || [ "$PRE_AUTH_KEY" = "null" ] || \
       [ -z "$VPC_SERVER_URL" ] || [ "$VPC_SERVER_URL" = "null" ]; then
        echo "ERROR: Missing required fields in registration response"
        exit 1
    fi

    echo "✓ Registration successful"

    # ========================================================================
    # Phase 2: Generate and save configuration
    # ========================================================================
    echo "Generating tailscaled config file..."
    cat > "$DATA_DIR/config.json" <<EOF
{
  "version": "alpha0",
  "serverURL": "$VPC_SERVER_URL",
  "authKey": "$PRE_AUTH_KEY",
  "hostname": "$NODE_NAME",
  "acceptDNS": true,
  "enabled": true
}
EOF

    # Save credentials to data directory
    echo "$PRE_AUTH_KEY" > "$DATA_DIR/pre_auth_key"
    echo "$SHARED_KEY" > "$DATA_DIR/shared_key"
    echo "$VPC_SERVER_URL" > "$DATA_DIR/server_url"

    # Save state
    cat > "$STATE_FILE" <<EOF
NODE_NAME=$NODE_NAME
VPC_SERVER_HOST=$VPC_SERVER_HOST
INITIALIZED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
EOF

    echo "✓ Configuration saved to $DATA_DIR"
else
    echo "Using existing configuration from $DATA_DIR"
fi

# ============================================================================
# Phase 3: Prepare runtime config
# ============================================================================
mkdir -p /etc/tailscale

# Copy config from data directory to runtime location
cp "$DATA_DIR/config.json" "$CONFIG_FILE"

# Also save to /shared for backward compatibility
mkdir -p /shared
cp "$DATA_DIR/pre_auth_key" /shared/pre_auth_key 2>/dev/null || true
cp "$DATA_DIR/shared_key" /shared/shared_key 2>/dev/null || true
cp "$DATA_DIR/server_url" /shared/server_url 2>/dev/null || true

echo "✓ Config file ready: $CONFIG_FILE"

# ============================================================================
# Phase 4: Start tailscaled with config file (foreground)
# ============================================================================
TUN_DEV_NAME=${TUN_DEV_NAME:-"tailscale0"}
DEBUG_ADDR=${DEBUG_ADDR:-"127.0.0.1:9002"}

echo "=========================================="
echo "Starting tailscaled with config file"
echo "  Config: $CONFIG_FILE"
echo "  TUN Device: $TUN_DEV_NAME"
echo "  State Directory: $DATA_DIR"
echo "  Debug Server: $DEBUG_ADDR (/debug/metrics)"
echo "=========================================="

# Trap signals for graceful shutdown
trap 'echo "Received shutdown signal, exiting..."; exit 0' TERM INT

# Start tailscaled in foreground (becomes PID 1)
# It will handle connection, reconnection, and state management
# Use --statedir instead of --state to support network-lock and other features
exec tailscaled \
    --config="$CONFIG_FILE" \
    --tun="$TUN_DEV_NAME" \
    --statedir="$DATA_DIR" \
    --socket=/var/run/tailscale/tailscaled.sock \
    --debug="$DEBUG_ADDR"
