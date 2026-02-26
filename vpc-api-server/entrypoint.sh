#!/bin/sh
set -e

# ============================================================================
# Environment Variables Validation
# ============================================================================
if [ -z "$OWNER_ADDRESS" ]; then
    echo "ERROR: OWNER_ADDRESS environment variable is not set"
    exit 1
fi

if [ -z "$DSTACK_MESH_URL" ]; then
    echo "ERROR: DSTACK_MESH_URL environment variable is not set"
    exit 1
fi

if [ -z "$HEADSCALE_INTERNAL_URL" ]; then
    echo "ERROR: HEADSCALE_INTERNAL_URL environment variable is not set"
    exit 1
fi

# ============================================================================
# Configuration
# ============================================================================
DATA_DIR="/data"
STATE_FILE="$DATA_DIR/.vpc-api-server-state"
API_KEY_FILE="$DATA_DIR/headscale_api_key"
HEADSCALE_GRPC_ADDR="${HEADSCALE_GRPC_ADDR:-headscale:50443}"

mkdir -p "$DATA_DIR"

# ============================================================================
# Initialization State Check
# ============================================================================
NEEDS_INIT=true

if [ -f "$STATE_FILE" ]; then
    echo "Found existing state file, checking..."

    SAVED_OWNER=$(grep "OWNER_ADDRESS=" "$STATE_FILE" | cut -d'=' -f2-)

    echo "  Saved OWNER_ADDRESS: $SAVED_OWNER"
    echo "  Current OWNER_ADDRESS: $OWNER_ADDRESS"

    if [ "$SAVED_OWNER" = "$OWNER_ADDRESS" ]; then
        if [ -f "$API_KEY_FILE" ] && [ -s "$API_KEY_FILE" ]; then
            echo "✓ Configuration is up-to-date, skipping initialization"
            NEEDS_INIT=false
        else
            echo "⚠ API key file missing, re-initializing..."
        fi
    else
        echo "⚠ OWNER_ADDRESS changed, re-initializing..."
    fi
else
    echo "No previous state found, initializing..."
fi

# ============================================================================
# Phase 1: Bootstrap - Initialize Headscale API Key (if needed)
# ============================================================================
if [ "$NEEDS_INIT" = true ]; then
    echo "=========================================="
    echo "VPC API Server Bootstrap"
    echo "  Owner Address: $OWNER_ADDRESS"
    echo "  Headscale URL: $HEADSCALE_INTERNAL_URL"
    echo "=========================================="

    # Wait for headscale to generate API key
    echo "Waiting for headscale API key..."
    MAX_RETRIES=60
    RETRY_COUNT=0

    SHARED_API_KEY_FILE="/data/headscale_api_key"

    while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
        if [ -f "$SHARED_API_KEY_FILE" ] && [ -s "$SHARED_API_KEY_FILE" ]; then
            echo "✓ Headscale API key found"
            break
        fi
        RETRY_COUNT=$((RETRY_COUNT + 1))
        echo "Waiting for API key file... ($RETRY_COUNT/$MAX_RETRIES)"
        sleep 2
    done

    if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
        echo "ERROR: API key file not found within timeout"
        echo "Expected location: $SHARED_API_KEY_FILE"
        exit 1
    fi

    # Copy API key to expected location (skip if already the same file)
    if [ "$SHARED_API_KEY_FILE" -ef "$API_KEY_FILE" ]; then
        echo "✓ API key already at $API_KEY_FILE"
        chmod 600 "$API_KEY_FILE"
    else
        cp "$SHARED_API_KEY_FILE" "$API_KEY_FILE"
        chmod 600 "$API_KEY_FILE"
        echo "✓ API key copied to $API_KEY_FILE"
    fi

    # Save state
    cat > "$STATE_FILE" <<EOF_STATE
OWNER_ADDRESS=$OWNER_ADDRESS
INITIALIZED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
EOF_STATE

    echo "✓ Bootstrap completed"
else
    echo "Using existing configuration from $DATA_DIR"
fi

# ============================================================================
# Phase 2: Prepare runtime environment
# ============================================================================
if [ ! -f "$API_KEY_FILE" ]; then
    echo "ERROR: API key file not found at $API_KEY_FILE"
    exit 1
fi

HEADSCALE_API_KEY=$(cat "$API_KEY_FILE")

if [ -z "$HEADSCALE_API_KEY" ]; then
    echo "ERROR: API key is empty"
    exit 1
fi

# Export for the Go application
export HEADSCALE_API_KEY

echo "==========================================="
echo "VPC API Server Configuration:"
echo "  Owner Address: $OWNER_ADDRESS"
echo "  Data Dir: $DATA_DIR"
echo "  Headscale URL: $HEADSCALE_INTERNAL_URL"
echo "  Mesh URL: $DSTACK_MESH_URL"
echo "  API Key: <redacted> (loaded from $API_KEY_FILE)"
echo "==========================================="

# ============================================================================
# Phase 3: Start vpc-api-server
# ============================================================================
echo "Starting VPC API Server..."
exec /root/vpc-api-server
