#!/bin/bash
set -e

if [ -z "$DSTACK_MESH_URL" ]; then
    echo "ERROR: DSTACK_MESH_URL is not set"
    exit 1
fi

echo "Fetching instance info from dstack-mesh..."
echo "curl -v $DSTACK_MESH_URL/info"
INFO=$(curl -s $DSTACK_MESH_URL/info)
INSTANCE_ID=$(jq -r .instance_id <<<"$INFO")
echo "INSTANCE_ID: $INSTANCE_ID"

if [ "$VPC_SERVER_APP_ID" = "self" ]; then
    VPC_SERVER_APP_ID=$(jq -r .app_id <<<"$INFO")
fi

echo "Instance ID: $INSTANCE_ID"
echo "VPC Server App ID: $VPC_SERVER_APP_ID"

# Retry registration — the VPC server may not have this app in its
# allowlist yet (orchestrator updates it after deploying the runner).
# Retry every 10s for up to 5 minutes.
MAX_RETRIES=30
RETRY_INTERVAL=10

for i in $(seq 1 $MAX_RETRIES); do
    RESPONSE=$(curl -s -H "x-dstack-target-app: $VPC_SERVER_APP_ID" -H "Host: dstack-vpc-server" \
        "$DSTACK_MESH_URL/api/register?instance_id=$INSTANCE_ID&node_name=$NODE_NAME")

    PRE_AUTH_KEY=$(jq -r '.pre_auth_key // empty' <<<"$RESPONSE")
    SHARED_KEY=$(jq -r '.shared_key // empty' <<<"$RESPONSE")
    VPC_SERVER_URL=$(jq -r '.server_url // empty' <<<"$RESPONSE")

    if [ -n "$PRE_AUTH_KEY" ] && [ -n "$SHARED_KEY" ] && [ -n "$VPC_SERVER_URL" ]; then
        echo "Registration succeeded (attempt $i)"
        break
    fi

    echo "Registration failed (attempt $i/$MAX_RETRIES): $RESPONSE"

    if [ "$i" -eq "$MAX_RETRIES" ]; then
        echo "ERROR: VPC registration failed after $MAX_RETRIES attempts"
        echo "Last response: $RESPONSE"
        exit 1
    fi

    echo "Retrying in ${RETRY_INTERVAL}s..."
    sleep $RETRY_INTERVAL
done

echo "$PRE_AUTH_KEY" > /shared/pre_auth_key
echo "$SHARED_KEY" > /shared/shared_key
echo "$VPC_SERVER_URL" > /shared/server_url

echo "VPC setup completed"
