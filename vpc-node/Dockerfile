# Base: Tailscale image (based on alpine)
FROM tailscale/tailscale:v1.76.1

# Install required tools
RUN apk add --no-cache \
    curl \
    jq \
    ca-certificates

# Create necessary directories
RUN mkdir -p /shared /var/run/tailscale /etc/tailscale /var/lib/vpc-node

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 41641/udp 9002/tcp

# Healthcheck: Use debug server metrics endpoint
# Falls back to tailscale CLI if debug endpoint is unavailable
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD curl -sf http://127.0.0.1:9002/debug/metrics > /dev/null || tailscale status --json | jq -e '.BackendState == "Running"' > /dev/null || exit 1

ENTRYPOINT ["/entrypoint.sh"]
