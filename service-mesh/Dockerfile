# Build stage: Compile dstack-mesh
FROM rust:1.86-alpine AS rust-builder
RUN apk add --no-cache musl-dev
RUN rustup target add x86_64-unknown-linux-musl
WORKDIR /build
COPY . /build
RUN cargo build --release --target x86_64-unknown-linux-musl

# Final stage: Alpine with bash, curl, jq
FROM alpine:3.20

# Install required tools
RUN apk add --no-cache \
    bash \
    curl \
    jq \
    ca-certificates

# Copy dstack-mesh binary (statically linked musl binary)
COPY --from=rust-builder /build/target/x86_64-unknown-linux-musl/release/dstack-mesh /usr/local/bin/dstack-mesh

# Create necessary directories
RUN mkdir -p /etc/dstack /etc/ssl/certs /etc/ssl/private /tmp /var/lib/dstack-mesh

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /app

EXPOSE 8091 8092

ENTRYPOINT ["/entrypoint.sh"]
