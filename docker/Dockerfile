# Multi-stage build for PinGuard
# Build stage
FROM rust:1.89.0 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Copy the Cargo.toml and Cargo.lock files
COPY pinGuard/Cargo.toml pinGuard/Cargo.lock ./

# Create a dummy main.rs to build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN mkdir benches && echo 'fn main() {}' > benches/benchmarks.rs

# Build dependencies (this layer will be cached)
RUN cargo build --release && rm -rf src benches

# Copy the actual source code
COPY pinGuard/src ./src
COPY pinGuard/benches ./benches

# Build the application in release mode
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create a non-root user
RUN groupadd -r pinGuard && useradd -r -g pinGuard -d /home/pinGuard -s /bin/bash pinGuard \
    && mkdir -p /home/pinGuard \
    && chown -R pinGuard:pinGuard /home/pinGuard

# Create necessary directories
RUN mkdir -p /var/lib/pinGuard /var/log/pinGuard /etc/pinGuard \
    && chown -R pinGuard:pinGuard /var/lib/pinGuard /var/log/pinGuard \
    && chmod 755 /etc/pinGuard

# Copy the binary from the builder stage
COPY --from=builder /app/target/release/pinGuard /usr/local/bin/pinGuard

# Copy default configuration
COPY config.example.yaml /etc/pinGuard/config.yaml

# Set proper permissions
RUN chmod +x /usr/local/bin/pinGuard \
    && chown root:root /usr/local/bin/pinGuard \
    && chmod 644 /etc/pinGuard/config.yaml

# Set up volumes for persistent data
VOLUME ["/var/lib/pinGuard", "/var/log/pinGuard"]

# Switch to non-root user for security
USER pinGuard

# Set working directory
WORKDIR /home/pinGuard

# Set environment variables
ENV RUST_LOG=info
ENV PINBOARD_CONFIG=/etc/pinGuard/config.yaml

# Add health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD pinGuard --help || exit 1

# Default command
ENTRYPOINT ["pinGuard"]
CMD ["--help"]
