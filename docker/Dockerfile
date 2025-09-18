# Use the official Rust image as the base image
FROM rust:1.75-slim as builder

# Set the working directory
WORKDIR /app

# Copy the Cargo.toml and Cargo.lock files
COPY pinGuard/Cargo.toml pinGuard/Cargo.lock ./

# Copy the source code
COPY pinGuard/src ./src

# Build the application in release mode
RUN cargo build --release

# Use a smaller base image for the final image
FROM debian:bookworm-slim

# Install necessary runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the binary from the builder stage
COPY --from=builder /app/target/release/pinGuard /usr/local/bin/pinGuard

# Set the binary as executable
RUN chmod +x /usr/local/bin/pinGuard

# Expose any necessary ports (if applicable)
# EXPOSE 8080

# Set the default command
CMD ["pinGuard"]
