# syntax=docker/dockerfile:1
#
# Image for the Docker-based end-to-end test of the ShadowVPN data plane
# (`ts_tunnel`). It contains the `tunnel_node` example binary plus the userspace
# tools (iproute2, ping) needed to bring the tunnel up and probe connectivity
# across it. The same image runs as both server and client; the compose file
# selects the role via the command.

# --- Build stage ------------------------------------------------------------
# The repo pins its toolchain via rust-toolchain.toml (1.95.0); rustup in the
# base image honours it, fetching that toolchain if the image ships another.
FROM rust:1.95-bookworm AS builder
WORKDIR /src

# Copy the whole workspace; building a single example only compiles `ts_tunnel`
# and its dependencies (notably NOT `ts_python`, which needs a Python runtime).
COPY . .

# Build the data-mover against the pinned lockfile.
RUN cargo build --release --locked -p ts_tunnel --example tunnel_node

# --- Runtime stage ----------------------------------------------------------
FROM debian:bookworm-slim

# iproute2: interface/route inspection. iputils-ping: the cross-tunnel probe.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/examples/tunnel_node /usr/local/bin/tunnel_node
COPY docker/run-server.sh docker/test-client.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/run-server.sh /usr/local/bin/test-client.sh

ENV RUST_LOG=info
