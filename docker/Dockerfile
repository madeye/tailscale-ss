# syntax=docker/dockerfile:1
#
# Image for the Docker-based end-to-end test of the ShadowVPN data plane. It
# contains the `tsvpn-server` and `tsvpn-client` binaries (from the `ts_vpn`
# crate) plus the userspace tools (iproute2, ping) needed to bring the tunnel up
# and probe connectivity across it. The same image runs as both the server and
# the client(s); the compose files select the role via the command.

# --- Build stage ------------------------------------------------------------
# The repo pins its toolchain via rust-toolchain.toml (1.95.0); rustup in the
# base image honours it, fetching that toolchain if the image ships another.
FROM rust:1.95-bookworm AS builder
WORKDIR /src

# Copy the whole workspace; building just `ts_vpn`'s binaries only compiles that
# crate and its dependencies (notably NOT `ts_python`, which needs a Python
# runtime).
COPY . .

# Build both binaries against the pinned lockfile.
RUN cargo build --release --locked -p ts_vpn --bins

# --- Runtime stage ----------------------------------------------------------
FROM debian:bookworm-slim

# iproute2: interface/route inspection. iputils-ping: the cross-tunnel probe.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/tsvpn-server /usr/local/bin/tsvpn-server
COPY --from=builder /src/target/release/tsvpn-client /usr/local/bin/tsvpn-client
COPY docker/run-server.sh docker/run-client.sh docker/test-client.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/run-server.sh /usr/local/bin/run-client.sh \
    /usr/local/bin/test-client.sh

ENV RUST_LOG=info
