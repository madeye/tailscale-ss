#!/bin/sh
# Entry point for the server container in the E2E test.
#
# Runs the tunnel node in server mode: it binds the UDP port, creates its TUN
# (10.9.0.1, peer 10.9.0.2), and learns the client's UDP address from the first
# authenticated datagram. PASSWORD/CIPHER/OBFS come from the environment so the
# same image can be exercised across every supported cipher from a CI matrix.
set -eu

exec tunnel_node \
    --listen 0.0.0.0:8388 \
    --tun-name tun0 \
    --tun-ip 10.9.0.1 \
    --peer-ip 10.9.0.2 \
    --password "${PASSWORD}" \
    --cipher "${CIPHER:-chacha20-poly1305}" \
    --obfs "${OBFS:-quic}"
