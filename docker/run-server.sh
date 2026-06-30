#!/bin/sh
# Entry point for the server container in the E2E tests.
#
# Runs the multi-client tsvpn-server: it binds the UDP port, creates its TUN
# (10.9.0.1 on a /24), and demultiplexes clients by their inner tunnel IP.
# PASSWORD/CIPHER/OBFS come from the environment so the same image can be
# exercised across every supported cipher from a CI matrix.
set -eu

exec tsvpn-server \
    --listen 0.0.0.0:8388 \
    --tun-name tun0 \
    --tun-ip "${SERVER_TUN_IP:-10.9.0.1}" \
    --tun-netmask 255.255.255.0 \
    --password "${PASSWORD}" \
    --cipher "${CIPHER:-chacha20-poly1305}" \
    --obfs "${OBFS:-quic}"
