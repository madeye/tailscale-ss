#!/bin/sh
# Runs a tsvpn-client in the foreground (a daemon). Used directly as a
# long-running client container, and launched in the background by
# test-client.sh. The client's tunnel IP comes from CLIENT_TUN_IP so several
# clients can share one image with distinct addresses.
set -eu

exec tsvpn-client \
    --server "${SERVER_ADDR:-server:8388}" \
    --tun-name tun0 \
    --tun-ip "${CLIENT_TUN_IP:-10.9.0.2}" \
    --peer-ip "${SERVER_TUN_IP:-10.9.0.1}" \
    --tun-netmask 255.255.255.0 \
    --password "${PASSWORD}" \
    --cipher "${CIPHER:-chacha20-poly1305}" \
    --obfs "${OBFS:-quic}"
