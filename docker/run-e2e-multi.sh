#!/usr/bin/env bash
# Run the multi-client ts_tunnel (ShadowVPN) Docker end-to-end test.
#
# Builds the image, starts a server and TWO clients (distinct tunnel IPs), and
# returns the second client's pass/fail as this script's exit code — which only
# succeeds if the first client is already connected (healthcheck-gated), so it
# proves the server serves multiple clients at once. Takes an optional cipher
# name as the first argument (default chacha20-poly1305); OBFS overrides the
# carrier obfuscation (default quic).
set -euo pipefail

cd "$(dirname "$0")"

CIPHER="${1:-${CIPHER:-chacha20-poly1305}}"
OBFS="${OBFS:-quic}"
export CIPHER OBFS

if docker compose version >/dev/null 2>&1; then
    COMPOSE="docker compose -f docker-compose.multi.yml"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE="docker-compose -f docker-compose.multi.yml"
else
    echo "error: neither 'docker compose' nor 'docker-compose' is available" >&2
    exit 1
fi

cleanup() {
    $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> ts_tunnel multi-client Docker E2E test (cipher=${CIPHER}, obfs=${OBFS})"

$COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
$COMPOSE up --build --abort-on-container-exit --exit-code-from client2
