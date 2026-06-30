#!/usr/bin/env bash
# End-to-end test: tailscale-ss against a local Headscale control plane, carrying
# real traffic over the selected data-plane protocol (ShadowVPN by default).
#
# It starts Headscale in Docker, registers two tailscale-ss nodes (the `tcp_echo`
# and `tcp_probe` examples), and asserts that a TCP echo round-trip succeeds
# through the tunnel. With PROTOCOL=shadowvpn the data plane is the shadowsocks
# AEAD UDP tunnel with QUIC obfuscation; with PROTOCOL=wireguard it is WireGuard.
#
#   ./docker/headscale/run-headscale-e2e.sh            # ShadowVPN (default)
#   PROTOCOL=wireguard ./docker/headscale/run-headscale-e2e.sh
#
# Requirements: Docker, a Rust toolchain, and outbound internet (data-plane
# traffic relays through Tailscale's public DERP servers). Host port 18080 must
# be free (Headscale's control plane is mapped there).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

PROTOCOL="${PROTOCOL:-shadowvpn}"
HS_PORT="${HS_PORT:-18080}"
CONTROL_URL="http://127.0.0.1:${HS_PORT}"
IMG="ts-headscale-e2e:latest"
CONTAINER="ts-hs-e2e"
ECHO_PORT=1234
WORK="$(mktemp -d)"
ECHO_LOG="$WORK/echo.log"
PROBE_LOG="$WORK/probe.log"
ECHO_PID=""

cleanup() {
    [ -n "$ECHO_PID" ] && kill "$ECHO_PID" 2>/dev/null || true
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

echo "==> ShadowVPN-over-Headscale E2E (protocol=${PROTOCOL})"

# 1. Build the Headscale image (config + allow-all policy baked in) and start it.
docker build -q -f docker/headscale/Dockerfile -t "$IMG" . >/dev/null
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER" -p "${HS_PORT}:8080" "$IMG" serve >/dev/null

echo "==> waiting for Headscale control plane on ${CONTROL_URL}"
for i in $(seq 1 30); do
    if curl -fsS -m 2 "${CONTROL_URL}/key?v=130" >/dev/null 2>&1; then break; fi
    [ "$i" = 30 ] && { echo "ERROR: Headscale did not come up" >&2; docker logs "$CONTAINER" | tail; exit 1; }
    sleep 1
done

# 2. Create a user and a reusable pre-auth key (both nodes share it).
docker exec "$CONTAINER" headscale users create node >/dev/null 2>&1
KEY="$(docker exec "$CONTAINER" headscale preauthkeys create --user 1 --reusable --expiration 1h 2>/dev/null | tail -1 | tr -d '\r')"
[ -n "$KEY" ] || { echo "ERROR: failed to create pre-auth key" >&2; exit 1; }

# 3. Build the two node examples (insecure-keyfetch allows the plain-HTTP control URL).
echo "==> building node examples"
cargo build -q --example tcp_echo --example tcp_probe --features insecure-keyfetch

COMMON_ENV=(
    TS_RS_EXPERIMENT=this_is_unstable_software
    TS_CONTROL_URL="$CONTROL_URL"
    TS_DATAPLANE_PROTOCOL="$PROTOCOL"
    RUST_LOG=info
    NO_COLOR=1
)

# 4. Start the echo node and learn its tailnet IP from its log.
echo "==> starting echo node"
env "${COMMON_ENV[@]}" ./target/debug/examples/tcp_echo \
    --key-file "$WORK/echo_keys.json" --auth-key "$KEY" \
    --hostname node-echo --listen-port "$ECHO_PORT" >"$ECHO_LOG" 2>&1 &
ECHO_PID=$!

ECHO_IP=""
for i in $(seq 1 40); do
    kill -0 "$ECHO_PID" 2>/dev/null || { echo "ERROR: echo node exited" >&2; cat "$ECHO_LOG"; exit 1; }
    # Strip any ANSI color codes, then pull the IP out of `listening_addr=<ip>:port`.
    ECHO_IP="$(sed 's/\x1b\[[0-9;]*m//g' "$ECHO_LOG" | sed -n 's/.*listening_addr=\([0-9.]*\):.*/\1/p' | head -1)"
    [ -n "$ECHO_IP" ] && break
    sleep 1
done
[ -n "$ECHO_IP" ] || { echo "ERROR: echo node never reported a tailnet IP" >&2; cat "$ECHO_LOG"; exit 1; }
echo "==> echo node listening on ${ECHO_IP}:${ECHO_PORT}"

# 5. Run the probe node: connect to the echo node and verify the round-trip.
echo "==> starting probe node"
if env "${COMMON_ENV[@]}" ./target/debug/examples/tcp_probe \
    --key-file "$WORK/probe_keys.json" --auth-key "$KEY" \
    --hostname node-probe --peer "${ECHO_IP}:${ECHO_PORT}" --timeout-secs 75 >"$PROBE_LOG" 2>&1
then :; fi

if grep -q PROBE_PASS "$PROBE_LOG"; then
    echo "==> PASS: TCP echo round-trip succeeded over the ${PROTOCOL} data plane via Headscale + DERP"
    exit 0
fi

echo "==> FAIL: probe did not complete the round-trip" >&2
echo "--- probe log ---" >&2; tail -20 "$PROBE_LOG" >&2
echo "--- echo log ---" >&2; tail -10 "$ECHO_LOG" >&2
exit 1
