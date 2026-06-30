#!/bin/sh
# Entry point for the client-under-test container.
#
# Brings up a tsvpn-client (in the background, via run-client.sh) and then
# verifies real connectivity *through* the encrypted tunnel by pinging the
# server's in-tunnel address (10.9.0.1). A successful ping proves the full data
# path end to end:
#
#   client kernel -> TUN -> seal(salt ++ AEAD, obfs) -> UDP -> server
#   -> open -> server TUN -> kernel reply -> ... -> back to this client.
#
# The client sends first (the ping), which is also how the server learns this
# client's inner tunnel IP -> UDP address mapping. Exits 0 on success, non-zero
# on failure, so compose `--exit-code-from` turns it into the test's verdict.
set -eu

SERVER_TUN_IP="${SERVER_TUN_IP:-10.9.0.1}"
PING_COUNT=5
STARTUP_TIMEOUT=30

echo "[client ${CLIENT_TUN_IP:-10.9.0.2}] starting tsvpn-client (cipher=${CIPHER:-chacha20-poly1305} obfs=${OBFS:-quic})"
run-client.sh &
CLIENT_PID=$!

trap 'kill "$CLIENT_PID" 2>/dev/null || true' EXIT

# Wait for the tunnel to carry a round-trip, retrying to absorb startup races.
connected=0
i=1
while [ "$i" -le "$STARTUP_TIMEOUT" ]; do
    if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
        echo "[client] FAIL: tsvpn-client exited during startup" >&2
        wait "$CLIENT_PID" || true
        exit 1
    fi
    if ping -c 1 -W 1 "$SERVER_TUN_IP" >/dev/null 2>&1; then
        connected=1
        break
    fi
    echo "[client] waiting for tunnel to come up... ($i/${STARTUP_TIMEOUT})"
    i=$((i + 1))
    sleep 1
done

if [ "$connected" -ne 1 ]; then
    echo "[client] FAIL: no reply from $SERVER_TUN_IP after ${STARTUP_TIMEOUT}s" >&2
    ip addr show tun0 >&2 || true
    exit 1
fi

# Stronger assertion: a short burst must all get through with 0% loss.
echo "[client] tunnel is up; running ping burst to $SERVER_TUN_IP"
if ping -c "$PING_COUNT" -i 0.3 -W 2 "$SERVER_TUN_IP"; then
    echo "[client] PASS: end-to-end connectivity through the tsvpn tunnel"
    exit 0
fi

echo "[client] FAIL: ping burst to $SERVER_TUN_IP lost packets" >&2
exit 1
