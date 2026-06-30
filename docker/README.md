# Docker end-to-end tests

Full data-path tests for the ShadowVPN data plane, driving the real
[`tsvpn-server`](../ts_vpn) and [`tsvpn-client`](../ts_vpn) binaries. Each test
builds the image, starts containers — each with its own TUN device — on a
private bridge, and pings through the encrypted tunnel.

A successful, lossless ping exercises the entire path:

```
TUN -> seal(salt ++ AEAD, obfs) -> UDP -> server -> open -> server TUN
    -> kernel reply -> ... -> back to the client
```

so it proves encryption, QUIC obfuscation, peer/inner-IP routing, and the relay
loops all work together.

## Single-client

```sh
./docker/run-e2e.sh                 # default cipher (chacha20-poly1305), quic obfs
./docker/run-e2e.sh aes-256-gcm     # any supported cipher
OBFS=none ./docker/run-e2e.sh       # disable carrier obfuscation
OBFS=base64 ./docker/run-e2e.sh aes-128-gcm
```

## Multi-client

Starts a server and **two** clients with distinct tunnel IPs (`10.9.0.2`,
`10.9.0.3`). `client1` is a long-running daemon whose healthcheck pings the
server; `client2` only starts once `client1` is healthy and then runs its own
ping test — so a green run proves the server serves two clients at once,
demultiplexing them by inner tunnel IP.

```sh
./docker/run-e2e-multi.sh                 # default cipher, quic obfs
./docker/run-e2e-multi.sh aes-256-gcm
```

The containers need `NET_ADMIN` and `/dev/net/tun` (the compose files request
both). Each script exits non-zero if connectivity through the tunnel fails, so
they double as CI gates.

## Files

| File | Purpose |
|------|---------|
| `Dockerfile` | Builds `tsvpn-server` + `tsvpn-client`; runtime image with `iproute2` + `ping`. |
| `docker-compose.yml` | Single-client: server + one client-under-test. |
| `docker-compose.multi.yml` | Multi-client: server + two clients (healthcheck-gated). |
| `run-server.sh` | Server entry point (binds UDP, brings up `10.9.0.1`). |
| `run-client.sh` | Foreground client daemon (env-driven tunnel IP). |
| `test-client.sh` | Brings up a client, pings the server, sets the exit code. |
| `run-e2e.sh` / `run-e2e-multi.sh` | Orchestrate `docker compose up` and return the client's verdict. |
