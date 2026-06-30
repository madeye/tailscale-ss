# Docker end-to-end test

A full data-path test for the ShadowVPN data plane (`ts_tunnel`). It builds the
[`tunnel_node`](../ts_tunnel/examples/tunnel_node.rs) example, starts a
**server** and a **client** container — each with its own TUN device — on a
private bridge network, and then pings the server's in-tunnel address
(`10.9.0.1`) from the client.

A successful, lossless ping exercises the entire path:

```
TUN -> Endpoint::send -> obfs(salt ++ AEAD) -> UDP -> server
    -> Endpoint::recv -> server TUN -> kernel reply -> ... -> back to the client
```

so it proves encryption, QUIC obfuscation, peer-address learning, and the relay
loops all work together.

## Running

```sh
./docker/run-e2e.sh                 # default cipher (chacha20-poly1305), quic obfs
./docker/run-e2e.sh aes-256-gcm     # any supported cipher
OBFS=none ./docker/run-e2e.sh       # disable carrier obfuscation
OBFS=base64 ./docker/run-e2e.sh aes-128-gcm
```

The containers need `NET_ADMIN` and `/dev/net/tun` (the compose file requests
both). The script exits non-zero if connectivity through the tunnel fails, so it
doubles as a CI gate.

## Files

| File | Purpose |
|------|---------|
| `Dockerfile` | Builds the `tunnel_node` example; runtime image with `iproute2` + `ping`. |
| `docker-compose.yml` | Server + client services sharing the image and TUN privileges. |
| `run-server.sh` | Server entry point (binds UDP, brings up `10.9.0.1`). |
| `test-client.sh` | Client entry point: brings up `10.9.0.2`, pings the server, sets the exit code. |
| `run-e2e.sh` | Orchestrates `docker compose up` and returns the client's verdict. |
