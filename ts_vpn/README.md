# ts_vpn

ShadowVPN **server** and **client** binaries built on [`ts_tunnel`](../ts_tunnel).

`ts_tunnel` is the sans-I/O data plane (the shadowsocks-AEAD UDP protocol with
optional QUIC obfuscation); `ts_vpn` turns it into runnable daemons that move
real packets between a TUN device and a UDP socket.

## Binaries

| Binary | Role |
|--------|------|
| `tsvpn-server` | Binds a UDP port + TUN and serves **many clients at once**, demultiplexing them by inner tunnel IP. |
| `tsvpn-client` | Tunnels its TUN traffic to one server and sends periodic keepalives. |

```sh
cargo build --release -p ts_vpn --bins
```

## Multi-client model

All peers share one pre-shared password, so the server can't tell clients apart
cryptographically. Instead it learns each client's **inner tunnel source IP →
UDP endpoint** from inbound traffic and routes replies by inner destination IP
(ShadowVPN's default mode). Therefore **each client must use a distinct
`tun_ip`**, and the server host must enable IP forwarding + NAT for clients to
reach beyond the tunnel (the binaries deliberately do not touch the routing
table or sysctls).

## Configuration

Both binaries take a JSON config file (`-c`) and/or CLI flags; **CLI flags
override file values**, and defaults fill the rest.

| Field | Server | Client | Default |
|-------|:------:|:------:|---------|
| `listen` (`--listen`) | ✓ (required) | — | — |
| `server` (`--server`) | — | ✓ (required) | — |
| `password` (`-k`) | ✓ | ✓ | — |
| `cipher` (`-m`) | ✓ | ✓ | `chacha20-poly1305` |
| `obfs` (`--obfs`) | ✓ | ✓ | `none` |
| `tun_ip` (`--tun-ip`) | ✓ (required) | ✓ (required) | — |
| `peer_ip` (`--peer-ip`) | — | ✓ (required) | — |
| `tun_netmask` (`--tun-netmask`) | ✓ | ✓ | `255.255.255.0` |
| `tun_name` (`--tun-name`) | ✓ | ✓ | OS picks |
| `mtu` (`--mtu`) | ✓ | ✓ | `1400` |
| `keepalive_secs` (`--keepalive-secs`) | — | ✓ | `25` |

### Example

Server (`server.json`):

```json
{ "listen": "0.0.0.0:8388", "password": "correct horse battery staple",
  "obfs": "quic", "tun_ip": "10.9.0.1", "tun_netmask": "255.255.255.0" }
```

Client (`client.json`):

```json
{ "server": "vpn.example.com:8388", "password": "correct horse battery staple",
  "obfs": "quic", "tun_ip": "10.9.0.2", "peer_ip": "10.9.0.1" }
```

```sh
sudo tsvpn-server -c server.json
sudo tsvpn-client -c client.json   # each client needs a distinct tun_ip
```

Creating a TUN device requires root (Linux) / elevated privileges. The
[`docker/`](../docker) end-to-end tests exercise both single- and multi-client
setups across every cipher and obfuscation mode.
