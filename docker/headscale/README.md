# Headscale integration test

Proves a `tailscale-ss` node registers against a [Headscale](https://github.com/juanfont/headscale)
control plane and carries real traffic over the **pluggable data plane** — ShadowVPN (PSK +
QUIC obfuscation) or WireGuard.

[`run-headscale-e2e.sh`](run-headscale-e2e.sh):

1. builds a Headscale image with [`config.yaml`](config.yaml) + an allow-all [`policy.json`](policy.json)
   baked in, and starts it (control plane on host port `18080`);
2. creates a user and a reusable pre-auth key;
3. builds the [`tcp_echo`](../../examples/tcp_echo) and [`tcp_probe`](../../examples/tcp_probe)
   examples and registers them as two nodes;
4. has the probe node connect to the echo node and asserts a TCP echo round-trip.

```sh
./docker/headscale/run-headscale-e2e.sh                 # ShadowVPN data plane (default)
PROTOCOL=wireguard ./docker/headscale/run-headscale-e2e.sh
```

The data-plane protocol is selected with the `TS_DATAPLANE_PROTOCOL` env var the harness sets; with
`shadowvpn` the tunnel uses the shadowsocks AEAD UDP scheme with QUIC obfuscation.

## Notes

- The nodes run on the host (the overlay uses a userspace netstack, so no TUN/root is needed) while
  Headscale runs in Docker.
- Data-plane traffic relays through **Tailscale's public DERP servers**, so the test needs outbound
  internet. (Direct/NAT-traversal paths are not yet implemented in this repo.)
- The control plane is plain HTTP; the examples are built with the `insecure-keyfetch` feature so the
  control machine key may be fetched over `http://` instead of forced `https://`. **Do not enable
  that feature in production.**
- This is a local/manual integration test (it depends on Docker + external DERP connectivity), not a
  CI gate.
