A secure packet tunnel over UDP, with a **pluggable** data-plane protocol.

This crate protects data-plane traffic with one of two interchangeable backends, chosen with the
[`Protocol`] enum and driven through a common [`Endpoint`] interface:

- **WireGuard** ([`Protocol::Wireguard`], the default) — a partial implementation of
  [WireGuard](https://www.wireguard.com/): the Noise IKpsk2 handshake, session lifecycle, cookie/MAC
  reply, and replay protection. Interoperable with other WireGuard clients, including the Tailscale Go
  client and anything coordinated by a Tailscale or [Headscale](https://github.com/juanfont/headscale)
  control plane.
- **ShadowVPN** ([`Protocol::Shadowvpn`]) — the [ShadowVPN](https://github.com/madeye/shadowvpn)
  protocol: a pre-shared-key (PSK) tunnel using the shadowsocks AEAD **UDP** wire scheme
  (`salt ++ AEAD`, HKDF-SHA1 `ss-subkey`, all-zero nonce) with optional QUIC carrier obfuscation.
  Stateless per datagram — no handshake, sessions, or timers. **Not** wire-compatible with WireGuard.

Both ends of a tunnel must use the same protocol. Pick by what you need: WireGuard for
interoperability with the Tailscale/Headscale ecosystem, or ShadowVPN for an obfuscation-capable PSK
tunnel.

```rust,ignore
use ts_tunnel::{Endpoint, Protocol, NodeKeyPair};

// WireGuard (default; interoperable with Tailscale/Headscale peers):
let wg = Endpoint::new(Protocol::Wireguard, NodeKeyPair::new());
// ShadowVPN (PSK + QUIC obfuscation):
let ss = Endpoint::new(Protocol::Shadowvpn, NodeKeyPair::new());
```

The two backends share an identical public API ([`Endpoint::upsert_peer`], [`send`](Endpoint::send),
[`recv`](Endpoint::recv), [`dispatch_events`](Endpoint::dispatch_events),
[`next_event`](Endpoint::next_event), …), so callers are protocol-agnostic once an endpoint is
constructed.

## Sans I/O

This crate is implemented in the [Sans I/O](https://sans-io.readthedocs.io/) style: an [`Endpoint`]
processes packets provided to it and returns the actions the caller should perform (transmit
encrypted datagrams to a peer, deliver decrypted packets locally, schedule a timer), but performs no
socket I/O itself. This decouples each protocol's state machine from the I/O strategy.

## Security limitations

This crate has not been subjected to a code audit by expert cryptography engineers. Conservatively,
assume there could be a critical security hole that exposes your traffic to attackers.

It operates on packets with no awareness of IP addressing: packets are opaque byte sequences tagged
by destination/origin peer ID. It does not enforce a 1:1 IP↔peer association or track underlay
endpoint addresses/roaming — the caller provides those.

The ShadowVPN backend additionally has no forward secrecy: its PSK is a symmetric secret shared by
both ends, so a compromised PSK exposes past and future traffic, and anyone holding it can read or
forge traffic. The WireGuard backend performs an authenticated key exchange and does not share these
properties.
