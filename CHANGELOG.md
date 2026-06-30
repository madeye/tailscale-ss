# Changelog

Record breaking or significant changes here. All dates are UTC.

## Unreleased - June 2026

Put changes for the upcoming release here!

- Changed (`ts_tunnel`): the data-plane protocol is now **pluggable** behind a
  `Protocol` enum and a common `Endpoint` interface, with two backends:
  **WireGuard** (the existing partial Noise-IKpsk2 implementation — the default,
  interoperable with WireGuard peers and therefore with a Tailscale/Headscale
  control plane) and **[ShadowVPN](https://github.com/madeye/shadowvpn)** (a
  pre-shared-key tunnel using the shadowsocks AEAD UDP wire scheme —
  `salt ++ AEAD`, HKDF-SHA1 `ss-subkey`, zero nonce — with optional QUIC carrier
  obfuscation). `ts_dataplane::DataPlane::wireguard` is renamed to `tunnel`, and
  `DataPlane::new` now takes a `Protocol`.
- Added: the data plane selects its protocol via the `TS_DATAPLANE_PROTOCOL`
  environment variable (`wireguard` | `shadowvpn`), defaulting to WireGuard for
  Tailscale/Headscale compatibility.
- Added (`ts_vpn`): a new crate providing runnable ShadowVPN daemons built on
  `ts_tunnel` — `tsvpn-server` and `tsvpn-client` binaries with JSON-plus-CLI
  config and client keepalives. The server is **multi-client**: all peers share
  one pre-shared password and the server demultiplexes them by inner tunnel IP
  (ShadowVPN's default mode), so each client uses a distinct `tun_ip`.
- Added: Docker end-to-end tests for the data plane under `docker/`, driving the
  real `tsvpn-server`/`tsvpn-client` binaries. `docker/run-e2e.sh` runs a server
  and a client, each with its own TUN device, and pings through the encrypted
  tunnel; `docker/run-e2e-multi.sh` runs a server with two simultaneous clients.
  They pass for every cipher (`aes-128-gcm`, `aes-256-gcm`, `chacha20-poly1305`)
  and obfuscation mode (`none`, `quic`, `base64`).
- Added (Rust API): Experimental support for user-defined tailnet SSH servers using
  [`russh`](https://docs.rs/russh/latest/russh/) and (optionally)
  [`ratatui`](https://docs.rs/ratatui/latest/ratatui/).
  [#178](https://github.com/tailscale/tailscale-rs/pull/178).

## [0.3.3](https://github.com/tailscale/tailscale-rs/releases/tag/v0.3.3) - 2026-05-20

- Fixed: don't generate `tailscale.h` on publish.
  [#196](https://github.com/tailscale/tailscale-rs/pull/196).
- Fixed: Elixir CI/CD publishing infrastructure.
  [#197](https://github.com/tailscale/tailscale-rs/pull/197).

## [0.3.2](https://github.com/tailscale/tailscale-rs/releases/tag/v0.3.2) - 2026-05-20

Partial release; this version is tagged and published to PyPI, but was not published to crates.io or hex.pm.

- Fixed: removed `std` dependency from `ts_netstack_smoltcp_core`.
  [#194](https://github.com/tailscale/tailscale-rs/pull/194).

## [0.3.1](https://github.com/tailscale/tailscale-rs/releases/tag/v0.3.1) - 2026-05-20

Partial release; this version is tagged and published to PyPI, but was not published to crates.io or hex.pm.

- Fixed: Python CI/CD publishing infrastructure.
  [#191](https://github.com/tailscale/tailscale-rs/pull/191).
- Fixed: Rust CI/CD publishing infrastructure.
  [#193](https://github.com/tailscale/tailscale-rs/pull/193).

## [0.3.0](https://github.com/tailscale/tailscale-rs/releases/tag/v0.3.0) - 2026-05-19

Internal release; this version is tagged, but was not published to any package repositories.

- **Breaking** (Rust API): exports `config`, `netstack`, and `keys` modules and moves some functionality
  from the crate root to these modules. Replaces `load_key_file` with `Config::default_with_key_file`.
  Exports a few more types so fewer users will have to depend on internal crates.
  [#105](https://github.com/tailscale/tailscale-rs/pull/105).
- **Breaking** (Rust API, ts_netstack_smoltcp, ts_control): errors have been refactored, some minor
  changes to APIs around errors.
  [#154](https://github.com/tailscale/tailscale-rs/pull/154).
- Added (Rust API): load configuration options from environment variables. Adds `config::auth_key_from_env`
  and `config::Config::default_from_env`.
  [#97](https://github.com/tailscale/tailscale-rs/pull/97).
- Added (Rust API, Python, Elixir): `Device::self_node`.
  [#147](https://github.com/tailscale/tailscale-rs/pull/147).
- Added (Python and Elixir bindings): optional configuration parameters.
  [#140](https://github.com/tailscale/tailscale-rs/pull/140) and [#148](https://github.com/tailscale/tailscale-rs/pull/148).
- Fixed (ts_netstack_smoltcp): big improvement to TCP accept performance.
  [#141](https://github.com/tailscale/tailscale-rs/pull/141).
- Updated MSRV to 1.94.1.
  [#181](https://github.com/tailscale/tailscale-rs/pull/181).

## [0.2.0](https://github.com/tailscale/tailscale-rs/releases/tag/v0.2.0) - 2026-04-15

Initial public release.

## 0.1.0

Hello, world!
