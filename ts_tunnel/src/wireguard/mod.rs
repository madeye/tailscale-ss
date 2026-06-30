//! The WireGuard data-plane backend.
//!
//! A partial implementation of the [WireGuard](https://www.wireguard.com/)
//! specification — Noise IKpsk2 handshake, session lifecycle, cookie/MAC reply,
//! and replay protection — interoperable with other WireGuard clients (including
//! the Tailscale Go client, and therefore Tailscale/Headscale coordination).

mod endpoint;
mod handshake;
mod macs;
mod messages;
mod replay;
mod session;
mod time;

pub use endpoint::Endpoint;
