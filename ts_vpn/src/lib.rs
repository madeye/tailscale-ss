//! A ShadowVPN server and client built on [`ts_tunnel`].
//!
//! This crate turns the sans-I/O [`ts_tunnel`] data plane into runnable
//! daemons. It ships two binaries:
//!
//! * `tsvpn-server` — binds a UDP port and a TUN device and relays for **many
//!   clients at once**, demultiplexing them by their inner tunnel IP (all
//!   clients share one pre-shared password, as in ShadowVPN's default mode).
//! * `tsvpn-client` — a single-peer node that tunnels its TUN traffic to the
//!   server and sends periodic keepalives.
//!
//! Both reuse the same per-datagram crypto and carrier obfuscation as the rest
//! of the data plane via [`crypto::Crypto`] (a thin wrapper over the
//! [`ts_tunnel`] shadowsocks-AEAD primitives), the same async [`tun::Tun`]
//! wrapper, and the same JSON-plus-CLI [`config`] handling.

pub mod config;
pub mod crypto;
pub mod net;
pub mod tun;

/// Largest plaintext IP packet we read from a TUN device in one go.
pub const MAX_IP_PACKET: usize = 65535;

/// Receive-buffer size for the encrypted (UDP) side: the largest plaintext plus
/// headroom for the salt, AEAD tag, and obfuscation header.
pub const MAX_DATAGRAM: usize = MAX_IP_PACKET + 256;

/// Minimum decrypted length we treat as a real IP packet. Shorter payloads
/// (e.g. the 1-byte keepalive) authenticate but are never written to the TUN.
pub const MIN_IP_PACKET: usize = 20;

/// The single-byte keepalive plaintext a client periodically sends so stateful
/// NAT/firewall mappings to the server stay open.
pub const KEEPALIVE_PAYLOAD: &[u8] = &[0u8];
