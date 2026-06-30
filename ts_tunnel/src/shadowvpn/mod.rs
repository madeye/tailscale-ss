//! The ShadowVPN data-plane backend.
//!
//! The [ShadowVPN](https://github.com/madeye/shadowvpn) protocol: a
//! pre-shared-key (PSK) tunnel using the shadowsocks AEAD UDP wire scheme
//! (`salt ++ AEAD`, HKDF-SHA1 `ss-subkey`, all-zero nonce) with optional QUIC
//! carrier obfuscation. Stateless per datagram — no handshake, sessions, or
//! timers. Not wire-compatible with WireGuard.

mod crypto;
mod endpoint;
mod obfs;

pub use crypto::{Cipher, CryptoError, decrypt_packet, encrypt_packet, evp_bytes_to_key};
pub use endpoint::Endpoint;
pub use obfs::{Obfuscator, QuicObfs};
