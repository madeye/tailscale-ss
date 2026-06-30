use ts_keys::NodePublicKey;

/// A handle for a tunnel peer.
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct PeerId(pub u32);

/// A symmetric pre-shared key for a peer.
///
/// In the ShadowVPN/shadowsocks AEAD scheme this is the per-peer master key from
/// which each datagram's subkey is derived. It is 32 bytes, which matches the key
/// length of the default `chacha20-poly1305` (and `aes-256-gcm`) cipher; ciphers
/// with a shorter key use the leading bytes.
pub type Psk = [u8; 32];

/// The cryptographic configuration for a tunnel peer.
pub struct PeerConfig {
    /// The peer's public key. Used purely as the peer's stable identity for
    /// routing and management; the ShadowVPN data plane is PSK-based and does
    /// not perform a public-key handshake.
    pub key: NodePublicKey,
    /// The pre-shared key (master key) shared with this peer. Both ends must
    /// configure the same value.
    pub psk: Psk,
}
