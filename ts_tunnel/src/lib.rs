#![doc = include_str!("../README.md")]

mod config;
mod results;
mod shadowvpn;
mod wireguard;

use std::time::Instant;

use ts_packet::PacketMut;
use ts_time::TimeRange;

pub use ts_keys::{NodeKeyPair, NodePrivateKey, NodePublicKey};

pub use crate::{
    config::{PeerConfig, PeerId, Psk},
    results::{EventResult, RecvResult, SendResult},
    // Low-level ShadowVPN primitives, reused by the `ts_vpn` daemons.
    shadowvpn::{
        Cipher, CryptoError, Obfuscator, QuicObfs, decrypt_packet, encrypt_packet, evp_bytes_to_key,
    },
};

/// Which data-plane protocol an [`Endpoint`] speaks.
///
/// Both ends of a tunnel must use the same protocol. Choose [`Protocol::Wireguard`]
/// for interoperability with WireGuard peers — i.e. the Tailscale Go client and
/// anything coordinated by a Tailscale/Headscale control plane — or
/// [`Protocol::Shadowvpn`] for the obfuscation-capable pre-shared-key tunnel
/// (which is not WireGuard-compatible).
#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub enum Protocol {
    /// WireGuard (Noise IKpsk2). The default; interoperable with WireGuard peers.
    #[default]
    Wireguard,
    /// ShadowVPN (shadowsocks AEAD UDP + optional QUIC obfuscation).
    Shadowvpn,
}

impl Protocol {
    /// Parse a protocol from a lowercase name (`"wireguard"` / `"shadowvpn"`).
    ///
    /// `"wg"` and `"ss"` are accepted as aliases. Returns `None` for any other
    /// value.
    pub fn from_name(name: &str) -> Option<Protocol> {
        match name {
            "wireguard" | "wg" => Some(Protocol::Wireguard),
            "shadowvpn" | "ss" => Some(Protocol::Shadowvpn),
            _ => None,
        }
    }

    /// The canonical lowercase name of this protocol.
    pub fn name(self) -> &'static str {
        match self {
            Protocol::Wireguard => "wireguard",
            Protocol::Shadowvpn => "shadowvpn",
        }
    }
}

/// A data-plane endpoint that communicates with multiple peers using a
/// selectable protocol.
///
/// This is a thin dispatcher over the two backends (WireGuard and ShadowVPN),
/// which share an identical public interface. Select the protocol at
/// construction with [`Endpoint::new`]; all other methods behave the same
/// regardless of backend.
pub enum Endpoint {
    /// A WireGuard endpoint.
    Wireguard(wireguard::Endpoint),
    /// A ShadowVPN endpoint.
    Shadowvpn(shadowvpn::Endpoint),
}

impl Endpoint {
    /// Construct an endpoint speaking the given `protocol` with the given keypair.
    pub fn new(protocol: Protocol, my_key: NodeKeyPair) -> Self {
        match protocol {
            Protocol::Wireguard => Endpoint::Wireguard(wireguard::Endpoint::new(my_key)),
            Protocol::Shadowvpn => Endpoint::Shadowvpn(shadowvpn::Endpoint::new(my_key)),
        }
    }

    /// The protocol this endpoint speaks.
    pub fn protocol(&self) -> Protocol {
        match self {
            Endpoint::Wireguard(_) => Protocol::Wireguard,
            Endpoint::Shadowvpn(_) => Protocol::Shadowvpn,
        }
    }

    /// Insert or update the peer with the given `id`. Returns the old config, if any.
    pub fn upsert_peer(&mut self, id: PeerId, cfg: PeerConfig) -> Option<PeerConfig> {
        match self {
            Endpoint::Wireguard(e) => e.upsert_peer(id, cfg),
            Endpoint::Shadowvpn(e) => e.upsert_peer(id, cfg),
        }
    }

    /// Remove the given peer. Returns whether it existed.
    pub fn remove_peer(&mut self, peer: PeerId) -> bool {
        match self {
            Endpoint::Wireguard(e) => e.remove_peer(peer),
            Endpoint::Shadowvpn(e) => e.remove_peer(peer),
        }
    }

    /// Encrypt packets and report the wire datagrams to send to each peer.
    pub fn send(
        &mut self,
        packets: impl IntoIterator<Item = (PeerId, Vec<PacketMut>)>,
    ) -> SendResult {
        match self {
            Endpoint::Wireguard(e) => e.send(packets),
            Endpoint::Shadowvpn(e) => e.send(packets),
        }
    }

    /// Decrypt received wire datagrams and report the packets to deliver locally.
    pub fn recv(&mut self, packets: impl IntoIterator<Item = PacketMut>) -> RecvResult {
        match self {
            Endpoint::Wireguard(e) => e.recv(packets),
            Endpoint::Shadowvpn(e) => e.recv(packets),
        }
    }

    /// Dispatch time-based events due at or before `now`.
    pub fn dispatch_events(&mut self, now: Instant) -> EventResult {
        match self {
            Endpoint::Wireguard(e) => e.dispatch_events(now),
            Endpoint::Shadowvpn(e) => e.dispatch_events(now),
        }
    }

    /// The next time range in which [`Endpoint::dispatch_events`] should be called.
    pub fn next_event(&self) -> Option<TimeRange> {
        match self {
            Endpoint::Wireguard(e) => e.next_event(),
            Endpoint::Shadowvpn(e) => e.next_event(),
        }
    }

    /// Return the node key for the selected peer.
    pub fn peer_key(&self, id: PeerId) -> Option<NodePublicKey> {
        match self {
            Endpoint::Wireguard(e) => e.peer_key(id),
            Endpoint::Shadowvpn(e) => e.peer_key(id),
        }
    }

    /// Return the peer id that has the selected node key.
    pub fn peer_id(&self, key: NodePublicKey) -> Option<PeerId> {
        match self {
            Endpoint::Wireguard(e) => e.peer_id(key),
            Endpoint::Shadowvpn(e) => e.peer_id(key),
        }
    }
}
