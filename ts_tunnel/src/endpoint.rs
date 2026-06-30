use std::collections::HashMap;
use std::time::Instant;

use ts_keys::{NodeKeyPair, NodePublicKey};
use ts_packet::PacketMut;
use ts_time::TimeRange;

use crate::config::{PeerConfig, PeerId};
use crate::crypto::{Cipher, decrypt_packet, encrypt_packet};
use crate::obfs::Obfuscator;

/// Minimum decrypted plaintext length we deliver to the local system.
///
/// The ShadowVPN keepalive convention sends a tiny (1-byte) encrypted datagram to
/// hold NAT/firewall mappings open; the receiver drops any decrypted payload
/// smaller than a 20-byte IPv4 header so the keepalive never reaches the local
/// delivery path. We apply the same floor for parity with the reference server.
const MIN_DELIVER_LEN: usize = 20;

/// Per-peer cryptographic state.
///
/// Unlike WireGuard there is no handshake, session rotation, or replay window:
/// the shadowsocks AEAD UDP scheme is stateless per datagram. A peer is just its
/// identity plus the pre-shared master key used to seal/open its datagrams.
struct Peer {
    id: PeerId,
    config: PeerConfig,
    /// Master key bytes (`config.psk` truncated to the cipher's key length).
    master_key: Vec<u8>,
}

impl Peer {
    fn new(id: PeerId, config: PeerConfig, cipher: Cipher) -> Self {
        let master_key = config.psk[..cipher.key_len()].to_vec();
        Self {
            id,
            config,
            master_key,
        }
    }
}

/// A tunnel endpoint capable of communicating with multiple remote peers using
/// the ShadowVPN protocol: a pre-shared-key (PSK) shadowsocks AEAD UDP scheme
/// with optional QUIC carrier obfuscation.
///
/// The endpoint is sans-I/O: it transforms packets handed to it and reports the
/// packets the caller should transmit or deliver, but performs no socket I/O and
/// holds no timers (the protocol is stateless).
pub struct Endpoint {
    /// Our own identity. Retained for management/identification; the data plane
    /// is symmetric-key and does not use it cryptographically.
    my_key: NodeKeyPair,
    /// The AEAD cipher used for every peer.
    cipher: Cipher,
    /// Carrier obfuscation applied to every datagram on the wire.
    obfs: Obfuscator,
    /// Peers indexed by their handle.
    peers: HashMap<PeerId, Peer>,
    /// Reverse index from a peer's public key to its handle.
    by_key: HashMap<NodePublicKey, PeerId>,
}

impl Endpoint {
    /// Construct a new endpoint with the given keypair, using the default cipher
    /// (`chacha20-poly1305`) and QUIC carrier obfuscation.
    pub fn new(my_key: NodeKeyPair) -> Self {
        Self::with_config(
            my_key,
            Cipher::ChaCha20Poly1305,
            Obfuscator::from_name("quic"),
        )
    }

    /// Construct a new endpoint with an explicit cipher and obfuscator.
    ///
    /// Both ends of the tunnel must agree on the cipher and obfuscation; a
    /// mismatched peer simply sees its datagrams fail to decode and dropped.
    pub fn with_config(my_key: NodeKeyPair, cipher: Cipher, obfs: Obfuscator) -> Self {
        Self {
            my_key,
            cipher,
            obfs,
            peers: HashMap::new(),
            by_key: HashMap::new(),
        }
    }

    /// The cipher this endpoint uses for all peers.
    pub fn cipher(&self) -> Cipher {
        self.cipher
    }

    /// Our own keypair.
    pub fn node_keys(&self) -> &NodeKeyPair {
        &self.my_key
    }

    /// Insert a peer if it doesn't exist, otherwise update the peer with the
    /// given `id` with the given config.
    ///
    /// Returns the old [`PeerConfig`] if there was one.
    ///
    /// # Panics
    ///
    /// If the [`NodePublicKey`] in the new [`PeerConfig`] collides with an
    /// existing key for a different [`PeerId`].
    pub fn upsert_peer(&mut self, id: PeerId, cfg: PeerConfig) -> Option<PeerConfig> {
        if let Some(existing) = self.by_key.get(&cfg.key)
            && *existing != id
        {
            panic!("nodekey collision");
        }

        let peer = Peer::new(id, cfg, self.cipher);
        let new_key = peer.config.key;

        match self.peers.insert(id, peer) {
            Some(old) => {
                if old.config.key != new_key {
                    self.by_key.remove(&old.config.key);
                    self.by_key.insert(new_key, id);
                }
                Some(old.config)
            }
            None => {
                self.by_key.insert(new_key, id);
                None
            }
        }
    }

    /// Remove the given peer.
    ///
    /// Returns whether the peer in question existed.
    pub fn remove_peer(&mut self, peer: PeerId) -> bool {
        match self.peers.remove(&peer) {
            None => false,
            Some(peer) => {
                self.by_key.remove(&peer.config.key);
                true
            }
        }
    }

    /// Encrypt packets and report the wire datagrams to send to each peer.
    ///
    /// Each plaintext packet becomes exactly one wire datagram
    /// (`obfs(salt ++ AEAD(plaintext))`). Unlike WireGuard there is no handshake
    /// or queueing: a packet to a known peer is encrypted and returned
    /// immediately.
    pub fn send(
        &mut self,
        packets: impl IntoIterator<Item = (PeerId, Vec<PacketMut>)>,
    ) -> SendResult {
        let mut ret = SendResult::default();
        for (peer_id, packets) in packets {
            let Some(peer) = self.peers.get(&peer_id) else {
                tracing::warn!(?peer_id, "no peer stored for id");
                continue;
            };

            tracing::debug!(
                ?peer_id,
                n_packets = packets.len(),
                "encrypting send packets"
            );

            let out = ret.to_peers.entry(peer_id).or_default();
            for packet in packets {
                match encrypt_packet(self.cipher, &peer.master_key, packet.as_ref()) {
                    Ok(datagram) => out.push(PacketMut::from(self.obfs.wrap(&datagram))),
                    Err(e) => tracing::error!(?peer_id, error = %e, "failed to encrypt packet"),
                }
            }
        }
        ret
    }

    /// Decrypt received wire datagrams and report the plaintext packets to
    /// deliver locally, tagged with the originating peer.
    ///
    /// Datagrams carry no peer identifier (the shadowsocks AEAD scheme has no
    /// session id), so each one is obfs-decoded and then trial-decrypted against
    /// each configured peer's master key. The AEAD tag authenticates the match,
    /// so the first peer whose key opens the datagram is the sender. Datagrams
    /// that no peer can open, or that decode to fewer than 20 bytes (a runt
    /// smaller than an IPv4 header, e.g. a keepalive), are dropped.
    pub fn recv(&mut self, packets: impl IntoIterator<Item = PacketMut>) -> RecvResult {
        let mut ret = RecvResult::default();

        for packet in packets {
            let Some(datagram) = self.obfs.unwrap(packet.as_ref()) else {
                tracing::trace!("dropping packet that failed obfs decode");
                continue;
            };

            let mut delivered = false;
            for peer in self.peers.values() {
                let Ok(plaintext) = decrypt_packet(self.cipher, &peer.master_key, &datagram) else {
                    continue;
                };

                delivered = true;
                if plaintext.len() < MIN_DELIVER_LEN {
                    // Keepalive / runt: authenticated but not a deliverable packet.
                    tracing::trace!(peer_id = ?peer.id, len = plaintext.len(), "dropping runt/keepalive");
                } else {
                    ret.to_local
                        .entry(peer.id)
                        .or_default()
                        .push(PacketMut::from(plaintext));
                }
                break;
            }

            if !delivered {
                tracing::trace!("dropping packet that no peer could decrypt");
            }
        }

        ret
    }

    /// Dispatch time-based events. The ShadowVPN data plane is stateless and has
    /// no timers, so this is a no-op retained for API compatibility.
    pub fn dispatch_events(&mut self, _now: Instant) -> EventResult {
        EventResult::default()
    }

    /// The next time range in which [`Endpoint::dispatch_events`] should be
    /// called. Always `None`: the stateless data plane schedules no events.
    pub fn next_event(&self) -> Option<TimeRange> {
        None
    }

    /// Return the node key for the selected peer.
    pub fn peer_key(&self, id: PeerId) -> Option<NodePublicKey> {
        Some(self.peers.get(&id)?.config.key)
    }

    /// Return the peer id that has the selected node key.
    pub fn peer_id(&self, key: NodePublicKey) -> Option<PeerId> {
        self.by_key.get(&key).copied()
    }
}

/// The outcome of attempting to send packets to peers.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct SendResult {
    /// Wire datagrams to be sent to remote peers.
    pub to_peers: HashMap<PeerId, Vec<PacketMut>>,
}

/// The outcome of processing received packets.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct RecvResult {
    /// Valid packets from peers to be delivered locally.
    pub to_local: HashMap<PeerId, Vec<PacketMut>>,
    /// Wire datagrams to be sent to remote peers. Always empty for ShadowVPN
    /// (there is no handshake to respond to), retained for API compatibility.
    pub to_peers: HashMap<PeerId, Vec<PacketMut>>,
}

/// The outcome of processing time-based events. Always empty for ShadowVPN.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct EventResult {
    /// Wire datagrams to be sent to remote peers.
    pub to_peers: HashMap<PeerId, Vec<PacketMut>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PeerConfig;

    fn peer_cfg(key: NodePublicKey, psk: Psk) -> PeerConfig {
        PeerConfig { key, psk }
    }

    use crate::config::Psk;

    /// Two endpoints sharing a PSK round-trip packets in both directions, for
    /// every cipher, with QUIC obfuscation on the wire.
    #[test]
    fn two_endpoints_round_trip() {
        for cipher in [
            Cipher::Aes128Gcm,
            Cipher::Aes256Gcm,
            Cipher::ChaCha20Poly1305,
        ] {
            let (a_static, b_static) = (NodeKeyPair::new(), NodeKeyPair::new());
            let psk: Psk = rand::random();

            let mut a_ep =
                Endpoint::with_config(a_static.clone(), cipher, Obfuscator::from_name("quic"));
            let mut b_ep =
                Endpoint::with_config(b_static.clone(), cipher, Obfuscator::from_name("quic"));

            let a_peer = PeerId(1);
            let b_peer = PeerId(1);

            assert!(
                a_ep.upsert_peer(a_peer, peer_cfg(b_static.public, psk))
                    .is_none()
            );
            assert!(
                b_ep.upsert_peer(b_peer, peer_cfg(a_static.public, psk))
                    .is_none()
            );

            // A sends two packets to B. Both are encrypted immediately (no handshake).
            let payloads = [
                PacketMut::from(vec![0x45u8; 40]),
                PacketMut::from(vec![0x46u8; 60]),
            ];
            let a_acts = a_ep.send([(a_peer, payloads.to_vec())]);
            let wire = a_acts.to_peers.get(&a_peer).expect("packets for peer");
            assert_eq!(wire.len(), 2, "one datagram per packet ({})", cipher.name());

            // B receives and decrypts them, attributing to the right peer.
            let b_acts = b_ep.recv(wire.clone());
            assert!(b_acts.to_peers.is_empty(), "no handshake response");
            let got = b_acts.to_local.get(&b_peer).expect("delivered packets");
            assert_eq!(
                got,
                &payloads,
                "B recovered A's packets ({})",
                cipher.name()
            );

            // B replies; A decrypts.
            let reply = PacketMut::from(vec![0x47u8; 50]);
            let b_acts = b_ep.send([(b_peer, vec![reply.clone()])]);
            let wire = b_acts.to_peers.get(&b_peer).expect("packets for peer");
            let a_acts = a_ep.recv(wire.clone());
            let got = a_acts.to_local.get(&a_peer).expect("delivered packets");
            assert_eq!(got, &[reply], "A recovered B's reply ({})", cipher.name());
        }
    }

    /// A datagram encrypted under a different PSK is dropped, not delivered.
    #[test]
    fn wrong_psk_is_dropped() {
        let (a_static, b_static) = (NodeKeyPair::new(), NodeKeyPair::new());
        let cipher = Cipher::ChaCha20Poly1305;

        let mut a_ep = Endpoint::with_config(a_static.clone(), cipher, Obfuscator::None);
        let mut b_ep = Endpoint::with_config(b_static.clone(), cipher, Obfuscator::None);

        a_ep.upsert_peer(PeerId(1), peer_cfg(b_static.public, [1u8; 32]));
        b_ep.upsert_peer(PeerId(1), peer_cfg(a_static.public, [2u8; 32]));

        let wire = a_ep.send([(PeerId(1), vec![PacketMut::from(vec![0x45u8; 40])])]);
        let datagrams = wire.to_peers.get(&PeerId(1)).unwrap();
        let b_acts = b_ep.recv(datagrams.clone());
        assert!(b_acts.to_local.is_empty(), "mismatched PSK must drop");
    }

    /// Keepalive-sized plaintext (< 20 bytes) authenticates but is not delivered.
    #[test]
    fn keepalive_is_not_delivered() {
        let (a_static, b_static) = (NodeKeyPair::new(), NodeKeyPair::new());
        let cipher = Cipher::ChaCha20Poly1305;
        let psk: Psk = rand::random();

        let mut a_ep = Endpoint::with_config(a_static.clone(), cipher, Obfuscator::None);
        let mut b_ep = Endpoint::with_config(b_static.clone(), cipher, Obfuscator::None);
        a_ep.upsert_peer(PeerId(1), peer_cfg(b_static.public, psk));
        b_ep.upsert_peer(PeerId(1), peer_cfg(a_static.public, psk));

        let wire = a_ep.send([(PeerId(1), vec![PacketMut::from(vec![0x00])])]);
        let datagrams = wire.to_peers.get(&PeerId(1)).unwrap();
        let b_acts = b_ep.recv(datagrams.clone());
        assert!(
            b_acts.to_local.is_empty(),
            "keepalive must not be delivered"
        );
    }

    /// Peer management: upsert returns the old config, key reverse-lookup works,
    /// and removal forgets the peer.
    #[test]
    fn peer_management() {
        let me = NodeKeyPair::new();
        let mut ep = Endpoint::new(me);
        let peer_key = NodeKeyPair::new().public;

        assert!(
            ep.upsert_peer(PeerId(7), peer_cfg(peer_key, [9u8; 32]))
                .is_none()
        );
        assert_eq!(ep.peer_id(peer_key), Some(PeerId(7)));
        assert_eq!(ep.peer_key(PeerId(7)), Some(peer_key));

        let old = ep.upsert_peer(PeerId(7), peer_cfg(peer_key, [10u8; 32]));
        assert_eq!(old.map(|c| c.psk), Some([9u8; 32]));

        assert!(ep.remove_peer(PeerId(7)));
        assert!(!ep.remove_peer(PeerId(7)));
        assert_eq!(ep.peer_id(peer_key), None);
    }
}
