//! Result types shared by both data-plane backends.
//!
//! The WireGuard and ShadowVPN [`Endpoint`](crate::Endpoint)s produce the same
//! shapes — maps of [`PeerId`] to packets — so these are defined once and reused
//! by both, which also lets the top-level dispatcher return them directly.

use std::collections::HashMap;

use ts_packet::PacketMut;

use crate::config::PeerId;

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
    /// Wire datagrams to be sent to remote peers (e.g. a WireGuard handshake
    /// response; always empty for the stateless ShadowVPN backend).
    pub to_peers: HashMap<PeerId, Vec<PacketMut>>,
}

/// The outcome of processing time-based events.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct EventResult {
    /// Wire datagrams to be sent to remote peers.
    pub to_peers: HashMap<PeerId, Vec<PacketMut>>,
}

/// Internal helper for accumulating per-peer outbound packets.
pub(crate) trait QueueToPeer {
    fn queue_to_peer(&mut self, peer: PeerId) -> &mut Vec<PacketMut>;
}

impl QueueToPeer for SendResult {
    fn queue_to_peer(&mut self, peer: PeerId) -> &mut Vec<PacketMut> {
        self.to_peers.entry(peer).or_default()
    }
}

impl RecvResult {
    pub(crate) fn queue_to_local(&mut self, peer: PeerId) -> &mut Vec<PacketMut> {
        self.to_local.entry(peer).or_default()
    }
}

impl QueueToPeer for RecvResult {
    fn queue_to_peer(&mut self, peer: PeerId) -> &mut Vec<PacketMut> {
        self.to_peers.entry(peer).or_default()
    }
}

impl QueueToPeer for EventResult {
    fn queue_to_peer(&mut self, peer: PeerId) -> &mut Vec<PacketMut> {
        self.to_peers.entry(peer).or_default()
    }
}
