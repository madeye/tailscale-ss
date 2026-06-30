//! `tsvpn-server`: a multi-client ShadowVPN server built on `ts_tunnel`.
//!
//! It binds a UDP port and a TUN device and serves **many clients at once**.
//! All clients share one pre-shared password, so the server cannot tell them
//! apart cryptographically; instead it demultiplexes them by their **inner
//! tunnel IP** (ShadowVPN's default mode):
//!
//! * inbound (UDP → TUN): decrypt, learn `inner source IP → client UDP address`,
//!   then write the packet to the TUN so the host stack routes it;
//! * outbound (TUN → UDP): look up the packet's inner destination IP in that
//!   table and encrypt it to the matching client (dropping packets for clients
//!   that have not been seen yet).
//!
//! Each client must therefore use a distinct `tun_ip`, and the host must enable
//! IP forwarding + NAT for tunneled clients to reach the wider network (this
//! binary deliberately does not touch the routing table or sysctls).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use ts_packet::PacketMut;
use ts_vpn::config::{ServerArgs, init_tracing};
use ts_vpn::crypto::Crypto;
use ts_vpn::net::bind_udp;
use ts_vpn::tun::Tun;
use ts_vpn::{MAX_DATAGRAM, MAX_IP_PACKET, MIN_IP_PACKET};

use clap::Parser;

/// Maps each client's inner tunnel IP to the UDP endpoint it was last seen from.
type Clients = Arc<Mutex<HashMap<Ipv4Addr, SocketAddr>>>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let cfg = ServerArgs::parse().resolve()?;

    let crypto = Arc::new(Crypto::new(&cfg.password, &cfg.cipher, &cfg.obfs)?);
    let tun = Arc::new(Tun::create(
        cfg.tun_name.as_deref(),
        cfg.tun_ip,
        cfg.tun_netmask,
        None, // multi-client: route the whole subnet, no point-to-point peer
        cfg.mtu,
    )?);
    let socket = Arc::new(bind_udp(cfg.listen).await?);
    let clients: Clients = Arc::new(Mutex::new(HashMap::new()));

    tracing::info!(
        tun = %tun.name().unwrap_or_default(),
        listen = %cfg.listen,
        tun_ip = %cfg.tun_ip,
        cipher = %crypto.cipher().name(),
        obfs = %cfg.obfs,
        "tsvpn-server up",
    );

    // Inbound: UDP -> decrypt -> learn client -> TUN.
    let downlink = {
        let (crypto, tun, socket, clients) =
            (crypto.clone(), tun.clone(), socket.clone(), clients.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            loop {
                let (n, src) = socket.recv_from(&mut buf).await?;
                let Some(plaintext) = crypto.open(&buf[..n]) else {
                    tracing::trace!(%src, "drop: failed to decrypt/de-obfuscate");
                    continue;
                };
                if plaintext.len() < MIN_IP_PACKET {
                    // Keepalive or runt: authenticated, but not a deliverable packet.
                    continue;
                }
                let pkt = PacketMut::from(plaintext);
                let Some(IpAddr::V4(inner_src)) = pkt.get_src_addr() else {
                    continue;
                };
                clients.lock().unwrap().insert(inner_src, src);
                if let Err(e) = tun.send(pkt.as_ref()).await {
                    tracing::trace!(error = %e, "tun write failed");
                }
            }
            #[allow(unreachable_code)]
            Ok::<(), std::io::Error>(())
        })
    };

    // Outbound: TUN -> route by inner dest IP -> encrypt -> UDP.
    let uplink = {
        let (crypto, tun, socket, clients) = (crypto, tun, socket, clients);
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_IP_PACKET];
            loop {
                let n = tun.recv(&mut buf).await?;
                let pkt = PacketMut::from(buf[..n].to_vec());
                let Some(IpAddr::V4(inner_dst)) = pkt.get_dst_addr() else {
                    continue;
                };
                let dst = clients.lock().unwrap().get(&inner_dst).copied();
                let Some(dst) = dst else {
                    tracing::trace!(%inner_dst, "drop: no client for destination");
                    continue;
                };
                match crypto.seal(pkt.as_ref()) {
                    Ok(wire) => {
                        socket.send_to(&wire, dst).await?;
                    }
                    Err(e) => tracing::warn!(error = %e, "failed to encrypt packet"),
                }
            }
            #[allow(unreachable_code)]
            Ok::<(), std::io::Error>(())
        })
    };

    tokio::select! {
        r = downlink => r??,
        r = uplink => r??,
    }
    Ok(())
}
