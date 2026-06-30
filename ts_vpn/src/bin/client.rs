//! `tsvpn-client`: a ShadowVPN client built on `ts_tunnel`.
//!
//! It brings up a TUN device and tunnels its traffic to a single server:
//!
//! * outbound (TUN → UDP): encrypt each IP packet and send it to the server;
//! * inbound (UDP → TUN): decrypt datagrams from the server and write them out;
//! * keepalive: periodically send a tiny encrypted datagram so stateful
//!   NAT/firewall mappings to the server stay open.
//!
//! Routing the desired destinations into the TUN (and keeping a host route to
//! the server over the real link) is left to the operator — this binary does
//! not modify the system routing table.

use ts_vpn::config::{ClientArgs, init_tracing};
use ts_vpn::crypto::Crypto;
use ts_vpn::net::{bind_udp, resolve};
use ts_vpn::tun::Tun;
use ts_vpn::{KEEPALIVE_PAYLOAD, MAX_DATAGRAM, MAX_IP_PACKET, MIN_IP_PACKET};

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let cfg = ClientArgs::parse().resolve()?;

    let crypto = Arc::new(Crypto::new(&cfg.password, &cfg.cipher, &cfg.obfs)?);
    let tun = Arc::new(Tun::create(
        cfg.tun_name.as_deref(),
        cfg.tun_ip,
        cfg.tun_netmask,
        Some(cfg.peer_ip), // point-to-point to the server's tunnel IP
        cfg.mtu,
    )?);

    let server = resolve(&cfg.server).await?;
    let bind: SocketAddr = (Ipv4Addr::UNSPECIFIED, 0).into();
    let socket = Arc::new(bind_udp(bind).await?);
    socket.connect(server).await?;

    tracing::info!(
        tun = %tun.name().unwrap_or_default(),
        %server,
        tun_ip = %cfg.tun_ip,
        peer_ip = %cfg.peer_ip,
        cipher = %crypto.cipher().name(),
        obfs = %cfg.obfs,
        keepalive_secs = cfg.keepalive_secs,
        "tsvpn-client up",
    );

    // Outbound: TUN -> encrypt -> server.
    let uplink = {
        let (crypto, tun, socket) = (crypto.clone(), tun.clone(), socket.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_IP_PACKET];
            loop {
                let n = tun.recv(&mut buf).await?;
                match crypto.seal(&buf[..n]) {
                    Ok(wire) => {
                        socket.send(&wire).await?;
                    }
                    Err(e) => tracing::warn!(error = %e, "failed to encrypt packet"),
                }
            }
            #[allow(unreachable_code)]
            Ok::<(), std::io::Error>(())
        })
    };

    // Inbound: server -> decrypt -> TUN.
    let downlink = {
        let (crypto, tun, socket) = (crypto.clone(), tun.clone(), socket.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            loop {
                let n = socket.recv(&mut buf).await?;
                let Some(plaintext) = crypto.open(&buf[..n]) else {
                    tracing::trace!("drop: failed to decrypt/de-obfuscate");
                    continue;
                };
                if plaintext.len() < MIN_IP_PACKET {
                    continue;
                }
                tun.send(&plaintext).await?;
            }
            #[allow(unreachable_code)]
            Ok::<(), std::io::Error>(())
        })
    };

    // Keepalive: a tiny encrypted datagram on an interval (0 disables).
    let keepalive = {
        let (crypto, socket, secs) = (crypto, socket, cfg.keepalive_secs);
        tokio::spawn(async move {
            if secs == 0 {
                return Ok::<(), std::io::Error>(());
            }
            let mut tick = tokio::time::interval(Duration::from_secs(secs));
            loop {
                tick.tick().await;
                if let Ok(wire) = crypto.seal(KEEPALIVE_PAYLOAD)
                    && let Err(e) = socket.send(&wire).await
                {
                    tracing::trace!(error = %e, "keepalive send failed");
                }
            }
        })
    };

    tokio::select! {
        r = uplink => r??,
        r = downlink => r??,
        r = keepalive => r??,
    }
    Ok(())
}
