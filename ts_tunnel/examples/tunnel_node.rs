//! A minimal point-to-point VPN node built on [`ts_tunnel::Endpoint`].
//!
//! This example is the moving part of the Docker end-to-end test
//! (`docker/run-e2e.sh`): it wires a TUN device to a UDP socket through the
//! ShadowVPN data plane so real IP packets traverse the encrypted tunnel.
//!
//! ```text
//! TUN (read IP packet) -> Endpoint::send -> obfs(salt ++ AEAD) -> UDP socket
//! UDP socket -> Endpoint::recv -> decrypt + de-obfs -> TUN (write IP packet)
//! ```
//!
//! One binary plays both roles. With `--connect <host:port>` it is a **client**
//! that sends to a fixed server address; otherwise it is a **server** that binds
//! `--listen` and learns the client's address from the first datagram it
//! authenticates (the data plane carries no addressing, so the node tracks the
//! peer's UDP endpoint itself — exactly the "underlay addressing" concern the
//! sans-I/O library leaves to its caller).
//!
//! Both ends must share the same `--password`, `--cipher`, and `--obfs`.
//!
//! Run (needs root / CAP_NET_ADMIN to create the TUN):
//!
//! ```sh
//! # server
//! tunnel_node --listen 0.0.0.0:8388 --tun-ip 10.9.0.1 --peer-ip 10.9.0.2 -k secret
//! # client
//! tunnel_node --connect server:8388 --tun-ip 10.9.0.2 --peer-ip 10.9.0.1 -k secret
//! ```

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use clap::Parser;
use tokio::net::UdpSocket;
use ts_packet::PacketMut;
use ts_tunnel::{Cipher, Endpoint, NodeKeyPair, Obfuscator, PeerConfig, PeerId, evp_bytes_to_key};
use tun_rs::DeviceBuilder;

/// The single peer this node talks to (point-to-point tunnel).
const PEER: PeerId = PeerId(1);

/// Largest IP datagram, and a little headroom for the crypto + obfs overhead on
/// the encrypted side.
const MAX_IP_PACKET: usize = 65535;
const MAX_DATAGRAM: usize = MAX_IP_PACKET + 256;

#[derive(Parser)]
#[command(about = "Point-to-point ShadowVPN node built on ts_tunnel::Endpoint")]
struct Args {
    /// Server mode: UDP address to bind and listen on (e.g. `0.0.0.0:8388`).
    #[arg(long, conflicts_with = "connect")]
    listen: Option<String>,

    /// Client mode: remote server address to connect to (e.g. `host:8388`).
    #[arg(long)]
    connect: Option<String>,

    /// Pre-shared password; the 32-byte master key is derived from it.
    #[arg(short = 'k', long)]
    password: String,

    /// AEAD cipher: `aes-128-gcm` | `aes-256-gcm` | `chacha20-poly1305`.
    #[arg(short = 'm', long, default_value = "chacha20-poly1305")]
    cipher: String,

    /// Carrier obfuscation: `none` | `quic` | `base64` (both ends must match).
    #[arg(long, default_value = "quic")]
    obfs: String,

    /// Local IPv4 address on the TUN interface.
    #[arg(long)]
    tun_ip: Ipv4Addr,

    /// Point-to-point peer IPv4 address.
    #[arg(long)]
    peer_ip: Ipv4Addr,

    /// IPv4 netmask for the TUN interface.
    #[arg(long, default_value = "255.255.255.0")]
    tun_netmask: Ipv4Addr,

    /// TUN interface MTU.
    #[arg(long, default_value_t = 1400)]
    mtu: u16,

    /// Explicit TUN interface name (e.g. `tun0`, `utun7`). Optional; OS picks one
    /// if omitted.
    #[arg(long)]
    tun_name: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let cipher = Cipher::from_name(&args.cipher)?;
    // Derive a 32-byte master key from the password (matches the cipher's key
    // length for the default ciphers; shorter-key ciphers use the leading bytes).
    let master = evp_bytes_to_key(args.password.as_bytes(), 32);
    let mut psk = [0u8; 32];
    psk.copy_from_slice(&master);

    // Build the endpoint. The node public key is just an identity placeholder —
    // the ShadowVPN data plane never puts it on the wire — so a fresh random key
    // on each side is fine; only the PSK has to match.
    let mut endpoint = Endpoint::with_config(
        NodeKeyPair::new(),
        cipher,
        Obfuscator::from_name(&args.obfs),
    );
    endpoint.upsert_peer(
        PEER,
        PeerConfig {
            key: NodeKeyPair::new().public,
            psk,
        },
    );
    let endpoint = Arc::new(Mutex::new(endpoint));

    // Bring up the TUN device (point-to-point: address + netmask + peer).
    let mut builder =
        DeviceBuilder::new()
            .mtu(args.mtu)
            .ipv4(args.tun_ip, args.tun_netmask, Some(args.peer_ip));
    if let Some(name) = &args.tun_name {
        builder = builder.name(name.clone());
    }
    let tun = Arc::new(builder.build_async()?);
    eprintln!(
        "[tunnel_node] tun up: ip={} peer={} mtu={} cipher={} obfs={}",
        args.tun_ip,
        args.peer_ip,
        args.mtu,
        cipher.name(),
        args.obfs,
    );

    // Set up the UDP socket and the peer's underlay address.
    let (socket, peer_addr) = match (&args.listen, &args.connect) {
        (Some(listen), None) => {
            let bind: SocketAddr = listen.parse()?;
            let socket = UdpSocket::bind(bind).await?;
            eprintln!("[tunnel_node] server listening on {bind}");
            // Learned from the first authenticated datagram.
            (socket, Arc::new(Mutex::new(None::<SocketAddr>)))
        }
        (None, Some(connect)) => {
            let server = resolve(connect).await?;
            let bind: SocketAddr = (Ipv4Addr::UNSPECIFIED, 0).into();
            let socket = UdpSocket::bind(bind).await?;
            eprintln!("[tunnel_node] client connecting to {server}");
            (socket, Arc::new(Mutex::new(Some(server))))
        }
        _ => return Err("specify exactly one of --listen (server) or --connect (client)".into()),
    };
    let socket = Arc::new(socket);

    // Downlink: UDP -> decrypt -> TUN. Also learns/refreshes the peer's address.
    let downlink = {
        let endpoint = endpoint.clone();
        let tun = tun.clone();
        let socket = socket.clone();
        let peer_addr = peer_addr.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            loop {
                let (n, src) = socket.recv_from(&mut buf).await?;
                let decrypted = {
                    let mut ep = endpoint.lock().unwrap();
                    ep.recv([PacketMut::from(buf[..n].to_vec())])
                };
                let Some(packets) = decrypted.to_local.get(&PEER) else {
                    continue;
                };
                if packets.is_empty() {
                    continue;
                }
                // Authenticated traffic from this source: remember where to reply.
                *peer_addr.lock().unwrap() = Some(src);
                for packet in packets {
                    tun.send(packet.as_ref()).await?;
                }
            }
            #[allow(unreachable_code)]
            Ok::<(), std::io::Error>(())
        })
    };

    // Uplink: TUN -> encrypt -> UDP.
    let uplink = {
        let endpoint = endpoint.clone();
        let tun = tun.clone();
        let socket = socket.clone();
        let peer_addr = peer_addr.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_IP_PACKET];
            loop {
                let n = tun.recv(&mut buf).await?;
                let Some(dst) = *peer_addr.lock().unwrap() else {
                    // No known peer address yet (server before first contact).
                    continue;
                };
                let encrypted = {
                    let mut ep = endpoint.lock().unwrap();
                    ep.send([(PEER, vec![PacketMut::from(buf[..n].to_vec())])])
                };
                if let Some(datagrams) = encrypted.to_peers.get(&PEER) {
                    for datagram in datagrams {
                        socket.send_to(datagram.as_ref(), dst).await?;
                    }
                }
            }
            #[allow(unreachable_code)]
            Ok::<(), std::io::Error>(())
        })
    };

    // If either relay loop returns (always an error), propagate it and exit.
    tokio::select! {
        r = downlink => r??,
        r = uplink => r??,
    }
    Ok(())
}

/// Resolve a `host:port` to a [`SocketAddr`], preferring IPv4.
async fn resolve(addr: &str) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return Ok(sa);
    }
    let mut last = None;
    for sa in tokio::net::lookup_host(addr).await? {
        last = Some(sa);
        if sa.is_ipv4() {
            return Ok(sa);
        }
    }
    last.ok_or_else(|| format!("could not resolve `{addr}`").into())
}
