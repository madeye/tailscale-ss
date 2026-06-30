//! UDP socket helpers.

use std::net::SocketAddr;

use tokio::net::UdpSocket;

/// Bind a UDP socket to `addr`.
pub async fn bind_udp(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    UdpSocket::bind(addr).await
}

/// Resolve a `host:port` string to a [`SocketAddr`], preferring IPv4.
///
/// A literal `ip:port` short-circuits with no DNS lookup.
pub async fn resolve(addr: &str) -> std::io::Result<SocketAddr> {
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
    last.ok_or_else(|| std::io::Error::other(format!("could not resolve `{addr}`")))
}
