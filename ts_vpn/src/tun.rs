//! A thin async wrapper around a [`tun-rs`](https://crates.io/crates/tun-rs)
//! TUN device that reads and writes whole IP packets.

use std::net::Ipv4Addr;

use tun_rs::{AsyncDevice, DeviceBuilder};

/// An async TUN interface. Closed when dropped.
pub struct Tun {
    inner: AsyncDevice,
}

impl Tun {
    /// Create and bring up a TUN interface.
    ///
    /// * `name` — explicit interface name, or `None` to let the OS pick.
    /// * `ip` / `netmask` — the local IPv4 address and netmask.
    /// * `peer` — point-to-point destination address (clients set the server's
    ///   tunnel IP; a multi-client server passes `None` and routes the whole
    ///   subnet via the netmask).
    /// * `mtu` — interface MTU.
    pub fn create(
        name: Option<&str>,
        ip: Ipv4Addr,
        netmask: Ipv4Addr,
        peer: Option<Ipv4Addr>,
        mtu: u16,
    ) -> std::io::Result<Self> {
        let mut builder = DeviceBuilder::new().mtu(mtu).ipv4(ip, netmask, peer);
        if let Some(name) = name {
            builder = builder.name(name.to_string());
        }
        Ok(Self {
            inner: builder.build_async()?,
        })
    }

    /// Read a single IP packet from the interface into `buf`.
    pub async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.recv(buf).await
    }

    /// Write a single IP packet to the interface.
    pub async fn send(&self, packet: &[u8]) -> std::io::Result<usize> {
        self.inner.send(packet).await
    }

    /// The OS-assigned interface name (e.g. `utun7`, `tun0`).
    pub fn name(&self) -> std::io::Result<String> {
        self.inner.name()
    }
}
