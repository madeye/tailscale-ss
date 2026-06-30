//! Configuration for the server and client binaries.
//!
//! Each role has one struct that derives **both** [`clap::Parser`] and
//! [`serde::Deserialize`], so the same fields come from CLI flags or a JSON
//! config file (`-c`). Every field is optional; [`ServerArgs::resolve`] /
//! [`ClientArgs::resolve`] merge them — **CLI values take precedence over the
//! file** — and apply defaults, validating that the required fields are present.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use clap::Parser;
use serde::Deserialize;

/// Default AEAD cipher when none is configured.
pub const DEFAULT_CIPHER: &str = "chacha20-poly1305";
/// Default carrier obfuscation when none is configured.
pub const DEFAULT_OBFS: &str = "none";
/// Default TUN netmask.
pub const DEFAULT_NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);
/// Default TUN MTU.
pub const DEFAULT_MTU: u16 = 1400;
/// Default client keepalive interval, in seconds.
pub const DEFAULT_KEEPALIVE_SECS: u64 = 25;

/// Errors resolving a configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The config file could not be read.
    #[error("reading config file {path}: {source}")]
    Read {
        /// The path that failed to read.
        path: String,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// The config file was not valid JSON.
    #[error("parsing config file {path}: {source}")]
    Parse {
        /// The path that failed to parse.
        path: String,
        /// The underlying JSON error.
        source: serde_json::Error,
    },
    /// A required field was not supplied by either the CLI or the file.
    #[error("missing required config field: {0}")]
    Missing(&'static str),
    /// A `host:port` value could not be parsed.
    #[error("invalid address for {field}: {value}")]
    Addr {
        /// The field name.
        field: &'static str,
        /// The offending value.
        value: String,
    },
}

/// Initialize `tracing` to stderr, honouring `RUST_LOG` (default `info`).
pub fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

fn read_file<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.display().to_string(),
        source,
    })?;
    serde_json::from_str(&text).map_err(|source| ConfigError::Parse {
        path: path.display().to_string(),
        source,
    })
}

fn parse_addr(field: &'static str, value: String) -> Result<SocketAddr, ConfigError> {
    value
        .parse()
        .map_err(|_| ConfigError::Addr { field, value })
}

/// Server configuration, from CLI flags and/or a JSON config file.
#[derive(Parser, Deserialize, Default)]
#[command(about = "Multi-client ShadowVPN server built on ts_tunnel")]
pub struct ServerArgs {
    /// Path to a JSON config file (CLI flags override its values).
    #[arg(short = 'c', long)]
    #[serde(skip)]
    pub config: Option<PathBuf>,

    /// UDP address to bind and listen on (e.g. `0.0.0.0:8388`).
    #[arg(long)]
    pub listen: Option<String>,

    /// Pre-shared password shared by the server and all clients.
    #[arg(short = 'k', long)]
    pub password: Option<String>,

    /// AEAD cipher: `aes-128-gcm` | `aes-256-gcm` | `chacha20-poly1305`.
    #[arg(short = 'm', long)]
    pub cipher: Option<String>,

    /// Carrier obfuscation: `none` | `quic` | `base64` (all peers must match).
    #[arg(long)]
    pub obfs: Option<String>,

    /// Explicit TUN interface name.
    #[arg(long)]
    pub tun_name: Option<String>,

    /// The server's own IPv4 address on the tunnel subnet.
    #[arg(long)]
    pub tun_ip: Option<Ipv4Addr>,

    /// IPv4 netmask defining the tunnel subnet.
    #[arg(long)]
    pub tun_netmask: Option<Ipv4Addr>,

    /// TUN interface MTU.
    #[arg(long)]
    pub mtu: Option<u16>,
}

/// A fully resolved, validated server configuration.
pub struct ServerConfig {
    /// UDP bind address.
    pub listen: SocketAddr,
    /// Pre-shared password.
    pub password: String,
    /// AEAD cipher name.
    pub cipher: String,
    /// Carrier obfuscation name.
    pub obfs: String,
    /// Explicit TUN name, if any.
    pub tun_name: Option<String>,
    /// Server tunnel IPv4 address.
    pub tun_ip: Ipv4Addr,
    /// Tunnel subnet netmask.
    pub tun_netmask: Ipv4Addr,
    /// TUN MTU.
    pub mtu: u16,
}

impl ServerArgs {
    /// Merge these CLI args over the file at `self.config` (if any) and apply
    /// defaults, producing a validated [`ServerConfig`].
    pub fn resolve(self) -> Result<ServerConfig, ConfigError> {
        let file: ServerArgs = match &self.config {
            Some(path) => read_file(path)?,
            None => ServerArgs::default(),
        };
        let listen = self
            .listen
            .or(file.listen)
            .ok_or(ConfigError::Missing("listen"))?;
        Ok(ServerConfig {
            listen: parse_addr("listen", listen)?,
            password: self
                .password
                .or(file.password)
                .ok_or(ConfigError::Missing("password"))?,
            cipher: self
                .cipher
                .or(file.cipher)
                .unwrap_or_else(|| DEFAULT_CIPHER.into()),
            obfs: self
                .obfs
                .or(file.obfs)
                .unwrap_or_else(|| DEFAULT_OBFS.into()),
            tun_name: self.tun_name.or(file.tun_name),
            tun_ip: self
                .tun_ip
                .or(file.tun_ip)
                .ok_or(ConfigError::Missing("tun_ip"))?,
            tun_netmask: self
                .tun_netmask
                .or(file.tun_netmask)
                .unwrap_or(DEFAULT_NETMASK),
            mtu: self.mtu.or(file.mtu).unwrap_or(DEFAULT_MTU),
        })
    }
}

/// Client configuration, from CLI flags and/or a JSON config file.
#[derive(Parser, Deserialize, Default)]
#[command(about = "ShadowVPN client built on ts_tunnel")]
pub struct ClientArgs {
    /// Path to a JSON config file (CLI flags override its values).
    #[arg(short = 'c', long)]
    #[serde(skip)]
    pub config: Option<PathBuf>,

    /// Remote server address to connect to (e.g. `vpn.example.com:8388`).
    #[arg(long)]
    pub server: Option<String>,

    /// Pre-shared password shared with the server.
    #[arg(short = 'k', long)]
    pub password: Option<String>,

    /// AEAD cipher: `aes-128-gcm` | `aes-256-gcm` | `chacha20-poly1305`.
    #[arg(short = 'm', long)]
    pub cipher: Option<String>,

    /// Carrier obfuscation: `none` | `quic` | `base64` (must match the server).
    #[arg(long)]
    pub obfs: Option<String>,

    /// Explicit TUN interface name.
    #[arg(long)]
    pub tun_name: Option<String>,

    /// This client's IPv4 address on the tunnel subnet (must be unique).
    #[arg(long)]
    pub tun_ip: Option<Ipv4Addr>,

    /// The server's tunnel IPv4 address (point-to-point peer).
    #[arg(long)]
    pub peer_ip: Option<Ipv4Addr>,

    /// IPv4 netmask for the TUN interface.
    #[arg(long)]
    pub tun_netmask: Option<Ipv4Addr>,

    /// TUN interface MTU.
    #[arg(long)]
    pub mtu: Option<u16>,

    /// Keepalive interval in seconds (0 disables keepalives).
    #[arg(long)]
    pub keepalive_secs: Option<u64>,
}

/// A fully resolved, validated client configuration.
pub struct ClientConfig {
    /// Remote server `host:port`.
    pub server: String,
    /// Pre-shared password.
    pub password: String,
    /// AEAD cipher name.
    pub cipher: String,
    /// Carrier obfuscation name.
    pub obfs: String,
    /// Explicit TUN name, if any.
    pub tun_name: Option<String>,
    /// Client tunnel IPv4 address.
    pub tun_ip: Ipv4Addr,
    /// Server tunnel IPv4 address (point-to-point peer).
    pub peer_ip: Ipv4Addr,
    /// TUN netmask.
    pub tun_netmask: Ipv4Addr,
    /// TUN MTU.
    pub mtu: u16,
    /// Keepalive interval in seconds (0 disables).
    pub keepalive_secs: u64,
}

impl ClientArgs {
    /// Merge these CLI args over the file at `self.config` (if any) and apply
    /// defaults, producing a validated [`ClientConfig`].
    pub fn resolve(self) -> Result<ClientConfig, ConfigError> {
        let file: ClientArgs = match &self.config {
            Some(path) => read_file(path)?,
            None => ClientArgs::default(),
        };
        Ok(ClientConfig {
            server: self
                .server
                .or(file.server)
                .ok_or(ConfigError::Missing("server"))?,
            password: self
                .password
                .or(file.password)
                .ok_or(ConfigError::Missing("password"))?,
            cipher: self
                .cipher
                .or(file.cipher)
                .unwrap_or_else(|| DEFAULT_CIPHER.into()),
            obfs: self
                .obfs
                .or(file.obfs)
                .unwrap_or_else(|| DEFAULT_OBFS.into()),
            tun_name: self.tun_name.or(file.tun_name),
            tun_ip: self
                .tun_ip
                .or(file.tun_ip)
                .ok_or(ConfigError::Missing("tun_ip"))?,
            peer_ip: self
                .peer_ip
                .or(file.peer_ip)
                .ok_or(ConfigError::Missing("peer_ip"))?,
            tun_netmask: self
                .tun_netmask
                .or(file.tun_netmask)
                .unwrap_or(DEFAULT_NETMASK),
            mtu: self.mtu.or(file.mtu).unwrap_or(DEFAULT_MTU),
            keepalive_secs: self
                .keepalive_secs
                .or(file.keepalive_secs)
                .unwrap_or(DEFAULT_KEEPALIVE_SECS),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_cli_overrides_file_and_applies_defaults() {
        // CLI sets listen + tun_ip + cipher; file isn't used (no path).
        let args = ServerArgs {
            listen: Some("0.0.0.0:9999".into()),
            password: Some("pw".into()),
            cipher: Some("aes-256-gcm".into()),
            tun_ip: Some(Ipv4Addr::new(10, 9, 0, 1)),
            ..Default::default()
        };
        let cfg = args.resolve().unwrap();
        assert_eq!(cfg.listen, "0.0.0.0:9999".parse().unwrap());
        assert_eq!(cfg.cipher, "aes-256-gcm");
        assert_eq!(cfg.obfs, DEFAULT_OBFS);
        assert_eq!(cfg.tun_netmask, DEFAULT_NETMASK);
        assert_eq!(cfg.mtu, DEFAULT_MTU);
    }

    #[test]
    fn server_missing_required_field_errors() {
        let args = ServerArgs {
            listen: Some("0.0.0.0:1".into()),
            // no password, no tun_ip
            ..Default::default()
        };
        assert!(matches!(
            args.resolve(),
            Err(ConfigError::Missing("password"))
        ));
    }

    #[test]
    fn client_defaults_keepalive_and_netmask() {
        let args = ClientArgs {
            server: Some("example.com:8388".into()),
            password: Some("pw".into()),
            tun_ip: Some(Ipv4Addr::new(10, 9, 0, 2)),
            peer_ip: Some(Ipv4Addr::new(10, 9, 0, 1)),
            ..Default::default()
        };
        let cfg = args.resolve().unwrap();
        assert_eq!(cfg.keepalive_secs, DEFAULT_KEEPALIVE_SECS);
        assert_eq!(cfg.tun_netmask, DEFAULT_NETMASK);
        assert_eq!(cfg.cipher, DEFAULT_CIPHER);
    }

    #[test]
    fn bad_listen_address_errors() {
        let args = ServerArgs {
            listen: Some("not-an-address".into()),
            password: Some("pw".into()),
            tun_ip: Some(Ipv4Addr::new(10, 9, 0, 1)),
            ..Default::default()
        };
        assert!(matches!(args.resolve(), Err(ConfigError::Addr { .. })));
    }
}
