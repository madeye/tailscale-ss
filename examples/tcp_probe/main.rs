//! Connect to a tailnet TCP peer, send a payload, and verify the echo.
//!
//! Paired with the `tcp_echo` example: bring up `tcp_echo` as one node, then run
//! this against its tailnet address. Used by the Headscale integration test to
//! prove the data plane carries real traffic between two nodes (over whichever
//! `TS_DATAPLANE_PROTOCOL` is selected).

use std::{error::Error, net::SocketAddr, path::PathBuf, time::Duration};

use clap::Parser;
use tailscale::{Config, Device};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing_subscriber::filter::LevelFilter;

#[derive(clap::Parser)]
#[command(version, about)]
struct Args {
    /// Path to a key file to use. Will be created if it doesn't exist.
    #[arg(short = 'c', long, default_value = "tsrs_keys.json")]
    key_file: PathBuf,

    /// The auth key to connect with.
    #[arg(short = 'k', long, env = "TS_AUTH_KEY")]
    auth_key: Option<String>,

    /// The hostname this node will request.
    #[arg(short = 'H', long, default_value = "tcp_probe_example")]
    hostname: Option<String>,

    /// The URL of the control server to connect to.
    #[arg(long, env = "TS_CONTROL_URL")]
    control_url: Option<url::Url>,

    /// The tailnet peer address to connect to (e.g. `100.64.0.2:1234`).
    #[arg(short, long)]
    peer: SocketAddr,

    /// How long to keep retrying the connect + echo before giving up.
    #[arg(long, default_value_t = 60)]
    timeout_secs: u64,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let args = Args::parse();

    let mut config = Config::default_with_key_file(&args.key_file).await?;
    config.requested_hostname = args.hostname;
    if let Some(url) = args.control_url {
        config.control_server_url = url;
    }

    let dev = Device::new(&config, args.auth_key).await?;
    tracing::info!(ipv4 = %dev.ipv4_addr().await?, "device up; probing peer");

    let payload = b"shadowvpn-over-headscale";
    let deadline = tokio::time::Instant::now() + Duration::from_secs(args.timeout_secs);

    let mut attempt = 0u32;
    loop {
        attempt += 1;
        match try_echo(&dev, args.peer, payload).await {
            Ok(()) => {
                tracing::info!(
                    attempt,
                    "PASS: echo round-trip through the tunnel succeeded"
                );
                println!("PROBE_PASS");
                return Ok(());
            }
            Err(e) if tokio::time::Instant::now() < deadline => {
                tracing::warn!(attempt, error = %e, "echo attempt failed; retrying");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(e) => {
                tracing::error!(attempt, error = %e, "FAIL: gave up");
                println!("PROBE_FAIL");
                return Err(e);
            }
        }
    }
}

/// One connect → write → read-back attempt, asserting the echo matches.
async fn try_echo(dev: &Device, peer: SocketAddr, payload: &[u8]) -> Result<(), Box<dyn Error>> {
    let conn = tokio::time::timeout(Duration::from_secs(8), dev.tcp_connect(peer)).await??;
    let (mut reader, mut writer) = tokio::io::split(conn);

    writer.write_all(payload).await?;
    writer.flush().await?;

    let mut buf = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(8), reader.read_exact(&mut buf)).await??;

    if buf == payload {
        Ok(())
    } else {
        Err(format!("echo mismatch: sent {payload:?}, got {buf:?}").into())
    }
}
