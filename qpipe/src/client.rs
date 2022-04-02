use std::fmt::Debug;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use futures_util::AsyncWriteExt;
use log::{info, warn};
use rustls::Certificate;

use super::server::alpn_protocols;

pub async fn run(target: impl Debug + ToSocketAddrs, server_cert: &Certificate) -> Result<()> {
    let targets: Vec<SocketAddr> = target.to_socket_addrs()?.collect();
    if targets.is_empty() {
        bail!("{:?} resolved to nowhere", target);
    }

    let mut roots = rustls::RootCertStore::empty();
    roots.add(server_cert)?;

    let mut client_crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        // TODO: opposite of final intention
        .with_no_client_auth();

    client_crypto.alpn_protocols = alpn_protocols();

    let mut endpoint = quinn::Endpoint::client(
        "[::]:0"
            .parse()
            .context("producing 'all addresses' address")?,
    )?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(client_crypto)));

    if 1 != targets.len() {
        warn!("ignoring some target addresses from: {:?}", targets);
    }
    let new_conn = endpoint.connect(targets[0], "localhost")?.await?;
    let quinn::NewConnection {
        connection: conn, ..
    } = new_conn;

    let (mut send, mut recv) = conn.open_bi().await?;
    info!("client stream open");
    let mut hello = [0u8; 2];

    // appears the server doesn't actually handle our connection until we speak on it
    send.write_all(b"hey cutie").await?;
    send.flush().await?;

    recv.read_exact(&mut hello).await?;
    info!("client recv: {:?}", hello);

    send.finish().await?;

    Ok(())
}
