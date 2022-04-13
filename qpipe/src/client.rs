use std::fmt::Debug;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use crate::frame::HeaderHeader;
use anyhow::{bail, Context, Result};
use log::{info, warn};

use super::package::ClientCerts;
use super::server::alpn_protocols;

pub async fn run(target: impl Debug + ToSocketAddrs, certs: &ClientCerts) -> Result<()> {
    let targets: Vec<SocketAddr> = target.to_socket_addrs()?.collect();
    if targets.is_empty() {
        bail!("{:?} resolved to nowhere", target);
    }

    let mut roots = rustls::RootCertStore::empty();
    roots.add(&certs.server_cert)?;

    let mut client_crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_single_cert(vec![certs.client_cert.clone()], certs.client_key.clone())?;
    // .with_client_cert_resolver(Arc::clone(&certs) as Arc<dyn ResolvesClientCert>);

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

    HeaderHeader::ping().write_all(&mut send).await?;
    send.write_all(&17u64.to_le_bytes()).await?;

    let resp = HeaderHeader::from(&mut recv).await?;
    info!("resp: {:?}", resp);
    let mut buf = [0u8; 8];
    recv.read_exact(&mut buf).await?;
    info!("pong body: {}", u64::from_le_bytes(buf));

    Ok(())
}
