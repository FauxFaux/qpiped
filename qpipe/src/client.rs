use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use anyhow::{bail, Context, Error, Result};
use futures_util::future::try_join_all;
use log::{error, warn};
use quinn::Connection;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::try_join;

use super::frame::{copy_framing, copy_unframing};
use super::package::ClientCerts;
use super::server::alpn_protocols;
use super::wire;
use crate::frame::HeaderHeader;
use crate::wire::Establish;

pub async fn run(target: String, certs: &ClientCerts, mappings: &[(String, String)]) -> Result<()> {
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
    let conn = endpoint.connect(targets[0], "localhost")?.await?;

    let mut proxies = Vec::new();
    for (source, target) in mappings {
        for source in source.to_socket_addrs()? {
            let establish = Establish {
                protocol: b't',
                address_port: target.to_string(),
            };
            proxies.push(tokio::spawn(spawn_proxies(conn.clone(), source, establish)));
        }
    }

    try_join_all(proxies).await?;

    Ok(())
}

async fn spawn_proxies(framed: Connection, source: SocketAddr, establish: Establish) -> Result<()> {
    let bind = TcpListener::bind(source).await?;

    loop {
        let (client, addr) = bind.accept().await?;
        let framed = framed.clone();
        let establish = establish.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_proxy_connection(client, framed, &establish).await {
                error!("processing connection from {:?}: {:?}", addr, e);
            }
        });
    }
}

async fn handle_proxy_connection(
    plain: TcpStream,
    framed: Connection,
    establish: &Establish,
) -> Result<()> {
    let (mut plain_from, mut plain_to) = plain.into_split();
    let (mut framed_to, mut framed_from) = framed.open_bi().await?;

    wire::write_establish(&mut framed_to, establish).await?;
    // TODO: handle ping?
    wire::read_okay(&mut framed_from).await?;

    try_join!(
        async {
            copy_framing(&mut plain_from, &mut framed_to).await?;
            HeaderHeader::finished().write_all(&mut framed_to).await?;
            framed_to.shutdown().await?;
            Ok::<_, Error>(())
        },
        async {
            let res = copy_unframing(&mut framed_from, &mut plain_to).await;
            plain_to.shutdown().await?;
            res
        }
    )?;

    Ok(())
}
