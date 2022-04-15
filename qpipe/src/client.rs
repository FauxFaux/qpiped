use std::fmt::Debug;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use crate::frame::HeaderHeader;
use anyhow::{bail, Context, Error, Result};
use log::{error, warn};
use quinn::Connection;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::try_join;

use super::frame::{copy_framing, copy_unframing};
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

    let bind = TcpListener::bind("127.0.0.1:6699").await?;

    loop {
        let (client, addr) = bind.accept().await?;
        let conn = conn.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_proxy_connection(client, conn).await {
                error!("processing connection from {:?}: {:?}", addr, e);
            }
        });
    }

    // info!("client stream open");
    //
    // HeaderHeader::ping().write_all(&mut send).await?;
    // send.write_all(&17u64.to_le_bytes()).await?;
    //
    // let resp = HeaderHeader::from(&mut recv).await?;
    // info!("resp: {:?}", resp);
    // let mut buf = [0u8; 8];
    // recv.read_exact(&mut buf).await?;
    // info!("pong body: {}", u64::from_le_bytes(buf));
}

async fn handle_proxy_connection(plain: TcpStream, framed: Connection) -> Result<()> {
    let (mut plain_from, mut plain_to) = plain.into_split();
    let (mut framed_to, mut framed_from) = framed.open_bi().await?;

    framed_to.write_all(b"TODO: establish").await?;
    let resp = HeaderHeader::from(&mut framed_from).await?;
    match &resp.four_cc {
        b"okay" => (),
        _ => bail!("unexpected response {:?}", resp),
    }
    // TODO: consume body

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
