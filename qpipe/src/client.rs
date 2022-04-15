use std::fmt::Debug;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use crate::frame::HeaderHeader;
use anyhow::{bail, Context, Error, Result};
use log::{info, warn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::{join, try_join};

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

        // spawn here
        let (mut read, mut write) = client.into_split();
        let (mut send, mut recv) = conn.open_bi().await?;

        send.write_all(b"TODO: establish").await?;
        let resp = HeaderHeader::from(&mut recv).await?;
        match &resp.four_cc {
            b"okay" => (),
            _ => bail!("unexpected response {:?}", resp),
        }
        // TODO: consume body

        try_join!(
            async {
                let mut buf = [0u8; 4096];
                loop {
                    let found = read.read(&mut buf).await?;
                    let buf = &buf[..found];
                    if buf.is_empty() {
                        break;
                    }
                    HeaderHeader::data(buf.len()).write_all(&mut send).await?;
                    send.write_all(&buf).await?;
                }

                HeaderHeader::finished().write_all(&mut send).await?;
                send.finish().await?;

                Ok::<_, Error>(())
            },
            async {
                let mut buf = [0u8; 8096];
                loop {
                    let hh = HeaderHeader::from(&mut recv).await?;
                    match &hh.four_cc {
                        b"data" => (),
                        b"fini" => break,
                        _ => bail!("unsupported frame on established connection: {:?}", hh),
                    };

                    if usize::from(hh.data_len) > buf.len() {
                        bail!("overlong data packet: {}", hh.data_len)
                    }

                    let buf = &mut buf[..usize::from(hh.data_len)];

                    recv.read_exact(buf).await?;
                    write.write_all(buf).await?;
                }

                write.shutdown().await?;

                Ok::<_, Error>(())
            }
        )?;
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
