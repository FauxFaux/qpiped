use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::{anyhow, ensure, Context, Result};
use log::{error, info, warn};
use rustls::server::AllowAnyAuthenticatedClient;
use rustls::{Certificate, PrivateKey, RootCertStore};
use tokio::net::{lookup_host, TcpSocket};
use tokio::try_join;

use super::frame::copy_framing;
use super::frame::copy_unframing;
use super::frame::HeaderHeader;
use super::wire;

pub struct Certs {
    pub server_key: PrivateKey,
    pub server_chain: Vec<Certificate>,
}

pub async fn run(certs: Certs, addr: SocketAddr) -> Result<()> {
    let mut root = RootCertStore::empty();
    for cert in &certs.server_chain {
        root.add(cert)?;
    }
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(AllowAnyAuthenticatedClient::new(root))
        .with_single_cert(certs.server_chain, certs.server_key)?;

    server_crypto.alpn_protocols = alpn_protocols();

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
    server_config.use_retry(true);

    let server = quinn::Endpoint::server(server_config, addr)?;

    // connection here is more like a bind in traditional networking;
    // as there are multiple, independent "connections" to it over its life
    while let Some(conn) = server.accept().await {
        // dunno what this explicit 'fut' is about; cargo-culted from the example
        let fut = handle_connection(conn);
        tokio::spawn(async move {
            if let Err(e) = fut.await {
                error!("connection handling failure, {:?}", e);
            }
        });
    }

    Ok(())
}

async fn handle_connection(conn: quinn::Connecting) -> Result<()> {
    let conn = conn.await.context("handshake failed")?;

    loop {
        info!("server stream noticed");
        let stream = match conn.accept_bi().await {
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                info!("app closed");
                return Ok(());
            }
            Err(e) => Err(e)?,
            Ok(s) => s,
        };

        // dunno what this explicit 'fut' is about; cargo-culted from the example
        let fut = handle_stream(stream);
        tokio::spawn(async move {
            if let Err(e) = fut.await {
                error!("stream failed: {:?}", e);
            }
        });
    }
}

// apparently this is the supported .. draft version?
// https://github.com/quinn-rs/quinn/blob/6fc46aefc65aeb3dd2d059ea6aabaf7a6c2f5bdb/quinn/examples/common/mod.rs#L69
pub fn alpn_protocols() -> Vec<Vec<u8>> {
    vec![b"hq-29".to_vec()]
}

async fn handle_stream(
    (mut framed_to, mut framed_from): (quinn::SendStream, quinn::RecvStream),
) -> Result<()> {
    let mut buf = vec![0u8; usize::from(u16::MAX)];

    let establish = loop {
        // read_frame?
        let req = HeaderHeader::from(&mut framed_from).await?;
        let buf = &mut buf[..usize::from(req.data_len)];
        framed_from.read_exact(buf).await?;

        // handle_common_or(b"con1", CloseOnError)?
        match &req.four_cc {
            b"ping" => {
                HeaderHeader::pong().write_all(&mut framed_to).await?;
                framed_to.write_all(&buf).await?;
            }
            b"con1" => {
                break wire::parse_establish(buf)?;
            }
            _ => {
                warn!(
                    "unsupported client request: {:?}, {:?}...",
                    req,
                    String::from_utf8_lossy(buf)
                        .chars()
                        .take(30)
                        .collect::<String>()
                );
                wire::write_error(&mut framed_to, 1, "unrecognised frame").await?
            }
        }
    };

    ensure!(
        establish.protocol == b't',
        "only tcp is supported, not {:?}",
        establish.protocol
    );

    // TODO: return these errors to the client cleanly?
    let mut resolution = lookup_host(&establish.address_port).await?;
    // TODO: try multiple addresses?
    let picked = resolution
        .next()
        .ok_or_else(|| anyhow!("no resolution for {:?}", establish.address_port))?;
    let plain = match picked.ip() {
        IpAddr::V4(_) => TcpSocket::new_v4()?,
        IpAddr::V6(_) => TcpSocket::new_v6()?,
    }
    .connect(picked)
    .await?;

    HeaderHeader::empty(*b"okay")
        .write_all(&mut framed_to)
        .await?;

    let (mut plain_from, mut plain_to) = plain.into_split();

    try_join!(
        async { copy_framing(&mut plain_from, &mut framed_to).await },
        async { copy_unframing(&mut framed_from, &mut plain_to).await }
    )?;

    framed_to.finish().await?;

    info!("closed?");
    Ok(())
}
