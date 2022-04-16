use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use futures_util::stream::StreamExt;
use log::{error, info, warn};
use rustls::server::AllowAnyAuthenticatedClient;
use rustls::{Certificate, PrivateKey, RootCertStore};

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

    let (_endpoint, mut incomming) = quinn::Endpoint::server(server_config, addr)?;

    // connection here is more like a bind in traditional networking;
    // as there are multiple, independent "connections" to it over its life
    while let Some(conn) = incomming.next().await {
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
    let quinn::NewConnection {
        connection: _,
        mut bi_streams,
        ..
    } = conn.await?;

    while let Some(stream) = bi_streams.next().await {
        info!("server stream noticed");
        let stream = match stream {
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

    Ok(())
}

// apparently this is the supported .. draft version?
// https://github.com/quinn-rs/quinn/blob/6fc46aefc65aeb3dd2d059ea6aabaf7a6c2f5bdb/quinn/examples/common/mod.rs#L69
pub fn alpn_protocols() -> Vec<Vec<u8>> {
    vec![b"hq-29".to_vec()]
}

async fn handle_stream((mut send, mut recv): (quinn::SendStream, quinn::RecvStream)) -> Result<()> {
    let mut buf = vec![0u8; usize::from(u16::MAX)];

    loop {
        let req = HeaderHeader::from(&mut recv).await?;
        let buf = &mut buf[..usize::from(req.data_len)];
        recv.read_exact(buf).await?;

        match &req.four_cc {
            b"ping" => {
                let mut buf = [0u8; 8];
                recv.read_exact(&mut buf).await?;
                HeaderHeader::pong().write_all(&mut send).await?;
                send.write_all(&buf).await?;
            }
            b"con1" => {
                println!("{:?}", wire::parse_establish(buf)?);
                HeaderHeader::empty(*b"okay").write_all(&mut send).await?;
            }
            b"fini" => break,
            _ => {
                warn!(
                    "unsupported client request: {:?}, {:?}...",
                    req,
                    String::from_utf8_lossy(buf)
                        .chars()
                        .take(30)
                        .collect::<String>()
                );
                wire::write_error(&mut send, 1, "unrecognised frame").await?
            }
        }
    }

    send.finish().await?;

    info!("closed?");
    Ok(())
}
