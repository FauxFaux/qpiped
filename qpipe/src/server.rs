use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use futures_util::stream::StreamExt;
use futures_util::AsyncWriteExt;
use log::{error, info};
use rustls::{Certificate, PrivateKey};

pub struct Certs {
    pub server_key: PrivateKey,
    pub server_chain: Vec<Certificate>,
}

pub async fn run(certs: Certs, addr: SocketAddr) -> Result<()> {
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_safe_defaults()
        // TODO: opposite of final intention
        .with_no_client_auth()
        .with_single_cert(certs.server_chain, certs.server_key)?;

    // apparently this is the supported .. draft version?
    // https://github.com/quinn-rs/quinn/blob/6fc46aefc65aeb3dd2d059ea6aabaf7a6c2f5bdb/quinn/examples/common/mod.rs#L69
    server_crypto.alpn_protocols = vec![b"hq-29".to_vec()];

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
        let stream = match stream {
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
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

async fn handle_stream((mut send, mut recv): (quinn::SendStream, quinn::RecvStream)) -> Result<()> {
    send.write_all(b"yo").await?;
    let mut buf = [0u8; 4];
    recv.read_exact(&mut buf).await?;
    info!("hello from client: {:?}", buf);
    send.close().await?;
    Ok(())
}
