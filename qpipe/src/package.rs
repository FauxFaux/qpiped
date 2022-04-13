use anyhow::{anyhow, bail, ensure, Result};
use futures_util::AsyncReadExt;
use rustls::{Certificate, PrivateKey};

use crate::frame::HeaderHeader;

pub struct ClientCerts {
    pub server_cert: Certificate,
    pub client_cert: Certificate,
    pub client_key: PrivateKey,
}

pub async fn read_package(package: &str) -> Result<ClientCerts> {
    let package_magic = "qpipe1:";
    ensure!(
        package.starts_with(package_magic),
        "expected package magic, not {:?}...",
        package.chars().take(20).collect::<String>()
    );
    let mut package =
        futures_util::io::Cursor::new(base64::decode(&package[package_magic.len()..])?);
    let mut server_cert = None;
    let mut client_cert = None;
    let mut client_key = None;

    loop {
        let hh = HeaderHeader::from(&mut package).await?;
        let mut buf = vec![0u8; usize::from(hh.data_len)];
        package.read_exact(&mut buf).await?;
        match &hh.four_cc {
            b"scrt" => server_cert = Some(rustls::Certificate(buf)),
            b"ccrt" => client_cert = Some(rustls::Certificate(buf)),
            b"ckey" => client_key = Some(rustls::PrivateKey(buf)),
            b"fini" => break,
            // TODO: some kind of extension mechanism here
            _ => bail!("unexpected packet in package: {:?}", hh),
        }
    }

    Ok(ClientCerts {
        server_cert: server_cert.ok_or_else(|| anyhow!("missing server_cert in package"))?,
        client_cert: client_cert.ok_or_else(|| anyhow!("missing client_cert in package"))?,
        client_key: client_key.ok_or_else(|| anyhow!("missing client_key in package"))?,
    })
}
