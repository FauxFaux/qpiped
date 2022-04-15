mod args;

use std::env;
use std::net::ToSocketAddrs;

use anyhow::{bail, Context, Result};
use qpipe::frame::{FourCc, HeaderHeader};
use qpipe::package::read_package;
use qpipe::server::Certs;
use tokio::io::AsyncWriteExt;

use crate::args::{Command, Connect, Issue, Serve};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    use clap::Parser as _;
    let args: args::Cli = args::Cli::parse();

    match args.command {
        Command::Issue(sub) => issue(sub).await,
        Command::Connect(sub) => connect(sub).await,
        Command::Serve(sub) => serve(sub).await,
    }?;

    Ok(())
}

async fn issue(_args: Issue) -> Result<()> {
    let dirs = directories::ProjectDirs::from("xxx", "fau", "qpiped").unwrap();
    let path = dirs.data_local_dir();
    let (ca_cert, ca_key) = qpipe::certs::server(path, &["localhost"])?;
    let (client_cert, client_key) = qpipe::certs::mint_client(&ca_key)?;
    drop(ca_key);

    let mut buf = Vec::new();
    write_der(&mut buf, *b"scrt", &ca_cert.0).await?;
    write_der(&mut buf, *b"ccrt", &client_cert.0).await?;
    write_der(&mut buf, *b"ckey", &client_key.0).await?;
    HeaderHeader::finished().write_all(&mut buf).await?;
    println!("qpipe1:{}", base64::encode(buf));
    Ok(())
}

async fn write_der(
    mut writer: impl AsyncWriteExt + Unpin,
    four_cc: FourCc,
    der: &[u8],
) -> Result<()> {
    HeaderHeader {
        four_cc,
        data_len: u16::try_from(der.len())?,
    }
    .write_all(&mut writer)
    .await?;
    writer.write_all(der).await?;
    Ok(())
}

async fn connect(args: Connect) -> Result<()> {
    let package = env::var("PACKAGE").context("env var PACKAGE must contain a package")?;
    let certs = read_package(&package).await?;
    qpipe::client::run(args.target, &certs).await?;
    Ok(())
}

async fn serve(args: Serve) -> Result<()> {
    let dirs = directories::ProjectDirs::from("xxx", "fau", "qpiped").unwrap();
    let path = dirs.data_local_dir();
    let (cert, key) = qpipe::certs::server(path, &["localhost"])?;
    let addrs = args.bind_address.to_socket_addrs()?.collect::<Vec<_>>();
    if 1 != addrs.len() {
        bail!("wrong number of interfaces for me! {:?}", addrs);
    }
    qpipe::server::run(
        Certs {
            server_key: key,
            server_chain: vec![cert],
        },
        addrs[0],
    )
    .await?;
    Ok(())
}
