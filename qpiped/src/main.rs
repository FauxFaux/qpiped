mod args;

use std::env;
use std::net::ToSocketAddrs;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
// why
use base64::{engine::general_purpose::STANDARD as base64, Engine as _};
use qpipe::certs::generate_client_certs;
use qpipe::frame::{FourCc, HeaderHeader};
use qpipe::package::read_package;
use qpipe::server::Certs;
use tokio::io::AsyncWriteExt;

use crate::args::{Command, Connect, Issue, KeyGen, Serve};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    use clap::Parser as _;
    let args: args::Cli = args::Cli::parse();

    let dirs = directories::ProjectDirs::from("xxx", "fau", "qpiped")
        .ok_or(anyhow!("unable to locate ('XDG') state directory"))?;
    let shared = Shared {
        state_dir: dirs.data_local_dir().to_path_buf(),
    };

    match args.command {
        Command::KeyGen(sub) => keygen(&shared, sub).await,
        Command::Issue(sub) => issue(&shared, sub).await,
        Command::Connect(sub) => connect(&shared, sub).await,
        Command::Serve(sub) => serve(&shared, sub).await,
    }?;

    Ok(())
}

struct Shared {
    state_dir: PathBuf,
}

async fn keygen(_shared: &Shared, _args: KeyGen) -> Result<()> {
    let (csr, keys) = generate_client_certs()?;
    Ok(())
}

async fn issue(shared: &Shared, args: Issue) -> Result<()> {
    let (ca_cert, ca_key) = qpipe::certs::server(&shared.state_dir, &["localhost"])?;
    let client_cert = qpipe::certs::mint_client(&ca_key, &qpipe::certs::parse_client(&args.csr)?)?;
    drop(ca_key);

    let mut buf = Vec::new();
    write_der(&mut buf, *b"scrt", &ca_cert.0).await?;
    write_der(&mut buf, *b"ccrt", &client_cert.0).await?;
    HeaderHeader::finished().write_all(&mut buf).await?;
    println!("qpipe1:{}", base64.encode(buf));
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

async fn connect(_shared: &Shared, args: Connect) -> Result<()> {
    let package = env::var("PACKAGE").context("env var PACKAGE must contain a package")?;
    let certs = read_package(&package).await?;
    let mut mappings = Vec::new();
    match (args.source.len(), args.target.len()) {
        (1, 1) => mappings.push((args.source[0].to_string(), args.target[0].to_string())),
        // (_, 1) => all sources mapped onto that target
        // (1, _) => that sourc mapped onto all targets
        // (a, a) => -s foo -t bar, -s quux -t baz? (foo -> bar, quux -> baz)
        (_, _) => bail!(
            "not implemented, more than one source or target: {:?} {:?}",
            args.source,
            args.target
        ),
    };
    qpipe::client::run(args.server, &certs, &mappings).await?;
    Ok(())
}

async fn serve(_shared: &Shared, args: Serve) -> Result<()> {
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
