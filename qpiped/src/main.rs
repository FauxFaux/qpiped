mod args;

use std::net::ToSocketAddrs;

use anyhow::{bail, Result};
use qpipe::server::Certs;

use crate::args::{Command, Connect, Serve};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    use clap::Parser as _;
    let args: args::Cli = args::Cli::parse();

    match args.command {
        Command::Issue(_) => unimplemented!("issue"),
        Command::Connect(sub) => connect(sub).await,
        Command::Serve(sub) => serve(sub).await,
    }?;

    Ok(())
}

async fn connect(args: Connect) -> Result<()> {
    let dirs = directories::ProjectDirs::from("xxx", "fau", "qpiped").unwrap();
    let path = dirs.data_local_dir();
    let (cert, _key) = qpipe::certs::server(path, &["localhost"])?;
    qpipe::client::run(args.target, &cert).await?;
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
