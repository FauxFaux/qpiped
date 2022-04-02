use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    Issue(Issue),
    Connect(Connect),

    Serve(Serve),
}

#[derive(Args)]
pub struct Issue {}

#[derive(Args)]
pub struct Connect {
    pub target: String,
}

#[derive(Args)]
pub struct Serve {
    #[clap(default_value = "[::]:60010")]
    pub bind_address: String,
}
