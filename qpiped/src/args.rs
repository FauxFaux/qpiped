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
    pub server: String,
    #[clap(short, long, num_args = 1, required = true)]
    pub source: Vec<String>,
    #[clap(short, long, num_args = 1, required = true)]
    pub target: Vec<String>,
}

#[derive(Args)]
pub struct Serve {
    #[clap(default_value = "[::]:60010")]
    pub bind_address: String,
}
