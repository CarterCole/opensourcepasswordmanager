use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
#[command(name = "secretd-cli", about = "SecretD CLI — like vault CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    #[command(subcommand)]
    Kv(KvCommands),
}

#[derive(clap::Subcommand)]
enum KvCommands {
    Get { path: String },
    Put { path: String, data: Vec<String> },
    List { path: String },
    Delete { path: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    let _cli = Cli::parse();
    Ok(())
}
