mod tui;
mod vpn;

use clap::{Parser, Subcommand};

use crate::vpn::OpenVpnCredentials;

#[derive(Parser)]
#[command(name = "p2pvpn", about = "Decentralised VPN client")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Connect to a VPN provider
    Connect {
        /// OpenVPN username (used only when profile needs auth-user-pass)
        #[arg(long)]
        ovpn_username: Option<String>,
        /// OpenVPN password (used only when profile needs auth-user-pass)
        #[arg(long)]
        ovpn_password: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Connect {
            ovpn_username,
            ovpn_password,
        } => {
            let credentials = match (ovpn_username, ovpn_password) {
                (Some(username), Some(password)) => Some(OpenVpnCredentials { username, password }),
                (None, None) => None,
                _ => anyhow::bail!(
                    "both --ovpn-username and --ovpn-password must be provided together"
                ),
            };
            tui::run(credentials).await?
        }
    }

    Ok(())
}
