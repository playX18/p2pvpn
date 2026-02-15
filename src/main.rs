mod contract;
mod tui;
mod vpn;
use crate::{tui::signer, vpn::OpenVpnCredentials};
use anyhow::Context;
use clap::{Parser, Subcommand};
use ethexe_ethereum::{primitives::Address, Ethereum};
use gsigner::PrivateKey;
use std::str::FromStr;

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
        /// Ethereum address of user to used for ranking VPN providers (optional).
        ///
        /// You have to import the corresponding private key using `import-key` command for this to work.
        #[arg(long)]
        sender_address: Address,
    },
    DeployContract {
        sender_address: gsigner::Address,
    },
    ImportKey {
        private_key: PrivateKey,
    },
}

const VARA_ETH_VALIDATOR: &str = "wss://vara-eth-validator-2.gear-tech.io";
const ETH_RPC: &str = "wss://hoodi-reth-rpc.gear-tech.io/ws";
const ROUTER_ADDRESS: &str = "0xBC888a8B050B9B76a985d91c815d2c4f2131a58A";
const VPN_ADDRESS: &str = "0x97d513e0106eae94b5fb61283b56358ced6a15f6";
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Connect {
            ovpn_username,
            ovpn_password,
            sender_address,
        } => {
            let signer = signer()?;
            let router =
                Address::from_str(ROUTER_ADDRESS).with_context(|| "Invalid router address")?;

            let eth = Ethereum::new(ETH_RPC, router.into(), signer, sender_address.into()).await?;
            let api = ethexe_sdk::VaraEthApi::new(VARA_ETH_VALIDATOR, eth).await?;

            let credentials = match (ovpn_username, ovpn_password) {
                (Some(username), Some(password)) => Some(OpenVpnCredentials { username, password }),
                (None, None) => None,
                _ => anyhow::bail!(
                    "both --ovpn-username and --ovpn-password must be provided together"
                ),
            };

            tui::connect(
                api,
                gsigner::Address::from_str(VPN_ADDRESS).with_context(|| "Invalid VPN address")?,
                credentials,
            )
            .await?
        }
        Commands::DeployContract { sender_address } => {
            tui::deploy(sender_address).await?;
        }
        Commands::ImportKey { private_key } => {
            tui::import_key(private_key).await?;
        }
    }

    Ok(())
}
