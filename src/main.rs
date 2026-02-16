//! Command-line entrypoint for the `shadowsprout` binary.
//!
//! This module wires together:
//! - command parsing (`clap`),
//! - Ethereum/Vara API bootstrapping,
//! - and dispatch into interactive/runtime workflows in [`crate::tui`] and [`crate::vpn`].

mod contract;
mod tui;
mod vpn;
use crate::{tui::signer, vpn::OpenVpnCredentials};
use anyhow::Context;
use clap::{Parser, Subcommand};
use ethexe_ethereum::{primitives::Address, Ethereum};
use gsigner::PrivateKey;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Parser)]
#[command(name = "shadowsprout", about = "Decentralised VPN client")]
/// Top-level CLI parser for all user-facing operations.
///
/// Use [`Commands`] to choose runtime mode.
struct Cli {
    #[command(subcommand)]
    /// The subcommand to execute.
    command: Commands,
}

#[derive(Subcommand)]
/// Supported subcommands for operating the VPN client and contract tooling.
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
        #[arg(long, env = "SENDER_ADDRESS")]
        sender_address: Address,
        /// Router contract address used for Ethereum API connection.
        #[arg(long, env = "ROUTER_ADDRESS", default_value = ROUTER_ADDRESS)]
        router_address: String,
        /// VPN contract address used by the TUI connect flow.
        #[arg(long, env = "VPN_ADDRESS", default_value = VPN_ADDRESS)]
        vpn_address: String,
    },
    DeployContract {
        #[arg(env = "SENDER_ADDRESS")]
        sender_address: gsigner::Address,
    },
    /// Upload a VPN provider file to the contract
    UploadFile {
        /// Ethereum address used to send the on-chain message
        #[arg(long, env = "SENDER_ADDRESS")]
        sender_address: gsigner::Address,
        /// Provider key as 32-byte hex (with or without 0x prefix)
        #[arg(long)]
        provider_key: String,
        /// Provider display name
        #[arg(long)]
        name: String,
        /// VPN kind (for example: openvpn or wireguard)
        #[arg(long)]
        kind: String,
        /// Path to VPN configuration file
        #[arg(long)]
        file: PathBuf,
    },
    ImportKey {
        private_key: PrivateKey,
    },
}

const VARA_ETH_VALIDATOR: &str = "wss://vara-eth-validator-2.gear-tech.io";
/// Default Ethereum RPC endpoint used by the client.
const ETH_RPC: &str = "wss://hoodi-reth-rpc.gear-tech.io/ws";
/// Default router contract address for Ethexe routing operations.
const ROUTER_ADDRESS: &str = "0xBC888a8B050B9B76a985d91c815d2c4f2131a58A";
/// Default deployed VPN contract address used by the `connect` flow.
const VPN_ADDRESS: &str = "0xecf8c8bc27e503a4ddf0fb59187fe71d543c50d9";

/// Program entrypoint.
///
/// Parses CLI input, initializes required clients, validates optional credentials,
/// and dispatches into the selected workflow.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Connect {
            ovpn_username,
            ovpn_password,
            sender_address,
            router_address,
            vpn_address,
        } => {
            let signer = signer()?;
            let router =
                Address::from_str(&router_address).with_context(|| "Invalid router address")?;

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
                gsigner::Address::from_str(&vpn_address).with_context(|| "Invalid VPN address")?,
                credentials,
                tui::ApiReconnectConfig {
                    validator_endpoint: VARA_ETH_VALIDATOR.to_string(),
                    eth_rpc: ETH_RPC.to_string(),
                    router_address,
                    sender_address: sender_address.into(),
                },
            )
            .await?
        }
        Commands::DeployContract { sender_address } => {
            tui::deploy(sender_address).await?;
        }
        Commands::UploadFile {
            sender_address,
            provider_key,
            name,
            kind,
            file,
        } => {
            tui::upload_file(sender_address, provider_key, name, kind, file).await?;
        }
        Commands::ImportKey { private_key } => {
            tui::import_key(private_key).await?;
        }
    }

    Ok(())
}
