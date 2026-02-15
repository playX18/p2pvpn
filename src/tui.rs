use crate::contract::{self, H256};
use crate::vpn;
use crate::vpn::{OpenVpnCredentials, OpenVpnSession};
use alloy::{
    consensus::{SidecarBuilder, SimpleCoder},
    eips::BlockNumberOrTag,
    providers::Provider as AlloyProviderExt,
};
use anyhow::Context;
use blake2::{digest::typenum::U32, Blake2b, Digest};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};

use ethexe_common::gear::CodeState;
use ethexe_ethereum::{abi::IRouter, TryGetReceipt};
use ethexe_sdk::VaraEthApi;
use gprimitives::CodeId;
//use gprimitives::CodeId;
use gsigner::secp256k1::Signer;
use gsigner::{Address, PrivateKey};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, List, ListItem, Paragraph},
};
use sails_rs::client::CallCodec;
use std::io;
use tokio::task;

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

struct Provider {
    name: String,
    key: H256,
    file_kind: String,
    failed: bool,
}

#[derive(Clone, Copy)]
enum Phase {
    Selecting,
    PromptCredentials(usize),
    Connecting(usize),
    Connected,
}

enum CredentialField {
    Username,
    Password,
}

pub struct App {
    providers: Vec<Provider>,
    selected: usize,
    phase: Phase,
    status_msg: String,
    credentials: Option<OpenVpnCredentials>,
    credentials_from_prompt: bool,
    active_session: Option<OpenVpnSession>,
    credential_field: CredentialField,
    username_input: String,
    password_input: String,
    pub api: VaraEthApi,
    pub vpn_contract: Address,
}

impl App {
    pub async fn fetch_provider_file(
        api: &VaraEthApi,
        vpn_contract: Address,
        provider: H256,
    ) -> anyhow::Result<contract::VpnFile> {
        let prefix = stringify!(P2PvpnContract);
        let msg = p2pvpn_contract_client::p_2_pvpn_contract::io::FetchProviderFile::encode_params_with_prefix(
            prefix,
            provider.0,
        );

        let reply = api
            .mirror(vpn_contract.into())
            .calculate_reply_for_handle(&msg, 0)
            .await?;

        if !reply.code.is_success() {
            panic!(
                "failed to fetch provider file: reply code {}, message: {}",
                reply.code,
                std::str::from_utf8(&reply.payload).unwrap()
            );
        }
        let (kind, config) =
            p2pvpn_contract_client::p_2_pvpn_contract::io::FetchProviderFile::decode_reply_with_prefix(
                prefix,
                &reply.payload,
            )?;

        match kind.as_str() {
            "openvpn" => Ok(contract::VpnFile::OpenVpn(config.as_bytes().to_vec())),
            "wireguard" => Ok(contract::VpnFile::Wireguard(config.as_bytes().to_vec())),
            _ => anyhow::bail!("unsupported VPN file kind: {}", kind),
        }
    }

    async fn new(
        api: VaraEthApi,
        contract: Address,
        credentials: Option<OpenVpnCredentials>,
    ) -> anyhow::Result<Self> {
        //        let mut msg = stringify!(P2PvpnContract).as_bytes().to_vec();
        let prefix = stringify!(P2PvpnContract);
        let msg = p2pvpn_contract_client::p_2_pvpn_contract::io::FetchProviders::encode_params_with_prefix(prefix);
        let reply = api
            .mirror(contract.into())
            .calculate_reply_for_handle(&msg, 0)
            .await?;
        if !reply.code.is_success() {
            return Err(anyhow::anyhow!(
                "failed to fetch providers: reply code {}, message: {}",
                reply.code,
                std::str::from_utf8(&reply.payload)?
            ));
        }
        let provider_list =
            p2pvpn_contract_client::p_2_pvpn_contract::io::FetchProviders::decode_reply_with_prefix(
                prefix,
                &reply.payload,
            )?;
        //let provider_list = contract::fetch_providers().await;
        let mut providers = Vec::with_capacity(provider_list.len());

        for (key, name) in provider_list {
            let file = Self::fetch_provider_file(&api, contract, H256(key)).await?;
            providers.push(Provider {
                name,
                key: H256(key),
                file_kind: file.kind().to_string(),
                failed: false,
            });
        }

        Ok(Self {
            providers,
            selected: 0,
            phase: Phase::Selecting,
            status_msg: String::from("Select a provider and press Enter to connect."),
            credentials,
            credentials_from_prompt: false,
            active_session: None,
            credential_field: CredentialField::Username,
            username_input: String::new(),
            password_input: String::new(),
            api,
            vpn_contract: contract,
        })
    }

    /// Move selection up, skipping failed providers.
    fn move_up(&mut self) {
        let len = self.providers.len();
        for i in 1..len {
            let idx = (self.selected + len - i) % len;
            if !self.providers[idx].failed {
                self.selected = idx;
                return;
            }
        }
    }

    /// Move selection down, skipping failed providers.
    fn move_down(&mut self) {
        let len = self.providers.len();
        for i in 1..len {
            let idx = (self.selected + i) % len;
            if !self.providers[idx].failed {
                self.selected = idx;
                return;
            }
        }
    }

    /// Ensure `selected` points at a non-failed entry.
    fn fix_selection(&mut self) {
        if !self.providers[self.selected].failed {
            return;
        }
        self.move_down();
    }

    fn all_failed(&self) -> bool {
        self.providers.iter().all(|p| p.failed)
    }

    fn reset_prompt_state(&mut self) {
        self.credential_field = CredentialField::Username;
        self.username_input.clear();
        self.password_input.clear();
    }

    fn prompt_status(&self) -> String {
        match self.credential_field {
            CredentialField::Username => {
                format!("OpenVPN username: {}", self.username_input)
            }
            CredentialField::Password => format!(
                "OpenVPN password: {}",
                "*".repeat(self.password_input.chars().count())
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// UI rendering
// ---------------------------------------------------------------------------

fn draw(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(5), Constraint::Length(3)])
        .split(frame.area());

    // -- Provider list --
    let items: Vec<ListItem> = app
        .providers
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let label = format!("{} [{}] ({})", p.name, p.key.short(), p.file_kind);

            let style = if p.failed {
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::CROSSED_OUT)
            } else if i == app.selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };

            let prefix = if i == app.selected && !p.failed {
                "▸ "
            } else {
                "  "
            };

            ListItem::new(format!("{prefix}{label}")).style(style)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .title(" p2pvpn – Providers ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    );
    frame.render_widget(list, chunks[0]);

    // -- Status bar --
    let status = Paragraph::new(app.status_msg.as_str())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .style(Style::default().fg(Color::Green));
    frame.render_widget(status, chunks[1]);
}

fn read_event_blocking() -> anyhow::Result<Event> {
    task::block_in_place(event::read).map_err(Into::into)
}

// ---------------------------------------------------------------------------
// Event loop
// ---------------------------------------------------------------------------

pub async fn connect(
    api: VaraEthApi,
    contract: Address,
    credentials: Option<OpenVpnCredentials>,
) -> anyhow::Result<()> {
    // Setup terminal.
    enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(api, contract, credentials).await?;

    loop {
        terminal.draw(|f| draw(f, &app))?;

        match app.phase {
            Phase::Selecting => {
                if let Event::Key(key) = read_event_blocking()? {
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => break,
                        KeyCode::Up | KeyCode::Char('k') => app.move_up(),
                        KeyCode::Down | KeyCode::Char('j') => app.move_down(),
                        KeyCode::Enter => {
                            if app.all_failed() {
                                app.status_msg =
                                    "All providers have failed. Press q to quit.".into();
                            } else {
                                let selected = app.selected;
                                if app.credentials.is_none()
                                    && vpn::provider_requires_credentials(
                                        &app,
                                        app.providers[selected].key,
                                    )
                                    .await?
                                {
                                    app.reset_prompt_state();
                                    app.phase = Phase::PromptCredentials(selected);
                                    app.status_msg = app.prompt_status();
                                } else {
                                    app.phase = Phase::Connecting(selected);
                                    app.status_msg =
                                        format!("Connecting to {}…", app.providers[selected].name);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            Phase::PromptCredentials(idx) => {
                if let Event::Key(key) = read_event_blocking()? {
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }

                    match key.code {
                        KeyCode::Esc => {
                            app.reset_prompt_state();
                            app.phase = Phase::Selecting;
                            app.status_msg =
                                "Credential input cancelled. Select a provider and press Enter."
                                    .into();
                        }
                        KeyCode::Backspace => match app.credential_field {
                            CredentialField::Username => {
                                app.username_input.pop();
                                app.status_msg = app.prompt_status();
                            }
                            CredentialField::Password => {
                                app.password_input.pop();
                                app.status_msg = app.prompt_status();
                            }
                        },
                        KeyCode::Enter => match app.credential_field {
                            CredentialField::Username => {
                                if app.username_input.is_empty() {
                                    app.status_msg = "Username cannot be empty.".into();
                                } else {
                                    app.credential_field = CredentialField::Password;
                                    app.status_msg = app.prompt_status();
                                }
                            }
                            CredentialField::Password => {
                                if app.password_input.is_empty() {
                                    app.status_msg = "Password cannot be empty.".into();
                                } else {
                                    app.credentials = Some(OpenVpnCredentials {
                                        username: app.username_input.clone(),
                                        password: app.password_input.clone(),
                                    });
                                    app.credentials_from_prompt = true;
                                    app.reset_prompt_state();
                                    app.phase = Phase::Connecting(idx);
                                    app.status_msg =
                                        format!("Connecting to {}…", app.providers[idx].name);
                                }
                            }
                        },
                        KeyCode::Char(ch) => match app.credential_field {
                            CredentialField::Username => {
                                app.username_input.push(ch);
                                app.status_msg = app.prompt_status();
                            }
                            CredentialField::Password => {
                                app.password_input.push(ch);
                                app.status_msg = app.prompt_status();
                            }
                        },
                        _ => {}
                    }
                }
            }
            Phase::Connecting(idx) => {
                // Redraw with "connecting" status, then attempt.
                terminal.draw(|f| draw(f, &app))?;

                let provider = &app.providers[idx];
                match vpn::try_connect(&app, provider.key, app.credentials.as_ref()).await? {
                    vpn::ConnectionAttempt::Connected(session) => {
                        app.active_session = Some(session);
                        app.phase = Phase::Connected;
                        app.status_msg = format!(
                            "✔ Connected to {}! Press q to disconnect & quit.",
                            app.providers[idx].name
                        );
                    }
                    vpn::ConnectionAttempt::Failed(reason) => {
                        if app.credentials_from_prompt {
                            app.credentials = None;
                            app.credentials_from_prompt = false;
                            app.reset_prompt_state();
                        }
                        app.providers[idx].failed = true;
                        app.status_msg = format!(
                            "✘ Connection to {} failed: {reason}. Select another provider.",
                            app.providers[idx].name
                        );
                        app.fix_selection();
                        app.phase = Phase::Selecting;
                    }
                }
            }
            Phase::Connected => {
                if let Event::Key(key) = read_event_blocking()? {
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }
                    if matches!(
                        key.code,
                        KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc
                    ) {
                        if let Some(session) = app.active_session.as_mut() {
                            let _ = session.terminate().await;
                        }
                        break;
                    }
                }
            }
        }
    }

    if let Some(session) = app.active_session.as_mut() {
        let _ = session.terminate().await;
    }

    // Restore terminal.
    disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;
    Ok(())
}

pub fn signer() -> anyhow::Result<Signer> {
    let dirs = directories::ProjectDirs::from("com", "gear", "ratatui")
        .context("failed to get project directories")?;
    let signer = Signer::fs(dirs.data_dir().join("keys"))?;
    Ok(signer)
}

pub async fn import_key(private_key: PrivateKey) -> anyhow::Result<()> {
    let signer = signer()?;
    let public_key = signer.import(private_key)?;
    println!("Imported key: {public_key}");
    println!("Address: {}", public_key.to_address());
    Ok(())
}

fn code_id_for(wasm: &[u8]) -> CodeId {
    type Blake2b256 = Blake2b<U32>;

    let mut hasher = Blake2b256::new();
    hasher.update(wasm);
    CodeId::new(hasher.finalize().into())
}

pub async fn deploy(sender_address: Address) -> anyhow::Result<()> {
    const RPC: &str = "wss://hoodi-reth-rpc.gear-tech.io/ws";

    let router_address = "0xBC888a8B050B9B76a985d91c815d2c4f2131a58A"
        .parse()
        .context("failed to parse router address")?;

    let signer = signer()?;

    println!("Connecting to {RPC}");
    let ethereum =
        ethexe_ethereum::Ethereum::new(RPC, router_address, signer, sender_address).await?;
    let provider = ethereum.provider();
    let router = IRouter::IRouterInstance::new(router_address.into(), provider.clone());
    let code = p2pvpn_contract::WASM_BINARY;
    let code_id = code_id_for(code);
    println!("Uploading code: {code_id}, len={} kb", code.len() / 1024);
    let chain_id = provider
        .get_chain_id()
        .await
        .context("failed to fetch chain id")?;
    let state = ethereum.router().query().code_state(code_id).await?;
    if let CodeState::Validated = state {
        println!("Code already uploaded and validated");
    } else if let CodeState::ValidationRequested = state {
        println!("Code validation already requested, waiting for result...");
        let res = ethereum.router().wait_for_code_validation(code_id).await?;
        anyhow::ensure!(res.valid, "code validation failed");
    } else {
        println!("Code not found on-chain, uploading...");

        let upload = router.requestCodeValidation(code_id.into_bytes().into());
        let upload = if chain_id == 31337 {
            upload.sidecar(SidecarBuilder::<SimpleCoder>::from_slice(code).build()?)
        } else {
            let base_fee_per_blob_gas = provider
                .get_fee_history(2, BlockNumberOrTag::Latest, &[] as &[f64])
                .await
                .context("failed to fetch blob fee history")?
                .base_fee_per_blob_gas
                .last()
                .copied()
                .context("blob fee history is missing base blob fee")?;

            upload
                .sidecar_7594(SidecarBuilder::<SimpleCoder>::from_slice(code).build_7594()?)
                .max_fee_per_blob_gas(base_fee_per_blob_gas.saturating_mul(3))
        };
        upload
            .send()
            .await
            .context("failed to submit code upload transaction")?
            .try_get_receipt_check_reverted()
            .await
            .context("failed to upload code")?;

        let router_client = ethereum.router();
        let res = router_client.wait_for_code_validation(code_id).await?;
        anyhow::ensure!(res.valid, "code validation failed");
    }
    let router_client = ethereum.router();
    println!("Creating program from {code_id} code ID");
    let salt: [u8; 32] = rand::random();
    let (_, actor_id) = router_client
        .create_program(code_id, salt.into(), None)
        .await
        .context("failed to create program")?;

    println!("Approving {actor_id} to spend VARA and top-up mirror balance");
    ethereum
        .wrapped_vara()
        .approve(actor_id, 1000 * 10u128.pow(12))
        .await?;
    println!("Topping up mirror balance for {actor_id}");
    ethereum
        .mirror(actor_id)
        .executable_balance_top_up(1000 * 10u128.pow(12))
        .await?;
    println!("Topped up");

    println!("Initializing contract");
    let (_, msg_id) = ethereum
        .mirror(actor_id)
        .send_message(p2pvpn_contract_client::io::Create::encode_params(), 0)
        .await?;

    let reply = ethereum.mirror(actor_id).wait_for_reply(msg_id).await?;
    println!("Initialization reply received");
    anyhow::ensure!(
        reply.code.is_success(),
        "contract initialization failed: code {}, message: {}",
        reply.code,
        std::str::from_utf8(&reply.payload)?
    );

    println!("Actor ID: {actor_id}");

    Ok(())
}
