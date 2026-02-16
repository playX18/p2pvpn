#![allow(dead_code)]
//! Terminal UI and contract operation helpers.
//!
//! This module hosts two groups of functionality:
//! - interactive provider selection and connection workflow (`connect`),
//! - command helpers for key import, contract deployment, and provider-file upload.

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
use ethexe_ethereum::{
    abi::IRouter, primitives::Address as EthereumAddress, Ethereum, TryGetReceipt,
};
use ethexe_sdk::VaraEthApi;
use gprimitives::CodeId;
//use gprimitives::CodeId;
use gsigner::secp256k1::Signer;
use gsigner::{Address, PrivateKey};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Gauge, List, ListItem, Paragraph},
};
use sails_rs::client::CallCodec;
use std::io;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;
use tokio::task;
use tokio::time::{timeout, Duration};

// ---------------------------------------------------------------------------
// Channel message types for background task communication
// ---------------------------------------------------------------------------

/// Tasks that the main UI thread sends to the background worker.
enum TaskRequest {
    /// Connect to a VPN provider.
    Connect {
        provider_key: H256,
        provider_name: String,
        credentials: Option<OpenVpnCredentials>,
    },
    /// Disconnect active VPN session, reconnect API, and rank provider.
    Disconnect {
        session: OpenVpnSession,
        provider_key: H256,
        provider_name: String,
    },
    /// Rank a provider on-chain.
    RankProvider { provider: H256, good: bool },
    /// Terminate the background worker.
    Shutdown,
}

/// Responses that the background worker sends back to the main UI thread.
enum TaskResponse {
    /// VPN connection succeeded.
    Connected {
        session: OpenVpnSession,
        provider_key: H256,
        provider_name: String,
    },
    /// VPN connection failed.
    ConnectionFailed { provider_key: H256, reason: String },
    /// API reconnection completed in background worker.
    ApiReconnected { api: Arc<VaraEthApi> },
    /// Disconnect and cleanup completed.
    Disconnected {
        provider_key: H256,
        provider_name: String,
        rank_success: bool,
    },
    /// Provider ranking completed.
    ProviderRanked {
        provider: H256,
        good: bool,
        new_rank: i32,
    },
    /// Background task encountered an error.
    Error(String),
}

/// Tracks pending operations for UI display.
#[derive(Clone, Debug)]
enum PendingOperation {
    /// Connecting to a provider.
    Connecting { provider_name: String },
    /// Disconnecting from a provider.
    Disconnecting { provider_name: String },
}

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

struct Provider {
    /// Human-readable provider label.
    name: String,
    /// Stable provider key used on-chain.
    key: H256,
    /// Provider reputation score used for sorting.
    rank: i32,
    /// Human-readable VPN file type (OpenVPN/WireGuard).
    file_kind: String,
    /// Whether the provider has failed during this UI session.
    failed: bool,
}

#[derive(Clone, Copy)]
enum Phase {
    /// User navigates and chooses a provider.
    Selecting,
    /// User enters missing OpenVPN credentials.
    PromptCredentials(usize),
    /// Connection attempt is in progress for selected index.
    Connecting(usize),
    /// Tunnel is active.
    Connected,
}

enum CredentialField {
    /// Username input cursor is active.
    Username,
    /// Password input cursor is active.
    Password,
}

/// Mutable state backing the terminal UI loop.
///
/// It tracks provider metadata, UI phase transitions, live status text,
/// optional credentials, active session process handle, and chain clients.
pub struct App {
    providers: Vec<Provider>,
    selected: usize,
    phase: Phase,
    status_msg: String,
    credentials: Option<OpenVpnCredentials>,
    credentials_from_prompt: bool,
    active_session: Option<OpenVpnSession>,
    connected_provider: Option<(H256, String)>,
    credential_field: CredentialField,
    username_input: String,
    password_input: String,
    pub api: Arc<VaraEthApi>,
    api_reconnect: ApiReconnectConfig,
    pub vpn_contract: Address,
    ui_tick: usize,
    phase_started_at: Instant,
    /// Channel for sending tasks to the background worker.
    task_sender: mpsc::Sender<TaskRequest>,
    /// Channel for receiving responses from the background worker.
    response_receiver: mpsc::Receiver<TaskResponse>,
    /// Current pending operation for UI display.
    pending_operation: Option<PendingOperation>,
}

#[derive(Clone)]
pub struct ApiReconnectConfig {
    pub validator_endpoint: String,
    pub eth_rpc: String,
    pub router_address: String,
    pub sender_address: Address,
}

impl App {
    /// Fetches a provider configuration file by calling the VPN contract mirror.
    ///
    /// Converts contract wire format into [`contract::VpnFile`].
    pub async fn fetch_provider_file(
        api: &VaraEthApi,
        vpn_contract: Address,
        provider: H256,
    ) -> anyhow::Result<contract::VpnFile> {
        let prefix = stringify!(ShadowsproutContract);
        let msg = shadowsprout_contract_client::shadowsprout_contract::io::FetchProviderFile::encode_params_with_prefix(
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
            shadowsprout_contract_client::shadowsprout_contract::io::FetchProviderFile::decode_reply_with_prefix(
                prefix,
                &reply.payload,
            )?;

        match kind.as_str() {
            "openvpn" => Ok(contract::VpnFile::OpenVpn(config.as_bytes().to_vec())),
            "wireguard" => Ok(contract::VpnFile::Wireguard(config.as_bytes().to_vec())),
            _ => anyhow::bail!("unsupported VPN file kind: {}", kind),
        }
    }

    /// Constructs initial app state and preloads providers from the contract.
    ///
    /// Provider list is enriched with file kind information and sorted by rank.
    async fn new(
        api: Arc<VaraEthApi>,
        contract: Address,
        credentials: Option<OpenVpnCredentials>,
        api_reconnect: ApiReconnectConfig,
        task_sender: mpsc::Sender<TaskRequest>,
        response_receiver: mpsc::Receiver<TaskResponse>,
    ) -> anyhow::Result<Self> {
        //        let mut msg = stringify!(ShadowsproutContract).as_bytes().to_vec();
        let prefix = stringify!(ShadowsproutContract);
        let msg = shadowsprout_contract_client::shadowsprout_contract::io::FetchProviders::encode_params_with_prefix(prefix);
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
            shadowsprout_contract_client::shadowsprout_contract::io::FetchProviders::decode_reply_with_prefix(
                prefix,
                &reply.payload,
            )?;
        //let provider_list = contract::fetch_providers().await;
        let mut providers = Vec::with_capacity(provider_list.len());

        for (key, name, rank) in provider_list {
            let file = Self::fetch_provider_file(&api, contract, H256(key)).await?;
            providers.push(Provider {
                name,
                key: H256(key),
                rank,
                file_kind: file.kind().to_string(),
                failed: false,
            });
        }

        let mut app = Self {
            providers,
            selected: 0,
            phase: Phase::Selecting,
            status_msg: String::from("Select a provider and press Enter to connect."),
            credentials,
            credentials_from_prompt: false,
            active_session: None,
            connected_provider: None,
            credential_field: CredentialField::Username,
            username_input: String::new(),
            password_input: String::new(),
            api,
            api_reconnect,
            vpn_contract: contract,
            ui_tick: 0,
            phase_started_at: Instant::now(),
            task_sender,
            response_receiver,
            pending_operation: None,
        };
        app.sort_providers_by_rank();
        Ok(app)
    }

    /// Transitions application phase and resets phase timer.
    fn set_phase(&mut self, phase: Phase) {
        self.phase = phase;
        self.phase_started_at = Instant::now();
    }

    /// Advances the spinner animation frame counter.
    fn tick(&mut self) {
        self.ui_tick = self.ui_tick.wrapping_add(1);
    }

    /// Returns current spinner glyph for animated UI status elements.
    fn spinner(&self) -> &'static str {
        const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        FRAMES[self.ui_tick % FRAMES.len()]
    }

    /// Returns display title for the current UI phase.
    fn phase_title(&self) -> &'static str {
        match self.phase {
            Phase::Selecting => "Selecting Provider",
            Phase::PromptCredentials(_) => "Credentials",
            Phase::Connecting(_) => "Connecting",
            Phase::Connected => "Connected",
        }
    }

    /// Maps current phase to a coarse completion ratio for progress rendering.
    fn phase_ratio(&self) -> f64 {
        match self.phase {
            Phase::Selecting => 0.12,
            Phase::PromptCredentials(_) => 0.35,
            Phase::Connecting(_) => {
                let elapsed = self.phase_started_at.elapsed().as_secs_f64();
                let fraction = (elapsed / 60.0).clamp(0.0, 1.0);
                0.35 + fraction * 0.6
            }
            Phase::Connected => 1.0,
        }
    }

    /// Returns contextual keybinding hints for the status bar.
    fn key_hints(&self) -> &'static str {
        match self.phase {
            Phase::Selecting => "↑/↓ move • Enter connect • Q quit",
            Phase::PromptCredentials(_) => "Type input • Enter continue • Esc cancel",
            Phase::Connecting(_) => "Esc/Q abort • Negotiating tunnel…",
            Phase::Connected => "Q disconnect • Esc quit",
        }
    }

    /// Submits a provider ranking vote and updates local ranking cache.
    ///
    /// `good = true` increments provider rank; `false` decrements.
    async fn rank_provider(&mut self, provider: H256, good: bool) -> anyhow::Result<()> {
        let prefix = stringify!(ShadowsproutContract);
        let msg =
            shadowsprout_contract_client::shadowsprout_contract::io::RankProvider::encode_params_with_prefix(
                prefix, provider.0, good,
            );

        let (_msg_id, promise) = self
            .api
            .mirror(self.vpn_contract.into())
            .send_message_injected_and_watch(msg, 0)
            .await?;
        let reply = promise.reply;

        anyhow::ensure!(
            reply.code.is_success(),
            "failed to rank provider: code {}, message: {}",
            reply.code,
            std::str::from_utf8(&reply.payload).unwrap_or("<non-utf8>")
        );

        if let Some(p) = self.providers.iter_mut().find(|p| p.key == provider) {
            p.rank += if good { 1 } else { -1 };
        }
        self.sort_providers_by_rank();

        Ok(())
    }

    /// Sorts providers by rank descending, then by name ascending.
    ///
    /// Attempts to keep the same selected provider key focused after sorting.
    fn sort_providers_by_rank(&mut self) {
        if self.providers.is_empty() {
            self.selected = 0;
            return;
        }

        let selected_key = self.providers.get(self.selected).map(|p| p.key);

        self.providers
            .sort_by(|a, b| b.rank.cmp(&a.rank).then_with(|| a.name.cmp(&b.name)));

        if let Some(key) = selected_key {
            if let Some(new_selected) = self.providers.iter().position(|p| p.key == key) {
                self.selected = new_selected;
                return;
            }
        }

        if self.selected >= self.providers.len() {
            self.selected = self.providers.len() - 1;
        }
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

    /// Returns `true` when all currently listed providers are marked failed.
    fn all_failed(&self) -> bool {
        self.providers.iter().all(|p| p.failed)
    }

    /// Clears credential prompt UI buffers and resets input field focus.
    fn reset_prompt_state(&mut self) {
        self.credential_field = CredentialField::Username;
        self.username_input.clear();
        self.password_input.clear();
    }

    /// Builds current credential prompt line for status rendering.
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

async fn build_api(config: ApiReconnectConfig) -> anyhow::Result<VaraEthApi> {
    let signer = signer()?;
    let router =
        EthereumAddress::from_str(&config.router_address).context("Invalid router address")?;

    let eth = Ethereum::new(
        &config.eth_rpc,
        router.into(),
        signer,
        config.sender_address,
    )
    .await
    .context("failed to reconnect Ethereum API")?;

    VaraEthApi::new(&config.validator_endpoint, eth)
        .await
        .context("failed to reconnect VaraEthApi")
}

// ---------------------------------------------------------------------------
// Background task worker
// ---------------------------------------------------------------------------

/// Background worker that processes tasks from the main UI thread.
async fn background_worker(
    mut task_receiver: mpsc::Receiver<TaskRequest>,
    response_sender: mpsc::Sender<TaskResponse>,
    api: Arc<VaraEthApi>,
    vpn_contract: Address,
    reconnect_config: ApiReconnectConfig,
) {
    let mut api = api;

    while let Some(task) = task_receiver.recv().await {
        match task {
            TaskRequest::Connect {
                provider_key,
                provider_name,
                credentials,
            } => {
                let cancel_flag = Arc::new(AtomicBool::new(false));
                let cancel_for_task = Arc::clone(&cancel_flag);

                let result = timeout(
                    Duration::from_secs(60),
                    vpn::try_connect(
                        api.as_ref(),
                        vpn_contract,
                        provider_key,
                        credentials.as_ref(),
                        cancel_for_task,
                    ),
                )
                .await;

                match result {
                    Ok(Ok(vpn::ConnectionAttempt::Connected(session))) => {
                        let _ = response_sender
                            .send(TaskResponse::Connected {
                                session,
                                provider_key,
                                provider_name,
                            })
                            .await;
                    }
                    Ok(Ok(vpn::ConnectionAttempt::Failed(reason))) => {
                        // Auto-reconnect API on failure
                        if let Ok(new_api) = build_api(reconnect_config.clone()).await {
                            api = Arc::new(new_api);
                            let _ = response_sender
                                .send(TaskResponse::ApiReconnected {
                                    api: Arc::clone(&api),
                                })
                                .await;
                        }
                        let _ = response_sender
                            .send(TaskResponse::ConnectionFailed {
                                provider_key,
                                reason,
                            })
                            .await;
                    }
                    Ok(Err(e)) => {
                        // Auto-reconnect API on error
                        if let Ok(new_api) = build_api(reconnect_config.clone()).await {
                            api = Arc::new(new_api);
                            let _ = response_sender
                                .send(TaskResponse::ApiReconnected {
                                    api: Arc::clone(&api),
                                })
                                .await;
                        }
                        let _ = response_sender
                            .send(TaskResponse::ConnectionFailed {
                                provider_key,
                                reason: e.to_string(),
                            })
                            .await;
                    }
                    Err(_) => {
                        // Timeout - auto-reconnect API
                        if let Ok(new_api) = build_api(reconnect_config.clone()).await {
                            api = Arc::new(new_api);
                            let _ = response_sender
                                .send(TaskResponse::ApiReconnected {
                                    api: Arc::clone(&api),
                                })
                                .await;
                        }
                        let _ = response_sender
                            .send(TaskResponse::ConnectionFailed {
                                provider_key,
                                reason: "connection timed out after 60 seconds".to_string(),
                            })
                            .await;
                    }
                }
            }
            TaskRequest::Disconnect {
                mut session,
                provider_key,
                provider_name,
            } => {
                // Terminate the VPN session
                let _ = session.terminate().await;

                // Reconnect API
                if let Ok(new_api) = build_api(reconnect_config.clone()).await {
                    api = Arc::new(new_api);
                    let _ = response_sender
                        .send(TaskResponse::ApiReconnected {
                            api: Arc::clone(&api),
                        })
                        .await;
                }

                // Rank provider (good = true for successful disconnect)
                let rank_success = rank_provider_internal(&api, vpn_contract, provider_key, true)
                    .await
                    .is_ok();

                let _ = response_sender
                    .send(TaskResponse::Disconnected {
                        provider_key,
                        provider_name,
                        rank_success,
                    })
                    .await;
            }
            TaskRequest::RankProvider { provider, good } => {
                let result = rank_provider_internal(&api, vpn_contract, provider, good).await;
                let new_rank = if result.is_ok() {
                    if good {
                        1
                    } else {
                        -1
                    }
                } else {
                    0
                };
                let _ = response_sender
                    .send(TaskResponse::ProviderRanked {
                        provider,
                        good,
                        new_rank,
                    })
                    .await;
            }
            TaskRequest::Shutdown => break,
        }
    }
}

/// Internal helper to rank a provider on-chain.
async fn rank_provider_internal(
    api: &VaraEthApi,
    vpn_contract: Address,
    provider: H256,
    good: bool,
) -> anyhow::Result<()> {
    let prefix = stringify!(ShadowsproutContract);
    let msg =
        shadowsprout_contract_client::shadowsprout_contract::io::RankProvider::encode_params_with_prefix(
            prefix, provider.0, good,
        );

    let (_msg_id, promise) = api
        .mirror(vpn_contract.into())
        .send_message_injected_and_watch(msg, 0)
        .await?;
    let reply = promise.reply;

    anyhow::ensure!(
        reply.code.is_success(),
        "failed to rank provider: code {}, message: {}",
        reply.code,
        std::str::from_utf8(&reply.payload).unwrap_or("<non-utf8>")
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// UI rendering
// ---------------------------------------------------------------------------

/// Renders current application frame, including providers, progress, and status.
fn draw(frame: &mut Frame, app: &App) {
    let show_progress = matches!(app.phase, Phase::Connecting(_));
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(if show_progress {
            vec![
                Constraint::Min(5),
                Constraint::Length(3),
                Constraint::Length(3),
            ]
        } else {
            vec![Constraint::Min(5), Constraint::Length(3)]
        })
        .split(frame.area());

    // -- Provider list --
    let items: Vec<ListItem> = app
        .providers
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let label = format!(
                "{} [{}] ({}, rank: {})",
                p.name,
                p.key.short(),
                p.file_kind,
                p.rank
            );

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

    let provider_title = match app.phase {
        Phase::Connecting(idx) => format!(
            " shadowsprout – Providers  {} Connecting to {} (Esc to abort) ",
            app.spinner(),
            app.providers[idx].name
        ),
        _ => " shadowsprout – Providers ".to_string(),
    };

    let list = List::new(items).block(
        Block::default()
            .title(provider_title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    );
    frame.render_widget(list, chunks[0]);

    if show_progress {
        // -- Progress bar --
        let ratio = app.phase_ratio();
        let percent = (ratio * 100.0).round() as u16;
        let progress = Gauge::default()
            .block(
                Block::default()
                    .title(format!(" {} ", app.phase_title()))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            )
            .gauge_style(
                Style::default()
                    .fg(Color::Magenta)
                    .bg(Color::Black)
                    .add_modifier(Modifier::BOLD),
            )
            .ratio(ratio)
            .label(format!("{:>3}%", percent));
        frame.render_widget(progress, chunks[1]);
    }

    // -- Status bar --
    let status_prefix = if matches!(
        app.pending_operation,
        Some(PendingOperation::Connecting { .. })
    ) || matches!(
        app.pending_operation,
        Some(PendingOperation::Disconnecting { .. })
    ) || matches!(app.phase, Phase::Connecting(_))
    {
        format!("{} ", app.spinner())
    } else {
        String::new()
    };
    let status_text = format!(
        "{}{}  │  {}",
        status_prefix,
        app.status_msg,
        app.key_hints()
    );
    let status = Paragraph::new(status_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .style(Style::default().fg(Color::Green));
    let status_chunk = if show_progress { chunks[2] } else { chunks[1] };
    frame.render_widget(status, status_chunk);
}

/// Blocks until a terminal event is available and converts errors into `anyhow`.
fn read_event_blocking() -> anyhow::Result<Event> {
    task::block_in_place(event::read).map_err(Into::into)
}

// ---------------------------------------------------------------------------
// Event loop
// ---------------------------------------------------------------------------

/// Runs the interactive VPN connection TUI.
///
/// Behavior summary:
/// - initializes terminal raw mode and alternate screen,
/// - loads providers from contract,
/// - guides selection, optional credential prompt, and connection attempts,
/// - submits provider ranking based on outcome,
/// - handles disconnect and clean shutdown.
pub async fn connect(
    api: VaraEthApi,
    contract: Address,
    credentials: Option<OpenVpnCredentials>,
    api_reconnect: ApiReconnectConfig,
) -> anyhow::Result<()> {
    // Setup terminal.
    enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    // Create channels for background task communication
    let (task_sender, task_receiver) = mpsc::channel::<TaskRequest>(8);
    let (response_sender, response_receiver) = mpsc::channel::<TaskResponse>(8);

    // Wrap API in Arc for sharing
    let api = Arc::new(api);

    // Spawn background worker
    let worker_api_reconnect = api_reconnect.clone();
    let worker_api = Arc::clone(&api);
    tokio::spawn(background_worker(
        task_receiver,
        response_sender,
        worker_api,
        contract,
        worker_api_reconnect,
    ));

    let mut app = App::new(
        api,
        contract,
        credentials,
        api_reconnect,
        task_sender,
        response_receiver,
    )
    .await?;
    let tick_rate = Duration::from_millis(120);

    loop {
        terminal.draw(|f| draw(f, &app))?;

        let event = if event::poll(tick_rate)? {
            Some(read_event_blocking()?)
        } else {
            None
        };

        app.tick();

        // Process any responses from background worker
        while let Ok(response) = app.response_receiver.try_recv() {
            handle_background_response(&mut app, response);
        }

        match app.phase {
            Phase::Selecting => {
                if let Some(Event::Key(key)) = event {
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
                                    app.set_phase(Phase::PromptCredentials(selected));
                                    app.status_msg = app.prompt_status();
                                } else {
                                    // Send connect task to background worker
                                    let provider_key = app.providers[selected].key;
                                    let provider_name = app.providers[selected].name.clone();
                                    let creds = app.credentials.clone();

                                    app.pending_operation = Some(PendingOperation::Connecting {
                                        provider_name: provider_name.clone(),
                                    });
                                    app.set_phase(Phase::Connecting(selected));
                                    app.status_msg = format!("Connecting to {}…", provider_name);

                                    let _ = app
                                        .task_sender
                                        .send(TaskRequest::Connect {
                                            provider_key,
                                            provider_name,
                                            credentials: creds,
                                        })
                                        .await;
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            Phase::PromptCredentials(idx) => {
                if let Some(Event::Key(key)) = event {
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }

                    match key.code {
                        KeyCode::Esc => {
                            app.reset_prompt_state();
                            app.set_phase(Phase::Selecting);
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

                                    // Send connect task to background worker
                                    let provider_key = app.providers[idx].key;
                                    let provider_name = app.providers[idx].name.clone();
                                    let creds = app.credentials.clone();

                                    app.pending_operation = Some(PendingOperation::Connecting {
                                        provider_name: provider_name.clone(),
                                    });
                                    app.set_phase(Phase::Connecting(idx));
                                    app.status_msg = format!("Connecting to {}…", provider_name);

                                    let _ = app
                                        .task_sender
                                        .send(TaskRequest::Connect {
                                            provider_key,
                                            provider_name,
                                            credentials: creds,
                                        })
                                        .await;
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
            Phase::Connecting(_idx) => {
                // Connection is handled by background worker
                // Just handle user input for abort
                if let Some(Event::Key(key)) = event {
                    if key.kind == KeyEventKind::Press
                        && matches!(
                            key.code,
                            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('Q')
                        )
                    {
                        // User wants to abort - just go back to selecting
                        app.pending_operation = None;
                        if app.credentials_from_prompt {
                            app.credentials = None;
                            app.credentials_from_prompt = false;
                            app.reset_prompt_state();
                        }
                        app.status_msg =
                            "Connection cancelled. Select a provider and press Enter.".into();
                        app.set_phase(Phase::Selecting);
                    }
                }

                // Update status message based on pending operation
                if let Some(PendingOperation::Connecting { provider_name }) = &app.pending_operation
                {
                    app.status_msg = format!("Connecting to {}…", provider_name);
                }
            }
            Phase::Connected => {
                if let Some(Event::Key(key)) = event {
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Char('Q') => {
                            // Send disconnect task to background worker
                            if let Some(session) = app.active_session.take() {
                                if let Some((provider_key, provider_name)) =
                                    app.connected_provider.take()
                                {
                                    app.pending_operation = Some(PendingOperation::Disconnecting {
                                        provider_name: provider_name.clone(),
                                    });
                                    app.status_msg =
                                        format!("Disconnecting from {}…", provider_name);

                                    let _ = app
                                        .task_sender
                                        .send(TaskRequest::Disconnect {
                                            session,
                                            provider_key,
                                            provider_name,
                                        })
                                        .await;
                                }
                            }
                            app.set_phase(Phase::Selecting);
                        }
                        KeyCode::Esc => break,
                        _ => {}
                    }
                }
            }
        }
    }

    // Send shutdown signal to background worker
    let _ = app.task_sender.send(TaskRequest::Shutdown).await;

    if let Some(session) = app.active_session.as_mut() {
        let _ = session.terminate().await;
    }

    // Restore terminal.
    disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;
    std::process::exit(0);
}

/// Handle responses from the background worker.
fn handle_background_response(app: &mut App, response: TaskResponse) {
    match response {
        TaskResponse::Connected {
            session,
            provider_key,
            provider_name,
        } => {
            app.active_session = Some(session);
            app.connected_provider = Some((provider_key, provider_name.clone()));
            app.pending_operation = None;
            app.set_phase(Phase::Connected);
            app.status_msg = format!("✔ Connected to {}! Press q to disconnect.", provider_name);
        }
        TaskResponse::ConnectionFailed {
            provider_key,
            reason,
        } => {
            app.pending_operation = None;

            // Find the provider index
            if let Some(idx) = app.providers.iter().position(|p| p.key == provider_key) {
                app.providers[idx].failed = true;
                app.fix_selection();
            }

            if app.credentials_from_prompt {
                app.credentials = None;
                app.credentials_from_prompt = false;
                app.reset_prompt_state();
            }

            app.status_msg = format!("✘ Connection failed: {}. Select another provider.", reason);
            app.set_phase(Phase::Selecting);
        }
        TaskResponse::ApiReconnected { api } => {
            app.api = api;
            if !matches!(app.phase, Phase::Connecting(_)) {
                app.status_msg =
                    "Background API reconnected. Select a provider and press Enter to connect."
                        .to_string();
            }
        }
        TaskResponse::Disconnected {
            provider_key,
            provider_name,
            rank_success,
        } => {
            app.pending_operation = None;

            // Update provider rank in local cache
            if let Some(p) = app.providers.iter_mut().find(|p| p.key == provider_key) {
                if rank_success {
                    p.rank += 1;
                }
            }
            app.sort_providers_by_rank();

            app.status_msg = if rank_success {
                format!(
                    "Disconnected from {}. Select a provider and press Enter to connect.",
                    provider_name
                )
            } else {
                format!(
                    "Disconnected from {}. Ranking failed. Select a provider and press Enter.",
                    provider_name
                )
            };
        }
        TaskResponse::ProviderRanked {
            provider,
            good,
            new_rank,
        } => {
            // Update provider rank in local cache
            if let Some(p) = app.providers.iter_mut().find(|p| p.key == provider) {
                if good {
                    p.rank += new_rank;
                } else {
                    p.rank -= new_rank.abs();
                }
            }
            app.sort_providers_by_rank();
        }
        TaskResponse::Error(msg) => {
            app.pending_operation = None;
            app.status_msg = format!("Error: {}. Select a provider and press Enter.", msg);
            app.set_phase(Phase::Selecting);
        }
    }
}

/// Loads signer key storage from application-specific data directory.
pub fn signer() -> anyhow::Result<Signer> {
    let dirs = directories::ProjectDirs::from("com", "gear", "ratatui")
        .context("failed to get project directories")?;
    let signer = Signer::fs(dirs.data_dir().join("keys"))?;
    Ok(signer)
}

/// Imports a private key into local signer storage and prints the resulting address.
pub async fn import_key(private_key: PrivateKey) -> anyhow::Result<()> {
    let signer = signer()?;
    let public_key = signer.import(private_key)?;
    println!("Imported key: {public_key}");
    println!("Address: {}", public_key.to_address());
    Ok(())
}

/// Computes deterministic `CodeId` as BLAKE2b-256 over WASM bytes.
fn code_id_for(wasm: &[u8]) -> CodeId {
    type Blake2b256 = Blake2b<U32>;

    let mut hasher = Blake2b256::new();
    hasher.update(wasm);
    CodeId::new(hasher.finalize().into())
}

/// Deploys and initializes the Shadowsprout contract program.
///
/// The flow validates or uploads contract code, creates a program actor,
/// tops up execution balance, and sends the `Create` initialization message.
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
    let code = shadowsprout_contract::WASM_BINARY;
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
        .send_message(shadowsprout_contract_client::io::Create::encode_params(), 0)
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

/// Parses 32-byte provider key from hexadecimal string with optional `0x` prefix.
fn parse_provider_key_hex(key: &str) -> anyhow::Result<[u8; 32]> {
    let key = key.strip_prefix("0x").unwrap_or(key);
    anyhow::ensure!(
        key.len() == 64,
        "provider key must be 32-byte hex (64 chars), got {} chars",
        key.len()
    );

    let mut out = [0u8; 32];
    for i in 0..32 {
        let from = i * 2;
        let to = from + 2;
        out[i] = u8::from_str_radix(&key[from..to], 16)
            .with_context(|| format!("invalid hex at byte {}", i))?;
    }
    Ok(out)
}

/// Uploads or replaces a provider VPN configuration file on-chain.
///
/// The file payload is submitted through `AddProviderFile` and success output
/// indicates whether the provider entry was newly inserted or updated.
pub async fn upload_file(
    sender_address: gsigner::Address,
    provider_key: String,
    name: String,
    kind: String,
    file: PathBuf,
) -> anyhow::Result<()> {
    const RPC: &str = "wss://hoodi-reth-rpc.gear-tech.io/ws";
    const ROUTER: &str = "0xBC888a8B050B9B76a985d91c815d2c4f2131a58A";
    const VPN: &str = "0xecf8c8bc27e503a4ddf0fb59187fe71d543c50d9";

    let provider = parse_provider_key_hex(&provider_key)?;
    let config = std::fs::read_to_string(&file)
        .with_context(|| format!("failed to read file {}", file.display()))?;

    let signer = signer()?;
    let router_address = ROUTER.parse().context("failed to parse router address")?;
    let ethereum = ethexe_ethereum::Ethereum::new(RPC, router_address, signer, sender_address)
        .await
        .context("failed to connect to Ethereum RPC")?;

    let contract: gsigner::Address = VPN
        .parse()
        .context("failed to parse VPN contract address")?;
    let prefix = stringify!(ShadowsproutContract);
    let message =
        shadowsprout_contract_client::shadowsprout_contract::io::AddProviderFile::encode_params_with_prefix(
            prefix, provider, name, kind, config,
        );

    println!("Uploading provider file for key {}...", provider_key);
    let (_, msg_id) = ethereum
        .mirror(contract.into())
        .send_message(message, 0)
        .await
        .context("failed to submit AddProviderFile message")?;

    println!("Waiting for upload result...");
    let reply = ethereum
        .mirror(contract.into())
        .wait_for_reply(msg_id)
        .await
        .context("failed while waiting for AddProviderFile reply")?;
    println!("Upload reply received");
    anyhow::ensure!(
        reply.code.is_success(),
        "upload failed: code {}, message: {}",
        reply.code,
        std::str::from_utf8(&reply.payload).unwrap_or("<non-utf8>")
    );

    let inserted =
        shadowsprout_contract_client::shadowsprout_contract::io::AddProviderFile::decode_reply_with_prefix(
            prefix,
            &reply.payload,
        )?;

    if inserted {
        println!("Uploaded provider file successfully (new provider inserted)");
    } else {
        println!("Uploaded provider file successfully (existing provider replaced)");
    }

    Ok(())
}
