use std::io;

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, List, ListItem, Paragraph},
};

use crate::contract::{self, H256};
use crate::vpn;

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

struct Provider {
    name: String,
    key: H256,
    file_kind: &'static str,
    failed: bool,
}

enum Phase {
    Selecting,
    Connecting(usize),
    Connected,
}

struct App {
    api: contract::Api,
    providers: Vec<Provider>,
    selected: usize,
    phase: Phase,
    status_msg: String,
}

impl App {
    async fn new() -> anyhow::Result<Self> {
        let api = contract::Api::new(None).await?;
        let fetched = contract::fetch_providers(&api).await;
        let mut built = Vec::with_capacity(fetched.len());
        for (name, key) in fetched {
            let file_kind = contract::fetch_provider_file(&api, key).await.kind();
            built.push(Provider {
                name,
                key,
                file_kind,
                failed: false,
            });
        }

        Ok(Self {
            api,
            providers: built,
            selected: 0,
            phase: Phase::Selecting,
            status_msg: String::from("Select a provider and press Enter to connect."),
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

// ---------------------------------------------------------------------------
// Event loop
// ---------------------------------------------------------------------------

pub async fn run() -> anyhow::Result<()> {
    // Setup terminal.
    enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new().await?;

    loop {
        terminal.draw(|f| draw(f, &app))?;

        match &app.phase {
            Phase::Selecting => {
                if let Event::Key(key) = event::read()? {
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Up | KeyCode::Char('k') => app.move_up(),
                        KeyCode::Down | KeyCode::Char('j') => app.move_down(),
                        KeyCode::Enter => {
                            if app.all_failed() {
                                app.status_msg =
                                    "All providers have failed. Press q to quit.".into();
                            } else {
                                app.phase = Phase::Connecting(app.selected);
                                app.status_msg =
                                    format!("Connecting to {}…", app.providers[app.selected].name);
                            }
                        }
                        _ => {}
                    }
                }
            }
            Phase::Connecting(idx) => {
                let idx = *idx;
                // Redraw with "connecting" status, then attempt.
                terminal.draw(|f| draw(f, &app))?;

                let provider = &app.providers[idx];
                let success = vpn::try_connect(&app.api, provider.key).await;

                if success {
                    app.phase = Phase::Connected;
                    app.status_msg = format!(
                        "✔ Connected to {}! Press q to disconnect & quit.",
                        app.providers[idx].name
                    );
                } else {
                    app.providers[idx].failed = true;
                    app.status_msg = format!(
                        "✘ Connection to {} failed. Select another provider.",
                        app.providers[idx].name
                    );
                    app.fix_selection();
                    app.phase = Phase::Selecting;
                }
            }
            Phase::Connected => {
                if let Event::Key(key) = event::read()? {
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }
                    if matches!(key.code, KeyCode::Char('q') | KeyCode::Esc) {
                        break;
                    }
                }
            }
        }
    }

    // Restore terminal.
    disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;
    Ok(())
}
