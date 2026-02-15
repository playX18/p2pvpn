use crate::contract::H256;
use crate::{contract, tui::App};
use anyhow::{anyhow, Context};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Stdio,
};
use tempfile::TempDir;
use tokio::{
    process::{Child, Command},
    time::{sleep, Duration},
};

#[derive(Debug, Clone)]
pub struct OpenVpnCredentials {
    pub username: String,
    pub password: String,
}

pub struct OpenVpnSession {
    child: Child,
    _staging_dir: TempDir,
}

impl OpenVpnSession {
    pub async fn terminate(&mut self) -> anyhow::Result<()> {
        if self.child.try_wait()?.is_none() {
            self.child.kill().await?;
            let _ = self.child.wait().await;
        }
        Ok(())
    }
}

impl Drop for OpenVpnSession {
    fn drop(&mut self) {
        match self.child.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) => {
                let _ = self.child.start_kill();
            }
            Err(_) => {}
        }
    }
}

pub enum ConnectionAttempt {
    Connected(OpenVpnSession),
    Failed(String),
}

pub async fn provider_requires_credentials(app: &App, provider: H256) -> anyhow::Result<bool> {
    let file = App::fetch_provider_file(&app.api, app.vpn_contract, provider).await?;
    match file {
        contract::VpnFile::OpenVpn(bytes) => Ok(std::str::from_utf8(&bytes)
            .map(profile_requires_credentials)
            .unwrap_or(false)),
        contract::VpnFile::Wireguard(_) => Ok(false),
    }
}

struct ParsedOpenVpnConfig {
    rendered_config: String,
    needs_auth_file: bool,
}

struct StagedOpenVpnConfig {
    config_path: PathBuf,
    staging_dir: TempDir,
}

/// Attempts to connect by spawning the native openvpn client as a child process.
pub async fn try_connect(
    app: &App,
    provider: H256,
    credentials: Option<&OpenVpnCredentials>,
) -> anyhow::Result<ConnectionAttempt> {
    let file = App::fetch_provider_file(&app.api, app.vpn_contract, provider).await?;

    let staged = match file {
        contract::VpnFile::OpenVpn(bytes) => {
            match stage_openvpn_config(&bytes, credentials).context("failed to stage config") {
                Ok(staged) => staged,
                Err(err) => {
                    contract::rank_provider(false, provider).await;
                    return Ok(ConnectionAttempt::Failed(err.to_string()));
                }
            }
        }
        contract::VpnFile::Wireguard(_) => {
            contract::rank_provider(false, provider).await;
            return Ok(ConnectionAttempt::Failed(
                "selected provider only exposes WireGuard config; OpenVPN is required".into(),
            ));
        }
    };

    let openvpn_binary = match resolve_openvpn_binary() {
        Ok(path) => path,
        Err(err) => {
            contract::rank_provider(false, provider).await;
            return Ok(ConnectionAttempt::Failed(err.to_string()));
        }
    };

    let mut child = match Command::new(&openvpn_binary)
        .arg("--config")
        .arg(&staged.config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            contract::rank_provider(false, provider).await;
            return Ok(ConnectionAttempt::Failed(format!(
                "failed to start openvpn: {err}"
            )));
        }
    };

    sleep(Duration::from_secs(2)).await;

    match child.try_wait() {
        Ok(Some(status)) => {
            contract::rank_provider(false, provider).await;

            // Capture stderr output from the failed process
            let stderr = child
                .wait_with_output()
                .await
                .map(|o| String::from_utf8_lossy(&o.stderr).to_string())
                .unwrap_or_default();
            let err_msg = if stderr.is_empty() {
                format!("openvpn exited early with status: {status}")
            } else {
                format!("openvpn exited early with status: {status}\nstderr: {stderr}")
            };
            Ok(ConnectionAttempt::Failed(err_msg))
        }
        Ok(None) => {
            contract::rank_provider(true, provider).await;
            Ok(ConnectionAttempt::Connected(OpenVpnSession {
                child,
                _staging_dir: staged.staging_dir,
            }))
        }
        Err(err) => {
            contract::rank_provider(false, provider).await;
            Ok(ConnectionAttempt::Failed(format!(
                "failed checking openvpn process: {err}"
            )))
        }
    }
}

fn stage_openvpn_config(
    config_bytes: &[u8],
    credentials: Option<&OpenVpnCredentials>,
) -> anyhow::Result<StagedOpenVpnConfig> {
    let config_text = std::str::from_utf8(config_bytes).context("config is not valid UTF-8")?;
    let parsed = parse_openvpn_config(config_text, credentials)?;

    let staging_dir = tempfile::Builder::new()
        .prefix("ratatui-vpn-")
        .tempdir()
        .context("failed to create temporary staging dir")?;
    let config_path = staging_dir.path().join("provider.ovpn");
    fs::write(&config_path, parsed.rendered_config).context("failed writing staged config")?;

    if parsed.needs_auth_file {
        let creds = credentials.ok_or_else(|| anyhow!("missing required OpenVPN credentials"))?;
        write_auth_file(staging_dir.path(), creds)?;
    }

    Ok(StagedOpenVpnConfig {
        config_path,
        staging_dir,
    })
}

fn parse_openvpn_config(
    original: &str,
    credentials: Option<&OpenVpnCredentials>,
) -> anyhow::Result<ParsedOpenVpnConfig> {
    let mut rendered = Vec::new();
    let mut needs_auth_file = false;

    for line in original.lines() {
        let trimmed = line.trim();
        let is_comment = trimmed.starts_with('#') || trimmed.starts_with(';');
        if is_comment || !trimmed.starts_with("auth-user-pass") {
            rendered.push(line.to_string());
            continue;
        }

        if !auth_user_pass_needs_generated_file(trimmed) {
            rendered.push(line.to_string());
            continue;
        }

        if credentials.is_none() {
            return Err(anyhow!(
                "OpenVPN profile requires credentials (auth-user-pass) but none were provided"
            ));
        }

        needs_auth_file = true;
        rendered.push("auth-user-pass auth.txt".to_string());
    }

    Ok(ParsedOpenVpnConfig {
        rendered_config: rendered.join("\n"),
        needs_auth_file,
    })
}

fn profile_requires_credentials(profile: &str) -> bool {
    profile.lines().any(|line| {
        let trimmed = line.trim();
        let is_comment = trimmed.starts_with('#') || trimmed.starts_with(';');
        !is_comment
            && trimmed.starts_with("auth-user-pass")
            && auth_user_pass_needs_generated_file(trimmed)
    })
}

fn auth_user_pass_needs_generated_file(line: &str) -> bool {
    let mut parts = line.split_whitespace();
    let _directive = parts.next();
    let path_arg = parts.next();
    path_arg.is_none()
}

fn write_auth_file(dir: &Path, credentials: &OpenVpnCredentials) -> anyhow::Result<()> {
    let auth_path = dir.join("auth.txt");
    let content = format!("{}\n{}\n", credentials.username, credentials.password);
    fs::write(auth_path, content).context("failed writing OpenVPN auth file")?;
    Ok(())
}

fn resolve_openvpn_binary() -> anyhow::Result<PathBuf> {
    if let Some(configured) = env::var_os("OPENVPN_BIN") {
        let configured_path = PathBuf::from(configured);
        if is_executable_file(&configured_path) {
            return Ok(configured_path);
        }

        return Err(anyhow!(
            "OPENVPN_BIN is set but not executable: {}",
            configured_path.display()
        ));
    }

    let mut searched = Vec::new();

    for candidate in [
        "/opt/homebrew/opt/openvpn/sbin/openvpn",
        "/usr/local/opt/openvpn/sbin/openvpn",
        "/opt/homebrew/sbin/openvpn",
        "/usr/local/sbin/openvpn",
        "/opt/local/sbin/openvpn",
        "/usr/sbin/openvpn",
        "/usr/bin/openvpn",
    ] {
        let path = PathBuf::from(candidate);
        searched.push(path.display().to_string());
        if is_executable_file(&path) {
            return Ok(path);
        }
    }

    if let Some(path_env) = env::var_os("PATH") {
        for dir in env::split_paths(&path_env) {
            let candidate = dir.join("openvpn");
            searched.push(candidate.display().to_string());
            if is_executable_file(&candidate) {
                return Ok(candidate);
            }
        }
    }

    Err(anyhow!(
        "openvpn binary not found. Install OpenVPN or set OPENVPN_BIN to the executable path. Searched: {}",
        searched.join(", ")
    ))
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    fs::metadata(path)
        .map(|meta| meta.is_file() && (meta.permissions().mode() & 0o111 != 0))
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}
