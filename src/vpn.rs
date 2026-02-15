use std::{
    fs,
    path::{Path, PathBuf},
    process::Stdio,
};

use anyhow::{anyhow, Context};
use tempfile::TempDir;
use tokio::{
    process::{Child, Command},
    time::{sleep, Duration},
};

use crate::contract::{self, H256};

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

pub enum ConnectionAttempt {
    Connected(OpenVpnSession),
    Failed(String),
}

pub async fn provider_requires_credentials(provider: H256) -> bool {
    let file = contract::fetch_provider_file(provider).await;
    match file {
        contract::VpnFile::OpenVpn(bytes) => std::str::from_utf8(&bytes)
            .map(profile_requires_credentials)
            .unwrap_or(false),
        contract::VpnFile::Wireguard(_) => false,
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
    provider: H256,
    credentials: Option<&OpenVpnCredentials>,
) -> ConnectionAttempt {
    let file = contract::fetch_provider_file(provider).await;

    let staged = match file {
        contract::VpnFile::OpenVpn(bytes) => {
            match stage_openvpn_config(&bytes, credentials).context("failed to stage config") {
                Ok(staged) => staged,
                Err(err) => {
                    contract::rank_provider(false, provider).await;
                    return ConnectionAttempt::Failed(err.to_string());
                }
            }
        }
        contract::VpnFile::Wireguard(_) => {
            contract::rank_provider(false, provider).await;
            return ConnectionAttempt::Failed(
                "selected provider only exposes WireGuard config; OpenVPN is required".into(),
            );
        }
    };

    let mut child = match Command::new("openvpn3")
        .arg("--config")
        .arg(&staged.config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            contract::rank_provider(false, provider).await;
            return ConnectionAttempt::Failed(format!("failed to start openvpn: {err}"));
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
            ConnectionAttempt::Failed(err_msg)
        }
        Ok(None) => {
            contract::rank_provider(true, provider).await;
            ConnectionAttempt::Connected(OpenVpnSession {
                child,
                _staging_dir: staged.staging_dir,
            })
        }
        Err(err) => {
            contract::rank_provider(false, provider).await;
            ConnectionAttempt::Failed(format!("failed checking openvpn process: {err}"))
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
