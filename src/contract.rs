//! Mock smart-contract types and API.
//!
//! This module provides local stand-ins for provider listing and provider-file retrieval.
//! In production-oriented flows, the application primarily talks to on-chain contracts via
//! generated client bindings; however, these types remain useful as a shared abstraction
//! for UI and VPN layers.

#![allow(dead_code)]

/// A 256-bit hash used as a unique provider key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct H256(pub [u8; 32]);

impl H256 {
    /// Returns a compact hexadecimal preview of the provider key.
    ///
    /// The output keeps only the first two and last two bytes, for example `0102…1f20`.
    pub fn short(&self) -> String {
        format!(
            "{:02x}{:02x}…{:02x}{:02x}",
            self.0[0], self.0[1], self.0[30], self.0[31]
        )
    }
}

/// VPN configuration file fetched from a provider.
#[derive(Debug, Clone)]
pub enum VpnFile {
    Wireguard(Vec<u8>),
    OpenVpn(Vec<u8>),
}

impl VpnFile {
    /// Returns a human-readable VPN kind label.
    pub fn kind(&self) -> &'static str {
        match self {
            VpnFile::Wireguard(_) => "WireGuard",
            VpnFile::OpenVpn(_) => "OpenVPN",
        }
    }

    /// Returns raw bytes of the provider configuration payload.
    pub fn bytes(&self) -> &[u8] {
        match self {
            VpnFile::Wireguard(b) | VpnFile::OpenVpn(b) => b,
        }
    }
}

// ---------------------------------------------------------------------------
// Mock data
// ---------------------------------------------------------------------------

fn mock_h256(seed: u8) -> H256 {
    let mut buf = [0u8; 32];
    for (i, b) in buf.iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8);
    }
    H256(buf)
}

static PROVIDERS: &[(&str, u8, i32)] = &[
    ("NordShield", 1, 4),
    ("GhostRoute", 2, 2),
    ("ZeroTrace", 3, 9),
    ("NebulaNet", 4, -1),
    ("VaultLink", 5, 0),
];

/// Fetch the list of available VPN providers.
///
/// Returns tuples of `(display_name, provider_key, rank)`.
/// The data is deterministic and in-memory.
pub async fn fetch_providers() -> Vec<(String, H256, i32)> {
    PROVIDERS
        .iter()
        .map(|(name, seed, rank)| (name.to_string(), mock_h256(*seed), *rank))
        .collect()
}

/// Fetch the VPN configuration file for a given provider.
///
/// Mock behavior:
/// - even first byte => OpenVPN profile,
/// - odd first byte => WireGuard profile.
///
/// Some generated OpenVPN profiles include `auth-user-pass`, which signals the
/// caller that runtime credentials are required.
pub async fn fetch_provider_file(provider: H256) -> VpnFile {
    if provider.0[0] % 2 == 0 {
        let requires_auth = provider.0[0] % 4 == 0;
        let mut config = format!(
            "client\ndev tun\nproto udp\nremote 127.0.0.1 1194\nnobind\npersist-key\npersist-tun\nverb 3\n# provider {:02x}\n",
            provider.0[0]
        );
        if requires_auth {
            config.push_str("auth-user-pass\n");
        }

        VpnFile::OpenVpn(config.into_bytes())
    } else {
        let raw = format!(
            "# Mock VPN config for provider {:02x}\n[Interface]\nAddress = 10.0.0.{}\n",
            provider.0[0], provider.0[0]
        )
        .into_bytes();
        VpnFile::Wireguard(raw)
    }
}

/// Rank a provider positively or negatively after a connection attempt.
///
/// In the mock implementation this is a no-op placeholder that models the shape
/// of the real contract call.
pub async fn rank_provider(good: bool, _provider: H256) {
    // In a real implementation this would call a smart-contract transaction.
    let _action = if good { "upvoted" } else { "downvoted" };
}
