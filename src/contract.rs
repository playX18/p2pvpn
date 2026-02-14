/// Mock smart-contract types and API.

#[cfg(feature = "ethexe")]
pub use ethexe_sdk::VaraEthApi;

/// A 256-bit hash used as a unique provider key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct H256(pub [u8; 32]);

impl H256 {
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
    pub fn kind(&self) -> &'static str {
        match self {
            VpnFile::Wireguard(_) => "WireGuard",
            VpnFile::OpenVpn(_) => "OpenVPN",
        }
    }

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

static PROVIDERS: &[(&str, u8)] = &[
    ("NordShield", 1),
    ("GhostRoute", 2),
    ("ZeroTrace", 3),
    ("NebulaNet", 4),
    ("VaultLink", 5),
];
const DEFAULT_API_ENDPOINT: &str = "ws://localhost:9944";

pub struct Api {
    pub endpoint: String,
}

impl Api {
    /// Async to match the real SDK initialization flow (RPC client creation).
    pub async fn new(endpoint: Option<&str>) -> anyhow::Result<Self> {
        let endpoint = endpoint.unwrap_or(DEFAULT_API_ENDPOINT).to_owned();
        Ok(Self { endpoint })
    }
}

/// Fetch the list of available VPN providers.
pub async fn fetch_providers(_api: &Api) -> Vec<(String, H256)> {
    PROVIDERS
        .iter()
        .map(|(name, seed)| (name.to_string(), mock_h256(*seed)))
        .collect()
}

/// Fetch the VPN configuration file for a given provider.
pub async fn fetch_provider_file(_api: &Api, provider: H256) -> VpnFile {
    // Alternate between WireGuard and OpenVPN based on the first byte.
    let raw = format!(
        "# Mock VPN config for provider {:02x}\n[Interface]\nAddress = 10.0.0.{}\n",
        provider.0[0], provider.0[0]
    )
    .into_bytes();

    if provider.0[0] % 2 == 0 {
        VpnFile::OpenVpn(raw)
    } else {
        VpnFile::Wireguard(raw)
    }
}

/// Rank a provider positively or negatively after a connection attempt.
pub async fn rank_provider(_api: &Api, good: bool, _provider: H256) {
    // In a real implementation this would call a smart-contract transaction.
    let _action = if good { "upvoted" } else { "downvoted" };
}

#[cfg(test)]
mod tests {
    use super::Api;

    #[tokio::test]
    async fn api_uses_localhost_by_default() {
        let api = Api::new(None).await.expect("api should be created");
        assert_eq!(api.endpoint, super::DEFAULT_API_ENDPOINT);
    }
}
