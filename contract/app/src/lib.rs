#![no_std]
extern crate alloc;

use alloc::collections::BTreeMap;
use sails_rs::prelude::*;

#[derive(Debug, Encode, Decode, TypeInfo)]
#[codec(crate = sails_rs::scale_codec)]
#[scale_info(crate = sails_rs::scale_info)]
enum VpnFileKind {
    Wireguard,
    OpenVpn,
}

impl VpnFileKind {
    fn into_static_str(self) -> &'static str {
        match self {
            VpnFileKind::Wireguard => "wireguard",
            VpnFileKind::OpenVpn => "openvpn",
        }
    }
}

struct Provider {
    name: &'static str,
    config: &'static str,
    rank: i32,
}

struct P2PvpnContract {
    providers: BTreeMap<[u8; 32], Provider>,
}

impl P2PvpnContract {
    fn create() -> Self {
        let mut providers = BTreeMap::new();
        providers.insert(
            [0; 32],
            Provider {
                name: "Japan",
                config: include_str!("../proxies/japan.ovpn"),
                rank: 1,
            },
        );
        providers.insert(
            [1; 32],
            Provider {
                name: "Korea",
                config: include_str!("../proxies/korea.ovpn"),
                rank: 3,
            },
        );
        providers.insert(
            [2; 32],
            Provider {
                name: "Russia",
                config: include_str!("../proxies/russia.ovpn"),
                rank: 5,
            },
        );
        providers.insert(
            [3; 32],
            Provider {
                name: "Thailand",
                config: include_str!("../proxies/thailand.ovpn"),
                rank: 10,
            },
        );
        providers.insert(
            [4; 32],
            Provider {
                name: "USA",
                config: include_str!("../proxies/usa.ovpn"),
                rank: -100,
            },
        );

        Self { providers }
    }
}

#[sails_rs::service]
impl P2PvpnContract {
    /// Fetch the list of available VPN providers.
    #[export]
    pub fn fetch_providers(&mut self) -> Vec<([u8; 32], &'static str)> {
        self.providers.iter().map(|(k, v)| (*k, v.name)).collect()
    }

    /// Fetch the VPN configuration file for a given provider.
    #[export]
    pub fn fetch_provider_file(&mut self, provider: [u8; 32]) -> (&'static str, &'static str) {
        let provider = self.providers.get(&provider).unwrap();
        (VpnFileKind::OpenVpn.into_static_str(), provider.config)
    }

    /// Rank a provider positively or negatively after a connection attempt.
    #[export]
    pub fn rank_provider(&mut self, provider: [u8; 32], good: bool) {
        let provider = self.providers.get_mut(&provider).unwrap();
        provider.rank += good as i32;
    }
}

#[derive(Default)]
pub struct Program(());

#[sails_rs::program]
impl Program {
    // Program's constructor
    pub fn create() -> Self {
        Self(())
    }

    // Exposed service
    pub fn p2pvpn_contract(&self) -> P2PvpnContract {
        P2PvpnContract::create()
    }
}
