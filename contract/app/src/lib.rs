#![no_std]
extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use sails_rs::prelude::*;

struct Provider {
    name: String,
    config: String,
    kind: String,
    rank: i32,
}

struct ShadowsproutContract<'a> {
    providers: &'a mut BTreeMap<[u8; 32], Provider>,
}

impl<'a> ShadowsproutContract<'a> {
    fn create(providers: &'a mut BTreeMap<[u8; 32], Provider>) -> Self {
        Self { providers }
    }
}

#[sails_rs::service]
impl ShadowsproutContract<'_> {
    /// Fetch the list of available VPN providers.
    #[export]
    pub fn fetch_providers(&mut self) -> Vec<([u8; 32], String, i32)> {
        self.providers
            .iter()
            .map(|(k, v)| (*k, v.name.clone(), v.rank))
            .collect()
    }

    /// Fetch the VPN configuration file for a given provider.
    #[export]
    pub fn fetch_provider_file(&mut self, provider: [u8; 32]) -> (String, String) {
        let provider = self.providers.get(&provider).unwrap();
        (provider.kind.clone(), provider.config.clone())
    }

    /// Add a new VPN provider file.
    #[export]
    pub fn add_provider_file(
        &mut self,
        provider: [u8; 32],
        name: String,
        kind: String,
        config: String,
    ) -> bool {
        self.providers
            .insert(
                provider,
                Provider {
                    name,
                    config,
                    kind,
                    rank: 0,
                },
            )
            .is_none()
    }

    /// Rank a provider positively or negatively after a connection attempt.
    #[export]
    pub fn rank_provider(&mut self, provider: [u8; 32], good: bool) {
        let provider = self.providers.get_mut(&provider).unwrap();
        provider.rank += if good { 1 } else { -1 };
    }
}

#[derive(Default)]
pub struct Program {
    providers: BTreeMap<[u8; 32], Provider>,
}

#[sails_rs::program]
impl Program {
    // Program's constructor
    pub fn create() -> Self {
        let mut providers = BTreeMap::new();
        providers.insert(
            [0; 32],
            Provider {
                name: "Japan".into(),
                config: include_str!("../proxies/japan.ovpn").into(),
                kind: "openvpn".into(),
                rank: 1,
            },
        );
        providers.insert(
            [1; 32],
            Provider {
                name: "Korea".into(),
                config: include_str!("../proxies/korea.ovpn").into(),
                kind: "openvpn".into(),
                rank: 3,
            },
        );
        providers.insert(
            [2; 32],
            Provider {
                name: "Russia".into(),
                config: include_str!("../proxies/russia.ovpn").into(),
                kind: "openvpn".into(),
                rank: 5,
            },
        );
        providers.insert(
            [3; 32],
            Provider {
                name: "Thailand".into(),
                config: include_str!("../proxies/thailand.ovpn").into(),
                kind: "openvpn".into(),
                rank: 10,
            },
        );
        providers.insert(
            [4; 32],
            Provider {
                name: "USA".into(),
                config: include_str!("../proxies/usa.ovpn").into(),
                kind: "openvpn".into(),
                rank: -100,
            },
        );

        Self { providers }
    }

    // Exposed service
    pub fn shadowsprout_contract(&mut self) -> ShadowsproutContract<'_> {
        ShadowsproutContract::create(&mut self.providers)
    }
}
