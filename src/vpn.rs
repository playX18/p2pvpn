use rand::Rng;
use tokio::time::{sleep, Duration};

use crate::contract::{self, Api, H256};

/// Simulates a VPN connection attempt. Returns `true` on success.
pub async fn try_connect(api: &Api, provider: H256) -> bool {
    let _file = contract::fetch_provider_file(api, provider).await;

    // Simulate connection delay.
    sleep(Duration::from_secs(1)).await;

    // 70 % chance of success in this mock.
    let success = rand::thread_rng().gen_bool(0.7);

    contract::rank_provider(api, success, provider).await;
    success
}
