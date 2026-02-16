use sails_rs::{client::*, gtest::*};
use shadowsprout_contract_client::shadowsprout_contract::ShadowsproutContract;
use shadowsprout_contract_client::{ShadowsproutContractClient, ShadowsproutContractClientCtors};

const ACTOR_ID: u64 = 42;

#[tokio::test]
async fn do_something_works() {
    const JAPAN: [u8; 32] = [0; 32];

    let system = System::new();
    system.init_logger_with_default_filter("gwasm=debug,gtest=info,sails_rs=debug");
    system.mint_to(ACTOR_ID, 100_000_000_000_000);
    // Submit program code into the system
    let program_code_id = system.submit_code(shadowsprout_contract::WASM_BINARY);

    // Create Sails Env
    let env = GtestEnv::new(system, ACTOR_ID.into());

    let program = env
        .deploy::<shadowsprout_contract_client::ShadowsproutContractClientProgram>(
            program_code_id,
            b"salt".to_vec(),
        )
        .create() // Call program's constructor
        .await
        .unwrap();

    let mut service_client = program.shadowsprout_contract();

    let providers = service_client.fetch_providers().await.unwrap();
    assert_eq!(providers.len(), 5);
    assert_eq!(providers[0].2, 1);

    let added = service_client
        .add_provider_file(
            [9; 32],
            "Test".to_string(),
            "openvpn".to_string(),
            "client\nproto udp\nremote example.org 1194".to_string(),
        )
        .await
        .unwrap();
    assert!(added);

    let providers = service_client.fetch_providers().await.unwrap();
    assert_eq!(providers.len(), 6);

    let (_, file) = service_client.fetch_provider_file([9; 32]).await.unwrap();
    assert_eq!(file, "client\nproto udp\nremote example.org 1194");

    service_client.rank_provider(JAPAN, true).await.unwrap();

    let providers = service_client.fetch_providers().await.unwrap();
    let japan_rank = providers
        .into_iter()
        .find_map(|(id, _name, rank)| (id == JAPAN).then_some(rank))
        .unwrap();
    assert_eq!(japan_rank, 2);
}
