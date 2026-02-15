use p2pvpn_contract_client::p_2_pvpn_contract::P2PvpnContract;
use p2pvpn_contract_client::{P2PvpnContractClient, P2PvpnContractClientCtors};
use sails_rs::{client::*, gtest::*};

const ACTOR_ID: u64 = 42;

#[tokio::test]
async fn do_something_works() {
    let system = System::new();
    system.init_logger_with_default_filter("gwasm=debug,gtest=info,sails_rs=debug");
    system.mint_to(ACTOR_ID, 100_000_000_000_000);
    // Submit program code into the system
    let program_code_id = system.submit_code(p2pvpn_contract::WASM_BINARY);

    // Create Sails Env
    let env = GtestEnv::new(system, ACTOR_ID.into());

    let program = env
        .deploy::<p2pvpn_contract_client::P2PvpnContractClientProgram>(
            program_code_id,
            b"salt".to_vec(),
        )
        .create() // Call program's constructor
        .await
        .unwrap();

    let mut service_client = program.p_2_pvpn_contract();

    let providers = service_client.fetch_providers().await.unwrap();
    assert_eq!(providers.len(), 5);
}
