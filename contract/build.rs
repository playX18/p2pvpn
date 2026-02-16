fn main() {
    if let Some((_, wasm_path)) = sails_rs::build_wasm() {
        sails_rs::ClientBuilder::<shadowsprout_contract_app::Program>::from_wasm_path(
            wasm_path.with_extension(""),
        )
        .build_idl();
    }
}
