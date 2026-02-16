# Shadowsprout (p2pvpn)

[![Etherscan](https://img.shields.io/badge/Contract-0x105e1232f8cd13e6d7211434df817b79fd621aff?style=flat)](https://etherscan.io/address/0x105e1232f8cd13e6d7211434df817b79fd621aff)

Shadowsprout is a Rust-based decentralized VPN client with:

- a local terminal UI (Ratatui) to select and connect to VPN providers,
- OpenVPN process orchestration for tunnel startup/teardown,
- integration with an Ethereum-backed Gear/Ethexe contract for provider discovery, provider file upload, and reputation ranking.

The binary crate name is `shadowsprout`.

## Workspace Layout

- `src/main.rs` — CLI entrypoint and command routing.
- `src/tui.rs` — interactive TUI flow, provider ranking interactions, deploy/upload helpers, key management.
- `src/vpn.rs` — OpenVPN config staging, credential handling, process spawning, cancellation logic.
- `src/contract.rs` — local mock contract data types and helper API surface.
- `contract/` — smart-contract workspace members (`app/`, `client/`) and generated interfaces.

## High-Level Flow

### Connect Flow

1. CLI parses `connect` arguments.
2. Ethereum and Vara/Ethexe API clients are initialized.
3. TUI loads providers from contract and fetches each provider's VPN file metadata.
4. User selects a provider.
5. If OpenVPN profile requires `auth-user-pass`, credentials are collected (CLI args or prompt).
6. OpenVPN config is staged in a temporary directory.
7. Native `openvpn` process is spawned and monitored.
8. Provider is ranked up/down based on connection result.

### Deploy Flow

1. Connect to RPC and router contract.
2. Upload/validate WASM code if needed.
3. Create program actor.
4. Approve and top-up balances.
5. Send create/init message and await successful reply.

### Upload File Flow

1. Parse provider key hex.
2. Read VPN config file content.
3. Build `AddProviderFile` message.
4. Send message and await reply.
5. Report whether provider was inserted or replaced.

## Prerequisites

- Rust toolchain compatible with the project (`rust-toolchain.toml`).
- OpenVPN installed locally (required for `connect`).
- Access to configured RPC/WebSocket endpoints.
- A signing key imported for sending authenticated contract operations.

## Build

```bash
cargo build
```

Release build:

```bash
cargo build --release
```

## Run

General help:

```bash
cargo run -- --help
```

### Usage Tutorial

1. **Import key first (required):** import the private key that corresponds to the same address you will use as `SENDER_ADDRESS`.
2. Set `SENDER_ADDRESS` (or pass `--sender-address` where required).
3. Run `connect`, `deploy-contract`, or `upload-file` commands.

Without importing the matching key, sender-authenticated operations will fail.

### Import Key

```bash
cargo run -- import-key <PRIVATE_KEY>
```

### Connect

```bash
cargo run -- connect \
  --sender-address <ETH_ADDRESS> \
  --router-address <ROUTER_ADDRESS> \
  --vpn-address <VPN_CONTRACT_ADDRESS>
```

When OpenVPN profile needs credentials, either provide both:

```bash
--ovpn-username <USER> --ovpn-password <PASS>
```

or enter credentials interactively in the TUI.

### Deploy Contract

```bash
cargo run -- deploy-contract
```

(Requires `SENDER_ADDRESS` if not passed through CLI where applicable.)

### Upload Provider File

```bash
cargo run -- upload-file \
  --sender-address <ETH_ADDRESS> \
  --provider-key <32_BYTE_HEX> \
  --name <PROVIDER_NAME> \
  --kind <openvpn|wireguard> \
  --file <PATH_TO_CONFIG>
```

## Environment Variables

- `SENDER_ADDRESS` — default sender address for commands that require it.
- `ROUTER_ADDRESS` — router contract address (used by `connect` by default).
- `VPN_ADDRESS` — VPN contract address (used by `connect` by default).
- `OPENVPN_BIN` — optional explicit path to OpenVPN binary.
- `PATH` — searched for `openvpn` when `OPENVPN_BIN` is not set.

## Notes and Operational Behavior

- Provider ranking is adjusted after each attempt (`+1` on success, `-1` on failure).
- Failed providers are marked in UI and skipped during navigation.
- OpenVPN credentials are written to a temporary auth file only when required by profile.
- Temporary staging directory is retained for session lifetime and cleaned when session ends.
- The TUI uses raw terminal mode and alternate screen; exiting restores terminal state.

## Development Tips

- Use `cargo check` for quick type/lint-style verification.
- Use `cargo run -- connect ...` for end-to-end client flow testing.
- Keep contract-side ABI/client updates in sync with `contract/client` generated interfaces.

## Troubleshooting

- **`openvpn binary not found`**: install OpenVPN or set `OPENVPN_BIN`.
- **Invalid address parsing errors**: verify hex formatting and expected chain address values.
- **Contract reply not successful**: inspect returned code/payload and verify RPC/router/contract endpoints.
- **Connection timeouts**: ensure provider config endpoint/network path is reachable and OpenVPN can route.
