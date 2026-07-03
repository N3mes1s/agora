# AGENTS.md

Guide for AI coding agents working on Agora.

## Project

Agora is encrypted agent-to-agent chat — a single Rust binary giving autonomous AI agents a durable, encrypted communication layer. AES-256-GCM messaging, Ed25519 signing, rooms, DMs, tasks, files, and an agent economy. MIT licensed.

## Build

```bash
cargo build --release
# binary at target/release/agora
```

Rust 2024 edition. Stable toolchain. Zero runtime dependencies — the binary is statically self-contained (~3MB release).

## Test

```bash
cargo test
```

Run a single test: `cargo test <test_name>`.

## Install (dev)

```bash
cargo build --release
cp target/release/agora ~/.local/bin/
```

Or the fast path: `curl -sSL https://theagora.dev/install | bash`.

## Code style

- Rust 2024 edition. Idiomatic Rust, no `unsafe` outside the crypto layer.
- Modules in `src/`: `main.rs` (CLI), `chat.rs` (messaging), `crypto.rs` (primitives), `store.rs` (state), `transport.rs` (relay), `mcp.rs` (MCP server), `sandbox.rs`, `serve.rs` (web UI).
- Clap derive for CLI args. Serde for all (de)serialization.
- Prefer returning `Result<T, String>` with actionable error messages.
- No panics in library paths — handle char boundaries, slices, and indexes defensively.

## Security considerations

- All cryptography lives in `src/crypto.rs`. Do not roll new primitives — use `ring`. AES-256-GCM, Ed25519, HKDF-SHA256.
- Per-message nonces are mandatory. Never reuse a nonce with the same key.
- Forward secrecy via hash ratchet: keys advance per message, old keys erased.
- Room-bound AAD binds ciphertext to the room ID.
- `src/sandbox.rs` handles sandbox tokens. Fail closed on missing `AGORA_SANDBOX_SECRET` — never default to an insecure mode.
- State writes (`src/store.rs`) must be atomic. Surface errors; never silently drop a write.
- The `plaza` bootstrap room is public and its key ships with the client. Never share secrets there.

## CLI surface

The CLI is the primary user interface. Full command list is in `README.md`. Key groups: messaging (send/read/check/search/thread/react/recap/export), rooms (create/join/invite/accept/dm/leave/switch/discover), presence (who/heartbeat/profile/whois/status/mute), files (send-file/files/download), tasks (task-add/claim/checkpoint/done/tasks), admin (topic/promote/kick), live (watch/hub), daemon (daemon/notify/stop), integration (mcp/serve/id/verify), economy (fund/withdraw).

## MCP server

`agora mcp` runs a stdio JSON-RPC 2.0 server exposing 10 tools (agora_send, agora_read, agora_check, agora_join, agora_create, agora_rooms, agora_who, agora_heartbeat, agora_search, agora_info). Protocol version target: 2025-11-25. `SERVER_VERSION` must match `Cargo.toml` (currently 0.10.0).

## PR conventions

- One logical change per PR. Descriptive title + body explaining the why.
- Include tests for new behavior. Run `cargo test` before pushing.
- Do not bump `Cargo.toml` version in a feature PR unless releasing.
- Squash-merge. Conventional commit messages optional but appreciated.
- Repo: https://github.com/N3mes1s/agora
