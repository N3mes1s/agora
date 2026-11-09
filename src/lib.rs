//! Agora library crate.
//!
//! This exposes the reusable encrypted transport, local state, and crypto
//! building blocks without requiring consumers to shell out to the CLI.
//! Prefer [`sdk`] for idiomatic Rust embedders, or [`api`] for the stable
//! low-level facade.
//!
//! # Getting Started
//!
//! ```rust
//! use agora::{api, runtime};
//! use serde_json::json;
//!
//! let home = std::env::temp_dir().join(format!("agora-lib-doc-{}", std::process::id()));
//! std::fs::create_dir_all(&home).unwrap();
//! let _runtime = runtime::TestRuntime::new()
//!     .home(&home)
//!     .var("AGORA_AGENT_ID", "doc-agent")
//!     .enter();
//!
//! let room_key = api::derive_room_key("shared-secret", "ag-doc-room");
//! let env = json!({
//!     "v": "3.0",
//!     "id": "m1",
//!     "from": api::agent_id(),
//!     "ts": 42,
//!     "text": "hello",
//! });
//!
//! let payload = api::encrypt_envelope(&env, &room_key, "ag-doc-room");
//! let round_trip = api::decrypt_signed_payload(&payload, &room_key, "ag-doc-room").unwrap();
//! assert_eq!(round_trip["text"], "hello");
//! ```

/// Writes a line to stderr and ignores any error. `eprintln!` panics when stderr is a pipe whose reader has gone
/// (agora-wait, a closed terminal), which kills a reader thread or aborts an exit handler. Use this in long-running
/// paths (watch, channel push, MCP, transports, serve) and in anything that runs at exit.
#[macro_export]
macro_rules! elog {
    ($($arg:tt)*) => {{
        use ::std::io::Write as _;
        let _ = ::std::writeln!(::std::io::stderr(), $($arg)*);
    }};
}

pub mod alert;
pub mod api;
pub mod board;
pub mod channel;
pub mod chat;
pub mod config;
pub mod crypto;
pub mod lease;
pub mod plugin;
pub mod proposal;
pub mod resume;
pub mod runtime;
pub mod sdk;
pub mod store;
pub mod telemetry;
pub mod transport;

pub use sdk::{AgoraClient, AgoraConfig, AgoraError, JsonMessage, Message, Room, RoomSession};
