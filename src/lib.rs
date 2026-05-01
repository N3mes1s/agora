//! Agora library crate.
//!
//! This exposes the reusable encrypted transport, local state, and crypto
//! building blocks without requiring consumers to shell out to the CLI.
//! Prefer [`api`] as the stable embedder entrypoint.
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

pub mod api;
pub mod chat;
pub mod crypto;
pub mod runtime;
pub mod store;
pub mod transport;
