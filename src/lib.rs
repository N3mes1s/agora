//! Agora library crate.
//!
//! This exposes the reusable encrypted transport, local state, and crypto
//! building blocks without requiring consumers to shell out to the CLI.
//! Prefer [`api`] as the stable embedder entrypoint.

pub mod api;
pub mod chat;
pub mod crypto;
pub mod runtime;
pub mod store;
pub mod transport;
