//! Stable embedder facade for Agora.
//!
//! New library consumers should prefer `agora::api` over reaching into the
//! lower-level modules directly. The facade is intentionally narrow and maps to
//! the transport and envelope operations embedders need for in-process relay
//! integration.
//!
//! # Stability
//!
//! This module is the intended semver-stable boundary for embedders. The
//! lower-level modules remain available for advanced use, but they may evolve
//! faster than this facade.
//!
//! # Example
//!
//! ```rust
//! use agora::{api, runtime};
//! use serde_json::json;
//!
//! let home = std::env::temp_dir().join(format!("agora-api-doc-{}", std::process::id()));
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

use crate::{chat, crypto, store, transport};

/// JSON message envelope exchanged over Agora.
pub type Envelope = serde_json::Value;

/// Derived symmetric room key used for encryption and decryption.
pub type RoomKey = [u8; 32];

/// Resolve the current local agent identity.
///
/// This honors the current runtime context, including [`crate::runtime::TestRuntime`].
pub fn agent_id() -> String {
    store::get_agent_id()
}

/// Load the local signing keypair for `agent_id`, creating one on first use.
///
/// The returned bytes are PKCS#8-encoded Ed25519 key material.
pub fn signing_keypair(agent_id: &str) -> Result<Vec<u8>, String> {
    store::load_signing_keypair(agent_id)
}

/// Return the trusted signing key currently bound to `agent_id`, if any.
///
/// The value is canonical standard-base64 text.
pub fn trusted_signing_key(agent_id: &str) -> Option<String> {
    store::get_trusted_signing_key(agent_id)
}

/// Derive the room encryption key from a shared secret and room identifier.
pub fn derive_room_key(shared_secret: &str, room_id: &str) -> RoomKey {
    crypto::derive_room_key(shared_secret, room_id)
}

/// Encrypt and sign an envelope for relay transport.
///
/// The result is the raw signed wire payload string suitable for
/// [`publish`].
pub fn encrypt_envelope(env: &Envelope, room_key: &RoomKey, room_id: &str) -> String {
    chat::encrypt_envelope(env, room_key, room_id)
}

/// Decrypt a signed relay payload into a verified envelope.
///
/// On success, the returned envelope includes `"_auth": "verified"`.
pub fn decrypt_signed_payload(raw: &str, room_key: &RoomKey, room_id: &str) -> Option<Envelope> {
    chat::decrypt_signed_payload(raw, room_key, room_id)
}

/// Decrypt either a signed payload or the legacy unsigned payload format.
///
/// Signed payloads yield `"_auth": "verified"`. Legacy unsigned payloads
/// yield `"_auth": "unsigned"`.
pub fn decrypt_payload(payload: &str, room_key: &RoomKey, room_id: &str) -> Option<Envelope> {
    chat::decrypt_payload(payload, room_key, room_id)
}

/// Publish an encrypted payload to the configured relay topic.
///
/// ```no_run
/// use agora::api;
///
/// let ok = api::publish("ag-room-id", "{\"payload\":\"...\"}");
/// assert!(ok);
/// ```
pub fn publish(topic: &str, payload: &str) -> bool {
    transport::publish(topic, payload)
}

/// Fetch recent raw payloads from the configured relay topic.
///
/// `since` follows the same format as the CLI transport layer, such as
/// `"30s"`, `"5m"`, `"2h"`, or `"0"`.
///
/// ```no_run
/// use agora::api;
///
/// let events = api::fetch("ag-room-id", "2m");
/// for (ts, raw) in events {
///     println!("{ts}: {raw}");
/// }
/// ```
pub fn fetch(topic: &str, since: &str) -> Vec<(u64, String)> {
    transport::fetch(topic, since)
}

/// Open a streaming SSE connection for `topic` and invoke `on_message` per event.
///
/// This blocks until the stream ends or the relay connection fails.
///
/// ```no_run
/// use agora::api;
///
/// api::stream("ag-room-id", |ts, raw| {
///     println!("{ts}: {raw}");
/// });
/// ```
pub fn stream<F>(topic: &str, on_message: F)
where
    F: FnMut(u64, &str),
{
    transport::stream(topic, on_message)
}
