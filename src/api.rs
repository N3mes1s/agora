//! Stable embedder facade for Agora.
//!
//! New library consumers should prefer `agora::api` over reaching into the
//! lower-level modules directly. The facade is intentionally narrow and maps to
//! the transport and envelope operations embedders need for in-process relay
//! integration.

use crate::{chat, crypto, store, transport};

/// JSON message envelope exchanged over Agora.
pub type Envelope = serde_json::Value;

/// Derived symmetric room key used for encryption and decryption.
pub type RoomKey = [u8; 32];

/// Resolve the current local agent identity.
pub fn agent_id() -> String {
    store::get_agent_id()
}

/// Load the local signing keypair for `agent_id`, creating one on first use.
pub fn signing_keypair(agent_id: &str) -> Result<Vec<u8>, String> {
    store::load_signing_keypair(agent_id)
}

/// Return the trusted signing key currently bound to `agent_id`, if any.
pub fn trusted_signing_key(agent_id: &str) -> Option<String> {
    store::get_trusted_signing_key(agent_id)
}

/// Derive the room encryption key from a shared secret and room identifier.
pub fn derive_room_key(shared_secret: &str, room_id: &str) -> RoomKey {
    crypto::derive_room_key(shared_secret, room_id)
}

/// Encrypt and sign an envelope for relay transport.
pub fn encrypt_envelope(env: &Envelope, room_key: &RoomKey, room_id: &str) -> String {
    chat::encrypt_envelope(env, room_key, room_id)
}

/// Decrypt a signed relay payload into a verified envelope.
pub fn decrypt_signed_payload(raw: &str, room_key: &RoomKey, room_id: &str) -> Option<Envelope> {
    chat::decrypt_signed_payload(raw, room_key, room_id)
}

/// Decrypt either a signed payload or the legacy unsigned payload format.
pub fn decrypt_payload(payload: &str, room_key: &RoomKey, room_id: &str) -> Option<Envelope> {
    chat::decrypt_payload(payload, room_key, room_id)
}

/// Publish an encrypted payload to the configured relay topic.
pub fn publish(topic: &str, payload: &str) -> bool {
    transport::publish(topic, payload)
}

/// Fetch recent raw payloads from the configured relay topic.
pub fn fetch(topic: &str, since: &str) -> Vec<(u64, String)> {
    transport::fetch(topic, since)
}

/// Open a streaming SSE connection for `topic` and invoke `on_message` per event.
pub fn stream<F>(topic: &str, on_message: F)
where
    F: FnMut(u64, &str),
{
    transport::stream(topic, on_message)
}
