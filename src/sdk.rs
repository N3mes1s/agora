//! Idiomatic Rust SDK for embedding Agora in another process.
//!
//! This module wraps the stable low-level [`crate::api`] facade with a
//! client/session API that owns the common embedder chores:
//!
//! - per-client runtime configuration without mutating process-wide env vars,
//! - loading joined rooms by label,
//! - constructing signed Agora message envelopes,
//! - publishing typed errors, and
//! - decrypting fetched or streamed room events.
//!
//! Use [`AgoraClient`] when embedding Agora in an app such as a broker,
//! daemon, or transport bridge. Use [`crate::api`] directly only when you need
//! the lowest-level envelope and relay primitives.

use crate::{api, crypto, runtime, store};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;
use std::path::PathBuf;
use std::time::Duration;

pub use crate::api::{PublishError, PublishLimits, StreamConfig, StreamDisconnect};

/// JSON message envelope exchanged over Agora.
pub type Envelope = api::Envelope;

/// Derived symmetric room key used for encryption and decryption.
pub type RoomKey = api::RoomKey;

/// SDK result alias.
pub type Result<T> = std::result::Result<T, AgoraError>;

/// Errors returned by the Rust SDK.
#[derive(Debug)]
pub enum AgoraError {
    /// No local room matches the requested label or room id.
    RoomNotFound(String),
    /// Relay publish failed.
    Publish(PublishError),
    /// JSON serialization or parsing failed.
    Json(serde_json::Error),
    /// Local Agora operation failed.
    Operation(String),
}

impl std::fmt::Display for AgoraError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RoomNotFound(room) => write!(f, "agora room not joined locally: {room}"),
            Self::Publish(err) => write!(f, "{err}"),
            Self::Json(err) => write!(f, "JSON error: {err}"),
            Self::Operation(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for AgoraError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Publish(err) => Some(err),
            Self::Json(err) => Some(err),
            Self::RoomNotFound(_) | Self::Operation(_) => None,
        }
    }
}

impl From<PublishError> for AgoraError {
    fn from(value: PublishError) -> Self {
        Self::Publish(value)
    }
}

impl From<serde_json::Error> for AgoraError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<String> for AgoraError {
    fn from(value: String) -> Self {
        Self::Operation(value)
    }
}

/// Per-client runtime configuration.
///
/// These values are installed only while an SDK call is executing. That lets
/// embedders run multiple Agora clients in one process without rewriting
/// process-wide environment variables.
#[derive(Debug, Clone, Default)]
pub struct AgoraConfig {
    home: Option<PathBuf>,
    agent_id: Option<String>,
    identity_seed: Option<String>,
    relay_url: Option<String>,
    relay_token: Option<String>,
    relay_mirror: Option<String>,
}

impl AgoraConfig {
    /// Create an empty config that inherits the process environment.
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the effective home directory for Agora state.
    pub fn home(mut self, home: impl Into<PathBuf>) -> Self {
        self.home = Some(home.into());
        self
    }

    /// Override the local agent identity display id.
    pub fn agent_id(mut self, agent_id: impl Into<String>) -> Self {
        self.agent_id = Some(agent_id.into());
        self
    }

    /// Configure a deterministic identity seed.
    pub fn identity_seed(mut self, seed: impl Into<String>) -> Self {
        self.identity_seed = Some(seed.into());
        self
    }

    /// Override the Agora relay URL.
    pub fn relay_url(mut self, relay_url: impl Into<String>) -> Self {
        self.relay_url = Some(relay_url.into());
        self
    }

    /// Override the relay bearer token.
    pub fn relay_token(mut self, relay_token: impl Into<String>) -> Self {
        self.relay_token = Some(relay_token.into());
        self
    }

    /// Override the optional mirror relay URL.
    pub fn relay_mirror(mut self, relay_mirror: impl Into<String>) -> Self {
        self.relay_mirror = Some(relay_mirror.into());
        self
    }

    fn has_overrides(&self) -> bool {
        self.home.is_some()
            || self.agent_id.is_some()
            || self.identity_seed.is_some()
            || self.relay_url.is_some()
            || self.relay_token.is_some()
            || self.relay_mirror.is_some()
    }

    fn runtime_context(&self) -> runtime::TestRuntime {
        let mut rt = runtime::TestRuntime::new();
        if let Some(home) = &self.home {
            rt = rt.home(home.clone());
        }
        if let Some(agent_id) = &self.agent_id {
            rt = rt.var("AGORA_AGENT_ID", agent_id.clone());
        }
        if let Some(seed) = &self.identity_seed {
            rt = rt.var("AGORA_IDENTITY_SEED", seed.clone());
        }
        if let Some(relay_url) = &self.relay_url {
            rt = rt.var("AGORA_RELAY_URL", relay_url.clone());
        }
        if let Some(relay_token) = &self.relay_token {
            rt = rt.var("AGORA_RELAY_TOKEN", relay_token.clone());
        }
        if let Some(relay_mirror) = &self.relay_mirror {
            rt = rt.var("AGORA_RELAY_MIRROR", relay_mirror.clone());
        }
        rt
    }

    fn with_runtime<T>(&self, f: impl FnOnce() -> T) -> T {
        if !self.has_overrides() {
            return f();
        }

        let _guard = self.runtime_context().enter();
        f()
    }
}

/// Agora SDK client.
#[derive(Debug, Clone, Default)]
pub struct AgoraClient {
    config: AgoraConfig,
}

impl AgoraClient {
    /// Create a client that inherits the process environment.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a client with explicit runtime configuration.
    pub fn with_config(config: AgoraConfig) -> Self {
        Self { config }
    }

    /// Return the runtime configuration used by this client.
    pub fn config(&self) -> &AgoraConfig {
        &self.config
    }

    /// Resolve this client's local agent id.
    pub fn agent_id(&self) -> String {
        self.config.with_runtime(api::agent_id)
    }

    /// Return client-side publish guidance for the configured relay.
    pub fn publish_limits(&self) -> PublishLimits {
        self.config.with_runtime(api::publish_limits)
    }

    /// List locally joined rooms.
    pub fn rooms(&self) -> Vec<Room> {
        self.config.with_runtime(|| {
            store::load_registry()
                .into_iter()
                .map(Room::from_entry)
                .collect()
        })
    }

    /// Open the active local room.
    pub fn active_room(&self) -> Result<RoomSession> {
        self.config.with_runtime(|| {
            let entry = store::get_active_room()
                .ok_or_else(|| AgoraError::RoomNotFound("<active>".to_string()))?;
            Ok(self.session_from_entry(entry))
        })
    }

    /// Open a joined room by label or room id.
    pub fn open_room(&self, label_or_id: impl AsRef<str>) -> Result<RoomSession> {
        let label_or_id = label_or_id.as_ref();
        self.config.with_runtime(|| {
            let entry = store::find_room(label_or_id)
                .ok_or_else(|| AgoraError::RoomNotFound(label_or_id.to_string()))?;
            Ok(self.session_from_entry(entry))
        })
    }

    /// Create, persist, and announce a new room.
    pub fn create_room(&self, label: impl AsRef<str>) -> Result<RoomSession> {
        let label = label.as_ref();
        self.config.with_runtime(|| {
            let room_id = crypto::generate_room_id();
            let secret = crypto::generate_secret();
            let entry = store::add_room(&room_id, &secret, label, store::Role::Admin);
            store::set_active_room(label);
            let session = self.session_from_entry(entry);
            let env = session.message_envelope("Room created (agora v3, Rust SDK).", None);
            session.publish_envelope(&env)?;
            Ok(session)
        })
    }

    /// Join, persist, and announce an existing room.
    pub fn join_room(
        &self,
        room_id: impl AsRef<str>,
        secret: impl AsRef<str>,
        label: impl AsRef<str>,
    ) -> Result<RoomSession> {
        let room_id = room_id.as_ref();
        let secret = secret.as_ref();
        let label = label.as_ref();
        self.config.with_runtime(|| {
            let entry = store::add_room(room_id, secret, label, store::Role::Member);
            store::set_active_room(label);
            let session = self.session_from_entry(entry);
            let env = session.message_envelope("Joined (agora v3, Rust SDK).", None);
            session.publish_envelope(&env)?;
            Ok(session)
        })
    }

    /// Switch the active local room.
    pub fn switch_room(&self, label_or_id: impl AsRef<str>) -> Result<()> {
        let label_or_id = label_or_id.as_ref();
        self.config.with_runtime(|| {
            let room = store::find_room(label_or_id)
                .ok_or_else(|| AgoraError::RoomNotFound(label_or_id.to_string()))?;
            store::set_active_room(&room.label);
            Ok(())
        })
    }

    fn session_from_entry(&self, entry: store::RoomEntry) -> RoomSession {
        let room_key = api::derive_room_key(&entry.secret, &entry.room_id);
        RoomSession {
            config: self.config.clone(),
            room_id: entry.room_id,
            label: entry.label,
            secret: entry.secret,
            room_key,
            agent_id: api::agent_id(),
        }
    }
}

/// Metadata for a joined room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Room {
    pub room_id: String,
    pub label: String,
    pub joined_at: u64,
    pub topic: Option<String>,
    pub purpose: Option<String>,
    pub dm_peer: Option<String>,
}

impl Room {
    fn from_entry(entry: store::RoomEntry) -> Self {
        Self {
            room_id: entry.room_id,
            label: entry.label,
            joined_at: entry.joined_at,
            topic: entry.topic,
            purpose: entry.purpose,
            dm_peer: entry.dm_peer,
        }
    }
}

/// Open room session for publishing, fetching, and streaming events.
#[derive(Debug, Clone)]
pub struct RoomSession {
    config: AgoraConfig,
    room_id: String,
    label: String,
    secret: String,
    room_key: RoomKey,
    agent_id: String,
}

impl RoomSession {
    /// Stable room id used as the relay topic.
    pub fn room_id(&self) -> &str {
        &self.room_id
    }

    /// Local room label.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Shared room secret.
    pub fn secret(&self) -> &str {
        &self.secret
    }

    /// Current local agent id.
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    /// Derived room key.
    pub fn room_key(&self) -> &RoomKey {
        &self.room_key
    }

    /// Human-readable room key fingerprint.
    pub fn fingerprint(&self) -> String {
        crypto::fingerprint(&self.room_key)
    }

    /// Build a signed-message envelope using this session's sender identity.
    pub fn message_envelope(&self, text: impl AsRef<str>, reply_to: Option<&str>) -> Envelope {
        let ts = self.config.with_runtime(runtime::unix_now);
        let mut env = json!({
            "v": "3.0",
            "id": message_id(),
            "from": self.agent_id,
            "ts": ts,
            "text": text.as_ref(),
        });
        if let Some(reply_to) = reply_to {
            env["reply_to"] = json!(reply_to);
        }
        env
    }

    /// Encrypt and sign an Agora envelope for this room.
    pub fn encrypt_envelope(&self, envelope: &Envelope) -> String {
        self.config
            .with_runtime(|| api::encrypt_envelope(envelope, &self.room_key, &self.room_id))
    }

    /// Decrypt a signed payload for this room.
    pub fn decrypt_signed_payload(&self, raw: &str) -> Option<Envelope> {
        self.config
            .with_runtime(|| api::decrypt_signed_payload(raw, &self.room_key, &self.room_id))
    }

    /// Decrypt a signed payload, falling back to the legacy unsigned wire format.
    pub fn decrypt_payload(&self, raw: &str) -> Option<Envelope> {
        self.config
            .with_runtime(|| api::decrypt_payload(raw, &self.room_key, &self.room_id))
    }

    /// Publish an already-encrypted wire payload.
    pub fn publish_payload(&self, payload: &str) -> Result<()> {
        self.config
            .with_runtime(|| api::publish(&self.room_id, payload))
            .map_err(AgoraError::from)
    }

    /// Encrypt, publish, and locally cache an envelope.
    pub fn publish_envelope(&self, envelope: &Envelope) -> Result<()> {
        let payload = self.encrypt_envelope(envelope);
        self.publish_payload(&payload)?;
        self.config
            .with_runtime(|| store::save_message(&self.room_id, envelope));
        Ok(())
    }

    /// Send a text message. Returns the Agora message id.
    pub fn send_text(&self, text: impl AsRef<str>) -> Result<String> {
        self.send_text_reply(text, None)
    }

    /// Send a text reply. Returns the Agora message id.
    pub fn send_text_reply(&self, text: impl AsRef<str>, reply_to: Option<&str>) -> Result<String> {
        let env = self.message_envelope(text, reply_to);
        let id = env["id"].as_str().unwrap_or("").to_string();
        self.publish_envelope(&env)?;
        Ok(id)
    }

    /// Serialize an application frame as JSON and send it in the Agora `text` field.
    ///
    /// This is the path embedders use when Agora is the encrypted relay for a
    /// higher-level protocol.
    pub fn send_json<T: Serialize>(&self, value: &T) -> Result<String> {
        let text = serde_json::to_string(value)?;
        self.send_text(text)
    }

    /// Fetch raw encrypted payloads from the configured relay.
    pub fn fetch_raw(&self, since: &str) -> Vec<(u64, String)> {
        self.config
            .with_runtime(|| api::fetch(&self.room_id, since))
    }

    /// Fetch and decrypt room envelopes, skipping payloads that do not decrypt.
    pub fn fetch_envelopes(&self, since: &str) -> Vec<(u64, Envelope)> {
        self.fetch_raw(since)
            .into_iter()
            .filter_map(|(ts, raw)| {
                let mut env = self.decrypt_payload(&raw)?;
                if env["ts"].as_u64().unwrap_or(0) == 0 {
                    env["ts"] = json!(ts);
                }
                Some((ts, env))
            })
            .collect()
    }

    /// Fetch decrypted text messages.
    pub fn fetch_messages(&self, since: &str) -> Vec<Message> {
        self.fetch_envelopes(since)
            .into_iter()
            .filter_map(|(_, env)| Message::from_envelope(env))
            .collect()
    }

    /// Stream and decrypt envelopes from this room.
    ///
    /// This call blocks until the underlying stream ends. Set
    /// `StreamConfig { reconnect: true, .. }` for long-lived embedders.
    pub fn stream_envelopes<F, G>(
        &self,
        stream_config: &StreamConfig,
        mut on_envelope: F,
        on_disconnect: G,
    ) where
        F: FnMut(u64, Envelope),
        G: FnMut(StreamDisconnect, Option<Duration>),
    {
        let room_id = self.room_id.clone();
        let room_key = self.room_key;
        self.config.with_runtime(|| {
            api::stream_with_config(
                &room_id,
                stream_config,
                |ts, raw| {
                    if let Some(mut env) = api::decrypt_payload(raw, &room_key, &room_id) {
                        if env["ts"].as_u64().unwrap_or(0) == 0 {
                            env["ts"] = json!(ts);
                        }
                        on_envelope(ts, env);
                    }
                },
                on_disconnect,
            );
        });
    }

    /// Stream and decrypt envelopes from this room, beginning at `since`.
    pub fn stream_since_envelopes<F, G>(
        &self,
        since: &str,
        stream_config: &StreamConfig,
        mut on_envelope: F,
        on_disconnect: G,
    ) where
        F: FnMut(u64, Envelope),
        G: FnMut(StreamDisconnect, Option<Duration>),
    {
        let room_id = self.room_id.clone();
        let room_key = self.room_key;
        self.config.with_runtime(|| {
            api::stream_since_with_config(
                &room_id,
                since,
                stream_config,
                |ts, raw| {
                    if let Some(mut env) = api::decrypt_payload(raw, &room_key, &room_id) {
                        if env["ts"].as_u64().unwrap_or(0) == 0 {
                            env["ts"] = json!(ts);
                        }
                        on_envelope(ts, env);
                    }
                },
                on_disconnect,
            );
        });
    }
}

/// Decrypted Agora text message.
#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    pub id: String,
    pub sender: String,
    pub timestamp: u64,
    pub text: String,
    pub reply_to: Option<String>,
    pub auth: Option<String>,
    pub envelope: Envelope,
}

impl Message {
    /// Convert a JSON envelope into a typed text message.
    pub fn from_envelope(envelope: Envelope) -> Option<Self> {
        Some(Self {
            id: envelope.get("id")?.as_str()?.to_string(),
            sender: envelope.get("from")?.as_str()?.to_string(),
            timestamp: envelope.get("ts").and_then(|v| v.as_u64()).unwrap_or(0),
            text: envelope.get("text")?.as_str()?.to_string(),
            reply_to: envelope
                .get("reply_to")
                .and_then(|v| v.as_str())
                .map(ToString::to_string),
            auth: envelope
                .get("_auth")
                .and_then(|v| v.as_str())
                .map(ToString::to_string),
            envelope,
        })
    }

    /// Parse this message's `text` field as an application JSON frame.
    pub fn text_json<T: DeserializeOwned>(&self) -> std::result::Result<T, serde_json::Error> {
        serde_json::from_str(&self.text)
    }
}

fn message_id() -> String {
    let mut bytes = [0u8; 4];
    SystemRandom::new()
        .fill(&mut bytes)
        .expect("random message id");
    hex::encode(bytes)
}
