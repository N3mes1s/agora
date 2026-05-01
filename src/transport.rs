//! Agora transport layer.
//!
//! E2E encrypted before hitting the wire. The relay only sees ciphertext.
//! The default transport is the public ntfy relay, but alternate backends can
//! be selected by URL scheme at runtime.
//!
//! Relay URL is configurable:
//!   AGORA_RELAY_URL=https://ntfy.theagora.dev  (default ntfy relay)
//!   AGORA_RELAY_URL=nats://127.0.0.1:4222     (NATS + JetStream)
//!   AGORA_RELAY_URL=memory://test-suite       (in-memory test relay)
//!
//! Optional relay auth:
//!   AGORA_RELAY_TOKEN=...  (ntfy bearer token or NATS auth token)
//!
//! Optional ntfy mirror publish:
//!   AGORA_RELAY_MIRROR=https://mirror.example  (publish to both)

mod memory;
mod nats;
mod ntfy;

use crate::runtime;
use std::collections::HashSet;
use std::time::Duration;

pub(crate) const DEFAULT_RELAY: &str = "https://ntfy.theagora.dev";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishError {
    RateLimited { retry_after: Option<Duration> },
    PayloadTooLarge { limit: Option<u64> },
    Forbidden(String),
    Network(String),
}

impl std::fmt::Display for PublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RateLimited { retry_after } => match retry_after {
                Some(delay) => write!(f, "relay rate-limited publish; retry after {delay:?}"),
                None => write!(f, "relay rate-limited publish"),
            },
            Self::PayloadTooLarge { limit } => match limit {
                Some(limit) => write!(f, "publish payload exceeds relay limit of {limit} bytes"),
                None => write!(f, "publish payload exceeds relay size limit"),
            },
            Self::Forbidden(message) => write!(f, "relay rejected publish: {message}"),
            Self::Network(message) => write!(f, "relay publish failed: {message}"),
        }
    }
}

impl std::error::Error for PublishError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublishLimits {
    pub burst: Option<usize>,
    pub sustained_per_second: Option<u32>,
    pub body_max_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamDisconnect {
    Auth(String),
    Connect(String),
    Read(String),
}

impl std::fmt::Display for StreamDisconnect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auth(message) => write!(f, "relay auth failed: {message}"),
            Self::Connect(message) => write!(f, "relay stream connection failed: {message}"),
            Self::Read(message) => write!(f, "relay stream read failed: {message}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamConfig {
    pub reconnect: bool,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            reconnect: false,
            initial_backoff: Duration::from_secs(5),
            max_backoff: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum StreamReplayKey {
    Id(String),
    Payload(String),
}

#[derive(Debug, Clone)]
pub(crate) struct StreamCursor {
    pub(crate) since_ts: u64,
    seen_at_since: HashSet<StreamReplayKey>,
}

impl StreamCursor {
    pub(crate) fn new(since_ts: u64) -> Self {
        Self {
            since_ts,
            seen_at_since: HashSet::new(),
        }
    }

    pub(crate) fn should_emit(&mut self, ts: u64, id: Option<&str>, payload: &str) -> bool {
        if ts < self.since_ts {
            return false;
        }

        let key = match id {
            Some(id) => StreamReplayKey::Id(id.to_string()),
            None => StreamReplayKey::Payload(payload.to_string()),
        };

        if ts == self.since_ts && self.seen_at_since.contains(&key) {
            return false;
        }

        if ts > self.since_ts {
            self.since_ts = ts;
            self.seen_at_since.clear();
        }

        self.seen_at_since.insert(key);
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportKind {
    Memory,
    Nats,
    Ntfy,
}

#[derive(Debug, Clone)]
struct TransportConfig {
    relay_url: String,
    relay_token: Option<String>,
    relay_mirror: Option<String>,
}

impl TransportConfig {
    fn current() -> Self {
        Self {
            relay_url: relay_url(),
            relay_token: relay_token(),
            relay_mirror: mirror_url(),
        }
    }

    fn kind(&self) -> TransportKind {
        if self.relay_url.starts_with("memory://") {
            return TransportKind::Memory;
        }

        if let Ok(url) = url::Url::parse(&self.relay_url) {
            return match url.scheme() {
                "nats" | "tls" => TransportKind::Nats,
                _ => TransportKind::Ntfy,
            };
        }

        TransportKind::Ntfy
    }
}

trait Transport {
    fn relay_status_label(&self, config: &TransportConfig) -> String;
    fn publish_limits(&self, config: &TransportConfig) -> PublishLimits;
    fn publish(
        &self,
        config: &TransportConfig,
        topic: &str,
        payload: &str,
    ) -> Result<(), PublishError>;
    fn fetch(&self, config: &TransportConfig, topic: &str, since: &str) -> Vec<(u64, String)>;
    fn stream(
        &self,
        config: &TransportConfig,
        topic: &str,
        initial_since: Option<&str>,
        stream_config: &StreamConfig,
        on_message: &mut dyn FnMut(u64, &str),
        on_disconnect: &mut dyn FnMut(StreamDisconnect, Option<Duration>),
    );
}

fn relay_url() -> String {
    runtime::var("AGORA_RELAY_URL").unwrap_or_else(|| DEFAULT_RELAY.to_string())
}

fn relay_token() -> Option<String> {
    runtime::var("AGORA_RELAY_TOKEN")
}

fn mirror_url() -> Option<String> {
    runtime::var("AGORA_RELAY_MIRROR").and_then(|value| {
        let value = value.trim();
        if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        }
    })
}

pub(crate) fn parse_since_cutoff(since: &str, now: u64) -> u64 {
    if let Some(secs) = since.strip_suffix('s').and_then(|v| v.parse::<u64>().ok()) {
        return now.saturating_sub(secs);
    }
    if let Some(mins) = since.strip_suffix('m').and_then(|v| v.parse::<u64>().ok()) {
        return now.saturating_sub(mins * 60);
    }
    if let Some(hours) = since.strip_suffix('h').and_then(|v| v.parse::<u64>().ok()) {
        return now.saturating_sub(hours * 3600);
    }
    if let Some(days) = since.strip_suffix('d').and_then(|v| v.parse::<u64>().ok()) {
        return now.saturating_sub(days * 86400);
    }
    since.parse::<u64>().unwrap_or(0)
}

fn with_transport<R>(f: impl FnOnce(&dyn Transport, &TransportConfig) -> R) -> R {
    let config = TransportConfig::current();
    match config.kind() {
        TransportKind::Memory => {
            let transport = memory::MemoryTransport;
            f(&transport, &config)
        }
        TransportKind::Nats => {
            let transport = nats::NatsTransport;
            f(&transport, &config)
        }
        TransportKind::Ntfy => {
            let transport = ntfy::NtfyTransport;
            f(&transport, &config)
        }
    }
}

pub fn relay_status_label() -> String {
    with_transport(|transport, config| transport.relay_status_label(config))
}

pub fn publish_limits() -> PublishLimits {
    with_transport(|transport, config| transport.publish_limits(config))
}

/// Publish an encrypted payload to the configured relay topic.
pub fn publish(topic: &str, payload: &str) -> bool {
    publish_detailed(topic, payload).is_ok()
}

/// Publish an encrypted payload to the configured relay topic with typed error reporting.
pub fn publish_detailed(topic: &str, payload: &str) -> Result<(), PublishError> {
    with_transport(|transport, config| transport.publish(config, topic, payload))
}

/// Fetch recent messages from the configured relay topic.
pub fn fetch(topic: &str, since: &str) -> Vec<(u64, String)> {
    with_transport(|transport, config| transport.fetch(config, topic, since))
}

/// Open a streaming connection to the configured relay topic.
pub fn stream<F>(topic: &str, mut on_message: F)
where
    F: FnMut(u64, &str),
{
    stream_with_config(topic, &StreamConfig::default(), &mut on_message, |_, _| {});
}

/// Open a streaming connection that starts with an explicit catchup cursor.
pub fn stream_since<F>(topic: &str, since: &str, mut on_message: F)
where
    F: FnMut(u64, &str),
{
    stream_since_with_config(
        topic,
        since,
        &StreamConfig::default(),
        &mut on_message,
        |_, _| {},
    );
}

/// Open a streaming connection with reconnect/backoff configuration.
pub fn stream_with_config<F, G>(topic: &str, config: &StreamConfig, on_message: F, on_disconnect: G)
where
    F: FnMut(u64, &str),
    G: FnMut(StreamDisconnect, Option<Duration>),
{
    stream_from_cursor_with_config(topic, None, config, on_message, on_disconnect);
}

/// Open a streaming connection with reconnect/backoff configuration and an explicit initial cursor.
pub fn stream_since_with_config<F, G>(
    topic: &str,
    since: &str,
    config: &StreamConfig,
    on_message: F,
    on_disconnect: G,
) where
    F: FnMut(u64, &str),
    G: FnMut(StreamDisconnect, Option<Duration>),
{
    stream_from_cursor_with_config(topic, Some(since), config, on_message, on_disconnect);
}

fn stream_from_cursor_with_config<F, G>(
    topic: &str,
    initial_since: Option<&str>,
    config: &StreamConfig,
    mut on_message: F,
    mut on_disconnect: G,
) where
    F: FnMut(u64, &str),
    G: FnMut(StreamDisconnect, Option<Duration>),
{
    with_transport(|transport, transport_config| {
        transport.stream(
            transport_config,
            topic,
            initial_since,
            config,
            &mut on_message,
            &mut on_disconnect,
        )
    });
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_RELAY, PublishError, PublishLimits, StreamConfig, StreamCursor, StreamDisconnect,
        TransportConfig, TransportKind, fetch, mirror_url, ntfy, publish, publish_detailed,
        publish_limits, relay_status_label, relay_token, relay_url, stream_since,
    };
    use crate::runtime;
    use std::time::Duration;

    #[test]
    fn relay_url_defaults_to_ntfy() {
        let _runtime = runtime::TestRuntime::new()
            .unset_var("AGORA_RELAY_URL")
            .enter();

        assert_eq!(relay_url(), DEFAULT_RELAY);
        assert_eq!(TransportConfig::current().kind(), TransportKind::Ntfy);
    }

    #[test]
    fn relay_url_uses_nats_scheme_override() {
        let _runtime = runtime::TestRuntime::new()
            .var("AGORA_RELAY_URL", "nats://127.0.0.1:4222")
            .enter();

        assert_eq!(relay_url(), "nats://127.0.0.1:4222");
        assert_eq!(TransportConfig::current().kind(), TransportKind::Nats);
    }

    #[test]
    fn relay_url_uses_memory_scheme_override() {
        let _runtime = runtime::TestRuntime::new()
            .var("AGORA_RELAY_URL", "memory://suite")
            .enter();

        assert_eq!(TransportConfig::current().kind(), TransportKind::Memory);
    }

    #[test]
    fn mirror_url_uses_default_when_env_is_unset() {
        let _runtime = runtime::TestRuntime::new()
            .unset_var("AGORA_RELAY_MIRROR")
            .enter();

        assert_eq!(mirror_url(), None);
    }

    #[test]
    fn mirror_url_can_be_disabled_with_empty_env() {
        let _runtime = runtime::TestRuntime::new()
            .var("AGORA_RELAY_MIRROR", "")
            .enter();

        assert_eq!(mirror_url(), None);
    }

    #[test]
    fn mirror_url_can_be_disabled_with_whitespace_env() {
        let _runtime = runtime::TestRuntime::new()
            .var("AGORA_RELAY_MIRROR", "  \t  ")
            .enter();

        assert_eq!(mirror_url(), None);
    }

    #[test]
    fn mirror_url_uses_explicit_override() {
        let _runtime = runtime::TestRuntime::new()
            .var("AGORA_RELAY_MIRROR", "https://mirror.example")
            .enter();

        assert_eq!(mirror_url(), Some("https://mirror.example".to_string()));
    }

    #[test]
    fn relay_token_is_optional() {
        let _runtime = runtime::TestRuntime::new()
            .unset_var("AGORA_RELAY_TOKEN")
            .enter();
        assert_eq!(relay_token(), None);

        let _runtime = runtime::TestRuntime::new()
            .var("AGORA_RELAY_TOKEN", "relay-secret")
            .enter();
        assert_eq!(relay_token(), Some("relay-secret".to_string()));
    }

    #[test]
    fn relay_status_label_reflects_override() {
        let _runtime = runtime::TestRuntime::new()
            .var("AGORA_RELAY_URL", "nats://127.0.0.1:4222")
            .enter();

        assert_eq!(relay_status_label(), "Relay (nats://127.0.0.1:4222)");
    }

    #[test]
    fn publish_limits_default_relay_are_conservative() {
        let _runtime = runtime::TestRuntime::new()
            .unset_var("AGORA_RELAY_URL")
            .enter();
        assert_eq!(
            publish_limits(),
            PublishLimits {
                burst: Some(2),
                sustained_per_second: Some(2),
                body_max_bytes: None,
            }
        );
    }

    #[test]
    fn publish_limits_custom_relays_are_unknown() {
        let _runtime = runtime::TestRuntime::new()
            .var("AGORA_RELAY_URL", "nats://127.0.0.1:4222")
            .enter();
        assert_eq!(
            publish_limits(),
            PublishLimits {
                burst: None,
                sustained_per_second: None,
                body_max_bytes: None,
            }
        );
    }

    #[test]
    fn classify_publish_failure_maps_rate_limit() {
        assert_eq!(
            ntfy::classify_publish_failure(429, Some("7"), "slow down"),
            PublishError::RateLimited {
                retry_after: Some(Duration::from_secs(7))
            }
        );
    }

    #[test]
    fn classify_publish_failure_maps_payload_too_large() {
        assert_eq!(
            ntfy::classify_publish_failure(413, None, "too large"),
            PublishError::PayloadTooLarge { limit: None }
        );
    }

    #[test]
    fn classify_publish_failure_maps_forbidden() {
        assert_eq!(
            ntfy::classify_publish_failure(403, None, "blocked"),
            PublishError::Forbidden("HTTP 403: blocked".to_string())
        );
    }

    #[test]
    fn classify_stream_connect_failure_maps_auth() {
        assert_eq!(
            ntfy::classify_stream_connect_failure(403, "blocked"),
            StreamDisconnect::Auth("HTTP 403: blocked".to_string())
        );
    }

    #[test]
    fn stream_config_defaults_are_reconnect_disabled() {
        assert_eq!(
            StreamConfig::default(),
            StreamConfig {
                reconnect: false,
                initial_backoff: Duration::from_secs(5),
                max_backoff: Duration::from_secs(30),
            }
        );
    }

    #[test]
    fn publish_and_fetch_use_memory_transport() {
        let home = std::env::temp_dir().join(format!(
            "agora-transport-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&home).unwrap();
        let _runtime = runtime::TestRuntime::new()
            .home(&home)
            .var("AGORA_RELAY_URL", "memory://suite")
            .enter();

        assert!(publish("room-a", "first"));
        assert!(publish("room-a", "second"));
        assert_eq!(publish_detailed("room-a", "third"), Ok(()));

        let events = fetch("room-a", "1h");
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].1, "first");
        assert_eq!(events[1].1, "second");
        assert_eq!(events[2].1, "third");
        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn stream_since_replays_from_explicit_cursor_in_memory_transport() {
        let home = std::env::temp_dir().join(format!(
            "agora-stream-since-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&home).unwrap();
        let _runtime = runtime::TestRuntime::new()
            .home(&home)
            .var("AGORA_RELAY_URL", "memory://suite")
            .now(100)
            .enter();

        assert!(publish("room-b", "first"));
        let _runtime = runtime::TestRuntime::new()
            .home(&home)
            .var("AGORA_RELAY_URL", "memory://suite")
            .now(120)
            .enter();
        assert!(publish("room-b", "second"));
        let _runtime = runtime::TestRuntime::new()
            .home(&home)
            .var("AGORA_RELAY_URL", "memory://suite")
            .now(140)
            .enter();
        assert!(publish("room-b", "third"));

        let mut events = Vec::new();
        stream_since("room-b", "121", |ts, payload| {
            events.push((ts, payload.to_string()));
        });

        assert_eq!(events, vec![(140, "third".to_string())]);
        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn stream_cursor_deduplicates_only_seen_events_at_reconnect_boundary() {
        let mut cursor = StreamCursor::new(100);
        assert!(cursor.should_emit(100, Some("a"), "first"));
        assert!(cursor.should_emit(100, Some("b"), "second"));
        assert!(!cursor.should_emit(100, Some("a"), "first"));
        assert!(cursor.should_emit(101, Some("c"), "third"));
        assert!(!cursor.should_emit(100, Some("b"), "second"));
    }
}
