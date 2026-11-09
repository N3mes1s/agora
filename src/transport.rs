//! Agora transport layer.
//!
//! E2E encrypted before hitting the wire. The relay only sees ciphertext.
//! The backend is selected by URL scheme at runtime. There is **no default
//! relay**: it must be configured in `~/.agora/config.toml` (`relay_url`,
//! `relay_token`, `mirror`, `local_only`) or via environment overrides,
//! otherwise every relay operation fails closed (see [`crate::config`]).
//!
//!   relay_url = "nats://127.0.0.1:4222"     (NATS + JetStream, recommended)
//!   relay_url = "http://127.0.0.1:2586"     (self-hosted ntfy)
//!   AGORA_RELAY_URL=memory://test-suite     (in-memory test relay)
//!
//! Relay auth: `relay_token` / AGORA_RELAY_TOKEN (ntfy bearer or NATS token).
//! Optional ntfy mirror publish: `mirror` / AGORA_RELAY_MIRROR.

mod memory;
mod nats;
mod ntfy;

use crate::config;
use std::collections::HashSet;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishError {
    RateLimited {
        retry_after: Option<Duration>,
    },
    PayloadTooLarge {
        limit: Option<u64>,
    },
    Forbidden(String),
    Network(String),
    /// No usable relay configuration (unset, or refused by `local_only`).
    NotConfigured(String),
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
            Self::NotConfigured(message) => write!(f, "relay not configured: {message}"),
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
    /// Treat the subscription as dead when nothing at all (a message, or for ntfy a keepalive line)
    /// has arrived for this long, and reopen it (with `reconnect`) from the cursor. None: wait forever.
    pub idle_timeout: Option<Duration>,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            reconnect: false,
            initial_backoff: Duration::from_secs(5),
            max_backoff: Duration::from_secs(30),
            idle_timeout: None,
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
    /// Resolve the relay configuration, failing closed when no relay is
    /// configured or when `local_only` refuses the configured host.
    fn current() -> Result<Self, String> {
        let settings = config::relay_settings();
        #[cfg(test)]
        let settings = {
            // Unit tests must never touch a real relay: default to memory.
            let mut settings = settings;
            if settings.url.is_none() && crate::runtime::var("AGORA_TEST_REQUIRE_RELAY").is_none() {
                settings.url = Some("memory://unit-tests".to_string());
            }
            settings
        };
        let relay_url = config::validate_relay(&settings)?;
        Ok(Self {
            relay_url,
            relay_token: settings.token,
            relay_mirror: settings.mirror,
        })
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
    fn fetch(&self, config: &TransportConfig, topic: &str, since: &str) -> Vec<(u64, String)> {
        match self.fetch_checked(config, topic, since) {
            Ok(events) => events,
            Err(err) => {
                crate::elog!("  [warn] relay fetch failed: {err}");
                Vec::new()
            }
        }
    }
    fn fetch_checked(
        &self,
        config: &TransportConfig,
        topic: &str,
        since: &str,
    ) -> Result<Vec<(u64, String)>, String>;
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

#[cfg(test)]
fn relay_url() -> String {
    TransportConfig::current()
        .map(|config| config.relay_url)
        .unwrap_or_default()
}

#[cfg(test)]
fn relay_token() -> Option<String> {
    config::relay_settings().token
}

#[cfg(test)]
fn mirror_url() -> Option<String> {
    config::relay_settings().mirror
}

/// Return `Ok(relay_url)` when a usable relay is configured, otherwise a clear
/// error explaining how to configure one. Call this before relay operations
/// whose silent failure would mislead the user (send, read, leases, ...).
pub fn require_relay() -> Result<String, String> {
    TransportConfig::current()
        .map(|config| config.relay_url)
        .map_err(|e| format!("relay unavailable: {e}"))
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

fn with_transport<R>(
    f: impl FnOnce(&dyn Transport, &TransportConfig) -> R,
    not_configured: impl FnOnce(String) -> R,
) -> R {
    let config = match TransportConfig::current() {
        Ok(config) => config,
        Err(err) => return not_configured(err),
    };
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
    with_transport(
        |transport, config| transport.relay_status_label(config),
        |err| format!("Relay (not configured: {err})"),
    )
}

pub fn publish_limits() -> PublishLimits {
    with_transport(
        |transport, config| transport.publish_limits(config),
        |_| PublishLimits {
            burst: None,
            sustained_per_second: None,
            body_max_bytes: None,
        },
    )
}

/// Publish an encrypted payload to the configured relay topic.
pub fn publish(topic: &str, payload: &str) -> bool {
    publish_detailed(topic, payload).is_ok()
}

/// Publish an encrypted payload to the configured relay topic with typed error reporting.
pub fn publish_detailed(topic: &str, payload: &str) -> Result<(), PublishError> {
    with_transport(
        |transport, config| transport.publish(config, topic, payload),
        |err| Err(PublishError::NotConfigured(err)),
    )
}

/// Publish and map any failure to a human-readable error string.
pub fn publish_checked(topic: &str, payload: &str) -> Result<(), String> {
    publish_with_retry(topic, payload).map_err(|e| e.to_string())
}

/// Publish with retry + exponential backoff on `PublishError::Network`.
/// Max 3 retries with 100ms / 200ms / 400ms backoff.
pub fn publish_with_retry(topic: &str, payload: &str) -> Result<(), PublishError> {
    let backoffs = [
        Duration::from_millis(100),
        Duration::from_millis(200),
        Duration::from_millis(400),
    ];
    let mut last_err = None;
    for attempt in 0..=backoffs.len() {
        match publish_detailed(topic, payload) {
            Ok(()) => return Ok(()),
            Err(e @ PublishError::Network(_)) => {
                last_err = Some(e);
                if attempt < backoffs.len() {
                    std::thread::sleep(backoffs[attempt]);
                }
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_err.unwrap_or_else(|| PublishError::Network("retry exhausted".to_string())))
}

/// Fetch recent messages from the configured relay topic.
pub fn fetch(topic: &str, since: &str) -> Vec<(u64, String)> {
    with_transport(
        |transport, config| transport.fetch(config, topic, since),
        |err| {
            crate::elog!("  [warn] relay not configured: {err}");
            Vec::new()
        },
    )
}

/// Fetch recent messages, returning an error when the relay is unconfigured
/// or unreachable (instead of an indistinguishable empty list).
pub fn fetch_checked(topic: &str, since: &str) -> Result<Vec<(u64, String)>, String> {
    with_transport(
        |transport, config| transport.fetch_checked(config, topic, since),
        |err| Err(format!("relay not configured: {err}")),
    )
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
    let failed = with_transport(
        |transport, transport_config| {
            transport.stream(
                transport_config,
                topic,
                initial_since,
                config,
                &mut on_message,
                &mut on_disconnect,
            );
            None
        },
        Some,
    );
    if let Some(err) = failed {
        on_disconnect(
            StreamDisconnect::Connect(format!("relay not configured: {err}")),
            None,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PublishError, PublishLimits, StreamConfig, StreamCursor, StreamDisconnect, TransportConfig,
        TransportKind, fetch, fetch_checked, mirror_url, ntfy, publish, publish_detailed,
        publish_limits, relay_status_label, relay_token, relay_url, require_relay, stream_since,
    };
    use crate::runtime;
    use std::time::Duration;

    fn empty_home(tag: &str) -> std::path::PathBuf {
        let home = std::env::temp_dir().join(format!(
            "agora-transport-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&home).unwrap();
        home
    }

    #[test]
    fn unconfigured_relay_fails_closed() {
        let home = empty_home("unconfigured");
        let _runtime = runtime::TestRuntime::new()
            .var("AGORA_CONFIG", "/nonexistent/agora-test-config.toml")
            .home(&home)
            .unset_var("AGORA_CONFIG")
            .unset_var("AGORA_RELAY_URL")
            .var("AGORA_TEST_REQUIRE_RELAY", "1")
            .enter();

        assert!(TransportConfig::current().is_err());
        let err = require_relay().unwrap_err();
        assert!(err.contains("no relay configured"), "{err}");
        assert!(matches!(
            publish_detailed("room-x", "payload"),
            Err(PublishError::NotConfigured(_))
        ));
        assert!(fetch_checked("room-x", "1h").is_err());
        assert!(relay_status_label().contains("not configured"));
        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn public_relay_is_refused_by_default() {
        let home = empty_home("public");
        let _runtime = runtime::TestRuntime::new()
            .var("AGORA_CONFIG", "/nonexistent/agora-test-config.toml")
            .home(&home)
            .unset_var("AGORA_CONFIG")
            .unset_var("AGORA_LOCAL_ONLY")
            .var("AGORA_RELAY_URL", "https://ntfy.theagora.dev")
            .enter();
        let err = require_relay().unwrap_err();
        assert!(err.contains("not a local/private host"), "{err}");
        assert!(!publish("room-x", "payload"));
        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn relay_url_from_config_file() {
        let home = empty_home("configfile");
        std::fs::create_dir_all(home.join(".agora")).unwrap();
        std::fs::write(
            home.join(".agora/config.toml"),
            "relay_url = \"http://127.0.0.1:2586\"\n",
        )
        .unwrap();
        let _runtime = runtime::TestRuntime::new()
            .var("AGORA_CONFIG", "/nonexistent/agora-test-config.toml")
            .home(&home)
            .unset_var("AGORA_CONFIG")
            .unset_var("AGORA_RELAY_URL")
            .unset_var("AGORA_LOCAL_ONLY")
            .enter();
        assert_eq!(relay_url(), "http://127.0.0.1:2586");
        assert_eq!(
            TransportConfig::current().unwrap().kind(),
            TransportKind::Ntfy
        );
        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn relay_url_uses_nats_scheme_override() {
        let _runtime = runtime::TestRuntime::new()
            .var("AGORA_CONFIG", "/nonexistent/agora-test-config.toml")
            .var("AGORA_RELAY_URL", "nats://127.0.0.1:4222")
            .enter();

        assert_eq!(relay_url(), "nats://127.0.0.1:4222");
        assert_eq!(
            TransportConfig::current().unwrap().kind(),
            TransportKind::Nats
        );
    }

    #[test]
    fn relay_url_uses_memory_scheme_override() {
        let _runtime = runtime::TestRuntime::new()
            .var("AGORA_CONFIG", "/nonexistent/agora-test-config.toml")
            .var("AGORA_RELAY_URL", "memory://suite")
            .enter();

        assert_eq!(
            TransportConfig::current().unwrap().kind(),
            TransportKind::Memory
        );
    }

    #[test]
    fn mirror_url_uses_default_when_env_is_unset() {
        let _runtime = runtime::TestRuntime::new()
            .var("AGORA_CONFIG", "/nonexistent/agora-test-config.toml")
            .unset_var("AGORA_RELAY_MIRROR")
            .enter();

        assert_eq!(mirror_url(), None);
    }

    #[test]
    fn mirror_url_can_be_disabled_with_empty_env() {
        let _runtime = runtime::TestRuntime::new()
            .var("AGORA_CONFIG", "/nonexistent/agora-test-config.toml")
            .var("AGORA_RELAY_MIRROR", "")
            .enter();

        assert_eq!(mirror_url(), None);
    }

    #[test]
    fn mirror_url_can_be_disabled_with_whitespace_env() {
        let _runtime = runtime::TestRuntime::new()
            .var("AGORA_CONFIG", "/nonexistent/agora-test-config.toml")
            .var("AGORA_RELAY_MIRROR", "  \t  ")
            .enter();

        assert_eq!(mirror_url(), None);
    }

    #[test]
    fn mirror_url_uses_explicit_override() {
        let _runtime = runtime::TestRuntime::new()
            .var("AGORA_CONFIG", "/nonexistent/agora-test-config.toml")
            .var("AGORA_RELAY_MIRROR", "https://mirror.example")
            .enter();

        assert_eq!(mirror_url(), Some("https://mirror.example".to_string()));
    }

    #[test]
    fn relay_token_is_optional() {
        let _runtime = runtime::TestRuntime::new()
            .var("AGORA_CONFIG", "/nonexistent/agora-test-config.toml")
            .unset_var("AGORA_RELAY_TOKEN")
            .enter();
        assert_eq!(relay_token(), None);

        let _runtime = runtime::TestRuntime::new()
            .var("AGORA_CONFIG", "/nonexistent/agora-test-config.toml")
            .var("AGORA_RELAY_TOKEN", "relay-secret")
            .enter();
        assert_eq!(relay_token(), Some("relay-secret".to_string()));
    }

    #[test]
    fn relay_status_label_reflects_override() {
        let _runtime = runtime::TestRuntime::new()
            .var("AGORA_CONFIG", "/nonexistent/agora-test-config.toml")
            .var("AGORA_RELAY_URL", "nats://127.0.0.1:4222")
            .unset_var("AGORA_NATS_STREAM")
            .unset_var("AGORA_NATS_SUBJECT_PREFIX")
            .enter();

        assert_eq!(
            relay_status_label(),
            "Relay (nats://127.0.0.1:4222 stream=AGORA subjects=agora.>)"
        );
    }

    #[test]
    fn publish_limits_custom_relays_are_unknown() {
        let _runtime = runtime::TestRuntime::new()
            .var("AGORA_CONFIG", "/nonexistent/agora-test-config.toml")
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
                idle_timeout: None,
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
            .var("AGORA_CONFIG", "/nonexistent/agora-test-config.toml")
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
            .var("AGORA_CONFIG", "/nonexistent/agora-test-config.toml")
            .home(&home)
            .var("AGORA_RELAY_URL", "memory://suite")
            .now(100)
            .enter();

        assert!(publish("room-b", "first"));
        let _runtime = runtime::TestRuntime::new()
            .var("AGORA_CONFIG", "/nonexistent/agora-test-config.toml")
            .home(&home)
            .var("AGORA_RELAY_URL", "memory://suite")
            .now(120)
            .enter();
        assert!(publish("room-b", "second"));
        let _runtime = runtime::TestRuntime::new()
            .var("AGORA_CONFIG", "/nonexistent/agora-test-config.toml")
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
