//! Agora transport layer — ntfy relay.
//!
//! E2E encrypted before hitting the wire. The relay only sees ciphertext.
//! Transport is pluggable — swap this module for WebSocket, Redis, etc.
//!
//! Relay URL is configurable:
//!   AGORA_RELAY_URL=https://ntfy.theagora.dev  (custom relay)
//!   Default: https://ntfy.theagora.dev
//!
//! Optional relay auth:
//!   AGORA_RELAY_TOKEN=...  (sent as Authorization: Bearer ...)
//!
//! Optional mirror publish:
//!   AGORA_RELAY_MIRROR=https://mirror.example  (publish to both)

#[cfg(not(test))]
use serde::Deserialize;

use crate::runtime;
use std::collections::HashSet;
use std::time::Duration;

#[cfg(not(test))]
use std::sync::{Condvar, Mutex, OnceLock};
#[cfg(not(test))]
use std::time::Instant;

const DEFAULT_RELAY: &str = "https://ntfy.theagora.dev";

#[cfg(test)]
type TestRelayStore = std::collections::HashMap<(String, String), Vec<(u64, String)>>;

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
struct StreamCursor {
    since_ts: u64,
    seen_at_since: HashSet<StreamReplayKey>,
}

impl StreamCursor {
    fn new(since_ts: u64) -> Self {
        Self {
            since_ts,
            seen_at_since: HashSet::new(),
        }
    }

    #[cfg(not(test))]
    fn reconnect_since(&self) -> String {
        self.since_ts.to_string()
    }

    fn should_emit(&mut self, ts: u64, id: Option<&str>, payload: &str) -> bool {
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

fn relay_url() -> String {
    runtime::var("AGORA_RELAY_URL").unwrap_or_else(|| DEFAULT_RELAY.to_string())
}

fn relay_token() -> Option<String> {
    runtime::var("AGORA_RELAY_TOKEN")
}

#[cfg(not(test))]
fn apply_auth(builder: reqwest::blocking::RequestBuilder) -> reqwest::blocking::RequestBuilder {
    if let Some(token) = relay_token() {
        builder.header("Authorization", format!("Bearer {token}"))
    } else {
        builder
    }
}

pub fn relay_status_label() -> String {
    format!("Relay ({})", relay_url())
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

pub fn publish_limits() -> PublishLimits {
    if relay_url() == DEFAULT_RELAY {
        PublishLimits {
            burst: Some(2),
            sustained_per_second: Some(2),
            body_max_bytes: None,
        }
    } else {
        PublishLimits {
            burst: None,
            sustained_per_second: None,
            body_max_bytes: None,
        }
    }
}

fn parse_retry_after(value: Option<&str>) -> Option<Duration> {
    value
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}

fn classify_publish_failure(status: u16, retry_after: Option<&str>, body: &str) -> PublishError {
    match status {
        429 => PublishError::RateLimited {
            retry_after: parse_retry_after(retry_after),
        },
        413 => PublishError::PayloadTooLarge { limit: None },
        401 | 403 => PublishError::Forbidden(format!("HTTP {status}: {}", body.trim())),
        400..=499 => PublishError::Forbidden(format!("HTTP {status}: {}", body.trim())),
        _ => PublishError::Network(format!("HTTP {status}: {}", body.trim())),
    }
}

fn parse_since_cutoff(since: &str, now: u64) -> u64 {
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

fn classify_stream_connect_failure(status: u16, body: &str) -> StreamDisconnect {
    let message = format!("HTTP {status}: {}", body.trim());
    match status {
        401 | 403 => StreamDisconnect::Auth(message),
        _ => StreamDisconnect::Connect(message),
    }
}

#[cfg(not(test))]
#[derive(Debug, Default)]
struct PublishGateState {
    next_allowed: Option<Instant>,
    in_flight: usize,
}

#[cfg(not(test))]
fn publish_gate() -> &'static (Mutex<PublishGateState>, Condvar) {
    static GATE: OnceLock<(Mutex<PublishGateState>, Condvar)> = OnceLock::new();
    GATE.get_or_init(|| (Mutex::new(PublishGateState::default()), Condvar::new()))
}

#[cfg(not(test))]
struct PublishPermit;

#[cfg(not(test))]
impl Drop for PublishPermit {
    fn drop(&mut self) {
        let (lock, cvar) = publish_gate();
        let mut state = lock.lock().unwrap_or_else(|e| e.into_inner());
        state.in_flight = state.in_flight.saturating_sub(1);
        cvar.notify_one();
    }
}

#[cfg(not(test))]
fn acquire_publish_permit() -> Option<PublishPermit> {
    let limits = publish_limits();
    let max_in_flight = limits.burst.filter(|burst| *burst > 0);
    let interval = limits
        .sustained_per_second
        .filter(|rate| *rate > 0)
        .map(|rate| Duration::from_secs_f64(1.0 / rate as f64));

    if max_in_flight.is_none() && interval.is_none() {
        return None;
    }

    let (lock, cvar) = publish_gate();
    let mut state = lock.lock().unwrap_or_else(|e| e.into_inner());
    loop {
        if let Some(limit) = max_in_flight
            && state.in_flight >= limit
        {
            state = cvar.wait(state).unwrap_or_else(|e| e.into_inner());
            continue;
        }

        if let Some(interval) = interval {
            let now = Instant::now();
            if let Some(next_allowed) = state.next_allowed
                && next_allowed > now
            {
                let delay = next_allowed.duration_since(now);
                drop(state);
                runtime::sleep(delay);
                state = lock.lock().unwrap_or_else(|e| e.into_inner());
                continue;
            }
            state.next_allowed = Some(now + interval);
        }

        state.in_flight += 1;
        return Some(PublishPermit);
    }
}

#[cfg(not(test))]
#[derive(Debug, Deserialize)]
struct NtfyEvent {
    id: Option<String>,
    event: Option<String>,
    message: Option<String>,
    time: Option<u64>,
}

#[cfg(not(test))]
fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .expect("failed to build HTTP client")
}

#[cfg(not(test))]
fn streaming_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(None)
        .build()
        .expect("failed to build streaming HTTP client")
}

#[cfg(test)]
fn test_relay() -> &'static std::sync::Mutex<TestRelayStore> {
    static RELAY: std::sync::OnceLock<std::sync::Mutex<TestRelayStore>> =
        std::sync::OnceLock::new();
    RELAY.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

#[cfg(test)]
fn test_namespace() -> String {
    runtime::home_dir()
        .map(|path| path.to_string_lossy().to_string())
        .unwrap_or_else(|| "__agora_test__".to_string())
}

#[cfg(test)]
fn test_now() -> u64 {
    runtime::unix_now()
}

#[cfg(test)]
fn test_since_cutoff(since: &str) -> u64 {
    parse_since_cutoff(since, test_now())
}

#[cfg(test)]
fn test_fetch(topic: &str, since: &str) -> Vec<(u64, String)> {
    let cutoff = test_since_cutoff(since);
    let relay = test_relay().lock().unwrap_or_else(|e| e.into_inner());
    relay
        .get(&(test_namespace(), topic.to_string()))
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|(ts, _)| *ts >= cutoff)
        .collect()
}

/// Publish an encrypted payload to the relay topic.
/// Also publishes to the mirror if AGORA_RELAY_MIRROR is set.
pub fn publish(topic: &str, payload: &str) -> bool {
    publish_detailed(topic, payload).is_ok()
}

/// Publish an encrypted payload to the relay topic with typed error reporting.
/// Also publishes to the mirror if AGORA_RELAY_MIRROR is set.
pub fn publish_detailed(topic: &str, payload: &str) -> Result<(), PublishError> {
    #[cfg(test)]
    {
        let mut relay = test_relay().lock().unwrap_or_else(|e| e.into_inner());
        relay
            .entry((test_namespace(), topic.to_string()))
            .or_default()
            .push((test_now(), payload.to_string()));
        Ok(())
    }

    #[cfg(not(test))]
    {
        let _permit = acquire_publish_permit();
        let base = relay_url();
        let url = format!("{base}/{topic}");
        let result = match apply_auth(client().post(&url))
            .body(payload.to_string())
            .send()
        {
            Ok(resp) if resp.status().is_success() => Ok(()),
            Ok(resp) => {
                let status = resp.status().as_u16();
                let retry_after = resp
                    .headers()
                    .get("retry-after")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string);
                let body = resp.text().unwrap_or_default();
                Err(classify_publish_failure(
                    status,
                    retry_after.as_deref(),
                    &body,
                ))
            }
            Err(e) => {
                eprintln!("  [warn] relay publish failed: {e}");
                Err(PublishError::Network(e.to_string()))
            }
        };

        // Dual-publish when an explicit mirror is configured.
        if let Some(mirror) = mirror_url() {
            let mirror_url = format!("{mirror}/{topic}");
            let _ = apply_auth(client().post(&mirror_url))
                .body(payload.to_string())
                .send();
        }

        result
    }
}

/// Fetch recent messages from the relay topic.
/// Falls back to mirror relay if primary fails.
/// Returns vec of (timestamp, raw_payload).
pub fn fetch(topic: &str, since: &str) -> Vec<(u64, String)> {
    #[cfg(test)]
    {
        test_fetch(topic, since)
    }

    #[cfg(not(test))]
    {
        let base = relay_url();
        let url = format!("{base}/{topic}/json?poll=1&since={since}");
        let body = match apply_auth(client().get(&url)).send() {
            Ok(resp) => resp.text().unwrap_or_default(),
            Err(e) => {
                eprintln!("  [warn] primary relay fetch failed: {e}");
                String::new()
            }
        };

        // Failover: if primary returned nothing, try mirror
        let body = if body.trim().is_empty() || !body.contains("message") {
            if let Some(mirror) = mirror_url() {
                let mirror_url = format!("{mirror}/{topic}/json?poll=1&since={since}");
                match client().get(&mirror_url).send() {
                    Ok(resp) => resp.text().unwrap_or(body),
                    Err(_) => body,
                }
            } else {
                body
            }
        } else {
            body
        };

        let mut events = Vec::new();
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(evt) = serde_json::from_str::<NtfyEvent>(line)
                && evt.event.as_deref() == Some("message")
                && let Some(msg) = evt.message
            {
                events.push((evt.time.unwrap_or(0), msg));
            }
        }

        events
    }
}

/// Open a streaming SSE connection to the relay topic.
/// Calls `on_message(timestamp, raw_payload)` for each message.
/// Blocks forever. Returns on connection error.
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

/// Open a streaming SSE connection with reconnect/backoff configuration.
pub fn stream_with_config<F, G>(topic: &str, config: &StreamConfig, on_message: F, on_disconnect: G)
where
    F: FnMut(u64, &str),
    G: FnMut(StreamDisconnect, Option<Duration>),
{
    stream_from_cursor_with_config(topic, None, config, on_message, on_disconnect);
}

/// Open a streaming SSE connection with reconnect/backoff configuration and an
/// explicit initial catchup cursor.
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
    on_disconnect: G,
) where
    F: FnMut(u64, &str),
    G: FnMut(StreamDisconnect, Option<Duration>),
{
    #[cfg(test)]
    {
        let _ = config;
        let _ = on_disconnect;
        for (ts, payload) in test_fetch(topic, initial_since.unwrap_or("0")) {
            on_message(ts, &payload);
        }
    }

    #[cfg(not(test))]
    {
        let mut cursor = match initial_since {
            Some(since) => Some(StreamCursor::new(parse_since_cutoff(
                since,
                runtime::unix_now(),
            ))),
            None if config.reconnect => Some(StreamCursor::new(runtime::unix_now())),
            None => None,
        };
        let mut on_disconnect = on_disconnect;
        let mut backoff = config.initial_backoff;
        let mut first_request = true;
        loop {
            let base = relay_url();
            let request_since = if first_request {
                initial_since.map(str::to_string)
            } else {
                cursor.as_ref().map(StreamCursor::reconnect_since)
            };
            first_request = false;
            let url = match request_since.as_deref() {
                Some(since) => format!("{base}/{topic}/json?since={since}"),
                None => format!("{base}/{topic}/json"),
            };
            let resp = match apply_auth(streaming_client().get(&url)).send() {
                Ok(r) if r.status().is_success() => {
                    backoff = config.initial_backoff;
                    r
                }
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let body = resp.text().unwrap_or_default();
                    let error = classify_stream_connect_failure(status, &body);
                    if matches!(error, StreamDisconnect::Auth(_)) || !config.reconnect {
                        on_disconnect(error, None);
                        return;
                    }
                    on_disconnect(error, Some(backoff));
                    runtime::sleep(backoff);
                    backoff = std::cmp::min(backoff.saturating_mul(2), config.max_backoff);
                    continue;
                }
                Err(e) => {
                    let error = StreamDisconnect::Connect(e.to_string());
                    if !config.reconnect {
                        on_disconnect(error, None);
                        return;
                    }
                    on_disconnect(error, Some(backoff));
                    runtime::sleep(backoff);
                    backoff = std::cmp::min(backoff.saturating_mul(2), config.max_backoff);
                    continue;
                }
            };

            let reader = std::io::BufReader::new(resp);
            use std::io::BufRead;
            let mut disconnect = StreamDisconnect::Read("stream ended".to_string());
            for line in reader.lines() {
                let line = match line {
                    Ok(l) => l,
                    Err(e) => {
                        disconnect = StreamDisconnect::Read(e.to_string());
                        break;
                    }
                };
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                if let Ok(evt) = serde_json::from_str::<NtfyEvent>(&line)
                    && evt.event.as_deref() == Some("message")
                    && let Some(ref msg) = evt.message
                {
                    let ts = evt.time.unwrap_or(0);
                    let should_emit = match cursor.as_mut() {
                        Some(cursor) => cursor.should_emit(ts, evt.id.as_deref(), msg),
                        None => true,
                    };
                    if should_emit {
                        on_message(ts, msg);
                    }
                }
            }
            if !config.reconnect {
                on_disconnect(disconnect, None);
                return;
            }
            on_disconnect(disconnect, Some(backoff));
            runtime::sleep(backoff);
            backoff = std::cmp::min(backoff.saturating_mul(2), config.max_backoff);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_RELAY, PublishError, StreamConfig, StreamCursor, StreamDisconnect,
        classify_publish_failure, classify_stream_connect_failure, fetch, mirror_url, publish,
        publish_detailed, publish_limits, relay_status_label, relay_token, relay_url, stream_since,
    };
    use crate::runtime;
    use std::time::Duration;

    #[test]
    fn relay_url_defaults_to_ntfy() {
        let _runtime = runtime::TestRuntime::new()
            .unset_var("AGORA_RELAY_URL")
            .enter();

        assert_eq!(relay_url(), DEFAULT_RELAY);
    }

    #[test]
    fn relay_url_uses_env_override() {
        let _runtime = runtime::TestRuntime::new()
            .var("AGORA_RELAY_URL", "https://ntfy.theagora.dev")
            .enter();

        assert_eq!(relay_url(), "https://ntfy.theagora.dev");
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
            .var("AGORA_RELAY_URL", "https://ntfy.theagora.dev")
            .enter();

        assert_eq!(relay_status_label(), "Relay (https://ntfy.theagora.dev)");
    }

    #[test]
    fn publish_limits_default_relay_are_conservative() {
        let _runtime = runtime::TestRuntime::new()
            .unset_var("AGORA_RELAY_URL")
            .enter();
        assert_eq!(
            publish_limits(),
            super::PublishLimits {
                burst: Some(2),
                sustained_per_second: Some(2),
                body_max_bytes: None,
            }
        );
    }

    #[test]
    fn publish_limits_custom_relay_are_unknown() {
        let _runtime = runtime::TestRuntime::new()
            .var("AGORA_RELAY_URL", "https://relay.example")
            .enter();
        assert_eq!(
            publish_limits(),
            super::PublishLimits {
                burst: None,
                sustained_per_second: None,
                body_max_bytes: None,
            }
        );
    }

    #[test]
    fn classify_publish_failure_maps_rate_limit() {
        assert_eq!(
            classify_publish_failure(429, Some("7"), "slow down"),
            PublishError::RateLimited {
                retry_after: Some(Duration::from_secs(7))
            }
        );
    }

    #[test]
    fn classify_publish_failure_maps_payload_too_large() {
        assert_eq!(
            classify_publish_failure(413, None, "too large"),
            PublishError::PayloadTooLarge { limit: None }
        );
    }

    #[test]
    fn classify_publish_failure_maps_forbidden() {
        assert_eq!(
            classify_publish_failure(403, None, "blocked"),
            PublishError::Forbidden("HTTP 403: blocked".to_string())
        );
    }

    #[test]
    fn classify_stream_connect_failure_maps_auth() {
        assert_eq!(
            classify_stream_connect_failure(403, "blocked"),
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
    fn publish_and_fetch_use_in_memory_relay_in_tests() {
        let home = std::env::temp_dir().join(format!(
            "agora-transport-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&home).unwrap();
        let _runtime = runtime::TestRuntime::new().home(&home).enter();

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
    fn stream_since_replays_from_explicit_cursor_in_tests() {
        let home = std::env::temp_dir().join(format!(
            "agora-stream-since-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&home).unwrap();
        let _runtime = runtime::TestRuntime::new().home(&home).now(100).enter();

        assert!(publish("room-b", "first"));
        let _runtime = runtime::TestRuntime::new().home(&home).now(120).enter();
        assert!(publish("room-b", "second"));
        let _runtime = runtime::TestRuntime::new().home(&home).now(140).enter();
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
