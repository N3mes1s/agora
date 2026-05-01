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
use std::time::Duration;

#[cfg(not(test))]
use std::sync::{Mutex, OnceLock};
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
    Connect(String),
    Read(String),
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
            burst: Some(4),
            sustained_per_second: Some(4),
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

#[cfg(not(test))]
fn publish_gate() -> &'static Mutex<Option<Instant>> {
    static GATE: OnceLock<Mutex<Option<Instant>>> = OnceLock::new();
    GATE.get_or_init(|| Mutex::new(None))
}

#[cfg(not(test))]
fn maybe_throttle_publish() {
    let Some(rate) = publish_limits().sustained_per_second else {
        return;
    };
    if rate == 0 {
        return;
    }
    let interval = Duration::from_secs_f64(1.0 / rate as f64);
    let mut gate = publish_gate().lock().unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();
    if let Some(next_allowed) = *gate
        && next_allowed > now
    {
        runtime::sleep(next_allowed.duration_since(now));
    }
    *gate = Some(Instant::now() + interval);
}

#[cfg(not(test))]
#[derive(Debug, Deserialize)]
struct NtfyEvent {
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
    let now = test_now();
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
        maybe_throttle_publish();
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

/// Open a streaming SSE connection with reconnect/backoff configuration.
pub fn stream_with_config<F, G>(
    topic: &str,
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
        for (ts, payload) in test_fetch(topic, "0") {
            on_message(ts, &payload);
        }
    }

    #[cfg(not(test))]
    {
        let mut on_disconnect = on_disconnect;
        let mut backoff = config.initial_backoff;
        loop {
            let base = relay_url();
            let url = format!("{base}/{topic}/json");
            let resp = match apply_auth(streaming_client().get(&url)).send() {
                Ok(r) => {
                    backoff = config.initial_backoff;
                    r
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
                    on_message(evt.time.unwrap_or(0), msg);
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
        DEFAULT_RELAY, PublishError, StreamConfig, classify_publish_failure, fetch, mirror_url,
        publish, publish_detailed, publish_limits, relay_status_label, relay_token, relay_url,
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
                burst: Some(4),
                sustained_per_second: Some(4),
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
}
