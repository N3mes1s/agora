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
//! Dual-publish for zero-downtime migration:
//!   AGORA_RELAY_MIRROR=https://ntfy.sh  (publish to both during transition)

#[cfg(not(test))]
use serde::Deserialize;

use crate::runtime;

const DEFAULT_RELAY: &str = "https://ntfy.theagora.dev";

#[cfg(test)]
type TestRelayStore = std::collections::HashMap<(String, String), Vec<(u64, String)>>;

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
    // During migration: dual-publish to ntfy.sh for agents not yet upgraded
    match runtime::var("AGORA_RELAY_MIRROR") {
        Some(value) => {
            let value = value.trim();
            if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            }
        }
        None => {
            if relay_url().contains("theagora.dev") {
                Some("https://ntfy.sh".to_string())
            } else {
                None
            }
        }
    }
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
    #[cfg(test)]
    {
        let mut relay = test_relay().lock().unwrap_or_else(|e| e.into_inner());
        relay
            .entry((test_namespace(), topic.to_string()))
            .or_default()
            .push((test_now(), payload.to_string()));
        true
    }

    #[cfg(not(test))]
    {
        let base = relay_url();
        let url = format!("{base}/{topic}");
        let ok = match apply_auth(client().post(&url))
            .body(payload.to_string())
            .send()
        {
            Ok(resp) => resp.status().is_success(),
            Err(e) => {
                eprintln!("  [warn] relay publish failed: {e}");
                false
            }
        };

        // Dual-publish to mirror for zero-downtime migration
        if let Some(mirror) = mirror_url() {
            let mirror_url = format!("{mirror}/{topic}");
            let _ = apply_auth(client().post(&mirror_url))
                .body(payload.to_string())
                .send();
        }

        ok
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
    #[cfg(test)]
    {
        for (ts, payload) in test_fetch(topic, "0") {
            on_message(ts, &payload);
        }
    }

    #[cfg(not(test))]
    {
        let base = relay_url();
        let url = format!("{base}/{topic}/json");
        let resp = match apply_auth(streaming_client().get(&url)).send() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("  [error] stream connect failed: {e}");
                return;
            }
        };

        let reader = std::io::BufReader::new(resp);
        use std::io::BufRead;
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
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
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_RELAY, fetch, mirror_url, publish, relay_status_label, relay_token, relay_url,
    };
    use crate::runtime;

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

        assert_eq!(mirror_url(), Some("https://ntfy.sh".to_string()));
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

        let events = fetch("room-a", "1h");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].1, "first");
        assert_eq!(events[1].1, "second");
        let _ = std::fs::remove_dir_all(home);
    }
}
