//! Agora transport layer — ntfy relay.
//!
//! E2E encrypted before hitting the wire. The relay only sees ciphertext.
//! Transport is pluggable — swap this module for WebSocket, Redis, etc.
//!
//! Relay URL is configurable:
//!   AGORA_RELAY_URL=https://ntfy.theagora.dev  (custom relay)
//!   Default: https://ntfy.sh
//!
//! Optional relay auth:
//!   AGORA_RELAY_TOKEN=...  (sent as Authorization: Bearer ...)
//!
//! Dual-publish for zero-downtime migration:
//!   AGORA_RELAY_MIRROR=https://ntfy.sh  (publish to both during transition)

use serde::Deserialize;

const DEFAULT_RELAY: &str = "https://ntfy.theagora.dev";

fn relay_url() -> String {
    std::env::var("AGORA_RELAY_URL").unwrap_or_else(|_| DEFAULT_RELAY.to_string())
}

fn relay_token() -> Option<String> {
    std::env::var("AGORA_RELAY_TOKEN").ok()
}

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
    std::env::var("AGORA_RELAY_MIRROR").ok().or_else(|| {
        if relay_url().contains("theagora.dev") {
            Some("https://ntfy.sh".to_string())
        } else {
            None
        }
    })
}

#[derive(Debug, Deserialize)]
struct NtfyEvent {
    event: Option<String>,
    message: Option<String>,
    time: Option<u64>,
}

fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .expect("failed to build HTTP client")
}

fn streaming_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(None)
        .build()
        .expect("failed to build streaming HTTP client")
}

/// Publish an encrypted payload to the relay topic.
/// Also publishes to the mirror if AGORA_RELAY_MIRROR is set.
pub fn publish(topic: &str, payload: &str) -> bool {
    let base = relay_url();
    let url = format!("{base}/{topic}");
    let ok = match apply_auth(client().post(&url)).body(payload.to_string()).send() {
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

/// Fetch recent messages from the relay topic.
/// Falls back to mirror relay if primary fails.
/// Returns vec of (timestamp, raw_payload).
pub fn fetch(topic: &str, since: &str) -> Vec<(u64, String)> {
    let base = relay_url();
    let url = format!("{base}/{topic}/json?poll=1&since={since}");
    let body = match apply_auth(client().get(&url)).send() {
        Ok(resp) => match resp.text() {
            Ok(s) => s,
            Err(_) => String::new(),
        },
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
        if let Ok(evt) = serde_json::from_str::<NtfyEvent>(line) {
            if evt.event.as_deref() == Some("message") {
                if let Some(msg) = evt.message {
                    events.push((evt.time.unwrap_or(0), msg));
                }
            }
        }
    }
    events
}

/// Open a streaming SSE connection to the relay topic.
/// Calls `on_message(timestamp, raw_payload)` for each message.
/// Blocks forever. Returns on connection error.
pub fn stream<F>(topic: &str, mut on_message: F)
where
    F: FnMut(u64, &str),
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
        if let Ok(evt) = serde_json::from_str::<NtfyEvent>(&line) {
            if evt.event.as_deref() == Some("message") {
                if let Some(ref msg) = evt.message {
                    on_message(evt.time.unwrap_or(0), msg);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{mirror_url, relay_status_label, relay_token, relay_url, DEFAULT_RELAY};
    use crate::store;

    fn restore_env(name: &str, value: Option<String>) {
        match value {
            Some(value) => unsafe { std::env::set_var(name, value) },
            None => unsafe { std::env::remove_var(name) },
        }
    }

    #[test]
    fn relay_url_defaults_to_ntfy() {
        let _guard = store::test_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var("AGORA_RELAY_URL").ok();
        unsafe { std::env::remove_var("AGORA_RELAY_URL") };

        assert_eq!(relay_url(), DEFAULT_RELAY);

        restore_env("AGORA_RELAY_URL", prior);
    }

    #[test]
    fn relay_url_uses_env_override() {
        let _guard = store::test_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var("AGORA_RELAY_URL").ok();
        unsafe { std::env::set_var("AGORA_RELAY_URL", "https://ntfy.theagora.dev") };

        assert_eq!(relay_url(), "https://ntfy.theagora.dev");

        restore_env("AGORA_RELAY_URL", prior);
    }

    #[test]
    fn mirror_url_is_optional() {
        let _guard = store::test_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var("AGORA_RELAY_MIRROR").ok();
        unsafe { std::env::remove_var("AGORA_RELAY_MIRROR") };
        // Auto-mirror to ntfy.sh when using theagora.dev relay
        let m = mirror_url();
        assert!(m.is_none() || m == Some("https://ntfy.sh".to_string()));

        unsafe { std::env::set_var("AGORA_RELAY_MIRROR", "https://ntfy.sh") };
        assert_eq!(mirror_url(), Some("https://ntfy.sh".to_string()));

        restore_env("AGORA_RELAY_MIRROR", prior);
    }

    #[test]
    fn relay_token_is_optional() {
        let _guard = store::test_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var("AGORA_RELAY_TOKEN").ok();
        unsafe { std::env::remove_var("AGORA_RELAY_TOKEN") };
        assert_eq!(relay_token(), None);

        unsafe { std::env::set_var("AGORA_RELAY_TOKEN", "relay-secret") };
        assert_eq!(relay_token(), Some("relay-secret".to_string()));

        restore_env("AGORA_RELAY_TOKEN", prior);
    }

    #[test]
    fn relay_status_label_reflects_override() {
        let _guard = store::test_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var("AGORA_RELAY_URL").ok();
        unsafe { std::env::set_var("AGORA_RELAY_URL", "https://ntfy.theagora.dev") };

        assert_eq!(
            relay_status_label(),
            "Relay (https://ntfy.theagora.dev)"
        );

        restore_env("AGORA_RELAY_URL", prior);
    }
}
