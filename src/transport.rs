//! Agora transport layer — ntfy relay.
//!
//! E2E encrypted before hitting the wire. The relay only sees ciphertext.
//! Transport is pluggable — swap this module for WebSocket, Redis, etc.
//!
//! Relay URL is configurable:
//!   AGORA_RELAY_URL=https://ntfy.theagora.dev  (custom relay)
//!   Default: https://ntfy.sh
//!
//! Dual-publish for zero-downtime migration:
//!   AGORA_RELAY_MIRROR=https://ntfy.sh  (publish to both during transition)

use serde::Deserialize;

const DEFAULT_RELAY: &str = "https://ntfy.sh";

fn relay_url() -> String {
    std::env::var("AGORA_RELAY_URL").unwrap_or_else(|_| DEFAULT_RELAY.to_string())
}

fn mirror_url() -> Option<String> {
    std::env::var("AGORA_RELAY_MIRROR").ok()
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
    let ok = match client().post(&url).body(payload.to_string()).send() {
        Ok(resp) => resp.status().is_success(),
        Err(e) => {
            eprintln!("  [warn] relay publish failed: {e}");
            false
        }
    };

    // Dual-publish to mirror for zero-downtime migration
    if let Some(mirror) = mirror_url() {
        let mirror_url = format!("{mirror}/{topic}");
        let _ = client().post(&mirror_url).body(payload.to_string()).send();
    }

    ok
}

/// Fetch recent messages from the relay topic.
/// Returns vec of (timestamp, raw_payload).
pub fn fetch(topic: &str, since: &str) -> Vec<(u64, String)> {
    let base = relay_url();
    let url = format!("{base}/{topic}/json?poll=1&since={since}");
    let body = match client().get(&url).send() {
        Ok(resp) => match resp.text() {
            Ok(s) => s,
            Err(_) => return vec![],
        },
        Err(_) => return vec![],
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
    let resp = match streaming_client().get(&url).send() {
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
