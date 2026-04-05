//! Agora transport layer — ntfy.sh relay.
//!
//! E2E encrypted before hitting the wire. ntfy.sh only sees ciphertext.
//! Transport is pluggable — swap this module for WebSocket, Redis, etc.
//!
//! Uses reqwest with rustls-native-roots to auto-detect system CA certs,
//! which works in proxied environments (NODE_EXTRA_CA_CERTS, custom CAs).

use serde::Deserialize;

const NTFY_BASE: &str = "https://ntfy.sh";

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

/// Publish an encrypted payload to a ntfy.sh topic.
pub fn publish(topic: &str, payload: &str) -> bool {
    let url = format!("{NTFY_BASE}/{topic}");
    match client().post(&url).body(payload.to_string()).send() {
        Ok(resp) => resp.status().is_success(),
        Err(e) => {
            eprintln!("  [warn] ntfy publish failed: {e}");
            false
        }
    }
}

/// Fetch recent messages from a ntfy.sh topic.
/// Returns vec of (timestamp, raw_payload).
pub fn fetch(topic: &str, since: &str) -> Vec<(u64, String)> {
    let url = format!("{NTFY_BASE}/{topic}/json?poll=1&since={since}");
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
