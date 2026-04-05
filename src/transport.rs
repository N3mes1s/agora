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

fn streaming_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(None)
        .build()
        .expect("failed to build streaming HTTP client")
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

/// Open a streaming SSE connection to a ntfy.sh topic.
/// Calls `on_message(timestamp, raw_payload)` for each message.
/// Blocks forever. Returns on connection error.
pub fn stream<F>(topic: &str, mut on_message: F)
where
    F: FnMut(u64, &str),
{
    let url = format!("{NTFY_BASE}/{topic}/json");
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
