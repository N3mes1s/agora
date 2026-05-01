use super::{
    DEFAULT_RELAY, PublishError, PublishLimits, StreamConfig, StreamCursor, StreamDisconnect,
    Transport, TransportConfig, parse_since_cutoff,
};
use crate::runtime;
use serde::Deserialize;
use std::io::BufRead;
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

pub(super) struct NtfyTransport;

impl Transport for NtfyTransport {
    fn relay_status_label(&self, config: &TransportConfig) -> String {
        format!("Relay ({})", config.relay_url)
    }

    fn publish_limits(&self, config: &TransportConfig) -> PublishLimits {
        if config.relay_url == DEFAULT_RELAY {
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

    fn publish(
        &self,
        config: &TransportConfig,
        topic: &str,
        payload: &str,
    ) -> Result<(), PublishError> {
        let _permit = acquire_publish_permit(self.publish_limits(config));
        let primary = format!("{}/{topic}", config.relay_url);
        let result = match apply_auth(config, client().post(&primary))
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
            Err(err) => {
                eprintln!("  [warn] relay publish failed: {err}");
                Err(PublishError::Network(err.to_string()))
            }
        };

        if let Some(mirror) = &config.relay_mirror {
            let mirror_url = format!("{mirror}/{topic}");
            let _ = apply_auth(config, client().post(&mirror_url))
                .body(payload.to_string())
                .send();
        }

        result
    }

    fn fetch(&self, config: &TransportConfig, topic: &str, since: &str) -> Vec<(u64, String)> {
        let primary_url = format!("{}/{topic}/json?poll=1&since={since}", config.relay_url);
        let primary_body = match apply_auth(config, client().get(&primary_url)).send() {
            Ok(resp) => resp.text().unwrap_or_default(),
            Err(err) => {
                eprintln!("  [warn] primary relay fetch failed: {err}");
                String::new()
            }
        };

        let body = if primary_body.trim().is_empty() || !primary_body.contains("message") {
            if let Some(mirror) = &config.relay_mirror {
                let mirror_url = format!("{mirror}/{topic}/json?poll=1&since={since}");
                match client().get(&mirror_url).send() {
                    Ok(resp) => resp.text().unwrap_or(primary_body),
                    Err(_) => primary_body,
                }
            } else {
                primary_body
            }
        } else {
            primary_body
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

    fn stream(
        &self,
        config: &TransportConfig,
        topic: &str,
        initial_since: Option<&str>,
        stream_config: &StreamConfig,
        on_message: &mut dyn FnMut(u64, &str),
        on_disconnect: &mut dyn FnMut(StreamDisconnect, Option<Duration>),
    ) {
        let mut cursor = match initial_since {
            Some(since) => Some(StreamCursor::new(parse_since_cutoff(
                since,
                runtime::unix_now(),
            ))),
            None if stream_config.reconnect => Some(StreamCursor::new(runtime::unix_now())),
            None => None,
        };
        let mut backoff = stream_config.initial_backoff;
        let mut first_request = true;

        loop {
            let request_since = if first_request {
                initial_since.map(str::to_string)
            } else {
                cursor.as_ref().map(|cursor| cursor.since_ts.to_string())
            };
            first_request = false;

            let url = match request_since.as_deref() {
                Some(since) => format!("{}/{topic}/json?since={since}", config.relay_url),
                None => format!("{}/{topic}/json", config.relay_url),
            };

            let response = match apply_auth(config, streaming_client().get(&url)).send() {
                Ok(resp) if resp.status().is_success() => {
                    backoff = stream_config.initial_backoff;
                    resp
                }
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let body = resp.text().unwrap_or_default();
                    let error = classify_stream_connect_failure(status, &body);
                    if matches!(error, StreamDisconnect::Auth(_)) || !stream_config.reconnect {
                        on_disconnect(error, None);
                        return;
                    }
                    on_disconnect(error, Some(backoff));
                    runtime::sleep(backoff);
                    backoff = std::cmp::min(backoff.saturating_mul(2), stream_config.max_backoff);
                    continue;
                }
                Err(err) => {
                    let error = StreamDisconnect::Connect(err.to_string());
                    if !stream_config.reconnect {
                        on_disconnect(error, None);
                        return;
                    }
                    on_disconnect(error, Some(backoff));
                    runtime::sleep(backoff);
                    backoff = std::cmp::min(backoff.saturating_mul(2), stream_config.max_backoff);
                    continue;
                }
            };

            let mut disconnect = StreamDisconnect::Read("stream ended".to_string());
            let reader = std::io::BufReader::new(response);
            for line in reader.lines() {
                let line = match line {
                    Ok(line) => line,
                    Err(err) => {
                        disconnect = StreamDisconnect::Read(err.to_string());
                        break;
                    }
                };
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                if let Ok(evt) = serde_json::from_str::<NtfyEvent>(&line)
                    && evt.event.as_deref() == Some("message")
                    && let Some(ref message) = evt.message
                {
                    let ts = evt.time.unwrap_or(0);
                    let should_emit = match cursor.as_mut() {
                        Some(cursor) => cursor.should_emit(ts, evt.id.as_deref(), message),
                        None => true,
                    };
                    if should_emit {
                        on_message(ts, message);
                    }
                }
            }

            if !stream_config.reconnect {
                on_disconnect(disconnect, None);
                return;
            }
            on_disconnect(disconnect, Some(backoff));
            runtime::sleep(backoff);
            backoff = std::cmp::min(backoff.saturating_mul(2), stream_config.max_backoff);
        }
    }
}

#[derive(Debug, Deserialize)]
struct NtfyEvent {
    id: Option<String>,
    event: Option<String>,
    message: Option<String>,
    time: Option<u64>,
}

#[derive(Debug, Default)]
struct PublishGateState {
    next_allowed: Option<Instant>,
    in_flight: usize,
}

struct PublishPermit;

impl Drop for PublishPermit {
    fn drop(&mut self) {
        let (lock, cvar) = publish_gate();
        let mut state = lock.lock().unwrap_or_else(|e| e.into_inner());
        state.in_flight = state.in_flight.saturating_sub(1);
        cvar.notify_one();
    }
}

fn publish_gate() -> &'static (Mutex<PublishGateState>, Condvar) {
    static GATE: OnceLock<(Mutex<PublishGateState>, Condvar)> = OnceLock::new();
    GATE.get_or_init(|| (Mutex::new(PublishGateState::default()), Condvar::new()))
}

fn acquire_publish_permit(limits: PublishLimits) -> Option<PublishPermit> {
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

fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("failed to build HTTP client")
}

fn streaming_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(None)
        .build()
        .expect("failed to build streaming HTTP client")
}

fn apply_auth(
    config: &TransportConfig,
    builder: reqwest::blocking::RequestBuilder,
) -> reqwest::blocking::RequestBuilder {
    if let Some(token) = &config.relay_token {
        builder.header("Authorization", format!("Bearer {token}"))
    } else {
        builder
    }
}

fn parse_retry_after(value: Option<&str>) -> Option<Duration> {
    value
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}

pub(super) fn classify_publish_failure(
    status: u16,
    retry_after: Option<&str>,
    body: &str,
) -> PublishError {
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

pub(super) fn classify_stream_connect_failure(status: u16, body: &str) -> StreamDisconnect {
    let message = format!("HTTP {status}: {}", body.trim());
    match status {
        401 | 403 => StreamDisconnect::Auth(message),
        _ => StreamDisconnect::Connect(message),
    }
}
