use super::{
    PublishError, PublishLimits, StreamConfig, StreamCursor, StreamDisconnect, Transport,
    TransportConfig, parse_since_cutoff,
};
use crate::runtime;
use async_nats::HeaderMap;
use async_nats::header::HeaderValue;
use async_nats::jetstream;
use async_nats::jetstream::consumer::{self, DeliverPolicy};
use async_nats::jetstream::context::traits::Publisher as _;
use async_nats::jetstream::message::PublishMessage;
use async_nats::jetstream::stream::{Config as StreamConfigJs, Stream as JetStream};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures_util::StreamExt;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

const STREAM_NAME: &str = "AGORA";
const STREAM_SUBJECTS: &[&str] = &["agora.>"];
const MESSAGE_ID_HEADER: &str = "Agora-Message-Id";
const JETSTREAM_TIMEOUT: Duration = Duration::from_secs(5);
const JETSTREAM_ACK_TIMEOUT: Duration = Duration::from_secs(30);
const JETSTREAM_MAX_ACK_INFLIGHT: usize = 8_192;
const JETSTREAM_ACK_CONCURRENCY: usize = 256;
const CONSUMER_INACTIVE_THRESHOLD: Duration = Duration::from_secs(10);
const CONSUMER_MAX_EXPIRES: Duration = Duration::from_secs(30);
const CONSUMER_MAX_BYTES: i64 = 1_048_576;
const FETCH_BATCH_SIZE: usize = 256;
const FETCH_EXPIRES: Duration = Duration::from_millis(250);
const STREAM_BATCH_SIZE: i64 = 512;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct NatsCacheKey {
    relay_url: String,
    relay_token: Option<String>,
}

struct NatsState {
    context: jetstream::Context,
    stream: JetStream,
}

#[derive(Debug)]
enum NatsStateError {
    Connect(async_nats::ConnectError),
    Runtime(String),
}

pub(super) struct NatsTransport;

impl Transport for NatsTransport {
    fn relay_status_label(&self, config: &TransportConfig) -> String {
        format!("Relay ({})", config.relay_url)
    }

    fn publish_limits(&self, _config: &TransportConfig) -> PublishLimits {
        PublishLimits {
            burst: None,
            sustained_per_second: None,
            body_max_bytes: None,
        }
    }

    fn publish(
        &self,
        config: &TransportConfig,
        topic: &str,
        payload: &str,
    ) -> Result<(), PublishError> {
        block_on(async {
            let state = shared_state(config)
                .await
                .map_err(classify_publish_state_error)?;
            let subject = subject_for_topic(topic);
            let message_id = message_id();
            let publish = PublishMessage::build()
                .message_id(message_id.clone())
                .header(MESSAGE_ID_HEADER, message_id)
                .payload(payload.as_bytes().to_vec().into())
                .outbound_message(subject);
            state
                .context
                .publish_message(publish)
                .await
                .map_err(classify_publish_runtime_error)?
                .await
                .map_err(classify_publish_runtime_error)?;
            Ok(())
        })
    }

    fn fetch(&self, config: &TransportConfig, topic: &str, since: &str) -> Vec<(u64, String)> {
        let cutoff = parse_since_cutoff(since, runtime::unix_now());
        match block_on(async {
            let state = shared_state(config)
                .await
                .map_err(classify_stream_state_error)?;
            fetch_since(&state, topic, cutoff).await
        }) {
            Ok(events) => events,
            Err(err) => {
                eprintln!("  [warn] relay fetch failed: {err}");
                Vec::new()
            }
        }
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

        loop {
            let stream_result = block_on(async {
                let state = shared_state(config)
                    .await
                    .map_err(classify_stream_state_error)?;
                let subject = subject_for_topic(topic);
                let deliver_policy = stream_deliver_policy(cursor.as_ref());
                let consumer = state
                    .stream
                    .create_consumer(consumer::pull::OrderedConfig {
                        filter_subject: subject,
                        deliver_policy,
                        max_batch: STREAM_BATCH_SIZE,
                        max_bytes: CONSUMER_MAX_BYTES,
                        max_expires: CONSUMER_MAX_EXPIRES,
                        ..Default::default()
                    })
                    .await
                    .map_err(classify_stream_runtime_error)?;
                let mut messages = consumer
                    .messages()
                    .await
                    .map_err(classify_stream_runtime_error)?;

                while let Some(message) = messages.next().await {
                    let message = message.map_err(classify_stream_runtime_error)?;
                    let ts = jetstream_message_timestamp(&message)?;
                    let payload = String::from_utf8_lossy(&message.message.payload).into_owned();
                    let message_id = message
                        .message
                        .headers
                        .as_ref()
                        .and_then(message_id_from_headers);
                    let should_emit = match cursor.as_mut() {
                        Some(cursor) => cursor.should_emit(ts, message_id.as_deref(), &payload),
                        None => true,
                    };
                    if should_emit {
                        on_message(ts, &payload);
                    }
                }

                Err::<(), _>(StreamDisconnect::Read("stream ended".to_string()))
            });

            match stream_result {
                Err(error)
                    if matches!(error, StreamDisconnect::Auth(_)) || !stream_config.reconnect =>
                {
                    on_disconnect(error, None);
                    return;
                }
                Err(error) => {
                    on_disconnect(error, Some(backoff));
                    runtime::sleep(backoff);
                    backoff = std::cmp::min(backoff.saturating_mul(2), stream_config.max_backoff);
                }
                Ok(()) => {
                    backoff = stream_config.initial_backoff;
                }
            }
        }
    }
}

async fn connect(config: &TransportConfig) -> Result<async_nats::Client, async_nats::ConnectError> {
    let mut options = async_nats::ConnectOptions::new()
        .connection_timeout(Duration::from_secs(5))
        .retry_on_initial_connect();
    if let Some(token) = &config.relay_token {
        options = options.token(token.clone());
    }
    if config.relay_url.starts_with("tls://") {
        options = options.require_tls(true);
    }
    options.connect(config.relay_url.clone()).await
}

fn state_cache() -> &'static Mutex<HashMap<NatsCacheKey, Arc<NatsState>>> {
    static CACHE: OnceLock<Mutex<HashMap<NatsCacheKey, Arc<NatsState>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

async fn shared_state(config: &TransportConfig) -> Result<Arc<NatsState>, NatsStateError> {
    let key = NatsCacheKey {
        relay_url: config.relay_url.clone(),
        relay_token: config.relay_token.clone(),
    };

    if let Some(existing) = state_cache().lock().unwrap().get(&key).cloned() {
        return Ok(existing);
    }

    let client = connect(config).await.map_err(NatsStateError::Connect)?;
    let context = jetstream::context::ContextBuilder::new()
        .timeout(JETSTREAM_TIMEOUT)
        .ack_timeout(JETSTREAM_ACK_TIMEOUT)
        .max_ack_inflight(JETSTREAM_MAX_ACK_INFLIGHT)
        .backpressure_on_inflight(true)
        .concurrency_limit(Some(JETSTREAM_ACK_CONCURRENCY))
        .build(client);
    let stream = ensure_stream(&context)
        .await
        .map_err(NatsStateError::Runtime)?;
    let state = Arc::new(NatsState { context, stream });

    let mut cache = state_cache().lock().unwrap();
    Ok(cache.entry(key).or_insert_with(|| state.clone()).clone())
}

async fn ensure_stream(context: &jetstream::Context) -> Result<JetStream, String> {
    context
        .get_or_create_stream(StreamConfigJs {
            name: STREAM_NAME.to_string(),
            subjects: STREAM_SUBJECTS
                .iter()
                .map(|subject| (*subject).to_string())
                .collect(),
            allow_direct: true,
            ..Default::default()
        })
        .await
        .map_err(|err| err.to_string())
}

async fn fetch_since(
    state: &NatsState,
    topic: &str,
    cutoff: u64,
) -> Result<Vec<(u64, String)>, StreamDisconnect> {
    let mut events = Vec::new();
    let subject = subject_for_topic(topic);
    let consumer = state
        .stream
        .create_consumer(consumer::pull::Config {
            filter_subject: subject,
            deliver_policy: deliver_policy_for_cutoff(cutoff),
            max_batch: FETCH_BATCH_SIZE as i64,
            max_bytes: CONSUMER_MAX_BYTES,
            max_expires: CONSUMER_MAX_EXPIRES,
            inactive_threshold: CONSUMER_INACTIVE_THRESHOLD,
            ..Default::default()
        })
        .await
        .map_err(classify_stream_runtime_error)?;
    let mut cursor = StreamCursor::new(cutoff);

    loop {
        let mut batch = consumer
            .fetch()
            .max_messages(FETCH_BATCH_SIZE)
            .expires(FETCH_EXPIRES)
            .messages()
            .await
            .map_err(classify_stream_runtime_error)?;
        let mut saw_messages = false;

        while let Some(message) = batch.next().await {
            let message = message.map_err(classify_stream_runtime_error)?;
            saw_messages = true;
            let ts = jetstream_message_timestamp(&message)?;
            let payload = String::from_utf8_lossy(&message.message.payload).into_owned();
            let message_id = message
                .message
                .headers
                .as_ref()
                .and_then(message_id_from_headers);
            message.ack().await.map_err(classify_stream_runtime_error)?;
            if cursor.should_emit(ts, message_id.as_deref(), &payload) {
                events.push((ts, payload));
            }
        }

        if !saw_messages {
            break;
        }
    }

    Ok(events)
}

fn deliver_policy_for_cutoff(cutoff: u64) -> DeliverPolicy {
    if cutoff == 0 {
        DeliverPolicy::All
    } else {
        DeliverPolicy::ByStartTime {
            start_time: unix_timestamp_to_offset(cutoff),
        }
    }
}

fn stream_deliver_policy(cursor: Option<&StreamCursor>) -> DeliverPolicy {
    match cursor {
        Some(cursor) => deliver_policy_for_cutoff(cursor.since_ts),
        None => DeliverPolicy::New,
    }
}

fn subject_for_topic(topic: &str) -> String {
    format!("agora.{}", URL_SAFE_NO_PAD.encode(topic.as_bytes()))
}

fn message_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    format!(
        "agora-{}-{}-{}",
        std::process::id(),
        runtime::unix_now(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

fn message_id_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get(MESSAGE_ID_HEADER)
        .map(HeaderValue::as_str)
        .map(str::to_string)
}

fn jetstream_message_timestamp(
    message: &async_nats::jetstream::Message,
) -> Result<u64, StreamDisconnect> {
    Ok(message
        .info()
        .map_err(classify_stream_runtime_error)?
        .published
        .unix_timestamp()
        .max(0) as u64)
}

fn unix_timestamp_to_offset(raw: u64) -> time::OffsetDateTime {
    let raw = raw.min(i64::MAX as u64) as i64;
    time::OffsetDateTime::from_unix_timestamp(raw).unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
}

#[cfg(test)]
fn parse_rfc3339_timestamp(raw: &str) -> Option<u64> {
    time::OffsetDateTime::parse(raw, &time::format_description::well_known::Rfc3339)
        .ok()
        .map(|ts| ts.unix_timestamp().max(0) as u64)
}

fn classify_publish_state_error(error: NatsStateError) -> PublishError {
    match error {
        NatsStateError::Connect(error) => classify_publish_connect_error(error),
        NatsStateError::Runtime(error) => classify_publish_runtime_error(error),
    }
}

fn classify_stream_state_error(error: NatsStateError) -> StreamDisconnect {
    match error {
        NatsStateError::Connect(error) => classify_stream_connect_error(error),
        NatsStateError::Runtime(error) => classify_stream_runtime_error(error),
    }
}

fn classify_publish_connect_error(error: async_nats::ConnectError) -> PublishError {
    let message = error.to_string();
    if seems_like_auth_failure(&message) {
        PublishError::Forbidden(message)
    } else {
        PublishError::Network(message)
    }
}

fn classify_publish_runtime_error(error: impl std::fmt::Display) -> PublishError {
    let message = error.to_string();
    if seems_like_auth_failure(&message) {
        PublishError::Forbidden(message)
    } else {
        PublishError::Network(message)
    }
}

fn classify_stream_connect_error(error: async_nats::ConnectError) -> StreamDisconnect {
    let message = error.to_string();
    if seems_like_auth_failure(&message) {
        StreamDisconnect::Auth(message)
    } else {
        StreamDisconnect::Connect(message)
    }
}

fn classify_stream_runtime_error(error: impl std::fmt::Display) -> StreamDisconnect {
    let message = error.to_string();
    if seems_like_auth_failure(&message) {
        StreamDisconnect::Auth(message)
    } else {
        StreamDisconnect::Connect(message)
    }
}

fn seems_like_auth_failure(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("auth") || lower.contains("authorization") || lower.contains("permission")
}

fn block_on<F>(future: F) -> F::Output
where
    F: std::future::Future,
{
    runtime_handle().block_on(future)
}

fn runtime_handle() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build NATS runtime")
    })
}

#[cfg(test)]
mod tests {
    use super::{
        DeliverPolicy, MESSAGE_ID_HEADER, deliver_policy_for_cutoff, message_id_from_headers,
        parse_rfc3339_timestamp, shared_state, stream_deliver_policy, subject_for_topic,
    };
    use crate::{runtime, transport};
    use async_nats::HeaderMap;
    use async_nats::jetstream;
    use async_nats::jetstream::stream::Config as JetStreamConfig;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use std::sync::Arc;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn subject_for_topic_is_stable_and_nats_safe() {
        let topic = "dm-agent.alice-agent:bob";
        let subject = subject_for_topic(topic);
        assert_eq!(
            subject,
            format!("agora.{}", URL_SAFE_NO_PAD.encode(topic.as_bytes()))
        );
        assert!(!subject.contains(' '));
        assert!(!subject.contains('*'));
        assert!(!subject.contains('>'));
    }

    #[test]
    fn parse_rfc3339_timestamp_returns_unix_seconds() {
        assert_eq!(
            parse_rfc3339_timestamp("2026-05-01T13:27:00Z"),
            Some(1_777_642_020)
        );
    }

    #[test]
    fn message_id_header_round_trips() {
        let mut headers = HeaderMap::new();
        headers.insert(MESSAGE_ID_HEADER, "msg-1");
        assert_eq!(message_id_from_headers(&headers).as_deref(), Some("msg-1"));
    }

    #[test]
    fn deliver_policy_defaults_to_all_for_zero_cutoff() {
        assert_eq!(deliver_policy_for_cutoff(0), DeliverPolicy::All);
    }

    #[test]
    fn stream_deliver_policy_uses_new_without_cursor() {
        assert_eq!(stream_deliver_policy(None), DeliverPolicy::New);
    }

    #[test]
    #[ignore = "requires AGORA_LIVE_NATS_URL pointing at a real NATS+JetStream server"]
    fn live_async_nats_jetstream_smoke() {
        let relay_url = std::env::var("AGORA_LIVE_NATS_URL")
            .expect("AGORA_LIVE_NATS_URL must point at a live NATS server");
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let stream_name = format!("AGORA_SMOKE_{unique}");
        let subject = format!("smoke.{unique}");

        let result = super::block_on(async {
            let client = async_nats::connect(relay_url)
                .await
                .map_err(|e| e.to_string())?;
            let context = jetstream::new(client);
            let stream = context
                .get_or_create_stream(JetStreamConfig {
                    name: stream_name,
                    subjects: vec!["smoke.>".to_string()],
                    allow_direct: true,
                    ..Default::default()
                })
                .await
                .map_err(|e| e.to_string())?;
            context
                .publish(subject.clone(), "hello".into())
                .await
                .map_err(|e| e.to_string())?
                .await
                .map_err(|e| e.to_string())?;
            let message = stream
                .direct_get_last_for_subject(subject)
                .await
                .map_err(|e| e.to_string())?;
            Ok::<_, String>(String::from_utf8_lossy(&message.payload).into_owned())
        });

        assert_eq!(result.unwrap(), "hello".to_string());
    }

    #[test]
    #[ignore = "requires AGORA_LIVE_NATS_URL pointing at a real NATS+JetStream server"]
    fn live_nats_publish_and_fetch_work() {
        let relay_url = std::env::var("AGORA_LIVE_NATS_URL")
            .expect("AGORA_LIVE_NATS_URL must point at a live NATS server");
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let home = std::env::temp_dir().join(format!("agora-live-nats-fetch-{unique}"));
        let topic = format!("ag-live-fetch-{unique}");
        std::fs::create_dir_all(&home).unwrap();

        let _runtime = runtime::TestRuntime::new()
            .home(&home)
            .var("AGORA_RELAY_URL", relay_url)
            .enter();

        assert_eq!(transport::publish_detailed(&topic, "first"), Ok(()));
        assert_eq!(transport::publish_detailed(&topic, "second"), Ok(()));

        let fetched = transport::fetch(&topic, "1h");
        assert!(fetched.iter().any(|(_, payload)| payload == "first"));
        assert!(fetched.iter().any(|(_, payload)| payload == "second"));
        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    #[ignore = "requires AGORA_LIVE_NATS_URL pointing at a real NATS+JetStream server"]
    fn live_nats_publish_fetch_and_stream_work() {
        let relay_url = std::env::var("AGORA_LIVE_NATS_URL")
            .expect("AGORA_LIVE_NATS_URL must point at a live NATS server");
        let container = std::env::var("AGORA_LIVE_NATS_CONTAINER")
            .expect("AGORA_LIVE_NATS_CONTAINER must name the live test container");
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let home = std::env::temp_dir().join(format!("agora-live-nats-{unique}"));
        let topic = format!("ag-live-nats-{unique}");
        std::fs::create_dir_all(&home).unwrap();

        let _runtime = runtime::TestRuntime::new()
            .home(&home)
            .var("AGORA_RELAY_URL", relay_url)
            .enter();

        assert_eq!(transport::publish_detailed(&topic, "first"), Ok(()));
        assert_eq!(transport::publish_detailed(&topic, "second"), Ok(()));

        let fetched = transport::fetch(&topic, "1h");
        assert!(fetched.iter().any(|(_, payload)| payload == "first"));
        assert!(fetched.iter().any(|(_, payload)| payload == "second"));

        let (tx, rx) = mpsc::channel();
        let stream_topic = topic.clone();
        let stream_handle = runtime::spawn_with_current(move || {
            transport::stream_with_config(
                &stream_topic,
                &transport::StreamConfig::default(),
                |_, payload| {
                    let _ = tx.send(payload.to_string());
                },
                |_, _| {},
            );
        });

        std::thread::sleep(Duration::from_millis(250));
        assert_eq!(transport::publish_detailed(&topic, "stream-live"), Ok(()));
        let received = rx.recv_timeout(Duration::from_secs(5)).ok();
        let stop_status = std::process::Command::new("docker")
            .args(["stop", &container])
            .status()
            .expect("failed to stop live NATS test container");
        assert!(stop_status.success(), "docker stop should succeed");
        drop(stream_handle);
        std::thread::sleep(Duration::from_millis(250));
        assert_eq!(
            received,
            Some("stream-live".to_string()),
            "stream callback should receive the live publish"
        );
        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    #[ignore = "requires AGORA_LIVE_NATS_URL pointing at a real NATS+JetStream server"]
    fn live_nats_burst_publish_and_fetch_work() {
        let relay_url = std::env::var("AGORA_LIVE_NATS_URL")
            .expect("AGORA_LIVE_NATS_URL must point at a live NATS server");
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let home = std::env::temp_dir().join(format!("agora-live-nats-burst-{unique}"));
        let topic = format!("ag-live-burst-{unique}");
        std::fs::create_dir_all(&home).unwrap();

        let _runtime = runtime::TestRuntime::new()
            .home(&home)
            .var("AGORA_RELAY_URL", relay_url)
            .enter();

        let handles: Vec<_> = (0..64)
            .map(|idx| {
                let topic = topic.clone();
                runtime::spawn_with_current(move || {
                    let payload = format!("burst-{idx}");
                    assert_eq!(transport::publish_detailed(&topic, &payload), Ok(()));
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("burst publish should not panic");
        }

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut fetched = Vec::new();
        while std::time::Instant::now() < deadline {
            fetched = transport::fetch(&topic, "1h");
            if fetched.len() >= 64 {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        assert_eq!(fetched.len(), 64, "all burst messages should be fetchable");
        for idx in 0..64 {
            assert!(
                fetched
                    .iter()
                    .any(|(_, payload)| payload == &format!("burst-{idx}")),
                "missing burst-{idx}"
            );
        }
        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    #[ignore = "requires AGORA_LIVE_NATS_URL pointing at a real NATS+JetStream server"]
    fn live_nats_reuses_cached_state() {
        let relay_url = std::env::var("AGORA_LIVE_NATS_URL")
            .expect("AGORA_LIVE_NATS_URL must point at a live NATS server");
        let home = std::env::temp_dir().join("agora-live-nats-cache");
        std::fs::create_dir_all(&home).unwrap();

        let _runtime = runtime::TestRuntime::new()
            .home(&home)
            .var("AGORA_RELAY_URL", relay_url)
            .enter();

        let config = super::TransportConfig::current();
        let first = super::block_on(shared_state(&config)).unwrap();
        let second = super::block_on(shared_state(&config)).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        let _ = std::fs::remove_dir_all(home);
    }
}
