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
use async_nats::jetstream::stream::{Config as StreamConfigJs, StorageType, Stream as JetStream};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures_util::StreamExt;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

const DEFAULT_STREAM_NAME: &str = "AGORA";
const DEFAULT_SUBJECT_PREFIX: &str = "agora";
const MESSAGE_ID_HEADER: &str = "Agora-Message-Id";
const JETSTREAM_TIMEOUT: Duration = Duration::from_secs(5);
const JETSTREAM_ACK_TIMEOUT: Duration = Duration::from_secs(30);
const JETSTREAM_MAX_ACK_INFLIGHT: usize = 8_192;
const JETSTREAM_ACK_CONCURRENCY: usize = 256;
const CONSUMER_INACTIVE_THRESHOLD: Duration = Duration::from_secs(10);
/// Per-pull-request server-side timeout for stream consumers. Under
/// `async_nats::jetstream::consumer::pull::OrderedConfig`, the `messages()`
/// stream returns `None` when the pull request expires server-side without
/// new traffic, which forces the outer reconnect loop into exponential
/// backoff and creates a window where messages published during the sleep
/// can sit in the stream unobserved until the next pull subscription. The
/// cursor recovers them on replay, but the gap is operator-visible as a
/// freeze. Bumped from 30s (RFD-0029 dogfood, 2026-05-14) — pi-rs's
/// SpritesProvider smoke surfaced the freeze on quiet RPC patterns where
/// init traffic completes inside the first 5s, then 30s of idle expires
/// the consumer right before the first bash-side op publishes a request.
const CONSUMER_MAX_EXPIRES: Duration = Duration::from_secs(300);
const CONSUMER_MAX_BYTES: i64 = 1_048_576;
const FETCH_BATCH_SIZE: usize = 256;
const FETCH_EXPIRES: Duration = Duration::from_millis(250);
const STREAM_BATCH_SIZE: i64 = 512;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct NatsCacheKey {
    relay_url: String,
    relay_token: Option<String>,
    settings: NatsSettings,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum NatsStorage {
    File,
    Memory,
}

impl NatsStorage {
    fn to_jetstream(self) -> StorageType {
        match self {
            Self::File => StorageType::File,
            Self::Memory => StorageType::Memory,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct NatsSettings {
    stream_name: String,
    subject_prefix: String,
    create_stream: bool,
    storage: NatsStorage,
    max_bytes: i64,
    max_age: Duration,
}

impl NatsSettings {
    fn current() -> Self {
        Self {
            stream_name: nats_stream_name(),
            subject_prefix: nats_subject_prefix(),
            create_stream: nats_create_stream(),
            storage: nats_storage(),
            max_bytes: nats_max_bytes(),
            max_age: nats_max_age(),
        }
    }

    fn stream_subject(&self) -> String {
        format!("{}.>", self.subject_prefix)
    }
}

impl Default for NatsSettings {
    fn default() -> Self {
        Self {
            stream_name: DEFAULT_STREAM_NAME.to_string(),
            subject_prefix: DEFAULT_SUBJECT_PREFIX.to_string(),
            create_stream: true,
            storage: NatsStorage::File,
            max_bytes: 0,
            max_age: Duration::default(),
        }
    }
}

pub(super) struct NatsTransport;

impl Transport for NatsTransport {
    fn relay_status_label(&self, config: &TransportConfig) -> String {
        let settings = NatsSettings::current();
        format!(
            "Relay ({} stream={} subjects={})",
            config.relay_url,
            settings.stream_name,
            settings.stream_subject()
        )
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
            let settings = NatsSettings::current();
            let state = shared_state(config, &settings)
                .await
                .map_err(classify_publish_state_error)?;
            let subject = subject_for_topic(&settings, topic);
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
            let settings = NatsSettings::current();
            let state = shared_state(config, &settings)
                .await
                .map_err(classify_stream_state_error)?;
            fetch_since(&state, &settings, topic, cutoff).await
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
                let settings = NatsSettings::current();
                let state = shared_state(config, &settings)
                    .await
                    .map_err(classify_stream_state_error)?;
                let subject = subject_for_topic(&settings, topic);
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
                    // Evict the cached state so the next `shared_state`
                    // call rebuilds the client + context + stream
                    // handle. Defense-in-depth: async_nats's Client
                    // typically auto-reconnects the underlying TCP
                    // transparently (verified locally by the
                    // container-restart probe), but if state-level
                    // corruption survives a reconnect — JetStream
                    // consumer references gone stale, etc. — the
                    // eviction forces a clean rebuild.
                    let settings = NatsSettings::current();
                    evict_shared_state(config, &settings);
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

async fn shared_state(
    config: &TransportConfig,
    settings: &NatsSettings,
) -> Result<Arc<NatsState>, NatsStateError> {
    let key = NatsCacheKey {
        relay_url: config.relay_url.clone(),
        relay_token: config.relay_token.clone(),
        settings: settings.clone(),
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
    let stream = ensure_stream(&context, settings)
        .await
        .map_err(NatsStateError::Runtime)?;
    let state = Arc::new(NatsState { context, stream });

    let mut cache = state_cache().lock().unwrap();
    Ok(cache.entry(key).or_insert_with(|| state.clone()).clone())
}

/// Evict the cached `NatsState` for the given key so the next call to
/// [`shared_state`] establishes a fresh client connection + JetStream
/// context + stream handle. The reconnect loop in [`Transport::stream`]
/// calls this on every transport-level error so a dead TCP connection
/// (e.g. Railway TCP-proxy closing an idle stream) doesn't leave the
/// cache poisoned with a stale state that all subsequent reconnect
/// attempts inherit. Surfaced during the RFD-0029 dogfood (room
/// cfs-rfd-0029 [323909]) where the empirical OrderedConfig-expire
/// probe ruled out [17a4d0]'s expire hypothesis, leaving cache-poisoned-
/// state as the remaining transport-level failure mode for a long-idle
/// agora-bridge whose underlying TCP got closed by an intermediate proxy.
fn evict_shared_state(config: &TransportConfig, settings: &NatsSettings) {
    let key = NatsCacheKey {
        relay_url: config.relay_url.clone(),
        relay_token: config.relay_token.clone(),
        settings: settings.clone(),
    };
    if let Ok(mut cache) = state_cache().lock() {
        cache.remove(&key);
    }
}

async fn ensure_stream(
    context: &jetstream::Context,
    settings: &NatsSettings,
) -> Result<JetStream, String> {
    if !settings.create_stream {
        return context
            .get_stream(&settings.stream_name)
            .await
            .map_err(|err| {
                format!(
                    "failed to open existing NATS JetStream stream '{}': {err}",
                    settings.stream_name
                )
            });
    }

    context
        .get_or_create_stream(stream_config(settings))
        .await
        .map_err(|err| err.to_string())
}

fn stream_config(settings: &NatsSettings) -> StreamConfigJs {
    StreamConfigJs {
        name: settings.stream_name.clone(),
        subjects: vec![settings.stream_subject()],
        allow_direct: true,
        storage: settings.storage.to_jetstream(),
        max_bytes: settings.max_bytes,
        max_age: settings.max_age,
        description: Some("Agora encrypted room relay events".to_string()),
        ..Default::default()
    }
}

async fn fetch_since(
    state: &NatsState,
    settings: &NatsSettings,
    topic: &str,
    cutoff: u64,
) -> Result<Vec<(u64, String)>, StreamDisconnect> {
    let mut events = Vec::new();
    let subject = subject_for_topic(settings, topic);
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

fn subject_for_topic(settings: &NatsSettings, topic: &str) -> String {
    format!(
        "{}.{}",
        settings.subject_prefix,
        URL_SAFE_NO_PAD.encode(topic.as_bytes())
    )
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

fn nats_stream_name() -> String {
    normalize_stream_name(
        runtime::var("AGORA_NATS_STREAM")
            .as_deref()
            .unwrap_or(DEFAULT_STREAM_NAME),
    )
}

fn nats_subject_prefix() -> String {
    normalize_subject_prefix(
        runtime::var("AGORA_NATS_SUBJECT_PREFIX")
            .as_deref()
            .unwrap_or(DEFAULT_SUBJECT_PREFIX),
    )
}

fn nats_create_stream() -> bool {
    runtime::var("AGORA_NATS_CREATE_STREAM")
        .map(|value| parse_env_bool(&value, true))
        .unwrap_or(true)
}

fn nats_storage() -> NatsStorage {
    match runtime::var("AGORA_NATS_STORAGE")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "memory" | "mem" => NatsStorage::Memory,
        _ => NatsStorage::File,
    }
}

fn nats_max_bytes() -> i64 {
    runtime::var("AGORA_NATS_MAX_BYTES")
        .and_then(|value| value.trim().parse::<i64>().ok())
        .unwrap_or(0)
        .max(0)
}

fn nats_max_age() -> Duration {
    runtime::var("AGORA_NATS_MAX_AGE")
        .as_deref()
        .and_then(parse_duration)
        .unwrap_or_default()
}

fn parse_env_bool(raw: &str, default: bool) -> bool {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => true,
        "0" | "false" | "no" | "off" => false,
        _ => default,
    }
}

fn parse_duration(raw: &str) -> Option<Duration> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let (digits, suffix) = raw
        .trim()
        .split_at(raw.find(|c: char| !c.is_ascii_digit()).unwrap_or(raw.len()));
    let value = digits.parse::<u64>().ok()?;
    match suffix {
        "" | "s" => Some(Duration::from_secs(value)),
        "m" => Some(Duration::from_secs(value.saturating_mul(60))),
        "h" => Some(Duration::from_secs(value.saturating_mul(3600))),
        "d" => Some(Duration::from_secs(value.saturating_mul(86400))),
        _ => None,
    }
}

fn normalize_stream_name(raw: &str) -> String {
    let normalized = raw
        .trim()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string();
    if normalized.is_empty() {
        DEFAULT_STREAM_NAME.to_string()
    } else {
        normalized
    }
}

fn normalize_subject_prefix(raw: &str) -> String {
    let tokens = raw
        .trim()
        .trim_matches('.')
        .split('.')
        .filter_map(|token| {
            let normalized = token
                .chars()
                .map(|ch| {
                    if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                        ch
                    } else {
                        '_'
                    }
                })
                .collect::<String>()
                .trim_matches('_')
                .to_string();
            if normalized.is_empty() {
                None
            } else {
                Some(normalized)
            }
        })
        .collect::<Vec<_>>();
    if tokens.is_empty() {
        DEFAULT_SUBJECT_PREFIX.to_string()
    } else {
        tokens.join(".")
    }
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
        DeliverPolicy, MESSAGE_ID_HEADER, NatsSettings, NatsStorage, deliver_policy_for_cutoff,
        message_id_from_headers, normalize_stream_name, normalize_subject_prefix, parse_duration,
        parse_rfc3339_timestamp, shared_state, stream_config, stream_deliver_policy,
        subject_for_topic,
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
        let settings = NatsSettings::default();
        let subject = subject_for_topic(&settings, topic);
        assert_eq!(
            subject,
            format!("agora.{}", URL_SAFE_NO_PAD.encode(topic.as_bytes()))
        );
        assert!(!subject.contains(' '));
        assert!(!subject.contains('*'));
        assert!(!subject.contains('>'));
    }

    #[test]
    fn nats_settings_read_env_overrides() {
        let _runtime = runtime::TestRuntime::new()
            .var("AGORA_NATS_STREAM", "prod.agora/stream")
            .var("AGORA_NATS_SUBJECT_PREFIX", ".prod/agora.room.")
            .var("AGORA_NATS_CREATE_STREAM", "false")
            .var("AGORA_NATS_STORAGE", "memory")
            .var("AGORA_NATS_MAX_BYTES", "1048576")
            .var("AGORA_NATS_MAX_AGE", "7d")
            .enter();

        let settings = NatsSettings::current();
        assert_eq!(settings.stream_name, "prod_agora_stream");
        assert_eq!(settings.subject_prefix, "prod_agora.room");
        assert!(!settings.create_stream);
        assert_eq!(settings.storage, NatsStorage::Memory);
        assert_eq!(settings.max_bytes, 1_048_576);
        assert_eq!(settings.max_age, Duration::from_secs(7 * 86_400));
    }

    #[test]
    fn nats_settings_sanitize_empty_or_invalid_names() {
        assert_eq!(normalize_stream_name("..."), "AGORA");
        assert_eq!(
            normalize_stream_name("prod/room.events"),
            "prod_room_events"
        );
        assert_eq!(normalize_subject_prefix("..."), "agora");
        assert_eq!(
            normalize_subject_prefix(".prod/room.events."),
            "prod_room.events"
        );
    }

    #[test]
    fn stream_config_uses_nats_settings() {
        let settings = NatsSettings {
            stream_name: "AGORA_PROD".to_string(),
            subject_prefix: "prod.agora".to_string(),
            create_stream: true,
            storage: NatsStorage::Memory,
            max_bytes: 4_096,
            max_age: Duration::from_secs(600),
        };

        let config = stream_config(&settings);
        assert_eq!(config.name, "AGORA_PROD");
        assert_eq!(config.subjects, vec!["prod.agora.>".to_string()]);
        assert!(config.allow_direct);
        assert_eq!(
            config.storage,
            async_nats::jetstream::stream::StorageType::Memory
        );
        assert_eq!(config.max_bytes, 4_096);
        assert_eq!(config.max_age, Duration::from_secs(600));
    }

    #[test]
    fn parse_duration_supports_operational_units() {
        assert_eq!(parse_duration("30"), Some(Duration::from_secs(30)));
        assert_eq!(parse_duration("5m"), Some(Duration::from_secs(300)));
        assert_eq!(parse_duration("2h"), Some(Duration::from_secs(7_200)));
        assert_eq!(parse_duration("1d"), Some(Duration::from_secs(86_400)));
        assert_eq!(parse_duration("bad"), None);
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

    /// Characterize what `messages.next()` actually returns when the
    /// server-side pull request expires. Drives the
    /// reconnect-on-idle bug surfaced by pi-rs's RFD-0029 dogfood
    /// (room cfs-rfd-0029 [251124]).
    ///
    /// Uses async_nats directly (not the agora SDK stream wrapper)
    /// so we observe the raw library behavior with no SDK
    /// interpretation in between. Sets `max_expires` to 1s, waits 2s,
    /// then publishes — and prints what `messages.next()` returns at
    /// each step.
    #[test]
    #[ignore = "requires AGORA_LIVE_NATS_URL pointing at a real NATS+JetStream server"]
    fn live_nats_ordered_consumer_behavior_on_expire() {
        let relay_url = std::env::var("AGORA_LIVE_NATS_URL")
            .expect("AGORA_LIVE_NATS_URL must point at a live NATS server");
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let stream_name = format!("AGORA_EXPIRE_{unique}");
        let subject = format!("expire-test.{unique}.x");

        let outcome = super::block_on(async {
            let client = async_nats::connect(relay_url)
                .await
                .map_err(|e| format!("connect: {e}"))?;
            let context = jetstream::new(client);
            let _stream = context
                .get_or_create_stream(JetStreamConfig {
                    name: stream_name.clone(),
                    subjects: vec![format!("expire-test.{unique}.>")],
                    allow_direct: true,
                    ..Default::default()
                })
                .await
                .map_err(|e| format!("stream: {e}"))?;
            let stream = context
                .get_stream(&stream_name)
                .await
                .map_err(|e| format!("get_stream: {e}"))?;
            let consumer = stream
                .create_consumer(async_nats::jetstream::consumer::pull::OrderedConfig {
                    filter_subject: subject.clone(),
                    deliver_policy: async_nats::jetstream::consumer::DeliverPolicy::All,
                    max_batch: 16,
                    max_bytes: 1_048_576,
                    max_expires: Duration::from_secs(1),
                    ..Default::default()
                })
                .await
                .map_err(|e| format!("create_consumer: {e}"))?;
            let mut messages = consumer
                .messages()
                .await
                .map_err(|e| format!("messages: {e}"))?;

            // Step 1: poll with 2-second tokio timeout while the
            // server's max_expires=1s is in effect. What does
            // messages.next() return?
            use futures_util::StreamExt as _;
            let t0 = std::time::Instant::now();
            let step1 = tokio::time::timeout(Duration::from_secs(2), messages.next()).await;
            let step1_elapsed = t0.elapsed();
            let step1_repr = match &step1 {
                Ok(Some(Ok(m))) => format!("Some(Ok({} bytes))", m.message.payload.len()),
                Ok(Some(Err(e))) => format!("Some(Err({e}))"),
                Ok(None) => "None — stream ended".to_string(),
                Err(_) => "Err(tokio timeout) — messages.next() still pending".to_string(),
            };
            eprintln!(
                "[expire-probe] step1 elapsed={:?} result={}",
                step1_elapsed, step1_repr
            );

            // Step 2: publish a message, see if a subsequent
            // messages.next() picks it up.
            context
                .publish(subject, "post-expire".into())
                .await
                .map_err(|e| format!("publish: {e}"))?
                .await
                .map_err(|e| format!("publish-ack: {e}"))?;
            let t1 = std::time::Instant::now();
            let step2 = tokio::time::timeout(Duration::from_secs(5), messages.next()).await;
            let step2_elapsed = t1.elapsed();
            let step2_repr = match &step2 {
                Ok(Some(Ok(m))) => format!(
                    "Some(Ok({} bytes: {:?}))",
                    m.message.payload.len(),
                    String::from_utf8_lossy(&m.message.payload)
                ),
                Ok(Some(Err(e))) => format!("Some(Err({e}))"),
                Ok(None) => "None — stream ended".to_string(),
                Err(_) => "Err(tokio timeout) — messages.next() still pending".to_string(),
            };
            eprintln!(
                "[expire-probe] step2 elapsed={:?} result={}",
                step2_elapsed, step2_repr
            );

            Ok::<_, String>((step1_repr, step2_repr))
        });

        let (step1, step2) = outcome.expect("probe should complete");
        // Behavioral assertions — what we EXPECT from a healthy
        // OrderedConfig consumer:
        //   - step1 should be `Err(tokio timeout)` because OrderedConfig
        //     SHOULD internally re-issue the pull request on expire and
        //     keep polling.
        //   - step2 should be `Some(Ok(...))` with the published message.
        //
        // What we currently SEE (per pi-rs's bug report and the agora
        // SDK falling through to `Err("stream ended")`):
        //   - step1 might be `None — stream ended` (the smoking gun).
        //
        // This test PRINTS the actual behavior; the assertions below
        // document the expected-healthy behavior. If they fail, the
        // SDK's `while let Some(...)` loop is misinterpreting the
        // library's API.
        assert!(
            !step1.starts_with("None"),
            "OrderedConfig should NOT end stream on pull expire — got: {step1}"
        );
        assert!(
            step2.starts_with("Some(Ok"),
            "post-publish poll should deliver the message — got: {step2}"
        );
    }

    /// Repro for the cache-poison-on-disconnect bug surfaced by
    /// pi-rs's RFD-0029 dogfood (room cfs-rfd-0029 [739a9c]). Spawns
    /// an agora stream against a docker NATS container, kills the
    /// container, restarts it, and asserts the stream delivers a
    /// message published after the restart. Requires
    /// `AGORA_LIVE_NATS_URL` AND `AGORA_LIVE_NATS_CONTAINER` (the
    /// docker container name so we can stop+start it). Before the
    /// shared_state cache-eviction fix this test hung — the SDK
    /// kept returning the dead state from cache on every
    /// reconnect attempt.
    #[test]
    #[ignore = "requires AGORA_LIVE_NATS_URL + AGORA_LIVE_NATS_CONTAINER"]
    fn live_nats_stream_recovers_from_container_restart() {
        let relay_url = std::env::var("AGORA_LIVE_NATS_URL")
            .expect("AGORA_LIVE_NATS_URL must point at a live NATS server");
        let container = std::env::var("AGORA_LIVE_NATS_CONTAINER")
            .expect("AGORA_LIVE_NATS_CONTAINER must name the docker container");
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let home = std::env::temp_dir().join(format!("agora-live-nats-restart-{unique}"));
        let topic = format!("ag-live-restart-{unique}");
        std::fs::create_dir_all(&home).unwrap();

        let _runtime = runtime::TestRuntime::new()
            .home(&home)
            .var("AGORA_RELAY_URL", relay_url)
            .enter();

        // Initial publish + stream startup. Capture every payload via
        // the stream callback.
        assert_eq!(transport::publish_detailed(&topic, "pre-restart"), Ok(()));

        let (tx, rx) = mpsc::channel();
        let stream_topic = topic.clone();
        let stream_handle = runtime::spawn_with_current(move || {
            transport::stream_with_config(
                &stream_topic,
                &transport::StreamConfig {
                    reconnect: true,
                    initial_backoff: Duration::from_millis(500),
                    max_backoff: Duration::from_secs(4),
                },
                |_ts, payload| {
                    let _ = tx.send(payload.to_string());
                },
                |_reason, _next_backoff| {},
            );
        });

        // Confirm the pre-restart message lands.
        let pre = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("pre-restart message should arrive");
        assert_eq!(pre, "pre-restart");

        // Kill the container — simulates the upstream proxy / NATS
        // server closing the TCP connection from the SDK's POV.
        let stop = std::process::Command::new("docker")
            .args(["stop", &container])
            .status()
            .expect("docker stop should run");
        assert!(stop.success(), "docker stop should succeed");

        // Bring it back. The cached NatsState now points at a dead
        // TCP; without 5bb3d9f, every reconnect cycle uses it.
        let start = std::process::Command::new("docker")
            .args(["start", &container])
            .status()
            .expect("docker start should run");
        assert!(start.success(), "docker start should succeed");
        // Tiny settle window for the container to bind 4222 again.
        std::thread::sleep(Duration::from_secs(2));

        // Publish post-restart. With the cache-eviction fix, the
        // stream's reconnect loop should evict the dead state and
        // rebuild — the new message should land within a few backoff
        // cycles. Generous timeout for the reconnect dance.
        assert_eq!(transport::publish_detailed(&topic, "post-restart"), Ok(()));
        let got = rx.recv_timeout(Duration::from_secs(20)).ok();
        let _ = stream_handle;
        let _ = std::fs::remove_dir_all(home);
        assert_eq!(
            got.as_deref(),
            Some("post-restart"),
            "stream must recover from container restart and deliver post-restart message"
        );
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
        let settings = NatsSettings::current();
        let first = super::block_on(shared_state(&config, &settings)).unwrap();
        let second = super::block_on(shared_state(&config, &settings)).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        let _ = std::fs::remove_dir_all(home);
    }
}
