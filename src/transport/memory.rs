use super::{
    PublishError, PublishLimits, StreamConfig, StreamCursor, StreamDisconnect, Transport,
    TransportConfig, parse_since_cutoff,
};
use crate::runtime;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

type MemoryRelayStore = HashMap<(String, String, String), Vec<(u64, String)>>;

pub(super) struct MemoryTransport;

impl Transport for MemoryTransport {
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
        let mut relay = relay().lock().unwrap_or_else(|e| e.into_inner());
        relay
            .entry(store_key(config, topic))
            .or_default()
            .push((runtime::unix_now(), payload.to_string()));
        Ok(())
    }

    fn fetch(&self, config: &TransportConfig, topic: &str, since: &str) -> Vec<(u64, String)> {
        let cutoff = parse_since_cutoff(since, runtime::unix_now());
        let relay = relay().lock().unwrap_or_else(|e| e.into_inner());
        relay
            .get(&store_key(config, topic))
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|(ts, _)| *ts >= cutoff)
            .collect()
    }

    fn stream(
        &self,
        config: &TransportConfig,
        topic: &str,
        initial_since: Option<&str>,
        _stream_config: &StreamConfig,
        on_message: &mut dyn FnMut(u64, &str),
        _on_disconnect: &mut dyn FnMut(StreamDisconnect, Option<Duration>),
    ) {
        let mut cursor = initial_since
            .map(|since| StreamCursor::new(parse_since_cutoff(since, runtime::unix_now())));
        for (ts, payload) in self.fetch(config, topic, initial_since.unwrap_or("0")) {
            let should_emit = match cursor.as_mut() {
                Some(cursor) => cursor.should_emit(ts, None, &payload),
                None => true,
            };
            if should_emit {
                on_message(ts, &payload);
            }
        }
    }
}

fn relay() -> &'static Mutex<MemoryRelayStore> {
    static RELAY: OnceLock<Mutex<MemoryRelayStore>> = OnceLock::new();
    RELAY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn namespace() -> String {
    runtime::home_dir()
        .map(|path| path.to_string_lossy().to_string())
        .unwrap_or_else(|| "__agora_memory__".to_string())
}

fn store_key(config: &TransportConfig, topic: &str) -> (String, String, String) {
    (config.relay_url.clone(), namespace(), topic.to_string())
}
