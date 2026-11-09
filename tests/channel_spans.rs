//! Spans of channel push and the hook dedupe, read with an in-process capture
//! subscriber. Its own test binary: tracing caches callsite interest
//! process-wide, so a parallel test thread could otherwise register a callsite
//! as "never" while the capture is in scope.

mod common;

use agora::channel::{self, Pusher};
use agora::store;
use common::*;
use std::sync::{Arc, Mutex};

/// Recorded `(field, value)` pairs of one span or event.
type FieldLog = Vec<(String, String)>;

/// In-process capture subscriber: span name plus every recorded field.
#[derive(Clone, Default)]
struct Capture {
    spans: Arc<Mutex<Vec<(String, FieldLog)>>>,
}

struct Fields<'a>(&'a mut Vec<(String, String)>);

impl tracing::field::Visit for Fields<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0
            .push((field.name().to_string(), format!("{value:?}")));
    }
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.push((field.name().to_string(), value.to_string()));
    }
}

impl tracing::Subscriber for Capture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        let mut spans = self.spans.lock().unwrap();
        let mut fields = Vec::new();
        attrs.record(&mut Fields(&mut fields));
        spans.push((attrs.metadata().name().to_string(), fields));
        tracing::span::Id::from_u64(spans.len() as u64)
    }
    fn record(&self, span: &tracing::span::Id, values: &tracing::span::Record<'_>) {
        let mut spans = self.spans.lock().unwrap();
        let index = span.into_u64() as usize - 1;
        values.record(&mut Fields(&mut spans[index].1));
    }
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut fields = Vec::new();
        event.record(&mut Fields(&mut fields));
        self.spans
            .lock()
            .unwrap()
            .push(("event".to_string(), fields));
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

fn field<'a>(fields: &'a [(String, String)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .rev()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

#[test]
fn push_and_dedupe_spans_carry_counts_and_kinds_never_text() {
    let home = temp_home("spans");
    setup(&home);
    let secret_text = "the deploy password is hunter2";
    send_as(&home, B, 1000, DM_AB, secret_text);
    send_as(&home, B, 1001, "ops", "chatter nobody addressed");

    let capture = Capture::default();
    tracing::subscriber::with_default(capture.clone(), || {
        pass(&home, &Pusher::new(A), 1002, DM_AB);
        pass(&home, &Pusher::new(A), 1003, "ops");
        let msgs = envelopes(&home, A, 1004, DM_AB);
        let _rt = as_agent(&home, A, 1004);
        let room_id = store::find_room(DM_AB).unwrap().room_id;
        channel::take_undelivered(&room_id, A, msgs);
    });

    let spans = capture.spans.lock().unwrap();
    let pushes: Vec<&Vec<(String, String)>> = spans
        .iter()
        .filter(|(name, _)| name == "agora.channel.push")
        .map(|(_, f)| f)
        .collect();
    assert_eq!(pushes.len(), 2, "{spans:?}");
    assert_eq!(field(pushes[0], "room_kind"), Some("dm"));
    assert_eq!(field(pushes[0], "kind"), Some("dm"));
    assert_eq!(field(pushes[0], "outcome"), Some("pushed"));
    assert_eq!(
        field(pushes[0], "text_len"),
        Some(secret_text.len().to_string().as_str())
    );
    assert_eq!(field(pushes[1], "room_kind"), Some("room"));
    assert_eq!(field(pushes[1], "kind"), Some("none"));
    assert_eq!(field(pushes[1], "outcome"), Some("not_addressed"));

    let dedupe = spans
        .iter()
        .find(|(name, _)| name == "agora.check.dedupe")
        .map(|(_, f)| f)
        .expect("dedupe span");
    assert_eq!(field(dedupe, "messages"), Some("1"));
    assert_eq!(field(dedupe, "suppressed"), Some("1"));

    for (name, fields) in spans.iter() {
        for (key, value) in fields {
            assert!(
                !value.contains("hunter2") && !value.contains("chatter"),
                "{name}.{key} records message text: {value}"
            );
        }
    }
}
