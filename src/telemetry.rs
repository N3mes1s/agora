//! Telemetry: the subscriber for agora's `tracing` spans.
//!
//! - Readable with no collector: every span that runs `AGORA_SLOW_SPAN_MS` (default 1000; 0 turns it
//!   off) or longer is written to stderr as one line: its name, how long it took, its parent span and
//!   its fields.
//! - OpenTelemetry: when `OTEL_EXPORTER_OTLP_ENDPOINT` (or `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`) is set,
//!   spans are also exported over OTLP/HTTP (protobuf). `OTEL_SERVICE_NAME` and
//!   `OTEL_RESOURCE_ATTRIBUTES` name the service. Off when unset. Export runs on its own thread in
//!   batches with a short timeout; a collector that is down never blocks or fails a command.
//!
//! Span fields carry counts, kinds, outcomes and agora's own identifiers, never message text.

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::trace::{BatchSpanProcessor, SdkTracerProvider};
use std::fmt::Write as _;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry::LookupSpan;

/// A span at least this long is logged to stderr, unless `AGORA_SLOW_SPAN_MS` says otherwise.
pub const SLOW_SPAN_MS: u64 = 1000;
/// One export attempt never takes longer than this.
const EXPORT_TIMEOUT: Duration = Duration::from_millis(1500);
/// Flushing at exit never takes longer than this.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
/// The slow-span log file starts over after this many bytes.
const SLOW_LOG_MAX_BYTES: u64 = 1024 * 1024;

static PROVIDER: Mutex<Option<SdkTracerProvider>> = Mutex::new(None);

/// The span fields recorded so far, as `name=value` pairs.
#[derive(Default)]
struct Fields(String);

impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if !self.0.is_empty() {
            self.0.push(' ');
        }
        let _ = write!(self.0, "{}={:?}", field.name(), value);
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        if !self.0.is_empty() {
            self.0.push(' ');
        }
        let _ = write!(self.0, "{}={}", field.name(), value);
    }
}

struct Started(Instant);

/// Writes one line to `out` for each span that ran at least `threshold`.
pub struct SlowSpans<W> {
    threshold: Duration,
    out: W,
}

impl<W> SlowSpans<W> {
    pub fn new(threshold: Duration, out: W) -> Self {
        Self { threshold, out }
    }
}

impl<S, W> Layer<S> for SlowSpans<W>
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    W: Fn(&str) + 'static,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let mut fields = Fields::default();
        attrs.record(&mut fields);
        let mut ext = span.extensions_mut();
        ext.insert(fields);
        ext.insert(Started(Instant::now()));
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id)
            && let Some(fields) = span.extensions_mut().get_mut::<Fields>()
        {
            values.record(fields);
        }
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else { return };
        // Our spans only (lead 3263d1 audit: async-nats's internal spans,
        // e.g. 'recreate ordered consumer' at 5001 ms, leak through this
        // layer and spam stderr). Match either the explicit target or the
        // agora-prefixed name (the crate's spans use both forms).
        let ours = span.metadata().target() == "agora"
            || span.name().starts_with("agora.");
        if !ours {
            return;
        }
        let ext = span.extensions();
        let Some(Started(at)) = ext.get::<Started>() else { return };
        let took = at.elapsed();
        if took < self.threshold {
            return;
        }
        let parent = span.parent().map_or("-".to_string(), |p| p.name().to_string());
        let fields = ext.get::<Fields>().map_or("", |f| f.0.as_str());
        // a long-poll command is supposed to wait: its own spans are the job, not a slow spot
        if span.name() == "agora.wait" || (span.name() == "agora.cli" && fields.contains("command=wait")) {
            return;
        }
        (self.out)(&format!("agora: slow span {} took {} ms (in {parent}) {fields}", span.name(), took.as_millis()));
    }
}

fn slow_threshold() -> Option<Duration> {
    let ms = std::env::var("AGORA_SLOW_SPAN_MS").ok().and_then(|v| v.trim().parse::<u64>().ok()).unwrap_or(SLOW_SPAN_MS);
    (ms > 0).then(|| Duration::from_millis(ms))
}

fn otlp_configured() -> bool {
    ["OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"]
        .iter()
        .any(|v| std::env::var(v).is_ok_and(|s| !s.trim().is_empty()))
}

/// The OTLP/HTTP tracer provider, when an endpoint is configured.
fn provider() -> Option<SdkTracerProvider> {
    if !otlp_configured() {
        return None;
    }
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
        .with_timeout(EXPORT_TIMEOUT)
        .build()
        .map_err(|e| {
            use std::io::Write as _;
            let _ = writeln!(std::io::stderr(), "agora: OTLP export disabled: {e}");
        })
        .ok()?;
    // The default detectors read OTEL_SERVICE_NAME and OTEL_RESOURCE_ATTRIBUTES.
    let mut resource = opentelemetry_sdk::Resource::builder();
    if std::env::var("OTEL_SERVICE_NAME").is_err() {
        resource = resource.with_service_name("agora");
    }
    let resource = resource.build();
    Some(
        SdkTracerProvider::builder()
            .with_span_processor(BatchSpanProcessor::builder(exporter).build())
            .with_resource(resource)
            .build(),
    )
}

/// Where telemetry and diagnostics go: a log file, or stderr when `None`. Set once by [`init`].
static DESTINATION: std::sync::OnceLock<Option<std::path::PathBuf>> = std::sync::OnceLock::new();

/// Writes one line to the log file (capped, directory created on first write) or to stderr, never panicking.
fn write_line(dest: &Option<std::path::PathBuf>, line: &str) {
    use std::io::Write as _;
    match dest {
        Some(path) => {
            // a log that only grows is a leak: start over once it passes the cap
            if let Some(dir) = path.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            let too_big = std::fs::metadata(path).is_ok_and(|m| m.len() > SLOW_LOG_MAX_BYTES);
            let mut options = std::fs::OpenOptions::new();
            options.create(true);
            if too_big {
                options.write(true).truncate(true);
            } else {
                options.append(true);
            }
            if let Ok(mut f) = options.open(path) {
                let _ = writeln!(f, "{line}");
            }
        }
        // Never `eprintln!`: it panics when stderr is a pipe whose reader is gone, and this runs from an
        // `atexit` handler where a panic aborts the process.
        None => {
            let _ = writeln!(std::io::stderr(), "{line}");
        }
    }
}

/// A routine diagnostic (a reader retrying an idle stream, for one): goes where slow spans go, so it never
/// lands in a hook's stderr. Failures that need someone's attention keep using `elog!`.
pub fn diag(line: &str) {
    write_line(DESTINATION.get().unwrap_or(&None), line);
}

/// Install the subscriber: the slow-span log, and OTLP export when configured. Call once at startup.
/// `slow_log`: append slow-span lines to this file instead of stderr (`agora tui` owns the terminal).
pub fn init(slow_log: Option<std::path::PathBuf>) {
    let _ = DESTINATION.set(slow_log.clone());
    let slow = slow_threshold().map(|t| {
        SlowSpans::new(t, move |line: &str| write_line(&slow_log, line))
    });
    let otel = provider().map(|p| {
        let layer = tracing_opentelemetry::layer().with_tracer(p.tracer("agora"));
        *PROVIDER.lock().unwrap_or_else(|e| e.into_inner()) = Some(p);
        layer
    });
    let _ = tracing_subscriber::registry().with(slow).with(otel).try_init();
}

/// Flush and stop the OTLP exporter (bounded); a no-op when export is off. Call before exiting.
pub fn shutdown() {
    if let Some(p) = PROVIDER.lock().unwrap_or_else(|e| e.into_inner()).take() {
        let _ = p.shutdown_with_timeout(SHUTDOWN_TIMEOUT);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn a_long_poll_command_is_not_reported_as_slow() {
        let lines = Arc::new(Mutex::new(Vec::<String>::new()));
        let sink = lines.clone();
        let layer = SlowSpans::new(Duration::from_millis(30), move |l: &str| sink.lock().unwrap().push(l.to_string()));
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            let cli = tracing::info_span!("agora.cli", command = "wait");
            let _c = cli.enter();
            tracing::info_span!("agora.wait").in_scope(|| std::thread::sleep(Duration::from_millis(40)));
            tracing::info_span!("agora.wait.rooms", rooms = 3).in_scope(|| std::thread::sleep(Duration::from_millis(40)));
        });
        let lines = lines.lock().unwrap();
        assert!(lines.iter().all(|l| !l.contains("agora.wait took")), "{lines:?}");
        assert!(lines.iter().any(|l| l.contains("agora.wait.rooms")), "the scan is the real work and still counts: {lines:?}");
    }

    #[test]
    fn only_spans_past_the_threshold_are_logged_with_their_fields_and_parent() {
        let lines = Arc::new(Mutex::new(Vec::<String>::new()));
        let sink = lines.clone();
        let layer = SlowSpans::new(Duration::from_millis(30), move |l: &str| sink.lock().unwrap().push(l.to_string()));
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            let outer = tracing::info_span!("agora.cli", command = "check");
            let _o = outer.enter();
            tracing::info_span!("agora.fast", n = 1).in_scope(|| {});
            let slow = tracing::info_span!("agora.slow", rooms = 3, outcome = tracing::field::Empty);
            slow.in_scope(|| std::thread::sleep(Duration::from_millis(40)));
            slow.record("outcome", "ok");
        });
        let lines = lines.lock().unwrap();
        assert!(lines.iter().all(|l| !l.contains("agora.fast")), "{lines:?}");
        let slow = lines.iter().find(|l| l.contains("agora.slow")).expect("slow span logged");
        assert!(slow.contains("(in agora.cli)") && slow.contains("rooms=3") && slow.contains("outcome=ok"), "{slow}");
    }
}
