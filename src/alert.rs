//! Alert ingestion: turn Grafana / Alertmanager webhook payloads into
//! structured `alert` room events.
//!
//! Accepted shapes:
//! * Alertmanager webhook (`version: "4"`, `alerts: [...]`) and Grafana
//!   unified alerting (same shape plus `title`/`message`/`state`).
//! * Legacy Grafana alerting (`ruleName`, `state`, `message`, `tags`).
//!
//! Each alert becomes one room message:
//! `{type: "alert", fingerprint, status, severity, summary, labels, ...}`
//! with a readable `text` line so plain `agora read` shows it too.

use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

/// Upper bound on alerts accepted from a single webhook delivery.
pub const MAX_ALERTS_PER_REQUEST: usize = 50;

#[derive(Debug, Clone, PartialEq)]
pub struct Alert {
    pub fingerprint: String,
    /// `firing` or `resolved` (legacy Grafana `alerting`/`ok` are mapped).
    pub status: String,
    pub severity: String,
    pub summary: String,
    pub labels: BTreeMap<String, String>,
    pub starts_at: Option<String>,
    pub generator_url: Option<String>,
}

impl Alert {
    pub fn alertname(&self) -> &str {
        self.labels
            .get("alertname")
            .map(String::as_str)
            .unwrap_or("alert")
    }

    /// Readable single-line rendering used as the message `text`.
    pub fn text(&self) -> String {
        let fp: String = self.fingerprint.chars().take(8).collect();
        format!(
            "[alert {} {}] {}: {} (fp {fp})",
            self.status.to_uppercase(),
            self.severity,
            self.alertname(),
            self.summary
        )
    }

    /// Structured fields merged into the room envelope.
    pub fn fields(&self) -> Value {
        json!({
            "type": "alert",
            "fingerprint": self.fingerprint,
            "status": self.status,
            "severity": self.severity,
            "summary": self.summary,
            "labels": self.labels,
            "starts_at": self.starts_at,
            "generator_url": self.generator_url,
        })
    }
}

fn str_map(v: &Value) -> BTreeMap<String, String> {
    v.as_object()
        .map(|o| {
            o.iter()
                .map(|(k, v)| {
                    let val = v
                        .as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| v.to_string());
                    (k.clone(), val)
                })
                .collect()
        })
        .unwrap_or_default()
}

fn fingerprint_for(labels: &BTreeMap<String, String>) -> String {
    let mut input = String::new();
    for (k, v) in labels {
        input.push_str(k);
        input.push('=');
        input.push_str(v);
        input.push('\n');
    }
    let digest = ring::digest::digest(&ring::digest::SHA256, input.as_bytes());
    hex::encode(&digest.as_ref()[..8])
}

fn clip(s: &str, max: usize) -> String {
    let s = s.trim().replace(['\n', '\r'], " ");
    if s.chars().count() <= max {
        s
    } else {
        let mut out: String = s.chars().take(max).collect();
        out.push('…');
        out
    }
}

fn normalize_status(raw: &str) -> String {
    match raw.trim().to_ascii_lowercase().as_str() {
        "resolved" | "ok" | "normal" | "inactive" => "resolved".to_string(),
        "pending" => "pending".to_string(),
        _ => "firing".to_string(),
    }
}

fn one_alert(
    a: &Value,
    common_labels: &Map<String, Value>,
    common_ann: &Map<String, Value>,
) -> Alert {
    let mut labels = str_map(&Value::Object(common_labels.clone()));
    labels.extend(str_map(&a["labels"]));
    let mut ann = str_map(&Value::Object(common_ann.clone()));
    ann.extend(str_map(&a["annotations"]));
    let severity = labels
        .get("severity")
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());
    let summary = ann
        .get("summary")
        .or_else(|| ann.get("description"))
        .or_else(|| ann.get("message"))
        .cloned()
        .or_else(|| a["valueString"].as_str().map(str::to_string))
        .unwrap_or_else(|| labels.get("alertname").cloned().unwrap_or_default());
    let fingerprint = a["fingerprint"]
        .as_str()
        .filter(|f| !f.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| fingerprint_for(&labels));
    Alert {
        fingerprint,
        status: normalize_status(a["status"].as_str().unwrap_or("firing")),
        severity: clip(&severity, 32),
        summary: clip(&summary, 400),
        labels,
        starts_at: a["startsAt"].as_str().map(str::to_string),
        generator_url: a["generatorURL"].as_str().map(str::to_string),
    }
}

/// Parse a Grafana / Alertmanager webhook body.
pub fn parse_webhook(body: &Value) -> Result<Vec<Alert>, String> {
    let empty = Map::new();
    if let Some(alerts) = body["alerts"].as_array() {
        if alerts.is_empty() {
            return Err("webhook contains no alerts".to_string());
        }
        if alerts.len() > MAX_ALERTS_PER_REQUEST {
            return Err(format!(
                "too many alerts in one request ({} > {MAX_ALERTS_PER_REQUEST})",
                alerts.len()
            ));
        }
        let common_labels = body["commonLabels"].as_object().unwrap_or(&empty);
        let common_ann = body["commonAnnotations"].as_object().unwrap_or(&empty);
        return Ok(alerts
            .iter()
            .map(|a| one_alert(a, common_labels, common_ann))
            .collect());
    }

    // Legacy Grafana alerting notification.
    if body["ruleName"].is_string() || body["state"].is_string() {
        let mut labels = str_map(&body["tags"]);
        let name = body["ruleName"]
            .as_str()
            .or_else(|| body["title"].as_str())
            .unwrap_or("grafana");
        labels
            .entry("alertname".to_string())
            .or_insert_with(|| name.to_string());
        let summary = body["message"]
            .as_str()
            .or_else(|| body["title"].as_str())
            .unwrap_or(name)
            .to_string();
        let severity = labels
            .get("severity")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        let fingerprint = body["ruleId"]
            .as_u64()
            .map(|id| format!("grafana-rule-{id}"))
            .unwrap_or_else(|| fingerprint_for(&labels));
        return Ok(vec![Alert {
            fingerprint,
            status: normalize_status(body["state"].as_str().unwrap_or("alerting")),
            severity: clip(&severity, 32),
            summary: clip(&summary, 400),
            labels,
            starts_at: None,
            generator_url: body["ruleUrl"].as_str().map(str::to_string),
        }]);
    }

    Err("unrecognized alert payload (expected Alertmanager/Grafana webhook JSON)".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_alertmanager_payload() {
        let body = json!({
            "version": "4",
            "status": "firing",
            "commonLabels": {"env": "prod"},
            "commonAnnotations": {},
            "alerts": [{
                "status": "firing",
                "labels": {"alertname": "DiskFull", "severity": "critical", "instance": "host-a"},
                "annotations": {"summary": "btrfs / is 91% full"},
                "startsAt": "2026-11-08T07:00:00Z",
                "generatorURL": "http://prometheus/graph",
                "fingerprint": "a1b2c3d4e5f60708"
            }, {
                "status": "resolved",
                "labels": {"alertname": "HighLoad"},
                "annotations": {"description": "load back to normal"}
            }]
        });
        let alerts = parse_webhook(&body).unwrap();
        assert_eq!(alerts.len(), 2);
        let a = &alerts[0];
        assert_eq!(a.fingerprint, "a1b2c3d4e5f60708");
        assert_eq!(a.status, "firing");
        assert_eq!(a.severity, "critical");
        assert_eq!(a.summary, "btrfs / is 91% full");
        assert_eq!(a.labels["env"], "prod");
        assert_eq!(
            a.text(),
            "[alert FIRING critical] DiskFull: btrfs / is 91% full (fp a1b2c3d4)"
        );
        assert_eq!(a.fields()["type"], "alert");
        let b = &alerts[1];
        assert_eq!(b.status, "resolved");
        assert_eq!(b.severity, "unknown");
        assert_eq!(b.summary, "load back to normal");
        assert_eq!(b.fingerprint.len(), 16, "derived fingerprint");
    }

    #[test]
    fn parses_legacy_grafana_payload() {
        let body = json!({
            "ruleId": 7,
            "ruleName": "API latency",
            "state": "alerting",
            "message": "p99 > 2s",
            "tags": {"severity": "warning"}
        });
        let alerts = parse_webhook(&body).unwrap();
        assert_eq!(alerts[0].fingerprint, "grafana-rule-7");
        assert_eq!(alerts[0].status, "firing");
        assert_eq!(alerts[0].severity, "warning");
        assert_eq!(alerts[0].alertname(), "API latency");

        let ok = json!({"ruleId": 7, "ruleName": "API latency", "state": "ok"});
        assert_eq!(parse_webhook(&ok).unwrap()[0].status, "resolved");
    }

    #[test]
    fn rejects_garbage_and_floods() {
        assert!(parse_webhook(&json!({"hello": "world"})).is_err());
        assert!(parse_webhook(&json!({"alerts": []})).is_err());
        let many: Vec<Value> = (0..=MAX_ALERTS_PER_REQUEST)
            .map(|i| json!({"labels": {"alertname": format!("a{i}")}}))
            .collect();
        assert!(parse_webhook(&json!({ "alerts": many })).is_err());
    }

    #[test]
    fn derived_fingerprint_is_stable_and_label_order_independent() {
        let a = parse_webhook(&json!({"alerts": [{"labels": {"b": "2", "a": "1"}}]})).unwrap();
        let b = parse_webhook(&json!({"alerts": [{"labels": {"a": "1", "b": "2"}}]})).unwrap();
        assert_eq!(a[0].fingerprint, b[0].fingerprint);
    }

    #[test]
    fn long_summaries_are_clipped_to_one_line() {
        let long = "x\n".repeat(600);
        let a = parse_webhook(&json!({"alerts": [{"annotations": {"summary": long}}]})).unwrap();
        assert!(!a[0].summary.contains('\n'));
        assert!(a[0].summary.chars().count() <= 401);
    }
}
