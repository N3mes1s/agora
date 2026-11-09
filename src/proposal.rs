//! Propose / HOLD: announce a risky action, give other agents a window to
//! object, then proceed only if nobody did.
//!
//! ```json
//! {"type": "proposal",  "proposal_id": "<hex>", "action": "restart docker",
//!  "resources": ["docker"], "deadline": 1731000300}
//! {"type": "objection", "proposal_id": "<hex>", "reason": "building, 5 more min"}
//! {"type": "ack",       "proposal_id": "<hex>", "note": "fine by me"}
//! ```
//!
//! Only signature-verified events count. An objection counts if it reached
//! the relay before the deadline. A proposal is also held by any active
//! lease on an overlapping resource held by someone other than the
//! proposer, and agents that hold such a lease object automatically when
//! their `agora check` processes the proposal.

use crate::lease::{self, overlaps, validate_resource};
use crate::{chat, runtime, store};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const MIN_WAIT_SECS: u64 = 5;
pub const MAX_WAIT_SECS: u64 = 24 * 3600;
const FOLD_WINDOW: &str = "25h";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Objection {
    pub from: String,
    pub reason: String,
    pub ts: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Proposal {
    pub id: String,
    pub proposer: String,
    pub action: String,
    pub resources: Vec<String>,
    pub deadline: u64,
    pub created_at: u64,
    pub objections: Vec<Objection>,
    pub acks: Vec<(String, Option<String>)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Deadline not reached, no objection yet.
    Open,
    /// At least one verified objection (or a conflicting lease).
    Held,
    /// Deadline passed without objection: go ahead.
    Clear,
}

impl Proposal {
    pub fn status(&self, now: u64) -> Status {
        if !self.objections.is_empty() {
            Status::Held
        } else if now >= self.deadline {
            Status::Clear
        } else {
            Status::Open
        }
    }

    pub fn short_id(&self) -> &str {
        &self.id[..self.id.len().min(6)]
    }
}

fn verified(env: &Value) -> Option<&str> {
    if env["_auth"].as_str() != Some("verified") {
        return None;
    }
    env["from"].as_str()
}

fn relay_ts(env: &Value) -> u64 {
    env["_relay_ts"]
        .as_u64()
        .or_else(|| env["ts"].as_u64())
        .unwrap_or(0)
}

/// Fold proposal/objection/ack events (decrypted envelopes) into proposals.
pub fn fold(events: &[Value]) -> BTreeMap<String, Proposal> {
    let mut out: BTreeMap<String, Proposal> = BTreeMap::new();
    for env in events {
        if env["type"].as_str() != Some("proposal") {
            continue;
        }
        let Some(from) = verified(env) else { continue };
        let Some(id) = env["proposal_id"].as_str() else {
            continue;
        };
        let resources: Vec<String> = env["resources"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|r| r.as_str())
                    .filter(|r| validate_resource(r).is_ok())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let created_at = env["ts"].as_u64().unwrap_or(0);
        let deadline = env["deadline"]
            .as_u64()
            .unwrap_or(0)
            .min(relay_ts(env) + MAX_WAIT_SECS);
        out.entry(id.to_string()).or_insert_with(|| Proposal {
            id: id.to_string(),
            proposer: from.to_string(),
            action: env["action"].as_str().unwrap_or("").to_string(),
            resources,
            deadline,
            created_at,
            objections: Vec::new(),
            acks: Vec::new(),
        });
    }
    for env in events {
        let kind = env["type"].as_str();
        if !matches!(kind, Some("objection") | Some("ack")) {
            continue;
        }
        let Some(from) = verified(env) else { continue };
        let Some(p) = env["proposal_id"].as_str().and_then(|id| out.get_mut(id)) else {
            continue;
        };
        if kind == Some("objection") {
            if relay_ts(env) > p.deadline {
                continue; // too late to hold
            }
            if p.objections.iter().any(|o| o.from == from) {
                continue;
            }
            p.objections.push(Objection {
                from: from.to_string(),
                reason: env["reason"].as_str().unwrap_or("").to_string(),
                ts: env["ts"].as_u64().unwrap_or(0),
            });
        } else if !p.acks.iter().any(|(f, _)| f == from) {
            p.acks
                .push((from.to_string(), env["note"].as_str().map(str::to_string)));
        }
    }
    out
}

/// Conflicting leases: active leases overlapping the proposal's resources
/// held by anyone other than the proposer.
pub fn conflicting_leases(
    p: &Proposal,
    table: &BTreeMap<String, lease::Lease>,
) -> Vec<lease::Lease> {
    table
        .values()
        .filter(|l| l.holder != p.proposer && p.resources.iter().any(|r| overlaps(r, &l.resource)))
        .cloned()
        .collect()
}

fn resolve_room(room_label: Option<&str>) -> Result<store::RoomEntry, String> {
    let room = match room_label {
        Some(l) => store::find_room(l),
        None => store::get_active_room(),
    };
    room.ok_or_else(|| match room_label {
        Some(l) => format!("Room '{l}' not found. Run: agora rooms"),
        None => "No active room. Use 'agora create' or 'agora accept' first.".to_string(),
    })
}

fn load(room: &store::RoomEntry) -> Result<(BTreeMap<String, Proposal>, Vec<Value>), String> {
    let events = chat::fetch_room_events(room, FOLD_WINDOW)?;
    Ok((fold(&events), events))
}

/// The verified proposer of proposal `id` (exact id) in `room`, if it is
/// within the fold window.
pub fn proposer_of(room: &store::RoomEntry, id: &str) -> Result<Option<String>, String> {
    let (props, _) = load(room)?;
    Ok(props.get(id).map(|p| p.proposer.clone()))
}

fn find<'a>(props: &'a BTreeMap<String, Proposal>, id: &str) -> Result<&'a Proposal, String> {
    let matches: Vec<&Proposal> = props.values().filter(|p| p.id.starts_with(id)).collect();
    match matches.as_slice() {
        [one] => Ok(one),
        [] => Err(format!("No proposal matching '{id}'")),
        _ => Err(format!("Proposal id '{id}' is ambiguous")),
    }
}

fn new_id() -> String {
    use ring::rand::SecureRandom;
    let mut bytes = [0u8; 6];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .expect("RNG failed");
    hex::encode(bytes)
}

fn hhmmss(ts: u64) -> String {
    chrono::DateTime::from_timestamp(ts as i64, 0)
        .map(|d| {
            d.with_timezone(&chrono::Local)
                .format("%H:%M:%S")
                .to_string()
        })
        .unwrap_or_default()
}

/// Announce an action on `resources`; others may object until now + wait.
pub fn propose(
    action: &str,
    resources: &[String],
    wait_secs: u64,
    room_label: Option<&str>,
) -> Result<Proposal, String> {
    let action = action.trim();
    if action.is_empty() {
        return Err("describe the action, e.g. agora propose \"restart docker\"".to_string());
    }
    for r in resources {
        validate_resource(r)?;
    }
    if !(MIN_WAIT_SECS..=MAX_WAIT_SECS).contains(&wait_secs) {
        return Err(format!(
            "--wait must be between {MIN_WAIT_SECS}s and {}h",
            MAX_WAIT_SECS / 3600
        ));
    }
    let room = resolve_room(room_label)?;
    let me = store::get_agent_id();
    let now = runtime::unix_now();
    let id = new_id();
    let deadline = now + wait_secs;
    let text = format!(
        "[proposal {}] {me} wants to: {action} (resources: {}; deadline {}). Object with: agora hold {} --reason \"...\"",
        &id[..6],
        if resources.is_empty() {
            "-".to_string()
        } else {
            resources.join(", ")
        },
        hhmmss(deadline),
        &id[..6],
    );
    chat::publish_event_in(
        &room,
        json!({
            "type": "proposal",
            "proposal_id": id,
            "action": action,
            "resources": resources,
            "deadline": deadline,
        }),
        &text,
    )?;
    Ok(Proposal {
        id,
        proposer: me,
        action: action.to_string(),
        resources: resources.to_vec(),
        deadline,
        created_at: now,
        objections: Vec::new(),
        acks: Vec::new(),
    })
}

/// Object to (HOLD) a proposal.
pub fn hold(id: &str, reason: &str, room_label: Option<&str>) -> Result<Proposal, String> {
    let room = resolve_room(room_label)?;
    let (props, _) = load(&room)?;
    let p = find(&props, id)?.clone();
    if runtime::unix_now() > p.deadline {
        return Err(format!(
            "proposal {} already passed its deadline ({})",
            p.short_id(),
            hhmmss(p.deadline)
        ));
    }
    publish_objection(&room, &p, reason)?;
    Ok(p)
}

fn publish_objection(room: &store::RoomEntry, p: &Proposal, reason: &str) -> Result<(), String> {
    let me = store::get_agent_id();
    let reason = if reason.trim().is_empty() {
        "no reason given"
    } else {
        reason.trim()
    };
    chat::publish_event_in(
        room,
        json!({"type": "objection", "proposal_id": p.id, "reason": reason}),
        &format!(
            "[hold {}] {me} objects to \"{}\": {reason}",
            p.short_id(),
            p.action
        ),
    )
    .map(|_| ())
}

/// Acknowledge a proposal (informational; does not shorten the deadline).
pub fn ack(id: &str, note: Option<&str>, room_label: Option<&str>) -> Result<Proposal, String> {
    let room = resolve_room(room_label)?;
    let (props, _) = load(&room)?;
    let p = find(&props, id)?.clone();
    let me = store::get_agent_id();
    chat::publish_event_in(
        &room,
        json!({"type": "ack", "proposal_id": p.id, "note": note}),
        &format!(
            "[ack {}] {me}: ok to \"{}\"{}",
            p.short_id(),
            p.action,
            note.map(|n| format!(" — {n}")).unwrap_or_default()
        ),
    )?;
    Ok(p)
}

/// Proposals in the room (newest first) with their status.
pub fn list(room_label: Option<&str>) -> Result<Vec<(Proposal, Status)>, String> {
    let room = resolve_room(room_label)?;
    let (props, _) = load(&room)?;
    let table = lease::table(&room)?;
    let now = runtime::unix_now();
    let mut out: Vec<(Proposal, Status)> = props
        .into_values()
        .map(|p| {
            let mut status = p.status(now);
            if status != Status::Held && !conflicting_leases(&p, &table).is_empty() {
                status = Status::Held;
            }
            (p, status)
        })
        .collect();
    out.sort_by_key(|(p, _)| std::cmp::Reverse(p.created_at));
    Ok(out)
}

/// Outcome of waiting on a proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Deadline passed, no objection, no conflicting lease.
    Clear(Proposal),
    /// Held: objections and/or conflicting leases (human-readable reasons).
    Held(Proposal, Vec<String>),
}

/// Evaluate a proposal once. Returns None while it is still open.
pub fn evaluate(id: &str, room_label: Option<&str>) -> Result<Option<Decision>, String> {
    let room = resolve_room(room_label)?;
    let (props, _) = load(&room)?;
    let p = find(&props, id)?.clone();
    let table = lease::table(&room)?;
    let now = runtime::unix_now();
    let mut reasons: Vec<String> = p
        .objections
        .iter()
        .map(|o| format!("{} objected: {}", o.from, o.reason))
        .collect();
    for l in conflicting_leases(&p, &table) {
        reasons.push(format!(
            "{} holds lease on {} for another {}s{}",
            l.holder,
            l.resource,
            l.remaining(now),
            l.reason
                .as_deref()
                .map(|r| format!(" ({r})"))
                .unwrap_or_default()
        ));
    }
    if !reasons.is_empty() {
        return Ok(Some(Decision::Held(p, reasons)));
    }
    if now >= p.deadline {
        return Ok(Some(Decision::Clear(p)));
    }
    Ok(None)
}

/// Block until the proposal is decided (polling every `poll_secs`).
pub fn wait(id: &str, poll_secs: u64, room_label: Option<&str>) -> Result<Decision, String> {
    loop {
        if let Some(decision) = evaluate(id, room_label)? {
            return Ok(decision);
        }
        let room = resolve_room(room_label)?;
        let (props, _) = load(&room)?;
        let deadline = find(&props, id)?.deadline;
        let left = deadline.saturating_sub(runtime::unix_now());
        runtime::sleep(std::time::Duration::from_secs(
            left.clamp(1, poll_secs.max(1)),
        ));
    }
}

/// Called by `agora check` for each new proposal from another agent: if we
/// hold a lease that overlaps the proposal's resources, object automatically.
/// Returns the objection reason when one was published.
pub fn auto_object(room: &store::RoomEntry, env: &Value) -> Option<String> {
    if env["type"].as_str() != Some("proposal") {
        return None;
    }
    let me = store::get_agent_id();
    let proposer = verified(env)?;
    if proposer == me {
        return None;
    }
    let props = fold(std::slice::from_ref(env));
    let p = props.values().next()?.clone();
    if runtime::unix_now() > p.deadline {
        return None;
    }
    let table = lease::table(room).ok()?;
    let mine = lease::overlapping_held_by(&table, &me, &p.resources);
    if mine.is_empty() {
        return None;
    }
    let now = runtime::unix_now();
    let reason = format!(
        "auto-hold: I hold {} for another {}s{}",
        mine.iter()
            .map(|l| l.resource.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        mine.iter().map(|l| l.remaining(now)).max().unwrap_or(0),
        mine.iter()
            .find_map(|l| l.reason.as_deref())
            .map(|r| format!(" ({r})"))
            .unwrap_or_default()
    );
    publish_objection(room, &p, &reason).ok()?;
    Some(reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proposal_env(id: &str, from: &str, resources: &[&str], deadline: u64, ts: u64) -> Value {
        json!({
            "type": "proposal", "proposal_id": id, "action": "restart docker",
            "resources": resources, "deadline": deadline, "from": from,
            "ts": ts, "_relay_ts": ts, "_auth": "verified", "id": format!("m-{id}")
        })
    }

    fn objection_env(id: &str, from: &str, ts: u64, auth: &str) -> Value {
        json!({
            "type": "objection", "proposal_id": id, "reason": "building",
            "from": from, "ts": ts, "_relay_ts": ts, "_auth": auth,
            "id": format!("o-{from}-{ts}")
        })
    }

    #[test]
    fn open_then_clear_without_objection() {
        let props = fold(&[proposal_env("p1", "vigil", &["docker"], 400, 100)]);
        let p = &props["p1"];
        assert_eq!(p.proposer, "vigil");
        assert_eq!(p.status(200), Status::Open);
        assert_eq!(p.status(400), Status::Clear);
    }

    #[test]
    fn verified_objection_before_deadline_holds() {
        let props = fold(&[
            proposal_env("p1", "vigil", &["docker"], 400, 100),
            objection_env("p1", "coder-1", 150, "verified"),
        ]);
        assert_eq!(props["p1"].status(500), Status::Held);
        assert_eq!(props["p1"].objections[0].from, "coder-1");
    }

    #[test]
    fn unverified_or_late_objections_do_not_hold() {
        let props = fold(&[
            proposal_env("p1", "vigil", &["docker"], 400, 100),
            objection_env("p1", "coder-1", 150, "unsigned"),
            objection_env("p1", "coder-2", 401, "verified"),
        ]);
        assert_eq!(props["p1"].status(500), Status::Clear);
    }

    #[test]
    fn unverified_proposals_are_ignored() {
        let mut env = proposal_env("p1", "vigil", &["docker"], 400, 100);
        env["_auth"] = json!("unsigned");
        assert!(fold(&[env]).is_empty());
    }

    #[test]
    fn deadline_is_capped() {
        let props = fold(&[proposal_env("p1", "vigil", &[], u64::MAX, 100)]);
        assert_eq!(props["p1"].deadline, 100 + MAX_WAIT_SECS);
    }

    #[test]
    fn conflicting_leases_ignore_the_proposer() {
        let props = fold(&[proposal_env("p1", "vigil", &["docker"], 400, 100)]);
        let events = [
            lease::LeaseEvent {
                id: "a".into(),
                resource: "docker:build".into(),
                holder: "coder-1".into(),
                lease_id: "l1".into(),
                action: lease::Action::Acquire,
                expires: 1000,
                seq: 1,
                reason: Some("cargo build".into()),
                ts: 90,
                order_ts: 90,
            },
            lease::LeaseEvent {
                id: "b".into(),
                resource: "docker".into(),
                holder: "vigil".into(),
                lease_id: "l2".into(),
                action: lease::Action::Acquire,
                expires: 1000,
                seq: 1,
                reason: None,
                ts: 91,
                order_ts: 91,
            },
        ];
        let table = lease::fold(&events, 200);
        let conflicts = conflicting_leases(&props["p1"], &table);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].holder, "coder-1");
    }
}
