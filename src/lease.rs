//! Generic, signed, TTL-bound leases on named resources.
//!
//! A lease is a room-scoped claim such as `docker`, `repo:agora` or
//! `task:3f9a1c`. Agents publish signed `lease` events and every reader
//! folds the same event log into the same state:
//!
//! ```json
//! {"type": "lease", "action": "acquire|renew|release", "resource": "docker",
//!  "holder": "<agent id>", "lease_id": "<hex>", "expires": 1731000000,
//!  "seq": 1, "reason": "cargo build"}
//! ```
//!
//! Fold rules (see [`fold`]):
//! * events that are not signature-verified, whose `holder` differs from the
//!   signed sender, or whose sender clock is more than
//!   [`MAX_CLOCK_SKEW_SECS`] away from the relay clock are ignored;
//! * events are ordered by relay receipt time, then sender time, sender, seq;
//! * `acquire` succeeds only if the resource is free, expired, or already
//!   held by the same agent;
//! * two acquires that reach the relay within [`SKEW_WINDOW_SECS`] of each
//!   other are concurrent: the lower `(ts, from)` wins regardless of
//!   arrival order. An acquirer therefore waits out the window and re-reads
//!   the log before it reports success;
//! * only the holder may `renew` or `release`. A renew for a resource that
//!   is free (e.g. the original acquire aged out of the relay) re-grants it.

use crate::{chat, runtime, store};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// Longest lease a single acquire/renew can request.
pub const MAX_TTL_SECS: u64 = 24 * 3600;
/// Shortest lease (keeps renew traffic sane).
pub const MIN_TTL_SECS: u64 = 5;
/// Acquires reaching the relay this close together are "concurrent".
pub const SKEW_WINDOW_SECS: u64 = 2;
/// Sender clocks further than this from the relay clock are not trusted.
pub const MAX_CLOCK_SKEW_SECS: u64 = 120;
/// How much relay history a fold reads.
pub const FOLD_WINDOW: &str = "25h";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Acquire,
    Renew,
    Release,
}

impl Action {
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "acquire" => Some(Self::Acquire),
            "renew" => Some(Self::Renew),
            "release" => Some(Self::Release),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Acquire => "acquire",
            Self::Renew => "renew",
            Self::Release => "release",
        }
    }
}

/// A verified lease event extracted from a room envelope.
#[derive(Debug, Clone, PartialEq)]
pub struct LeaseEvent {
    pub id: String,
    pub resource: String,
    pub holder: String,
    pub lease_id: String,
    pub action: Action,
    pub expires: u64,
    pub seq: u64,
    pub reason: Option<String>,
    /// Sender timestamp (signed).
    pub ts: u64,
    /// Relay receipt timestamp (falls back to `ts`).
    pub order_ts: u64,
}

/// Current holder of a resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Lease {
    pub resource: String,
    pub holder: String,
    pub lease_id: String,
    pub expires: u64,
    pub acquired_at: u64,
    pub seq: u64,
    pub reason: Option<String>,
    #[serde(skip)]
    grant_order_ts: u64,
    #[serde(skip)]
    grant_ts: u64,
    #[serde(skip)]
    granted_by_acquire: bool,
}

impl Lease {
    pub fn remaining(&self, now: u64) -> u64 {
        self.expires.saturating_sub(now)
    }
}

/// Validate a resource name: 1-256 chars of `[A-Za-z0-9._:/@~+=,%-]`, e.g.
/// `docker`, `docker:build-cache`, `disk:/`, `path:/var/lib/x`, `container:web-1`.
pub fn validate_resource(resource: &str) -> Result<(), String> {
    let ok = !resource.is_empty()
        && resource.len() <= 256
        && resource
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._:/@~+=,%-".contains(c));
    if ok {
        Ok(())
    } else {
        Err(format!(
            "invalid resource '{resource}' (use 1-256 chars of A-Z a-z 0-9 . _ : / @ ~ + = , % -)"
        ))
    }
}

/// Parse durations like `90s`, `10m`, `2h`, `1d` or bare seconds.
pub fn parse_duration(raw: &str) -> Result<u64, String> {
    let s = raw.trim().to_ascii_lowercase();
    let (num, mult) = if let Some(n) = s.strip_suffix('s') {
        (n, 1)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60)
    } else if let Some(n) = s.strip_suffix('h') {
        (n, 3600)
    } else if let Some(n) = s.strip_suffix('d') {
        (n, 86400)
    } else {
        (s.as_str(), 1)
    };
    num.trim()
        .parse::<u64>()
        .map(|n| n.saturating_mul(mult))
        .map_err(|_| format!("invalid duration '{raw}' (e.g. 30s, 10m, 2h)"))
}

/// Do two resource names overlap? Equal, or one is a `:`/`/` prefix of the
/// other (`docker` overlaps `docker:build`, not `dockerd`).
pub fn overlaps(a: &str, b: &str) -> bool {
    fn prefix(short: &str, long: &str) -> bool {
        long.len() > short.len()
            && long.starts_with(short)
            && matches!(long.as_bytes()[short.len()], b':' | b'/')
    }
    a == b || prefix(a, b) || prefix(b, a)
}

/// Extract a lease event from a decrypted envelope, applying the trust
/// rules (verified signature, holder == sender, bounded clock skew).
pub fn parse_event(env: &Value) -> Option<LeaseEvent> {
    if env["type"].as_str() != Some("lease") || env["_auth"].as_str() != Some("verified") {
        return None;
    }
    let from = env["from"].as_str()?;
    let holder = env["holder"].as_str()?;
    if holder != from {
        return None;
    }
    let resource = env["resource"].as_str()?;
    validate_resource(resource).ok()?;
    let action = Action::parse(env["action"].as_str()?)?;
    let ts = env["ts"].as_u64()?;
    let order_ts = env["_relay_ts"].as_u64().unwrap_or(ts);
    if ts.abs_diff(order_ts) > MAX_CLOCK_SKEW_SECS {
        return None;
    }
    let lease_id = env["lease_id"].as_str().unwrap_or("").to_string();
    if lease_id.is_empty() {
        return None;
    }
    Some(LeaseEvent {
        id: env["id"].as_str().unwrap_or("").to_string(),
        resource: resource.to_string(),
        holder: holder.to_string(),
        lease_id,
        action,
        expires: env["expires"].as_u64().unwrap_or(0),
        seq: env["seq"].as_u64().unwrap_or(0),
        reason: env["reason"].as_str().map(str::to_string),
        ts,
        order_ts,
    })
}

fn capped_expiry(ev: &LeaseEvent) -> u64 {
    ev.expires
        .min(ev.order_ts + MAX_TTL_SECS + MAX_CLOCK_SKEW_SECS)
}

fn grant(ev: &LeaseEvent, by_acquire: bool, prev: Option<&Lease>) -> Lease {
    let same = prev.filter(|l| l.holder == ev.holder && l.lease_id == ev.lease_id);
    Lease {
        resource: ev.resource.clone(),
        holder: ev.holder.clone(),
        lease_id: ev.lease_id.clone(),
        expires: capped_expiry(ev),
        acquired_at: same.map(|l| l.acquired_at).unwrap_or(ev.ts),
        seq: ev.seq,
        reason: ev
            .reason
            .clone()
            .or_else(|| same.and_then(|l| l.reason.clone())),
        grant_order_ts: same.map(|l| l.grant_order_ts).unwrap_or(ev.order_ts),
        grant_ts: same.map(|l| l.grant_ts).unwrap_or(ev.ts),
        granted_by_acquire: same.map(|l| l.granted_by_acquire).unwrap_or(by_acquire),
    }
}

/// Fold lease events into the current lease table (only leases still valid
/// at `now` are returned). Pure and order-independent for a given event set.
pub fn fold(events: &[LeaseEvent], now: u64) -> BTreeMap<String, Lease> {
    let mut sorted: Vec<&LeaseEvent> = events.iter().collect();
    sorted.sort_by(|a, b| {
        (a.order_ts, a.ts, &a.holder, a.seq, &a.id)
            .cmp(&(b.order_ts, b.ts, &b.holder, b.seq, &b.id))
    });

    let mut state: BTreeMap<String, Lease> = BTreeMap::new();
    for ev in sorted {
        let current = state.get(&ev.resource).cloned();
        let live = current.as_ref().filter(|l| l.expires > ev.order_ts);
        match ev.action {
            Action::Acquire => match live {
                None => {
                    state.insert(ev.resource.clone(), grant(ev, true, None));
                }
                Some(l) if l.holder == ev.holder => {
                    state.insert(ev.resource.clone(), grant(ev, true, Some(l)));
                }
                Some(l) => {
                    // Concurrent acquires: lower (ts, from) wins no matter
                    // which one the relay saw first.
                    let concurrent = l.granted_by_acquire
                        && ev.order_ts.saturating_sub(l.grant_order_ts) <= SKEW_WINDOW_SECS;
                    if concurrent && (ev.ts, ev.holder.as_str()) < (l.grant_ts, l.holder.as_str()) {
                        state.insert(ev.resource.clone(), grant(ev, true, None));
                    }
                }
            },
            Action::Renew => match live {
                Some(l) if l.holder == ev.holder => {
                    if l.lease_id == ev.lease_id && ev.seq >= l.seq {
                        state.insert(ev.resource.clone(), grant(ev, false, Some(l)));
                    }
                }
                Some(_) => {}
                None => {
                    // Free (or the acquire aged out of the relay window).
                    state.insert(ev.resource.clone(), grant(ev, false, None));
                }
            },
            Action::Release => {
                if let Some(l) = live
                    && l.holder == ev.holder
                    && l.lease_id == ev.lease_id
                {
                    state.remove(&ev.resource);
                }
            }
        }
    }
    state.retain(|_, l| l.expires > now);
    state
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

/// Fetch the room log from the relay and fold the lease table. Fails closed
/// when the relay is unreachable.
pub fn table(room: &store::RoomEntry) -> Result<BTreeMap<String, Lease>, String> {
    let events = chat::fetch_room_events(room, FOLD_WINDOW)?;
    let parsed: Vec<LeaseEvent> = events.iter().filter_map(parse_event).collect();
    Ok(fold(&parsed, runtime::unix_now()))
}

/// Lease operation failure: either someone else holds the resource, or
/// something else went wrong (relay unreachable, bad input...).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseError {
    Held(Box<Lease>),
    Other(String),
}

impl std::fmt::Display for LeaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Held(l) => write!(
                f,
                "'{}' is held by {} for another {}s{}",
                l.resource,
                l.holder,
                l.remaining(runtime::unix_now()),
                l.reason
                    .as_deref()
                    .map(|r| format!(" ({r})"))
                    .unwrap_or_default()
            ),
            Self::Other(e) => f.write_str(e),
        }
    }
}

impl From<String> for LeaseError {
    fn from(value: String) -> Self {
        Self::Other(value)
    }
}

impl From<LeaseError> for String {
    fn from(value: LeaseError) -> Self {
        value.to_string()
    }
}

/// Result of an acquire attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Acquire {
    Acquired(Lease),
    Held(Lease),
}

fn new_lease_id() -> String {
    use ring::rand::SecureRandom;
    let mut bytes = [0u8; 8];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .expect("RNG failed");
    hex::encode(bytes)
}

fn clamp_ttl(ttl: u64) -> Result<u64, String> {
    if ttl < MIN_TTL_SECS {
        return Err(format!("ttl must be at least {MIN_TTL_SECS}s"));
    }
    Ok(ttl.min(MAX_TTL_SECS))
}

#[allow(clippy::too_many_arguments)]
fn publish(
    room: &store::RoomEntry,
    me: &str,
    resource: &str,
    action: Action,
    lease_id: &str,
    expires: u64,
    seq: u64,
    reason: Option<&str>,
) -> Result<(), String> {
    let now = runtime::unix_now();
    let text = match action {
        Action::Acquire => format!(
            "[lease] {me} acquired {resource} for {}s{}",
            expires.saturating_sub(now),
            reason.map(|r| format!(": {r}")).unwrap_or_default()
        ),
        Action::Renew => format!(
            "[lease] {me} renewed {resource} (+{}s)",
            expires.saturating_sub(now)
        ),
        Action::Release => format!("[lease] {me} released {resource}"),
    };
    chat::publish_event_as(
        room,
        me,
        json!({
            "type": "lease",
            "action": action.as_str(),
            "resource": resource,
            "holder": me,
            "lease_id": lease_id,
            "expires": expires,
            "seq": seq,
            "reason": reason,
        }),
        &text,
    )
    .map(|_| ())
}

/// Active leases overlapping `resource` (exact, parent or child names),
/// those held by agents other than `me` first, exact matches first.
pub fn overlapping(table: &BTreeMap<String, Lease>, resource: &str, me: &str) -> Vec<Lease> {
    let mut out: Vec<Lease> = table
        .values()
        .filter(|l| overlaps(resource, &l.resource))
        .cloned()
        .collect();
    out.sort_by_key(|l| (l.holder == me, l.resource != resource));
    out
}

/// Who blocks `resource`? Returns the most relevant overlapping lease: one
/// held by another agent if any (so `docker` is reported busy while someone
/// holds `docker:build-cache`), else your own, else None (free).
pub fn check(resource: &str, room_label: Option<&str>) -> Result<Option<Lease>, String> {
    validate_resource(resource)?;
    let room = resolve_room(room_label)?;
    let me = store::get_agent_id();
    Ok(overlapping(&table(&room)?, resource, &me)
        .into_iter()
        .next())
}

/// List active leases in the room.
pub fn list(room_label: Option<&str>) -> Result<Vec<Lease>, String> {
    let room = resolve_room(room_label)?;
    Ok(table(&room)?.into_values().collect())
}

/// Acquire `resource` for `ttl_secs`. Publishes an acquire event, waits out
/// the concurrency window (`settle_secs`) and re-reads the log, so a returned
/// [`Acquire::Acquired`] has survived concurrent contenders.
pub fn acquire(
    resource: &str,
    ttl_secs: u64,
    reason: Option<&str>,
    settle_secs: u64,
    room_label: Option<&str>,
) -> Result<Acquire, String> {
    acquire_as(
        &store::get_agent_id(),
        resource,
        ttl_secs,
        reason,
        settle_secs,
        room_label,
    )
}

/// [`acquire`] on behalf of `me` (an identity this process signs for, e.g.
/// the verified caller of the HTTP API).
pub fn acquire_as(
    me: &str,
    resource: &str,
    ttl_secs: u64,
    reason: Option<&str>,
    settle_secs: u64,
    room_label: Option<&str>,
) -> Result<Acquire, String> {
    validate_resource(resource)?;
    let ttl = clamp_ttl(ttl_secs)?;
    let room = resolve_room(room_label)?;
    let now = runtime::unix_now();

    let mut current_table = table(&room)?;
    // Overlapping leases held by others (e.g. docker:images while asking for
    // docker) block the acquire up front; exact-name races are settled by
    // the fold.
    if let Some(blocker) = overlapping(&current_table, resource, me)
        .into_iter()
        .find(|l| l.holder != me && l.resource != resource)
    {
        return Ok(Acquire::Held(blocker));
    }
    let current = current_table.remove(resource);
    let (lease_id, seq) = match &current {
        Some(l) if l.holder != me => return Ok(Acquire::Held(l.clone())),
        Some(l) => (l.lease_id.clone(), l.seq + 1),
        None => (new_lease_id(), 1),
    };
    publish(
        &room,
        me,
        resource,
        Action::Acquire,
        &lease_id,
        now + ttl,
        seq,
        reason,
    )?;

    if settle_secs > 0 {
        runtime::sleep(std::time::Duration::from_secs(settle_secs));
    }
    match table(&room)?.remove(resource) {
        Some(l) if l.holder == me && l.lease_id == lease_id => Ok(Acquire::Acquired(l)),
        Some(l) => Ok(Acquire::Held(l)),
        None => Err(format!(
            "acquire of '{resource}' was published but is not visible on the relay yet; retry"
        )),
    }
}

/// Extend a lease you hold ([`LeaseError::Held`] if someone else holds it).
pub fn renew(resource: &str, ttl_secs: u64, room_label: Option<&str>) -> Result<Lease, LeaseError> {
    renew_as(&store::get_agent_id(), resource, ttl_secs, None, room_label)
}

/// [`renew`] on behalf of `me`, optionally updating the reason.
pub fn renew_as(
    me: &str,
    resource: &str,
    ttl_secs: u64,
    reason: Option<&str>,
    room_label: Option<&str>,
) -> Result<Lease, LeaseError> {
    validate_resource(resource)?;
    let ttl = clamp_ttl(ttl_secs)?;
    let room = resolve_room(room_label)?;
    let current = table(&room)?.remove(resource);
    let (lease_id, seq) = match &current {
        Some(l) if l.holder == me => (l.lease_id.clone(), l.seq + 1),
        Some(l) => return Err(LeaseError::Held(Box::new(l.clone()))),
        None => (new_lease_id(), 1),
    };
    let expires = runtime::unix_now() + ttl;
    publish(
        &room,
        me,
        resource,
        Action::Renew,
        &lease_id,
        expires,
        seq,
        reason,
    )?;
    match table(&room)?.remove(resource) {
        Some(l) if l.holder == me => Ok(l),
        Some(l) => Err(LeaseError::Held(Box::new(l))),
        None => Err(LeaseError::Other(format!(
            "renew of '{resource}' not visible on the relay yet; retry"
        ))),
    }
}

/// Release a lease you hold. Returns Ok(false) if it was already free.
pub fn release(resource: &str, room_label: Option<&str>) -> Result<bool, LeaseError> {
    release_as(&store::get_agent_id(), resource, room_label)
}

/// [`release`] on behalf of `me`.
pub fn release_as(me: &str, resource: &str, room_label: Option<&str>) -> Result<bool, LeaseError> {
    validate_resource(resource)?;
    let room = resolve_room(room_label)?;
    match table(&room)?.remove(resource) {
        None => Ok(false),
        Some(l) if l.holder != me => Err(LeaseError::Held(Box::new(l))),
        Some(l) => {
            publish(
                &room,
                me,
                resource,
                Action::Release,
                &l.lease_id,
                runtime::unix_now(),
                l.seq + 1,
                None,
            )?;
            Ok(true)
        }
    }
}

/// Release lease `lease_id` on `resource` although another agent id holds it: a lease stranded
/// when its holder's window reconnected under a new id. Only for ids this host signs for
/// ([`store::has_local_signing_key`]); the release is published as the holder, so every reader
/// folds it like an ordinary release, and `me` posts who released it and why. Naming the exact
/// lease id keeps a newer lease on the same resource from being released by mistake.
pub fn release_stranded(
    me: &str,
    resource: &str,
    lease_id: &str,
    reason: &str,
    room_label: Option<&str>,
) -> Result<Lease, LeaseError> {
    validate_resource(resource)?;
    if reason.trim().is_empty() {
        return Err(LeaseError::Other("say why with --reason (it is posted to the room)".into()));
    }
    let room = resolve_room(room_label)?;
    let l = match table(&room)?.remove(resource) {
        None => return Err(LeaseError::Other(format!("{resource} is not held"))),
        Some(l) if l.lease_id != lease_id => {
            return Err(LeaseError::Other(format!(
                "{resource} is now held under lease {} by {}, not {lease_id}",
                l.lease_id, l.holder
            )));
        }
        Some(l) => l,
    };
    if l.holder != me && !store::has_local_signing_key(&l.holder) {
        return Err(LeaseError::Other(format!(
            "{} did not take this lease on this host: ask them to release it, or wait {}s for it to expire",
            l.holder,
            l.remaining(runtime::unix_now())
        )));
    }
    publish(
        &room,
        &l.holder,
        resource,
        Action::Release,
        &l.lease_id,
        runtime::unix_now(),
        l.seq + 1,
        Some(reason),
    )?;
    if l.holder != me {
        chat::send(
            &format!(
                "[lease] {me} released {resource} (lease {}) held by {} on its behalf: {reason}",
                l.lease_id, l.holder
            ),
            None,
            Some(&room.room_id),
        )?;
    }
    Ok(l)
}

/// Leases currently held by `agent_id` that overlap any of `resources`.
pub fn overlapping_held_by(
    table: &BTreeMap<String, Lease>,
    agent_id: &str,
    resources: &[String],
) -> Vec<Lease> {
    table
        .values()
        .filter(|l| l.holder == agent_id && resources.iter().any(|r| overlaps(r, &l.resource)))
        .cloned()
        .collect()
}

/// Is this envelope a lease event (hidden from chat output)?
pub fn is_lease_event(env: &Value) -> bool {
    env["type"].as_str() == Some("lease")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(
        resource: &str,
        holder: &str,
        action: Action,
        lease_id: &str,
        ts: u64,
        expires: u64,
        seq: u64,
    ) -> LeaseEvent {
        LeaseEvent {
            id: format!("{holder}-{ts}-{seq}-{}", action.as_str()),
            resource: resource.into(),
            holder: holder.into(),
            lease_id: lease_id.into(),
            action,
            expires,
            seq,
            reason: None,
            ts,
            order_ts: ts,
        }
    }

    #[test]
    fn acquire_on_free_resource_grants() {
        let t = fold(
            &[ev("docker", "a", Action::Acquire, "l1", 100, 700, 1)],
            200,
        );
        assert_eq!(t["docker"].holder, "a");
        assert_eq!(t["docker"].expires, 700);
    }

    #[test]
    fn second_acquire_is_rejected_while_held() {
        let t = fold(
            &[
                ev("docker", "a", Action::Acquire, "l1", 100, 700, 1),
                ev("docker", "b", Action::Acquire, "l2", 150, 900, 1),
            ],
            200,
        );
        assert_eq!(t["docker"].holder, "a");
    }

    #[test]
    fn expired_lease_can_be_taken() {
        let t = fold(
            &[
                ev("docker", "a", Action::Acquire, "l1", 100, 160, 1),
                ev("docker", "b", Action::Acquire, "l2", 170, 900, 1),
            ],
            200,
        );
        assert_eq!(t["docker"].holder, "b");
    }

    #[test]
    fn expired_leases_are_not_reported() {
        let t = fold(
            &[ev("docker", "a", Action::Acquire, "l1", 100, 160, 1)],
            200,
        );
        assert!(t.is_empty());
    }

    #[test]
    fn concurrent_acquires_lower_ts_then_from_wins_regardless_of_arrival() {
        // b's acquire reached the relay first but a's has the lower (ts, from).
        let mut a = ev("docker", "a", Action::Acquire, "la", 100, 700, 1);
        let mut b = ev("docker", "b", Action::Acquire, "lb", 101, 700, 1);
        a.order_ts = 102;
        b.order_ts = 101;
        let t = fold(&[a.clone(), b.clone()], 103);
        assert_eq!(t["docker"].holder, "a");
        // Same sender timestamp: tie broken by agent id.
        let mut c = ev("docker", "zed", Action::Acquire, "lz", 100, 700, 1);
        c.order_ts = 100;
        let mut d = ev("docker", "amy", Action::Acquire, "ly", 100, 700, 1);
        d.order_ts = 101;
        assert_eq!(fold(&[c, d], 102)["docker"].holder, "amy");
    }

    #[test]
    fn acquires_outside_skew_window_do_not_preempt() {
        let a = ev("docker", "b", Action::Acquire, "lb", 100, 700, 1);
        // Lower ts but reached the relay well after the window: rejected.
        let mut late = ev("docker", "a", Action::Acquire, "la", 99, 700, 1);
        late.order_ts = 100 + SKEW_WINDOW_SECS + 5;
        assert_eq!(fold(&[a.clone(), late.clone()], 120)["docker"].holder, "b");
        // ...but inside the window the same event would have won.
        late.order_ts = 100 + SKEW_WINDOW_SECS;
        assert_eq!(fold(&[a, late], 120)["docker"].holder, "a");
    }

    #[test]
    fn only_holder_can_renew_or_release() {
        let t = fold(
            &[
                ev("docker", "a", Action::Acquire, "l1", 100, 200, 1),
                ev("docker", "b", Action::Renew, "l2", 110, 900, 1),
                ev("docker", "b", Action::Release, "l1", 111, 111, 2),
            ],
            150,
        );
        assert_eq!(t["docker"].holder, "a");
        assert_eq!(t["docker"].expires, 200);

        let t = fold(
            &[
                ev("docker", "a", Action::Acquire, "l1", 100, 200, 1),
                ev("docker", "a", Action::Renew, "l1", 150, 400, 2),
            ],
            300,
        );
        assert_eq!(t["docker"].expires, 400);
        assert_eq!(t["docker"].acquired_at, 100);

        let t = fold(
            &[
                ev("docker", "a", Action::Acquire, "l1", 100, 200, 1),
                ev("docker", "a", Action::Release, "l1", 150, 150, 2),
                ev("docker", "b", Action::Acquire, "l2", 160, 400, 1),
            ],
            170,
        );
        assert_eq!(t["docker"].holder, "b");
    }

    #[test]
    fn renew_regrants_when_acquire_aged_out() {
        let t = fold(&[ev("docker", "a", Action::Renew, "l1", 100, 400, 7)], 200);
        assert_eq!(t["docker"].holder, "a");
    }

    #[test]
    fn unverified_or_forged_events_are_ignored() {
        let mut env = json!({
            "type": "lease", "action": "acquire", "resource": "docker",
            "holder": "a", "from": "a", "lease_id": "l1", "expires": 999,
            "seq": 1, "ts": 100, "id": "m1", "_auth": "unsigned"
        });
        assert!(parse_event(&env).is_none());
        env["_auth"] = json!("verified");
        assert!(parse_event(&env).is_some());
        env["holder"] = json!("b"); // signed by a, claims to be b
        assert!(parse_event(&env).is_none());
        env["holder"] = json!("a");
        env["_relay_ts"] = json!(100 + MAX_CLOCK_SKEW_SECS + 1);
        assert!(parse_event(&env).is_none(), "sender clock too far off");
        env["_relay_ts"] = json!(101);
        env["resource"] = json!("bad resource!");
        assert!(parse_event(&env).is_none());
    }

    #[test]
    fn ttl_is_capped() {
        let t = fold(
            &[ev("docker", "a", Action::Acquire, "l1", 100, u64::MAX, 1)],
            200,
        );
        assert_eq!(
            t["docker"].expires,
            100 + MAX_TTL_SECS + MAX_CLOCK_SKEW_SECS
        );
    }

    #[test]
    fn resource_names_used_by_vigil_are_valid() {
        for r in [
            "docker",
            "docker:build-cache",
            "docker:images",
            "mbx",
            "journal",
            "disk:/",
            "container:web-1",
            "path:/var/lib/vigil/freeze",
            "path:~/code/agora",
            "task:3f9a1c",
        ] {
            assert!(validate_resource(r).is_ok(), "{r}");
        }
        for r in ["", "has space", "quote\"", "semi;colon", "back\\slash"] {
            assert!(validate_resource(r).is_err(), "{r:?}");
        }
    }

    #[test]
    fn overlapping_prefers_other_holders_and_exact_names() {
        let t = fold(
            &[
                ev("docker", "me", Action::Acquire, "l1", 100, 900, 1),
                ev("docker:images", "other", Action::Acquire, "l2", 101, 900, 1),
                ev("dockerd", "other", Action::Acquire, "l3", 102, 900, 1),
            ],
            200,
        );
        let o = overlapping(&t, "docker", "me");
        assert_eq!(o.len(), 2, "dockerd does not overlap docker");
        assert_eq!(o[0].holder, "other");
        assert_eq!(o[1].holder, "me");
        assert!(overlapping(&t, "disk:/", "me").is_empty());
    }

    #[test]
    fn overlap_rules() {
        assert!(overlaps("docker", "docker"));
        assert!(overlaps("docker", "docker:build"));
        assert!(overlaps("repo/agora", "repo"));
        assert!(!overlaps("docker", "dockerd"));
        assert!(!overlaps("docker", "podman"));
    }

    #[test]
    fn duration_parsing() {
        assert_eq!(parse_duration("90s").unwrap(), 90);
        assert_eq!(parse_duration("10m").unwrap(), 600);
        assert_eq!(parse_duration("2h").unwrap(), 7200);
        assert_eq!(parse_duration("45").unwrap(), 45);
        assert!(parse_duration("soon").is_err());
    }
}
