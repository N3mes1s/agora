//! Agora chat engine.
//!
//! Wire format: base64(nonce || AES-256-GCM(envelope_json, aad=room_id))
//!
//! Envelope (plaintext JSON):
//! ```json
//! {
//!     "v": "3.0",
//!     "id": "<8-hex message ID>",
//!     "from": "<agent-id>",
//!     "ts": <unix-timestamp>,
//!     "text": "<message body>",
//!     "reply_to": "<optional parent ID>"
//! }
//! ```

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use ring::{digest, rand::SecureRandom};

use crate::{crypto, store, transport};

const VERSION: &str = "3.0";
const SIGNED_WIRE_VERSION: &str = "3.1";
const SOMA_VOLATILITY_COMMIT_CAP: f64 = 32.0;
const PLAZA_RATE_LIMIT_LABEL: &str = "plaza";
const PLAZA_RATE_LIMIT_MAX_MSGS: usize = 10;
const PLAZA_RATE_LIMIT_WINDOW_SECS: u64 = 60;
const DISCOVERY_POSITIVE_HALF_LIFE_SECS: f64 = 604800.0;
const DISCOVERY_NEGATIVE_HALF_LIFE_SECS: f64 = 1814400.0;
const DISCOVERY_STALE_CLAIM_GRACE_SECS: u64 = 3 * 24 * 60 * 60;
const BASE64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedWirePayload {
    v: String,
    from: String,
    payload: String,
    signing_pubkey: String,
    sig: String,
}

#[derive(Debug, Clone, PartialEq)]
struct SomaVolatility {
    path: Option<String>,
    git_ref: Option<String>,
    churn_commits: Option<u64>,
    churn_decay: Option<f64>,
    effective_confidence: Option<f64>,
}

#[derive(Debug, Clone)]
pub struct DiscoveredCapabilityCard {
    pub room_label: String,
    pub room_id: String,
    pub card: store::AgentCapabilityCard,
    pub overlap: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ListedWorkReceipt {
    pub room_label: String,
    pub receipt: store::WorkReceipt,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn msg_id() -> String {
    let mut bytes = [0u8; 4];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .expect("RNG failed");
    hex::encode(bytes)
}

// ── Envelope ────────────────────────────────────────────────────

fn make_envelope(text: &str, reply_to: Option<&str>) -> serde_json::Value {
    let mut env = json!({
        "v": VERSION,
        "id": msg_id(),
        "from": store::get_agent_id(),
        "ts": now(),
        "text": text,
    });
    if let Some(rt) = reply_to {
        env["reply_to"] = json!(rt);
    }
    env
}

fn make_heartbeat() -> serde_json::Value {
    json!({
        "v": VERSION,
        "id": msg_id(),
        "from": store::get_agent_id(),
        "ts": now(),
        "type": "heartbeat",
        "text": "",
    })
}

fn is_heartbeat(env: &serde_json::Value) -> bool {
    env["type"].as_str() == Some("heartbeat")
}

fn make_receipt(msg_ids: &[String]) -> serde_json::Value {
    json!({
        "v": VERSION,
        "id": msg_id(),
        "from": store::get_agent_id(),
        "ts": now(),
        "type": "receipt",
        "read_ids": msg_ids,
        "text": "",
    })
}

fn is_receipt(env: &serde_json::Value) -> bool {
    env["type"].as_str() == Some("receipt")
}

fn is_work_receipt(env: &serde_json::Value) -> bool {
    env["type"].as_str() == Some("work_receipt")
}

fn is_role_state(env: &serde_json::Value) -> bool {
    env["type"].as_str() == Some("role_state")
}

fn make_reaction(target_id: &str, emoji: &str) -> serde_json::Value {
    json!({
        "v": VERSION,
        "id": msg_id(),
        "from": store::get_agent_id(),
        "ts": now(),
        "type": "reaction",
        "target_id": target_id,
        "emoji": emoji,
        "text": "",
    })
}

fn is_reaction(env: &serde_json::Value) -> bool {
    env["type"].as_str() == Some("reaction")
}

fn auth_warning_id(
    room_id: &str,
    sender: &str,
    signing_pubkey: &str,
    sig: &str,
    reason: &str,
) -> String {
    use ring::digest;
    let input = format!(
        "agora-auth-warning-v1\n{room_id}\n{sender}\n{signing_pubkey}\n{sig}\n{reason}"
    );
    let hash = digest::digest(&digest::SHA256, input.as_bytes());
    format!("auth-{}", hex::encode(&hash.as_ref()[..4]))
}

fn make_auth_warning(
    room_id: &str,
    wire: &SignedWirePayload,
    reason: &str,
    text: String,
) -> serde_json::Value {
    json!({
        "v": VERSION,
        "id": auth_warning_id(room_id, &wire.from, &wire.signing_pubkey, &wire.sig, reason),
        "from": "[auth]",
        "sender": wire.from,
        "ts": 0,
        "type": "auth_warning",
        "auth_reason": reason,
        "text": text,
    })
}

fn is_auth_warning(env: &serde_json::Value) -> bool {
    env["type"].as_str() == Some("auth_warning")
}

fn is_capability_card(env: &serde_json::Value) -> bool {
    env["type"].as_str() == Some("card")
}

fn make_invite_redemption(
    invite_id: &str,
    invite_created_by: Option<&str>,
    invite_max_uses: Option<u32>,
) -> serde_json::Value {
    json!({
        "v": VERSION,
        "id": msg_id(),
        "from": store::get_agent_id(),
        "ts": now(),
        "type": "invite_redeem",
        "invite_id": invite_id,
        "invite_created_by": invite_created_by,
        "invite_max_uses": invite_max_uses,
        "text": "",
    })
}

fn is_invite_redeem(env: &serde_json::Value) -> bool {
    env["type"].as_str() == Some("invite_redeem")
}

fn is_system_msg(env: &serde_json::Value) -> bool {
    is_heartbeat(env)
        || is_receipt(env)
        || is_work_receipt(env)
        || is_role_state(env)
        || is_file_msg(env)
        || is_reaction(env)
        || is_invite_redeem(env)
        || is_capability_card(env)
}

#[derive(Default)]
struct PlazaRateLimitState {
    muted: HashSet<String>,
    recent_by_sender: HashMap<String, VecDeque<u64>>,
    me_is_admin: bool,
}

fn is_public_plaza(room: &store::RoomEntry) -> bool {
    room.label == PLAZA_RATE_LIMIT_LABEL
}

fn counts_toward_plaza_rate_limit(env: &serde_json::Value) -> bool {
    if is_system_msg(env) {
        return false;
    }
    if env["type"].as_str() == Some("profile") {
        return false;
    }
    let from = env["from"].as_str().unwrap_or("");
    !from.is_empty()
}

fn prune_recent(queue: &mut VecDeque<u64>, effective_ts: u64) {
    while let Some(front) = queue.front().copied() {
        if effective_ts.saturating_sub(front) >= PLAZA_RATE_LIMIT_WINDOW_SECS {
            queue.pop_front();
        } else {
            break;
        }
    }
}

fn seed_plaza_rate_limit_state(
    room: &store::RoomEntry,
    existing: &[serde_json::Value],
) -> PlazaRateLimitState {
    let mut state = PlazaRateLimitState {
        muted: store::load_muted(&room.room_id),
        recent_by_sender: HashMap::new(),
        me_is_admin: store::is_admin(&room.room_id, &store::get_agent_id()),
    };

    for env in existing {
        if !counts_toward_plaza_rate_limit(env) {
            continue;
        }
        let from = env["from"].as_str().unwrap_or("");
        if from.is_empty() {
            continue;
        }
        let ts = env["ts"].as_u64().unwrap_or(0);
        let queue = state.recent_by_sender.entry(from.to_string()).or_default();
        prune_recent(queue, ts);
        queue.push_back(ts);
    }

    state
}

fn enforce_outbound_plaza_rate_limit(room: &store::RoomEntry, sender: &str) -> Result<(), String> {
    if !is_public_plaza(room) {
        return Ok(());
    }

    let now_ts = now();
    let recent = store::load_messages(&room.room_id, PLAZA_RATE_LIMIT_WINDOW_SECS);
    let mut queue = VecDeque::new();
    for env in &recent {
        if !counts_toward_plaza_rate_limit(env) {
            continue;
        }
        if env["from"].as_str().unwrap_or("") != sender {
            continue;
        }
        let ts = env["ts"].as_u64().unwrap_or(0);
        prune_recent(&mut queue, now_ts);
        if now_ts.saturating_sub(ts) < PLAZA_RATE_LIMIT_WINDOW_SECS {
            queue.push_back(ts);
        }
    }

    if queue.len() >= PLAZA_RATE_LIMIT_MAX_MSGS {
        return Err(format!(
            "Plaza rate limit exceeded: max {} messages per {}s.",
            PLAZA_RATE_LIMIT_MAX_MSGS, PLAZA_RATE_LIMIT_WINDOW_SECS
        ));
    }

    Ok(())
}

fn allow_incoming_message(
    room: &store::RoomEntry,
    env: &serde_json::Value,
    effective_ts: u64,
    state: &mut PlazaRateLimitState,
) -> bool {
    let from = env["from"].as_str().unwrap_or("");
    if from.is_empty() {
        return false;
    }

    if state.muted.contains(from) {
        return false;
    }

    if !is_public_plaza(room) || !counts_toward_plaza_rate_limit(env) {
        return true;
    }

    let queue = state.recent_by_sender.entry(from.to_string()).or_default();
    prune_recent(queue, effective_ts);
    if queue.len() >= PLAZA_RATE_LIMIT_MAX_MSGS {
        state.muted.insert(from.to_string());
        store::mute_agent(&room.room_id, from);
        eprintln!(
            "  [warn] muted '{}' in '{}' due to plaza rate limit (>{} msgs/{}s)",
            from, room.label, PLAZA_RATE_LIMIT_MAX_MSGS, PLAZA_RATE_LIMIT_WINDOW_SECS
        );
        if state.me_is_admin && !store::is_admin(&room.room_id, from) {
            let _ = kick(from, Some(room.label.as_str()));
        }
        return false;
    }
    queue.push_back(effective_ts);
    true
}

fn ingest_auxiliary_event(room_id: &str, env: &serde_json::Value) {
    let from = env["from"].as_str().unwrap_or("");

    if is_receipt(env) {
        if let Some(ids) = env["read_ids"].as_array() {
            let msg_ids: Vec<String> = ids
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
            store::record_receipts(room_id, &msg_ids, from);
        }
        return;
    }

    if env["type"].as_str() == Some("profile") {
        let profile = store::AgentProfile {
            agent_id: from.to_string(),
            name: env["profile_name"].as_str().map(|s| s.to_string()),
            role: env["profile_role"].as_str().map(|s| s.to_string()),
            updated_at: env["ts"].as_u64().unwrap_or(0),
        };
        store::upsert_profile(room_id, &profile);
        return;
    }

    if is_work_receipt(env) {
        let receipt = store::WorkReceipt {
            id: env["id"].as_str().unwrap_or("?").to_string(),
            task_id: env["task_id"].as_str().unwrap_or("").to_string(),
            task_title: env["task_title"].as_str().unwrap_or("").to_string(),
            agent_id: from.to_string(),
            status: env["receipt_status"].as_str().unwrap_or("done").to_string(),
            notes: env["receipt_notes"].as_str().map(|s| s.to_string()),
            task_hash: env["task_hash"].as_str().unwrap_or("").to_string(),
            witness_ids: env["witness_ids"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default(),
            created_at: env["ts"].as_u64().unwrap_or(0),
            auth: env["_auth"].as_str().unwrap_or("unsigned").to_string(),
        };
        store::upsert_work_receipt(room_id, &receipt);
        return;
    }

    if is_role_state(env) {
        let role = env["role_name"].as_str().unwrap_or("").trim().to_string();
        if role.is_empty() {
            return;
        }
        if env["role_action"].as_str() == Some("release") {
            store::remove_role_lease(room_id, &role);
            return;
        }
        let lease = store::RoleLease {
            role,
            agent_id: from.to_string(),
            lease_expires: env["lease_expires"].as_u64().unwrap_or(0),
            last_heartbeat: env["last_heartbeat"]
                .as_u64()
                .unwrap_or_else(|| env["ts"].as_u64().unwrap_or(0)),
            context_summary: env["context_summary"].as_str().map(|s| s.to_string()),
            last_task_ids: env["last_task_ids"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default(),
            updated_at: env["ts"].as_u64().unwrap_or(0),
        };
        store::upsert_role_lease(room_id, &lease);
        return;
    }

    if is_capability_card(env) {
        let capabilities = env["card_capabilities"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        let card = store::AgentCapabilityCard {
            agent_id: from.to_string(),
            capabilities,
            summary: env["card_summary"].as_str().map(|s| s.to_string()),
            updated_at: env["ts"].as_u64().unwrap_or(0),
            auth: env["_auth"].as_str().unwrap_or("unsigned").to_string(),
        };
        store::upsert_capability_card(room_id, &card);
        return;
    }

    if is_reaction(env) {
        if let (Some(target), Some(emoji)) = (env["target_id"].as_str(), env["emoji"].as_str()) {
            store::add_reaction(room_id, target, from, emoji);
        }
    }
}

fn should_display_message(env: &serde_json::Value) -> bool {
    !is_heartbeat(env)
        && !is_invite_redeem(env)
        && !is_receipt(env)
        && !is_work_receipt(env)
        && !is_role_state(env)
        && !is_reaction(env)
        && !is_capability_card(env)
}

/// Update last_seen for the sender of a message.
fn track_presence(room_id: &str, env: &serde_json::Value) {
    if is_auth_warning(env) {
        return;
    }
    if let Some(from) = env["from"].as_str() {
        store::update_last_seen(room_id, from);
    }
}

fn parse_envelope(raw: &str) -> Option<serde_json::Value> {
    if let Ok(env) = serde_json::from_str::<serde_json::Value>(raw) {
        if env["v"].is_string() && env["text"].is_string() {
            return Some(env);
        }
    }
    // v1 fallback: "agent_id: message"
    if let Some((sender, text)) = raw.split_once(':') {
        return Some(json!({
            "v": "1.0",
            "id": "?",
            "from": sender.trim(),
            "ts": now(),
            "text": text.trim(),
        }));
    }
    None
}

fn signing_message_bytes(room_id: &str, from: &str, signing_pubkey: &str, payload: &str) -> Vec<u8> {
    format!(
        "agora-signed-wire-v1\n{room_id}\n{from}\n{signing_pubkey}\n{payload}"
    )
    .into_bytes()
}

// ── Encrypt / Decrypt ───────────────────────────────────────────

fn encrypt_envelope(env: &serde_json::Value, room_key: &[u8; 32], room_id: &str) -> String {
    let (enc_key, _) = crypto::derive_message_keys(room_key);
    let plaintext = serde_json::to_string(env).unwrap();
    let aad = room_id.as_bytes();
    let blob = crypto::encrypt(plaintext.as_bytes(), &enc_key, aad).expect("encrypt failed");
    let payload = BASE64.encode(&blob);
    let from = env["from"].as_str().unwrap_or("");

    let pkcs8 = store::load_or_create_signing_keypair(from).expect("signing key load failed");
    let signing_pubkey = BASE64
        .encode(crypto::signing_public_key(&pkcs8).expect("signing pubkey derivation failed"));
    store::trust_signing_key(from, &signing_pubkey);

    let signing_input = signing_message_bytes(room_id, from, &signing_pubkey, &payload);
    let sig = BASE64.encode(
        crypto::sign_message(&pkcs8, &signing_input).expect("message signing failed")
    );

    serde_json::to_string(&SignedWirePayload {
        v: SIGNED_WIRE_VERSION.to_string(),
        from: from.to_string(),
        payload,
        signing_pubkey,
        sig,
    })
    .unwrap()
}

fn decrypt_signed_payload(raw: &str, room_key: &[u8; 32], room_id: &str) -> Option<serde_json::Value> {
    let wire = serde_json::from_str::<SignedWirePayload>(raw).ok()?;
    let signing_input =
        signing_message_bytes(room_id, &wire.from, &wire.signing_pubkey, &wire.payload);
    let public_key = BASE64.decode(&wire.signing_pubkey).ok()?;
    let sig = BASE64.decode(&wire.sig).ok()?;

    if !crypto::verify_message_signature(&public_key, &signing_input, &sig) {
        return Some(make_auth_warning(
            room_id,
            &wire,
            "invalid_signature",
            format!(
                "[auth] Dropped message from '{}' due to invalid signature.",
                wire.from
            ),
        ));
    }

    if let Some(trusted) = store::get_trusted_signing_key(&wire.from) {
        if trusted != wire.signing_pubkey {
            return Some(make_auth_warning(
                room_id,
                &wire,
                "signing_key_mismatch",
                format!(
                    "[auth] Dropped message from '{}' because its signing key no longer matches the trusted key for that identity.",
                    wire.from
                ),
            ));
        }
    } else {
        store::trust_signing_key(&wire.from, &wire.signing_pubkey);
    }

    let (enc_key, _) = crypto::derive_message_keys(room_key);
    let blob = BASE64.decode(&wire.payload).ok()?;
    let aad = room_id.as_bytes();
    let plaintext = crypto::decrypt(&blob, &enc_key, aad).ok()?;
    let raw = String::from_utf8(plaintext).ok()?;
    let mut env = parse_envelope(&raw)?;
    if env["from"].as_str() != Some(wire.from.as_str()) {
        return Some(make_auth_warning(
            room_id,
            &wire,
            "sender_signature_mismatch",
            format!(
                "[auth] Dropped message from '{}' because the signed sender did not match the decrypted payload.",
                wire.from
            ),
        ));
    }
    env["_auth"] = json!("verified");
    Some(env)
}

fn decrypt_payload(payload: &str, room_key: &[u8; 32], room_id: &str) -> Option<serde_json::Value> {
    if payload.trim_start().starts_with('{') {
        return decrypt_signed_payload(payload, room_key, room_id);
    }

    let (enc_key, _) = crypto::derive_message_keys(room_key);
    let blob = BASE64.decode(payload).ok()?;
    let aad = room_id.as_bytes();
    let plaintext = crypto::decrypt(&blob, &enc_key, aad).ok()?;
    let raw = String::from_utf8(plaintext).ok()?;
    let mut env = parse_envelope(&raw)?;
    env["_auth"] = json!("unsigned");
    Some(env)
}

// ── Room Operations ─────────────────────────────────────────────

fn resolve_room(label: Option<&str>) -> Result<store::RoomEntry, String> {
    let room = if let Some(l) = label {
        store::find_room(l)
    } else {
        store::get_active_room()
    };
    room.ok_or_else(|| {
        if let Some(label) = label {
            format!("Room '{label}' not found. Run: agora rooms")
        } else {
            "No active room. Use 'agora create' or 'agora join' first.".to_string()
        }
    })
}

pub fn create(label: &str) -> Result<(String, String), String> {
    let room_id = crypto::generate_room_id();
    let secret = crypto::generate_secret();
    let room_key = crypto::derive_room_key(&secret, &room_id);

    store::add_room(&room_id, &secret, label, store::Role::Admin);
    store::set_active_room(label);

    let env = make_envelope("Room created (agora v3, AES-256-GCM).", None);
    let encrypted = encrypt_envelope(&env, &room_key, &room_id);
    transport::publish(&room_id, &encrypted);
    store::save_message(&room_id, &env);

    Ok((room_id, secret))
}

pub fn join(room_id: &str, secret: &str, label: &str) -> Result<store::RoomEntry, String> {
    let room_key = crypto::derive_room_key(secret, room_id);
    let entry = store::add_room(room_id, secret, label, store::Role::Member);
    store::set_active_room(label);

    let env = make_envelope("Joined (agora v3).", None);
    let encrypted = encrypt_envelope(&env, &room_key, room_id);
    transport::publish(room_id, &encrypted);
    store::save_message(room_id, &env);

    Ok(entry)
}

pub fn leave(room_label: Option<&str>) -> Result<serde_json::Value, String> {
    let room = resolve_room(room_label)?;
    let pid_path = store::daemon_pid_path(&room.room_id);
    let mut daemon_stopped = false;

    if let Ok(pid_str) = std::fs::read_to_string(&pid_path) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            unsafe { libc::kill(pid, libc::SIGTERM); }
            daemon_stopped = true;
        }
        let _ = std::fs::remove_file(&pid_path);
    }

    let removed = store::remove_room(&room.room_id)
        .ok_or_else(|| format!("Room '{}' not found.", room.label))?;
    let active_room = store::get_active_room().map(|r| r.label);

    Ok(json!({
        "label": removed.label,
        "room_id": removed.room_id,
        "daemon_stopped": daemon_stopped,
        "active_room": active_room,
    }))
}

pub fn heartbeat(room_label: Option<&str>) -> Result<(), String> {
    let room = resolve_room(room_label)?;
    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let env = make_heartbeat();
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);
    transport::publish(&room.room_id, &encrypted);
    // Update our own last_seen
    store::update_last_seen(&room.room_id, &store::get_agent_id());
    Ok(())
}

pub fn send(message: &str, reply_to: Option<&str>, room_label: Option<&str>) -> Result<String, String> {
    let room = resolve_room(room_label)?;
    let sender = store::get_agent_id();
    enforce_outbound_plaza_rate_limit(&room, &sender)?;
    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);

    let env = make_envelope(message, reply_to);
    let mid = env["id"].as_str().unwrap_or("?").to_string();
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);

    transport::publish(&room.room_id, &encrypted);
    store::save_message(&room.room_id, &env);

    Ok(mid)
}

fn count_invite_redemptions_in_envs(events: &[serde_json::Value], invite_id: &str) -> u32 {
    let mut seen = HashSet::new();
    let mut count = 0;
    for env in events {
        if !is_invite_redeem(env) {
            continue;
        }
        if env["invite_id"].as_str() != Some(invite_id) {
            continue;
        }
        let mid = env["id"].as_str().unwrap_or("");
        if !mid.is_empty() && !seen.insert(mid.to_string()) {
            continue;
        }
        count += 1;
    }
    count
}

pub fn count_invite_redemptions(
    room_id: &str,
    secret: &str,
    invite_id: &str,
    issued_at: Option<u64>,
) -> Result<u32, String> {
    let room_key = crypto::derive_room_key(secret, room_id);
    let since = issued_at
        .map(|ts| ts.to_string())
        .unwrap_or_else(|| "24h".to_string());
    let remote_events = transport::fetch(room_id, &since);
    let mut events = Vec::new();
    for (ts, payload) in &remote_events {
        if let Some(mut env) = decrypt_payload(payload, &room_key, room_id) {
            if env["ts"].as_u64().unwrap_or(0) == 0 {
                env["ts"] = json!(ts);
            }
            events.push(env);
        }
    }
    Ok(count_invite_redemptions_in_envs(&events, invite_id))
}

pub fn redeem_invite(
    room_id: &str,
    secret: &str,
    invite_id: &str,
    invite_created_by: Option<&str>,
    invite_max_uses: Option<u32>,
) -> Result<(), String> {
    let room_key = crypto::derive_room_key(secret, room_id);
    let env = make_invite_redemption(invite_id, invite_created_by, invite_max_uses);
    let encrypted = encrypt_envelope(&env, &room_key, room_id);
    if !transport::publish(room_id, &encrypted) {
        return Err("failed to publish invite redemption to relay".to_string());
    }
    Ok(())
}

pub fn read(since: &str, limit: usize, room_label: Option<&str>) -> Result<Vec<serde_json::Value>, String> {
    let room = resolve_room(room_label)?;
    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let since_secs = parse_since(since);
    let local_msgs = store::load_messages(&room.room_id, since_secs);
    let local_ids: HashSet<String> = local_msgs
        .iter()
        .filter_map(|msg| msg["id"].as_str().map(|s| s.to_string()))
        .collect();
    let recent_local = store::load_messages(&room.room_id, PLAZA_RATE_LIMIT_WINDOW_SECS);
    let mut rate_limit = seed_plaza_rate_limit_state(&room, &recent_local);

    // Fetch from relay
    let mut remote_events = transport::fetch(&room.room_id, since);
    remote_events.sort_by_key(|(ts, _)| *ts);
    let mut remote_msgs: Vec<serde_json::Value> = Vec::new();
    for (ts, payload) in &remote_events {
        if let Some(mut env) = decrypt_payload(payload, &room_key, &room.room_id) {
            if env["ts"].as_u64().unwrap_or(0) == 0 {
                env["ts"] = json!(ts);
            }
            let mid = env["id"].as_str().unwrap_or("?");
            if mid != "?" && local_ids.contains(mid) {
                continue;
            }
            if !allow_incoming_message(&room, &env, *ts, &mut rate_limit) {
                continue;
            }
            remote_msgs.push(env);
        }
    }

    let mut seen_ids: HashSet<String> = HashSet::new();
    let mut merged = Vec::new();
    for msg in remote_msgs.into_iter().chain(local_msgs) {
        let mid = msg["id"].as_str().unwrap_or("?").to_string();
        if mid != "?" && seen_ids.contains(&mid) {
            continue;
        }
        seen_ids.insert(mid);
        // Track presence from all messages (including heartbeats)
        track_presence(&room.room_id, &msg);
        ingest_auxiliary_event(&room.room_id, &msg);
        if should_display_message(&msg) {
            store::save_message(&room.room_id, &msg);
            merged.push(msg);
        }
    }

    // Filter muted agents
    let muted = store::load_muted(&room.room_id);
    merged.retain(|m| {
        let from = m["from"].as_str().unwrap_or("");
        !muted.contains(from)
    });

    merged.sort_by_key(|m| m["ts"].as_u64().unwrap_or(0));
    if merged.len() > limit {
        merged = merged[merged.len() - limit..].to_vec();
    }
    Ok(merged)
}

pub fn check(since: &str, room_label: Option<&str>) -> Result<Vec<serde_json::Value>, String> {
    let room = resolve_room(room_label)?;
    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let me = store::get_agent_id();
    let seen = store::load_seen(&room.room_id);
    let recent_local = store::load_messages(&room.room_id, PLAZA_RATE_LIMIT_WINDOW_SECS);
    let mut rate_limit = seed_plaza_rate_limit_state(&room, &recent_local);

    let mut remote_events = transport::fetch(&room.room_id, since);
    remote_events.sort_by_key(|(ts, _)| *ts);
    let mut new_msgs = Vec::new();
    let mut read_ids = Vec::new();
    for (ts, payload) in &remote_events {
        if let Some(env) = decrypt_payload(payload, &room_key, &room.room_id) {
            track_presence(&room.room_id, &env);
            let mid = env["id"].as_str().unwrap_or("?").to_string();
            let from = env["from"].as_str().unwrap_or("");
            if from == me || seen.contains(&mid) {
                continue;
            }
            store::mark_seen(&room.room_id, &mid);
            if !allow_incoming_message(&room, &env, *ts, &mut rate_limit) {
                continue;
            }

            // Process incoming receipts
            if is_receipt(&env) {
                if let Some(ids) = env["read_ids"].as_array() {
                    let reader = from.to_string();
                    let msg_ids: Vec<String> = ids.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect();
                    store::record_receipts(&room.room_id, &msg_ids, &reader);
                }
                continue;
            }

            if is_heartbeat(&env) {
                continue;
            }

            if is_invite_redeem(&env) {
                continue;
            }

            if is_work_receipt(&env) {
                ingest_auxiliary_event(&room.room_id, &env);
                continue;
            }

            // Process incoming profiles
            if env["type"].as_str() == Some("profile") {
                let profile = store::AgentProfile {
                    agent_id: from.to_string(),
                    name: env["profile_name"].as_str().map(|s| s.to_string()),
                    role: env["profile_role"].as_str().map(|s| s.to_string()),
                    updated_at: env["ts"].as_u64().unwrap_or(0),
                };
                store::upsert_profile(&room.room_id, &profile);
                store::save_message(&room.room_id, &env);
                new_msgs.push(env);
                continue;
            }

            // Process incoming reactions
            if is_reaction(&env) {
                if let (Some(target), Some(emoji)) = (env["target_id"].as_str(), env["emoji"].as_str()) {
                    store::add_reaction(&room.room_id, target, from, emoji);
                }
                continue;
            }

            store::save_message(&room.room_id, &env);
            read_ids.push(mid);
            new_msgs.push(env);
        }
    }

    // Send read receipts for messages we just read
    if !read_ids.is_empty() {
        let receipt = make_receipt(&read_ids);
        let encrypted = encrypt_envelope(&receipt, &room_key, &room.room_id);
        transport::publish(&room.room_id, &encrypted);
    }

    // Fire webhooks for new messages
    if !new_msgs.is_empty() {
        fire_webhooks(&room.room_id, &new_msgs);
    }

    // Deliver any due scheduled messages
    let _ = deliver_scheduled(room_label);

    Ok(new_msgs)
}

/// Get read receipt status for recent messages.
pub fn read_status(room_label: Option<&str>) -> Result<Vec<serde_json::Value>, String> {
    let room = resolve_room(room_label)?;
    let msgs = store::load_messages(&room.room_id, 7200); // last 2h
    let receipts = store::load_receipts(&room.room_id);
    let me = store::get_agent_id();

    let mut status = Vec::new();
    for msg in &msgs {
        let mid = msg["id"].as_str().unwrap_or("?").to_string();
        let from = msg["from"].as_str().unwrap_or("?");
        // Only show status for our own messages
        if from != me {
            continue;
        }
        let readers = receipts.get(&mid).cloned().unwrap_or_default();
        status.push(json!({
            "id": mid,
            "text": msg["text"].as_str().unwrap_or("")[..50.min(msg["text"].as_str().unwrap_or("").len())],
            "ts": msg["ts"],
            "read_by": readers,
        }));
    }
    Ok(status)
}

/// React to a message with an emoji.
pub fn react(target_id: &str, emoji: &str, room_label: Option<&str>) -> Result<(), String> {
    let room = resolve_room(room_label)?;
    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let env = make_reaction(target_id, emoji);
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);
    transport::publish(&room.room_id, &encrypted);
    store::save_message(&room.room_id, &env);
    // Also store locally
    store::add_reaction(&room.room_id, target_id, &store::get_agent_id(), emoji);
    Ok(())
}

/// Get reactions for recent messages.
pub fn reactions(room_label: Option<&str>) -> Result<std::collections::HashMap<String, Vec<(String, String)>>, String> {
    let room = resolve_room(room_label)?;
    Ok(store::load_reactions(&room.room_id))
}

/// Mute an agent locally (their messages won't show in read/check).
pub fn mute(agent_id: &str, room_label: Option<&str>) -> Result<(), String> {
    let room = resolve_room(room_label)?;
    store::mute_agent(&room.room_id, agent_id);
    Ok(())
}

/// Unmute an agent.
pub fn unmute(agent_id: &str, room_label: Option<&str>) -> Result<(), String> {
    let room = resolve_room(room_label)?;
    store::unmute_agent(&room.room_id, agent_id);
    Ok(())
}

/// List muted agents.
pub fn muted(room_label: Option<&str>) -> Result<std::collections::HashSet<String>, String> {
    let room = resolve_room(room_label)?;
    Ok(store::load_muted(&room.room_id))
}

/// Set your agent profile and broadcast it to the room.
pub fn set_profile(name: Option<&str>, role: Option<&str>, room_label: Option<&str>) -> Result<(), String> {
    let room = resolve_room(room_label)?;
    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let agent_id = store::get_agent_id();

    let profile = store::AgentProfile {
        agent_id: agent_id.clone(),
        name: name.map(|s| s.to_string()),
        role: role.map(|s| s.to_string()),
        updated_at: now(),
    };
    store::upsert_profile(&room.room_id, &profile);

    // Broadcast profile as a special envelope
    let env = json!({
        "v": VERSION,
        "id": msg_id(),
        "from": agent_id,
        "ts": now(),
        "type": "profile",
        "profile_name": profile.name,
        "profile_role": profile.role,
        "text": format!("Profile updated: {} ({})",
            profile.name.as_deref().unwrap_or(&agent_id),
            profile.role.as_deref().unwrap_or("agent")),
    });
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);
    transport::publish(&room.room_id, &encrypted);
    store::save_message(&room.room_id, &env);
    Ok(())
}

/// Look up an agent's profile.
pub fn whois(agent_id: &str, room_label: Option<&str>) -> Result<Option<store::AgentProfile>, String> {
    let room = resolve_room(room_label)?;
    Ok(store::get_profile(&room.room_id, agent_id))
}

fn claimed_task_ids(room_id: &str, agent_id: &str) -> Vec<String> {
    store::load_tasks(room_id)
        .into_iter()
        .filter(|task| task.status != "done" && task.claimed_by.as_deref() == Some(agent_id))
        .map(|task| task.id)
        .collect()
}

fn publish_role_state(
    room: &store::RoomEntry,
    lease: &store::RoleLease,
    action: &str,
) -> Result<(), String> {
    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let text = match action {
        "claim" => format!("[role] {} claimed {}", lease.agent_id, lease.role),
        "release" => format!("[role] {} released {}", lease.agent_id, lease.role),
        _ => format!("[role] {} heartbeat {}", lease.agent_id, lease.role),
    };
    let env = json!({
        "v": VERSION,
        "id": msg_id(),
        "from": lease.agent_id,
        "ts": now(),
        "type": "role_state",
        "role_name": lease.role,
        "role_action": action,
        "lease_expires": lease.lease_expires,
        "last_heartbeat": lease.last_heartbeat,
        "context_summary": lease.context_summary,
        "last_task_ids": lease.last_task_ids,
        "text": text,
    });
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);
    transport::publish(&room.room_id, &encrypted);
    store::save_message(&room.room_id, &env);
    Ok(())
}

pub fn role_claim(
    role: &str,
    summary: Option<&str>,
    ttl_secs: u64,
    room_label: Option<&str>,
) -> Result<store::RoleLease, String> {
    let room = resolve_room(room_label)?;
    let me = store::get_agent_id();
    let now_ts = now();

    if let Some(existing) = store::get_role_lease(&room.room_id, role) {
        if existing.agent_id != me && existing.lease_expires > now_ts {
            return Err(format!(
                "Role '{}' is currently held by '{}' for another {}s.",
                role,
                existing.agent_id,
                existing.lease_expires.saturating_sub(now_ts)
            ));
        }
    }

    let lease = store::RoleLease {
        role: role.to_string(),
        agent_id: me.clone(),
        lease_expires: now_ts + ttl_secs,
        last_heartbeat: now_ts,
        context_summary: summary.map(|s| s.to_string()),
        last_task_ids: claimed_task_ids(&room.room_id, &me),
        updated_at: now_ts,
    };
    store::upsert_role_lease(&room.room_id, &lease);
    publish_role_state(&room, &lease, "claim")?;
    Ok(lease)
}

pub fn role_heartbeat(
    role: &str,
    summary: Option<&str>,
    ttl_secs: u64,
    room_label: Option<&str>,
) -> Result<store::RoleLease, String> {
    let room = resolve_room(room_label)?;
    let me = store::get_agent_id();
    let now_ts = now();
    let existing = store::get_role_lease(&room.room_id, role);

    if let Some(current) = &existing {
        if current.agent_id != me && current.lease_expires > now_ts {
            return Err(format!(
                "Role '{}' is currently held by '{}' for another {}s.",
                role,
                current.agent_id,
                current.lease_expires.saturating_sub(now_ts)
            ));
        }
    }

    let lease = store::RoleLease {
        role: role.to_string(),
        agent_id: me.clone(),
        lease_expires: now_ts + ttl_secs,
        last_heartbeat: now_ts,
        context_summary: summary
            .map(|s| s.to_string())
            .or_else(|| existing.and_then(|current| current.context_summary)),
        last_task_ids: claimed_task_ids(&room.room_id, &me),
        updated_at: now_ts,
    };
    store::upsert_role_lease(&room.room_id, &lease);
    publish_role_state(&room, &lease, "heartbeat")?;
    Ok(lease)
}

pub fn role_release(role: &str, room_label: Option<&str>) -> Result<(), String> {
    let room = resolve_room(room_label)?;
    let me = store::get_agent_id();
    let now_ts = now();
    let existing = store::get_role_lease(&room.room_id, role)
        .ok_or_else(|| format!("Role '{}' is not currently claimed.", role))?;

    if existing.agent_id != me && existing.lease_expires > now_ts {
        return Err(format!("Role '{}' is currently held by '{}'.", role, existing.agent_id));
    }

    let released = store::RoleLease {
        role: existing.role.clone(),
        agent_id: me,
        lease_expires: now_ts,
        last_heartbeat: now_ts,
        context_summary: existing.context_summary.clone(),
        last_task_ids: existing.last_task_ids.clone(),
        updated_at: now_ts,
    };
    store::remove_role_lease(&room.room_id, role);
    publish_role_state(&room, &released, "release")?;
    Ok(())
}

pub fn list_role_leases(room_label: Option<&str>) -> Result<Vec<store::RoleLease>, String> {
    let room = resolve_room(room_label)?;
    Ok(store::load_role_leases(&room.room_id))
}

// ── Room Directory ─────────────────────────────────────────────

// ── Credits / Agent Economy ────────────────────────────────────

pub fn credit_grant(agent_id: &str, amount: i64, reason: &str, room_label: Option<&str>) -> Result<i64, String> {
    let room = resolve_room(room_label)?;
    let me = store::get_agent_id();
    // Bootstrap: if no admin exists, first granter becomes admin
    let has_admin = room.members.iter().any(|m| m.role == store::Role::Admin);
    if !has_admin {
        store::set_member_role(&room.room_id, &me, store::Role::Admin);
    } else if !store::is_admin(&room.room_id, &me) {
        return Err("Only admins can grant credits.".to_string());
    }
    store::credit_add(&room.room_id, agent_id, amount, reason);
    let balance = store::credit_balance(&room.room_id, agent_id);
    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let env = make_envelope(&format!("[credit] +{amount} to {agent_id}: {reason} (balance: {balance})"), None);
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);
    transport::publish(&room.room_id, &encrypted);
    store::save_message(&room.room_id, &env);
    Ok(balance)
}

pub fn credit_balance_check(agent_id: Option<&str>, room_label: Option<&str>) -> Result<(i64, i64), String> {
    let room = resolve_room(room_label)?;
    let id = agent_id.unwrap_or(&store::get_agent_id()).to_string();
    Ok((store::credit_balance(&room.room_id, &id), store::trust_balance(&room.room_id, &id)))
}

/// Compute a live trust score for an agent across all joined rooms.
/// Mirrors the discover algorithm but does not require a capability card.
/// Returns (score, receipt_count, rooms_active, vouch_count).
pub fn compute_agent_trust_score(agent_id: &str) -> (f64, usize, usize, usize) {
    let rooms = store::load_registry();
    let now_ts = now();
    let mut total_weighted_receipts = 0.0_f64;
    let mut total_receipt_count = 0usize;
    let mut rooms_active = 0usize;
    let mut total_stale_penalty = 0.0_f64;

    for room in &rooms {
        let receipts = store::load_work_receipts(&room.room_id);
        let agent_receipts: Vec<_> = receipts.iter().filter(|r| r.agent_id == agent_id).collect();
        if agent_receipts.is_empty() { continue; }
        rooms_active += 1;
        total_receipt_count += agent_receipts.len();
        total_weighted_receipts += agent_receipts
            .iter()
            .map(|r| discovery_decay_weight(now_ts.saturating_sub(r.created_at), DISCOVERY_POSITIVE_HALF_LIFE_SECS))
            .sum::<f64>();

        // Stale claims penalty
        if let Ok(tasks) = task_list(Some(&room.room_id)) {
            for task in &tasks {
                if task.status != "done" && task.claimed_by.as_deref() == Some(agent_id) {
                    let age = now_ts.saturating_sub(task.updated_at);
                    total_stale_penalty += stale_claim_weight(age);
                }
            }
        }
    }

    let vouches = vouch_count(agent_id);
    let room_presence = 1.0 + rooms_active as f64 * 0.2;
    let abandonment_rate = if total_weighted_receipts + total_stale_penalty > 0.0 {
        total_stale_penalty / (total_weighted_receipts + total_stale_penalty)
    } else {
        0.0
    };
    let abandonment_penalty = (1.0 - abandonment_rate * 0.7).clamp(0.2, 1.0);
    let positive_score = (1.0 + total_weighted_receipts) * room_presence * (1.0 + vouches as f64 * 0.3);
    let score = positive_score * abandonment_penalty;

    (score, total_receipt_count, rooms_active, vouches)
}

pub fn credit_spend(amount: i64, reason: &str, room_label: Option<&str>) -> Result<i64, String> {
    let room = resolve_room(room_label)?;
    let me = store::get_agent_id();
    let balance = store::credit_balance(&room.room_id, &me);
    if balance < amount { return Err(format!("Insufficient credits: have {balance}, need {amount}")); }
    store::credit_add(&room.room_id, &me, -amount, reason);
    Ok(balance - amount)
}

// ── Prediction Market ──────────────────────────────────────────

pub fn bet_create(question: &str, room_label: Option<&str>) -> Result<String, String> {
    let room = resolve_room(room_label)?;
    let me = store::get_agent_id();
    let id = msg_id();
    let bet = store::Bet {
        id: id.clone(), question: question.to_string(), created_by: me.clone(),
        created_at: now(), status: "open".to_string(),
        stakes_yes: Vec::new(), stakes_no: Vec::new(),
    };
    let mut bets = store::load_bets(&room.room_id);
    bets.push(bet);
    store::save_bets(&room.room_id, &bets);

    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let env = make_envelope(&format!("[bet] New: {} (id: {})", question, &id[..6]), None);
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);
    transport::publish(&room.room_id, &encrypted);
    store::save_message(&room.room_id, &env);
    Ok(id)
}

pub fn bet_stake(bet_id: &str, side: bool, amount: i64, room_label: Option<&str>) -> Result<(), String> {
    let room = resolve_room(room_label)?;
    let me = store::get_agent_id();
    let balance = store::credit_balance(&room.room_id, &me);
    if balance < amount { return Err(format!("Insufficient credits: have {balance}, need {amount}")); }

    let mut bets = store::load_bets(&room.room_id);
    let bet = bets.iter_mut().find(|b| b.id.starts_with(bet_id) && b.status == "open")
        .ok_or("Bet not found or already resolved")?;

    if side { bet.stakes_yes.push((me.clone(), amount)); }
    else { bet.stakes_no.push((me.clone(), amount)); }
    store::save_bets(&room.room_id, &bets);

    // Escrow: debit the staker
    store::credit_add(&room.room_id, &me, -amount, &format!("bet escrow: {} on {}", if side {"YES"} else {"NO"}, &bet_id[..6.min(bet_id.len())]));

    let side_str = if side { "YES" } else { "NO" };
    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let env = make_envelope(&format!("[bet] {me} stakes {amount} on {side_str} (bet {})", &bet_id[..6.min(bet_id.len())]), None);
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);
    transport::publish(&room.room_id, &encrypted);
    store::save_message(&room.room_id, &env);
    Ok(())
}

pub fn bet_resolve(bet_id: &str, outcome: bool, room_label: Option<&str>) -> Result<String, String> {
    let room = resolve_room(room_label)?;
    let me = store::get_agent_id();
    if !store::is_admin(&room.room_id, &me) { return Err("Only admins can resolve bets.".to_string()); }

    let mut bets = store::load_bets(&room.room_id);
    let idx = bets.iter().position(|b| b.id.starts_with(bet_id) && b.status == "open")
        .ok_or("Bet not found or already resolved")?;

    bets[idx].status = if outcome { "resolved_yes".to_string() } else { "resolved_no".to_string() };

    let winners = if outcome { bets[idx].stakes_yes.clone() } else { bets[idx].stakes_no.clone() };
    let losers = if outcome { bets[idx].stakes_no.clone() } else { bets[idx].stakes_yes.clone() };

    let total_pot: i64 = losers.iter().map(|(_, a)| a).sum();
    let winner_total: i64 = winners.iter().map(|(_, a)| a).sum();
    let question = bets[idx].question.clone();

    let mut payouts = Vec::new();
    for (agent, stake) in &winners {
        let share = if winner_total > 0 { (*stake as f64 / winner_total as f64 * total_pot as f64) as i64 } else { 0 };
        let payout = stake + share;
        store::credit_add(&room.room_id, agent, payout, &format!("bet won: {}", &bet_id[..6.min(bet_id.len())]));
        payouts.push(format!("{}: +{}", agent, payout));
    }

    store::save_bets(&room.room_id, &bets);

    let outcome_str = if outcome { "YES" } else { "NO" };
    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let env = make_envelope(&format!("[bet resolved] {} → {} | Pot: {} | {}", question, outcome_str, total_pot, payouts.join(", ")), None);
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);
    transport::publish(&room.room_id, &encrypted);
    store::save_message(&room.room_id, &env);
    Ok(format!("Resolved: {} → {outcome_str}, pot {total_pot} distributed to {} winners", question, winners.len()))
}

pub fn bet_list(room_label: Option<&str>) -> Result<Vec<store::Bet>, String> {
    let room = resolve_room(room_label)?;
    Ok(store::load_bets(&room.room_id))
}

// ── Capability Gaps (v0.7 typed schema from plaza design) ──────

/// A typed capability gap signal — what a room needs.
/// Schema: {type, urgency 1-5, blocked_tasks, since}
#[derive(Debug, Clone)]
pub struct CapabilityGap {
    pub gap_type: String,
    pub urgency: u32,
    pub blocked_tasks: usize,
    pub since: u64,
    pub room_label: String,
}

/// Emit a capability gap for the current room.
pub fn gap_emit(gap_type: &str, urgency: u32, room_label: Option<&str>) -> Result<String, String> {
    let room = resolve_room(room_label)?;
    let me = store::get_agent_id();
    let id = msg_id();

    // Count blocked tasks (open tasks matching this gap type)
    let tasks = store::load_tasks(&room.room_id);
    let blocked = tasks.iter().filter(|t| t.status == "open").count();

    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let env = json!({
        "v": VERSION, "id": id, "from": me, "ts": now(),
        "type": "capability_gap",
        "gap_type": gap_type,
        "urgency": urgency,
        "blocked_tasks": blocked,
        "since": now(),
        "text": format!("[gap] Seeking: {} (urgency: {}/5, {} tasks blocked)", gap_type, urgency, blocked),
    });
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);
    transport::publish(&room.room_id, &encrypted);
    store::save_message(&room.room_id, &env);
    Ok(id)
}

/// List all capability gaps across rooms.
pub fn gap_list() -> Vec<CapabilityGap> {
    let rooms = store::load_registry();
    let mut gaps = Vec::new();
    for room in &rooms {
        let msgs = store::load_messages(&room.room_id, 604800);
        for m in &msgs {
            if m["type"].as_str() == Some("capability_gap") {
                gaps.push(CapabilityGap {
                    gap_type: m["gap_type"].as_str().unwrap_or("?").to_string(),
                    urgency: m["urgency"].as_u64().unwrap_or(0) as u32,
                    blocked_tasks: m["blocked_tasks"].as_u64().unwrap_or(0) as usize,
                    since: m["since"].as_u64().unwrap_or(0),
                    room_label: room.label.clone(),
                });
            }
        }
    }
    // Deduplicate by gap_type+room, keep latest
    let mut seen = std::collections::HashMap::new();
    for gap in gaps.into_iter().rev() {
        let key = format!("{}:{}", gap.room_label, gap.gap_type);
        seen.entry(key).or_insert(gap);
    }
    let mut result: Vec<_> = seen.into_values().collect();
    result.sort_by(|a, b| b.urgency.cmp(&a.urgency).then(b.blocked_tasks.cmp(&a.blocked_tasks)));
    result
}

pub struct RoomInfo {
    pub label: String,
    pub room_id: String,
    pub topic: Option<String>,
    pub agent_count: usize,
    pub message_count: usize,
    pub last_activity: u64,
}

pub fn directory() -> Result<Vec<RoomInfo>, String> {
    let rooms = store::load_registry();
    let now_ts = now();
    let mut infos = Vec::new();
    for room in &rooms {
        let msgs = store::load_messages(&room.room_id, 86400);
        let online = room.members.iter().filter(|m| m.last_seen > 0 && now_ts - m.last_seen < 300).count();
        let last_ts = msgs.iter().map(|m| m["ts"].as_u64().unwrap_or(0)).max().unwrap_or(0);
        infos.push(RoomInfo {
            label: room.label.clone(), room_id: room.room_id.clone(),
            topic: room.topic.clone(), agent_count: online,
            message_count: msgs.len(), last_activity: last_ts,
        });
    }
    infos.sort_by(|a, b| b.last_activity.cmp(&a.last_activity));
    Ok(infos)
}

// ── Capability Cards ───────────────────────────────────────────

pub fn card_set(capabilities: &[String], description: Option<&str>, room_label: Option<&str>) -> Result<(), String> {
    let room = resolve_room(room_label)?;
    let me = store::get_agent_id();
    let card = store::CapabilityCard {
        agent_id: me.clone(), capabilities: capabilities.to_vec(),
        available: true, description: description.map(|s| s.to_string()), updated_at: now(),
    };
    store::save_card(&card);
    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let env = json!({
        "v": VERSION, "id": msg_id(), "from": me, "ts": now(),
        "type": "capability_card", "capabilities": card.capabilities,
        "available": card.available, "description": card.description,
        "text": format!("[card] {} — capabilities: {}", me, card.capabilities.join(", ")),
    });
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);
    transport::publish(&room.room_id, &encrypted);
    store::save_message(&room.room_id, &env);
    Ok(())
}

pub fn card_show(agent_id: Option<&str>, room_label: Option<&str>) -> Result<Option<store::CapabilityCard>, String> {
    if agent_id.is_none() { return Ok(store::load_card()); }
    let room = resolve_room(room_label)?;
    let cards = store::load_peer_cards(&room.room_id);
    Ok(cards.into_iter().find(|c| c.agent_id == agent_id.unwrap()))
}

/// Agent discovery result with trust score.
pub struct DiscoveryResult {
    pub card: store::CapabilityCard,
    pub trust_score: f64,
    pub receipt_count: usize,
    pub rooms_active: usize,
    pub stale_claims: usize,
    pub abandonment_rate: f64,
    pub volatility_score: f64,
}

/// Discover agents by capability with trust-weighted ranking.
/// Trust = weighted receipts * room presence * vouches, penalized by stale claims and volatility.
pub fn discover(need: &str, room_label: Option<&str>) -> Result<Vec<DiscoveryResult>, String> {
    #[derive(Clone)]
    struct DiscoveryAccumulator {
        card: store::CapabilityCard,
        receipt_count: usize,
        rooms_active: usize,
        weighted_receipts: f64,
        stale_claims: usize,
        stale_claim_weight: f64,
        volatility_sum: f64,
    }

    let need_lower = need.to_lowercase();
    let needs: Vec<&str> = need_lower.split(',').map(|s| s.trim()).collect();
    let rooms = if let Some(label) = room_label {
        vec![resolve_room(Some(label))?]
    } else {
        store::load_registry()
    };
    let now_ts = now();
    let mut agent_map: HashMap<String, DiscoveryAccumulator> = HashMap::new();

    for room in &rooms {
        let receipts = store::load_work_receipts(&room.room_id);
        let tasks = task_list(Some(&room.room_id))?;
        for card in store::load_peer_cards(&room.room_id) {
            let matches = needs.iter().all(|n| card.capabilities.iter().any(|c| c.to_lowercase().contains(n)));
            if !matches { continue; }

            let agent_receipts: Vec<_> = receipts.iter().filter(|r| r.agent_id == card.agent_id).collect();
            let receipt_count = agent_receipts.len();
            let weighted_receipts = agent_receipts
                .iter()
                .map(|receipt| discovery_decay_weight(
                    now_ts.saturating_sub(receipt.created_at),
                    DISCOVERY_POSITIVE_HALF_LIFE_SECS,
                ))
                .sum::<f64>();
            let freshest_receipt = agent_receipts
                .iter()
                .map(|receipt| receipt.created_at)
                .max();
            let stale_claims: Vec<_> = tasks
                .iter()
                .filter(|task| task.status != "done" && task.claimed_by.as_deref() == Some(card.agent_id.as_str()))
                .filter_map(|task| {
                    let age = now_ts.saturating_sub(task.updated_at);
                    let weight = stale_claim_weight(age);
                    (weight > 0.0).then_some(weight)
                })
                .collect();
            let stale_claim_count = stale_claims.len();
            let stale_claim_weight = stale_claims.into_iter().sum::<f64>();

            let card_freshness = discovery_decay_weight(
                now_ts.saturating_sub(card.updated_at),
                DISCOVERY_POSITIVE_HALF_LIFE_SECS,
            );
            let execution_freshness = freshest_receipt
                .map(|ts| discovery_decay_weight(now_ts.saturating_sub(ts), DISCOVERY_POSITIVE_HALF_LIFE_SECS))
                .unwrap_or(0.0);
            let volatility = (card_freshness - execution_freshness).max(0.0);

            let entry = agent_map.entry(card.agent_id.clone()).or_insert_with(|| DiscoveryAccumulator {
                card: card.clone(),
                receipt_count: 0,
                rooms_active: 0,
                weighted_receipts: 0.0,
                stale_claims: 0,
                stale_claim_weight: 0.0,
                volatility_sum: 0.0,
            });
            if card.updated_at > entry.card.updated_at {
                entry.card = card.clone();
            }
            entry.receipt_count += receipt_count;
            entry.rooms_active += 1;
            entry.weighted_receipts += weighted_receipts;
            entry.stale_claims += stale_claim_count;
            entry.stale_claim_weight += stale_claim_weight;
            entry.volatility_sum += volatility;
        }
    }

    let mut results: Vec<DiscoveryResult> = agent_map
        .into_iter()
        .map(|(agent_id, entry)| {
            let vouches = vouch_count(&agent_id) as f64;
            let abandonment_rate = if entry.weighted_receipts + entry.stale_claim_weight > 0.0 {
                entry.stale_claim_weight / (entry.weighted_receipts + entry.stale_claim_weight)
            } else {
                0.0
            };
            let volatility_score = if entry.rooms_active > 0 {
                (entry.volatility_sum / entry.rooms_active as f64).clamp(0.0, 1.0)
            } else {
                0.0
            };
            let room_presence = 1.0 + entry.rooms_active as f64 * 0.2;
            let positive_score = (1.0 + entry.weighted_receipts) * room_presence * (1.0 + vouches * 0.3);
            let abandonment_penalty = (1.0 - abandonment_rate * 0.7).clamp(0.2, 1.0);
            let volatility_penalty = (1.0 - volatility_score * 0.4).clamp(0.4, 1.0);
            DiscoveryResult {
                card: entry.card,
                trust_score: positive_score * abandonment_penalty * volatility_penalty,
                receipt_count: entry.receipt_count,
                rooms_active: entry.rooms_active,
                stale_claims: entry.stale_claims,
                abandonment_rate,
                volatility_score,
            }
        })
        .collect();
    results.sort_by(|a, b| b.trust_score.partial_cmp(&a.trust_score).unwrap_or(std::cmp::Ordering::Equal));
    Ok(results)
}

fn discovery_decay_weight(age_secs: u64, half_life_secs: f64) -> f64 {
    0.5_f64.powf(age_secs as f64 / half_life_secs)
}

fn stale_claim_weight(age_secs: u64) -> f64 {
    if age_secs <= DISCOVERY_STALE_CLAIM_GRACE_SECS {
        return 0.0;
    }
    discovery_decay_weight(
        age_secs - DISCOVERY_STALE_CLAIM_GRACE_SECS,
        DISCOVERY_NEGATIVE_HALF_LIFE_SECS,
    )
}

pub fn process_card_message(room_id: &str, msg: &serde_json::Value) {
    if msg["type"].as_str() != Some("capability_card") { return; }
    let agent_id = msg["from"].as_str().unwrap_or("").to_string();
    if agent_id.is_empty() { return; }
    let caps: Vec<String> = msg["capabilities"].as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let card = store::CapabilityCard {
        agent_id, capabilities: caps,
        available: msg["available"].as_bool().unwrap_or(true),
        description: msg["description"].as_str().map(String::from),
        updated_at: msg["ts"].as_u64().unwrap_or(0),
    };
    store::save_peer_card(room_id, &card);
}

// ── Vouch / Trust Mesh ─────────────────────────────────────────

/// Vouch for another agent — adds to their trust score.
pub fn vouch(agent_id: &str, reason: Option<&str>, room_label: Option<&str>) -> Result<(), String> {
    let room = resolve_room(room_label)?;
    let me = store::get_agent_id();
    if me == agent_id { return Err("Cannot vouch for yourself.".to_string()); }

    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let reason_str = reason.unwrap_or("trusted collaborator");
    let env = json!({
        "v": VERSION, "id": msg_id(), "from": me, "ts": now(),
        "type": "vouch",
        "vouched_for": agent_id,
        "reason": reason_str,
        "text": format!("[vouch] {me} vouches for {agent_id}: {reason_str}"),
    });
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);
    transport::publish(&room.room_id, &encrypted);
    store::save_message(&room.room_id, &env);
    Ok(())
}

/// Count vouches for an agent across rooms.
pub fn vouch_count(agent_id: &str) -> usize {
    let rooms = store::load_registry();
    let mut count = 0;
    for room in &rooms {
        let msgs = store::load_messages(&room.room_id, 604800 * 4); // 4 weeks
        for msg in &msgs {
            if msg["type"].as_str() == Some("vouch") && msg["vouched_for"].as_str() == Some(agent_id) {
                count += 1;
            }
        }
    }
    count
}

// ── Bounties ───────────────────────────────────────────────────

/// Post a bounty — a task with a priority weight that boosts discoverer trust.
///
/// `acceptance_oracle`: optional shell command run against submissions to auto-verify (e.g. "cargo test").
pub fn bounty_post(
    title: &str,
    priority: u32,
    acceptance_oracle: Option<&str>,
    reward_credits: Option<i64>,
    room_label: Option<&str>,
) -> Result<String, String> {
    let room = resolve_room(room_label)?;
    let me = store::get_agent_id();
    let id = msg_id();
    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let reward_trust = reward_credits.map(|c| (c / 10).max(1));
    let reward_label = reward_credits
        .map(|c| format!(", reward: {c} credits"))
        .unwrap_or_default();
    let mut env = json!({
        "v": VERSION, "id": id, "from": me, "ts": now(),
        "type": "bounty",
        "title": title,
        "priority": priority,
        "status": "open",
        "text": format!("[bounty P{}] {title}{reward_label} (id: {})", priority, &id[..6]),
    });
    if let Some(oracle) = acceptance_oracle {
        env["acceptance_oracle"] = json!(oracle);
    }
    if let Some(r) = reward_credits {
        env["reward_credits"] = json!(r);
        env["reward_trust"] = json!(reward_trust.unwrap_or(1));
    }
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);
    transport::publish(&room.room_id, &encrypted);
    store::save_message(&room.room_id, &env);

    // Also create as a task (with oracle and reward)
    let _ = task_add_with_oracle(title, acceptance_oracle, reward_credits, reward_trust, room_label);
    Ok(id)
}

/// Internal: add a task with an optional acceptance oracle and reward.
fn task_add_with_oracle(
    title: &str,
    acceptance_oracle: Option<&str>,
    reward_credits: Option<i64>,
    reward_trust: Option<i64>,
    room_label: Option<&str>,
) -> Result<String, String> {
    let room = resolve_room(room_label)?;
    let me = store::get_agent_id();
    let id = msg_id();
    let mut tasks = store::load_tasks(&room.room_id);
    tasks.push(store::Task {
        id: id.clone(),
        title: title.to_string(),
        status: "open".to_string(),
        created_by: me,
        claimed_by: None,
        created_at: now(),
        updated_at: now(),
        notes: None,
        acceptance_oracle: acceptance_oracle.map(|s| s.to_string()),
        reward_credits,
        reward_trust,
        submissions: vec![],
    });
    store::save_tasks(&room.room_id, &tasks);
    Ok(id)
}

/// Submit a branch as a bounty/task solution.
/// Records the submission on the task and optionally runs the acceptance oracle.
pub fn bounty_submit(task_id: &str, branch: &str, room_label: Option<&str>) -> Result<String, String> {
    let room = resolve_room(room_label)?;
    let me = store::get_agent_id();
    let mut tasks = store::load_tasks(&room.room_id);

    // If not in local store, reconstruct from room messages (cross-session support).
    if !tasks.iter().any(|t| t.id.starts_with(task_id)) {
        let msgs = store::load_messages(&room.room_id, 604800);
        for msg in &msgs {
            if msg["type"].as_str() == Some("bounty")
                && msg["id"].as_str().map_or(false, |id| id.starts_with(task_id))
            {
                tasks.push(store::Task {
                    id: msg["id"].as_str().unwrap_or(task_id).to_string(),
                    title: msg["title"].as_str().unwrap_or("").to_string(),
                    status: msg["status"].as_str().unwrap_or("open").to_string(),
                    created_by: msg["from"].as_str().unwrap_or("").to_string(),
                    claimed_by: None,
                    created_at: msg["ts"].as_u64().unwrap_or(0),
                    updated_at: msg["ts"].as_u64().unwrap_or(0),
                    notes: None,
                    acceptance_oracle: msg["acceptance_oracle"].as_str().map(|s| s.to_string()),
                    // Bounty messages may use "reward_credits" or the legacy "reward" key.
                    reward_credits: msg["reward_credits"].as_i64()
                        .or_else(|| msg["reward"].as_i64()),
                    reward_trust: msg["reward_trust"].as_i64(),
                    submissions: vec![],
                });
                break;
            }
        }
    }

    let task = tasks.iter_mut()
        .find(|t| t.id.starts_with(task_id))
        .ok_or_else(|| format!("No task matching '{task_id}'"))?;

    // Prevent bounty poster from submitting to their own bounty (anti-self-dealing)
    if task.created_by == me {
        return Err(format!("Agent {me} cannot submit to their own bounty (self-dealing not permitted)"));
    }

    // Prevent duplicate submissions from same agent
    if task.submissions.iter().any(|s| s.agent_id == me) {
        return Err(format!("Agent {me} already submitted to task {task_id}"));
    }

    task.submissions.push(store::BountySubmission {
        agent_id: me.clone(),
        branch: branch.to_string(),
        submitted_at: now(),
        oracle_passed: None,
    });
    task.updated_at = now();
    let title = task.title.clone();
    let oracle = task.acceptance_oracle.clone();
    store::save_tasks(&room.room_id, &tasks);

    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let env = make_envelope(
        &format!("[bounty submit] {me} → branch '{branch}' for task {task_id}: {title}"),
        None,
    );
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);
    transport::publish(&room.room_id, &encrypted);
    store::save_message(&room.room_id, &env);

    // Auto-verify if oracle is configured and repo has the branch
    if let Some(ref cmd) = oracle {
        match run_oracle_on_branch(branch, cmd) {
            Ok(passed) => {
                // Update oracle result
                let mut tasks2 = store::load_tasks(&room.room_id);
                if let Some(t) = tasks2.iter_mut().find(|t| t.id.starts_with(task_id)) {
                    if let Some(sub) = t.submissions.iter_mut().find(|s| s.agent_id == me) {
                        sub.oracle_passed = Some(passed);
                    }
                    t.updated_at = now();
                }
                store::save_tasks(&room.room_id, &tasks2);
                let result = if passed { "PASS" } else { "FAIL" };
                let env2 = make_envelope(
                    &format!("[bounty oracle] {result}: '{cmd}' on branch '{branch}' (task {task_id})"),
                    None,
                );
                let encrypted2 = encrypt_envelope(&env2, &room_key, &room.room_id);
                transport::publish(&room.room_id, &encrypted2);
                store::save_message(&room.room_id, &env2);
                return Ok(format!("Submitted. Oracle: {result}"));
            }
            Err(e) => return Ok(format!("Submitted. Oracle error: {e}")),
        }
    }

    Ok(format!("Submitted branch '{branch}' for task '{title}'. No oracle configured — manual review required."))
}

/// Run a shell command in the context of a git branch (stashes current state, checks out branch, runs, restores).
fn run_oracle_on_branch(branch: &str, oracle_cmd: &str) -> Result<bool, String> {
    use std::process::Command;

    // Verify branch exists
    let check = Command::new("git")
        .args(["rev-parse", "--verify", &format!("refs/heads/{branch}")])
        .output()
        .map_err(|e| format!("git error: {e}"))?;
    if !check.status.success() {
        return Err(format!("Branch '{branch}' not found locally"));
    }

    // Stash any working-tree changes
    let _ = Command::new("git").args(["stash", "--quiet"]).output();

    // Remember current branch
    let head = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .map_err(|e| format!("git error: {e}"))?;
    let original_branch = String::from_utf8_lossy(&head.stdout).trim().to_string();

    // Checkout submission branch
    let checkout = Command::new("git")
        .args(["checkout", "--quiet", branch])
        .output()
        .map_err(|e| format!("git checkout error: {e}"))?;
    if !checkout.status.success() {
        return Err(format!("Could not checkout branch '{branch}'"));
    }

    // Run oracle
    let parts: Vec<&str> = oracle_cmd.split_whitespace().collect();
    let result = if parts.is_empty() {
        Err("Empty oracle command".to_string())
    } else {
        Command::new(parts[0])
            .args(&parts[1..])
            .output()
            .map(|o| o.status.success())
            .map_err(|e| format!("Oracle exec error: {e}"))
    };

    // Restore original branch
    let _ = Command::new("git")
        .args(["checkout", "--quiet", &original_branch])
        .output();
    let _ = Command::new("git").args(["stash", "pop", "--quiet"]).output();

    result
}

/// Verify an existing submission by running the oracle now (useful for deferred verification).
pub fn bounty_verify(task_id: &str, agent_id: &str, room_label: Option<&str>) -> Result<String, String> {
    let room = resolve_room(room_label)?;
    let mut tasks = store::load_tasks(&room.room_id);
    let task = tasks.iter_mut()
        .find(|t| t.id.starts_with(task_id))
        .ok_or_else(|| format!("No task matching '{task_id}'"))?;
    let oracle = task.acceptance_oracle.clone()
        .ok_or_else(|| "Task has no acceptance_oracle configured".to_string())?;
    let sub = task.submissions.iter_mut()
        .find(|s| s.agent_id.starts_with(agent_id))
        .ok_or_else(|| format!("No submission from agent '{agent_id}'"))?;
    let branch = sub.branch.clone();

    let passed = run_oracle_on_branch(&branch, &oracle)?;
    sub.oracle_passed = Some(passed);
    let reward_credits = task.reward_credits;
    let reward_trust = task.reward_trust;
    let task_title = task.title.clone();
    let task_id_short = task_id[..6.min(task_id.len())].to_string();
    if passed {
        task.status = "done".to_string();
        task.claimed_by = Some(agent_id.to_string());
    }
    task.updated_at = now();
    store::save_tasks(&room.room_id, &tasks);

    let result = if passed { "PASS" } else { "FAIL" };
    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);

    // Auto-distribute credits and trust when oracle passes
    if passed {
        // Issue a work receipt for the winning agent
        let receipt_task = store::Task {
            id: task_id.to_string(),
            title: task_title.clone(),
            status: "done".to_string(),
            created_by: String::new(),
            claimed_by: Some(agent_id.to_string()),
            created_at: now(),
            updated_at: now(),
            notes: Some(format!("oracle:{oracle}")),
            acceptance_oracle: Some(oracle.clone()),
            reward_credits,
            reward_trust,
            submissions: vec![],
        };
        publish_task_receipt(&room, &receipt_task, agent_id, "done", Some(&format!("oracle:{oracle}")), now());

        // Grant credits if configured on the bounty
        if let Some(credits) = reward_credits {
            store::credit_add(&room.room_id, agent_id, credits, &format!("bounty oracle PASS: {task_title} ({task_id_short})"));
            let balance = store::credit_balance(&room.room_id, agent_id);
            let credit_env = make_envelope(
                &format!("[bounty reward] +{credits} credits to {agent_id} for bounty '{task_title}' (balance: {balance})"),
                None,
            );
            let enc = encrypt_envelope(&credit_env, &room_key, &room.room_id);
            transport::publish(&room.room_id, &enc);
            store::save_message(&room.room_id, &credit_env);
        }

        // Grant trust points if configured on the bounty
        if let Some(trust) = reward_trust {
            store::trust_add(&room.room_id, agent_id, trust, &format!("bounty oracle PASS: {task_title}"), "oracle");
        }
    }

    let env = make_envelope(
        &format!("[bounty verify] {result}: '{oracle}' on branch '{branch}' (agent {agent_id}, task {task_id_short})"),
        None,
    );
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);
    transport::publish(&room.room_id, &encrypted);
    store::save_message(&room.room_id, &env);

    Ok(format!("{result}: oracle '{oracle}' on branch '{branch}'"))
}

/// List open bounties in a room.
pub fn bounty_list(room_label: Option<&str>) -> Result<Vec<serde_json::Value>, String> {
    let room = resolve_room(room_label)?;
    let msgs = store::load_messages(&room.room_id, 604800);
    let bounties: Vec<_> = msgs.into_iter()
        .filter(|m| m["type"].as_str() == Some("bounty") && m["status"].as_str() == Some("open"))
        .collect();
    Ok(bounties)
}

// ── Payments ────────────────────────────────────────────────────

const SOLANA_RPC_URL: &str = "https://api.mainnet-beta.solana.com";
const SOLANA_USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const SOLANA_TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const SOLANA_TREASURY_WALLET: &str = "Kh2hZ9Kga9i8WLVxM78VnS51hf7AgGug83rtkSk8vNH";
const SOLANA_USDC_BASE_UNITS_PER_CENT: i64 = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
struct VerifiedSolanaDeposit {
    signature: String,
    amount_raw: i64,
    amount_cents: i64,
    credits: i64,
}

fn parse_token_amount(raw: &serde_json::Value) -> Option<i64> {
    raw.as_str()?.parse::<i64>().ok()
}

fn sum_owner_token_amount(
    balances: &serde_json::Value,
    owner: &str,
    mint: &str,
    program_id: &str,
) -> i64 {
    balances
        .as_array()
        .into_iter()
        .flatten()
        .filter(|entry| {
            entry["owner"].as_str() == Some(owner)
                && entry["mint"].as_str() == Some(mint)
                && entry["programId"].as_str() == Some(program_id)
        })
        .filter_map(|entry| parse_token_amount(&entry["uiTokenAmount"]["amount"]))
        .sum()
}

fn verified_solana_deposit_from_tx(
    signature: &str,
    tx: &serde_json::Value,
    wallet: &str,
) -> Result<VerifiedSolanaDeposit, String> {
    if tx.is_null() {
        return Err(format!("Transaction {signature} not found or not finalized yet."));
    }
    if !tx["meta"]["err"].is_null() {
        return Err(format!("Transaction {signature} failed on-chain."));
    }

    let pre_raw = sum_owner_token_amount(
        &tx["meta"]["preTokenBalances"],
        wallet,
        SOLANA_USDC_MINT,
        SOLANA_TOKEN_PROGRAM,
    );
    let post_raw = sum_owner_token_amount(
        &tx["meta"]["postTokenBalances"],
        wallet,
        SOLANA_USDC_MINT,
        SOLANA_TOKEN_PROGRAM,
    );
    let delta_raw = post_raw - pre_raw;
    if delta_raw <= 0 {
        return Err(format!(
            "Transaction {signature} does not deliver USDC to {wallet}."
        ));
    }
    if delta_raw < SOLANA_USDC_BASE_UNITS_PER_CENT {
        return Err(format!(
            "Transaction {signature} delivered less than $0.01 USDC."
        ));
    }
    if delta_raw % SOLANA_USDC_BASE_UNITS_PER_CENT != 0 {
        return Err(format!(
            "Transaction {signature} amount is not a whole US-cent amount of USDC."
        ));
    }

    let amount_cents = delta_raw / SOLANA_USDC_BASE_UNITS_PER_CENT;
    Ok(VerifiedSolanaDeposit {
        signature: signature.to_string(),
        amount_raw: delta_raw,
        amount_cents,
        credits: amount_cents * store::CREDITS_PER_USD_CENT,
    })
}

fn verify_solana_usdc_transfer(signature: &str) -> Result<VerifiedSolanaDeposit, String> {
    let rpc_url = std::env::var("SOLANA_RPC_URL").unwrap_or_else(|_| SOLANA_RPC_URL.to_string());
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTransaction",
        "params": [
            signature,
            {
                "commitment": "finalized",
                "encoding": "json",
                "maxSupportedTransactionVersion": 0
            }
        ]
    });

    let client = reqwest::blocking::Client::new();
    let response: serde_json::Value = client
        .post(rpc_url)
        .json(&body)
        .send()
        .map_err(|e| format!("Solana RPC error: {e}"))?
        .json()
        .map_err(|e| format!("Solana RPC parse error: {e}"))?;

    if let Some(err) = response["error"]["message"].as_str() {
        return Err(format!("Solana RPC rejected {signature}: {err}"));
    }

    verified_solana_deposit_from_tx(signature, &response["result"], SOLANA_TREASURY_WALLET)
}

fn payment_complete_solana_deposit(
    verified: &VerifiedSolanaDeposit,
    room_label: Option<&str>,
) -> Result<String, String> {
    if store::find_payment_by_reference(&verified.signature).is_some() {
        return Err(format!(
            "Transaction {} was already claimed.",
            verified.signature
        ));
    }

    let room = resolve_room(room_label)?;
    let me = store::get_agent_id();
    let record = store::PaymentRecord {
        id: msg_id(),
        agent_id: me.clone(),
        kind: store::PaymentKind::Deposit,
        status: store::PaymentStatus::Completed,
        provider: store::PaymentProvider::Solana,
        amount_cents: verified.amount_cents,
        credits: verified.credits,
        fee_credits: 0,
        stripe_id: Some(verified.signature.clone()),
        checkout_url: None,
        created_at: now(),
        updated_at: now(),
    };

    let mut payments = store::load_payments();
    payments.push(record);
    store::save_payments(&payments);

    store::credit_add(
        &room.room_id,
        &me,
        verified.credits,
        &format!("solana usdc deposit {}", verified.signature),
    );

    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let env = json!({
        "v": VERSION, "id": msg_id(), "from": me, "ts": now(),
        "type": "payment",
        "action": "solana_verified",
        "tx": verified.signature,
        "credits": verified.credits,
        "amount_cents": verified.amount_cents,
        "text": format!(
            "[payment] {} verified Solana USDC deposit {}: {} credits (${:.2})",
            store::get_agent_id(),
            &verified.signature[..8.min(verified.signature.len())],
            verified.credits,
            verified.amount_cents as f64 / 100.0
        ),
        "hidden": true,
    });
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);
    transport::publish(&room.room_id, &encrypted);
    store::save_message(&room.room_id, &env);

    Ok(format!(
        "Verified Solana USDC deposit {} and minted {} credits (${:.2}).",
        &verified.signature[..8.min(verified.signature.len())],
        verified.credits,
        verified.amount_cents as f64 / 100.0
    ))
}

/// Create a Stripe Checkout session and return the checkout URL.
/// On success the pending PaymentRecord is persisted; credits are only minted
/// when the Stripe webhook confirms `checkout.session.completed`.
///
/// Requires env: STRIPE_SECRET_KEY
/// Optional: STRIPE_SUCCESS_URL, STRIPE_CANCEL_URL
pub fn payment_fund(
    credits: i64,
    room_label: Option<&str>,
) -> Result<String, String> {
    if credits <= 0 {
        return Err("Credits must be positive.".to_string());
    }
    let room = resolve_room(room_label)?;
    let me = store::get_agent_id();

    let stripe_key = std::env::var("STRIPE_SECRET_KEY")
        .map_err(|_| "STRIPE_SECRET_KEY not set. Configure Stripe to enable payments.".to_string())?;
    if stripe_key.is_empty() {
        return Err("STRIPE_SECRET_KEY is empty.".to_string());
    }

    let amount_cents = credits / store::CREDITS_PER_USD_CENT;
    if amount_cents < 50 {
        return Err(format!(
            "Minimum deposit is {} credits ($0.50). Requested {credits}.",
            50 * store::CREDITS_PER_USD_CENT
        ));
    }

    let success_url = std::env::var("STRIPE_SUCCESS_URL")
        .unwrap_or_else(|_| "https://theagora.dev/payment/success?session_id={CHECKOUT_SESSION_ID}".to_string());
    let cancel_url = std::env::var("STRIPE_CANCEL_URL")
        .unwrap_or_else(|_| "https://theagora.dev/payment/cancel".to_string());

    let payment_id = msg_id();

    // Stripe Checkout Session via form-encoded POST (no extra crate needed)
    let params = format!(
        "mode=payment\
         &payment_method_types[]=card\
         &line_items[0][price_data][currency]=usd\
         &line_items[0][price_data][unit_amount]={amount_cents}\
         &line_items[0][price_data][product_data][name]={credits_label}+Agora+Credits\
         &line_items[0][price_data][product_data][description]=1+credit+%3D+%240.001+%2810+credits%2F%240.01%29\
         &line_items[0][quantity]=1\
         &success_url={success_url}\
         &cancel_url={cancel_url}\
         &metadata[agent_id]={me}\
         &metadata[payment_id]={payment_id}\
         &metadata[credits]={credits_meta}\
         &metadata[room_id]={room_id}",
        amount_cents = amount_cents,
        credits_label = credits,
        success_url = urlencoded(&success_url),
        cancel_url = urlencoded(&cancel_url),
        me = urlencoded(&me),
        payment_id = urlencoded(&payment_id),
        credits_meta = credits,
        room_id = urlencoded(&room.room_id),
    );

    let client = reqwest::blocking::Client::new();
    let resp = client
        .post("https://api.stripe.com/v1/checkout/sessions")
        .basic_auth(&stripe_key, None::<&str>)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(params)
        .send()
        .map_err(|e| format!("Stripe API error: {e}"))?;

    let status = resp.status().as_u16();
    let body: serde_json::Value = resp.json()
        .map_err(|e| format!("Stripe response parse error: {e}"))?;

    if status != 200 {
        let err = body["error"]["message"].as_str().unwrap_or("unknown");
        return Err(format!("Stripe error {status}: {err}"));
    }

    let session_id = body["id"].as_str()
        .ok_or("Stripe response missing session id")?
        .to_string();
    let checkout_url = body["url"].as_str()
        .ok_or("Stripe response missing checkout url")?
        .to_string();

    // Persist pending payment record
    let fee_credits = credits / 10; // 10% platform fee
    let record = store::PaymentRecord {
        id: payment_id.clone(),
        agent_id: me.clone(),
        kind: store::PaymentKind::Deposit,
        status: store::PaymentStatus::Pending,
        provider: store::PaymentProvider::Stripe,
        amount_cents,
        credits,
        fee_credits,
        stripe_id: Some(session_id),
        checkout_url: Some(checkout_url.clone()),
        created_at: now(),
        updated_at: now(),
    };
    let mut payments = store::load_payments();
    payments.push(record);
    store::save_payments(&payments);

    // Announce pending deposit to room (hidden)
    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let env = json!({
        "v": VERSION, "id": msg_id(), "from": me, "ts": now(),
        "type": "payment",
        "action": "checkout_created",
        "payment_id": payment_id,
        "credits": credits,
        "amount_cents": amount_cents,
        "text": format!("[payment] {me} initiated deposit: {credits} credits (${:.2})", amount_cents as f64 / 100.0),
        "hidden": true,
    });
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);
    transport::publish(&room.room_id, &encrypted);
    store::save_message(&room.room_id, &env);

    Ok(checkout_url)
}

pub fn payment_fund_via_tx(tx_sig: &str, room_label: Option<&str>) -> Result<String, String> {
    let verified = verify_solana_usdc_transfer(tx_sig)?;
    payment_complete_solana_deposit(&verified, room_label)
}

/// Minimal percent-encoding for Stripe form params.
fn urlencoded(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
            | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// Complete a deposit payment after Stripe webhook confirmation.
/// Called by the webhook handler in serve.rs on `checkout.session.completed`.
/// Mints credits to the agent's ledger and marks the payment completed.
pub fn payment_complete_deposit(
    stripe_session_id: &str,
    room_id: &str,
) -> Result<(), String> {
    let mut payments = store::load_payments();
    let record = payments
        .iter_mut()
        .find(|p| p.stripe_id.as_deref() == Some(stripe_session_id)
              && p.kind == store::PaymentKind::Deposit
              && p.status == store::PaymentStatus::Pending)
        .ok_or_else(|| format!("No pending deposit for session {stripe_session_id}"))?;

    record.status = store::PaymentStatus::Completed;
    record.updated_at = now();
    let agent_id = record.agent_id.clone();
    let credits = record.credits;
    let fee = record.fee_credits;
    let net = credits - fee;

    store::save_payments(&payments);

    // Mint net credits to agent (gross minus platform fee)
    store::credit_add(room_id, &agent_id, net, &format!("stripe deposit {stripe_session_id} (net after 10% fee)"));

    // Collect platform fee to treasury
    let platform = "9d107f-cc"; // platform treasury agent
    store::credit_add(room_id, platform, fee, &format!("platform fee 10% on deposit {stripe_session_id}"));

    Ok(())
}

/// Request a credit withdrawal (credits → USD payout).
/// Creates a pending withdrawal record. Actual payout requires admin approval
/// and bank info on file — agora does not have Stripe Connect yet.
pub fn payment_withdraw(
    credits: i64,
    room_label: Option<&str>,
) -> Result<String, String> {
    if credits <= 0 {
        return Err("Credits must be positive.".to_string());
    }
    let room = resolve_room(room_label)?;
    let me = store::get_agent_id();

    let balance = store::credit_balance(&room.room_id, &me);
    if balance < credits {
        return Err(format!("Insufficient credits: have {balance}, need {credits}."));
    }

    let amount_cents = credits / store::CREDITS_PER_USD_CENT;
    let fee_credits = credits / 10; // 10% withdrawal fee
    let net_credits = credits - fee_credits;
    let net_cents = net_credits / store::CREDITS_PER_USD_CENT;

    if net_cents < 100 {
        return Err(format!(
            "Minimum withdrawal is {} credits (${:.2} net). Requested {credits} credits.",
            (100 * store::CREDITS_PER_USD_CENT * 10 / 9) + 1,
            net_cents as f64 / 100.0,
        ));
    }

    let payment_id = msg_id();
    let record = store::PaymentRecord {
        id: payment_id.clone(),
        agent_id: me.clone(),
        kind: store::PaymentKind::Withdrawal,
        status: store::PaymentStatus::Pending,
        provider: store::PaymentProvider::Manual,
        amount_cents,
        credits,
        fee_credits,
        stripe_id: None,
        checkout_url: None,
        created_at: now(),
        updated_at: now(),
    };

    // Escrow the credits immediately (debit from agent)
    store::credit_add(&room.room_id, &me, -credits, &format!("withdrawal escrow {}", &payment_id[..8]));
    // Collect platform fee
    store::credit_add(&room.room_id, "9d107f-cc", fee_credits, &format!("platform fee 10% on withdrawal {}", &payment_id[..8]));

    let mut payments = store::load_payments();
    payments.push(record);
    store::save_payments(&payments);

    // Publish hidden withdrawal request event
    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let env = json!({
        "v": VERSION, "id": msg_id(), "from": me, "ts": now(),
        "type": "payment",
        "action": "withdrawal_requested",
        "payment_id": payment_id,
        "credits": credits,
        "net_cents": net_cents,
        "text": format!(
            "[payment] {me} requested withdrawal: {credits} credits → ${:.2} (after 10% fee)",
            net_cents as f64 / 100.0
        ),
        "hidden": true,
    });
    let room_key_enc = crypto::derive_room_key(&room.secret, &room.room_id);
    let encrypted = encrypt_envelope(&env, &room_key_enc, &room.room_id);
    transport::publish(&room.room_id, &encrypted);
    store::save_message(&room.room_id, &env);
    let _ = room_key; // silence warning

    Ok(format!(
        "Withdrawal pending: {credits} credits → ${:.2} (net after 10% fee). ID: {}. Admin will process payout.",
        net_cents as f64 / 100.0,
        &payment_id[..8],
    ))
}

/// List payment history for the calling agent.
pub fn payment_history(room_label: Option<&str>) -> Result<Vec<store::PaymentRecord>, String> {
    let _room = resolve_room(room_label)?;
    let me = store::get_agent_id();
    let payments = store::load_payments()
        .into_iter()
        .filter(|p| p.agent_id == me)
        .collect();
    Ok(payments)
}

// ── SOMA — Shared Observable Memory for Agents ─────────────────

fn infer_soma_subject_path(subject: &str) -> Option<String> {
    let candidate = subject.split(':').next()?.trim();
    if candidate.is_empty() || !Path::new(candidate).exists() {
        return None;
    }
    Some(candidate.to_string())
}

fn current_git_head() -> Option<String> {
    let output = Command::new("git").args(["rev-parse", "HEAD"]).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let head = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if head.is_empty() {
        None
    } else {
        Some(head)
    }
}

fn git_churn_commits_since(git_ref: &str, path: &str) -> Option<u64> {
    let range = format!("{git_ref}..HEAD");
    let output = Command::new("git")
        .args(["log", "--follow", "--format=%H", &range, "--", path])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count() as u64,
    )
}

fn soma_churn_decay(churn_commits: u64) -> f64 {
    if churn_commits == 0 {
        return 0.0;
    }
    let capped = (churn_commits as f64).min(SOMA_VOLATILITY_COMMIT_CAP);
    (capped + 1.0).log2() / (SOMA_VOLATILITY_COMMIT_CAP + 1.0).log2()
}

fn soma_effective_confidence(confidence: f64, churn_decay: f64) -> f64 {
    (confidence * (1.0 - churn_decay)).clamp(0.0, 1.0)
}

fn compute_soma_volatility(
    subject: &str,
    confidence: Option<f64>,
    git_ref: Option<&str>,
    stored_path: Option<&str>,
) -> SomaVolatility {
    let path = stored_path
        .map(str::to_string)
        .or_else(|| infer_soma_subject_path(subject));
    let git_ref = git_ref.map(str::to_string);

    let (Some(path), Some(git_ref)) = (path.clone(), git_ref.clone()) else {
        return SomaVolatility {
            path,
            git_ref,
            churn_commits: None,
            churn_decay: None,
            effective_confidence: None,
        };
    };

    let Some(churn_commits) = git_churn_commits_since(&git_ref, &path) else {
        return SomaVolatility {
            path: Some(path),
            git_ref: Some(git_ref),
            churn_commits: None,
            churn_decay: None,
            effective_confidence: None,
        };
    };

    let churn_decay = soma_churn_decay(churn_commits);
    let effective_confidence = confidence.map(|conf| soma_effective_confidence(conf, churn_decay));

    SomaVolatility {
        path: Some(path),
        git_ref: Some(git_ref),
        churn_commits: Some(churn_commits),
        churn_decay: Some(churn_decay),
        effective_confidence,
    }
}

fn annotate_soma_message(msg: &mut serde_json::Value) {
    let volatility = compute_soma_volatility(
        msg["subject"].as_str().unwrap_or(""),
        msg["confidence"].as_f64(),
        msg["git_ref"].as_str(),
        msg["volatility_path"].as_str(),
    );

    if let Some(path) = volatility.path {
        msg["volatility_path"] = json!(path);
    }
    if let Some(git_ref) = volatility.git_ref {
        msg["git_ref"] = json!(git_ref);
    }
    if let Some(churn_commits) = volatility.churn_commits {
        msg["churn_commits"] = json!(churn_commits);
    }
    if let Some(churn_decay) = volatility.churn_decay {
        msg["churn_decay"] = json!(churn_decay);
    }
    if let Some(effective_confidence) = volatility.effective_confidence {
        msg["effective_confidence"] = json!(effective_confidence);
    }
}

pub fn soma_assert(subject: &str, predicate: &str, confidence: Option<f64>, git_ref: Option<&str>, room_label: Option<&str>) -> Result<String, String> {
    let room = resolve_room(room_label)?;
    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let id = msg_id();
    let conf = confidence.unwrap_or(0.8);
    let resolved_git_ref = git_ref.map(str::to_string).or_else(current_git_head);
    let volatility_path = infer_soma_subject_path(subject);
    let volatility = compute_soma_volatility(
        subject,
        Some(conf),
        resolved_git_ref.as_deref(),
        volatility_path.as_deref(),
    );
    let env = json!({
        "v": VERSION, "id": id, "from": store::get_agent_id(), "ts": now(),
        "type": "soma_belief", "subject": subject, "predicate": predicate,
        "confidence": conf,
        "git_ref": resolved_git_ref,
        "volatility_path": volatility.path,
        "churn_commits": volatility.churn_commits,
        "churn_decay": volatility.churn_decay,
        "effective_confidence": volatility.effective_confidence,
        "text": format!("[soma] {subject}: {predicate} (confidence: {:.0}%)", conf * 100.0),
    });
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);
    transport::publish(&room.room_id, &encrypted);
    store::save_message(&room.room_id, &env);
    Ok(id)
}

pub fn soma_query(subject: &str, room_label: Option<&str>) -> Result<Vec<serde_json::Value>, String> {
    let room = resolve_room(room_label)?;
    let msgs = store::load_messages(&room.room_id, 604800);
    let q = subject.to_lowercase();
    let mut beliefs: Vec<serde_json::Value> = msgs.into_iter().filter(|m| {
        (m["type"].as_str() == Some("soma_belief") || m["type"].as_str() == Some("soma_correction")) &&
        m["subject"].as_str().unwrap_or("").to_lowercase().contains(&q)
    }).collect();
    for belief in &mut beliefs {
        annotate_soma_message(belief);
    }
    Ok(beliefs)
}

fn resolve_soma_belief<'a>(
    msgs: &'a [serde_json::Value],
    needle: &str,
) -> Result<&'a serde_json::Value, String> {
    let matches: Vec<&serde_json::Value> = msgs
        .iter()
        .filter(|m| m["type"].as_str() == Some("soma_belief"))
        .filter(|m| {
            m["id"]
                .as_str()
                .map(|id| id == needle || id.starts_with(needle))
                .unwrap_or(false)
        })
        .collect();

    match matches.len() {
        0 => Err(format!("Belief '{needle}' not found in local cache.")),
        1 => Ok(matches[0]),
        _ => Err(format!(
            "Belief ID '{needle}' is ambiguous: {}",
            matches
                .into_iter()
                .filter_map(|m| m["id"].as_str())
                .take(5)
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

pub fn soma_correct(belief_id: &str, new_predicate: &str, reason: Option<&str>, room_label: Option<&str>) -> Result<String, String> {
    let room = resolve_room(room_label)?;
    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let msgs = store::load_messages(&room.room_id, 604800);
    let belief = resolve_soma_belief(&msgs, belief_id)?;
    let resolved_belief_id = belief["id"]
        .as_str()
        .ok_or_else(|| format!("Belief '{belief_id}' is missing an ID."))?;
    let subject = belief["subject"]
        .as_str()
        .ok_or_else(|| format!("Belief '{resolved_belief_id}' is missing a subject."))?
        .to_string();
    let git_ref = belief["git_ref"].as_str().map(str::to_string);
    let volatility_path = belief["volatility_path"]
        .as_str()
        .map(str::to_string)
        .or_else(|| infer_soma_subject_path(&subject));
    let volatility = compute_soma_volatility(
        &subject,
        belief["confidence"].as_f64(),
        git_ref.as_deref(),
        volatility_path.as_deref(),
    );
    let id = msg_id();
    let reason_str = reason.unwrap_or("no reason given");
    let env = json!({
        "v": VERSION, "id": id, "from": store::get_agent_id(), "ts": now(),
        "type": "soma_correction", "corrects": resolved_belief_id, "subject": subject,
        "git_ref": git_ref,
        "volatility_path": volatility.path,
        "churn_commits": volatility.churn_commits,
        "churn_decay": volatility.churn_decay,
        "effective_confidence": volatility.effective_confidence,
        "predicate": new_predicate, "reason": reason_str, "reply_to": resolved_belief_id,
        "text": format!("[soma correction] {subject}: {new_predicate} (reason: {reason_str})"),
    });
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);
    transport::publish(&room.room_id, &encrypted);
    store::save_message(&room.room_id, &env);
    fire_webhooks(&room.room_id, &[env]);
    Ok(id)
}

fn compute_task_hash(
    room_id: &str,
    task_id: &str,
    title: &str,
    agent_id: &str,
    status: &str,
    notes: Option<&str>,
    completed_at: u64,
) -> String {
    let payload = format!(
        "{room_id}\n{task_id}\n{title}\n{agent_id}\n{status}\n{}\n{completed_at}",
        notes.unwrap_or("")
    );
    hex::encode(digest::digest(&digest::SHA256, payload.as_bytes()).as_ref())
}

fn build_work_receipt(
    room: &store::RoomEntry,
    task: &store::Task,
    agent_id: &str,
    status: &str,
    notes: Option<&str>,
    created_at: u64,
) -> store::WorkReceipt {
    let witness_ids = room
        .members
        .iter()
        .filter(|member| member.role == store::Role::Admin)
        .map(|member| member.agent_id.clone())
        .collect::<Vec<_>>();

    store::WorkReceipt {
        id: msg_id(),
        task_id: task.id.clone(),
        task_title: task.title.clone(),
        agent_id: agent_id.to_string(),
        status: status.to_string(),
        notes: notes.map(|note| note.to_string()),
        task_hash: compute_task_hash(
            &room.room_id,
            &task.id,
            &task.title,
            agent_id,
            status,
            notes,
            created_at,
        ),
        witness_ids,
        created_at,
        auth: "verified".to_string(),
    }
}

fn publish_task_receipt(
    room: &store::RoomEntry,
    task: &store::Task,
    agent_id: &str,
    status: &str,
    notes: Option<&str>,
    created_at: u64,
) {
    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let receipt = build_work_receipt(room, task, agent_id, status, notes, created_at);
    store::upsert_work_receipt(&room.room_id, &receipt);
    let verb = if status == "checkpoint" {
        "checkpointed"
    } else {
        "completed"
    };
    let receipt_env = json!({
        "v": VERSION,
        "id": receipt.id,
        "from": agent_id,
        "ts": receipt.created_at,
        "type": "work_receipt",
        "task_id": receipt.task_id,
        "task_title": receipt.task_title,
        "task_hash": receipt.task_hash,
        "receipt_status": receipt.status,
        "receipt_notes": receipt.notes,
        "witness_ids": receipt.witness_ids,
        "text": format!("[receipt] {} {} {}", receipt.agent_id, verb, receipt.task_title),
    });
    let encrypted_receipt = encrypt_envelope(&receipt_env, &room_key, &room.room_id);
    transport::publish(&room.room_id, &encrypted_receipt);
    store::save_message(&room.room_id, &receipt_env);
}

/// Add a task to the room queue.
pub fn task_add(title: &str, room_label: Option<&str>) -> Result<String, String> {
    let room = resolve_room(room_label)?;
    let id = msg_id();
    let me = store::get_agent_id();
    let task = store::Task {
        id: id.clone(),
        title: title.to_string(),
        status: "open".to_string(),
        created_by: me.clone(),
        claimed_by: None,
        created_at: now(),
        updated_at: now(),
        notes: None,
        acceptance_oracle: None,
        reward_credits: None,
        reward_trust: None,
        submissions: vec![],
    };
    let mut tasks = store::load_tasks(&room.room_id);
    tasks.push(task);
    store::save_tasks(&room.room_id, &tasks);

    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let env = make_envelope(&format!("[task] New: {title} (id: {})", &id[..6]), None);
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);
    transport::publish(&room.room_id, &encrypted);
    store::save_message(&room.room_id, &env);
    Ok(id)
}

/// Claim an open task.
pub fn task_claim(task_id: &str, room_label: Option<&str>) -> Result<String, String> {
    let room = resolve_room(room_label)?;
    let me = store::get_agent_id();
    let mut tasks = store::load_tasks(&room.room_id);
    let task = tasks.iter_mut().find(|t| t.id.starts_with(task_id) && t.status == "open")
        .ok_or_else(|| format!("No open task matching '{task_id}'"))?;
    task.status = "claimed".to_string();
    task.claimed_by = Some(me.clone());
    task.updated_at = now();
    let title = task.title.clone();
    let tid = task.id.clone();
    store::save_tasks(&room.room_id, &tasks);

    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let env = make_envelope(&format!("[task] Claimed by {me}: {title}"), None);
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);
    transport::publish(&room.room_id, &encrypted);
    store::save_message(&room.room_id, &env);
    Ok(tid)
}

/// Mark a task as done.
pub fn task_done(task_id: &str, notes: Option<&str>, room_label: Option<&str>) -> Result<String, String> {
    let room = resolve_room(room_label)?;
    let me = store::get_agent_id();
    let mut tasks = store::load_tasks(&room.room_id);
    let task = tasks.iter_mut().find(|t| t.id.starts_with(task_id))
        .ok_or_else(|| format!("No task matching '{task_id}'"))?;
    task.status = "done".to_string();
    task.updated_at = now();
    if let Some(n) = notes { task.notes = Some(n.to_string()); }
    let task_snapshot = task.clone();
    let title = task_snapshot.title.clone();
    let tid = task_snapshot.id.clone();
    store::save_tasks(&room.room_id, &tasks);

    let note_str = notes.map(|n| format!(" — {n}")).unwrap_or_default();
    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let env = make_envelope(&format!("[task] Done by {me}: {title}{note_str}"), None);
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);
    transport::publish(&room.room_id, &encrypted);
    store::save_message(&room.room_id, &env);

    publish_task_receipt(
        &room,
        &task_snapshot,
        &me,
        "done",
        task_snapshot.notes.as_deref(),
        task_snapshot.updated_at,
    );
    Ok(tid)
}

/// Record partial progress on a task without marking it done.
pub fn task_checkpoint(task_id: &str, notes: Option<&str>, room_label: Option<&str>) -> Result<String, String> {
    let room = resolve_room(room_label)?;
    let me = store::get_agent_id();
    let mut tasks = store::load_tasks(&room.room_id);
    let task = tasks
        .iter_mut()
        .find(|t| t.id.starts_with(task_id) && t.status != "done")
        .ok_or_else(|| format!("No active task matching '{task_id}'"))?;

    if let Some(claimed_by) = task.claimed_by.as_deref() {
        if claimed_by != me {
            return Err(format!("Task '{}' is currently claimed by '{}'.", task.id, claimed_by));
        }
    } else {
        task.status = "claimed".to_string();
        task.claimed_by = Some(me.clone());
    }

    task.updated_at = now();
    if let Some(note) = notes {
        task.notes = Some(note.to_string());
    }
    let checkpoint_notes = notes.map(|note| note.to_string()).or_else(|| task.notes.clone());
    let task_snapshot = task.clone();
    let title = task_snapshot.title.clone();
    let tid = task_snapshot.id.clone();
    store::save_tasks(&room.room_id, &tasks);

    let note_str = checkpoint_notes
        .as_deref()
        .map(|note| format!(" — {note}"))
        .unwrap_or_default();
    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let env = make_envelope(&format!("[task] Checkpoint by {me}: {title}{note_str}"), None);
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);
    transport::publish(&room.room_id, &encrypted);
    store::save_message(&room.room_id, &env);

    publish_task_receipt(
        &room,
        &task_snapshot,
        &me,
        "checkpoint",
        checkpoint_notes.as_deref(),
        task_snapshot.updated_at,
    );
    Ok(tid)
}

// ── Calibration Seeds ──────────────────────────────────────────────────────

/// Static puzzle bank. Each entry is (title, puzzle_text, answer, difficulty).
const PUZZLES: &[(&str, &str, &str, &str)] = &[
    (
        "String reversal",
        "Reverse the string 'agora' (no spaces, lowercase).",
        "aroga",
        "easy",
    ),
    (
        "Vowel count",
        "Count the vowels (a,e,i,o,u) in 'cryptographic' (answer is a decimal integer).",
        "3",
        "easy",
    ),
    (
        "Power of two",
        "What is 2^16? (answer is a decimal integer)",
        "65536",
        "easy",
    ),
    (
        "Fibonacci",
        "What is the 10th Fibonacci number? (1-indexed, starting 1,1,..., answer is a decimal integer)",
        "55",
        "easy",
    ),
    (
        "Word count",
        "How many words are in the phrase 'the quick brown fox jumps over the lazy dog'? (answer is a decimal integer)",
        "9",
        "easy",
    ),
    (
        "ROT13 decode",
        "Decode this ROT13 message (lowercase, no punctuation): 'ntnag argjbex'",
        "agent network",
        "medium",
    ),
    (
        "Base64 decode",
        "Base64-decode 'YWdvcmE=' (UTF-8 string, lowercase).",
        "agora",
        "easy",
    ),
    (
        "Hex to decimal",
        "Convert the hex number 'ff' to decimal (answer is a decimal integer).",
        "255",
        "medium",
    ),
    (
        "Prime check",
        "Is 97 a prime number? Answer 'yes' or 'no' (lowercase).",
        "yes",
        "medium",
    ),
    (
        "Caesar cipher",
        "Decrypt this Caesar cipher (shift 3, lowercase, no spaces): 'djhqw'",
        "agent",
        "medium",
    ),
    (
        "SHA256 prefix",
        "What are the first 4 hex characters of the SHA256 hash of 'agora'? (lowercase)",
        "f347",
        "hard",
    ),
    (
        "Anagram solve",
        "Unscramble this anagram into a common English word (lowercase): 'tsure'",
        "trust",
        "medium",
    ),
    (
        "Binary to decimal",
        "Convert binary '10110101' to decimal (answer is a decimal integer).",
        "181",
        "medium",
    ),
];

/// Credits awarded for solving calibration seeds by difficulty.
fn seed_credit_reward(difficulty: &str) -> i64 {
    match difficulty {
        "easy" => 0,
        "medium" => 5,
        "hard" => 25,
        _ => 0,
    }
}

fn sha256_hex(input: &str) -> String {
    let d = digest::digest(&digest::SHA256, input.as_bytes());
    hex::encode(d.as_ref())
}

/// Generate a calibration seed task and publish it to the room.
/// Returns (seed_id, puzzle_text).
pub fn seed_gen(room_label: Option<&str>) -> Result<(String, String), String> {
    let room = resolve_room(room_label)?;
    let me = store::get_agent_id();
    let id = msg_id();

    // Pick puzzle by rotating through based on existing seed count.
    let existing = store::load_seeds(&room.room_id);
    let puzzle_idx = existing.len() % PUZZLES.len();
    let (title, puzzle, answer, difficulty) = PUZZLES[puzzle_idx];

    let seed = store::CalibrationSeed {
        id: id.clone(),
        title: title.to_string(),
        puzzle: puzzle.to_string(),
        answer_hash: sha256_hex(answer),
        difficulty: difficulty.to_string(),
        created_by: me.clone(),
        created_at: now(),
        solved_by: Vec::new(),
    };

    let mut seeds = existing;
    seeds.push(seed);
    store::save_seeds(&room.room_id, &seeds);

    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let credit_reward = seed_credit_reward(difficulty);
    let reward_note = if credit_reward > 0 {
        format!(", reward: {credit_reward} credits")
    } else {
        String::new()
    };
    let msg = format!(
        "[seed] New calibration seed [{id_short}]: {title} ({difficulty}{reward_note}) — solve with: agora seed-verify {id_short} <answer>",
        id_short = &id[..8]
    );
    let env = make_envelope(&msg, None);
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);
    transport::publish(&room.room_id, &encrypted);
    store::save_message(&room.room_id, &env);

    Ok((id, puzzle.to_string()))
}

/// Attempt to verify an answer for a calibration seed.
/// If correct, marks the seed solved and publishes a work receipt.
pub fn seed_verify(seed_id: &str, answer: &str, room_label: Option<&str>) -> Result<bool, String> {
    let room = resolve_room(room_label)?;
    let me = store::get_agent_id();
    let mut seeds = store::load_seeds(&room.room_id);

    let seed = seeds
        .iter_mut()
        .find(|s| s.id.starts_with(seed_id))
        .ok_or_else(|| format!("No calibration seed matching '{seed_id}'"))?;

    let answer_clean = answer.trim().to_lowercase();
    let submitted_hash = sha256_hex(&answer_clean);

    if submitted_hash != seed.answer_hash {
        return Ok(false);
    }

    if seed.solved_by.contains(&me) {
        return Err(format!("You have already solved seed '{}'.", &seed.id[..8]));
    }

    seed.solved_by.push(me.clone());
    let seed_snapshot = seed.clone();
    store::save_seeds(&room.room_id, &seeds);

    // Award credits based on difficulty (autonomous economy bootstrapping).
    let credit_reward = seed_credit_reward(&seed_snapshot.difficulty);

    // Synthesise a Task so we can reuse publish_task_receipt.
    let task = store::Task {
        id: seed_snapshot.id.clone(),
        title: format!("[seed] {}", seed_snapshot.title),
        status: "done".to_string(),
        created_by: seed_snapshot.created_by.clone(),
        claimed_by: Some(me.clone()),
        created_at: seed_snapshot.created_at,
        updated_at: now(),
        notes: Some(format!("difficulty:{}", seed_snapshot.difficulty)),
        acceptance_oracle: None,
        reward_credits: if credit_reward > 0 { Some(credit_reward) } else { None },
        reward_trust: None,
        submissions: vec![],
    };

    publish_task_receipt(&room, &task, &me, "done", task.notes.as_deref(), task.updated_at);

    // Grant credits for medium/hard seeds (proof-of-work bootstrapping).
    if credit_reward > 0 {
        store::credit_add(&room.room_id, &me, credit_reward, &format!("seed:{}", &seed_snapshot.id[..8]));
    }

    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let credit_note = if credit_reward > 0 {
        format!(" (+{credit_reward} credits)")
    } else {
        String::new()
    };
    let msg = format!(
        "[seed] {} solved calibration seed [{}]: {} — receipt issued{credit_note}",
        me,
        &seed_snapshot.id[..8],
        seed_snapshot.title
    );
    let env = make_envelope(&msg, None);
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);
    transport::publish(&room.room_id, &encrypted);
    store::save_message(&room.room_id, &env);

    Ok(true)
}

/// List calibration seeds in the room.
pub fn seed_list(room_label: Option<&str>) -> Result<Vec<store::CalibrationSeed>, String> {
    let room = resolve_room(room_label)?;
    Ok(store::load_seeds(&room.room_id))
}

/// List tasks — merges local state with room messages for cloud agents.
pub fn task_list(room_label: Option<&str>) -> Result<Vec<store::Task>, String> {
    let room = resolve_room(room_label)?;
    let mut tasks = store::load_tasks(&room.room_id);

    // Also scan room messages for task announcements (for agents without local state)
    let msgs = store::load_messages(&room.room_id, 604800);
    for msg in &msgs {
        let text = msg["text"].as_str().unwrap_or("");
        if text.starts_with("[task] New:") {
            // Extract id from "(id: XXXXXX)" at end
            if let Some(id_start) = text.rfind("(id: ") {
                let id = &text[id_start + 5..text.len() - 1];
                if !tasks.iter().any(|t| t.id.starts_with(id)) {
                    let title = text["[task] New: ".len()..id_start].trim().to_string();
                    tasks.push(store::Task {
                        id: id.to_string(),
                        title,
                        status: "open".to_string(),
                        created_by: msg["from"].as_str().unwrap_or("?").to_string(),
                        claimed_by: None,
                        created_at: msg["ts"].as_u64().unwrap_or(0),
                        updated_at: msg["ts"].as_u64().unwrap_or(0),
                        notes: None,
                        acceptance_oracle: None,
                        reward_credits: None,
                        reward_trust: None,
                        submissions: vec![],
                    });
                }
            }
        } else if text.starts_with("[task] Claimed by ") {
            let rest = &text["[task] Claimed by ".len()..];
            if let Some(colon) = rest.find(": ") {
                let claimer = &rest[..colon];
                let title = &rest[colon + 2..];
                if let Some(t) = tasks.iter_mut().find(|t| t.title == title && t.status == "open") {
                    t.status = "claimed".to_string();
                    t.claimed_by = Some(claimer.to_string());
                }
            }
        } else if text.starts_with("[task] Done by ") {
            let rest = &text["[task] Done by ".len()..];
            if let Some(colon) = rest.find(": ") {
                let title_and_notes = &rest[colon + 2..];
                let title = title_and_notes.split(" — ").next().unwrap_or(title_and_notes);
                if let Some(t) = tasks.iter_mut().find(|t| t.title == title) {
                    t.status = "done".to_string();
                }
            }
        }
    }

    // Deduplicate by title
    let mut seen = std::collections::HashSet::new();
    tasks.retain(|t| seen.insert(t.title.clone()));
    Ok(tasks)
}

pub fn list_work_receipts(
    agent_id: Option<&str>,
    room_label: Option<&str>,
) -> Result<Vec<ListedWorkReceipt>, String> {
    let rooms = if let Some(label) = room_label {
        vec![resolve_room(Some(label))?]
    } else {
        store::load_registry()
    };

    let mut receipts = Vec::new();
    for room in rooms {
        for receipt in store::load_work_receipts(&room.room_id) {
            if agent_id.is_some_and(|target| target != receipt.agent_id) {
                continue;
            }
            receipts.push(ListedWorkReceipt {
                room_label: room.label.clone(),
                receipt,
            });
        }
    }

    receipts.sort_by(|a, b| b.receipt.created_at.cmp(&a.receipt.created_at));
    Ok(receipts)
}

/// Activity timeline — all events (messages, joins, files, reactions, profiles, work receipts).
pub fn timeline(since: &str, room_label: Option<&str>) -> Result<Vec<serde_json::Value>, String> {
    let room = resolve_room(room_label)?;
    let since_secs = parse_since(since);
    let mut events = store::load_messages(&room.room_id, since_secs);

    // Annotate event types
    for evt in &mut events {
        let etype = if evt["type"].as_str() == Some("file") {
            "file"
        } else if evt["type"].as_str() == Some("profile") {
            "profile"
        } else if is_work_receipt(evt) {
            "work_receipt"
        } else if evt["type"].as_str() == Some("reaction") {
            "reaction"
        } else if evt["text"].as_str().unwrap_or("").contains("Joined (agora") {
            "join"
        } else if evt["text"].as_str().unwrap_or("").starts_with("Topic set:") {
            "topic"
        } else if evt["text"].as_str().unwrap_or("").starts_with("Promoted ") {
            "admin"
        } else if evt["text"].as_str().unwrap_or("").starts_with("Kicked ") {
            "kick"
        } else if evt["text"].as_str().unwrap_or("").starts_with("[scheduled]") {
            "scheduled"
        } else {
            "message"
        };
        evt["event_type"] = json!(etype);
    }

    events.sort_by_key(|m| m["ts"].as_u64().unwrap_or(0));
    Ok(events)
}

/// Generate a formatted digest report.
pub fn digest(since: &str, room_label: Option<&str>) -> Result<String, String> {
    let room = resolve_room(room_label)?;
    let since_secs = parse_since(since);
    let msgs = store::load_messages(&room.room_id, since_secs);
    let reactions = store::load_reactions(&room.room_id);

    if msgs.is_empty() {
        return Ok(format!("# {} — Digest (last {})\n\nNo activity.", room.label, since));
    }

    let mut agents: HashMap<String, u64> = HashMap::new();
    let mut topics: HashMap<String, u64> = HashMap::new();
    let first_ts = msgs.first().and_then(|m| m["ts"].as_u64()).unwrap_or(0);
    let last_ts = msgs.last().and_then(|m| m["ts"].as_u64()).unwrap_or(0);

    for msg in &msgs {
        let from = msg["from"].as_str().unwrap_or("?").to_string();
        *agents.entry(from).or_insert(0) += 1;
        if let Some(text) = msg["text"].as_str() {
            for word in text.split_whitespace() {
                let w = word.trim_matches(|c: char| !c.is_alphanumeric()).to_lowercase();
                if w.len() >= 5 && !is_stopword(&w) {
                    *topics.entry(w).or_insert(0) += 1;
                }
            }
        }
    }

    let mut sorted_agents: Vec<_> = agents.into_iter().collect();
    sorted_agents.sort_by(|a, b| b.1.cmp(&a.1));
    let mut sorted_topics: Vec<_> = topics.into_iter().collect();
    sorted_topics.sort_by(|a, b| b.1.cmp(&a.1));
    sorted_topics.truncate(8);

    let total_reactions: usize = reactions.values().map(|v| v.len()).sum();

    let first_dt = chrono::DateTime::from_timestamp(first_ts as i64, 0)
        .map(|d| d.format("%H:%M").to_string()).unwrap_or_default();
    let last_dt = chrono::DateTime::from_timestamp(last_ts as i64, 0)
        .map(|d| d.format("%H:%M").to_string()).unwrap_or_default();

    let mut report = format!("# {} — Digest (last {})\n\n", room.label, since);
    report.push_str(&format!("**Period:** {} → {}\n", first_dt, last_dt));
    report.push_str(&format!("**Messages:** {}  |  **Agents:** {}  |  **Reactions:** {}\n\n", msgs.len(), sorted_agents.len(), total_reactions));

    report.push_str("## Participants\n");
    for (agent, count) in &sorted_agents {
        report.push_str(&format!("- **{}**: {} messages\n", agent, count));
    }

    report.push_str("\n## Key Topics\n");
    report.push_str(&sorted_topics.iter().map(|(w, _)| w.as_str()).collect::<Vec<_>>().join(", "));

    report.push_str("\n\n## Highlights\n");
    // Pick messages with most text (likely substantive)
    let mut by_length: Vec<_> = msgs.iter().collect();
    by_length.sort_by(|a, b| {
        let la = a["text"].as_str().unwrap_or("").len();
        let lb = b["text"].as_str().unwrap_or("").len();
        lb.cmp(&la)
    });
    for msg in by_length.iter().take(5) {
        let from = msg["from"].as_str().unwrap_or("?");
        let text = msg["text"].as_str().unwrap_or("");
        let short = &text[..100.min(text.len())];
        report.push_str(&format!("- **{}**: {}\n", from, short));
    }

    Ok(report)
}

/// Add a webhook URL to a room.
pub fn add_webhook(url: &str, room_label: Option<&str>) -> Result<String, String> {
    let room = resolve_room(room_label)?;
    Ok(store::add_webhook(&room.room_id, url))
}

/// Remove a webhook.
pub fn remove_webhook(webhook_id: &str, room_label: Option<&str>) -> Result<bool, String> {
    let room = resolve_room(room_label)?;
    Ok(store::remove_webhook(&room.room_id, webhook_id))
}

/// List webhooks for a room.
pub fn list_webhooks(room_label: Option<&str>) -> Result<Vec<store::Webhook>, String> {
    let room = resolve_room(room_label)?;
    Ok(store::load_webhooks(&room.room_id))
}

/// Fire webhooks for new messages (called from check).
fn fire_webhooks(room_id: &str, msgs: &[serde_json::Value]) {
    let hooks = store::load_webhooks(room_id);
    if hooks.is_empty() || msgs.is_empty() {
        return;
    }
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_else(|_| reqwest::blocking::Client::new());

    for hook in &hooks {
        let payload = json!({
            "room_id": room_id,
            "messages": msgs,
            "count": msgs.len(),
        });
        let _ = client.post(&hook.url)
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(&payload).unwrap())
            .send();
    }
}

/// Find messages where an agent was @mentioned.
pub fn mentions(agent_id: Option<&str>, since: &str, room_label: Option<&str>) -> Result<Vec<serde_json::Value>, String> {
    let room = resolve_room(room_label)?;
    let target = agent_id.unwrap_or(&store::get_agent_id()).to_string();
    let since_secs = parse_since(since);
    let msgs = store::load_messages(&room.room_id, since_secs);
    let pattern = format!("@{target}");

    let results: Vec<serde_json::Value> = msgs.into_iter()
        .filter(|m| {
            let text = m["text"].as_str().unwrap_or("");
            let from = m["from"].as_str().unwrap_or("");
            text.contains(&pattern) && from != target
        })
        .collect();
    Ok(results)
}

/// Extract all URLs shared in the room.
pub fn links(since: &str, room_label: Option<&str>) -> Result<Vec<serde_json::Value>, String> {
    let room = resolve_room(room_label)?;
    let since_secs = parse_since(since);
    let msgs = store::load_messages(&room.room_id, since_secs);
    let url_re = regex::Regex::new(r"https?://[^\s<>\]\)]+").unwrap();

    let mut results = Vec::new();
    for msg in &msgs {
        let text = msg["text"].as_str().unwrap_or("");
        for url_match in url_re.find_iter(text) {
            results.push(json!({
                "url": url_match.as_str(),
                "from": msg["from"],
                "ts": msg["ts"],
                "msg_id": msg["id"],
            }));
        }
    }
    Ok(results)
}

/// Encrypt arbitrary data with the room key. Returns base64.
pub fn encrypt_data(data: &[u8], room_label: Option<&str>) -> Result<String, String> {
    let room = resolve_room(room_label)?;
    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let blob = crypto::encrypt(data, &room_key, room.room_id.as_bytes())
        .map_err(|e| format!("Encrypt failed: {e}"))?;
    Ok(BASE64.encode(&blob))
}

/// Decrypt base64 data with the room key.
pub fn decrypt_data(b64: &str, room_label: Option<&str>) -> Result<Vec<u8>, String> {
    let room = resolve_room(room_label)?;
    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let blob = BASE64.decode(b64).map_err(|e| format!("Decode failed: {e}"))?;
    crypto::decrypt(&blob, &room_key, room.room_id.as_bytes())
        .map_err(|e| format!("Decrypt failed: {e}"))
}

/// Auto-generate a changelog from message history.
/// Finds messages mentioning PRs, shipped features, and milestones.
pub fn changelog(since: &str, room_label: Option<&str>) -> Result<Vec<serde_json::Value>, String> {
    let room = resolve_room(room_label)?;
    let since_secs = parse_since(since);
    let msgs = store::load_messages(&room.room_id, since_secs);

    let keywords = ["shipped", "merged", "built", "added", "fixed", "PR #", "pr #",
        "feature", "released", "deployed", "launched", "done", "complete"];

    let results: Vec<serde_json::Value> = msgs.into_iter()
        .filter(|m| {
            let text = m["text"].as_str().unwrap_or("").to_lowercase();
            keywords.iter().any(|kw| text.contains(&kw.to_lowercase()))
        })
        .collect();

    Ok(results)
}

/// Health check — validate local setup, connectivity, encryption.
pub fn healthcheck(room_label: Option<&str>) -> Result<Vec<(String, bool, String)>, String> {
    let mut checks: Vec<(String, bool, String)> = Vec::new();

    // Check identity
    let id = store::get_agent_id();
    checks.push(("Agent ID".into(), !id.is_empty(), id.clone()));

    // Check rooms
    let rooms = store::load_registry();
    checks.push(("Rooms joined".into(), !rooms.is_empty(), format!("{}", rooms.len())));

    // Check active room
    let active = if let Some(r) = room_label {
        store::find_room(r)
    } else {
        store::get_active_room()
    };
    match &active {
        Some(r) => {
            checks.push(("Active room".into(), true, r.label.clone()));

            // Check encryption
            let room_key = crypto::derive_room_key(&r.secret, &r.room_id);
            let test_data = b"healthcheck";
            match crypto::encrypt(test_data, &room_key, b"test") {
                Ok(blob) => {
                    match crypto::decrypt(&blob, &room_key, b"test") {
                        Ok(pt) => checks.push(("AES-256-GCM".into(), pt == test_data, "encrypt/decrypt OK".into())),
                        Err(e) => checks.push(("AES-256-GCM".into(), false, format!("decrypt failed: {e}"))),
                    }
                }
                Err(e) => checks.push(("AES-256-GCM".into(), false, format!("encrypt failed: {e}"))),
            }

            // Check relay connectivity
            let events = transport::fetch(&r.room_id, "1m");
            checks.push((
                transport::relay_status_label(),
                true,
                format!("{} events in last 1m", events.len()),
            ));

            // Check messages
            let msgs = store::load_messages(&r.room_id, 3600);
            checks.push(("Local messages".into(), true, format!("{} in last 1h", msgs.len())));

            // Check members
            checks.push(("Members tracked".into(), !r.members.is_empty(), format!("{}", r.members.len())));
        }
        None => {
            checks.push(("Active room".into(), false, "none".into()));
        }
    }

    Ok(checks)
}

/// Schedule a message for future delivery.
/// Stores in a queue file; `check` or `send-scheduled` delivers when time is up.
pub fn schedule_message(text: &str, deliver_at: u64, room_label: Option<&str>) -> Result<String, String> {
    let room = resolve_room(room_label)?;
    let id = msg_id();
    let entry = json!({
        "id": id,
        "text": text,
        "deliver_at": deliver_at,
        "room_id": room.room_id,
        "room_label": room.label,
        "created_at": now(),
    });

    let mut queue = store::load_scheduled(&room.room_id);
    queue.push(entry);
    store::save_scheduled(&room.room_id, &queue);
    Ok(id)
}

/// Deliver any scheduled messages whose time has come.
pub fn deliver_scheduled(room_label: Option<&str>) -> Result<Vec<String>, String> {
    let room = resolve_room(room_label)?;
    let mut queue = store::load_scheduled(&room.room_id);
    let current = now();

    let mut delivered = Vec::new();
    let mut remaining = Vec::new();

    for entry in queue.drain(..) {
        let deliver_at = entry["deliver_at"].as_u64().unwrap_or(u64::MAX);
        if deliver_at <= current {
            let text = entry["text"].as_str().unwrap_or("").to_string();
            if let Ok(mid) = send(&format!("[scheduled] {text}"), None, Some(&room.label)) {
                delivered.push(mid);
            }
        } else {
            remaining.push(entry);
        }
    }

    store::save_scheduled(&room.room_id, &remaining);
    Ok(delivered)
}

/// List pending scheduled messages.
pub fn list_scheduled(room_label: Option<&str>) -> Result<Vec<serde_json::Value>, String> {
    let room = resolve_room(room_label)?;
    Ok(store::load_scheduled(&room.room_id))
}

/// Compact old messages: move to archive, keep recent.
pub fn compact(keep_hours: u64, room_label: Option<&str>) -> Result<(usize, usize), String> {
    let room = resolve_room(room_label)?;
    let all_msgs = store::load_messages(&room.room_id, 604800); // load 7 days
    let cutoff = now() - (keep_hours * 3600);

    let mut archived = 0;
    let mut kept = 0;

    // Separate old from recent
    let mut old_msgs = Vec::new();
    for msg in &all_msgs {
        let ts = msg["ts"].as_u64().unwrap_or(0);
        if ts < cutoff {
            old_msgs.push(msg.clone());
            archived += 1;
        } else {
            kept += 1;
        }
    }

    if archived == 0 {
        return Ok((0, kept));
    }

    // Append old messages to archive file
    let archive_path = store::archive_path(&room.room_id);
    let mut archive_data = if archive_path.exists() {
        std::fs::read_to_string(&archive_path).unwrap_or_default()
    } else {
        String::new()
    };

    for msg in &old_msgs {
        archive_data.push_str(&serde_json::to_string(msg).unwrap());
        archive_data.push('\n');
    }
    std::fs::write(&archive_path, &archive_data).map_err(|e| format!("Archive write: {e}"))?;

    // Delete old message files
    store::delete_messages_before(&room.room_id, cutoff);

    Ok((archived, kept))
}

/// Search across ALL joined rooms.
pub fn grep(query: &str, use_regex: bool) -> Result<Vec<(String, serde_json::Value)>, String> {
    let rooms = store::load_registry();
    let re = if use_regex {
        Some(regex::RegexBuilder::new(query)
            .case_insensitive(true)
            .build()
            .map_err(|e| format!("Invalid regex: {e}"))?)
    } else {
        None
    };
    let query_lower = query.to_lowercase();

    let mut results = Vec::new();
    for room in &rooms {
        let msgs = store::load_messages(&room.room_id, 604800);
        for msg in msgs {
            let text = msg["text"].as_str().unwrap_or("");
            let matches = if let Some(ref re) = re {
                re.is_match(text)
            } else {
                text.to_lowercase().contains(&query_lower)
            };
            if matches {
                results.push((room.label.clone(), msg));
            }
        }
    }
    results.sort_by_key(|(_, m)| m["ts"].as_u64().unwrap_or(0));
    Ok(results)
}

/// Broadcast a message to all joined rooms.
pub fn broadcast(message: &str) -> Result<Vec<(String, String)>, String> {
    let rooms = store::load_registry();
    if rooms.is_empty() {
        return Err("No rooms joined.".to_string());
    }
    let mut results = Vec::new();
    for room in &rooms {
        match send(message, None, Some(&room.label)) {
            Ok(mid) => results.push((room.label.clone(), mid)),
            Err(e) => results.push((room.label.clone(), format!("error: {e}"))),
        }
    }
    Ok(results)
}

/// Room statistics dashboard.
pub fn stats(room_label: Option<&str>) -> Result<serde_json::Value, String> {
    let room = resolve_room(room_label)?;
    let msgs = store::load_messages(&room.room_id, 604800); // 7 days
    let receipts = store::load_receipts(&room.room_id);
    let reactions = store::load_reactions(&room.room_id);
    let pins = store::load_pins(&room.room_id);
    let profiles = store::load_profiles(&room.room_id);

    let total = msgs.len();
    let mut agents: HashMap<String, u64> = HashMap::new();
    let mut hourly: HashMap<u64, u64> = HashMap::new();
    let mut file_count: u64 = 0;
    let mut total_chars: u64 = 0;

    for msg in &msgs {
        let from = msg["from"].as_str().unwrap_or("?").to_string();
        *agents.entry(from).or_insert(0) += 1;

        let ts = msg["ts"].as_u64().unwrap_or(0);
        let hour = (ts / 3600) * 3600;
        *hourly.entry(hour).or_insert(0) += 1;

        if msg["type"].as_str() == Some("file") {
            file_count += 1;
        }
        total_chars += msg["text"].as_str().unwrap_or("").len() as u64;
    }

    let total_reactions: usize = reactions.values().map(|v| v.len()).sum();
    let total_receipts: usize = receipts.values().map(|v| v.len()).sum();

    let mut sorted_agents: Vec<_> = agents.into_iter().collect();
    sorted_agents.sort_by(|a, b| b.1.cmp(&a.1));

    // Peak hour
    let peak = hourly.iter().max_by_key(|(_, v)| *v);

    Ok(json!({
        "room": room.label,
        "total_messages": total,
        "total_agents": sorted_agents.len(),
        "total_characters": total_chars,
        "total_files": file_count,
        "total_reactions": total_reactions,
        "total_receipts": total_receipts,
        "total_pins": pins.len(),
        "total_profiles": profiles.len(),
        "agents": sorted_agents.iter().map(|(a, c)| json!({"id": a, "messages": c})).collect::<Vec<_>>(),
        "peak_hour": peak.map(|(h, c)| json!({"ts": h, "messages": c})),
    }))
}

/// Export room history as JSON.
pub fn export(since: &str, out_path: Option<&str>, room_label: Option<&str>) -> Result<(String, usize), String> {
    let room = resolve_room(room_label)?;
    let since_secs = parse_since(since);
    let msgs = store::load_messages(&room.room_id, since_secs);
    let receipts = store::load_receipts(&room.room_id);
    let reactions = store::load_reactions(&room.room_id);
    let pins = store::load_pins(&room.room_id);

    let export = json!({
        "room": {
            "id": room.room_id,
            "label": room.label,
            "topic": room.topic,
            "members": room.members.iter().map(|m| json!({
                "agent_id": m.agent_id,
                "role": format!("{:?}", m.role),
            })).collect::<Vec<_>>(),
        },
        "exported_at": now(),
        "since": since,
        "message_count": msgs.len(),
        "messages": msgs,
        "receipts": receipts,
        "reactions": reactions,
        "pins": pins,
    });

    let json_str = serde_json::to_string_pretty(&export).map_err(|e| format!("JSON error: {e}"))?;
    let count = msgs.len();

    let dest = out_path.unwrap_or_else(|| {
        // Will be handled by caller with a default
        ""
    });
    if dest.is_empty() {
        let default = format!("agora-export-{}-{}.json", room.label, now());
        std::fs::write(&default, &json_str).map_err(|e| format!("Write error: {e}"))?;
        Ok((default, count))
    } else {
        std::fs::write(dest, &json_str).map_err(|e| format!("Write error: {e}"))?;
        Ok((dest.to_string(), count))
    }
}

pub fn info(room_label: Option<&str>) -> Result<serde_json::Value, String> {
    let room = resolve_room(room_label)?;
    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let msgs = store::load_messages(&room.room_id, 7200);
    let members: Vec<_> = room.members.iter().map(|m| {
        json!({
            "agent_id": m.agent_id,
            "role": format!("{:?}", m.role),
            "nickname": m.nickname,
        })
    }).collect();
    Ok(json!({
        "room_id": room.room_id,
        "label": room.label,
        "topic": room.topic,
        "encryption": "AES-256-GCM",
        "key_derivation": "HKDF-SHA256",
        "fingerprint": crypto::fingerprint(&room_key),
        "messages": msgs.len(),
        "members": members,
        "joined_at": room.joined_at,
    }))
}

pub fn who(room_label: Option<&str>, online_only: bool) -> Result<Vec<store::RoomMember>, String> {
    let room = resolve_room(room_label)?;
    if online_only {
        let cutoff = now() - 300; // 5 minutes
        Ok(room.members.into_iter().filter(|m| m.last_seen >= cutoff).collect())
    } else {
        Ok(room.members)
    }
}

pub fn topic(new_topic: &str, room_label: Option<&str>) -> Result<(), String> {
    let mut room = resolve_room(room_label)?;
    let me = store::get_agent_id();
    if !store::is_admin(&room.room_id, &me) {
        return Err("Only admins can set the topic.".to_string());
    }
    room.topic = Some(new_topic.to_string());
    store::update_room(&room);

    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let env = make_envelope(&format!("Topic set: {new_topic}"), None);
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);
    transport::publish(&room.room_id, &encrypted);
    store::save_message(&room.room_id, &env);
    Ok(())
}

pub fn promote(agent_id: &str, room_label: Option<&str>) -> Result<(), String> {
    let room = resolve_room(room_label)?;
    let me = store::get_agent_id();
    if !store::is_admin(&room.room_id, &me) {
        return Err("Only admins can promote members.".to_string());
    }
    store::set_member_role(&room.room_id, agent_id, store::Role::Admin);

    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let env = make_envelope(&format!("Promoted {agent_id} to admin."), None);
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);
    transport::publish(&room.room_id, &encrypted);
    store::save_message(&room.room_id, &env);
    Ok(())
}

pub fn kick(agent_id: &str, room_label: Option<&str>) -> Result<(), String> {
    let room = resolve_room(room_label)?;
    let me = store::get_agent_id();
    if !store::is_admin(&room.room_id, &me) {
        return Err("Only admins can kick members.".to_string());
    }
    if store::is_admin(&room.room_id, agent_id) {
        return Err("Cannot kick another admin.".to_string());
    }
    store::remove_member_from_room(&room.room_id, agent_id);

    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let env = make_envelope(&format!("Kicked {agent_id} from the room."), None);
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);
    transport::publish(&room.room_id, &encrypted);
    store::save_message(&room.room_id, &env);
    Ok(())
}

/// Delete a message from local store and announce deletion. Admin only.
pub fn delete_message(msg_id: &str, room_label: Option<&str>) -> Result<(), String> {
    let room = resolve_room(room_label)?;
    let me = store::get_agent_id();
    if !store::is_admin(&room.room_id, &me) {
        return Err("Only admins can delete messages.".to_string());
    }
    store::delete_message(&room.room_id, msg_id);

    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let env = make_envelope(&format!("[mod] Message {msg_id} deleted by admin."), None);
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);
    transport::publish(&room.room_id, &encrypted);
    store::save_message(&room.room_id, &env);
    Ok(())
}

fn send_watch_heartbeat(room_id: &str) -> Result<(), String> {
    heartbeat(Some(room_id))
}

/// Watch a room in real-time. Calls `on_message` for each new message.
/// Sends a heartbeat every `heartbeat_secs` seconds.
/// Blocks forever.
pub fn watch<F>(room_label: Option<&str>, heartbeat_secs: u64, mut on_message: F) -> Result<(), String>
where
    F: FnMut(&serde_json::Value),
{
    let room = resolve_room(room_label)?;
    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let room_id = room.room_id.clone();
    let mut rate_limit = seed_plaza_rate_limit_state(
        &room,
        &store::load_messages(&room.room_id, PLAZA_RATE_LIMIT_WINDOW_SECS),
    );

    // Track last heartbeat time
    let mut last_heartbeat = now();
    // Send initial heartbeat
    let _ = send_watch_heartbeat(&room_id);

    transport::stream(&room_id, |ts, payload| {
        if let Some(mut env) = decrypt_payload(payload, &room_key, &room_id) {
            if env["ts"].as_u64().unwrap_or(0) == 0 {
                env["ts"] = json!(ts);
            }
            track_presence(&room_id, &env);
            if !allow_incoming_message(&room, &env, ts, &mut rate_limit) {
                return;
            }
            ingest_auxiliary_event(&room_id, &env);
            if should_display_message(&env) {
                store::save_message(&room_id, &env);
                on_message(&env);
            }
        }
        // Periodic heartbeat
        let elapsed = now() - last_heartbeat;
        if elapsed >= heartbeat_secs {
            let _ = send_watch_heartbeat(&room_id);
            last_heartbeat = now();
        }
    });

    Ok(())
}

/// Generate a compact activity summary for a room.
/// Shows: time range, active agents, message counts, top keywords.
pub fn recap(since: &str, room_label: Option<&str>) -> Result<serde_json::Value, String> {
    let room = resolve_room(room_label)?;
    let since_secs = parse_since(since);
    let msgs = store::load_messages(&room.room_id, since_secs);

    if msgs.is_empty() {
        return Ok(json!({
            "room": room.label,
            "since": since,
            "total_messages": 0,
            "summary": "No activity."
        }));
    }

    // Time range
    let first_ts = msgs.first().and_then(|m| m["ts"].as_u64()).unwrap_or(0);
    let last_ts = msgs.last().and_then(|m| m["ts"].as_u64()).unwrap_or(0);

    // Per-agent message counts
    let mut agent_counts: HashMap<String, u64> = HashMap::new();
    let mut words: HashMap<String, u64> = HashMap::new();

    for msg in &msgs {
        let from = msg["from"].as_str().unwrap_or("?").to_string();
        *agent_counts.entry(from).or_insert(0) += 1;

        // Extract keywords (words 4+ chars, skip common ones)
        if let Some(text) = msg["text"].as_str() {
            for word in text.split_whitespace() {
                let w = word.trim_matches(|c: char| !c.is_alphanumeric()).to_lowercase();
                if w.len() >= 4 && !is_stopword(&w) {
                    *words.entry(w).or_insert(0) += 1;
                }
            }
        }
    }

    // Sort agents by message count
    let mut agents: Vec<_> = agent_counts.into_iter().collect();
    agents.sort_by(|a, b| b.1.cmp(&a.1));

    // Top 10 keywords
    let mut top_words: Vec<_> = words.into_iter().collect();
    top_words.sort_by(|a, b| b.1.cmp(&a.1));
    top_words.truncate(10);

    Ok(json!({
        "room": room.label,
        "since": since,
        "total_messages": msgs.len(),
        "time_range": {
            "first": first_ts,
            "last": last_ts,
        },
        "agents": agents.iter().map(|(a, c)| json!({"id": a, "messages": c})).collect::<Vec<_>>(),
        "top_keywords": top_words.iter().map(|(w, c)| json!({"word": w, "count": c})).collect::<Vec<_>>(),
    }))
}

fn is_stopword(w: &str) -> bool {
    matches!(w, "that" | "this" | "with" | "from" | "have" | "been"
        | "will" | "your" | "they" | "what" | "when" | "were" | "them"
        | "then" | "than" | "each" | "just" | "also" | "into" | "some"
        | "more" | "here" | "agora" | "room" | "send" | "read" | "check"
        | "should" | "would" | "could" | "about" | "there" | "which"
        | "their" | "after" | "before" | "still" | "already" | "need"
        | "want" | "like" | "make" | "does" | "done" | "good" | "work"
        | "working" | "works" | "built" | "build" | "main" | "branch"
        | "push" | "pull" | "merge" | "merged")
}

// ── File Sharing ───────────────────────────────────────────────

const MAX_INLINE_FILE_SIZE: usize = 32 * 1024; // 32KB

fn make_file_envelope(filename: &str, file_id: &str, data: &str, size: u64, chunk_n: u64, total_chunks: u64) -> serde_json::Value {
    json!({
        "v": VERSION,
        "id": msg_id(),
        "from": store::get_agent_id(),
        "ts": now(),
        "type": "file",
        "file_id": file_id,
        "filename": filename,
        "size": size,
        "chunk_n": chunk_n,
        "total_chunks": total_chunks,
        "data": data,
        "text": format!("[file: {} ({} bytes)]", filename, size),
    })
}

fn is_file_msg(env: &serde_json::Value) -> bool {
    env["type"].as_str() == Some("file")
}

/// Send a file to the room. Encrypts and chunks if needed.
pub fn send_file(path: &str, room_label: Option<&str>) -> Result<(String, u64), String> {
    let room = resolve_room(room_label)?;
    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);

    let file_data = std::fs::read(path).map_err(|e| format!("Cannot read file: {e}"))?;
    let filename = std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unnamed")
        .to_string();
    let size = file_data.len() as u64;
    let file_id = msg_id();

    let chunks: Vec<&[u8]> = if file_data.len() <= MAX_INLINE_FILE_SIZE {
        vec![&file_data]
    } else {
        file_data.chunks(MAX_INLINE_FILE_SIZE).collect()
    };
    let total_chunks = chunks.len() as u64;

    for (i, chunk) in chunks.iter().enumerate() {
        let b64_data = BASE64.encode(chunk);
        let env = make_file_envelope(&filename, &file_id, &b64_data, size, i as u64, total_chunks);
        let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);
        transport::publish(&room.room_id, &encrypted);
        store::save_message(&room.room_id, &env);
    }

    Ok((file_id, size))
}

/// List files shared in the room.
pub fn list_files(room_label: Option<&str>) -> Result<Vec<serde_json::Value>, String> {
    let room = resolve_room(room_label)?;
    let msgs = store::load_messages(&room.room_id, 604800); // 7 days
    let mut files: Vec<serde_json::Value> = Vec::new();
    let mut seen_ids: std::collections::HashSet<String> = std::collections::HashSet::new();

    for msg in &msgs {
        if is_file_msg(msg) {
            let fid = msg["file_id"].as_str().unwrap_or("?").to_string();
            if msg["chunk_n"].as_u64().unwrap_or(0) == 0 && !seen_ids.contains(&fid) {
                seen_ids.insert(fid);
                files.push(json!({
                    "file_id": msg["file_id"],
                    "filename": msg["filename"],
                    "size": msg["size"],
                    "from": msg["from"],
                    "ts": msg["ts"],
                    "chunks": msg["total_chunks"],
                }));
            }
        }
    }
    Ok(files)
}

/// Download a file from the room by file_id.
pub fn download_file(file_id: &str, out_path: Option<&str>, room_label: Option<&str>) -> Result<String, String> {
    let room = resolve_room(room_label)?;
    let msgs = store::load_messages(&room.room_id, 604800);

    // Collect all chunks for this file
    let mut chunks: Vec<(u64, String)> = Vec::new();
    let mut filename = String::from("unnamed");
    let mut total_chunks: u64 = 1;

    for msg in &msgs {
        if is_file_msg(msg) {
            let fid = msg["file_id"].as_str().unwrap_or("");
            if fid == file_id || fid.starts_with(file_id) {
                let chunk_n = msg["chunk_n"].as_u64().unwrap_or(0);
                let data = msg["data"].as_str().unwrap_or("").to_string();
                chunks.push((chunk_n, data));
                if chunk_n == 0 {
                    filename = msg["filename"].as_str().unwrap_or("unnamed").to_string();
                    total_chunks = msg["total_chunks"].as_u64().unwrap_or(1);
                }
            }
        }
    }

    if chunks.is_empty() {
        return Err(format!("File '{file_id}' not found."));
    }
    if chunks.len() as u64 != total_chunks {
        return Err(format!("Incomplete file: got {}/{} chunks.", chunks.len(), total_chunks));
    }

    // Sort by chunk number and reassemble
    chunks.sort_by_key(|(n, _)| *n);
    let mut file_data = Vec::new();
    for (_, data) in &chunks {
        let decoded = BASE64.decode(data).map_err(|e| format!("Decode error: {e}"))?;
        file_data.extend_from_slice(&decoded);
    }

    // Write to file
    let dest = out_path.unwrap_or(&filename);
    std::fs::write(dest, &file_data).map_err(|e| format!("Write error: {e}"))?;
    Ok(dest.to_string())
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use super::{
        allow_incoming_message, annotate_soma_message, count_invite_redemptions_in_envs,
        decrypt_payload, discover, discovery_decay_weight, enforce_outbound_plaza_rate_limit,
        encrypt_envelope,
        infer_soma_subject_path, ingest_auxiliary_event, list_role_leases, list_work_receipts,
        make_envelope, make_invite_redemption, pin, pins, resolve_room, role_claim,
        role_heartbeat, role_release, payment_complete_solana_deposit,
        seed_plaza_rate_limit_state, send_watch_heartbeat,
        should_display_message, signing_message_bytes, soma_churn_decay, soma_correct,
        bounty_submit, bounty_verify, stale_claim_weight, task_add, task_add_with_oracle,
        task_checkpoint, task_done, unpin,
        verified_solana_deposit_from_tx, SignedWirePayload, VerifiedSolanaDeposit,
        SIGNED_WIRE_VERSION, BASE64, DISCOVERY_POSITIVE_HALF_LIFE_SECS,
        PLAZA_RATE_LIMIT_WINDOW_SECS, SOLANA_TOKEN_PROGRAM, SOLANA_TREASURY_WALLET,
        SOLANA_USDC_MINT,
    };
    use crate::crypto;
    use crate::store::{self, Role};
    use serde_json::json;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_home() -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("agora-watch-heartbeat-{ts}"))
    }

    fn member_last_seen(room_label: &str) -> u64 {
        let me = store::get_agent_id();
        let room = store::find_room(room_label).expect("room exists");
        room.members
            .into_iter()
            .find(|m| m.agent_id == me)
            .map(|m| m.last_seen)
            .unwrap_or(0)
    }

    fn setup_pin_room() -> (PathBuf, String, String) {
        let home = std::env::temp_dir().join(format!(
            "agora-pin-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&home).unwrap();
        unsafe {
            std::env::set_var("HOME", &home);
            std::env::set_var("AGORA_AGENT_ID", "pin-test");
        }

        let room = store::add_room("ag-pin-test", "secret-pin", "pins", Role::Admin);
        store::set_active_room("pins");
        let first = "aaaabbbb".to_string();
        let second = "ccccdddd".to_string();

        store::save_message(&room.room_id, &json!({
            "id": first,
            "from": "pin-test",
            "ts": 100,
            "text": "first",
            "v": "3.0",
        }));
        store::save_message(&room.room_id, &json!({
            "id": second,
            "from": "pin-test",
            "ts": 101,
            "text": "second",
            "v": "3.0",
        }));

        (home, first, second)
    }

    fn setup_plaza_room(agent_id: &str, role: Role) -> (PathBuf, store::RoomEntry) {
        let home = std::env::temp_dir().join(format!(
            "agora-plaza-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&home).unwrap();
        unsafe {
            std::env::set_var("HOME", &home);
            std::env::set_var("AGORA_AGENT_ID", agent_id);
        }

        let room = store::add_room("ag-plaza-test", "secret-plaza", "plaza", role);
        store::set_active_room("plaza");
        (home, room)
    }

    fn setup_soma_room() -> (PathBuf, store::RoomEntry) {
        let home = std::env::temp_dir().join(format!(
            "agora-soma-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&home).unwrap();
        unsafe {
            std::env::set_var("HOME", &home);
            std::env::set_var("AGORA_AGENT_ID", "soma-test");
        }

        let room = store::add_room("ag-soma-test", "secret-soma", "soma", Role::Admin);
        store::set_active_room("soma");
        (home, room)
    }

    fn current_ts() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn run_git(cwd: &std::path::Path, args: &[&str]) -> std::process::Output {
        std::process::Command::new("git")
            .args(args)
            .current_dir(cwd)
            .output()
            .unwrap()
    }

    #[test]
    fn resolve_room_reports_missing_explicit_target() {
        let _guard = store::test_env_lock().lock().unwrap();
        let home = temp_home();
        std::fs::create_dir_all(&home).unwrap();
        unsafe {
            std::env::set_var("HOME", &home);
            std::env::set_var("AGORA_AGENT_ID", "watch-test");
        }

        let err = resolve_room(Some("missing-room")).unwrap_err();
        assert_eq!(err, "Room 'missing-room' not found. Run: agora rooms");
    }

    #[test]
    fn watch_heartbeat_targets_watched_room_not_active_room() {
        let _guard = store::test_env_lock().lock().unwrap();
        let home = temp_home();
        std::fs::create_dir_all(&home).unwrap();
        unsafe {
            std::env::set_var("HOME", &home);
            std::env::set_var("AGORA_AGENT_ID", "watch-test");
        }

        let alpha = store::add_room("ag-alpha", "secret-alpha", "alpha", Role::Admin);
        let beta = store::add_room("ag-beta", "secret-beta", "beta", Role::Admin);
        store::set_active_room("alpha");

        let mut rooms = store::load_registry();
        for room in &mut rooms {
            for member in &mut room.members {
                member.last_seen = 0;
            }
        }
        store::save_registry(&rooms);

        send_watch_heartbeat(&beta.room_id).unwrap();

        assert_eq!(member_last_seen(&alpha.label), 0);
        assert!(member_last_seen(&beta.label) > 0);
    }

    #[test]
    fn incoming_plaza_rate_limit_mutes_spammer() {
        let _guard = store::test_env_lock().lock().unwrap();
        let (_home, room) = setup_plaza_room("listener", Role::Member);
        let now_ts = current_ts();

        for i in 0..10 {
            store::save_message(&room.room_id, &json!({
                "id": format!("spam{i}"),
                "from": "spammer",
                "ts": now_ts - 30 + i,
                "text": format!("msg {i}"),
                "v": "3.0",
            }));
        }

        let recent = store::load_messages(&room.room_id, PLAZA_RATE_LIMIT_WINDOW_SECS);
        let mut state = seed_plaza_rate_limit_state(&room, &recent);
        let overflow = json!({
            "id": "overflow",
            "from": "spammer",
            "ts": now_ts,
            "text": "too much",
            "v": "3.0",
        });

        assert!(!allow_incoming_message(&room, &overflow, now_ts, &mut state));
        assert!(store::load_muted(&room.room_id).contains("spammer"));
    }

    #[test]
    fn outbound_plaza_rate_limit_rejects_eleventh_message() {
        let _guard = store::test_env_lock().lock().unwrap();
        let (_home, room) = setup_plaza_room("speaker", Role::Member);
        let now_ts = current_ts();

        for i in 0..10 {
            store::save_message(&room.room_id, &json!({
                "id": format!("mine{i}"),
                "from": "speaker",
                "ts": now_ts - 30 + i,
                "text": format!("own {i}"),
                "v": "3.0",
            }));
        }

        let err = enforce_outbound_plaza_rate_limit(&room, "speaker").unwrap_err();
        assert!(err.contains("Plaza rate limit exceeded"));
    }

    #[test]
    fn receipts_are_not_display_messages() {
        let receipt = json!({
            "id": "receipt1",
            "from": "reader",
            "ts": current_ts(),
            "type": "receipt",
            "read_ids": ["abc123"],
            "text": "",
            "v": "3.0",
        });

        assert!(!should_display_message(&receipt));
    }

    #[test]
    fn task_done_generates_work_receipt() {
        let _guard = store::test_env_lock().lock().unwrap();
        let (_home, _room) = setup_plaza_room("receipt-admin", Role::Admin);

        let task_id = task_add("Ship receipts", None).unwrap();
        task_done(&task_id, Some("PR #60"), None).unwrap();

        let receipts = list_work_receipts(Some("receipt-admin"), Some("plaza")).unwrap();
        assert_eq!(receipts.len(), 1);
        let receipt = &receipts[0].receipt;
        assert_eq!(receipt.task_id, task_id);
        assert_eq!(receipt.task_title, "Ship receipts");
        assert_eq!(receipt.status, "done");
        assert_eq!(receipt.notes.as_deref(), Some("PR #60"));
        assert_eq!(receipt.auth, "verified");
        assert_eq!(receipt.witness_ids, vec!["receipt-admin".to_string()]);
        assert_eq!(receipt.task_hash.len(), 64);
    }

    #[test]
    fn task_checkpoint_generates_work_receipt_without_closing_task() {
        let _guard = store::test_env_lock().lock().unwrap();
        let (_home, room) = setup_plaza_room("receipt-admin", Role::Admin);

        let task_id = task_add("Ship checkpoint", None).unwrap();
        let checkpoint_id = task_checkpoint(&task_id, Some("half done"), None).unwrap();
        assert_eq!(checkpoint_id, task_id);

        let tasks = store::load_tasks(&room.room_id);
        let task = tasks
            .iter()
            .find(|task| task.id == task_id)
            .expect("task exists");
        assert_eq!(task.status, "claimed");
        assert_eq!(task.claimed_by.as_deref(), Some("receipt-admin"));
        assert_eq!(task.notes.as_deref(), Some("half done"));

        let receipts = list_work_receipts(Some("receipt-admin"), Some("plaza")).unwrap();
        assert_eq!(receipts.len(), 1);
        let receipt = &receipts[0].receipt;
        assert_eq!(receipt.task_id, task_id);
        assert_eq!(receipt.status, "checkpoint");
        assert_eq!(receipt.notes.as_deref(), Some("half done"));
        assert_eq!(receipt.auth, "verified");
        assert_eq!(receipt.witness_ids, vec!["receipt-admin".to_string()]);
    }

    #[test]
    fn work_receipts_are_hidden_messages_but_cached() {
        let _guard = store::test_env_lock().lock().unwrap();
        let (_home, room) = setup_plaza_room("receipt-reader", Role::Admin);
        let env = json!({
            "id": "wr01",
            "from": "peer-agent",
            "ts": current_ts(),
            "type": "work_receipt",
            "task_id": "task01",
            "task_title": "Implement receipts",
            "task_hash": "abc123",
            "receipt_status": "checkpoint",
            "receipt_notes": "done",
            "witness_ids": ["admin-a", "admin-b"],
            "text": "[receipt] peer-agent completed Implement receipts",
            "_auth": "verified",
            "v": "3.0",
        });

        assert!(!should_display_message(&env));
        ingest_auxiliary_event(&room.room_id, &env);

        let receipts = list_work_receipts(Some("peer-agent"), Some("plaza")).unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].receipt.task_id, "task01");
        assert_eq!(receipts[0].receipt.status, "checkpoint");
        assert_eq!(receipts[0].receipt.witness_ids.len(), 2);
        assert_eq!(receipts[0].receipt.auth, "verified");
    }

    #[test]
    fn verified_solana_deposit_extracts_wallet_usdc_delta() {
        let tx = json!({
            "meta": {
                "err": null,
                "preTokenBalances": [
                    {
                        "owner": SOLANA_TREASURY_WALLET,
                        "mint": SOLANA_USDC_MINT,
                        "programId": SOLANA_TOKEN_PROGRAM,
                        "uiTokenAmount": { "amount": "1500000" }
                    },
                    {
                        "owner": "other-owner",
                        "mint": SOLANA_USDC_MINT,
                        "programId": SOLANA_TOKEN_PROGRAM,
                        "uiTokenAmount": { "amount": "900000" }
                    }
                ],
                "postTokenBalances": [
                    {
                        "owner": SOLANA_TREASURY_WALLET,
                        "mint": SOLANA_USDC_MINT,
                        "programId": SOLANA_TOKEN_PROGRAM,
                        "uiTokenAmount": { "amount": "2500000" }
                    },
                    {
                        "owner": "other-owner",
                        "mint": SOLANA_USDC_MINT,
                        "programId": SOLANA_TOKEN_PROGRAM,
                        "uiTokenAmount": { "amount": "100000" }
                    }
                ]
            }
        });

        let verified =
            verified_solana_deposit_from_tx("sig123", &tx, SOLANA_TREASURY_WALLET).unwrap();
        assert_eq!(verified.amount_raw, 1_000_000);
        assert_eq!(verified.amount_cents, 100);
        assert_eq!(verified.credits, 1000);
    }

    #[test]
    fn payment_complete_solana_deposit_mints_once() {
        let _guard = store::test_env_lock().lock().unwrap();
        let (_home, room) = setup_plaza_room("solana-funder", Role::Admin);
        let verified = VerifiedSolanaDeposit {
            signature: "solsig123".to_string(),
            amount_raw: 2_500_000,
            amount_cents: 250,
            credits: 2500,
        };

        let msg = payment_complete_solana_deposit(&verified, Some("plaza")).unwrap();
        assert!(msg.contains("minted 2500 credits"));
        assert_eq!(store::credit_balance(&room.room_id, "solana-funder"), 2500);

        let payments = store::load_payments();
        assert_eq!(payments.len(), 1);
        assert_eq!(payments[0].stripe_id.as_deref(), Some("solsig123"));
        assert!(matches!(payments[0].provider, store::PaymentProvider::Solana));

        let dup = payment_complete_solana_deposit(&verified, Some("plaza")).unwrap_err();
        assert!(dup.contains("already claimed"));
    }

    #[test]
    fn role_state_messages_are_hidden_but_cached() {
        let _guard = store::test_env_lock().lock().unwrap();
        let (_home, room) = setup_plaza_room("role-reader", Role::Admin);
        let now_ts = current_ts();
        let env = json!({
            "id": "role1",
            "from": "backend-peer",
            "ts": now_ts,
            "type": "role_state",
            "role_name": "backend",
            "role_action": "claim",
            "lease_expires": now_ts + 900,
            "last_heartbeat": now_ts,
            "context_summary": "Owns transport",
            "last_task_ids": ["task123"],
            "text": "[role] backend-peer claimed backend",
        });

        assert!(!should_display_message(&env));
        ingest_auxiliary_event(&room.room_id, &env);

        let lease = store::get_role_lease(&room.room_id, "backend").unwrap();
        assert_eq!(lease.agent_id, "backend-peer");
        assert_eq!(lease.context_summary.as_deref(), Some("Owns transport"));
        assert_eq!(lease.last_task_ids, vec!["task123".to_string()]);
    }

    #[test]
    fn role_claim_heartbeat_and_release_manage_leases() {
        let _guard = store::test_env_lock().lock().unwrap();
        let (_home, room) = setup_plaza_room("backend-agent", Role::Admin);

        let claimed = role_claim("backend", Some("Owns chat/store"), 900, Some("plaza")).unwrap();
        assert_eq!(claimed.role, "backend");
        assert_eq!(claimed.agent_id, "backend-agent");
        assert_eq!(claimed.context_summary.as_deref(), Some("Owns chat/store"));

        let leases = list_role_leases(Some("plaza")).unwrap();
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].role, "backend");

        let heartbeat =
            role_heartbeat("backend", Some("Owns transport too"), 1200, Some("plaza")).unwrap();
        assert!(heartbeat.lease_expires >= claimed.lease_expires);
        let stored = store::get_role_lease(&room.room_id, "backend").unwrap();
        assert_eq!(stored.context_summary.as_deref(), Some("Owns transport too"));

        role_release("backend", Some("plaza")).unwrap();
        assert!(store::get_role_lease(&room.room_id, "backend").is_none());
    }

    #[test]
    fn stale_claims_decay_slower_than_positive_receipts() {
        let age = 8 * 24 * 60 * 60;
        let positive = discovery_decay_weight(age, DISCOVERY_POSITIVE_HALF_LIFE_SECS);
        let negative = stale_claim_weight(age);

        assert!(negative > positive);
    }

    #[test]
    fn discover_penalizes_stale_claims_and_capability_volatility() {
        let _guard = store::test_env_lock().lock().unwrap();
        let (_home, room) = setup_plaza_room("discover-admin", Role::Admin);
        let now_ts = current_ts();

        store::save_peer_card(
            &room.room_id,
            &store::CapabilityCard {
                agent_id: "steady".to_string(),
                capabilities: vec!["rust".to_string(), "agent-systems".to_string()],
                available: true,
                description: Some("recently shipped work".to_string()),
                updated_at: now_ts - 2 * 24 * 60 * 60,
            },
        );
        store::save_peer_card(
            &room.room_id,
            &store::CapabilityCard {
                agent_id: "flaky".to_string(),
                capabilities: vec!["rust".to_string(), "agent-systems".to_string()],
                available: true,
                description: Some("fresh card, stale execution".to_string()),
                updated_at: now_ts - 300,
            },
        );
        store::upsert_work_receipt(
            &room.room_id,
            &store::WorkReceipt {
                id: "receipt-steady".to_string(),
                task_id: "task-steady".to_string(),
                task_title: "Ship feature".to_string(),
                agent_id: "steady".to_string(),
                status: "done".to_string(),
                notes: Some("merged".to_string()),
                task_hash: "abcd1234".to_string(),
                witness_ids: vec!["discover-admin".to_string()],
                created_at: now_ts - 60 * 60,
                auth: "verified".to_string(),
            },
        );
        store::save_tasks(
            &room.room_id,
            &[store::Task {
                id: "task-flaky".to_string(),
                title: "Unfinished migration".to_string(),
                status: "claimed".to_string(),
                created_by: "discover-admin".to_string(),
                claimed_by: Some("flaky".to_string()),
                created_at: now_ts - 10 * 24 * 60 * 60,
                updated_at: now_ts - 10 * 24 * 60 * 60,
                notes: Some("went dark".to_string()),
                acceptance_oracle: None,
                reward_credits: None,
                reward_trust: None,
                submissions: vec![],
            }],
        );

        let results = discover("rust", Some("plaza")).unwrap();
        assert_eq!(results.len(), 2);

        let steady = results
            .iter()
            .find(|result| result.card.agent_id == "steady")
            .expect("steady result");
        let flaky = results
            .iter()
            .find(|result| result.card.agent_id == "flaky")
            .expect("flaky result");

        assert_eq!(results[0].card.agent_id, "steady");
        assert_eq!(flaky.stale_claims, 1);
        assert!(steady.trust_score > flaky.trust_score);
        assert!(steady.abandonment_rate < flaky.abandonment_rate);
        assert!(flaky.abandonment_rate > 0.5);
        assert!(flaky.volatility_score > 0.9);
    }

    #[test]
    fn pin_and_unpin_round_trip() {
        let _guard = store::test_env_lock().lock().unwrap();
        let (_home, first, _second) = setup_pin_room();

        let (resolved, added) = pin("aaaa", None).unwrap();
        assert_eq!(resolved, first);
        assert!(added);

        let pinned = pins(None).unwrap();
        assert_eq!(pinned.len(), 1);
        assert_eq!(pinned[0]["id"].as_str(), Some(first.as_str()));

        let (_, added_again) = pin("aaaa", None).unwrap();
        assert!(!added_again);

        let (unpinned, removed) = unpin("aaaa", None).unwrap();
        assert_eq!(unpinned, first);
        assert!(removed);
        assert!(pins(None).unwrap().is_empty());
    }

    #[test]
    fn soma_correct_uses_canonical_belief_id() {
        let _guard = store::test_env_lock().lock().unwrap();
        let (_home, room) = setup_soma_room();
        let belief_id = "abcd1234".to_string();
        store::save_message(&room.room_id, &json!({
            "id": belief_id,
            "from": "soma-test",
            "ts": current_ts(),
            "type": "soma_belief",
            "subject": "src/chat.rs:soma_correct",
            "predicate": "returns success for unknown belief ids",
            "confidence": 0.7,
            "v": "3.0",
            "text": "[soma] src/chat.rs:soma_correct: returns success for unknown belief ids",
        }));

        let correction_id =
            soma_correct("abcd", "rejects unknown belief ids", Some("regression fix"), None)
                .unwrap();
        let msgs = store::load_messages(&room.room_id, u64::MAX);
        let correction = msgs
            .iter()
            .find(|m| m["id"].as_str() == Some(correction_id.as_str()))
            .unwrap();

        assert_eq!(correction["corrects"].as_str(), Some("abcd1234"));
        assert_eq!(correction["reply_to"].as_str(), Some("abcd1234"));
        assert_eq!(
            correction["subject"].as_str(),
            Some("src/chat.rs:soma_correct")
        );
    }

    #[test]
    fn soma_correct_rejects_missing_belief() {
        let _guard = store::test_env_lock().lock().unwrap();
        let (_home, _room) = setup_soma_room();

        let err = soma_correct("deadbeef", "new predicate", Some("missing"), None).unwrap_err();
        assert_eq!(err, "Belief 'deadbeef' not found in local cache.");
    }

    #[test]
    fn soma_correct_rejects_ambiguous_belief_prefix() {
        let _guard = store::test_env_lock().lock().unwrap();
        let (_home, room) = setup_soma_room();
        let base_ts = current_ts();
        for (id, ts) in [("abcd1111", base_ts), ("abcd2222", base_ts + 1)] {
            store::save_message(&room.room_id, &json!({
                "id": id,
                "from": "soma-test",
                "ts": ts,
                "type": "soma_belief",
                "subject": "src/main.rs",
                "predicate": "placeholder",
                "confidence": 0.6,
                "v": "3.0",
                "text": "[soma] src/main.rs: placeholder",
            }));
        }

        let err = soma_correct("abcd", "new predicate", Some("ambiguous"), None).unwrap_err();
        assert!(err.starts_with("Belief ID 'abcd' is ambiguous:"));
        assert!(err.contains("abcd1111"));
        assert!(err.contains("abcd2222"));
    }

    #[test]
    fn infer_soma_subject_path_uses_existing_file_prefix() {
        assert_eq!(
            infer_soma_subject_path("src/chat.rs:soma_assert"),
            Some("src/chat.rs".to_string())
        );
        assert_eq!(infer_soma_subject_path("not-a-real-file:thing"), None);
    }

    #[test]
    fn soma_churn_decay_scales_and_caps() {
        assert_eq!(soma_churn_decay(0), 0.0);
        assert!(soma_churn_decay(1) > 0.0);
        assert!(soma_churn_decay(8) > soma_churn_decay(2));
        assert!(soma_churn_decay(100) <= 1.0);
    }

    #[test]
    fn annotate_soma_message_adds_git_churn_metadata() {
        let _guard = store::test_env_lock().lock().unwrap();
        let repo = std::env::temp_dir().join(format!(
            "agora-soma-git-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&repo).unwrap();

        assert!(run_git(&repo, &["init"]).status.success());
        assert!(run_git(&repo, &["config", "user.email", "soma@test.local"]).status.success());
        assert!(run_git(&repo, &["config", "user.name", "Soma Test"]).status.success());
        assert!(run_git(&repo, &["config", "commit.gpgsign", "false"]).status.success());

        let tracked = repo.join("tracked.txt");
        std::fs::write(&tracked, "v1\n").unwrap();
        assert!(run_git(&repo, &["add", "tracked.txt"]).status.success());
        assert!(run_git(&repo, &["commit", "-m", "initial"]).status.success());

        let base_ref = String::from_utf8_lossy(&run_git(&repo, &["rev-parse", "HEAD"]).stdout)
            .trim()
            .to_string();

        std::fs::write(&tracked, "v2\n").unwrap();
        assert!(run_git(&repo, &["commit", "-am", "second"]).status.success());
        std::fs::write(&tracked, "v3\n").unwrap();
        assert!(run_git(&repo, &["commit", "-am", "third"]).status.success());

        let original_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&repo).unwrap();

        let mut msg = json!({
            "id": "belief01",
            "subject": "tracked.txt:line-1",
            "predicate": "stays stable",
            "confidence": 0.8,
            "git_ref": base_ref,
            "type": "soma_belief",
        });
        annotate_soma_message(&mut msg);

        std::env::set_current_dir(original_cwd).unwrap();

        assert_eq!(msg["volatility_path"].as_str(), Some("tracked.txt"));
        assert_eq!(msg["churn_commits"].as_u64(), Some(2));
        assert!(msg["churn_decay"].as_f64().unwrap() > 0.0);
        assert!(msg["effective_confidence"].as_f64().unwrap() < 0.8);
    }

    #[test]
    fn signed_payload_round_trip_marks_verified() {
        let _guard = store::test_env_lock().lock().unwrap();
        let home = temp_home();
        std::fs::create_dir_all(&home).unwrap();
        unsafe {
            std::env::set_var("HOME", &home);
            std::env::set_var("AGORA_AGENT_ID", "sign-test");
        }

        let room = store::add_room("ag-sign", "secret-sign", "sign", Role::Admin);
        let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
        let env = make_envelope("hello signed world", None);
        let wire = encrypt_envelope(&env, &room_key, &room.room_id);
        let decrypted = decrypt_payload(&wire, &room_key, &room.room_id).unwrap();

        assert_eq!(decrypted["text"].as_str(), Some("hello signed world"));
        assert_eq!(decrypted["_auth"].as_str(), Some("verified"));
        assert!(store::get_trusted_signing_key("sign-test").is_some());
    }

    #[test]
    fn legacy_payload_round_trip_marks_unsigned() {
        let _guard = store::test_env_lock().lock().unwrap();
        let room_key = crypto::derive_room_key("secret-legacy", "ag-legacy");
        let env = json!({
            "v": "3.0",
            "id": "legacy01",
            "from": "legacy-agent",
            "ts": 123,
            "text": "legacy message",
        });
        let plaintext = serde_json::to_string(&env).unwrap();
        let (enc_key, _) = crypto::derive_message_keys(&room_key);
        let blob = crypto::encrypt(plaintext.as_bytes(), &enc_key, b"ag-legacy").unwrap();
        let raw = BASE64.encode(&blob);

        let decrypted = decrypt_payload(&raw, &room_key, "ag-legacy").unwrap();
        assert_eq!(decrypted["text"].as_str(), Some("legacy message"));
        assert_eq!(decrypted["_auth"].as_str(), Some("unsigned"));
    }

    #[test]
    fn signed_payload_rejects_trusted_key_mismatch() {
        let _guard = store::test_env_lock().lock().unwrap();
        let home = temp_home();
        std::fs::create_dir_all(&home).unwrap();
        unsafe {
            std::env::set_var("HOME", &home);
            std::env::set_var("AGORA_AGENT_ID", "alice");
        }

        let room = store::add_room("ag-sign-mismatch", "secret-sign-mismatch", "sign-mismatch", Role::Admin);
        let room_key = crypto::derive_room_key(&room.secret, &room.room_id);

        let trusted_env = make_envelope("trusted", None);
        let trusted_wire = encrypt_envelope(&trusted_env, &room_key, &room.room_id);
        assert!(decrypt_payload(&trusted_wire, &room_key, &room.room_id).is_some());

        let forged_env = json!({
            "v": "3.0",
            "id": "forged01",
            "from": "alice",
            "ts": 456,
            "text": "forged",
        });
        let plaintext = serde_json::to_string(&forged_env).unwrap();
        let (enc_key, _) = crypto::derive_message_keys(&room_key);
        let blob = crypto::encrypt(plaintext.as_bytes(), &enc_key, room.room_id.as_bytes()).unwrap();
        let payload = BASE64.encode(&blob);

        let alt_pkcs8 = crypto::generate_signing_keypair_pkcs8().unwrap();
        let alt_pubkey = BASE64.encode(crypto::signing_public_key(&alt_pkcs8).unwrap());
        let signing_input = signing_message_bytes(&room.room_id, "alice", &alt_pubkey, &payload);
        let sig = BASE64.encode(crypto::sign_message(&alt_pkcs8, &signing_input).unwrap());
        let forged_wire = serde_json::to_string(&SignedWirePayload {
            v: SIGNED_WIRE_VERSION.to_string(),
            from: "alice".to_string(),
            payload,
            signing_pubkey: alt_pubkey,
            sig,
        }).unwrap();

        let warning = decrypt_payload(&forged_wire, &room_key, &room.room_id).unwrap();
        assert_eq!(warning["type"].as_str(), Some("auth_warning"));
        assert_eq!(warning["from"].as_str(), Some("[auth]"));
        assert_eq!(warning["sender"].as_str(), Some("alice"));
        assert_eq!(warning["auth_reason"].as_str(), Some("signing_key_mismatch"));
        assert!(warning["text"]
            .as_str()
            .unwrap_or("")
            .contains("signing key"));
    }

    #[test]
    fn invite_redemption_counter_matches_invite_id() {
        let first = make_invite_redemption("invite-a", Some("alice"), Some(1));
        let second = make_invite_redemption("invite-a", Some("alice"), Some(1));
        let third = make_invite_redemption("invite-b", Some("alice"), Some(1));
        let events = vec![first, second, third];

        assert_eq!(count_invite_redemptions_in_envs(&events, "invite-a"), 2);
        assert_eq!(count_invite_redemptions_in_envs(&events, "invite-b"), 1);
        assert_eq!(count_invite_redemptions_in_envs(&events, "invite-c"), 0);
    }

    /// Verify that bounty_verify grants the configured credits to the winning agent
    /// when the acceptance oracle exits with status 0 (PASS).
    #[test]
    fn bounty_verify_awards_credits_to_winner() {
        let _guard = store::test_env_lock().lock().unwrap();
        let agent_id = "bounty-winner";
        let (_home, room) = setup_plaza_room(agent_id, Role::Admin);

        // Create a temporary git branch so run_oracle_on_branch can check it out.
        // We use a nanosecond-suffixed name to avoid collisions between parallel runs.
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let branch = format!("test-bounty-verify-{ts}");
        let _ = std::process::Command::new("git")
            .args(["branch", &branch])
            .output();

        // Create a bounty task with a 50-credit reward. Oracle is "true" — always passes.
        let task_id = task_add_with_oracle(
            "Build feature X",
            Some("true"),
            Some(50),
            None,
            None,
        )
        .unwrap();

        // Register a submission from the winner agent using the branch above.
        let mut tasks = store::load_tasks(&room.room_id);
        let task = tasks.iter_mut().find(|t| t.id == task_id).unwrap();
        task.submissions.push(store::BountySubmission {
            agent_id: agent_id.to_string(),
            branch: branch.clone(),
            submitted_at: 0,
            oracle_passed: None,
        });
        store::save_tasks(&room.room_id, &tasks);

        // Pre-condition: no credits yet.
        assert_eq!(
            store::credit_balance(&room.room_id, agent_id),
            0,
            "winner should start with 0 credits"
        );

        // Run the oracle.
        let result = bounty_verify(&task_id, agent_id, None)
            .expect("bounty_verify should succeed");
        assert!(
            result.starts_with("PASS"),
            "oracle 'true' must PASS, got: {result}"
        );

        // Post-condition: winner received the bounty reward.
        assert_eq!(
            store::credit_balance(&room.room_id, agent_id),
            50,
            "bounty_verify must grant 50 credits to the winner on oracle PASS"
        );

        // Task should be closed and attributed to the winner.
        let tasks = store::load_tasks(&room.room_id);
        let task = tasks.iter().find(|t| t.id == task_id).unwrap();
        assert_eq!(task.status, "done", "task must be marked done after oracle PASS");
        assert_eq!(
            task.claimed_by.as_deref(),
            Some(agent_id),
            "winning agent must be set as claimed_by"
        );

        // Clean up the temporary branch.
        let _ = std::process::Command::new("git")
            .args(["branch", "-D", &branch])
            .output();
    }

    /// Verify that a bounty poster cannot submit to their own bounty (anti-self-dealing).
    #[test]
    fn bounty_submit_rejects_self_dealing() {
        let _guard = store::test_env_lock().lock().unwrap();
        let poster_id = "bounty-poster-self";
        let (_home, room) = setup_plaza_room(poster_id, Role::Admin);

        // Poster creates a task directly (simulating bounty_post).
        let task_id = task_add_with_oracle("Self-deal test task", None, Some(50), None, None).unwrap();

        // The poster tries to submit to their own bounty.
        let result = bounty_submit(&task_id, "some-branch", None);
        assert!(
            result.is_err(),
            "bounty_submit must reject self-dealing (poster submitting to own bounty)"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("self-dealing not permitted"),
            "error message must mention self-dealing, got: {err}"
        );

        // Confirm no submission was recorded.
        let tasks = store::load_tasks(&room.room_id);
        let task = tasks.iter().find(|t| t.id == task_id).unwrap();
        assert!(
            task.submissions.is_empty(),
            "no submission should be recorded for self-dealing attempt"
        );
    }
}

/// Search messages by text, optionally filtered by sender.
pub fn search(
    query: &str,
    from: Option<&str>,
    after: Option<u64>,
    before: Option<u64>,
    use_regex: bool,
    room_label: Option<&str>,
) -> Result<Vec<serde_json::Value>, String> {
    let room = resolve_room(room_label)?;
    // Search all local messages (up to 7 days)
    let msgs = store::load_messages(&room.room_id, 604800);

    let re = if use_regex {
        Some(regex::RegexBuilder::new(query)
            .case_insensitive(true)
            .build()
            .map_err(|e| format!("Invalid regex: {e}"))?)
    } else {
        None
    };
    let query_lower = query.to_lowercase();

    let mut results: Vec<serde_json::Value> = msgs
        .into_iter()
        .filter(|m| {
            let text = m["text"].as_str().unwrap_or("");
            let sender = m["from"].as_str().unwrap_or("");
            let ts = m["ts"].as_u64().unwrap_or(0);

            // Text match: regex or plain
            let matches_query = if let Some(ref re) = re {
                re.is_match(text)
            } else {
                text.to_lowercase().contains(&query_lower)
            };

            let matches_from = from.map_or(true, |f| sender == f);
            let matches_after = after.map_or(true, |a| ts >= a);
            let matches_before = before.map_or(true, |b| ts <= b);

            matches_query && matches_from && matches_after && matches_before
        })
        .collect();
    results.sort_by_key(|m| m["ts"].as_u64().unwrap_or(0));
    Ok(results)
}

#[derive(Clone)]
pub struct ThreadItem {
    pub depth: usize,
    pub env: serde_json::Value,
}

fn resolve_message_id(msgs: &[serde_json::Value], needle: &str) -> Result<String, String> {
    if msgs.iter().any(|m| m["id"].as_str() == Some(needle)) {
        return Ok(needle.to_string());
    }

    let matches: Vec<String> = msgs
        .iter()
        .filter_map(|m| {
            let id = m["id"].as_str()?;
            id.starts_with(needle).then(|| id.to_string())
        })
        .collect();

    match matches.len() {
        0 => Err(format!("Message '{needle}' not found in local cache.")),
        1 => Ok(matches[0].clone()),
        _ => Err(format!(
            "Message ID '{needle}' is ambiguous: {}",
            matches
                .into_iter()
                .take(5)
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

fn resolve_saved_id(ids: &[String], needle: &str) -> Result<String, String> {
    if ids.iter().any(|id| id == needle) {
        return Ok(needle.to_string());
    }

    let matches: Vec<String> = ids
        .iter()
        .filter(|id| id.starts_with(needle))
        .cloned()
        .collect();

    match matches.len() {
        0 => Err(format!("Message '{needle}' is not pinned.")),
        1 => Ok(matches[0].clone()),
        _ => Err(format!(
            "Message ID '{needle}' is ambiguous: {}",
            matches.into_iter().take(5).collect::<Vec<_>>().join(", ")
        )),
    }
}

fn walk_thread(
    env: &serde_json::Value,
    depth: usize,
    children: &HashMap<String, Vec<serde_json::Value>>,
    out: &mut Vec<ThreadItem>,
) {
    out.push(ThreadItem {
        depth,
        env: env.clone(),
    });

    if let Some(id) = env["id"].as_str() {
        if let Some(replies) = children.get(id) {
            for reply in replies {
                walk_thread(reply, depth + 1, children, out);
            }
        }
    }
}

/// Show a message plus all cached replies beneath it.
pub fn thread(message_id: &str, room_label: Option<&str>) -> Result<Vec<ThreadItem>, String> {
    let room = resolve_room(room_label)?;
    let mut msgs = store::load_messages(&room.room_id, 30 * 24 * 3600);
    if msgs.is_empty() {
        return Err("No cached messages for the active room.".to_string());
    }
    msgs.sort_by(|a, b| {
        a["ts"]
            .as_u64()
            .unwrap_or(0)
            .cmp(&b["ts"].as_u64().unwrap_or(0))
            .then_with(|| {
                a["id"]
                    .as_str()
                    .unwrap_or("?")
                    .cmp(b["id"].as_str().unwrap_or("?"))
            })
    });

    let root_id = resolve_message_id(&msgs, message_id)?;
    let mut root = None;
    let mut children: HashMap<String, Vec<serde_json::Value>> = HashMap::new();

    for msg in msgs {
        let id = msg["id"].as_str().unwrap_or("?").to_string();
        if id == root_id {
            root = Some(msg.clone());
        }
        if let Some(parent) = msg["reply_to"].as_str() {
            children.entry(parent.to_string()).or_default().push(msg);
        }
    }

    for replies in children.values_mut() {
        replies.sort_by_key(|m| m["ts"].as_u64().unwrap_or(0));
    }

    let root = root.ok_or_else(|| format!("Message '{message_id}' not found in local cache."))?;
    let mut out = Vec::new();
    walk_thread(&root, 0, &children, &mut out);
    Ok(out)
}

pub fn pin(message_id: &str, room_label: Option<&str>) -> Result<(String, bool), String> {
    let room = resolve_room(room_label)?;
    let msgs = store::load_messages(&room.room_id, u64::MAX);
    if msgs.is_empty() {
        return Err("No cached messages for the active room.".to_string());
    }

    let resolved_id = resolve_message_id(&msgs, message_id)?;
    let added = store::add_pin(&room.room_id, &resolved_id);
    Ok((resolved_id, added))
}

pub fn unpin(message_id: &str, room_label: Option<&str>) -> Result<(String, bool), String> {
    let room = resolve_room(room_label)?;
    let pins = store::load_pins(&room.room_id);
    if pins.is_empty() {
        return Err("No pinned messages for the active room.".to_string());
    }

    let resolved_id = resolve_saved_id(&pins, message_id)?;
    let removed = store::remove_pin(&room.room_id, &resolved_id);
    Ok((resolved_id, removed))
}

pub fn pins(room_label: Option<&str>) -> Result<Vec<serde_json::Value>, String> {
    let room = resolve_room(room_label)?;
    let pinned_ids = store::load_pins(&room.room_id);
    if pinned_ids.is_empty() {
        return Ok(Vec::new());
    }

    let msgs = store::load_messages(&room.room_id, u64::MAX);
    let by_id: HashMap<String, serde_json::Value> = msgs
        .into_iter()
        .filter_map(|msg| {
            let id = msg["id"].as_str()?.to_string();
            Some((id, msg))
        })
        .collect();

    let mut out = Vec::new();
    for id in pinned_ids {
        if let Some(msg) = by_id.get(&id) {
            out.push(msg.clone());
        }
    }
    Ok(out)
}

/// Start a background daemon that watches the room via SSE.
/// Writes a JSON flag file on new messages for hook consumption.
/// Returns the child PID.
pub fn daemon(room_label: Option<&str>) -> Result<u32, String> {
    let room = resolve_room(room_label)?;
    let pid_path = store::daemon_pid_path(&room.room_id);

    // Kill existing daemon if running
    if let Ok(pid_str) = std::fs::read_to_string(&pid_path) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            unsafe { libc::kill(pid, libc::SIGTERM); }
        }
        let _ = std::fs::remove_file(&pid_path);
    }

    let room_id = room.room_id.clone();
    let secret = room.secret.clone();
    let pidfile = pid_path;

    // Fork
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err("Fork failed".to_string());
    }
    if pid > 0 {
        // Parent — write PID and return
        let _ = std::fs::write(&pidfile, pid.to_string());
        return Ok(pid as u32);
    }

    // Child — daemon process
    unsafe { libc::setsid(); }

    let room_key = crypto::derive_room_key(&secret, &room_id);
    let me = store::get_agent_id();
    let mut rate_limit = seed_plaza_rate_limit_state(
        &room,
        &store::load_messages(&room.room_id, PLAZA_RATE_LIMIT_WINDOW_SECS),
    );

    transport::stream(&room_id, |ts, payload| {
        if let Some(mut env) = decrypt_payload(payload, &room_key, &room_id) {
            if env["ts"].as_u64().unwrap_or(0) == 0 {
                env["ts"] = json!(ts);
            }
            track_presence(&room_id, &env);
            let from = env["from"].as_str().unwrap_or("");
            // Skip own messages and heartbeats
            if from == me || is_heartbeat(&env) {
                return;
            }
            if !allow_incoming_message(&room, &env, ts, &mut rate_limit) {
                return;
            }
            ingest_auxiliary_event(&room_id, &env);
            if should_display_message(&env) {
                store::save_message(&room_id, &env);
                store::set_notify_flag(&room_id, &env);
            }
        }
    });

    std::process::exit(0);
}

/// Check the flag file for new messages (for hooks). Clears the flag.
/// Returns cached unseen messages, or empty if no new messages.
pub fn notify(since: &str, room_label: Option<&str>) -> Result<Vec<serde_json::Value>, String> {
    let room = resolve_room(room_label)?;
    if !store::take_notify_flag(&room.room_id) {
        return Ok(vec![]);
    }

    let me = store::get_agent_id();
    let seen = store::load_seen(&room.room_id);
    let since_secs = parse_since(since);
    let mut new_msgs = Vec::new();

    for env in store::load_messages(&room.room_id, since_secs) {
        let mid = env["id"].as_str().unwrap_or("?").to_string();
        let from = env["from"].as_str().unwrap_or("");
        if from == me || seen.contains(&mid) || is_heartbeat(&env) {
            continue;
        }
        store::mark_seen(&room.room_id, &mid);
        new_msgs.push(env);
    }
    Ok(new_msgs)
}

/// Stop the daemon process.
pub fn stop_daemon(room_label: Option<&str>) -> Result<(), String> {
    let room = resolve_room(room_label)?;
    let pid_path = store::daemon_pid_path(&room.room_id);
    if let Ok(pid_str) = std::fs::read_to_string(&pid_path) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            unsafe { libc::kill(pid, libc::SIGTERM); }
            let _ = std::fs::remove_file(pid_path);
            return Ok(());
        }
    }
    Err("No daemon running.".to_string())
}

pub fn verify(room_label: Option<&str>) -> Result<serde_json::Value, String> {
    let room = resolve_room(room_label)?;
    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let (nonce, commitment) = crypto::zkp_create_commitment(&room_key)
        .map_err(|e| e.to_string())?;
    let challenge = crypto::zkp_create_challenge().map_err(|e| e.to_string())?;
    let response = crypto::zkp_respond(&room_key, &nonce, &challenge);
    let valid = crypto::zkp_verify(&room_key, &nonce, &challenge, &response);
    Ok(json!({
        "room_id": room.room_id,
        "proof_valid": valid,
        "nonce": hex::encode(nonce),
        "commitment": hex::encode(commitment),
        "challenge": hex::encode(challenge),
        "response": hex::encode(response),
    }))
}

fn parse_since(since: &str) -> u64 {
    let s = since.trim().to_lowercase();
    if let Some(h) = s.strip_suffix('h') {
        h.parse::<u64>().unwrap_or(2) * 3600
    } else if let Some(m) = s.strip_suffix('m') {
        m.parse::<u64>().unwrap_or(5) * 60
    } else if let Some(secs) = s.strip_suffix('s') {
        secs.parse::<u64>().unwrap_or(300)
    } else {
        7200
    }
}

/// Transfer credits between agents.
pub fn credit_transfer(to_agent: &str, amount: i64, reason: Option<&str>, room_label: Option<&str>) -> Result<(i64, i64), String> {
    let room = resolve_room(room_label)?;
    let me = store::get_agent_id();
    if me == to_agent { return Err("Cannot transfer to yourself.".to_string()); }
    let balance = store::credit_balance(&room.room_id, &me);
    if balance < amount { return Err(format!("Insufficient credits: have {balance}, need {amount}")); }
    let reason_str = reason.unwrap_or("transfer");
    store::credit_add(&room.room_id, &me, -amount, &format!("sent to {to_agent}: {reason_str}"));
    store::credit_add(&room.room_id, to_agent, amount, &format!("received from {me}: {reason_str}"));
    let my_balance = store::credit_balance(&room.room_id, &me);
    let their_balance = store::credit_balance(&room.room_id, to_agent);

    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let env = make_envelope(&format!("[transfer] {me} → {to_agent}: {amount} credits ({reason_str})"), None);
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);
    transport::publish(&room.room_id, &encrypted);
    store::save_message(&room.room_id, &env);
    Ok((my_balance, their_balance))
}
