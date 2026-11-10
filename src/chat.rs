//! Agora chat engine.
//!
//! Wire format: base64(nonce || AES-256-GCM(envelope_json, aad=room_id))
//!
//! Envelope (plaintext JSON):
//! ```json
//! {
//!     "v": "3.0",
//!     "id": "<32-hex message ID>",
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

use ring::{digest, rand::SecureRandom};

use crate::{crypto, runtime, store, transport};

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

// ---------------------------------------------------------------------------
// Graceful shutdown: global flag set by SIGTERM/SIGINT signal handler.
// Checked in long-running loops (daemon, watch) to break and clean up.
// ---------------------------------------------------------------------------
static SHUTDOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

extern "C" fn shutdown_handler(_sig: libc::c_int) {
    // Exit immediately — PidFileGuard::drop cleans up the PID file.
    // This is async-signal-safe: exit() is safe, and Drop runs cleanup.
    std::process::exit(0);
}

/// Install SIGTERM/SIGINT handlers that set the global `SHUTDOWN` flag.
/// Call this once in any long-running process (daemon child, watch loop).
pub fn install_shutdown_handler() {
    unsafe {
        libc::signal(libc::SIGTERM, shutdown_handler as *const () as usize);
        libc::signal(libc::SIGINT, shutdown_handler as *const () as usize);
    }
}

/// RAII guard that removes a PID file on drop (including panics / unwinds).
struct PidFileGuard {
    path: std::path::PathBuf,
}

impl PidFileGuard {
    fn new(path: std::path::PathBuf) -> Self {
        Self { path }
    }
}

impl Drop for PidFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

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
pub struct ListedWorkReceipt {
    pub room_label: String,
    pub receipt: store::WorkReceipt,
}

fn now() -> u64 {
    runtime::unix_now()
}

fn msg_id() -> String {
    let mut bytes = [0u8; 16];
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

fn make_envelope_from(sender: &str, text: &str, reply_to: Option<&str>) -> serde_json::Value {
    let mut env = json!({
        "v": VERSION,
        "id": msg_id(),
        "from": sender,
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
    let input =
        format!("agora-auth-warning-v1\n{room_id}\n{sender}\n{signing_pubkey}\n{sig}\n{reason}");
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
    matches!(env["type"].as_str(), Some("card") | Some("capability_card"))
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
        crate::elog!(
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
        // Legacy role_state events are cached for display only, and only
        // when signature-verified; authority now lives in role:<name> leases.
        if env["_auth"].as_str() != Some("verified") {
            return;
        }
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
        let capabilities = env["capabilities"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .chain(
                env["card_capabilities"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|v| v.as_str().map(|s| s.to_string())),
            )
            .collect();
        let card = store::CapabilityCard {
            agent_id: from.to_string(),
            capabilities,
            available: env["available"].as_bool().unwrap_or(true),
            description: env["description"]
                .as_str()
                .or_else(|| env["card_summary"].as_str())
                .map(|s| s.to_string()),
            updated_at: env["ts"].as_u64().unwrap_or(0),
        };
        store::save_peer_card(room_id, &card);
        return;
    }

    if is_reaction(env)
        && let (Some(target), Some(emoji)) = (env["target_id"].as_str(), env["emoji"].as_str())
    {
        store::add_reaction(room_id, target, from, emoji);
    }
}

/// A message a person or agent would read: not bus state (heartbeats, leases,
/// receipts, reactions, cards, role state, plugin bookkeeping), not a profile
/// broadcast and not an auth warning synthesized by the reader.
pub fn is_conversational(env: &serde_json::Value) -> bool {
    should_display_message(env)
        && !is_auth_warning(env)
        && env["type"].as_str() != Some("profile")
        && !crate::plugin::is_quiet_event(env)
}

fn should_display_message(env: &serde_json::Value) -> bool {
    !is_heartbeat(env)
        && !crate::lease::is_lease_event(env)
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
    if let Ok(env) = serde_json::from_str::<serde_json::Value>(raw)
        && env["v"].is_string()
        && env["text"].is_string()
    {
        return Some(env);
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

fn signing_message_bytes(
    room_id: &str,
    from: &str,
    signing_pubkey: &str,
    payload: &str,
) -> Vec<u8> {
    format!("agora-signed-wire-v1\n{room_id}\n{from}\n{signing_pubkey}\n{payload}").into_bytes()
}

// ── Encrypt / Decrypt ───────────────────────────────────────────

/// Encrypt and sign a message envelope for transport over the relay.
pub fn encrypt_envelope(env: &serde_json::Value, room_key: &[u8; 32], room_id: &str) -> String {
    let (enc_key, _) = crypto::derive_message_keys(room_key);
    let plaintext = serde_json::to_string(env).unwrap();
    let aad = room_id.as_bytes();
    let blob = crypto::encrypt(plaintext.as_bytes(), &enc_key, aad).expect("encrypt failed");
    let payload = BASE64.encode(&blob);
    let from = env["from"].as_str().unwrap_or("");

    let pkcs8 = store::load_or_create_signing_keypair(from).expect("signing key load failed");
    let signing_pubkey = store::encode_signing_pubkey(
        &crypto::signing_public_key(&pkcs8).expect("signing pubkey derivation failed"),
    );
    store::trust_signing_key(from, &signing_pubkey);

    let signing_input = signing_message_bytes(room_id, from, &signing_pubkey, &payload);
    let sig = BASE64
        .encode(crypto::sign_message(&pkcs8, &signing_input).expect("message signing failed"));

    serde_json::to_string(&SignedWirePayload {
        v: SIGNED_WIRE_VERSION.to_string(),
        from: from.to_string(),
        payload,
        signing_pubkey,
        sig,
    })
    .unwrap()
}

/// Decrypt a signed transport payload and return the verified envelope.
pub fn decrypt_signed_payload(
    raw: &str,
    room_key: &[u8; 32],
    room_id: &str,
) -> Option<serde_json::Value> {
    let wire = serde_json::from_str::<SignedWirePayload>(raw).ok()?;
    let signing_input =
        signing_message_bytes(room_id, &wire.from, &wire.signing_pubkey, &wire.payload);
    let public_key = store::decode_signing_pubkey(&wire.signing_pubkey)?;
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
        if !store::signing_pubkeys_match(&trusted, &wire.signing_pubkey) {
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

/// Decrypt either a signed payload or the legacy unsigned payload format.
pub fn decrypt_payload(
    payload: &str,
    room_key: &[u8; 32],
    room_id: &str,
) -> Option<serde_json::Value> {
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
    create_with_options(label, false)
}

/// Create a room without publishing the "Room created..." presence envelope.
///
/// Mirrors [`crate::sdk::AgoraClient::create_room_silent`]. Used by embedders
/// (cfs-mesh `expose_uds`, transient bridges, tests) that don't want a stray
/// system message landing as the first envelope receivers see.
pub fn create_silent(label: &str) -> Result<(String, String), String> {
    create_with_options(label, true)
}

fn create_with_options(label: &str, silent: bool) -> Result<(String, String), String> {
    transport::require_relay()?;
    let room_id = crypto::generate_room_id();
    let secret = crypto::generate_secret();
    let room_key = crypto::derive_room_key(&secret, &room_id);

    // Publish first: a relay that rejects us (bad token, unreachable) must
    // not leave a half-created room behind.
    let created = if silent {
        None
    } else {
        let env = make_envelope("Room created (agora v3, AES-256-GCM).", None);
        let encrypted = encrypt_envelope(&env, &room_key, &room_id);
        transport::publish_checked(&room_id, &encrypted)?;
        Some(env)
    };

    store::add_room(&room_id, &secret, label, store::Role::Admin);
    store::set_active_room(label);
    if let Some(env) = created {
        store::save_message(&room_id, &env);
    }

    Ok((room_id, secret))
}

pub fn join(room_id: &str, secret: &str, label: &str) -> Result<store::RoomEntry, String> {
    transport::require_relay()?;
    let room_key = crypto::derive_room_key(secret, room_id);
    let env = make_envelope("Joined (agora v3).", None);
    let encrypted = encrypt_envelope(&env, &room_key, room_id);
    transport::publish_checked(room_id, &encrypted)?;

    let entry = store::add_room(room_id, secret, label, store::Role::Member);
    store::set_active_room(label);
    store::save_message(room_id, &env);

    Ok(entry)
}

pub fn leave(room_label: Option<&str>) -> Result<serde_json::Value, String> {
    let room = resolve_room(room_label)?;
    let pid_path = store::daemon_pid_path(&room.room_id);
    let mut daemon_stopped = false;

    if let Ok(pid_str) = std::fs::read_to_string(&pid_path) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            unsafe {
                libc::kill(pid, libc::SIGTERM);
            }
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

pub fn send(
    message: &str,
    reply_to: Option<&str>,
    room_label: Option<&str>,
) -> Result<String, String> {
    let room = resolve_room(room_label)?;
    let sender = store::get_agent_id();
    enforce_outbound_plaza_rate_limit(&room, &sender)?;
    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);

    let env = make_envelope(message, reply_to);
    let mid = env["id"].as_str().unwrap_or("?").to_string();
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);

    // Fail loudly: a message that never reached the relay was not sent.
    transport::publish_checked(&room.room_id, &encrypted)?;
    store::save_message(&room.room_id, &env);

    Ok(mid)
}

/// Publish a structured, signed + encrypted event envelope into a room.
///
/// `fields` must be a JSON object and should carry a `type`; it is merged
/// into a fresh envelope (the reserved keys `v`, `id`, `from`, `ts`, `text`
/// cannot be overridden). Fails if the relay rejects the publish.
pub fn publish_event(
    room_label: Option<&str>,
    fields: serde_json::Value,
    text: &str,
) -> Result<serde_json::Value, String> {
    let room = resolve_room(room_label)?;
    publish_event_in(&room, fields, text)
}

pub(crate) fn publish_event_in(
    room: &store::RoomEntry,
    fields: serde_json::Value,
    text: &str,
) -> Result<serde_json::Value, String> {
    publish_event_as(room, &store::get_agent_id(), fields, text)
}

/// [`publish_event_in`] signed as `sender` (an identity whose signing key
/// lives in this agora home, e.g. a verified HTTP API caller).
pub(crate) fn publish_event_as(
    room: &store::RoomEntry,
    sender: &str,
    fields: serde_json::Value,
    text: &str,
) -> Result<serde_json::Value, String> {
    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let mut env = make_envelope_from(sender, text, None);
    if let Some(obj) = fields.as_object() {
        for (k, v) in obj {
            if !matches!(k.as_str(), "v" | "id" | "from" | "ts" | "text" | "_auth") {
                env[k] = v.clone();
            }
        }
    }
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);
    transport::publish_checked(&room.room_id, &encrypted)?;
    store::save_message(&room.room_id, &env);
    Ok(env)
}

/// Fetch, decrypt and verify a room's events from the relay (oldest first,
/// de-duplicated by id). Events carry `_auth` = `verified`/`unsigned`; auth
/// failures surface as `auth_warning` envelopes. Errors if the relay is
/// unconfigured or unreachable, so callers can fail closed.
pub fn fetch_room_events(
    room: &store::RoomEntry,
    since: &str,
) -> Result<Vec<serde_json::Value>, String> {
    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let mut remote = transport::fetch_checked(&room.room_id, since)?;
    remote.sort_by_key(|(ts, _)| *ts);
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for (ts, payload) in &remote {
        let Some(mut env) = decrypt_payload(payload, &room_key, &room.room_id) else {
            continue;
        };
        if env["ts"].as_u64().unwrap_or(0) == 0 {
            env["ts"] = json!(ts);
        }
        // Relay receipt time: a clock the sender does not control.
        env["_relay_ts"] = json!(ts);
        let id = env["id"].as_str().unwrap_or("").to_string();
        if !id.is_empty() && id != "?" && !seen.insert(id) {
            continue;
        }
        out.push(env);
    }
    Ok(out)
}

/// Post one parsed alert as a structured `alert` event.
pub fn post_alert(room_label: Option<&str>, alert: &crate::alert::Alert) -> Result<String, String> {
    let env = publish_event(room_label, alert.fields(), &alert.text())?;
    Ok(env["id"].as_str().unwrap_or("?").to_string())
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

pub fn read(
    since: &str,
    limit: usize,
    room_label: Option<&str>,
) -> Result<Vec<serde_json::Value>, String> {
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

    // Fetch from relay (fail closed: an unreachable relay is an error, not "no messages")
    let mut remote_events = transport::fetch_checked(&room.room_id, since)?;
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

    let mut remote_events = transport::fetch_checked(&room.room_id, since)?;
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
                    let msg_ids: Vec<String> = ids
                        .iter()
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

            // Lease traffic (acquire/renew/release) is state, not chat: keep
            // it out of wake-ups. Query it with `agora lease list`.
            if crate::lease::is_lease_event(&env) || crate::plugin::is_quiet_event(&env) {
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
                if let (Some(target), Some(emoji)) =
                    (env["target_id"].as_str(), env["emoji"].as_str())
                {
                    store::add_reaction(&room.room_id, target, from, emoji);
                }
                continue;
            }

            // A proposal touching a resource we hold a lease on: HOLD it.
            let mut env = env;
            if let Some(reason) = crate::proposal::auto_object(&room, &env) {
                env["_auto_hold"] = json!(reason);
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
            "text": msg["text"].as_str().unwrap_or("").chars().take(50).collect::<String>(),
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

/// Set your agent profile and broadcast it to the room.
pub fn set_profile(
    name: Option<&str>,
    role: Option<&str>,
    room_label: Option<&str>,
) -> Result<(), String> {
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
pub fn whois(
    agent_id: &str,
    room_label: Option<&str>,
) -> Result<Option<store::AgentProfile>, String> {
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

/// Roles are leases on the `role:<name>` resource (signed, TTL-bound, folded
/// with the lease rules) — no more last-writer-wins `role_state` events.
fn role_resource(role: &str) -> String {
    format!("role:{role}")
}

const ROLE_SETTLE_SECS: u64 = crate::lease::SKEW_WINDOW_SECS + 1;

fn role_view(room_id: &str, l: &crate::lease::Lease) -> store::RoleLease {
    store::RoleLease {
        role: l.resource.trim_start_matches("role:").to_string(),
        agent_id: l.holder.clone(),
        lease_expires: l.expires,
        last_heartbeat: l
            .acquired_at
            .max(l.expires.saturating_sub(crate::lease::MAX_TTL_SECS)),
        context_summary: l.reason.clone(),
        last_task_ids: claimed_task_ids(room_id, &l.holder),
        updated_at: now(),
    }
}

fn role_held_error(role: &str, l: &crate::lease::Lease) -> String {
    format!(
        "Role '{}' is currently held by '{}' for another {}s.",
        role,
        l.holder,
        l.remaining(now())
    )
}

pub fn role_claim(
    role: &str,
    summary: Option<&str>,
    ttl_secs: u64,
    room_label: Option<&str>,
) -> Result<store::RoleLease, String> {
    let room = resolve_room(room_label)?;
    let me = store::get_agent_id();
    match crate::lease::acquire_as(
        &me,
        &role_resource(role),
        ttl_secs,
        summary,
        ROLE_SETTLE_SECS,
        Some(&room.room_id),
    )? {
        crate::lease::Acquire::Acquired(l) => {
            let view = role_view(&room.room_id, &l);
            store::upsert_role_lease(&room.room_id, &view);
            Ok(view)
        }
        crate::lease::Acquire::Held(l) => Err(role_held_error(role, &l)),
    }
}

pub fn role_heartbeat(
    role: &str,
    summary: Option<&str>,
    ttl_secs: u64,
    room_label: Option<&str>,
) -> Result<store::RoleLease, String> {
    let room = resolve_room(room_label)?;
    let me = store::get_agent_id();
    match crate::lease::renew_as(
        &me,
        &role_resource(role),
        ttl_secs,
        summary,
        Some(&room.room_id),
    ) {
        Ok(l) => {
            let view = role_view(&room.room_id, &l);
            store::upsert_role_lease(&room.room_id, &view);
            Ok(view)
        }
        Err(crate::lease::LeaseError::Held(l)) => Err(role_held_error(role, &l)),
        Err(e) => Err(e.to_string()),
    }
}

pub fn role_release(role: &str, room_label: Option<&str>) -> Result<(), String> {
    let room = resolve_room(room_label)?;
    let me = store::get_agent_id();
    match crate::lease::release_as(&me, &role_resource(role), Some(&room.room_id)) {
        Ok(true) => {
            store::remove_role_lease(&room.room_id, role);
            Ok(())
        }
        Ok(false) => {
            store::remove_role_lease(&room.room_id, role);
            Err(format!("Role '{}' is not currently claimed.", role))
        }
        Err(crate::lease::LeaseError::Held(l)) => Err(format!(
            "Role '{}' is currently held by '{}'.",
            role, l.holder
        )),
        Err(e) => Err(e.to_string()),
    }
}

/// Active role leases, folded from the signed lease log on the relay.
pub fn list_role_leases(room_label: Option<&str>) -> Result<Vec<store::RoleLease>, String> {
    let room = resolve_room(room_label)?;
    let table = crate::lease::table(&room)?;
    let roles: Vec<store::RoleLease> = table
        .values()
        .filter(|l| l.resource.starts_with("role:"))
        .map(|l| role_view(&room.room_id, l))
        .collect();
    store::save_role_leases(&room.room_id, &roles);
    Ok(roles)
}

// ── Room Directory ─────────────────────────────────────────────

// ── Trust Score ─────────────────────────────────────────────────

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
        if agent_receipts.is_empty() {
            continue;
        }
        rooms_active += 1;
        total_receipt_count += agent_receipts.len();
        total_weighted_receipts += agent_receipts
            .iter()
            .map(|r| {
                discovery_decay_weight(
                    now_ts.saturating_sub(r.created_at),
                    DISCOVERY_POSITIVE_HALF_LIFE_SECS,
                )
            })
            .sum::<f64>();

        // Stale claims penalty
        {
            let tasks = task_list_unleased(room);
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
    let positive_score =
        (1.0 + total_weighted_receipts) * room_presence * (1.0 + vouches as f64 * 0.3);
    let score = positive_score * abandonment_penalty;

    (score, total_receipt_count, rooms_active, vouches)
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
    result.sort_by(|a, b| {
        b.urgency
            .cmp(&a.urgency)
            .then(b.blocked_tasks.cmp(&a.blocked_tasks))
    });
    result
}

pub struct RoomInfo {
    pub label: String,
    pub topic: Option<String>,
    pub agent_count: usize,
    pub message_count: usize,
    pub last_activity: u64,
}

#[derive(Debug, Clone)]
pub struct RoomSummary {
    pub room: store::RoomEntry,
    /// The current agent's peer, when this is its DM (see `store::room_dm_peer`).
    pub dm_peer: Option<String>,
    pub unread_count: usize,
    pub last_message_at: u64,
}

fn visible_room_messages(room: &store::RoomEntry) -> Vec<serde_json::Value> {
    store::load_messages(&room.room_id, u64::MAX)
        .into_iter()
        .filter(should_display_message)
        .collect()
}

fn message_position(message: &serde_json::Value) -> Option<(u64, String)> {
    Some((
        message["ts"].as_u64()?,
        message["id"].as_str().unwrap_or("").to_string(),
    ))
}

fn room_unread_count(
    me: &str,
    cursor: Option<&store::ReadCursor>,
    messages: &[serde_json::Value],
) -> usize {
    messages
        .iter()
        .filter(|msg| msg["from"].as_str().unwrap_or("") != me)
        .filter(|msg| {
            let ts = msg["ts"].as_u64().unwrap_or(0);
            let id = msg["id"].as_str().unwrap_or("");
            cursor.is_none_or(|cursor| (ts, id) > (cursor.ts, cursor.id.as_str()))
        })
        .count()
}

pub fn room_summaries() -> Vec<RoomSummary> {
    let me = store::get_agent_id();
    store::load_registry()
        .into_iter()
        .map(|room| {
            let messages = visible_room_messages(&room);
            let cursor = store::load_read_cursor(&room.room_id);
            let last_message_at = messages
                .iter()
                .map(|msg| msg["ts"].as_u64().unwrap_or(0))
                .max()
                .unwrap_or(0);
            let unread_count = room_unread_count(&me, cursor.as_ref(), &messages);
            RoomSummary {
                dm_peer: store::room_dm_peer(&room, &me),
                room,
                unread_count,
                last_message_at,
            }
        })
        .collect()
}

/// The current agent's DM rooms. The registry is shared by every agent of the host, so a DM between
/// two other agents is listed for neither of them but those two.
pub fn dm_room_summaries() -> Vec<RoomSummary> {
    let mut rooms: Vec<_> = room_summaries()
        .into_iter()
        .filter(|summary| summary.room.purpose.as_deref() == Some("dm") && summary.dm_peer.is_some())
        .collect();
    rooms.sort_by(|a, b| {
        b.last_message_at
            .cmp(&a.last_message_at)
            .then(a.room.label.cmp(&b.room.label))
    });
    rooms
}

pub fn mark_displayed_messages_read(room_id: &str, displayed: &[serde_json::Value]) {
    let Some(first_displayed) = displayed.first().and_then(message_position) else {
        return;
    };
    let me = store::get_agent_id();
    let cursor = store::load_read_cursor(room_id);
    let has_skipped_unread = store::load_messages(room_id, u64::MAX)
        .into_iter()
        .filter(should_display_message)
        .filter(|msg| msg["from"].as_str().unwrap_or("") != me)
        .filter_map(|msg| message_position(&msg))
        .filter(|(ts, id)| {
            cursor
                .as_ref()
                .is_none_or(|cursor| (*ts, id.as_str()) > (cursor.ts, cursor.id.as_str()))
        })
        .any(|position| position < first_displayed);
    if !has_skipped_unread {
        store::mark_room_read(room_id, displayed);
    }
}

pub fn directory() -> Result<Vec<RoomInfo>, String> {
    let rooms = store::load_registry();
    let now_ts = now();
    let mut infos = Vec::new();
    for room in &rooms {
        let msgs = store::load_messages(&room.room_id, 86400);
        let online = room
            .members
            .iter()
            .filter(|m| m.last_seen > 0 && now_ts - m.last_seen < 300)
            .count();
        let last_ts = msgs
            .iter()
            .map(|m| m["ts"].as_u64().unwrap_or(0))
            .max()
            .unwrap_or(0);
        infos.push(RoomInfo {
            label: room.label.clone(),
            topic: room.topic.clone(),
            agent_count: online,
            message_count: msgs.len(),
            last_activity: last_ts,
        });
    }
    infos.sort_by_key(|entry| std::cmp::Reverse(entry.last_activity));
    Ok(infos)
}

// ── Capability Cards ───────────────────────────────────────────

pub fn card_set(
    capabilities: &[String],
    description: Option<&str>,
    room_label: Option<&str>,
) -> Result<(), String> {
    let room = resolve_room(room_label)?;
    let me = store::get_agent_id();
    let card = store::CapabilityCard {
        agent_id: me.clone(),
        capabilities: capabilities.to_vec(),
        available: true,
        description: description.map(|s| s.to_string()),
        updated_at: now(),
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

pub fn card_show(
    agent_id: Option<&str>,
    room_label: Option<&str>,
) -> Result<Option<store::CapabilityCard>, String> {
    if agent_id.is_none() {
        return Ok(store::load_card());
    }
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
        let tasks = task_list_unleased(room);
        for card in store::load_peer_cards(&room.room_id) {
            let matches = needs.iter().all(|n| {
                card.capabilities
                    .iter()
                    .any(|c| c.to_lowercase().contains(n))
            });
            if !matches {
                continue;
            }

            let agent_receipts: Vec<_> = receipts
                .iter()
                .filter(|r| r.agent_id == card.agent_id)
                .collect();
            let receipt_count = agent_receipts.len();
            let weighted_receipts = agent_receipts
                .iter()
                .map(|receipt| {
                    discovery_decay_weight(
                        now_ts.saturating_sub(receipt.created_at),
                        DISCOVERY_POSITIVE_HALF_LIFE_SECS,
                    )
                })
                .sum::<f64>();
            let freshest_receipt = agent_receipts
                .iter()
                .map(|receipt| receipt.created_at)
                .max();
            let stale_claims: Vec<_> = tasks
                .iter()
                .filter(|task| {
                    task.status != "done"
                        && task.claimed_by.as_deref() == Some(card.agent_id.as_str())
                })
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
                .map(|ts| {
                    discovery_decay_weight(
                        now_ts.saturating_sub(ts),
                        DISCOVERY_POSITIVE_HALF_LIFE_SECS,
                    )
                })
                .unwrap_or(0.0);
            let volatility = (card_freshness - execution_freshness).max(0.0);

            let entry =
                agent_map
                    .entry(card.agent_id.clone())
                    .or_insert_with(|| DiscoveryAccumulator {
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
            let positive_score =
                (1.0 + entry.weighted_receipts) * room_presence * (1.0 + vouches * 0.3);
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
    results.sort_by(|a, b| {
        b.trust_score
            .partial_cmp(&a.trust_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
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

// ── Vouch / Trust Mesh ─────────────────────────────────────────

/// Vouch for another agent — adds to their trust score.
pub fn vouch(agent_id: &str, reason: Option<&str>, room_label: Option<&str>) -> Result<(), String> {
    let room = resolve_room(room_label)?;
    let me = store::get_agent_id();
    if me == agent_id {
        return Err("Cannot vouch for yourself.".to_string());
    }

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
            if msg["type"].as_str() == Some("vouch")
                && msg["vouched_for"].as_str() == Some(agent_id)
            {
                count += 1;
            }
        }
    }
    count
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
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let head = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if head.is_empty() { None } else { Some(head) }
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

pub fn soma_assert(
    subject: &str,
    predicate: &str,
    confidence: Option<f64>,
    git_ref: Option<&str>,
    room_label: Option<&str>,
) -> Result<String, String> {
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

pub fn soma_query(
    subject: &str,
    room_label: Option<&str>,
) -> Result<Vec<serde_json::Value>, String> {
    let room = resolve_room(room_label)?;
    let msgs = store::load_messages(&room.room_id, 604800);
    let q = subject.to_lowercase();
    let mut beliefs: Vec<serde_json::Value> = msgs
        .into_iter()
        .filter(|m| {
            (m["type"].as_str() == Some("soma_belief")
                || m["type"].as_str() == Some("soma_correction"))
                && m["subject"]
                    .as_str()
                    .unwrap_or("")
                    .to_lowercase()
                    .contains(&q)
        })
        .collect();
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

pub fn soma_correct(
    belief_id: &str,
    new_predicate: &str,
    reason: Option<&str>,
    room_label: Option<&str>,
) -> Result<String, String> {
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
    let verb = match status {
        "checkpoint" => "checkpointed",
        "rejected" => "rejected",
        _ => "completed",
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
    let me = store::get_agent_id();
    task_add_as(&me, title, room_label)
}

/// Add a task to the room queue on behalf of a verified agent.
pub fn task_add_as(
    agent_id: &str,
    title: &str,
    room_label: Option<&str>,
) -> Result<String, String> {
    let room = resolve_room(room_label)?;
    let id = msg_id();
    let task = store::Task {
        id: id.clone(),
        title: title.to_string(),
        status: "open".to_string(),
        created_by: agent_id.to_string(),
        claimed_by: None,
        created_at: now(),
        updated_at: now(),
        notes: None,
        resume: None,
    };
    let mut tasks = store::load_tasks(&room.room_id);
    tasks.push(task);
    store::save_tasks(&room.room_id, &tasks);

    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let env = make_envelope_from(
        agent_id,
        &format!("[task] New: {title} (id: {})", &id[..6]),
        None,
    );
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);
    transport::publish(&room.room_id, &encrypted);
    store::save_message(&room.room_id, &env);
    Ok(id)
}

/// Fetch a single task by ID prefix.
pub fn task_get(task_id: &str, room_label: Option<&str>) -> Result<store::Task, String> {
    let tasks = task_list(room_label)?;
    tasks
        .into_iter()
        .find(|t| t.id.starts_with(task_id) || t.id == task_id)
        .ok_or_else(|| format!("No task matching '{task_id}'"))
}

/// Claim an open task.
pub fn task_claim(task_id: &str, room_label: Option<&str>) -> Result<String, String> {
    let me = store::get_agent_id();
    task_claim_as(&me, task_id, room_label)
}

/// Default lease held on a claimed task (renewed by task-checkpoint).
pub const TASK_CLAIM_TTL_SECS: u64 = 2 * 3600;

/// Lease resource backing a task claim. Remote agents only learn the 6-char
/// id prefix from the "[task] New" announcement, so the prefix is the key.
pub fn task_resource(task_id: &str) -> String {
    format!("task:{}", task_id.chars().take(6).collect::<String>())
}

/// Claim an open task on behalf of a verified agent.
pub fn task_claim_as(
    agent_id: &str,
    task_id: &str,
    room_label: Option<&str>,
) -> Result<String, String> {
    task_claim_as_ttl(agent_id, task_id, TASK_CLAIM_TTL_SECS, room_label)
}

/// Claim a task by acquiring the signed `task:<id>` lease for `ttl_secs`.
/// Concurrent claims are settled by the lease rules; an expired claim makes
/// the task claimable again.
pub fn task_claim_as_ttl(
    agent_id: &str,
    task_id: &str,
    ttl_secs: u64,
    room_label: Option<&str>,
) -> Result<String, String> {
    let room = resolve_room(room_label)?;
    let task = task_list(Some(&room.room_id))?
        .into_iter()
        .find(|t| t.id.starts_with(task_id))
        .ok_or_else(|| format!("No task matching '{task_id}'"))?;
    let offered = store::load_delivered(&room.room_id, agent_id).iter().any(|entry| {
        entry.strip_prefix("task-pull:")
            .and_then(|entry| entry.split_once('|'))
            .is_some_and(|(id, _)| id == task.id)
    });
    let _span = offered.then(|| tracing::info_span!(target: "agora", "task.claim.via-offer").entered());
    if task.status == "done" {
        return Err(format!("Task '{}' is already done.", task.id));
    }
    match crate::lease::acquire_as(
        agent_id,
        &task_resource(&task.id),
        ttl_secs,
        Some(&task.title),
        crate::lease::SKEW_WINDOW_SECS + 1,
        Some(&room.room_id),
    )? {
        crate::lease::Acquire::Acquired(_) => {}
        crate::lease::Acquire::Held(l) => {
            return Err(format!(
                "Task '{}' is currently claimed by '{}' for another {}s.",
                task.id,
                l.holder,
                l.remaining(now())
            ));
        }
    }

    store::update_tasks(&room.room_id, |tasks| {
        let i = match tasks.iter().position(|t| t.id == task.id) {
            Some(i) => i,
            None => {
                tasks.push(task.clone());
                tasks.len() - 1
            }
        };
        let t = &mut tasks[i];
        t.status = "claimed".to_string();
        t.claimed_by = Some(agent_id.to_string());
        t.updated_at = now();
        // Another agent's recorded session must never be resumed for this claim.
        if t.resume.as_ref().is_some_and(|s| s.agent_id != agent_id) {
            t.resume = None;
        }
    });

    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let env = make_envelope_from(
        agent_id,
        &format!("[task] Claimed by {agent_id}: {}", task.title),
        None,
    );
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);
    transport::publish(&room.room_id, &encrypted);
    store::save_message(&room.room_id, &env);
    Ok(task.id)
}

/// Mark a task as done.
pub fn task_done(
    task_id: &str,
    notes: Option<&str>,
    room_label: Option<&str>,
) -> Result<String, String> {
    let me = store::get_agent_id();
    task_done_as(&me, task_id, notes, room_label)
}

/// Mark a task as done on behalf of a verified agent.
pub fn task_done_as(
    agent_id: &str,
    task_id: &str,
    notes: Option<&str>,
    room_label: Option<&str>,
) -> Result<String, String> {
    let room = resolve_room(room_label)?;
    let mut tasks = store::load_tasks(&room.room_id);
    let task = tasks
        .iter_mut()
        .find(|t| t.id.starts_with(task_id))
        .ok_or_else(|| format!("No task matching '{task_id}'"))?;
    task.status = "done".to_string();
    task.updated_at = now();
    if let Some(n) = notes {
        task.notes = Some(n.to_string());
    }
    let task_snapshot = task.clone();
    let title = task_snapshot.title.clone();
    let tid = task_snapshot.id.clone();
    store::save_tasks(&room.room_id, &tasks);

    let note_str = notes.map(|n| format!(" — {n}")).unwrap_or_default();
    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let env = make_envelope_from(
        agent_id,
        &format!("[task] Done by {agent_id}: {title}{note_str}"),
        None,
    );
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);
    transport::publish(&room.room_id, &encrypted);
    store::save_message(&room.room_id, &env);

    publish_task_receipt(
        &room,
        &task_snapshot,
        agent_id,
        "done",
        task_snapshot.notes.as_deref(),
        task_snapshot.updated_at,
    );
    // Free the claim lease (no-op if someone else holds it or it expired).
    let _ = crate::lease::release_as(agent_id, &task_resource(&tid), Some(&room.room_id));
    Ok(tid)
}

/// Record partial progress on a task without marking it done. Run from inside an agent harness, it also
/// records the harness session, so the task's agent can be resumed (`task_resume_line`).
pub fn task_checkpoint(
    task_id: &str,
    notes: Option<&str>,
    room_label: Option<&str>,
) -> Result<String, String> {
    let me = store::get_agent_id();
    let session = crate::resume::detect(&me, now());
    task_checkpoint_recording(&me, task_id, notes, room_label, session)
}

/// Record partial progress on a task on behalf of a verified agent.
pub fn task_checkpoint_as(
    agent_id: &str,
    task_id: &str,
    notes: Option<&str>,
    room_label: Option<&str>,
) -> Result<String, String> {
    task_checkpoint_recording(agent_id, task_id, notes, room_label, None)
}

/// Record partial progress, and the agent's harness session when known (an unknown one keeps the last).
pub fn task_checkpoint_recording(
    agent_id: &str,
    task_id: &str,
    notes: Option<&str>,
    room_label: Option<&str>,
    session: Option<crate::resume::Session>,
) -> Result<String, String> {
    let room = resolve_room(room_label)?;
    let task = store::load_tasks(&room.room_id)
        .into_iter()
        .find(|t| t.id.starts_with(task_id) && t.status != "done")
        .ok_or_else(|| format!("No active task matching '{task_id}'"))?;
    if let Some(claimed_by) = task.claimed_by.as_deref()
        && claimed_by != agent_id
    {
        return Err(format!(
            "Task '{}' is currently claimed by '{}'.",
            task.id, claimed_by
        ));
    }
    // A checkpoint extends (or establishes) the claim lease.
    match crate::lease::renew_as(
        agent_id,
        &task_resource(&task.id),
        TASK_CLAIM_TTL_SECS,
        None,
        Some(&room.room_id),
    ) {
        Ok(_) => {}
        Err(crate::lease::LeaseError::Held(l)) => {
            return Err(format!(
                "Task '{}' is currently claimed by '{}'.",
                task.id, l.holder
            ));
        }
        Err(e) => return Err(e.to_string()),
    }

    let task_snapshot = store::update_tasks(&room.room_id, |tasks| {
        let t = tasks.iter_mut().find(|t| t.id == task.id)?;
        if t.claimed_by.is_none() {
            t.status = "claimed".to_string();
            t.claimed_by = Some(agent_id.to_string());
        }
        t.updated_at = now();
        if session.is_some() {
            t.resume = session;
        }
        if let Some(note) = notes {
            t.notes = Some(note.to_string());
        }
        Some(t.clone())
    })
    .ok_or_else(|| format!("No active task matching '{task_id}'"))?;
    let checkpoint_notes = notes
        .map(|note| note.to_string())
        .or_else(|| task_snapshot.notes.clone());
    let title = task_snapshot.title.clone();
    let tid = task_snapshot.id.clone();

    let note_str = checkpoint_notes
        .as_deref()
        .map(|note| format!(" — {note}"))
        .unwrap_or_default();
    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let env = make_envelope_from(
        agent_id,
        &format!("[task] Checkpoint by {agent_id}: {title}{note_str}"),
        None,
    );
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);
    transport::publish(&room.room_id, &encrypted);
    store::save_message(&room.room_id, &env);

    publish_task_receipt(
        &room,
        &task_snapshot,
        agent_id,
        "checkpoint",
        checkpoint_notes.as_deref(),
        task_snapshot.updated_at,
    );
    Ok(tid)
}

/// The command that resumes a task's agent where it left off: the session its last checkpoint recorded,
/// with the task and that checkpoint as the first message. Returns the session and the command's argv.
pub fn task_resume_line(
    task_id: &str,
    room_label: Option<&str>,
) -> Result<(crate::resume::Session, Vec<String>), String> {
    let room = resolve_room(room_label)?;
    let task = store::load_tasks(&room.room_id)
        .into_iter()
        .find(|t| t.id.starts_with(task_id))
        .ok_or_else(|| format!("No task matching '{task_id}'"))?;
    if task.status == "done" {
        return Err(format!("Task '{}' is already done.", task.id));
    }
    let session = task.resume.clone().ok_or_else(|| {
        format!(
            "Task '{}' has no recorded session: it was never checkpointed from inside claude, omp or codex.",
            task.id
        )
    })?;
    // Only the agent that still holds the claim is resumed: a lapsed claim belongs to nobody, and a
    // later claimant's work must not get a second agent.
    match crate::lease::check(&task_resource(&task.id), Some(&room.room_id))? {
        Some(l) if l.holder == session.agent_id => {}
        Some(l) => {
            return Err(format!(
                "Task '{}' is held by '{}', not by '{}' whose session was recorded: not resuming it.",
                task.id, l.holder, session.agent_id
            ));
        }
        None => {
            return Err(format!(
                "Task '{}' has no live claim: claim it again rather than resuming '{}'.",
                task.id, session.agent_id
            ));
        }
    }
    let prompt = crate::resume::context(
        &task.id,
        &task.title,
        &room.label,
        task.notes.as_deref(),
        now().saturating_sub(task.updated_at),
    );
    let argv = crate::resume::command(&session, &prompt);
    Ok((session, argv))
}

/// Run a task's resume line in its agent's tmux pane (`task-resume --exec`). Two guards span the check,
/// the launch and the record of where the agent now runs: a host-local lock on the task (a lease does not
/// exclude a second run by the same agent id) and a `resume:<task id>` lease (people acting on one
/// proposal from different hosts). Eligibility is checked again once both are held.
pub fn task_resume_exec(task_id: &str, room_label: Option<&str>) -> Result<String, String> {
    let room = resolve_room(room_label)?;
    // Fail fast, and resolve the prefix: the guards are keyed on the full task id.
    let full = store::load_tasks(&room.room_id)
        .into_iter()
        .find(|t| t.id.starts_with(task_id))
        .map(|t| t.id)
        .ok_or_else(|| format!("No task matching '{task_id}'"))?;
    let (before, _) = task_resume_line(&full, Some(&room.room_id))?;
    let lock = store::agora_dir().join("rooms").join(&room.room_id).join(format!("resume-{full}"));
    store::with_file_lock(&lock, || {
        let me = store::get_agent_id();
        let resource = format!("resume:{full}");
        match crate::lease::acquire_as(
            &me,
            &resource,
            120,
            Some("task-resume --exec"),
            crate::lease::SKEW_WINDOW_SECS + 1,
            Some(&room.room_id),
        )? {
            crate::lease::Acquire::Acquired(_) => {}
            crate::lease::Acquire::Held(l) => {
                return Err(format!("{} is already resuming this task.", l.holder));
            }
        }
        let result = (|| {
            // The claim may have lapsed or moved while the lease settled.
            let (mut session, argv) = task_resume_line(&full, Some(&room.room_id))?;
            if session != before {
                return Err(format!("Task '{full}' changed hands or sessions while waiting for the resume lease: not resuming it."));
            }
            let how = crate::resume::exec(&mut session, &crate::resume::shell_line(&argv))?;
            if session != before {
                // A new window was opened: the next resume must find the agent there, not a missing pane.
                store::update_tasks(&room.room_id, |tasks| {
                    if let Some(t) = tasks.iter_mut().find(|t| t.id == full) {
                        t.resume = Some(session.clone());
                    }
                });
            }
            Ok(format!("{} session {} {how}", session.harness, session.session_id))
        })();
        let _ = crate::lease::release_as(&me, &resource, Some(&room.room_id));
        result
    })
}

/// Reject a task and, if currently claimed by the rejecting agent, return it to the open pool.
pub fn task_reject(
    task_id: &str,
    notes: Option<&str>,
    room_label: Option<&str>,
) -> Result<String, String> {
    let me = store::get_agent_id();
    task_reject_as(&me, task_id, notes, room_label)
}

/// Reject a task on behalf of a verified agent.
pub fn task_reject_as(
    agent_id: &str,
    task_id: &str,
    notes: Option<&str>,
    room_label: Option<&str>,
) -> Result<String, String> {
    let room = resolve_room(room_label)?;
    let mut tasks = store::load_tasks(&room.room_id);
    let task = tasks
        .iter_mut()
        .find(|t| t.id.starts_with(task_id) && t.status != "done")
        .ok_or_else(|| format!("No active task matching '{task_id}'"))?;

    if let Some(claimed_by) = task.claimed_by.as_deref() {
        if claimed_by != agent_id {
            return Err(format!(
                "Task '{}' is currently claimed by '{}'.",
                task.id, claimed_by
            ));
        }
        task.status = "open".to_string();
        task.claimed_by = None;
    }

    task.updated_at = now();
    if let Some(note) = notes {
        task.notes = Some(note.to_string());
    }
    let rejection_notes = notes
        .map(|note| note.to_string())
        .or_else(|| task.notes.clone());
    let task_snapshot = task.clone();
    let title = task_snapshot.title.clone();
    let tid = task_snapshot.id.clone();
    store::save_tasks(&room.room_id, &tasks);

    let note_str = rejection_notes
        .as_deref()
        .map(|note| format!(" — {note}"))
        .unwrap_or_default();
    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let env = make_envelope_from(
        agent_id,
        &format!("[task] Rejected by {agent_id}: {title}{note_str}"),
        None,
    );
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);
    transport::publish(&room.room_id, &encrypted);
    store::save_message(&room.room_id, &env);

    publish_task_receipt(
        &room,
        &task_snapshot,
        agent_id,
        "rejected",
        rejection_notes.as_deref(),
        task_snapshot.updated_at,
    );
    let _ = crate::lease::release_as(agent_id, &task_resource(&tid), Some(&room.room_id));
    Ok(tid)
}

/// List tasks — merges local state with room messages for cloud agents.
pub fn task_list(room_label: Option<&str>) -> Result<Vec<store::Task>, String> {
    let room = resolve_room(room_label)?;
    let mut tasks = task_list_unleased(&room);
    match crate::lease::table(&room) {
        Ok(table) => apply_task_claims(&mut tasks, &table),
        Err(e) => crate::elog!("  [warn] task claims not checked against leases: {e}"),
    }
    Ok(tasks)
}

/// `task_list` for callers that act on claims (`tasks --json`, the watchdog): fails instead of
/// falling back to the local, possibly stale, claim view when the lease log cannot be read.
pub fn task_list_leased(room_label: Option<&str>) -> Result<Vec<store::Task>, String> {
    let room = resolve_room(room_label)?;
    let mut tasks = task_list_unleased(&room);
    apply_task_claims(&mut tasks, &crate::lease::table(&room)?);
    Ok(tasks)
}

/// Claims are leases: the signed lease log is authoritative, and a claim
/// whose lease expired (or was never taken) is open again.
pub fn apply_task_claims(
    tasks: &mut [store::Task],
    table: &std::collections::BTreeMap<String, crate::lease::Lease>,
) {
    for t in tasks.iter_mut().filter(|t| t.status != "done") {
        match table.get(&task_resource(&t.id)) {
            Some(l) => {
                t.status = "claimed".to_string();
                t.claimed_by = Some(l.holder.clone());
            }
            None if t.status == "claimed" => {
                t.status = "open".to_string();
                t.claimed_by = None;
            }
            None => {}
        }
    }
}

/// Task view from local state + "[task]" announcements, without consulting
/// leases. Reputation signals (stale claims) are computed from this view.
pub(crate) fn task_list_unleased(room: &store::RoomEntry) -> Vec<store::Task> {
    // Also scan room messages for task announcements (for agents without local state)
    let msgs = store::load_messages(&room.room_id, 604800);
    fold_task_announcements(store::load_tasks(&room.room_id), &msgs)
}

/// Apply "[task] New/Claimed by/Done by" announcements in `msgs` (oldest
/// first) to `tasks`, then drop duplicate titles. Announcement text comes
/// from other agents, so malformed text is skipped, never trusted to parse.
pub fn fold_task_announcements(
    mut tasks: Vec<store::Task>,
    msgs: &[serde_json::Value],
) -> Vec<store::Task> {
    for msg in msgs {
        let text = msg["text"].as_str().unwrap_or("");
        if text.starts_with("[task] New:") {
            // Extract id from "(id: XXXXXX)" at end
            if let Some(id_start) = text.rfind("(id: ")
                && let Some(id) = text[id_start + 5..].strip_suffix(')')
                && !id.is_empty()
                && !tasks.iter().any(|t| t.id.starts_with(id))
            {
                let title = text
                    .get("[task] New: ".len()..id_start)
                    .unwrap_or("")
                    .trim()
                    .to_string();
                tasks.push(store::Task {
                    id: id.to_string(),
                    title,
                    status: "open".to_string(),
                    created_by: msg["from"].as_str().unwrap_or("?").to_string(),
                    claimed_by: None,
                    created_at: msg["ts"].as_u64().unwrap_or(0),
                    updated_at: msg["ts"].as_u64().unwrap_or(0),
                    notes: None,
                    resume: None,
                });
            }
        } else if let Some(rest) = text.strip_prefix("[task] Claimed by ") {
            if let Some(colon) = rest.find(": ") {
                let claimer = &rest[..colon];
                let title = &rest[colon + 2..];
                if let Some(t) = tasks
                    .iter_mut()
                    .find(|t| t.title == title && t.status == "open")
                {
                    t.status = "claimed".to_string();
                    t.claimed_by = Some(claimer.to_string());
                }
            }
        } else if let Some(rest) = text.strip_prefix("[task] Done by ")
            && let Some(colon) = rest.find(": ")
        {
            let title_and_notes = &rest[colon + 2..];
            let title = title_and_notes
                .split(" — ")
                .next()
                .unwrap_or(title_and_notes);
            if let Some(t) = tasks.iter_mut().find(|t| t.title == title) {
                t.status = "done".to_string();
            }
        }
    }

    // Deduplicate by title
    let mut seen = std::collections::HashSet::new();
    tasks.retain(|t| seen.insert(t.title.clone()));
    tasks
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

    receipts.sort_by_key(|entry| std::cmp::Reverse(entry.receipt.created_at));
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
        } else if evt["text"]
            .as_str()
            .unwrap_or("")
            .starts_with("[scheduled]")
        {
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
        return Ok(format!(
            "# {} — Digest (last {})\n\nNo activity.",
            room.label, since
        ));
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
                let w = word
                    .trim_matches(|c: char| !c.is_alphanumeric())
                    .to_lowercase();
                if w.len() >= 5 && !is_stopword(&w) {
                    *topics.entry(w).or_insert(0) += 1;
                }
            }
        }
    }

    let mut sorted_agents: Vec<_> = agents.into_iter().collect();
    sorted_agents.sort_by_key(|entry| std::cmp::Reverse(entry.1));
    let mut sorted_topics: Vec<_> = topics.into_iter().collect();
    sorted_topics.sort_by_key(|entry| std::cmp::Reverse(entry.1));
    sorted_topics.truncate(8);

    let total_reactions: usize = reactions.values().map(|v| v.len()).sum();

    let first_dt = chrono::DateTime::from_timestamp(first_ts as i64, 0)
        .map(|d| d.format("%H:%M").to_string())
        .unwrap_or_default();
    let last_dt = chrono::DateTime::from_timestamp(last_ts as i64, 0)
        .map(|d| d.format("%H:%M").to_string())
        .unwrap_or_default();

    let mut report = format!("# {} — Digest (last {})\n\n", room.label, since);
    report.push_str(&format!("**Period:** {} → {}\n", first_dt, last_dt));
    report.push_str(&format!(
        "**Messages:** {}  |  **Agents:** {}  |  **Reactions:** {}\n\n",
        msgs.len(),
        sorted_agents.len(),
        total_reactions
    ));

    report.push_str("## Participants\n");
    for (agent, count) in &sorted_agents {
        report.push_str(&format!("- **{}**: {} messages\n", agent, count));
    }

    report.push_str("\n## Key Topics\n");
    report.push_str(
        &sorted_topics
            .iter()
            .map(|(w, _)| w.as_str())
            .collect::<Vec<_>>()
            .join(", "),
    );

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
    check_webhook_url(url)?;
    Ok(store::add_webhook(&room.room_id, url))
}

/// Webhooks receive decrypted room traffic, so under `local_only` they must
/// point at a local/private host like the relay itself.
fn check_webhook_url(url: &str) -> Result<(), String> {
    if crate::config::relay_settings().local_only {
        crate::config::check_local_url(url).map_err(|e| {
            format!("webhook {e}; webhooks receive decrypted messages (local_only = true)")
        })?;
    }
    Ok(())
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
        // Re-check at delivery time: hooks registered before local_only
        // existed must not leak plaintext to public hosts.
        if check_webhook_url(&hook.url).is_err() {
            continue;
        }
        let payload = json!({
            "room_id": room_id,
            "messages": msgs,
            "count": msgs.len(),
        });
        let _ = client
            .post(&hook.url)
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(&payload).unwrap())
            .send();
    }
}

/// Find messages where an agent was @mentioned.
pub fn mentions(
    agent_id: Option<&str>,
    since: &str,
    room_label: Option<&str>,
) -> Result<Vec<serde_json::Value>, String> {
    let room = resolve_room(room_label)?;
    let target = agent_id.unwrap_or(&store::get_agent_id()).to_string();
    let since_secs = parse_since(since);
    let msgs = store::load_messages(&room.room_id, since_secs);
    let pattern = format!("@{target}");

    let results: Vec<serde_json::Value> = msgs
        .into_iter()
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
    let blob = BASE64
        .decode(b64)
        .map_err(|e| format!("Decode failed: {e}"))?;
    crypto::decrypt(&blob, &room_key, room.room_id.as_bytes())
        .map_err(|e| format!("Decrypt failed: {e}"))
}

/// Auto-generate a changelog from message history.
/// Finds messages mentioning PRs, shipped features, and milestones.
pub fn changelog(since: &str, room_label: Option<&str>) -> Result<Vec<serde_json::Value>, String> {
    let room = resolve_room(room_label)?;
    let since_secs = parse_since(since);
    let msgs = store::load_messages(&room.room_id, since_secs);

    let keywords = [
        "shipped", "merged", "built", "added", "fixed", "PR #", "pr #", "feature", "released",
        "deployed", "launched", "done", "complete",
    ];

    let results: Vec<serde_json::Value> = msgs
        .into_iter()
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
    checks.push((
        "Rooms joined".into(),
        !rooms.is_empty(),
        format!("{}", rooms.len()),
    ));

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
                Ok(blob) => match crypto::decrypt(&blob, &room_key, b"test") {
                    Ok(pt) => checks.push((
                        "AES-256-GCM".into(),
                        pt == test_data,
                        "encrypt/decrypt OK".into(),
                    )),
                    Err(e) => {
                        checks.push(("AES-256-GCM".into(), false, format!("decrypt failed: {e}")))
                    }
                },
                Err(e) => {
                    checks.push(("AES-256-GCM".into(), false, format!("encrypt failed: {e}")))
                }
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
            checks.push((
                "Local messages".into(),
                true,
                format!("{} in last 1h", msgs.len()),
            ));

            // Check members
            checks.push((
                "Members tracked".into(),
                !r.members.is_empty(),
                format!("{}", r.members.len()),
            ));
        }
        None => {
            checks.push(("Active room".into(), false, "none".into()));
        }
    }

    Ok(checks)
}

/// Schedule a message for future delivery.
/// Stores in a queue file; `check` or `send-scheduled` delivers when time is up.
pub fn schedule_message(
    text: &str,
    deliver_at: u64,
    room_label: Option<&str>,
) -> Result<String, String> {
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
        Some(
            regex::RegexBuilder::new(query)
                .case_insensitive(true)
                .build()
                .map_err(|e| format!("Invalid regex: {e}"))?,
        )
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
    sorted_agents.sort_by_key(|entry| std::cmp::Reverse(entry.1));

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
pub fn export(
    since: &str,
    out_path: Option<&str>,
    room_label: Option<&str>,
) -> Result<(String, usize), String> {
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
            "purpose": room.purpose,
            "dm_peer": store::room_dm_peer(&room, &store::get_agent_id()),
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

    let dest = out_path.unwrap_or({
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
    let members: Vec<_> = room
        .members
        .iter()
        .map(|m| {
            json!({
                "agent_id": m.agent_id,
                "role": format!("{:?}", m.role),
                "nickname": m.nickname,
            })
        })
        .collect();
    Ok(json!({
        "room_id": room.room_id,
        "label": room.label,
        "topic": room.topic,
        "purpose": room.purpose,
        "dm_peer": store::room_dm_peer(&room, &store::get_agent_id()),
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
        Ok(room
            .members
            .into_iter()
            .filter(|m| m.last_seen >= cutoff)
            .collect())
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
pub fn watch<F>(room_label: Option<&str>, heartbeat_secs: u64, on_message: F) -> Result<(), String>
where
    F: FnMut(&serde_json::Value),
{
    watch_with(room_label, heartbeat_secs, None, on_message)
}

/// The idle timeout `watch` uses unless told otherwise: two heartbeats and some slack. A live
/// subscription sees at least its own heartbeats in that time.
pub fn default_watch_idle(heartbeat_secs: u64) -> std::time::Duration {
    std::time::Duration::from_secs(heartbeat_secs.max(1) * 2 + 30)
}

/// [`watch`], reopening the subscription when nothing at all (its own heartbeats included) has
/// arrived for `idle_timeout` (default [`default_watch_idle`]), or when the relay drops it. Returns
/// only when the relay refuses our credentials.
pub fn watch_with<F>(
    room_label: Option<&str>,
    heartbeat_secs: u64,
    idle_timeout: Option<std::time::Duration>,
    mut on_message: F,
) -> Result<(), String>
where
    F: FnMut(&serde_json::Value),
{
    install_shutdown_handler();

    let room = resolve_room(room_label)?;
    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let room_id = room.room_id.clone();
    let mut rate_limit = seed_plaza_rate_limit_state(
        &room,
        &store::load_messages(&room.room_id, PLAZA_RATE_LIMIT_WINDOW_SECS),
    );

    // Heartbeats on a timer of their own: sent from the stream callback they stopped in a quiet room,
    // and they are what keeps a live subscription from looking idle.
    let _ = send_watch_heartbeat(&room_id);
    {
        let room_id = room_id.clone();
        let every = std::time::Duration::from_secs(heartbeat_secs.max(1));
        runtime::spawn_with_current(move || loop {
            std::thread::sleep(every);
            let _ = send_watch_heartbeat(&room_id);
        });
    }

    let config = transport::StreamConfig {
        reconnect: true,
        idle_timeout: Some(idle_timeout.unwrap_or_else(|| default_watch_idle(heartbeat_secs))),
        ..Default::default()
    };
    let mut fatal = None;
    transport::stream_with_config(
        &room_id,
        &config,
        |ts, payload| {
            if SHUTDOWN.load(std::sync::atomic::Ordering::Relaxed) {
                std::process::exit(0);
            }
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
        },
        |disconnect, retry| match retry {
            Some(after) => crate::elog!("agora: watch: {disconnect}; reconnecting in {}s", after.as_secs()),
            None => fatal = Some(disconnect.to_string()),
        },
    );

    match fatal {
        Some(e) => Err(e),
        None => Ok(()),
    }
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
                let w = word
                    .trim_matches(|c: char| !c.is_alphanumeric())
                    .to_lowercase();
                if w.len() >= 4 && !is_stopword(&w) {
                    *words.entry(w).or_insert(0) += 1;
                }
            }
        }
    }

    // Sort agents by message count
    let mut agents: Vec<_> = agent_counts.into_iter().collect();
    agents.sort_by_key(|entry| std::cmp::Reverse(entry.1));

    // Top 10 keywords
    let mut top_words: Vec<_> = words.into_iter().collect();
    top_words.sort_by_key(|entry| std::cmp::Reverse(entry.1));
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
    matches!(
        w,
        "that"
            | "this"
            | "with"
            | "from"
            | "have"
            | "been"
            | "will"
            | "your"
            | "they"
            | "what"
            | "when"
            | "were"
            | "them"
            | "then"
            | "than"
            | "each"
            | "just"
            | "also"
            | "into"
            | "some"
            | "more"
            | "here"
            | "agora"
            | "room"
            | "send"
            | "read"
            | "check"
            | "should"
            | "would"
            | "could"
            | "about"
            | "there"
            | "which"
            | "their"
            | "after"
            | "before"
            | "still"
            | "already"
            | "need"
            | "want"
            | "like"
            | "make"
            | "does"
            | "done"
            | "good"
            | "work"
            | "working"
            | "works"
            | "built"
            | "build"
            | "main"
            | "branch"
            | "push"
            | "pull"
            | "merge"
            | "merged"
    )
}

// ── File Sharing ───────────────────────────────────────────────

const MAX_INLINE_FILE_SIZE: usize = 32 * 1024; // 32KB

fn make_file_envelope(
    filename: &str,
    file_id: &str,
    data: &str,
    size: u64,
    chunk_n: u64,
    total_chunks: u64,
) -> serde_json::Value {
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
        transport::publish_with_retry(&room.room_id, &encrypted)
            .map_err(|e| format!("publish failed: {e}"))?;
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
pub fn download_file(
    file_id: &str,
    out_path: Option<&str>,
    room_label: Option<&str>,
) -> Result<String, String> {
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
        return Err(format!(
            "Incomplete file: got {}/{} chunks.",
            chunks.len(),
            total_chunks
        ));
    }

    // Sort by chunk number and reassemble
    chunks.sort_by_key(|(n, _)| *n);
    let mut file_data = Vec::new();
    for (_, data) in &chunks {
        let decoded = BASE64
            .decode(data)
            .map_err(|e| format!("Decode error: {e}"))?;
        file_data.extend_from_slice(&decoded);
    }

    // Write to file. The sender controls `filename`, so never let it pick a
    // path: keep only the final component (no "../", no absolute paths).
    let safe_name = safe_file_name(&filename)?;
    let dest = out_path.unwrap_or(&safe_name);
    std::fs::write(dest, &file_data).map_err(|e| format!("Write error: {e}"))?;
    Ok(dest.to_string())
}

/// Reduce a peer-supplied file name to a safe single path component.
pub(crate) fn safe_file_name(raw: &str) -> Result<String, String> {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or("").trim();
    if base.is_empty() || base == "." || base == ".." || base.contains('\0') {
        return Err(format!("refusing unsafe file name '{raw}'; pass --out"));
    }
    Ok(base.to_string())
}

#[cfg(test)]
mod webhook_url_tests {
    use super::check_webhook_url;
    use crate::runtime;

    #[test]
    fn local_only_refuses_public_webhooks() {
        let _rt = runtime::TestRuntime::new()
            .var("AGORA_CONFIG", "/nonexistent/agora-test-config.toml")
            .unset_var("AGORA_LOCAL_ONLY")
            .enter();
        assert!(check_webhook_url("https://hooks.example.com/x").is_err());
        assert!(check_webhook_url("http://127.0.0.1:9000/hook").is_ok());
        let _rt = runtime::TestRuntime::new()
            .var("AGORA_CONFIG", "/nonexistent/agora-test-config.toml")
            .var("AGORA_LOCAL_ONLY", "false")
            .enter();
        assert!(check_webhook_url("https://hooks.example.com/x").is_ok());
    }
}

#[cfg(test)]
mod file_name_tests {
    use super::safe_file_name;

    #[test]
    fn peer_file_names_cannot_escape_cwd() {
        assert_eq!(safe_file_name("notes.txt").unwrap(), "notes.txt");
        assert_eq!(
            safe_file_name("../../.ssh/authorized_keys").unwrap(),
            "authorized_keys"
        );
        assert_eq!(safe_file_name("/etc/passwd").unwrap(), "passwd");
        assert_eq!(safe_file_name("..\\..\\x.bat").unwrap(), "x.bat");
        assert!(safe_file_name("..").is_err());
        assert!(safe_file_name("dir/").is_err());
        assert!(safe_file_name("").is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BASE64, DISCOVERY_POSITIVE_HALF_LIFE_SECS, PLAZA_RATE_LIMIT_WINDOW_SECS,
        SIGNED_WIRE_VERSION, SignedWirePayload, VERSION, allow_incoming_message,
        annotate_soma_message, count_invite_redemptions_in_envs, decrypt_payload, discover,
        discovery_decay_weight, dm_room_summaries, encrypt_envelope,
        enforce_outbound_plaza_rate_limit, infer_soma_subject_path, ingest_auxiliary_event,
        list_role_leases, list_work_receipts, make_envelope, make_invite_redemption,
        mark_displayed_messages_read, pin, pins, resolve_room, role_claim, role_heartbeat,
        role_release, room_summaries, seed_plaza_rate_limit_state, send_watch_heartbeat,
        should_display_message, signing_message_bytes, soma_churn_decay, soma_correct,
        stale_claim_weight, task_add, task_add_as, task_checkpoint, task_checkpoint_as,
        task_checkpoint_recording, task_claim_as, task_done, task_done_as, task_reject_as,
        task_resource, task_resume_line, unpin,
    };
    use crate::crypto;
    use crate::runtime;
    use crate::store::{self, Role};
    use base64::Engine;
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
        runtime::TestRuntime::new()
            .home(&home)
            .var("AGORA_AGENT_ID", "pin-test")
            .install();

        let room = store::add_room("ag-pin-test", "secret-pin", "pins", Role::Admin);
        store::set_active_room("pins");
        let first = "aaaabbbb".to_string();
        let second = "ccccdddd".to_string();

        store::save_message(
            &room.room_id,
            &json!({
                "id": first,
                "from": "pin-test",
                "ts": 100,
                "text": "first",
                "v": "3.0",
            }),
        );
        store::save_message(
            &room.room_id,
            &json!({
                "id": second,
                "from": "pin-test",
                "ts": 101,
                "text": "second",
                "v": "3.0",
            }),
        );

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
        runtime::TestRuntime::new()
            .home(&home)
            .var("AGORA_AGENT_ID", agent_id)
            .advance_sleep()
            .install();

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
        runtime::TestRuntime::new()
            .home(&home)
            .var("AGORA_AGENT_ID", "soma-test")
            .install();

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

    #[test]
    fn room_summaries_count_only_unread_visible_messages() {
        let (home, room) = setup_plaza_room("summary-agent", Role::Admin);

        store::save_message(
            &room.room_id,
            &json!({
                "id": "peer-seen",
                "from": "peer-agent",
                "ts": 1,
                "text": "seen",
                "v": "3.0",
            }),
        );
        store::mark_room_read(
            &room.room_id,
            &store::load_messages(&room.room_id, u64::MAX),
        );
        store::save_message(
            &room.room_id,
            &json!({
                "id": "reaction-1",
                "from": "peer-agent",
                "ts": 2,
                "type": "reaction",
                "target_id": "peer-seen",
                "emoji": "+1",
                "text": "",
                "v": "3.0",
            }),
        );
        store::save_message(
            &room.room_id,
            &json!({
                "id": "mine",
                "from": "summary-agent",
                "ts": 3,
                "text": "mine",
                "v": "3.0",
            }),
        );
        store::save_message(
            &room.room_id,
            &json!({
                "id": "peer-new",
                "from": "peer-agent",
                "ts": 4,
                "text": "new",
                "v": "3.0",
            }),
        );

        let summary = room_summaries()
            .into_iter()
            .find(|summary| summary.room.room_id == room.room_id)
            .expect("summary exists");
        assert_eq!(summary.unread_count, 1);
        assert_eq!(summary.last_message_at, 4);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn dm_room_summaries_only_include_dm_rooms_and_sort_latest_first() {
        let home = std::env::temp_dir().join(format!(
            "agora-dm-summary-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&home).unwrap();
        runtime::TestRuntime::new()
            .home(&home)
            .var("AGORA_AGENT_ID", "agent-a")
            .install();

        let dm_old = store::add_room("ag-dm-old", "secret", "dm-agent-a-agent-b", Role::Admin);
        store::mark_dm_room(&dm_old.room_id, "agent-b").unwrap();
        let dm_new = store::add_room("ag-dm-new", "secret", "dm-agent-a-agent-c", Role::Admin);
        store::mark_dm_room(&dm_new.room_id, "agent-c").unwrap();
        store::add_room("ag-plaza", "secret", "plaza", Role::Admin);

        store::save_message(
            &dm_old.room_id,
            &json!({
                "id": "older",
                "from": "agent-b",
                "ts": 10,
                "text": "old",
                "v": "3.0",
            }),
        );
        store::save_message(
            &dm_new.room_id,
            &json!({
                "id": "newer",
                "from": "agent-c",
                "ts": 20,
                "text": "new",
                "v": "3.0",
            }),
        );

        let summaries = dm_room_summaries();
        assert_eq!(summaries.len(), 2);
        assert_eq!(summaries[0].room.label, "dm-agent-a-agent-c");
        assert_eq!(summaries[1].room.label, "dm-agent-a-agent-b");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn mark_displayed_messages_read_does_not_clear_skipped_unread_messages() {
        let (home, room) = setup_plaza_room("cursor-agent", Role::Admin);

        store::save_message(
            &room.room_id,
            &json!({
                "id": "peer-1",
                "from": "peer-agent",
                "ts": 1,
                "text": "first",
                "v": "3.0",
            }),
        );
        store::save_message(
            &room.room_id,
            &json!({
                "id": "peer-2",
                "from": "peer-agent",
                "ts": 2,
                "text": "second",
                "v": "3.0",
            }),
        );

        let displayed = vec![serde_json::json!({
            "id": "peer-2",
            "from": "peer-agent",
            "ts": 2,
            "text": "second",
            "v": "3.0",
        })];
        mark_displayed_messages_read(&room.room_id, &displayed);

        let summary = room_summaries()
            .into_iter()
            .find(|summary| summary.room.room_id == room.room_id)
            .expect("summary exists");
        assert_eq!(summary.unread_count, 2);
        assert!(store::load_read_cursor(&room.room_id).is_none());
        let _ = std::fs::remove_dir_all(&home);
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
        runtime::TestRuntime::new()
            .home(&home)
            .var("AGORA_AGENT_ID", "watch-test")
            .install();

        let err = resolve_room(Some("missing-room")).unwrap_err();
        assert_eq!(err, "Room 'missing-room' not found. Run: agora rooms");
    }

    #[test]
    fn watch_heartbeat_targets_watched_room_not_active_room() {
        let _guard = store::test_env_lock().lock().unwrap();
        let home = temp_home();
        std::fs::create_dir_all(&home).unwrap();
        runtime::TestRuntime::new()
            .home(&home)
            .var("AGORA_AGENT_ID", "watch-test")
            .install();

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
            store::save_message(
                &room.room_id,
                &json!({
                    "id": format!("spam{i}"),
                    "from": "spammer",
                    "ts": now_ts - 30 + i,
                    "text": format!("msg {i}"),
                    "v": "3.0",
                }),
            );
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

        assert!(!allow_incoming_message(
            &room, &overflow, now_ts, &mut state
        ));
        assert!(store::load_muted(&room.room_id).contains("spammer"));
    }

    #[test]
    fn outbound_plaza_rate_limit_rejects_eleventh_message() {
        let _guard = store::test_env_lock().lock().unwrap();
        let (_home, room) = setup_plaza_room("speaker", Role::Member);
        let now_ts = current_ts();

        for i in 0..10 {
            store::save_message(
                &room.room_id,
                &json!({
                    "id": format!("mine{i}"),
                    "from": "speaker",
                    "ts": now_ts - 30 + i,
                    "text": format!("own {i}"),
                    "v": "3.0",
                }),
            );
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
    fn a_checkpoint_records_the_harness_session_and_task_resume_rebuilds_its_line() {
        let _guard = store::test_env_lock().lock().unwrap();
        let (_home, room) = setup_plaza_room("resume-agent", Role::Admin);
        let task_id = task_add("Ship resume", None).unwrap();
        task_checkpoint_as("resume-agent", &task_id, Some("first"), None).unwrap();
        let err = task_resume_line(&task_id, None).unwrap_err();
        assert!(err.contains("no recorded session"), "{err}");

        let session = crate::resume::Session {
            harness: "omp".into(),
            session_id: "01a1bd18".into(),
            cwd: "/w".into(),
            tmux_socket: Some("/tmp/tmux-1000/default".into()),
            tmux_window: Some("main:12".into()),
            agent_id: "resume-agent".into(),
            recorded_at: 1,
            ..Default::default()
        };
        task_checkpoint_recording("resume-agent", &task_id, Some("tests queued"), None, Some(session.clone())).unwrap();
        // a checkpoint from outside a harness (API, cron) keeps the recorded session
        task_checkpoint_as("resume-agent", &task_id, Some("tests green"), None).unwrap();
        let task = store::load_tasks(&room.room_id).into_iter().find(|t| t.id == task_id).unwrap();
        assert_eq!(task.resume.as_ref(), Some(&session));

        let (s, argv) = task_resume_line(&task_id[..6], None).unwrap();
        assert_eq!(s, session);
        assert_eq!(&argv[..5], ["env", "AGORA_AGENT_ID=resume-agent", "omp", "--resume", "01a1bd18"]);
        assert!(argv[5].contains(&format!("[{}]", &task_id[..6])) && argv[5].contains("\"tests green\""), "{}", argv[5]);
        // a lapsed claim belongs to nobody: not resumed
        crate::lease::release_as("resume-agent", &task_resource(&task_id), None).unwrap();
        assert!(task_resume_line(&task_id, None).unwrap_err().contains("no live claim"));
        // another agent's claim drops the recorded session: its work never gets a second agent
        task_claim_as("other-agent", &task_id, None).unwrap();
        let task = store::load_tasks(&room.room_id).into_iter().find(|t| t.id == task_id).unwrap();
        assert_eq!(task.resume, None);
        assert!(task_resume_line(&task_id, None).unwrap_err().contains("no recorded session"));
        task_done(&task_id, None, None).unwrap();
        assert!(task_resume_line(&task_id, None).unwrap_err().contains("already done"));
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
        assert!(
            store::get_role_lease(&room.room_id, "backend").is_none(),
            "unsigned role_state must not be cached"
        );
        let mut env = env;
        env["_auth"] = json!("verified");
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
        assert_eq!(
            stored.context_summary.as_deref(),
            Some("Owns transport too")
        );

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
                resume: None,
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
    fn ingest_capability_card_updates_peer_card_cache() {
        let _guard = store::test_env_lock().lock().unwrap();
        let (_home, room) = setup_plaza_room("card-admin", Role::Admin);
        let env = json!({
            "v": VERSION,
            "id": "card01",
            "from": "peer-agent",
            "ts": current_ts(),
            "type": "capability_card",
            "capabilities": ["rust", "ops"],
            "available": false,
            "description": "handles deploys",
            "text": "[card] peer-agent -- capabilities: rust, ops",
        });

        ingest_auxiliary_event(&room.room_id, &env);

        let cards = store::load_peer_cards(&room.room_id);
        assert_eq!(cards.len(), 1);
        assert_eq!(cards[0].agent_id, "peer-agent");
        assert_eq!(cards[0].capabilities, vec!["rust", "ops"]);
        assert!(!cards[0].available);
        assert_eq!(cards[0].description.as_deref(), Some("handles deploys"));
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
        store::save_message(
            &room.room_id,
            &json!({
                "id": belief_id,
                "from": "soma-test",
                "ts": current_ts(),
                "type": "soma_belief",
                "subject": "src/chat.rs:soma_correct",
                "predicate": "returns success for unknown belief ids",
                "confidence": 0.7,
                "v": "3.0",
                "text": "[soma] src/chat.rs:soma_correct: returns success for unknown belief ids",
            }),
        );

        let correction_id = soma_correct(
            "abcd",
            "rejects unknown belief ids",
            Some("regression fix"),
            None,
        )
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
            store::save_message(
                &room.room_id,
                &json!({
                    "id": id,
                    "from": "soma-test",
                    "ts": ts,
                    "type": "soma_belief",
                    "subject": "src/main.rs",
                    "predicate": "placeholder",
                    "confidence": 0.6,
                    "v": "3.0",
                    "text": "[soma] src/main.rs: placeholder",
                }),
            );
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
        assert!(
            run_git(&repo, &["config", "user.email", "soma@test.local"])
                .status
                .success()
        );
        assert!(
            run_git(&repo, &["config", "user.name", "Soma Test"])
                .status
                .success()
        );
        assert!(
            run_git(&repo, &["config", "commit.gpgsign", "false"])
                .status
                .success()
        );

        let tracked = repo.join("tracked.txt");
        std::fs::write(&tracked, "v1\n").unwrap();
        assert!(run_git(&repo, &["add", "tracked.txt"]).status.success());
        assert!(
            run_git(&repo, &["commit", "-m", "initial"])
                .status
                .success()
        );

        let base_ref = String::from_utf8_lossy(&run_git(&repo, &["rev-parse", "HEAD"]).stdout)
            .trim()
            .to_string();

        std::fs::write(&tracked, "v2\n").unwrap();
        assert!(
            run_git(&repo, &["commit", "-am", "second"])
                .status
                .success()
        );
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
    fn task_announcements_from_peers_never_panic() {
        let msgs: Vec<serde_json::Value> = [
            "[task] New:(id: abc)",
            "[task] New: x (id: ",
            "[task] New: x (id: )",
            "[task] New: (id: q",
            "[task] New: ok task (id: abc123)",
            "[task] Claimed by ",
            "[task] Done by agent-b: ok task — shipped",
        ]
        .iter()
        .map(|t| json!({"from": "agent-b", "ts": 1, "text": t}))
        .collect();
        let tasks = super::fold_task_announcements(Vec::new(), &msgs);
        let ok: Vec<_> = tasks.iter().filter(|t| t.id == "abc123").collect();
        assert_eq!(ok.len(), 1);
        assert_eq!(ok[0].title, "ok task");
        assert_eq!(ok[0].status, "done");
    }

    #[test]
    fn signed_payload_round_trip_marks_verified() {
        let _guard = store::test_env_lock().lock().unwrap();
        let home = temp_home();
        std::fs::create_dir_all(&home).unwrap();
        runtime::TestRuntime::new()
            .home(&home)
            .var("AGORA_AGENT_ID", "sign-test")
            .install();

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
        runtime::TestRuntime::new()
            .home(&home)
            .var("AGORA_AGENT_ID", "alice")
            .install();

        let room = store::add_room(
            "ag-sign-mismatch",
            "secret-sign-mismatch",
            "sign-mismatch",
            Role::Admin,
        );
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
        let blob =
            crypto::encrypt(plaintext.as_bytes(), &enc_key, room.room_id.as_bytes()).unwrap();
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
        })
        .unwrap();

        let warning = decrypt_payload(&forged_wire, &room_key, &room.room_id).unwrap();
        assert_eq!(warning["type"].as_str(), Some("auth_warning"));
        assert_eq!(warning["from"].as_str(), Some("[auth]"));
        assert_eq!(warning["sender"].as_str(), Some("alice"));
        assert_eq!(
            warning["auth_reason"].as_str(),
            Some("signing_key_mismatch")
        );
        assert!(
            warning["text"]
                .as_str()
                .unwrap_or("")
                .contains("signing key")
        );
    }

    #[test]
    fn signed_payload_accepts_legacy_url_safe_trusted_key() {
        let _guard = store::test_env_lock().lock().unwrap();
        let home = temp_home();
        std::fs::create_dir_all(&home).unwrap();
        runtime::TestRuntime::new()
            .home(&home)
            .var("AGORA_AGENT_ID", "alice")
            .install();

        let room = store::add_room(
            "ag-sign-legacy",
            "secret-sign-legacy",
            "sign-legacy",
            Role::Admin,
        );
        let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
        let env = make_envelope("hello signed world", None);
        let wire = encrypt_envelope(&env, &room_key, &room.room_id);

        let pkcs8 = store::load_or_create_signing_keypair("alice").unwrap();
        let legacy_pubkey = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(crypto::signing_public_key(&pkcs8).unwrap());
        let mut trusted = std::collections::HashMap::new();
        trusted.insert("alice".to_string(), legacy_pubkey);
        store::save_trusted_signing_keys(&trusted);

        let decrypted = decrypt_payload(&wire, &room_key, &room.room_id).unwrap();
        assert_eq!(decrypted["text"].as_str(), Some("hello signed world"));
        assert_eq!(decrypted["_auth"].as_str(), Some("verified"));
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

    #[test]
    fn task_add_as_records_verified_creator() {
        let _guard = store::test_env_lock().lock().unwrap();
        let (_home, room) = setup_plaza_room("server-host", Role::Admin);

        let task_id = task_add_as("api-agent", "Ship API auth", Some("plaza")).unwrap();

        let tasks = store::load_tasks(&room.room_id);
        let task = tasks.iter().find(|t| t.id == task_id).expect("task saved");
        assert_eq!(task.created_by, "api-agent");

        let messages = store::load_messages(&room.room_id, 3600);
        let msg = messages
            .iter()
            .find(|m| m["id"].as_str() == Some(task_id.as_str()))
            .or_else(|| {
                messages
                    .iter()
                    .find(|m| m["text"].as_str().unwrap_or("").contains("Ship API auth"))
            })
            .expect("task message saved");
        assert_eq!(msg["from"].as_str(), Some("api-agent"));
    }

    #[test]
    fn task_lifecycle_as_uses_verified_agent_identity() {
        let _guard = store::test_env_lock().lock().unwrap();
        let (_home, room) = setup_plaza_room("server-host", Role::Admin);

        let task_id = task_add_as("api-agent", "Ship API auth", None).unwrap();
        let claimed = task_claim_as("api-agent", &task_id, None).unwrap();
        assert_eq!(claimed, task_id);

        let checkpointed =
            task_checkpoint_as("api-agent", &task_id, Some("progress"), None).unwrap();
        assert_eq!(checkpointed, task_id);

        let done = task_done_as("api-agent", &task_id, Some("done"), None).unwrap();
        assert_eq!(done, task_id);

        let tasks = store::load_tasks(&room.room_id);
        let task = tasks.iter().find(|t| t.id == task_id).expect("task saved");
        assert_eq!(task.claimed_by.as_deref(), Some("api-agent"));
        assert_eq!(task.status, "done");

        let messages = store::load_messages(&room.room_id, 3600);
        let task_messages: Vec<_> = messages
            .iter()
            .filter(|m| {
                m["text"].as_str().unwrap_or("").contains("Ship API auth")
                    || m["text"].as_str().unwrap_or("").contains("progress")
                    || m["text"].as_str().unwrap_or("").contains("done")
            })
            .collect();
        assert!(
            task_messages
                .iter()
                .all(|m| m["from"].as_str() == Some("api-agent")),
            "task lifecycle messages should use verified caller identity"
        );
    }

    #[test]
    fn task_reject_as_reopens_claimed_task_for_verified_agent() {
        let _guard = store::test_env_lock().lock().unwrap();
        let (_home, room) = setup_plaza_room("server-host", Role::Admin);

        let task_id = task_add_as("api-agent", "Review shady task", None).unwrap();
        task_claim_as("api-agent", &task_id, None).unwrap();
        let rejected =
            task_reject_as("api-agent", &task_id, Some("scope is abusive"), None).unwrap();
        assert_eq!(rejected, task_id);

        let tasks = store::load_tasks(&room.room_id);
        let task = tasks.iter().find(|t| t.id == task_id).expect("task saved");
        assert_eq!(task.status, "open");
        assert_eq!(task.claimed_by, None);
        assert_eq!(task.notes.as_deref(), Some("scope is abusive"));

        let receipts = store::load_work_receipts(&room.room_id);
        let receipt = receipts
            .iter()
            .find(|r| r.task_id == task_id && r.status == "rejected")
            .expect("rejection receipt saved");
        assert_eq!(receipt.agent_id, "api-agent");
        assert_eq!(receipt.notes.as_deref(), Some("scope is abusive"));

        let messages = store::load_messages(&room.room_id, 3600);
        let reject_msg = messages
            .iter()
            .find(|m| {
                m["text"]
                    .as_str()
                    .unwrap_or("")
                    .contains("Rejected by api-agent")
            })
            .expect("reject message saved");
        assert_eq!(reject_msg["from"].as_str(), Some("api-agent"));
    }

    #[test]
    fn task_reject_as_refuses_other_agents_claim() {
        let _guard = store::test_env_lock().lock().unwrap();
        let (_home, _room) = setup_plaza_room("server-host", Role::Admin);

        let task_id = task_add_as("creator", "Review shady task", None).unwrap();
        task_claim_as("builder-agent", &task_id, None).unwrap();

        let err = task_reject_as("other-agent", &task_id, Some("not mine"), None)
            .expect_err("other agents must not reject a claimed task they do not hold");
        assert!(err.contains("currently claimed by 'builder-agent'"));
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
        Some(
            regex::RegexBuilder::new(query)
                .case_insensitive(true)
                .build()
                .map_err(|e| format!("Invalid regex: {e}"))?,
        )
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

            let matches_from = from.is_none_or(|f| sender == f);
            let matches_after = after.is_none_or(|a| ts >= a);
            let matches_before = before.is_none_or(|b| ts <= b);

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
            matches.into_iter().take(5).collect::<Vec<_>>().join(", ")
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

    if let Some(id) = env["id"].as_str()
        && let Some(replies) = children.get(id)
    {
        for reply in replies {
            walk_thread(reply, depth + 1, children, out);
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
            unsafe {
                libc::kill(pid, libc::SIGTERM);
            }
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
    unsafe {
        libc::setsid();
    }
    install_shutdown_handler();

    // Guard removes the PID file on any exit path (signal, panic, normal).
    let _pid_guard = PidFileGuard::new(pidfile.clone());

    let room_key = crypto::derive_room_key(&secret, &room_id);
    let me = store::get_agent_id();
    let mut rate_limit = seed_plaza_rate_limit_state(
        &room,
        &store::load_messages(&room.room_id, PLAZA_RATE_LIMIT_WINDOW_SECS),
    );

    transport::stream(&room_id, |ts, payload| {
        if SHUTDOWN.load(std::sync::atomic::Ordering::Relaxed) {
            // PidFileGuard::drop removes the PID file, then exit.
            std::process::exit(0);
        }
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
    if let Ok(pid_str) = std::fs::read_to_string(&pid_path)
        && let Ok(pid) = pid_str.trim().parse::<i32>()
    {
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
        // The daemon's signal handler calls exit(0), which drops PidFileGuard
        // and removes the PID file. Wait briefly for cleanup, then escalate.
        std::thread::sleep(std::time::Duration::from_millis(200));
        // If still alive after 200ms, SIGKILL and clean up ourselves.
        if unsafe { libc::kill(pid, 0) } == 0 {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
            let _ = std::fs::remove_file(pid_path);
        }
        return Ok(());
    }
    Err("No daemon running.".to_string())
}

pub fn verify(room_label: Option<&str>) -> Result<serde_json::Value, String> {
    let room = resolve_room(room_label)?;
    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);
    let (nonce, commitment) =
        crypto::zkp_create_commitment(&room_key).map_err(|e| e.to_string())?;
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
