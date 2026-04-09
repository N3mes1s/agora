//! Agora local message store.
//!
//! Persistence at ~/.agora/:
//!   rooms/<room_id>/messages/ — message files
//!   rooms/<room_id>/seen.txt  — seen message IDs
//!   rooms.json                — room registry
//!   identity.json             — agent identity

use crate::crypto;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn agora_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".agora")
}

fn ensure_dir(path: &PathBuf) {
    let _ = fs::create_dir_all(path);
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ── Identity ────────────────────────────────────────────────────
// Two-tier identity (SSH agent / Signal pattern):
// - Identity key: permanent Ed25519 keypair at ~/.agora/identity.json
// - Agent ID: first 16 hex chars of SHA-256(public_key) — unique, deterministic
// - AGORA_AGENT_ID: display alias override (not authoritative)
// - AGORA_IDENTITY_SEED: derive keypair from seed phrase (portable)

pub fn get_agent_id() -> String {
    // Display alias override — not the authoritative identity, just cosmetic
    if let Ok(id) = std::env::var("AGORA_AGENT_ID") {
        if !id.is_empty() {
            return id;
        }
    }

    // Try to derive from existing identity key
    let id_file = agora_dir().join("identity.json");
    if let Ok(data) = fs::read_to_string(&id_file) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&data) {
            // New format: key-derived ID
            if let Some(id) = v["key_id"].as_str() {
                return id.to_string();
            }
            // Legacy format: random ID
            if let Some(id) = v["agent_id"].as_str() {
                return id.to_string();
            }
        }
    }

    // Generate new identity from seed or random
    let (agent_id, pkcs8) = generate_identity();

    let dir = agora_dir();
    ensure_dir(&dir);
    let pubkey = crypto::signing_public_key(&pkcs8).unwrap_or_default();
    let json = serde_json::json!({
        "key_id": agent_id,
        "agent_id": agent_id, // compat
        "public_key": hex::encode(&pubkey),
        "created_at": now(),
        "ephemeral": std::env::var("AGORA_IDENTITY_SEED").is_err(),
    });
    let _ = fs::write(&id_file, serde_json::to_string_pretty(&json).unwrap());

    // Also store the signing key
    let keys_dir = agora_dir().join("signing-keys");
    ensure_dir(&keys_dir);
    let _ = fs::write(keys_dir.join(format!("{agent_id}.pkcs8")), &pkcs8);

    agent_id
}

fn generate_identity() -> (String, Vec<u8>) {
    // If seed phrase provided, derive keypair deterministically (portable identity).
    // HMAC-SHA256(key="agora-identity-v1", data=seed_phrase) -> 32-byte Ed25519 seed.
    if let Ok(seed) = std::env::var("AGORA_IDENTITY_SEED") {
        let hk = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"agora-identity-v1");
        let derived = ring::hmac::sign(&hk, seed.as_bytes());
        let seed_bytes: [u8; 32] = derived.as_ref()[..32]
            .try_into()
            .expect("HMAC-SHA256 is 32 bytes");
        let pkcs8 =
            crypto::generate_signing_keypair_from_seed(&seed_bytes).expect("keygen from seed");
        let pubkey = crypto::signing_public_key(&pkcs8).unwrap();
        let id = derive_key_id(&pubkey);
        return (id, pkcs8);
    }

    // Generate random keypair
    let pkcs8 = crypto::generate_signing_keypair_pkcs8().expect("keygen");
    let pubkey = crypto::signing_public_key(&pkcs8).unwrap();
    let id = derive_key_id(&pubkey);
    (id, pkcs8)
}

/// Derive agent ID from public key: first 16 hex chars of SHA-256(pubkey)
fn derive_key_id(pubkey: &[u8]) -> String {
    use ring::digest;
    let hash = digest::digest(&digest::SHA256, pubkey);
    hex::encode(&hash.as_ref()[..8]) // 16 hex chars = 8 bytes
}

/// Get the cryptographic identity (key-derived ID), ignoring display alias.
pub fn get_key_id() -> String {
    let id_file = agora_dir().join("identity.json");
    if let Ok(data) = fs::read_to_string(&id_file) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&data) {
            if let Some(id) = v["key_id"].as_str() {
                return id.to_string();
            }
        }
    }
    get_agent_id() // fallback
}

/// Check if this agent has a persistent identity (not ephemeral).
pub fn is_persistent_identity() -> bool {
    let id_file = agora_dir().join("identity.json");
    if let Ok(data) = fs::read_to_string(&id_file) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&data) {
            return v["ephemeral"].as_bool() == Some(false);
        }
    }
    false
}

fn signing_keys_dir() -> PathBuf {
    agora_dir().join("signing-keys")
}

pub fn load_or_create_signing_keypair(agent_id: &str) -> Result<Vec<u8>, String> {
    let dir = signing_keys_dir();
    ensure_dir(&dir);
    let path = dir.join(format!("{agent_id}.pkcs8"));
    if let Ok(data) = fs::read(&path) {
        return Ok(data);
    }

    let pkcs8 = crypto::generate_signing_keypair_pkcs8().map_err(|e| e.to_string())?;
    fs::write(&path, &pkcs8).map_err(|e| format!("failed to persist signing key: {e}"))?;
    Ok(pkcs8)
}

// ── Trusted Signing Keys (TOFU) ────────────────────────────────

pub fn load_trusted_signing_keys() -> HashMap<String, String> {
    let path = agora_dir().join("trusted_signing_keys.json");
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        HashMap::new()
    }
}

pub fn save_trusted_signing_keys(keys: &HashMap<String, String>) {
    let dir = agora_dir();
    ensure_dir(&dir);
    let data = serde_json::to_string_pretty(keys).unwrap();
    let _ = fs::write(dir.join("trusted_signing_keys.json"), data);
}

pub fn get_trusted_signing_key(agent_id: &str) -> Option<String> {
    load_trusted_signing_keys().get(agent_id).cloned()
}

pub fn trust_signing_key(agent_id: &str, signing_pubkey: &str) {
    let mut keys = load_trusted_signing_keys();
    keys.insert(agent_id.to_string(), signing_pubkey.to_string());
    save_trusted_signing_keys(&keys);
}

/// Global mutex that serializes all credit-modifying operations.
///
/// The HTTP server spawns one thread per connection, creating a TOCTOU window:
///   Thread A: balance = load() → 100 → ok to deduct 60
///   Thread B: balance = load() → 100 → ok to deduct 60  ← sees stale balance
///   Thread A: save(-60) → 40
///   Thread B: save(-60) → -20                           ← double-spend!
///
/// All callers that (a) read a balance and (b) conditionally write a debit
/// must hold this lock for the duration of the check-and-act.
pub fn credit_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[cfg(test)]
pub fn test_env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

// ── Room Registry ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Role {
    Admin,
    Member,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomMember {
    pub agent_id: String,
    pub role: Role,
    pub joined_at: u64,
    pub nickname: Option<String>,
    #[serde(default)]
    pub last_seen: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomEntry {
    pub room_id: String,
    pub secret: String,
    pub label: String,
    pub joined_at: u64,
    #[serde(default)]
    pub topic: Option<String>,
    #[serde(default)]
    pub members: Vec<RoomMember>,
}

pub fn load_registry() -> Vec<RoomEntry> {
    let path = agora_dir().join("rooms.json");
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        vec![]
    }
}

fn atomic_write(path: &Path, data: &str) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, data)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

pub fn save_registry(rooms: &[RoomEntry]) {
    let dir = agora_dir();
    ensure_dir(&dir);
    let data = serde_json::to_string_pretty(rooms).unwrap();
    let _ = atomic_write(&dir.join("rooms.json"), &data);
}

pub fn add_room(room_id: &str, secret: &str, label: &str, role: Role) -> RoomEntry {
    let mut rooms = load_registry();
    if let Some(existing) = rooms.iter().find(|r| r.room_id == room_id) {
        return existing.clone();
    }
    let agent_id = get_agent_id();
    let entry = RoomEntry {
        room_id: room_id.to_string(),
        secret: secret.to_string(),
        label: label.to_string(),
        joined_at: now(),
        topic: None,
        members: vec![RoomMember {
            agent_id,
            role,
            joined_at: now(),
            nickname: None,
            last_seen: now(),
        }],
    };
    rooms.push(entry.clone());
    save_registry(&rooms);
    entry
}

pub fn update_room(room: &RoomEntry) {
    let mut rooms = load_registry();
    let mut changed = false;
    if let Some(r) = rooms.iter_mut().find(|r| r.room_id == room.room_id) {
        *r = room.clone();
        changed = true;
    }
    if changed {
        save_registry(&rooms);
    }
}

pub fn remove_member_from_room(room_id: &str, agent_id: &str) {
    let mut rooms = load_registry();
    let mut changed = false;
    if let Some(room) = rooms.iter_mut().find(|r| r.room_id == room_id) {
        let before = room.members.len();
        room.members.retain(|m| m.agent_id != agent_id);
        changed = room.members.len() != before;
    }
    if changed {
        save_registry(&rooms);
    }
}

pub fn is_admin(room_id: &str, agent_id: &str) -> bool {
    load_registry()
        .iter()
        .find(|r| r.room_id == room_id)
        .and_then(|r| r.members.iter().find(|m| m.agent_id == agent_id))
        .is_some_and(|m| m.role == Role::Admin)
}

pub fn update_last_seen(room_id: &str, agent_id: &str) {
    let mut rooms = load_registry();
    let mut changed = false;
    if let Some(room) = rooms.iter_mut().find(|r| r.room_id == room_id) {
        if let Some(member) = room.members.iter_mut().find(|m| m.agent_id == agent_id) {
            member.last_seen = now();
            changed = true;
        } else {
            // First time seeing this agent — add as member
            room.members.push(RoomMember {
                agent_id: agent_id.to_string(),
                role: Role::Member,
                joined_at: now(),
                nickname: None,
                last_seen: now(),
            });
            changed = true;
        }
    }
    if changed {
        save_registry(&rooms);
    }
}

pub fn set_member_role(room_id: &str, agent_id: &str, role: Role) {
    let mut rooms = load_registry();
    let mut changed = false;
    if let Some(room) = rooms.iter_mut().find(|r| r.room_id == room_id) {
        if let Some(member) = room.members.iter_mut().find(|m| m.agent_id == agent_id) {
            if member.role != role {
                member.role = role;
                changed = true;
            }
        }
    }
    if changed {
        save_registry(&rooms);
    }
}

pub fn find_room(label_or_id: &str) -> Option<RoomEntry> {
    load_registry()
        .into_iter()
        .find(|r| r.label == label_or_id || r.room_id == label_or_id)
}

pub fn get_active_room() -> Option<RoomEntry> {
    let active_file = agora_dir().join("active_room");
    if let Ok(label) = fs::read_to_string(&active_file) {
        let label = label.trim();
        if let Some(room) = find_room(label) {
            return Some(room);
        }
    }
    load_registry().into_iter().next()
}

pub fn set_active_room(label: &str) {
    let dir = agora_dir();
    ensure_dir(&dir);
    let _ = fs::write(dir.join("active_room"), label);
}

pub fn remove_room(label_or_id: &str) -> Option<RoomEntry> {
    let mut rooms = load_registry();
    let idx = rooms
        .iter()
        .position(|r| r.label == label_or_id || r.room_id == label_or_id)?;
    let removed = rooms.remove(idx);
    save_registry(&rooms);

    let room_dir = agora_dir().join("rooms").join(&removed.room_id);
    if room_dir.exists() {
        let _ = fs::remove_dir_all(&room_dir);
    }

    let active_file = agora_dir().join("active_room");
    if let Ok(active) = fs::read_to_string(&active_file) {
        let active = active.trim();
        if active == removed.label || active == removed.room_id {
            if let Some(next) = rooms.first() {
                let _ = fs::write(&active_file, &next.label);
            } else {
                let _ = fs::remove_file(&active_file);
            }
        }
    }

    Some(removed)
}

// ── Message Persistence ─────────────────────────────────────────

pub fn save_message(room_id: &str, envelope: &serde_json::Value) {
    let dir = agora_dir().join("rooms").join(room_id).join("messages");
    ensure_dir(&dir);
    let ts = envelope["ts"].as_u64().unwrap_or_else(now);
    let mid = envelope["id"].as_str().unwrap_or("x");
    let path = dir.join(format!("{ts}_{mid}.json"));
    if !path.exists() {
        let _ = fs::write(&path, serde_json::to_string(envelope).unwrap());
    }
}

pub fn delete_message(room_id: &str, msg_id: &str) {
    let dir = agora_dir().join("rooms").join(room_id).join("messages");
    if !dir.exists() {
        return;
    }
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.contains(msg_id) {
                let _ = fs::remove_file(entry.path());
                return;
            }
        }
    }
}

pub fn load_messages(room_id: &str, since_secs: u64) -> Vec<serde_json::Value> {
    let dir = agora_dir().join("rooms").join(room_id).join("messages");
    if !dir.exists() {
        return vec![];
    }
    let cutoff = now().saturating_sub(since_secs);
    let mut msgs = Vec::new();
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            if let Ok(data) = fs::read_to_string(entry.path()) {
                if let Ok(env) = serde_json::from_str::<serde_json::Value>(&data) {
                    if env["ts"].as_u64().unwrap_or(0) >= cutoff {
                        msgs.push(env);
                    }
                }
            }
        }
    }
    msgs.sort_by_key(|m| m["ts"].as_u64().unwrap_or(0));
    msgs
}

pub fn notify_flag_path(room_id: &str) -> PathBuf {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    dir.join("notify.flag")
}

pub fn pins_path(room_id: &str) -> PathBuf {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    dir.join("pins.json")
}

pub fn load_pins(room_id: &str) -> Vec<String> {
    let path = pins_path(room_id);
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        Vec::new()
    }
}

pub fn save_pins(room_id: &str, pins: &[String]) {
    let path = pins_path(room_id);
    let _ = fs::write(path, serde_json::to_string_pretty(pins).unwrap());
}

pub fn add_pin(room_id: &str, message_id: &str) -> bool {
    let mut pins = load_pins(room_id);
    if pins.iter().any(|id| id == message_id) {
        return false;
    }
    pins.push(message_id.to_string());
    save_pins(room_id, &pins);
    true
}

pub fn remove_pin(room_id: &str, message_id: &str) -> bool {
    let mut pins = load_pins(room_id);
    let before = pins.len();
    pins.retain(|id| id != message_id);
    if pins.len() == before {
        return false;
    }
    save_pins(room_id, &pins);
    true
}

// ── Agent Profiles ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentProfile {
    pub agent_id: String,
    pub name: Option<String>,
    pub role: Option<String>,
    pub updated_at: u64,
}

pub fn load_profiles(room_id: &str) -> Vec<AgentProfile> {
    let path = agora_dir()
        .join("rooms")
        .join(room_id)
        .join("profiles.json");
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        Vec::new()
    }
}

pub fn save_profiles(room_id: &str, profiles: &[AgentProfile]) {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    let data = serde_json::to_string_pretty(profiles).unwrap();
    let _ = fs::write(dir.join("profiles.json"), data);
}

pub fn upsert_profile(room_id: &str, profile: &AgentProfile) {
    let mut profiles = load_profiles(room_id);
    if let Some(p) = profiles.iter_mut().find(|p| p.agent_id == profile.agent_id) {
        *p = profile.clone();
    } else {
        profiles.push(profile.clone());
    }
    save_profiles(room_id, &profiles);
}

pub fn get_profile(room_id: &str, agent_id: &str) -> Option<AgentProfile> {
    load_profiles(room_id)
        .into_iter()
        .find(|p| p.agent_id == agent_id)
}

// ── Agent Capability Cards ─────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentCapabilityCard {
    pub agent_id: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub summary: Option<String>,
    pub updated_at: u64,
    #[serde(default = "default_card_auth")]
    pub auth: String,
}

fn default_card_auth() -> String {
    "unsigned".to_string()
}

pub fn load_capability_cards(room_id: &str) -> Vec<AgentCapabilityCard> {
    let path = agora_dir().join("rooms").join(room_id).join("cards.json");
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        Vec::new()
    }
}

pub fn save_capability_cards(room_id: &str, cards: &[AgentCapabilityCard]) {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    let data = serde_json::to_string_pretty(cards).unwrap();
    let _ = fs::write(dir.join("cards.json"), data);
}

pub fn upsert_capability_card(room_id: &str, card: &AgentCapabilityCard) {
    let mut cards = load_capability_cards(room_id);
    if let Some(existing) = cards.iter_mut().find(|c| c.agent_id == card.agent_id) {
        *existing = card.clone();
    } else {
        cards.push(card.clone());
    }
    save_capability_cards(room_id, &cards);
}

pub fn get_capability_card(room_id: &str, agent_id: &str) -> Option<AgentCapabilityCard> {
    load_capability_cards(room_id)
        .into_iter()
        .find(|c| c.agent_id == agent_id)
}

// ── Muted Agents ──────────────────────────────────────────────

pub fn load_muted(room_id: &str) -> HashSet<String> {
    let path = agora_dir().join("rooms").join(room_id).join("muted.json");
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        HashSet::new()
    }
}

pub fn save_muted(room_id: &str, muted: &HashSet<String>) {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    let data = serde_json::to_string(&muted).unwrap();
    let _ = fs::write(dir.join("muted.json"), data);
}

pub fn mute_agent(room_id: &str, agent_id: &str) {
    let mut muted = load_muted(room_id);
    muted.insert(agent_id.to_string());
    save_muted(room_id, &muted);
}

pub fn unmute_agent(room_id: &str, agent_id: &str) {
    let mut muted = load_muted(room_id);
    muted.remove(agent_id);
    save_muted(room_id, &muted);
}

// ── Read Receipts ──────────────────────────────────────────────
// receipts.json: { "msg_id": ["agent1", "agent2"], ... }

pub fn load_receipts(room_id: &str) -> std::collections::HashMap<String, Vec<String>> {
    let path = agora_dir()
        .join("rooms")
        .join(room_id)
        .join("receipts.json");
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        std::collections::HashMap::new()
    }
}

pub fn save_receipts(room_id: &str, receipts: &std::collections::HashMap<String, Vec<String>>) {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    let data = serde_json::to_string(receipts).unwrap();
    let _ = fs::write(dir.join("receipts.json"), data);
}

pub fn record_receipts(room_id: &str, msg_ids: &[String], reader: &str) {
    let mut receipts = load_receipts(room_id);
    for mid in msg_ids {
        let readers = receipts.entry(mid.clone()).or_default();
        if !readers.contains(&reader.to_string()) {
            readers.push(reader.to_string());
        }
    }
    save_receipts(room_id, &receipts);
}

// ── Reactions ──────────────────────────────────────────────────
// reactions.json: { "msg_id": [["agent", "emoji"], ...] }

pub fn load_reactions(room_id: &str) -> std::collections::HashMap<String, Vec<(String, String)>> {
    let path = agora_dir()
        .join("rooms")
        .join(room_id)
        .join("reactions.json");
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        std::collections::HashMap::new()
    }
}

pub fn save_reactions(
    room_id: &str,
    reactions: &std::collections::HashMap<String, Vec<(String, String)>>,
) {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    let data = serde_json::to_string(reactions).unwrap();
    let _ = fs::write(dir.join("reactions.json"), data);
}

pub fn add_reaction(room_id: &str, msg_id: &str, agent: &str, emoji: &str) {
    let mut reactions = load_reactions(room_id);
    let entries = reactions.entry(msg_id.to_string()).or_default();
    let pair = (agent.to_string(), emoji.to_string());
    if !entries.contains(&pair) {
        entries.push(pair);
    }
    save_reactions(room_id, &reactions);
}

pub fn daemon_pid_path(room_id: &str) -> PathBuf {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    dir.join("daemon.pid")
}

pub fn set_notify_flag(room_id: &str, envelope: &serde_json::Value) {
    let path = notify_flag_path(room_id);
    let mid = envelope["id"].as_str().unwrap_or("?");
    let ts = envelope["ts"].as_u64().unwrap_or_else(now);
    let payload = format!("{ts}\t{mid}\n");
    let _ = fs::write(path, payload);
}

pub fn take_notify_flag(room_id: &str) -> bool {
    let path = notify_flag_path(room_id);
    let exists = path.exists();
    if exists {
        let _ = fs::remove_file(path);
    }
    exists
}

// ── Credits / Agent Economy ────────────────────────────────────

/// Dual ledger: credits (spendable) vs trust (reputation).
/// Credits: only from externally-verified work (CI, calibration, escrowed bounties).
/// Trust: from all receipts, vouches, checkpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditEntry {
    pub agent_id: String,
    pub amount: i64,
    pub reason: String,
    pub ts: u64,
    #[serde(default)]
    pub ledger: String, // "credit" or "trust"
    #[serde(default)]
    pub verified_by: String, // "external", "participant", "admin", "calibration"
}

pub fn load_ledger(room_id: &str) -> Vec<CreditEntry> {
    let path = agora_dir().join("rooms").join(room_id).join("ledger.json");
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        Vec::new()
    }
}

pub fn save_ledger(room_id: &str, ledger: &[CreditEntry]) {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    let data = serde_json::to_string_pretty(ledger).unwrap();
    let _ = atomic_write(&dir.join("ledger.json"), &data);
}

/// Per-process mutex serialising all ledger mutations to prevent TOCTOU races.
fn ledger_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

pub fn credit_balance(room_id: &str, agent_id: &str) -> i64 {
    load_ledger(room_id)
        .iter()
        .filter(|e| e.agent_id == agent_id && (e.ledger.is_empty() || e.ledger == "credit"))
        .map(|e| e.amount)
        .sum()
}

pub fn trust_balance(room_id: &str, agent_id: &str) -> i64 {
    load_ledger(room_id)
        .iter()
        .filter(|e| e.agent_id == agent_id && e.ledger == "trust")
        .map(|e| e.amount)
        .sum()
}

pub fn credit_add(room_id: &str, agent_id: &str, amount: i64, reason: &str) {
    let _guard = ledger_lock().lock().unwrap();
    let mut ledger = load_ledger(room_id);
    ledger.push(CreditEntry {
        agent_id: agent_id.to_string(),
        amount,
        reason: reason.to_string(),
        ts: now(),
        ledger: "credit".to_string(),
        verified_by: "admin".to_string(),
    });
    save_ledger(room_id, &ledger);
}

pub fn trust_add(room_id: &str, agent_id: &str, amount: i64, reason: &str, verified_by: &str) {
    let mut ledger = load_ledger(room_id);
    ledger.push(CreditEntry {
        agent_id: agent_id.to_string(),
        amount,
        reason: reason.to_string(),
        ts: now(),
        ledger: "trust".to_string(),
        verified_by: verified_by.to_string(),
    });
    save_ledger(room_id, &ledger);
}

/// Atomically check-and-debit credits for `agent_id`.
///
/// `amount` must be positive — it is the number of credits to spend.
/// Returns the new balance on success, or `Err` if the agent has insufficient funds.
///
/// The check and the ledger append are performed under a per-process mutex so
/// concurrent sandbox-create requests cannot both see a passing balance and
/// then both deduct, driving the account negative (TOCTOU race).
pub fn atomic_credit_debit(
    room_id: &str,
    agent_id: &str,
    amount: i64,
    reason: &str,
) -> Result<i64, String> {
    assert!(amount > 0, "debit amount must be positive");
    let _guard = ledger_lock().lock().unwrap();
    let mut ledger = load_ledger(room_id);
    let balance: i64 = ledger
        .iter()
        .filter(|e| e.agent_id == agent_id && (e.ledger.is_empty() || e.ledger == "credit"))
        .map(|e| e.amount)
        .sum();
    if balance < amount {
        return Err(format!(
            "Insufficient credits: need {amount}, have {balance}"
        ));
    }
    ledger.push(CreditEntry {
        agent_id: agent_id.to_string(),
        amount: -amount,
        reason: reason.to_string(),
        ts: now(),
        ledger: "credit".to_string(),
        verified_by: "system".to_string(),
    });
    save_ledger(room_id, &ledger);
    Ok(balance - amount)
}

// ── Prediction Market ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bet {
    pub id: String,
    pub question: String,
    pub created_by: String,
    pub created_at: u64,
    pub status: String, // "open", "resolved_yes", "resolved_no", "cancelled"
    pub stakes_yes: Vec<(String, i64)>, // (agent_id, amount)
    pub stakes_no: Vec<(String, i64)>,
}

pub fn load_bets(room_id: &str) -> Vec<Bet> {
    let path = agora_dir().join("rooms").join(room_id).join("bets.json");
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        Vec::new()
    }
}

pub fn save_bets(room_id: &str, bets: &[Bet]) {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    let _ = fs::write(
        dir.join("bets.json"),
        serde_json::to_string_pretty(bets).unwrap(),
    );
}

// ── Capability Cards ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityCard {
    pub agent_id: String,
    pub capabilities: Vec<String>,
    pub available: bool,
    pub description: Option<String>,
    pub updated_at: u64,
}

pub fn save_card(card: &CapabilityCard) {
    let dir = agora_dir();
    ensure_dir(&dir);
    let data = serde_json::to_string_pretty(card).unwrap();
    let _ = fs::write(dir.join("card.json"), data);
}

pub fn load_card() -> Option<CapabilityCard> {
    let path = agora_dir().join("card.json");
    fs::read_to_string(&path)
        .ok()
        .and_then(|d| serde_json::from_str(&d).ok())
}

pub fn save_peer_card(room_id: &str, card: &CapabilityCard) {
    let dir = agora_dir().join("rooms").join(room_id).join("cards");
    ensure_dir(&dir);
    let data = serde_json::to_string_pretty(card).unwrap();
    let _ = fs::write(dir.join(format!("{}.json", card.agent_id)), data);
}

pub fn load_peer_cards(room_id: &str) -> Vec<CapabilityCard> {
    let dir = agora_dir().join("rooms").join(room_id).join("cards");
    if !dir.exists() {
        return Vec::new();
    }
    let mut cards = Vec::new();
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            if let Ok(data) = fs::read_to_string(entry.path()) {
                if let Ok(card) = serde_json::from_str::<CapabilityCard>(&data) {
                    cards.push(card);
                }
            }
        }
    }
    cards
}

// ── Task Queue ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub title: String,
    pub status: String, // open, claimed, done
    pub created_by: String,
    pub claimed_by: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
    pub notes: Option<String>,
    /// Shell command run against a submission to determine pass/fail (e.g. "cargo test")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acceptance_oracle: Option<String>,
    /// Credits automatically granted to the winning agent when oracle passes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reward_credits: Option<i64>,
    /// Trust points automatically granted to the winning agent when oracle passes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reward_trust: Option<i64>,
    /// Submitted branches: vec of (agent_id, branch_name)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub submissions: Vec<BountySubmission>,
    /// Unix timestamp after which the bounty auto-expires and credits are refunded
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// Crowdfunding contributors: vec of (agent_id, amount) pledged to this bounty
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contributors: Vec<(String, i64)>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BountySubmission {
    pub agent_id: String,
    pub branch: String,
    pub submitted_at: u64,
    /// None = not yet verified, Some(true/false) = oracle result
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oracle_passed: Option<bool>,
}

pub fn load_tasks(room_id: &str) -> Vec<Task> {
    let path = agora_dir().join("rooms").join(room_id).join("tasks.json");
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        Vec::new()
    }
}

pub fn save_tasks(room_id: &str, tasks: &[Task]) {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    let data = serde_json::to_string_pretty(tasks).unwrap();
    let _ = fs::write(dir.join("tasks.json"), data);
}

// ── Payments ───────────────────────────────────────────────────

/// Exchange rate: 10 credits per USD cent (i.e. 1000 credits = $1.00).
pub const CREDITS_PER_USD_CENT: i64 = 10;

/// Status of a payment transaction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PaymentStatus {
    Pending,
    Completed,
    Failed,
    Refunded,
}

/// Direction of a payment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PaymentKind {
    /// External USD → internal credits (fund-bounty / top-up)
    Deposit,
    /// Internal credits → external USD (withdrawal / payout request)
    Withdrawal,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PaymentProvider {
    Stripe,
    Solana,
    Manual,
}

fn default_payment_provider() -> PaymentProvider {
    PaymentProvider::Stripe
}

/// Immutable record of a real-money transaction. Stored in ~/.agora/payments.json.
/// Room-independent — payments are per-agent, not per-room.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentRecord {
    /// Our internal payment ID
    pub id: String,
    /// Agent who initiated the payment
    pub agent_id: String,
    pub kind: PaymentKind,
    pub status: PaymentStatus,
    #[serde(default = "default_payment_provider")]
    pub provider: PaymentProvider,
    /// Amount in USD cents (e.g. 1000 = $10.00)
    pub amount_cents: i64,
    /// Credits minted or burned (amount_cents * CREDITS_PER_USD_CENT)
    pub credits: i64,
    /// Platform fee in credits (10% of credits)
    pub fee_credits: i64,
    /// External payment reference (e.g. Stripe checkout session or Solana tx signature)
    pub stripe_id: Option<String>,
    /// Hosted checkout URL for pending flows
    pub checkout_url: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxAuditRecord {
    pub id: String,
    pub ts: u64,
    pub agent_id: String,
    #[serde(default)]
    pub room_id: Option<String>,
    pub action: String,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub command_hash: Option<String>,
    #[serde(default)]
    pub command_len: Option<usize>,
    pub outcome: String,
    #[serde(default)]
    pub detail: Option<String>,
}

pub fn load_payments() -> Vec<PaymentRecord> {
    let path = agora_dir().join("payments.json");
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        Vec::new()
    }
}

pub fn save_payments(payments: &[PaymentRecord]) {
    let dir = agora_dir();
    ensure_dir(&dir);
    let _ = fs::write(
        dir.join("payments.json"),
        serde_json::to_string_pretty(payments).unwrap(),
    );
}

pub fn find_payment_by_stripe_id(stripe_id: &str) -> Option<PaymentRecord> {
    load_payments()
        .into_iter()
        .find(|p| p.stripe_id.as_deref() == Some(stripe_id))
}

pub fn find_payment_by_reference(reference: &str) -> Option<PaymentRecord> {
    load_payments()
        .into_iter()
        .find(|p| p.stripe_id.as_deref() == Some(reference))
}

pub fn load_sandbox_audit() -> Vec<SandboxAuditRecord> {
    let path = agora_dir().join("sandbox_audit.jsonl");
    let Ok(data) = fs::read_to_string(path) else {
        return Vec::new();
    };
    data.lines()
        .filter_map(|line| serde_json::from_str::<SandboxAuditRecord>(line).ok())
        .collect()
}

pub fn append_sandbox_audit(record: &SandboxAuditRecord) {
    use std::io::Write;

    let dir = agora_dir();
    ensure_dir(&dir);
    let path = dir.join("sandbox_audit.jsonl");
    let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(path) else {
        return;
    };
    let Ok(line) = serde_json::to_string(record) else {
        return;
    };
    let _ = writeln!(file, "{line}");
}

// ── Calibration Seeds ──────────────────────────────────────────

/// A calibration seed: a self-verifiable puzzle for trust bootstrapping.
/// Cold-start agents solve these to earn their first work receipts without
/// prior vouches or completed tasks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationSeed {
    pub id: String,
    pub title: String,
    pub puzzle: String,
    /// SHA256 hex digest of the correct answer (trimmed, lowercase).
    pub answer_hash: String,
    pub difficulty: String,
    pub created_by: String,
    pub created_at: u64,
    pub solved_by: Vec<String>,
}

pub fn load_seeds(room_id: &str) -> Vec<CalibrationSeed> {
    let path = agora_dir()
        .join("rooms")
        .join(room_id)
        .join("calibration_seeds.json");
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        Vec::new()
    }
}

pub fn save_seeds(room_id: &str, seeds: &[CalibrationSeed]) {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    let data = serde_json::to_string_pretty(seeds).unwrap();
    let _ = fs::write(dir.join("calibration_seeds.json"), data);
}

// ── Work Receipts ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkReceipt {
    pub id: String,
    pub task_id: String,
    pub task_title: String,
    pub agent_id: String,
    #[serde(default = "default_receipt_status")]
    pub status: String,
    #[serde(default)]
    pub notes: Option<String>,
    pub task_hash: String,
    #[serde(default)]
    pub witness_ids: Vec<String>,
    pub created_at: u64,
    #[serde(default = "default_receipt_auth")]
    pub auth: String,
}

fn default_receipt_auth() -> String {
    "unsigned".to_string()
}

fn default_receipt_status() -> String {
    "done".to_string()
}

pub fn load_work_receipts(room_id: &str) -> Vec<WorkReceipt> {
    let path = agora_dir()
        .join("rooms")
        .join(room_id)
        .join("work_receipts.json");
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        Vec::new()
    }
}

pub fn save_work_receipts(room_id: &str, receipts: &[WorkReceipt]) {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    let data = serde_json::to_string_pretty(receipts).unwrap();
    let _ = fs::write(dir.join("work_receipts.json"), data);
}

pub fn upsert_work_receipt(room_id: &str, receipt: &WorkReceipt) {
    let mut receipts = load_work_receipts(room_id);
    if let Some(existing) = receipts.iter_mut().find(|r| r.id == receipt.id) {
        *existing = receipt.clone();
    } else {
        receipts.push(receipt.clone());
    }
    receipts.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    save_work_receipts(room_id, &receipts);
}

// ── Sandbox Leases ─────────────────────────────────────────────

/// Maximum duration an active lease can exist before being considered stale on recovery.
pub const MAX_LEASE_SECS: u64 = 3600; // 1 hour

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum LeaseStatus {
    Active,
    Closed,
}

/// Tracks credit authorization for a single sandbox session.
/// Persisted so crash recovery can detect and close stale leases.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxLease {
    pub id: String, // matches SandboxSession.id
    pub agent_id: String,
    pub max_cost_credits: i64,
    pub credits_per_minute: i64,
    pub started_at: u64, // unix timestamp
    pub status: LeaseStatus,
    #[serde(default)]
    pub actual_cost: Option<i64>, // set when closed
    #[serde(default)]
    pub closed_at: Option<u64>,
}

pub fn load_leases(room_id: &str) -> Vec<SandboxLease> {
    let path = agora_dir()
        .join("rooms")
        .join(room_id)
        .join("sandbox_leases.json");
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        Vec::new()
    }
}

pub fn save_leases(room_id: &str, leases: &[SandboxLease]) {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    let data = serde_json::to_string_pretty(leases).unwrap();
    let _ = fs::write(dir.join("sandbox_leases.json"), data);
}

/// Open a new lease. Returns Err if the agent already has an active lease in this room.
pub fn open_lease(room_id: &str, lease: SandboxLease) -> Result<(), String> {
    let mut leases = load_leases(room_id);
    if leases
        .iter()
        .any(|l| l.agent_id == lease.agent_id && l.status == LeaseStatus::Active)
    {
        return Err(format!(
            "Agent {} already has an active lease",
            lease.agent_id
        ));
    }
    leases.push(lease);
    save_leases(room_id, &leases);
    Ok(())
}

/// Close an existing lease with the actual cost incurred.
pub fn close_lease(room_id: &str, lease_id: &str, actual_cost: i64) {
    let mut leases = load_leases(room_id);
    if let Some(lease) = leases.iter_mut().find(|l| l.id == lease_id) {
        lease.status = LeaseStatus::Closed;
        lease.actual_cost = Some(actual_cost);
        lease.closed_at = Some(now());
    }
    save_leases(room_id, &leases);
}

/// On startup: scan all rooms for active leases older than MAX_LEASE_SECS and close them
/// at ceiling cost (penalizes ungraceful shutdown, prevents credit escrow leaks).
/// Returns the number of stale leases recovered.
pub fn recover_stale_leases(room_id: &str) -> Vec<SandboxLease> {
    let cutoff = now().saturating_sub(MAX_LEASE_SECS);
    let mut leases = load_leases(room_id);
    let mut recovered = Vec::new();
    for lease in leases.iter_mut() {
        if lease.status == LeaseStatus::Active && lease.started_at < cutoff {
            lease.status = LeaseStatus::Closed;
            lease.actual_cost = Some(lease.max_cost_credits); // charge ceiling
            lease.closed_at = Some(now());
            recovered.push(lease.clone());
        }
    }
    if !recovered.is_empty() {
        save_leases(room_id, &leases);
    }
    recovered
}

// ── Role Leases ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleLease {
    pub role: String,
    pub agent_id: String,
    pub lease_expires: u64,
    pub last_heartbeat: u64,
    #[serde(default)]
    pub context_summary: Option<String>,
    #[serde(default)]
    pub last_task_ids: Vec<String>,
    pub updated_at: u64,
}

pub fn load_role_leases(room_id: &str) -> Vec<RoleLease> {
    let path = agora_dir()
        .join("rooms")
        .join(room_id)
        .join("role_leases.json");
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        Vec::new()
    }
}

pub fn save_role_leases(room_id: &str, roles: &[RoleLease]) {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    let data = serde_json::to_string_pretty(roles).unwrap();
    let _ = fs::write(dir.join("role_leases.json"), data);
}

pub fn upsert_role_lease(room_id: &str, lease: &RoleLease) {
    let mut roles = load_role_leases(room_id);
    if let Some(existing) = roles.iter_mut().find(|r| r.role == lease.role) {
        *existing = lease.clone();
    } else {
        roles.push(lease.clone());
    }
    roles.sort_by(|a, b| a.role.cmp(&b.role));
    save_role_leases(room_id, &roles);
}

pub fn remove_role_lease(room_id: &str, role: &str) {
    let mut roles = load_role_leases(room_id);
    let before = roles.len();
    roles.retain(|r| r.role != role);
    if roles.len() != before {
        save_role_leases(room_id, &roles);
    }
}

pub fn get_role_lease(room_id: &str, role: &str) -> Option<RoleLease> {
    load_role_leases(room_id)
        .into_iter()
        .find(|lease| lease.role == role)
}

// ── Aliases ────────────────────────────────────────────────────
// Global agent aliases, stored at ~/.agora/aliases.json

pub fn load_aliases() -> std::collections::HashMap<String, String> {
    let path = agora_dir().join("aliases.json");
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        std::collections::HashMap::new()
    }
}

pub fn save_aliases(aliases: &std::collections::HashMap<String, String>) {
    let dir = agora_dir();
    ensure_dir(&dir);
    let data = serde_json::to_string_pretty(aliases).unwrap();
    let _ = fs::write(dir.join("aliases.json"), data);
}

pub fn set_alias(agent_id: &str, name: &str) {
    let mut aliases = load_aliases();
    aliases.insert(agent_id.to_string(), name.to_string());
    save_aliases(&aliases);
}

pub fn remove_alias(agent_id: &str) {
    let mut aliases = load_aliases();
    aliases.remove(agent_id);
    save_aliases(&aliases);
}

pub fn get_alias(agent_id: &str) -> Option<String> {
    load_aliases().get(agent_id).cloned()
}

// ── Webhooks ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Webhook {
    pub id: String,
    pub url: String,
    pub created_at: u64,
}

pub fn load_webhooks(room_id: &str) -> Vec<Webhook> {
    let path = agora_dir()
        .join("rooms")
        .join(room_id)
        .join("webhooks.json");
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        Vec::new()
    }
}

pub fn save_webhooks(room_id: &str, hooks: &[Webhook]) {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    let data = serde_json::to_string_pretty(hooks).unwrap();
    let _ = fs::write(dir.join("webhooks.json"), data);
}

pub fn add_webhook(room_id: &str, url: &str) -> String {
    let mut hooks = load_webhooks(room_id);
    let mut id_bytes = [0u8; 4];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut id_bytes).expect("RNG");
    let id = hex::encode(id_bytes);
    hooks.push(Webhook {
        id: id.clone(),
        url: url.to_string(),
        created_at: now(),
    });
    save_webhooks(room_id, &hooks);
    id
}

pub fn remove_webhook(room_id: &str, webhook_id: &str) -> bool {
    let mut hooks = load_webhooks(room_id);
    let before = hooks.len();
    hooks.retain(|h| h.id != webhook_id);
    if hooks.len() == before {
        return false;
    }
    save_webhooks(room_id, &hooks);
    true
}

// ── Scheduled Messages ─────────────────────────────────────────

pub fn load_scheduled(room_id: &str) -> Vec<serde_json::Value> {
    let path = agora_dir()
        .join("rooms")
        .join(room_id)
        .join("scheduled.json");
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        Vec::new()
    }
}

pub fn save_scheduled(room_id: &str, queue: &[serde_json::Value]) {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    let data = serde_json::to_string_pretty(queue).unwrap();
    let _ = fs::write(dir.join("scheduled.json"), data);
}

pub fn archive_path(room_id: &str) -> PathBuf {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    dir.join("archive.jsonl")
}

pub fn delete_messages_before(room_id: &str, before_ts: u64) {
    let dir = agora_dir().join("rooms").join(room_id).join("messages");
    if !dir.exists() {
        return;
    }
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let fname = entry.file_name().to_string_lossy().to_string();
            // Files are named: <ts>_<mid>.json
            if let Some(ts_str) = fname.split('_').next() {
                if let Ok(ts) = ts_str.parse::<u64>() {
                    if ts < before_ts {
                        let _ = fs::remove_file(entry.path());
                    }
                }
            }
        }
    }
}

// ── Seen Tracking ───────────────────────────────────────────────

pub fn load_seen(room_id: &str) -> HashSet<String> {
    let path = agora_dir().join("rooms").join(room_id).join("seen.txt");
    if let Ok(data) = fs::read_to_string(&path) {
        data.lines().map(|s| s.to_string()).collect()
    } else {
        HashSet::new()
    }
}

pub fn mark_seen(room_id: &str, msg_id: &str) {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    let path = dir.join("seen.txt");
    let mut seen = load_seen(room_id);
    seen.insert(msg_id.to_string());
    let mut ids: Vec<_> = seen.into_iter().collect();
    ids.sort();
    if ids.len() > 1000 {
        ids = ids[ids.len() - 1000..].to_vec();
    }
    let _ = fs::write(&path, ids.join("\n"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn test_home(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("agora-store-{name}-{}", std::process::id()))
    }

    #[test]
    fn update_last_seen_does_not_clobber_invalid_registry() {
        let _guard = test_env_lock().lock().unwrap();
        let home = test_home("invalid-registry");
        let agora = home.join(".agora");
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(&agora).unwrap();
        fs::write(agora.join("rooms.json"), "{not-json").unwrap();

        let old_home = env::var("HOME").ok();
        unsafe {
            env::set_var("HOME", &home);
        }

        update_last_seen("missing-room", "agent-1");

        let persisted = fs::read_to_string(agora.join("rooms.json")).unwrap();
        assert_eq!(persisted, "{not-json");

        if let Some(old) = old_home {
            unsafe {
                env::set_var("HOME", old);
            }
        } else {
            unsafe {
                env::remove_var("HOME");
            }
        }
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn save_registry_persists_valid_json() {
        let _guard = test_env_lock().lock().unwrap();
        let home = test_home("atomic-save");
        let agora = home.join(".agora");
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(&agora).unwrap();

        let old_home = env::var("HOME").ok();
        unsafe {
            env::set_var("HOME", &home);
        }

        let room = RoomEntry {
            room_id: "room-1".to_string(),
            secret: "secret".to_string(),
            label: "plaza".to_string(),
            joined_at: 1,
            topic: None,
            members: vec![],
        };
        save_registry(&[room]);

        let persisted = fs::read_to_string(agora.join("rooms.json")).unwrap();
        let parsed: Vec<RoomEntry> = serde_json::from_str(&persisted).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].label, "plaza");

        if let Some(old) = old_home {
            unsafe {
                env::set_var("HOME", old);
            }
        } else {
            unsafe {
                env::remove_var("HOME");
            }
        }
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn payment_record_round_trips() {
        let _guard = test_env_lock().lock().unwrap();
        let home = test_home("payment-rt");
        let agora = home.join(".agora");
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(&agora).unwrap();

        let old_home = env::var("HOME").ok();
        unsafe {
            env::set_var("HOME", &home);
        }

        let record = PaymentRecord {
            id: "pay-test-001".to_string(),
            agent_id: "agent-abc".to_string(),
            kind: PaymentKind::Deposit,
            status: PaymentStatus::Pending,
            provider: PaymentProvider::Stripe,
            amount_cents: 1000,
            credits: 10000,
            fee_credits: 1000,
            stripe_id: Some("cs_test_abc123".to_string()),
            checkout_url: Some("https://checkout.stripe.com/pay/cs_test".to_string()),
            created_at: 1700000000,
            updated_at: 1700000000,
        };

        save_payments(&[record.clone()]);
        let loaded = load_payments();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, "pay-test-001");
        assert_eq!(loaded[0].credits, 10000);
        assert_eq!(loaded[0].fee_credits, 1000);
        assert!(matches!(loaded[0].kind, PaymentKind::Deposit));
        assert!(matches!(loaded[0].status, PaymentStatus::Pending));

        // find_payment_by_stripe_id
        let found = find_payment_by_stripe_id("cs_test_abc123");
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, "pay-test-001");

        let not_found = find_payment_by_stripe_id("nonexistent");
        assert!(not_found.is_none());

        let found_by_reference = find_payment_by_reference("cs_test_abc123");
        assert!(found_by_reference.is_some());

        if let Some(old) = old_home {
            unsafe {
                env::set_var("HOME", old);
            }
        } else {
            unsafe {
                env::remove_var("HOME");
            }
        }
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn credits_per_usd_cent_constant_is_correct() {
        // 10 credits = $0.01 means 1000 credits = $1.00
        assert_eq!(CREDITS_PER_USD_CENT, 10);
        // $10 should give 10000 credits
        let dollars_in_cents = 1000i64;
        let credits = dollars_in_cents * CREDITS_PER_USD_CENT;
        assert_eq!(credits, 10000);
    }

    #[test]
    fn sandbox_audit_round_trips() {
        let _guard = test_env_lock().lock().unwrap();
        let home = test_home("sandbox-audit");
        let agora = home.join(".agora");
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(&agora).unwrap();

        let old_home = env::var("HOME").ok();
        unsafe {
            env::set_var("HOME", &home);
        }

        let record = SandboxAuditRecord {
            id: "audit-1".to_string(),
            ts: 1700000000,
            agent_id: "agent-abc".to_string(),
            room_id: Some("room-1".to_string()),
            action: "exec".to_string(),
            session_id: Some("session-1".to_string()),
            provider: Some("daytona".to_string()),
            command_hash: Some("deadbeef".to_string()),
            command_len: Some(12),
            outcome: "success".to_string(),
            detail: None,
        };

        append_sandbox_audit(&record);
        let loaded = load_sandbox_audit();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, "audit-1");
        assert_eq!(loaded[0].agent_id, "agent-abc");
        assert_eq!(loaded[0].room_id.as_deref(), Some("room-1"));
        assert_eq!(loaded[0].action, "exec");
        assert_eq!(loaded[0].command_len, Some(12));

        if let Some(old) = old_home {
            unsafe {
                env::set_var("HOME", old);
            }
        } else {
            unsafe {
                env::remove_var("HOME");
            }
        }
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn sandbox_lease_open_close_roundtrip() {
        let _guard = test_env_lock().lock().unwrap();
        let home = test_home("lease-roundtrip");
        let agora = home.join(".agora");
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(&agora).unwrap();
        let old_home = env::var("HOME").ok();
        unsafe {
            env::set_var("HOME", &home);
        }

        let lease = SandboxLease {
            id: "sandbox-1".to_string(),
            agent_id: "agent-1".to_string(),
            max_cost_credits: 100,
            credits_per_minute: 5,
            started_at: now(),
            status: LeaseStatus::Active,
            actual_cost: None,
            closed_at: None,
        };
        open_lease("room-1", lease).unwrap();
        close_lease("room-1", "sandbox-1", 42);

        let leases = load_leases("room-1");
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].status, LeaseStatus::Closed);
        assert_eq!(leases[0].actual_cost, Some(42));

        if let Some(old) = old_home {
            unsafe {
                env::set_var("HOME", old);
            }
        } else {
            unsafe {
                env::remove_var("HOME");
            }
        }
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn sandbox_lease_rejects_duplicate_active() {
        let _guard = test_env_lock().lock().unwrap();
        let home = test_home("lease-duplicate");
        let agora = home.join(".agora");
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(&agora).unwrap();
        let old_home = env::var("HOME").ok();
        unsafe {
            env::set_var("HOME", &home);
        }

        let lease = SandboxLease {
            id: "sandbox-1".to_string(),
            agent_id: "agent-1".to_string(),
            max_cost_credits: 100,
            credits_per_minute: 5,
            started_at: now(),
            status: LeaseStatus::Active,
            actual_cost: None,
            closed_at: None,
        };
        open_lease("room-1", lease.clone()).unwrap();
        let second = SandboxLease {
            id: "sandbox-2".to_string(),
            ..lease
        };
        assert!(open_lease("room-1", second).is_err());

        if let Some(old) = old_home {
            unsafe {
                env::set_var("HOME", old);
            }
        } else {
            unsafe {
                env::remove_var("HOME");
            }
        }
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn recover_stale_leases_charges_ceiling() {
        let _guard = test_env_lock().lock().unwrap();
        let home = test_home("lease-stale");
        let agora = home.join(".agora");
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(&agora).unwrap();
        let old_home = env::var("HOME").ok();
        unsafe {
            env::set_var("HOME", &home);
        }

        // A lease that started well beyond MAX_LEASE_SECS ago
        let stale_lease = SandboxLease {
            id: "stale-sandbox".to_string(),
            agent_id: "agent-crash".to_string(),
            max_cost_credits: 200,
            credits_per_minute: 10,
            started_at: now().saturating_sub(MAX_LEASE_SECS + 60),
            status: LeaseStatus::Active,
            actual_cost: None,
            closed_at: None,
        };
        // A fresh lease that should NOT be recovered
        let fresh_lease = SandboxLease {
            id: "fresh-sandbox".to_string(),
            agent_id: "agent-ok".to_string(),
            max_cost_credits: 50,
            credits_per_minute: 2,
            started_at: now(),
            status: LeaseStatus::Active,
            actual_cost: None,
            closed_at: None,
        };

        let mut leases = vec![stale_lease, fresh_lease];
        save_leases("room-1", &mut leases);

        let recovered = recover_stale_leases("room-1");
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].id, "stale-sandbox");
        assert_eq!(recovered[0].actual_cost, Some(200)); // charged ceiling

        let persisted = load_leases("room-1");
        // stale is closed, fresh is still active
        let stale = persisted.iter().find(|l| l.id == "stale-sandbox").unwrap();
        let fresh = persisted.iter().find(|l| l.id == "fresh-sandbox").unwrap();
        assert_eq!(stale.status, LeaseStatus::Closed);
        assert_eq!(fresh.status, LeaseStatus::Active);

        if let Some(old) = old_home {
            unsafe {
                env::set_var("HOME", old);
            }
        } else {
            unsafe {
                env::remove_var("HOME");
            }
        }
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn atomic_credit_debit_succeeds_with_sufficient_balance() {
        let _guard = test_env_lock().lock().unwrap();
        let home = test_home("debit-ok");
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(home.join(".agora")).unwrap();
        let old_home = env::var("HOME").ok();
        unsafe {
            env::set_var("HOME", &home);
        }

        credit_add("room-1", "agent-1", 50, "seed");
        let result = atomic_credit_debit("room-1", "agent-1", 10, "sandbox:open");
        assert_eq!(result, Ok(40));
        assert_eq!(credit_balance("room-1", "agent-1"), 40);

        if let Some(old) = old_home {
            unsafe {
                env::set_var("HOME", old);
            }
        } else {
            unsafe {
                env::remove_var("HOME");
            }
        }
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn atomic_credit_debit_rejects_insufficient_balance() {
        let _guard = test_env_lock().lock().unwrap();
        let home = test_home("debit-fail");
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(home.join(".agora")).unwrap();
        let old_home = env::var("HOME").ok();
        unsafe {
            env::set_var("HOME", &home);
        }

        credit_add("room-1", "agent-1", 5, "seed");
        let result = atomic_credit_debit("room-1", "agent-1", 10, "sandbox:open");
        assert!(result.is_err());
        // Balance must be unchanged after a failed debit
        assert_eq!(credit_balance("room-1", "agent-1"), 5);

        if let Some(old) = old_home {
            unsafe {
                env::set_var("HOME", old);
            }
        } else {
            unsafe {
                env::remove_var("HOME");
            }
        }
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn atomic_credit_debit_rejects_zero_balance() {
        let _guard = test_env_lock().lock().unwrap();
        let home = test_home("debit-zero");
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(home.join(".agora")).unwrap();
        let old_home = env::var("HOME").ok();
        unsafe {
            env::set_var("HOME", &home);
        }

        // No credits added — debit must fail
        let result = atomic_credit_debit("room-1", "agent-1", 1, "sandbox:open");
        assert!(result.is_err());
        assert_eq!(credit_balance("room-1", "agent-1"), 0);

        if let Some(old) = old_home {
            unsafe {
                env::set_var("HOME", old);
            }
        } else {
            unsafe {
                env::remove_var("HOME");
            }
        }
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn atomic_credit_debit_drains_to_zero() {
        let _guard = test_env_lock().lock().unwrap();
        let home = test_home("debit-drain");
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(home.join(".agora")).unwrap();
        let old_home = env::var("HOME").ok();
        unsafe {
            env::set_var("HOME", &home);
        }

        credit_add("room-1", "agent-1", 10, "seed");
        let result = atomic_credit_debit("room-1", "agent-1", 10, "sandbox:open");
        assert_eq!(result, Ok(0));
        // Next debit must fail
        let second = atomic_credit_debit("room-1", "agent-1", 1, "sandbox:open");
        assert!(second.is_err());

        if let Some(old) = old_home {
            unsafe {
                env::set_var("HOME", old);
            }
        } else {
            unsafe {
                env::remove_var("HOME");
            }
        }
        let _ = fs::remove_dir_all(&home);
    }
}
