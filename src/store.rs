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
#[cfg(test)]
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
        let seed_bytes: [u8; 32] = derived.as_ref()[..32].try_into().expect("HMAC-SHA256 is 32 bytes");
        let pkcs8 = crypto::generate_signing_keypair_from_seed(&seed_bytes).expect("keygen from seed");
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
    let dir = agora_dir()
        .join("rooms")
        .join(room_id)
        .join("messages");
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
    if !dir.exists() { return; }
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
    let dir = agora_dir()
        .join("rooms")
        .join(room_id)
        .join("messages");
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
    let path = agora_dir().join("rooms").join(room_id).join("profiles.json");
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
    load_profiles(room_id).into_iter().find(|p| p.agent_id == agent_id)
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
    let path = agora_dir().join("rooms").join(room_id).join("receipts.json");
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
    let path = agora_dir().join("rooms").join(room_id).join("reactions.json");
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        std::collections::HashMap::new()
    }
}

pub fn save_reactions(room_id: &str, reactions: &std::collections::HashMap<String, Vec<(String, String)>>) {
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
    if let Ok(data) = fs::read_to_string(&path) { serde_json::from_str(&data).unwrap_or_default() }
    else { Vec::new() }
}

pub fn save_ledger(room_id: &str, ledger: &[CreditEntry]) {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    let _ = fs::write(dir.join("ledger.json"), serde_json::to_string_pretty(ledger).unwrap());
}

pub fn credit_balance(room_id: &str, agent_id: &str) -> i64 {
    load_ledger(room_id).iter()
        .filter(|e| e.agent_id == agent_id && (e.ledger.is_empty() || e.ledger == "credit"))
        .map(|e| e.amount).sum()
}

pub fn trust_balance(room_id: &str, agent_id: &str) -> i64 {
    load_ledger(room_id).iter()
        .filter(|e| e.agent_id == agent_id && e.ledger == "trust")
        .map(|e| e.amount).sum()
}

pub fn credit_add(room_id: &str, agent_id: &str, amount: i64, reason: &str) {
    let mut ledger = load_ledger(room_id);
    ledger.push(CreditEntry {
        agent_id: agent_id.to_string(), amount, reason: reason.to_string(),
        ts: now(), ledger: "credit".to_string(), verified_by: "admin".to_string(),
    });
    save_ledger(room_id, &ledger);
}

pub fn trust_add(room_id: &str, agent_id: &str, amount: i64, reason: &str, verified_by: &str) {
    let mut ledger = load_ledger(room_id);
    ledger.push(CreditEntry {
        agent_id: agent_id.to_string(), amount, reason: reason.to_string(),
        ts: now(), ledger: "trust".to_string(), verified_by: verified_by.to_string(),
    });
    save_ledger(room_id, &ledger);
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
    if let Ok(data) = fs::read_to_string(&path) { serde_json::from_str(&data).unwrap_or_default() }
    else { Vec::new() }
}

pub fn save_bets(room_id: &str, bets: &[Bet]) {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    let _ = fs::write(dir.join("bets.json"), serde_json::to_string_pretty(bets).unwrap());
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
    fs::read_to_string(&path).ok().and_then(|d| serde_json::from_str(&d).ok())
}

pub fn save_peer_card(room_id: &str, card: &CapabilityCard) {
    let dir = agora_dir().join("rooms").join(room_id).join("cards");
    ensure_dir(&dir);
    let data = serde_json::to_string_pretty(card).unwrap();
    let _ = fs::write(dir.join(format!("{}.json", card.agent_id)), data);
}

pub fn load_peer_cards(room_id: &str) -> Vec<CapabilityCard> {
    let dir = agora_dir().join("rooms").join(room_id).join("cards");
    if !dir.exists() { return Vec::new(); }
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

// ── Role Leases ────────────────────────────────────────────────

/// Specialist agent role lease. Stored globally (not per-room) in ~/.agora/roles.json.
/// A role is held by at most one agent at a time; ownership expires after `lease_expires`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleLease {
    /// Role name, e.g. "backend", "security", "devops"
    pub role: String,
    /// Agent ID currently holding the lease
    pub agent_id: String,
    /// Unix timestamp when the lease expires (default: claim_time + 3600s)
    pub lease_expires: u64,
    /// Unix timestamp of last heartbeat
    pub last_heartbeat: u64,
    /// Free-text summary of what the agent is working on
    pub context_summary: Option<String>,
}

pub fn load_roles() -> Vec<RoleLease> {
    let path = agora_dir().join("roles.json");
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        Vec::new()
    }
}

pub fn save_roles(roles: &[RoleLease]) {
    let dir = agora_dir();
    ensure_dir(&dir);
    let data = serde_json::to_string_pretty(roles).unwrap();
    let _ = fs::write(dir.join("roles.json"), data);
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
    let path = agora_dir().join("rooms").join(room_id).join("calibration_seeds.json");
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
    let path = agora_dir().join("rooms").join(room_id).join("work_receipts.json");
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
    let path = agora_dir().join("rooms").join(room_id).join("webhooks.json");
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
    if hooks.len() == before { return false; }
    save_webhooks(room_id, &hooks);
    true
}

// ── Scheduled Messages ─────────────────────────────────────────

pub fn load_scheduled(room_id: &str) -> Vec<serde_json::Value> {
    let path = agora_dir().join("rooms").join(room_id).join("scheduled.json");
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
        unsafe { env::set_var("HOME", &home); }

        update_last_seen("missing-room", "agent-1");

        let persisted = fs::read_to_string(agora.join("rooms.json")).unwrap();
        assert_eq!(persisted, "{not-json");

        if let Some(old) = old_home {
            unsafe { env::set_var("HOME", old); }
        } else {
            unsafe { env::remove_var("HOME"); }
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
        unsafe { env::set_var("HOME", &home); }

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
            unsafe { env::set_var("HOME", old); }
        } else {
            unsafe { env::remove_var("HOME"); }
        }
        let _ = fs::remove_dir_all(&home);
    }
}
