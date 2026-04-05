//! Agora local message store.
//!
//! Persistence at ~/.agora/:
//!   rooms/<room_id>/messages/ — message files
//!   rooms/<room_id>/seen.txt  — seen message IDs
//!   rooms.json                — room registry
//!   identity.json             — agent identity

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Process-wide mutex for tests that mutate env vars (AGORA_DIR / AGORA_AGENT_ID).
/// Exported so sibling test modules can share the same lock.
#[cfg(test)]
pub static TEST_ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn agora_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("AGORA_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
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

pub fn get_agent_id() -> String {
    // Env override — lets multiple runtimes on the same machine have distinct IDs.
    if let Ok(id) = std::env::var("AGORA_AGENT_ID") {
        if !id.is_empty() {
            return id;
        }
    }

    let id_file = agora_dir().join("identity.json");
    if let Ok(data) = fs::read_to_string(&id_file) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&data) {
            if let Some(id) = v["agent_id"].as_str() {
                return id.to_string();
            }
        }
    }

    // Derive from env or generate
    let agent_id = if let Ok(sid) = std::env::var("CLAUDE_CODE_SESSION_ID") {
        if sid.starts_with("cse_") {
            sid[4..12.min(sid.len())].to_string()
        } else {
            sid[..8.min(sid.len())].to_string()
        }
    } else {
        let rng = ring::rand::SystemRandom::new();
        let mut buf = [0u8; 4];
        ring::rand::SecureRandom::fill(&rng, &mut buf).expect("RNG failed");
        hex::encode(buf)
    };

    let dir = agora_dir();
    ensure_dir(&dir);
    let json = serde_json::json!({"agent_id": agent_id});
    let _ = fs::write(&id_file, serde_json::to_string_pretty(&json).unwrap());
    agent_id
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

pub fn save_registry(rooms: &[RoomEntry]) {
    let dir = agora_dir();
    ensure_dir(&dir);
    let data = serde_json::to_string_pretty(rooms).unwrap();
    let _ = fs::write(dir.join("rooms.json"), data);
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
    if let Some(r) = rooms.iter_mut().find(|r| r.room_id == room.room_id) {
        *r = room.clone();
    }
    save_registry(&rooms);
}

pub fn remove_member_from_room(room_id: &str, agent_id: &str) {
    let mut rooms = load_registry();
    if let Some(room) = rooms.iter_mut().find(|r| r.room_id == room_id) {
        room.members.retain(|m| m.agent_id != agent_id);
    }
    save_registry(&rooms);
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
    if let Some(room) = rooms.iter_mut().find(|r| r.room_id == room_id) {
        if let Some(member) = room.members.iter_mut().find(|m| m.agent_id == agent_id) {
            member.last_seen = now();
        } else {
            // First time seeing this agent — add as member
            room.members.push(RoomMember {
                agent_id: agent_id.to_string(),
                role: Role::Member,
                joined_at: now(),
                nickname: None,
                last_seen: now(),
            });
        }
    }
    save_registry(&rooms);
}

pub fn set_member_role(room_id: &str, agent_id: &str, role: Role) {
    let mut rooms = load_registry();
    if let Some(room) = rooms.iter_mut().find(|r| r.room_id == room_id) {
        if let Some(member) = room.members.iter_mut().find(|m| m.agent_id == agent_id) {
            member.role = role;
        }
    }
    save_registry(&rooms);
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

// ── Delivery Receipts ───────────────────────────────────────────

fn receipts_path(room_id: &str) -> PathBuf {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    dir.join("receipts.json")
}

fn receipted_path(room_id: &str) -> PathBuf {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    dir.join("receipted.txt")
}

/// Load all receipts for a room: map of msg_id -> [(from, ts), ...]
pub fn load_all_receipts(room_id: &str) -> HashMap<String, Vec<(String, u64)>> {
    let path = receipts_path(room_id);
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        HashMap::new()
    }
}

/// Load receipts for a specific message.
pub fn load_receipts(room_id: &str, msg_id: &str) -> Vec<(String, u64)> {
    load_all_receipts(room_id)
        .remove(msg_id)
        .unwrap_or_default()
}

/// Save a receipt (another agent acknowledged receipt of msg_id).
pub fn save_receipt(room_id: &str, receipt_for: &str, from: &str, ts: u64) {
    let path = receipts_path(room_id);
    let mut all = load_all_receipts(room_id);
    let entry = all.entry(receipt_for.to_string()).or_default();
    // Avoid duplicates
    if !entry.iter().any(|(f, _)| f == from) {
        entry.push((from.to_string(), ts));
    }
    let _ = fs::write(&path, serde_json::to_string(&all).unwrap());
}

/// Check if we've already sent a receipt for this message.
pub fn is_receipted(room_id: &str, msg_id: &str) -> bool {
    let path = receipted_path(room_id);
    if let Ok(data) = fs::read_to_string(&path) {
        data.lines().any(|l| l == msg_id)
    } else {
        false
    }
}

/// Mark that we've sent a receipt for this message.
pub fn mark_receipted(room_id: &str, msg_id: &str) {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    let path = receipted_path(room_id);
    let mut ids: Vec<String> = if let Ok(data) = fs::read_to_string(&path) {
        data.lines().map(|s| s.to_string()).collect()
    } else {
        vec![]
    };
    if !ids.iter().any(|id| id == msg_id) {
        ids.push(msg_id.to_string());
        if ids.len() > 1000 {
            ids = ids[ids.len() - 1000..].to_vec();
        }
        let _ = fs::write(&path, ids.join("\n"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn isolated_dir() -> (PathBuf, std::sync::MutexGuard<'static, ()>) {
        let guard = super::TEST_ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let tid = std::thread::current().id();
        let dir = std::env::temp_dir().join(format!("agora-store-test-{ts}-{tid:?}"));
        std::fs::create_dir_all(&dir).unwrap();
        unsafe { std::env::set_var("AGORA_DIR", &dir); }
        (dir, guard)
    }

    #[test]
    fn receipt_save_and_load() {
        let (_dir, _guard) = isolated_dir();
        let room = "ag-test-room";

        save_receipt(room, "msg1", "agent-a", 1000);
        save_receipt(room, "msg1", "agent-b", 1001);

        let receipts = load_receipts(room, "msg1");
        assert_eq!(receipts.len(), 2);
        let agents: Vec<&str> = receipts.iter().map(|(f, _)| f.as_str()).collect();
        assert!(agents.contains(&"agent-a"));
        assert!(agents.contains(&"agent-b"));
    }

    #[test]
    fn receipt_deduplicates_same_agent() {
        let (_dir, _guard) = isolated_dir();
        let room = "ag-dedup-room";

        save_receipt(room, "msg2", "agent-a", 1000);
        save_receipt(room, "msg2", "agent-a", 1005); // second call should not add a duplicate

        let receipts = load_receipts(room, "msg2");
        assert_eq!(receipts.len(), 1);
    }

    #[test]
    fn is_receipted_and_mark_receipted() {
        let (_dir, _guard) = isolated_dir();
        let room = "ag-mark-room";

        assert!(!is_receipted(room, "msg3"));
        mark_receipted(room, "msg3");
        assert!(is_receipted(room, "msg3"));
        // Idempotent
        mark_receipted(room, "msg3");
        assert!(is_receipted(room, "msg3"));
    }

    #[test]
    fn receipts_isolated_per_message() {
        let (_dir, _guard) = isolated_dir();
        let room = "ag-isolated-room";

        save_receipt(room, "msgA", "agent-x", 200);
        assert!(load_receipts(room, "msgB").is_empty());
    }
}
