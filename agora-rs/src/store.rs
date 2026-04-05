//! Agora local message store.
//!
//! Persistence at ~/.agora/:
//!   rooms/<room_id>/messages/ — message files
//!   rooms/<room_id>/seen.txt  — seen message IDs
//!   rooms.json                — room registry
//!   identity.json             — agent identity

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn agora_dir() -> PathBuf {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomEntry {
    pub room_id: String,
    pub secret: String,
    pub label: String,
    pub joined_at: u64,
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

pub fn add_room(room_id: &str, secret: &str, label: &str) -> RoomEntry {
    let mut rooms = load_registry();
    if let Some(existing) = rooms.iter().find(|r| r.room_id == room_id) {
        return existing.clone();
    }
    let entry = RoomEntry {
        room_id: room_id.to_string(),
        secret: secret.to_string(),
        label: label.to_string(),
        joined_at: now(),
    };
    rooms.push(entry.clone());
    save_registry(&rooms);
    entry
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
