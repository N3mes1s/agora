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
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use ring::rand::SecureRandom;

use crate::{crypto, store, transport};

const VERSION: &str = "3.0";
const BASE64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

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

fn is_system_msg(env: &serde_json::Value) -> bool {
    is_heartbeat(env) || is_receipt(env) || is_file_msg(env) || is_reaction(env)
}

/// Update last_seen for the sender of a message.
fn track_presence(room_id: &str, env: &serde_json::Value) {
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

// ── Encrypt / Decrypt ───────────────────────────────────────────

fn encrypt_envelope(env: &serde_json::Value, room_key: &[u8; 32], room_id: &str) -> String {
    let (enc_key, _) = crypto::derive_message_keys(room_key);
    let plaintext = serde_json::to_string(env).unwrap();
    let aad = room_id.as_bytes();
    let blob = crypto::encrypt(plaintext.as_bytes(), &enc_key, aad).expect("encrypt failed");
    BASE64.encode(&blob)
}

fn decrypt_payload(payload: &str, room_key: &[u8; 32], room_id: &str) -> Option<serde_json::Value> {
    let (enc_key, _) = crypto::derive_message_keys(room_key);
    let blob = BASE64.decode(payload).ok()?;
    let aad = room_id.as_bytes();
    let plaintext = crypto::decrypt(&blob, &enc_key, aad).ok()?;
    let raw = String::from_utf8(plaintext).ok()?;
    parse_envelope(&raw)
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
    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);

    let env = make_envelope(message, reply_to);
    let mid = env["id"].as_str().unwrap_or("?").to_string();
    let encrypted = encrypt_envelope(&env, &room_key, &room.room_id);

    transport::publish(&room.room_id, &encrypted);
    store::save_message(&room.room_id, &env);

    Ok(mid)
}

pub fn read(since: &str, limit: usize, room_label: Option<&str>) -> Result<Vec<serde_json::Value>, String> {
    let room = resolve_room(room_label)?;
    let room_key = crypto::derive_room_key(&room.secret, &room.room_id);

    // Fetch from relay
    let remote_events = transport::fetch(&room.room_id, since);
    let mut remote_msgs: Vec<serde_json::Value> = Vec::new();
    for (ts, payload) in &remote_events {
        if let Some(mut env) = decrypt_payload(payload, &room_key, &room.room_id) {
            if env["ts"].as_u64().unwrap_or(0) == 0 {
                env["ts"] = json!(ts);
            }
            remote_msgs.push(env);
        }
    }

    // Merge with local
    let since_secs = parse_since(since);
    let local_msgs = store::load_messages(&room.room_id, since_secs);

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
        // Only persist and display non-heartbeat messages
        if !is_heartbeat(&msg) {
            store::save_message(&room.room_id, &msg);
            merged.push(msg);
        }
    }

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

    let remote_events = transport::fetch(&room.room_id, since);
    let mut new_msgs = Vec::new();
    let mut read_ids = Vec::new();
    for (_, payload) in &remote_events {
        if let Some(env) = decrypt_payload(payload, &room_key, &room.room_id) {
            track_presence(&room.room_id, &env);
            let mid = env["id"].as_str().unwrap_or("?").to_string();
            let from = env["from"].as_str().unwrap_or("");
            if from == me || seen.contains(&mid) {
                continue;
            }
            store::mark_seen(&room.room_id, &mid);

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

    // Track last heartbeat time
    let mut last_heartbeat = now();
    // Send initial heartbeat
    let _ = send_watch_heartbeat(&room_id);

    transport::stream(&room_id, |_ts, payload| {
        if let Some(env) = decrypt_payload(payload, &room_key, &room_id) {
            track_presence(&room_id, &env);
            if !is_heartbeat(&env) {
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
    use super::{pin, pins, resolve_room, send_watch_heartbeat, unpin};
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

    #[test]
    fn resolve_room_reports_missing_explicit_target() {
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
    fn pin_and_unpin_round_trip() {
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

    transport::stream(&room_id, |_ts, payload| {
        if let Some(env) = decrypt_payload(payload, &room_key, &room_id) {
            track_presence(&room_id, &env);
            let from = env["from"].as_str().unwrap_or("");
            // Skip own messages and heartbeats
            if from == me || is_heartbeat(&env) {
                return;
            }
            store::save_message(&room_id, &env);
            store::set_notify_flag(&room_id, &env);
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
