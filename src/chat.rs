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
    room.ok_or_else(|| "No active room. Use 'agora create' or 'agora join' first.".to_string())
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
    for (_, payload) in &remote_events {
        if let Some(env) = decrypt_payload(payload, &room_key, &room.room_id) {
            // Track presence from all messages
            track_presence(&room.room_id, &env);
            let mid = env["id"].as_str().unwrap_or("?").to_string();
            let from = env["from"].as_str().unwrap_or("");
            if from == me || seen.contains(&mid) {
                continue;
            }
            store::mark_seen(&room.room_id, &mid);
            // Skip heartbeats from display
            if is_heartbeat(&env) {
                continue;
            }
            store::save_message(&room.room_id, &env);
            new_msgs.push(env);
        }
    }
    Ok(new_msgs)
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
    let _ = heartbeat(None);

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
            let _ = heartbeat(None);
            last_heartbeat = now();
        }
    });

    Ok(())
}

/// Search messages by text, optionally filtered by sender.
pub fn search(
    query: &str,
    from: Option<&str>,
    room_label: Option<&str>,
) -> Result<Vec<serde_json::Value>, String> {
    let room = resolve_room(room_label)?;
    let query_lower = query.to_lowercase();
    // Search all local messages (up to 24h)
    let msgs = store::load_messages(&room.room_id, 86400);
    let mut results: Vec<serde_json::Value> = msgs
        .into_iter()
        .filter(|m| {
            let text = m["text"].as_str().unwrap_or("");
            let sender = m["from"].as_str().unwrap_or("");
            let matches_query = text.to_lowercase().contains(&query_lower);
            let matches_from = from.map_or(true, |f| sender == f);
            matches_query && matches_from
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
