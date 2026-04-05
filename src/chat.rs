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
use std::collections::HashSet;
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
        store::save_message(&room.room_id, &msg);
        merged.push(msg);
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
            let mid = env["id"].as_str().unwrap_or("?").to_string();
            let from = env["from"].as_str().unwrap_or("");
            if from == me || seen.contains(&mid) {
                continue;
            }
            store::mark_seen(&room.room_id, &mid);
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

pub fn who(room_label: Option<&str>) -> Result<Vec<store::RoomMember>, String> {
    let room = resolve_room(room_label)?;
    Ok(room.members)
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
