//! Shared helpers for the channel push tests: agents on one HOME and one
//! in-memory relay, like windows on a host.
#![allow(dead_code)]

use agora::channel::{Outcome, Pusher};
use agora::{chat, crypto, runtime, store, transport};
use serde_json::Value;
use std::cell::RefCell;
use std::path::PathBuf;

pub fn temp_home(tag: &str) -> PathBuf {
    let home = std::env::temp_dir().join(format!(
        "agora-channel-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&home).unwrap();
    home
}

/// All agents share one HOME and one in-memory relay, like windows on a host.
pub fn as_agent(home: &PathBuf, agent: &str, now: u64) -> runtime::TestRuntimeGuard {
    runtime::TestRuntime::new()
        .home(home)
        .var("AGORA_CONFIG", "/nonexistent/agora-test-config.toml")
        .var("AGORA_RELAY_URL", format!("memory://{}", home.display()))
        .unset_var("AGORA_IDENTITY_SEED")
        .var("AGORA_AGENT_ID", agent)
        .now(now)
        .advance_sleep()
        .enter()
}

pub const A: &str = "agent-a";
pub const B: &str = "agent-b";
pub const C: &str = "agent-c";
pub const DM_AB: &str = "dm-agent-a-agent-b";

pub fn setup(home: &PathBuf) {
    let _rt = as_agent(home, A, 900);
    chat::create_silent("ops").unwrap();
    chat::create_silent(DM_AB).unwrap();
    chat::create_silent("dm-agent-b-agent-c").unwrap();
}

pub fn send_as(home: &PathBuf, agent: &str, now: u64, room: &str, text: &str) -> String {
    let _rt = as_agent(home, agent, now);
    chat::send(text, None, Some(room)).unwrap()
}

/// Run every relay message of `label` through `pusher` as agent `me`.
pub fn pass(home: &PathBuf, pusher: &Pusher, now: u64, label: &str) -> (Vec<Value>, Vec<Outcome>) {
    let _rt = as_agent(home, pusher.agent(), now);
    let room = store::find_room(label).unwrap();
    let key = crypto::derive_room_key(&room.secret, &room.room_id);
    let emitted = RefCell::new(Vec::new());
    let mut outcomes = Vec::new();
    for (ts, payload) in transport::fetch_checked(&room.room_id, "0").unwrap() {
        let emit = |v: &Value| emitted.borrow_mut().push(v.clone());
        if let Some(o) = pusher.handle_payload(&room, &key, ts, &payload, &emit) {
            outcomes.push(o);
        }
    }
    (emitted.into_inner(), outcomes)
}

pub fn pushed(outcomes: &[Outcome]) -> usize {
    outcomes.iter().filter(|o| **o == Outcome::Pushed).count()
}

/// Decrypted envelopes of `label`, as `agora check` would hand them over.
pub fn envelopes(home: &PathBuf, agent: &str, now: u64, label: &str) -> Vec<Value> {
    let _rt = as_agent(home, agent, now);
    let room = store::find_room(label).unwrap();
    chat::fetch_room_events(&room, "0").unwrap()
}
