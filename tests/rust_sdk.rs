use agora::{AgoraClient, AgoraConfig, sdk::StreamConfig};
use serde::{Deserialize, Serialize};

fn temp_home(name: &str) -> std::path::PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("agora-rust-sdk-{name}-{unique}"))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AppFrame {
    kind: String,
    id: String,
    body: String,
}

#[test]
fn rust_sdk_embeds_custom_json_over_room_messages() {
    let home = temp_home("embed");
    std::fs::create_dir_all(&home).unwrap();
    let client = AgoraClient::with_config(
        AgoraConfig::new()
            .home(&home)
            .agent_id("sdk-agent")
            .relay_url("memory://rust-sdk-embed"),
    );

    assert_eq!(client.agent_id(), "sdk-agent");
    let session = client.create_room("embed-room").unwrap();
    assert_eq!(session.label(), "embed-room");
    assert_eq!(session.agent_id(), "sdk-agent");
    assert!(!session.fingerprint().is_empty());

    let frame = AppFrame {
        kind: "req".to_string(),
        id: "frame-1".to_string(),
        body: "payload".to_string(),
    };
    let message_id = session.send_json(&frame).unwrap();

    let opened = client.open_room("embed-room").unwrap();
    assert_eq!(opened.room_id(), session.room_id());

    let messages = opened.fetch_messages("1h");
    let found = messages
        .iter()
        .find(|message| message.id == message_id)
        .expect("sent frame should round trip");

    assert_eq!(found.sender, "sdk-agent");
    assert_eq!(found.auth.as_deref(), Some("verified"));
    assert_eq!(found.text_json::<AppFrame>().unwrap(), frame);

    let frames = opened.fetch_json::<AppFrame>("1h");
    let found_frame = frames
        .iter()
        .find(|event| event.message.id == message_id)
        .expect("sent JSON frame should parse");
    assert_eq!(found_frame.value, frame);
}

#[test]
fn rust_sdk_streams_decrypted_envelopes_without_polling() {
    let home = temp_home("stream");
    std::fs::create_dir_all(&home).unwrap();
    let client = AgoraClient::with_config(
        AgoraConfig::new()
            .home(&home)
            .agent_id("stream-agent")
            .relay_url("memory://rust-sdk-stream"),
    );
    let session = client.create_room("stream-room").unwrap();
    let message_id = session.send_text("stream me").unwrap();

    let mut seen = Vec::new();
    session.stream_envelopes(
        &StreamConfig::default(),
        |_ts, env| {
            if env["id"].as_str() == Some(message_id.as_str()) {
                seen.push(env);
            }
        },
        |_reason, _next_backoff| {},
    );

    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0]["text"].as_str(), Some("stream me"));
    assert_eq!(seen[0]["_auth"].as_str(), Some("verified"));
}

#[test]
fn rust_sdk_client_config_is_scoped_per_client() {
    let home_a = temp_home("a");
    let home_b = temp_home("b");
    std::fs::create_dir_all(&home_a).unwrap();
    std::fs::create_dir_all(&home_b).unwrap();

    let client_a = AgoraClient::with_config(AgoraConfig::new().home(&home_a).agent_id("agent-a"));
    let client_b = AgoraClient::with_config(AgoraConfig::new().home(&home_b).agent_id("agent-b"));

    assert_eq!(client_a.agent_id(), "agent-a");
    assert_eq!(client_b.agent_id(), "agent-b");
    assert!(client_a.rooms().is_empty());
    assert!(client_b.rooms().is_empty());
}

#[test]
fn rust_sdk_init_identity_materializes_persistent_identity() {
    let home = temp_home("init-identity");
    std::fs::create_dir_all(&home).unwrap();
    // No explicit agent_id — force the SDK to derive one from the seed and
    // write the identity file on first use. init_identity must trigger that.
    let client = AgoraClient::with_config(
        AgoraConfig::new()
            .home(&home)
            .identity_seed("rfd-0029-init-identity-seed")
            .relay_url("memory://rust-sdk-init-identity"),
    );

    assert!(
        !home.join(".agora/identity.json").exists(),
        "fixture precondition: identity not yet written"
    );
    let from_init = client.init_identity();
    let from_getter = client.agent_id();
    assert!(!from_init.is_empty());
    assert_eq!(from_init, from_getter);
    assert!(
        home.join(".agora/identity.json").exists(),
        "init_identity must materialize the identity file"
    );
}

#[test]
fn rust_sdk_create_room_silent_skips_presence_message() {
    let home = temp_home("create-room-silent");
    std::fs::create_dir_all(&home).unwrap();
    let client = AgoraClient::with_config(
        AgoraConfig::new()
            .home(&home)
            .agent_id("silent-admin")
            .relay_url("memory://rust-sdk-create-room-silent"),
    );

    let silent = client.create_room_silent("silent-room").unwrap();
    assert_eq!(silent.label(), "silent-room");
    assert_eq!(silent.agent_id(), "silent-admin");
    assert!(silent.room_id().starts_with("ag-"));
    assert!(!silent.secret().is_empty());

    // The room must contain no envelopes from this admin — create_room_silent
    // did not publish the "Room created..." presence message.
    let from_admin = silent
        .fetch_messages("1h")
        .into_iter()
        .filter(|message| message.sender == "silent-admin")
        .count();
    assert_eq!(
        from_admin, 0,
        "create_room_silent must not publish a presence envelope"
    );

    // For comparison, create_room SHOULD publish a presence envelope into the
    // same memory bus (same home, different room).
    let loud = client.create_room("loud-room").unwrap();
    let from_admin_loud = loud
        .fetch_messages("1h")
        .into_iter()
        .filter(|message| message.sender == "silent-admin")
        .count();
    assert!(
        from_admin_loud >= 1,
        "create_room (non-silent) should publish at least one presence envelope"
    );
}
