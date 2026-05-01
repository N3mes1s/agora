use agora::{api, runtime};
use serde_json::json;

#[test]
fn stable_embedder_facade_round_trips_signed_payloads() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let home = std::env::temp_dir().join(format!("agora-lib-test-{}", unique));
    let topic = format!("ag-lib-room-{unique}");
    std::fs::create_dir_all(&home).unwrap();
    let _runtime = runtime::TestRuntime::new()
        .home(&home)
        .var("AGORA_AGENT_ID", "lib-agent")
        .enter();

    let _: fn(&str, &str) -> Result<(), api::PublishError> = api::publish;
    let _: fn(&str, &str) -> bool = api::publish_ok;
    let _: fn(&str, &str) -> Vec<(u64, String)> = api::fetch;
    let _: fn(&str) -> Result<Vec<u8>, String> = api::signing_keypair;
    let _: fn(&str) -> Option<String> = api::trusted_signing_key;
    let _: fn(&str, &str) -> api::RoomKey = api::derive_room_key;
    let _: fn() -> api::PublishLimits = api::publish_limits;

    assert_eq!(api::agent_id(), "lib-agent");
    assert_eq!(api::publish(&topic, "payload-1"), Ok(()));
    assert!(api::publish_ok(&topic, "payload-2"));
    assert_eq!(api::fetch(&topic, "1h").len(), 2);

    let room_key = api::derive_room_key("secret", &topic);
    let env = json!({
        "v": "3.0",
        "id": "m1",
        "from": "lib-agent",
        "ts": 42,
        "text": "hello",
    });

    let payload = api::encrypt_envelope(&env, &room_key, &topic);
    let decrypted = api::decrypt_signed_payload(&payload, &room_key, &topic)
        .expect("signed payload should decrypt");

    assert_eq!(decrypted["id"].as_str(), Some("m1"));
    assert_eq!(decrypted["from"].as_str(), Some("lib-agent"));
    assert_eq!(decrypted["text"].as_str(), Some("hello"));
    assert_eq!(decrypted["_auth"].as_str(), Some("verified"));
    assert!(api::trusted_signing_key("lib-agent").is_some());
}
