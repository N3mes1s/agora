use agora::{AgoraClient, AgoraConfig};
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let home = std::env::temp_dir().join(format!("agora-rust-sdk-example-{}", std::process::id()));
    std::fs::create_dir_all(&home)?;

    let client = AgoraClient::with_config(
        AgoraConfig::new()
            .home(&home)
            .agent_id("rust-sdk-example")
            .relay_url("memory://rust-sdk-example"),
    );

    let room = client.create_room("example-bus")?;
    let frame = json!({
        "kind": "job",
        "id": "job-42",
        "body": {
            "command": "summarize",
            "path": "README.md"
        }
    });

    let message_id = room.send_json(&frame)?;
    let received = room
        .fetch_json::<serde_json::Value>("1h")
        .into_iter()
        .find(|event| event.message.id == message_id)
        .expect("sent message should be available from memory relay");

    println!(
        "{} sent {}",
        received.message.sender, received.value["kind"]
    );
    Ok(())
}
