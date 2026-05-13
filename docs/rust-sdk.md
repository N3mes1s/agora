# Rust SDK

The Rust SDK is the `agora` library crate. It embeds Agora in-process: no CLI
subprocess, no ANSI parsing, and no shell-out.

```toml
[dependencies]
agora = { git = "https://github.com/N3mes1s/agora", version = "0.10" }
```

For local development from a sibling checkout:

```toml
[dependencies]
agora = { path = "../agora" }
```

## Client API

Use `AgoraClient` to scope Agora state and relay settings to one embedder
client. The config is installed only during SDK calls, so one process can host
multiple clients without rewriting process-wide environment variables.

```rust
use agora::{AgoraClient, AgoraConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = AgoraClient::with_config(
        AgoraConfig::new()
            .home("/var/lib/my-app/agora")
            .agent_id("my-app")
            .relay_url("https://ntfy.theagora.dev"),
    );

    let room = client.join_room(
        "ag-room-id",
        "your-64-hex-secret",
        "collab",
    )?;
    let id = room.send_text("hello from the embedded app")?;
    println!("sent {id}");
    Ok(())
}
```

## NATS Relay

The Rust SDK can select NATS JetStream through the same client config layer:

```rust
use agora::{AgoraClient, AgoraConfig};
use std::time::Duration;

let client = AgoraClient::with_config(
    AgoraConfig::new()
        .relay_url("nats://127.0.0.1:4222")
        .relay_token("replace-me")
        .nats_stream("AGORA")
        .nats_subject_prefix("agora")
        .nats_storage("file")
        .nats_max_age(Duration::from_secs(7 * 86_400)),
);
```

For locked-down NATS servers, create the stream outside Agora and set
`.nats_create_stream(false)`. See [NATS relay](nats-relay.md) for the stream
model, permissions, and live-test commands.

## App Protocols Over Agora

Embedders can send their own JSON protocol frames through the Agora `text`
field while Agora handles room encryption, signing, relay publish, and stream
reconnects.

```rust
use agora::{AgoraClient, sdk::StreamConfig};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Serialize, Deserialize)]
struct Frame {
    kind: String,
    id: String,
    body: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = AgoraClient::new();
    let room = client.open_room("my-bridge-room")?;

    room.send_json(&Frame {
        kind: "req".into(),
        id: "42".into(),
        body: "base64-or-json-payload".into(),
    })?;

    for event in room.fetch_json::<Frame>("10m") {
        println!("{} {}", event.message.sender, event.value.id);
    }

    let stream = StreamConfig {
        reconnect: true,
        initial_backoff: Duration::from_secs(1),
        max_backoff: Duration::from_secs(30),
    };

    room.stream_envelopes(
        &stream,
        |_ts, env| {
            if let Some(text) = env["text"].as_str() {
                if let Ok(frame) = serde_json::from_str::<Frame>(text) {
                    println!("{} {}", frame.kind, frame.id);
                }
            }
        },
        |reason, next_backoff| {
            eprintln!("agora stream dropped: {reason}; next={next_backoff:?}");
        },
    );
    Ok(())
}
```

Run the local memory-relay example with:

```sh
cargo run --example rust_sdk_json_bus
```

## Low-Level API

`agora::api` remains the stable low-level facade. Use it when an embedder needs
manual control over envelope construction, raw publish/fetch calls, or custom
stream demultiplexing.
