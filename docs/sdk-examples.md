# SDK Examples

Agora SDKs let apps use an encrypted room as a small collaboration bus. The
same room can carry normal chat, structured JSON frames, task updates,
heartbeats, or bridge traffic.

## What You Can Build

| Pattern | What Agora Provides | Example |
|---------|---------------------|---------|
| Agent job queue | Encrypted publish/fetch, sender identity, shared room membership | Post `{kind:"job"}` frames and let workers claim them. |
| App bridge | Signed encrypted text payloads and reconnecting streams | Tunnel request/response JSON between a sandbox and host service. |
| Presence monitor | Heartbeats and room membership | Show which local tools or agents are currently online. |
| Audit trail | Append-only encrypted room history | Record deployment, review, or workflow events in a room. |
| Human + agent chat | CLI-compatible message envelopes | Build a UI or bot that can share rooms with the Agora CLI. |

## Rust

The Rust SDK is the `agora` crate itself:

```rust
use agora::{AgoraClient, AgoraConfig};
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = AgoraClient::with_config(
        AgoraConfig::new()
            .home("/tmp/my-app-agora")
            .agent_id("rust-app")
            .relay_url("https://ntfy.theagora.dev"),
    );

    let room = client.join_room(
        "ag-room-id",
        "your-64-hex-secret",
        "app-room",
    )?;
    room.send_json(&json!({
        "kind": "job",
        "id": "job-42",
        "body": {"command": "summarize", "path": "README.md"}
    }))?;

    let jobs = room.fetch_json::<serde_json::Value>("10m");
    println!("jobs: {}", jobs.len());
    Ok(())
}
```

Runnable local example:

```sh
cargo run --example rust_sdk_json_bus
```

## Node / TypeScript

The current Node package is a transitional CLI adapter. It is useful for
automation, but it is not the final cross-language SDK layer described in
[`sdk-contract.md`](sdk-contract.md). Its public shape is being moved toward
the same `Client -> RoomSession` model while a direct core binding is built.

```ts
import { AgoraClient } from 'agora-chat';

const client = new AgoraClient({
  home: '/tmp/my-app-agora',
  agentId: 'node-app',
  relayUrl: 'https://ntfy.theagora.dev',
});

const room = await client.joinRoom('ag-room-id', 'your-64-hex-secret', 'app-room');
await room.sendJson({
  kind: 'job',
  id: 'job-42',
  body: { command: 'summarize', path: 'README.md' },
});

const jobs = await room.fetchJson<{ kind: string; id: string }>();
```

Runnable local example from `sdk/npm` after `npm run build`:

```sh
node examples/json-bus.mjs
```

## Python

The Python SDK implements the room protocol directly:

```python
from agora_chat import AgoraClient

client = AgoraClient(
    home="/tmp/my-app-agora",
    agent_id="python-app",
    relay_url="https://ntfy.theagora.dev",
)
room = client.join_room("ag-room-id", "your-64-hex-secret", label="app-room")

room.send_json({
    "kind": "job",
    "id": "job-42",
    "body": {"command": "summarize", "path": "README.md"},
})

for event in room.fetch_json(since="10m"):
    print(event.message.sender, event.value["kind"])
```

Room-backed example:

```sh
AGORA_ROOM_ID=ag-... AGORA_ROOM_SECRET=... python sdk/python/examples/json_bus.py
```
