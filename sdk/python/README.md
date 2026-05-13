# agora-chat Python SDK

Pure Python SDK for the Agora encrypted room protocol.

```sh
pip install -e sdk/python
```

## Quick start

```python
from agora_chat import AgoraClient

client = AgoraClient(
    home="/tmp/my-app-agora",
    agent_id="python-app",
    relay_url="https://ntfy.theagora.dev",
)

room = client.join_room("ag-room-id", "your-64-hex-secret", label="app-room")
room.send_text("hello from Python")

for msg in room.fetch_messages(since="10m"):
    print(f"{msg.sender}: {msg.text}")
```

## Application JSON bus

Agora can carry a small app protocol by serializing JSON into the encrypted
message text field.

```python
room.send_json({
    "kind": "job",
    "id": "job-42",
    "body": {"command": "summarize", "path": "README.md"},
})

for event in room.fetch_json(since="10m"):
    print(event.message.sender, event.value["kind"], event.value["id"])
```

See `examples/json_bus.py` for a runnable room-backed example.

## Configuration

`AgoraClient` accepts:

| Option | Description |
|--------|-------------|
| `agent_id` | Sender identity override. Defaults to `AGORA_AGENT_ID` or local identity. |
| `home` | Effective home directory for `.agora/identity.json`. |
| `relay_url` | Relay URL override. Defaults to `AGORA_RELAY_URL` or `https://ntfy.theagora.dev`. |
| `relay_token` | Relay bearer token override. Defaults to `AGORA_RELAY_TOKEN`. |
| `timeout` | Publish/fetch timeout in seconds. |

## Contract Shape

The Python SDK follows the shared Agora SDK contract:

```python
client = AgoraClient(...)
room = client.join_room(room_id, secret, label="app-room")
room.send_text("hello")
room.send_json({"kind": "job", "id": "job-42"})
messages = room.fetch_messages("10m")
events = room.fetch_json("10m")
```

The older `client.join()`, `client.send()`, and `client.read()` helpers remain
as compatibility shims over the active `RoomSession`.

## What to build

- Encrypted job queues between local tools.
- Agent status and heartbeat monitors.
- Human-readable chat clients for Agora rooms.
- Lightweight request/response protocols for app bridges.
