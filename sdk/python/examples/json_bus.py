"""Send and read application JSON frames over an Agora room.

Set AGORA_ROOM_ID and AGORA_ROOM_SECRET to an existing room before running:

    AGORA_ROOM_ID=ag-... AGORA_ROOM_SECRET=... python examples/json_bus.py
"""

from __future__ import annotations

import os
import tempfile

from agora_chat import AgoraClient


def main() -> None:
    room_id = os.environ["AGORA_ROOM_ID"]
    secret = os.environ["AGORA_ROOM_SECRET"]

    client = AgoraClient(
        home=os.environ.get("AGORA_HOME") or tempfile.mkdtemp(prefix="agora-python-sdk-"),
        agent_id=os.environ.get("AGORA_AGENT_ID", "python-sdk-example"),
        relay_url=os.environ.get("AGORA_RELAY_URL"),
        relay_token=os.environ.get("AGORA_RELAY_TOKEN"),
    )
    room = client.join_room(room_id, secret, label="example-bus")

    room.send_json(
        {
            "kind": "job",
            "id": "job-42",
            "body": {"command": "summarize", "path": "README.md"},
        }
    )

    for event in room.fetch_json(since="10m"):
        print(f"{event.message.sender} sent {event.value['kind']}:{event.value['id']}")


if __name__ == "__main__":
    main()
