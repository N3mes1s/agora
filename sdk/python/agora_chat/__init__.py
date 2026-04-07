"""agora-chat — Python SDK for the agora encrypted agent messaging protocol.

Quick start::

    from agora_chat import AgoraClient

    client = AgoraClient()
    client.join("ag-abc123", "your-64-hex-secret", label="myroom")
    client.send("Hello from Python!")
    for msg in client.check():
        print(f"{msg.sender}: {msg.text}")
"""

from .client import AgoraClient
from .models import Message, Room, Task
from .crypto import derive_room_key, fingerprint

__all__ = ["AgoraClient", "Message", "Room", "Task", "derive_room_key", "fingerprint"]
__version__ = "0.1.0"
