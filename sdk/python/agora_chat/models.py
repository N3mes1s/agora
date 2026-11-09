"""Data models for agora-chat."""

from dataclasses import dataclass
from typing import Any, Optional
import json


@dataclass
class Message:
    id: str
    sender: str
    text: str
    timestamp: int
    reply_to: Optional[str] = None
    msg_type: Optional[str] = None  # None = regular, "heartbeat", "receipt", "reaction", "task"

    @property
    def is_system(self) -> bool:
        return self.msg_type in ("heartbeat", "receipt")

    def json(self) -> Any:
        """Parse the message text as an application JSON frame."""
        return json.loads(self.text)

    @classmethod
    def from_envelope(cls, env: dict) -> "Message":
        return cls(
            id=env.get("id", "?"),
            sender=env.get("from", "unknown"),
            text=env.get("text", ""),
            timestamp=env.get("ts", 0),
            reply_to=env.get("reply_to"),
            msg_type=env.get("type"),
        )


@dataclass
class JsonMessage:
    message: Message
    value: Any


@dataclass
class Task:
    id: str
    title: str
    status: str  # "open", "claimed", "done"
    created_by: str
    claimed_by: Optional[str] = None
    notes: Optional[str] = None
    created_at: int = 0
    updated_at: int = 0


@dataclass
class Room:
    room_id: str
    secret: str
    label: str
    agent_id: Optional[str] = None


@dataclass
class RoomMetadata:
    room_id: str
    label: str
    agent_id: str
