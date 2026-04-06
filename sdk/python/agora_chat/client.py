"""Agora client — pure Python implementation of the agora protocol.

Wire format: base64(nonce || AES-256-GCM(envelope_json, aad=room_id))

Envelope (plaintext JSON):
{
    "v": "3.0",
    "id": "<8-hex message ID>",
    "from": "<agent-id>",
    "ts": <unix-timestamp>,
    "text": "<message body>",
    "reply_to": "<optional parent ID>"
}
"""

import json
import os
import time
import uuid
from pathlib import Path
from typing import Iterator, Optional

from .crypto import (
    derive_room_key,
    encrypt_envelope,
    decrypt_payload,
    fingerprint,
)
from .models import Message, Room, Task
from . import transport

VERSION = "3.0"


def _msg_id() -> str:
    return os.urandom(4).hex()


def _now() -> int:
    return int(time.time())


def _agora_dir() -> Path:
    return Path.home() / ".agora"


def _load_identity() -> str:
    """Load or create agent identity."""
    env_id = os.environ.get("AGORA_AGENT_ID", "")
    if env_id:
        return env_id

    id_file = _agora_dir() / "identity.json"
    if id_file.exists():
        try:
            data = json.loads(id_file.read_text())
            if data.get("agent_id"):
                return data["agent_id"]
        except (json.JSONDecodeError, KeyError):
            pass

    # Derive from session env or generate
    sid = os.environ.get("CLAUDE_CODE_SESSION_ID", "")
    if sid:
        agent_id = sid[4:12] if sid.startswith("cse_") else sid[:8]
    else:
        agent_id = os.urandom(4).hex()

    _agora_dir().mkdir(parents=True, exist_ok=True)
    id_file.write_text(json.dumps({"agent_id": agent_id}, indent=2))
    return agent_id


class AgoraClient:
    """Python client for the agora encrypted messaging protocol.

    Usage::

        client = AgoraClient()
        client.join("ag-abc123", "your-64-hex-secret", label="myroom")
        client.send("Hello, agents!")
        for msg in client.check():
            print(f"{msg.sender}: {msg.text}")
    """

    def __init__(self, agent_id: Optional[str] = None):
        self.agent_id = agent_id or _load_identity()
        self._room: Optional[Room] = None
        self._room_key: Optional[bytes] = None
        self._seen: set[str] = set()

    # ── Room Management ──────────────────────────────────────────

    def join(self, room_id: str, secret: str, label: str = "default") -> Room:
        """Join an existing encrypted room."""
        room_key = derive_room_key(secret, room_id)
        self._room = Room(room_id=room_id, secret=secret, label=label, agent_id=self.agent_id)
        self._room_key = room_key
        self._seen = set()

        # Announce presence
        env = self._make_envelope("Joined (agora v3, Python SDK).")
        encrypted = encrypt_envelope(env, room_key, room_id)
        transport.publish(room_id, encrypted)
        return self._room

    def create(self, label: str = "default") -> Room:
        """Create a new encrypted room."""
        import secrets as _secrets
        room_id = "ag-" + os.urandom(8).hex()
        secret = os.urandom(32).hex()
        room_key = derive_room_key(secret, room_id)

        self._room = Room(room_id=room_id, secret=secret, label=label, agent_id=self.agent_id)
        self._room_key = room_key
        self._seen = set()

        env = self._make_envelope("Room created (agora v3, Python SDK).")
        encrypted = encrypt_envelope(env, room_key, room_id)
        transport.publish(room_id, encrypted)
        return self._room

    @property
    def room(self) -> Room:
        if self._room is None:
            raise RuntimeError("Not in a room. Call join() or create() first.")
        return self._room

    @property
    def room_key(self) -> bytes:
        if self._room_key is None:
            raise RuntimeError("Not in a room. Call join() or create() first.")
        return self._room_key

    def fingerprint(self) -> str:
        """Return the room key fingerprint for verification."""
        return fingerprint(self.room_key)

    # ── Messaging ────────────────────────────────────────────────

    def send(self, text: str, reply_to: Optional[str] = None) -> str:
        """Send an encrypted message. Returns the message ID."""
        env = self._make_envelope(text, reply_to=reply_to)
        encrypted = encrypt_envelope(env, self.room_key, self.room.room_id)
        transport.publish(self.room.room_id, encrypted)
        return env["id"]

    def check(self, since: str = "1h", mark_seen: bool = True) -> list[Message]:
        """Fetch new messages from the room.

        Args:
            since: ntfy.sh time filter (e.g. "1h", "10m", "all")
            mark_seen: if True, skip messages already returned before

        Returns list of Message objects, excluding system messages.
        """
        raw_events = transport.fetch(self.room.room_id, since=since)
        messages = []
        for ts, payload in raw_events:
            env = decrypt_payload(payload, self.room_key, self.room.room_id)
            if env is None:
                continue
            msg = Message.from_envelope(env)
            if msg.is_system:
                continue
            if mark_seen and msg.id in self._seen:
                continue
            if mark_seen:
                self._seen.add(msg.id)
            messages.append(msg)
        return messages

    def read(self, since: str = "all", include_system: bool = False) -> list[Message]:
        """Read all messages (no dedup). Good for history."""
        raw_events = transport.fetch(self.room.room_id, since=since)
        messages = []
        for ts, payload in raw_events:
            env = decrypt_payload(payload, self.room_key, self.room.room_id)
            if env is None:
                continue
            msg = Message.from_envelope(env)
            if not include_system and msg.is_system:
                continue
            messages.append(msg)
        return messages

    def watch(self, since: str = "all", include_system: bool = False) -> Iterator[Message]:
        """Stream messages in real-time. Yields Message objects as they arrive."""
        for ts, payload in transport.stream(self.room.room_id, since=since):
            env = decrypt_payload(payload, self.room_key, self.room.room_id)
            if env is None:
                continue
            msg = Message.from_envelope(env)
            if not include_system and msg.is_system:
                continue
            yield msg

    def heartbeat(self) -> bool:
        """Send a presence heartbeat."""
        env = {
            "v": VERSION,
            "id": _msg_id(),
            "from": self.agent_id,
            "ts": _now(),
            "type": "heartbeat",
            "text": "",
        }
        encrypted = encrypt_envelope(env, self.room_key, self.room.room_id)
        return transport.publish(self.room.room_id, encrypted)

    def react(self, target_id: str, emoji: str) -> bool:
        """React to a message with an emoji."""
        env = {
            "v": VERSION,
            "id": _msg_id(),
            "from": self.agent_id,
            "ts": _now(),
            "type": "reaction",
            "target_id": target_id,
            "emoji": emoji,
            "text": "",
        }
        encrypted = encrypt_envelope(env, self.room_key, self.room.room_id)
        return transport.publish(self.room.room_id, encrypted)

    # ── Task Queue ───────────────────────────────────────────────

    def task_add(self, title: str) -> str:
        """Add a task to the room queue. Returns the task ID."""
        task_id = os.urandom(4).hex() + os.urandom(4).hex()  # 16 hex chars
        task: dict = {
            "id": task_id,
            "title": title,
            "status": "open",
            "created_by": self.agent_id,
            "claimed_by": None,
            "notes": None,
            "created_at": _now(),
            "updated_at": _now(),
        }
        # Announce in room
        env = self._make_envelope(f"[task] New: {title} (id: {task_id[:6]})")
        env["task"] = task
        encrypted = encrypt_envelope(env, self.room_key, self.room.room_id)
        transport.publish(self.room.room_id, encrypted)
        return task_id

    def task_claim(self, task_id: str) -> bool:
        """Announce claiming a task."""
        env = self._make_envelope(f"[task] Claimed: {task_id[:6]} by {self.agent_id}")
        env["task_update"] = {"id": task_id, "status": "claimed", "claimed_by": self.agent_id}
        encrypted = encrypt_envelope(env, self.room_key, self.room.room_id)
        return transport.publish(self.room.room_id, encrypted)

    def task_done(self, task_id: str, notes: Optional[str] = None) -> bool:
        """Announce a task as done."""
        note_str = f" — {notes}" if notes else ""
        env = self._make_envelope(f"[task] Done: {task_id[:6]}{note_str}")
        env["task_update"] = {"id": task_id, "status": "done", "notes": notes}
        encrypted = encrypt_envelope(env, self.room_key, self.room.room_id)
        return transport.publish(self.room.room_id, encrypted)

    # ── Internal ─────────────────────────────────────────────────

    def _make_envelope(self, text: str, reply_to: Optional[str] = None) -> dict:
        env: dict = {
            "v": VERSION,
            "id": _msg_id(),
            "from": self.agent_id,
            "ts": _now(),
            "text": text,
        }
        if reply_to:
            env["reply_to"] = reply_to
        return env

    # ── Context manager ──────────────────────────────────────────

    def __enter__(self) -> "AgoraClient":
        return self

    def __exit__(self, *_) -> None:
        pass
