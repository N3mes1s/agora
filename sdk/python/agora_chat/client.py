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
from pathlib import Path
from typing import Any, Iterator, Optional

from .crypto import (
    create_identity,
    derive_room_key,
    encrypt_envelope,
    decrypt_payload,
    fingerprint,
)
from .models import JsonMessage, Message, Room, RoomMetadata, Task
from . import transport

VERSION = "3.0"


def _msg_id() -> str:
    return os.urandom(4).hex()


def _now() -> int:
    return int(time.time())


def _agora_dir(home: Optional[Path] = None) -> Path:
    return (home or Path.home()) / ".agora"


def _load_identity(home: Optional[Path] = None) -> str:
    """Load or create agent identity."""
    env_id = os.environ.get("AGORA_AGENT_ID", "")
    if env_id:
        return env_id

    agora_dir = _agora_dir(home)
    id_file = agora_dir / "identity.json"
    if id_file.exists():
        try:
            data = json.loads(id_file.read_text())
            if data.get("agent_id"):
                return data["agent_id"]
        except (json.JSONDecodeError, KeyError):
            pass

    return create_identity(home)


class RoomSession:
    """Joined Agora room following the shared SDK contract."""

    def __init__(self, client: "AgoraClient", room: Room, room_key: bytes):
        self._client = client
        self._room = room
        self._room_key = room_key

    @property
    def room_id(self) -> str:
        return self._room.room_id

    @property
    def label(self) -> str:
        return self._room.label

    @property
    def agent_id(self) -> str:
        return self._client.agent_id

    @property
    def metadata(self) -> RoomMetadata:
        return RoomMetadata(room_id=self.room_id, label=self.label, agent_id=self.agent_id)

    def fingerprint(self) -> str:
        return fingerprint(self._room_key)

    def send_text(self, text: str, reply_to: Optional[str] = None) -> str:
        env = self._client._make_envelope(text, reply_to=reply_to)
        encrypted = self._client._encrypt_envelope(env, self._room_key, self.room_id)
        self._client._publish_encrypted(self.room_id, encrypted)
        return env["id"]

    def send_json(self, value: Any, reply_to: Optional[str] = None) -> str:
        return self.send_text(json.dumps(value, separators=(",", ":")), reply_to=reply_to)

    def fetch_messages(self, since: str = "all", include_system: bool = False) -> list[Message]:
        messages: list[Message] = []
        for _ts, payload in self._client._fetch_raw(self.room_id, since):
            env = self._client._decrypt_payload(payload, self._room_key, self.room_id)
            if env is None:
                continue
            msg = Message.from_envelope(env)
            if not include_system and msg.is_system:
                continue
            messages.append(msg)
        return messages

    def fetch_json(self, since: str = "all", include_system: bool = False) -> list[JsonMessage]:
        return self._client._messages_to_json(
            self.fetch_messages(since=since, include_system=include_system)
        )

    def stream_messages(
        self, since: str = "all", include_system: bool = False
    ) -> Iterator[Message]:
        for _ts, payload in transport.stream(
            self.room_id,
            since=since,
            base_url=self._client.relay_url,
            token=self._client.relay_token,
            nats=self._client.nats_settings,
        ):
            env = self._client._decrypt_payload(payload, self._room_key, self.room_id)
            if env is None:
                continue
            msg = Message.from_envelope(env)
            if not include_system and msg.is_system:
                continue
            yield msg

    def stream_json(
        self, since: str = "all", include_system: bool = False
    ) -> Iterator[JsonMessage]:
        for msg in self.stream_messages(since=since, include_system=include_system):
            try:
                yield JsonMessage(message=msg, value=msg.json())
            except json.JSONDecodeError:
                continue


class AgoraClient:
    """Python client for the agora encrypted messaging protocol.

    Usage::

        client = AgoraClient()
        client.join("ag-abc123", "your-64-hex-secret", label="myroom")
        client.send("Hello, agents!")
        for msg in client.check():
            print(f"{msg.sender}: {msg.text}")
    """

    def __init__(
        self,
        agent_id: Optional[str] = None,
        home: Optional[str | Path] = None,
        relay_url: Optional[str] = None,
        relay_token: Optional[str] = None,
        timeout: int = transport.DEFAULT_TIMEOUT,
        nats_stream: Optional[str] = None,
        nats_subject_prefix: Optional[str] = None,
        nats_create_stream: Optional[bool] = None,
        nats_storage: Optional[str] = None,
        nats_max_bytes: Optional[int] = None,
        nats_max_age: Optional[int | float | str] = None,
    ):
        self.home = Path(home).expanduser() if home is not None else None
        self.relay_url = relay_url
        self.relay_token = relay_token
        self.timeout = timeout
        self.nats_settings = transport.NatsSettings.current(
            stream_name=nats_stream,
            subject_prefix=nats_subject_prefix,
            create_stream=nats_create_stream,
            storage=nats_storage,
            max_bytes=nats_max_bytes,
            max_age=nats_max_age,
        )
        self.agent_id = agent_id or _load_identity(self.home)
        self._room: Optional[Room] = None
        self._room_key: Optional[bytes] = None
        self._session: Optional[RoomSession] = None
        self._seen: set[str] = set()

    # ── Room Management ──────────────────────────────────────────

    def join(self, room_id: str, secret: str, label: str = "default") -> Room:
        """Join an existing encrypted room."""
        session = self.join_room(room_id, secret, label)
        return session._room

    def join_room(self, room_id: str, secret: str, label: str = "default") -> RoomSession:
        """Join an existing encrypted room and return a room session."""
        room_key = derive_room_key(secret, room_id)
        self._room = Room(room_id=room_id, secret=secret, label=label, agent_id=self.agent_id)
        self._room_key = room_key
        self._session = RoomSession(self, self._room, room_key)
        self._seen = set()

        # Announce presence
        env = self._make_envelope("Joined (agora v3, Python SDK).")
        encrypted = self._encrypt_envelope(env, room_key, room_id)
        self._publish_encrypted(room_id, encrypted)
        return self._session

    def create(self, label: str = "default") -> Room:
        """Create a new encrypted room."""
        session = self.create_room(label)
        return session._room

    def create_room(self, label: str = "default") -> RoomSession:
        """Create a new encrypted room and return a room session."""
        return self._create_room_with_options(label, silent=False)

    def create_room_silent(self, label: str = "default") -> RoomSession:
        """Create a new encrypted room without publishing the presence envelope.

        Mirrors AgoraClient::create_room_silent in the Rust SDK. Use when an
        embedder (cfs-mesh expose_uds, transient bridges, tests) needs a
        fresh room but does not want a stray system message landing as the
        first envelope receivers see.
        """
        return self._create_room_with_options(label, silent=True)

    def _create_room_with_options(self, label: str, silent: bool) -> RoomSession:
        room_id = "ag-" + os.urandom(8).hex()
        secret = os.urandom(32).hex()
        room_key = derive_room_key(secret, room_id)

        self._room = Room(room_id=room_id, secret=secret, label=label, agent_id=self.agent_id)
        self._room_key = room_key
        self._session = RoomSession(self, self._room, room_key)
        self._seen = set()

        if not silent:
            env = self._make_envelope("Room created (agora v3, Python SDK).")
            encrypted = self._encrypt_envelope(env, room_key, room_id)
            self._publish_encrypted(room_id, encrypted)
        return self._session

    def init_identity(self) -> str:
        """Eagerly materialize the local identity and return its agent id.

        Mirrors AgoraClient::init_identity in the Rust SDK. The Python SDK
        already loads/creates identity in __init__, so this is an
        explicit-intent alias for that work; useful at embedder call
        sites that want to express "set up identity now" without it
        reading like an accidental getter.
        """
        return self.agent_id

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

    @property
    def session(self) -> RoomSession:
        if self._session is None:
            raise RuntimeError("Not in a room. Call join_room() or create_room() first.")
        return self._session

    def fingerprint(self) -> str:
        """Return the room key fingerprint for verification."""
        return fingerprint(self.room_key)

    # ── Messaging ────────────────────────────────────────────────

    def send(self, text: str, reply_to: Optional[str] = None) -> str:
        """Send an encrypted message. Returns the message ID."""
        return self.session.send_text(text, reply_to=reply_to)

    def send_json(self, value: Any, reply_to: Optional[str] = None) -> str:
        """Send an application JSON frame in the Agora message text field."""
        return self.session.send_json(value, reply_to=reply_to)

    def check(self, since: str = "1h", mark_seen: bool = True) -> list[Message]:
        """Fetch new messages from the room.

        Args:
            since: relay time filter (e.g. "1h", "10m", "all")
            mark_seen: if True, skip messages already returned before

        Returns list of Message objects, excluding system messages.
        """
        raw_events = self._fetch_raw(self.room.room_id, since)
        messages = []
        for ts, payload in raw_events:
            env = self._decrypt_payload(payload, self.room_key, self.room.room_id)
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

    def check_json(self, since: str = "1h", mark_seen: bool = True) -> list[JsonMessage]:
        """Fetch new messages whose text field contains application JSON."""
        return self._messages_to_json(self.check(since=since, mark_seen=mark_seen))

    def read(self, since: str = "all", include_system: bool = False) -> list[Message]:
        """Read all messages (no dedup). Good for history."""
        raw_events = self._fetch_raw(self.room.room_id, since)
        messages = []
        for ts, payload in raw_events:
            env = self._decrypt_payload(payload, self.room_key, self.room.room_id)
            if env is None:
                continue
            msg = Message.from_envelope(env)
            if not include_system and msg.is_system:
                continue
            messages.append(msg)
        return messages

    def read_json(self, since: str = "all", include_system: bool = False) -> list[JsonMessage]:
        """Read messages whose text field contains application JSON."""
        return self._messages_to_json(self.read(since=since, include_system=include_system))

    def watch(self, since: str = "all", include_system: bool = False) -> Iterator[Message]:
        """Stream messages in real-time. Yields Message objects as they arrive."""
        yield from self.session.stream_messages(since=since, include_system=include_system)

    def watch_json(self, since: str = "all", include_system: bool = False) -> Iterator[JsonMessage]:
        """Stream messages whose text field contains application JSON."""
        for msg in self.watch(since=since, include_system=include_system):
            try:
                yield JsonMessage(message=msg, value=msg.json())
            except json.JSONDecodeError:
                continue

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
        encrypted = self._encrypt_envelope(env, self.room_key, self.room.room_id)
        return self._publish_encrypted(self.room.room_id, encrypted)

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
        encrypted = self._encrypt_envelope(env, self.room_key, self.room.room_id)
        return self._publish_encrypted(self.room.room_id, encrypted)

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
        encrypted = self._encrypt_envelope(env, self.room_key, self.room.room_id)
        self._publish_encrypted(self.room.room_id, encrypted)
        return task_id

    def task_claim(self, task_id: str) -> bool:
        """Announce claiming a task."""
        env = self._make_envelope(f"[task] Claimed: {task_id[:6]} by {self.agent_id}")
        env["task_update"] = {"id": task_id, "status": "claimed", "claimed_by": self.agent_id}
        encrypted = self._encrypt_envelope(env, self.room_key, self.room.room_id)
        return self._publish_encrypted(self.room.room_id, encrypted)

    def task_done(self, task_id: str, notes: Optional[str] = None) -> bool:
        """Announce a task as done."""
        note_str = f" — {notes}" if notes else ""
        env = self._make_envelope(f"[task] Done: {task_id[:6]}{note_str}")
        env["task_update"] = {"id": task_id, "status": "done", "notes": notes}
        encrypted = self._encrypt_envelope(env, self.room_key, self.room.room_id)
        return self._publish_encrypted(self.room.room_id, encrypted)

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

    def _publish_encrypted(self, room_id: str, payload: str) -> bool:
        return transport.publish(
            room_id,
            payload,
            timeout=self.timeout,
            base_url=self.relay_url,
            token=self.relay_token,
            nats=self.nats_settings,
        )

    def _encrypt_envelope(self, env: dict, room_key: bytes, room_id: str) -> str:
        return encrypt_envelope(env, room_key, room_id, home=self.home)

    def _decrypt_payload(self, payload: str, room_key: bytes, room_id: str) -> dict | None:
        return decrypt_payload(payload, room_key, room_id, home=self.home)

    def _fetch_raw(self, room_id: str, since: str) -> list[tuple[int, str]]:
        return transport.fetch(
            room_id,
            since=since,
            timeout=self.timeout,
            base_url=self.relay_url,
            token=self.relay_token,
            nats=self.nats_settings,
        )

    @staticmethod
    def _messages_to_json(messages: list[Message]) -> list[JsonMessage]:
        parsed: list[JsonMessage] = []
        for msg in messages:
            try:
                parsed.append(JsonMessage(message=msg, value=msg.json()))
            except json.JSONDecodeError:
                continue
        return parsed

    # ── Context manager ──────────────────────────────────────────

    def __enter__(self) -> "AgoraClient":
        return self

    def __exit__(self, *_) -> None:
        pass
