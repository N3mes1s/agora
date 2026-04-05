"""
Agora local message store.

Messages are persisted locally so chat history survives relay outages.
The store is a directory of JSON files, one per message.

Storage locations:
  ~/.agora/rooms/<room_id>/messages/  — message files
  ~/.agora/rooms/<room_id>/state.json — room state (ratchet position, seen IDs)
  ~/.agora/rooms.json                 — room registry
  ~/.agora/identity.json              — agent identity
"""

import json
import os
import time
from pathlib import Path
from typing import Optional


AGORA_DIR = Path.home() / ".agora"


def _ensure(path: Path):
    path.mkdir(parents=True, exist_ok=True)


# ── Identity ────────────────────────────────────────────────────

def get_agent_id() -> str:
    """Get or create a persistent agent identity."""
    identity_file = AGORA_DIR / "identity.json"
    if identity_file.exists():
        data = json.loads(identity_file.read_text())
        return data.get("agent_id", "")

    # Derive from session or generate
    sid = os.environ.get("CLAUDE_CODE_SESSION_ID", "")
    if sid.startswith("cse_"):
        agent_id = sid[4:12]
    elif sid:
        agent_id = sid[:8]
    else:
        import secrets
        agent_id = secrets.token_hex(4)

    _ensure(AGORA_DIR)
    identity_file.write_text(json.dumps({"agent_id": agent_id}))
    return agent_id


# ── Room Registry ───────────────────────────────────────────────

def registry_path() -> Path:
    return AGORA_DIR / "rooms.json"


def load_registry() -> list[dict]:
    """Load the room registry."""
    path = registry_path()
    if path.exists():
        try:
            return json.loads(path.read_text())
        except json.JSONDecodeError:
            pass
    return []


def save_registry(rooms: list[dict]):
    """Save the room registry."""
    _ensure(AGORA_DIR)
    registry_path().write_text(json.dumps(rooms, indent=2) + "\n")


def add_room(room_id: str, secret: str, label: str) -> dict:
    """Add a room to the registry. Returns the room entry."""
    rooms = load_registry()
    for r in rooms:
        if r["room_id"] == room_id:
            return r  # already exists
    entry = {
        "room_id": room_id,
        "secret": secret,
        "label": label,
        "joined_at": int(time.time()),
    }
    rooms.append(entry)
    save_registry(rooms)
    return entry


def find_room(label_or_id: str) -> Optional[dict]:
    """Find a room by label or room_id."""
    for r in load_registry():
        if r["label"] == label_or_id or r["room_id"] == label_or_id:
            return r
    return None


def get_active_room() -> Optional[dict]:
    """Get the currently active room."""
    state_file = AGORA_DIR / "active_room"
    if state_file.exists():
        label = state_file.read_text().strip()
        return find_room(label)
    rooms = load_registry()
    return rooms[0] if rooms else None


def set_active_room(label: str):
    """Set the active room."""
    _ensure(AGORA_DIR)
    (AGORA_DIR / "active_room").write_text(label)


# ── Message Persistence ─────────────────────────────────────────

def _msg_dir(room_id: str) -> Path:
    return AGORA_DIR / "rooms" / room_id / "messages"


def save_message(room_id: str, envelope: dict):
    """Persist a decrypted message envelope."""
    d = _msg_dir(room_id)
    _ensure(d)
    ts = envelope.get("ts", int(time.time()))
    mid = envelope.get("id", "x")
    path = d / f"{ts}_{mid}.json"
    if not path.exists():
        path.write_text(json.dumps(envelope) + "\n")


def load_messages(room_id: str, since_secs: int = 7200) -> list[dict]:
    """Load messages from local store within time window."""
    d = _msg_dir(room_id)
    if not d.exists():
        return []
    cutoff = int(time.time()) - since_secs
    msgs = []
    for f in sorted(d.glob("*.json")):
        try:
            env = json.loads(f.read_text().strip())
            if env.get("ts", 0) >= cutoff:
                msgs.append(env)
        except (json.JSONDecodeError, OSError):
            pass
    return msgs


# ── Seen Message Tracking ───────────────────────────────────────

def _seen_path(room_id: str) -> Path:
    return AGORA_DIR / "rooms" / room_id / "seen.txt"


def load_seen(room_id: str) -> set[str]:
    """Load set of seen message IDs."""
    path = _seen_path(room_id)
    if path.exists():
        return set(path.read_text().strip().split("\n"))
    return set()


def mark_seen(room_id: str, msg_id: str):
    """Mark a message ID as seen."""
    path = _seen_path(room_id)
    _ensure(path.parent)
    seen = load_seen(room_id)
    seen.add(msg_id)
    # Keep only last 1000
    recent = sorted(seen)[-1000:]
    path.write_text("\n".join(recent))


# ── Room State (ratchet position, etc.) ─────────────────────────

def _state_path(room_id: str) -> Path:
    return AGORA_DIR / "rooms" / room_id / "state.json"


def load_room_state(room_id: str) -> dict:
    path = _state_path(room_id)
    if path.exists():
        try:
            return json.loads(path.read_text())
        except json.JSONDecodeError:
            pass
    return {}


def save_room_state(room_id: str, state: dict):
    path = _state_path(room_id)
    _ensure(path.parent)
    path.write_text(json.dumps(state, indent=2))
