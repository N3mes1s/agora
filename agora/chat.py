"""
Agora chat — the core chat engine.

Unifies room management, encryption, transport, and persistence
into a single coherent module.

Message format (wire):
    base64(nonce || AES-256-GCM(envelope_json, aad=room_id))

Envelope (plaintext JSON inside the encryption):
    {
        "v": "3.0",
        "id": "<8-hex-char message ID>",
        "from": "<agent-id>",
        "ts": <unix-timestamp>,
        "text": "<message body>",
        "reply_to": "<optional parent message ID>",
        "ratchet_idx": <optional ratchet position for forward secrecy>
    }
"""

import base64
import json
import secrets
import time
from typing import Optional

from . import crypto, transport, store


VERSION = "3.0"


# ── Envelope Construction ───────────────────────────────────────

def _make_envelope(text: str, reply_to: str = None) -> dict:
    return {
        "v": VERSION,
        "id": secrets.token_hex(4),
        "from": store.get_agent_id(),
        "ts": int(time.time()),
        "text": text,
        **({"reply_to": reply_to} if reply_to else {}),
    }


def _parse_envelope(raw: str) -> dict:
    """Parse a message envelope. Handles v3, v2, and v1 formats."""
    try:
        env = json.loads(raw)
        if "v" in env and "text" in env:
            return env
    except (json.JSONDecodeError, TypeError):
        pass
    # v1 fallback: "session_id: message text"
    parts = raw.split(":", 1)
    sender = parts[0].strip() if len(parts) == 2 else "?"
    text = parts[1].strip() if len(parts) == 2 else raw
    return {"v": "1.0", "id": "?", "from": sender, "ts": int(time.time()), "text": text}


# ── Encrypt / Decrypt ───────────────────────────────────────────

def _encrypt_envelope(envelope: dict, room_key: bytes, room_id: str) -> str:
    """Encrypt an envelope for transport. Returns base64 string."""
    enc_key, _ = crypto.derive_message_keys(room_key)
    plaintext = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    aad = room_id.encode("utf-8")
    ciphertext = crypto.encrypt(plaintext, enc_key, aad)
    return base64.b64encode(ciphertext).decode("ascii")


def _decrypt_payload(payload: str, room_key: bytes, room_id: str) -> Optional[dict]:
    """Decrypt a transport payload. Returns envelope dict or None."""
    enc_key, _ = crypto.derive_message_keys(room_key)
    try:
        blob = base64.b64decode(payload)
        aad = room_id.encode("utf-8")
        plaintext = crypto.decrypt(blob, enc_key, aad)
        return _parse_envelope(plaintext.decode("utf-8"))
    except Exception:
        # Try legacy v1/v2 decryption for backwards compat
        return _try_legacy_decrypt(payload, room_key)


def _try_legacy_decrypt(payload: str, room_key: bytes) -> Optional[dict]:
    """Attempt to decrypt v1 (CBC) or v2 (CTR+HMAC) messages."""
    import hashlib
    import subprocess

    # Detect format by colon count
    parts = payload.split(":")
    secret_hex = room_key.hex()  # Use raw key bytes as hex for legacy compat

    if len(parts) == 2:
        # v1 format: base64(iv):base64(ciphertext) — AES-256-CBC
        try:
            iv = base64.b64decode(parts[0])
            dk = hashlib.sha256(secret_hex.encode()).digest()
            r = subprocess.run(
                ["openssl", "enc", "-aes-256-cbc", "-d", "-base64", "-A",
                 "-K", dk.hex(), "-iv", iv.hex()],
                input=parts[1].encode(), capture_output=True, timeout=5,
            )
            if r.returncode == 0:
                return _parse_envelope(r.stdout.decode())
        except Exception:
            pass

    if len(parts) == 3:
        # v2 format: base64(iv):hmac_tag:base64(ciphertext) — AES-256-CTR+HMAC
        try:
            iv = base64.b64decode(parts[0])
            dk = hashlib.sha256(secret_hex.encode()).digest()
            r = subprocess.run(
                ["openssl", "enc", "-aes-256-ctr", "-d", "-base64", "-A",
                 "-K", dk.hex(), "-iv", iv.hex().ljust(32, "0")],
                input=parts[2].encode(), capture_output=True, timeout=5,
            )
            if r.returncode == 0:
                return _parse_envelope(r.stdout.decode())
        except Exception:
            pass

    return None


# ── Room Operations ─────────────────────────────────────────────

def create(label: str = "default") -> tuple[str, str]:
    """Create a new encrypted chat room. Returns (room_id, secret)."""
    room_id = crypto.generate_room_id()
    secret = crypto.generate_secret()

    room_key = crypto.derive_room_key(secret, room_id)
    store.add_room(room_id, secret, label)
    store.set_active_room(label)

    # Send creation notice
    env = _make_envelope("Room created (agora v3, AES-256-GCM).")
    encrypted = _encrypt_envelope(env, room_key, room_id)
    transport.publish(room_id, encrypted)
    store.save_message(room_id, env)

    return room_id, secret


def join(room_id: str, secret: str, label: str = None) -> dict:
    """Join an existing room. Returns the room entry."""
    if label is None:
        label = room_id[:12]
    entry = store.add_room(room_id, secret, label)
    store.set_active_room(label)

    room_key = crypto.derive_room_key(secret, room_id)
    env = _make_envelope("Joined (agora v3).")
    encrypted = _encrypt_envelope(env, room_key, room_id)
    transport.publish(room_id, encrypted)
    store.save_message(room_id, env)

    return entry


def send(message: str, reply_to: str = None, room_label: str = None) -> str:
    """Send an encrypted message. Returns message ID."""
    room = _resolve_room(room_label)
    room_key = crypto.derive_room_key(room["secret"], room["room_id"])

    env = _make_envelope(message, reply_to=reply_to)
    encrypted = _encrypt_envelope(env, room_key, room["room_id"])

    success = transport.publish(room["room_id"], encrypted)
    store.save_message(room["room_id"], env)

    if not success:
        # Saved locally, will sync when relay is back
        pass

    return env["id"]


def read(since: str = "2h", limit: int = 50, room_label: str = None) -> list[dict]:
    """Read messages — merge remote + local, deduplicate."""
    room = _resolve_room(room_label)
    room_key = crypto.derive_room_key(room["secret"], room["room_id"])

    # Fetch from relay
    remote_events = transport.fetch(room["room_id"], since=since)
    remote_msgs = []
    for evt in remote_events:
        payload = evt.get("message", "")
        env = _decrypt_payload(payload, room_key, room["room_id"])
        if env:
            if "ts" not in env or env["ts"] == 0:
                env["ts"] = evt.get("time", int(time.time()))
            remote_msgs.append(env)

    # Merge with local store
    since_secs = _parse_since(since)
    local_msgs = store.load_messages(room["room_id"], since_secs)

    seen_ids = set()
    merged = []
    for msg in remote_msgs + local_msgs:
        mid = msg.get("id", "?")
        if mid != "?" and mid in seen_ids:
            continue
        seen_ids.add(mid)
        merged.append(msg)
        store.save_message(room["room_id"], msg)

    merged.sort(key=lambda m: m.get("ts", 0))
    return merged[-limit:]


def check(since: str = "5m", room_label: str = None) -> list[dict]:
    """Check for new messages from others. Returns unseen messages."""
    room = _resolve_room(room_label)
    room_key = crypto.derive_room_key(room["secret"], room["room_id"])
    me = store.get_agent_id()
    seen = store.load_seen(room["room_id"])

    remote_events = transport.fetch(room["room_id"], since=since)
    new_msgs = []
    for evt in remote_events:
        payload = evt.get("message", "")
        env = _decrypt_payload(payload, room_key, room["room_id"])
        if not env:
            continue
        mid = env.get("id", "?")
        if env.get("from") == me:
            continue
        if mid in seen:
            continue
        new_msgs.append(env)
        store.mark_seen(room["room_id"], mid)
        store.save_message(room["room_id"], env)

    return new_msgs


def info(room_label: str = None) -> dict:
    """Get room info including key fingerprint."""
    room = _resolve_room(room_label)
    room_key = crypto.derive_room_key(room["secret"], room["room_id"])
    msgs = store.load_messages(room["room_id"])
    return {
        "room_id": room["room_id"],
        "label": room["label"],
        "encryption": "AES-256-GCM",
        "key_derivation": "HKDF-SHA256",
        "fingerprint": crypto.fingerprint(room_key),
        "messages": len(msgs),
        "joined_at": room.get("joined_at", 0),
    }


def verify_membership(room_label: str = None) -> dict:
    """Generate a ZKP membership proof for the current room."""
    room = _resolve_room(room_label)
    room_key = crypto.derive_room_key(room["secret"], room["room_id"])
    nonce, commitment = crypto.zkp_create_commitment(room_key)
    challenge = crypto.zkp_create_challenge()
    response = crypto.zkp_respond(room_key, nonce, challenge)
    valid = crypto.zkp_verify(room_key, nonce, challenge, response)
    return {
        "room_id": room["room_id"],
        "proof_valid": valid,
        "nonce": nonce.hex(),
        "commitment": commitment.hex(),
        "challenge": challenge.hex(),
        "response": response.hex(),
    }


# ── Helpers ─────────────────────────────────────────────────────

def _resolve_room(label: str = None) -> dict:
    """Resolve a room by label or get the active room."""
    if label:
        room = store.find_room(label)
    else:
        room = store.get_active_room()
    if not room:
        raise RuntimeError("No active room. Use 'agora create' or 'agora join' first.")
    return room


def _parse_since(since: str) -> int:
    """Convert '2h', '30m', '5s' to seconds."""
    s = since.strip().lower()
    if s.endswith("h"):
        return int(s[:-1]) * 3600
    if s.endswith("m"):
        return int(s[:-1]) * 60
    if s.endswith("s"):
        return int(s[:-1])
    return 7200
