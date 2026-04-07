"""Agora cryptographic core — Python implementation.

Matches the Rust implementation exactly:
- HKDF-SHA256 key derivation
- AES-256-GCM authenticated encryption
- Per-message random 96-bit nonces
"""

import os
import base64
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_LEN = 12


def derive_room_key(shared_secret: str, room_id: str) -> bytes:
    """Derive a 256-bit room key from a shared secret using HKDF-SHA256.

    The room_id is used as salt so the same secret produces different
    keys for different rooms, preventing cross-room key reuse.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=room_id.encode(),
        info=b"agora-room-key-v1",
    )
    return hkdf.derive(shared_secret.encode())


def _hkdf_derive(ikm: bytes, info: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"",
        info=info,
    )
    return hkdf.derive(ikm)


def derive_message_keys(room_key: bytes) -> tuple[bytes, bytes]:
    """Derive separate encryption and MAC keys from the room key."""
    enc_key = _hkdf_derive(room_key, b"agora-enc-v1")
    mac_key = _hkdf_derive(room_key, b"agora-mac-v1")
    return enc_key, mac_key


def encrypt(plaintext: bytes, key: bytes, aad: bytes) -> bytes:
    """Encrypt with AES-256-GCM.

    Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
    """
    nonce = os.urandom(NONCE_LEN)
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce + ciphertext_with_tag


def decrypt(blob: bytes, key: bytes, aad: bytes) -> bytes:
    """Decrypt AES-256-GCM.

    Input: nonce (12 bytes) || ciphertext || tag (16 bytes)
    """
    if len(blob) < NONCE_LEN + 16:
        raise ValueError("blob too short")
    nonce = blob[:NONCE_LEN]
    ciphertext_with_tag = blob[NONCE_LEN:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext_with_tag, aad)


def fingerprint(key: bytes) -> str:
    """Human-readable key fingerprint for out-of-band verification."""
    import hashlib
    digest = hashlib.sha256(key).digest()
    hex_str = digest[:16].hex()
    parts = [hex_str[i:i+4] for i in range(0, len(hex_str), 4)]
    return " ".join(parts)


def encrypt_envelope(envelope: dict, room_key: bytes, room_id: str) -> str:
    """Encrypt a JSON envelope and return base64-encoded wire payload."""
    import json
    enc_key, _ = derive_message_keys(room_key)
    plaintext = json.dumps(envelope).encode()
    aad = room_id.encode()
    blob = encrypt(plaintext, enc_key, aad)
    return base64.b64encode(blob).decode()


def decrypt_payload(payload: str, room_key: bytes, room_id: str) -> dict | None:
    """Decrypt a base64-encoded wire payload into an envelope dict."""
    import json
    enc_key, _ = derive_message_keys(room_key)
    try:
        blob = base64.b64decode(payload)
        aad = room_id.encode()
        plaintext = decrypt(blob, enc_key, aad)
        return json.loads(plaintext.decode())
    except Exception:
        return None
