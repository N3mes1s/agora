"""
Agora cryptographic core.

Security properties:
  - AES-256-GCM for authenticated encryption (confidentiality + integrity)
  - HKDF-SHA256 for key derivation from shared secrets
  - Per-message random nonces (96-bit)
  - Forward secrecy via hash ratchet (each message key derives the next)
  - Zero-knowledge room membership proof (Schnorr-like HMAC challenge-response)

No pip dependencies beyond `cryptography` (ships with most Python installs).
"""

import hashlib
import hmac
import os
import secrets
import struct
import time
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


# ── Key Derivation ──────────────────────────────────────────────

def derive_room_key(shared_secret: str, room_id: str) -> bytes:
    """Derive a 256-bit room key from a shared secret using HKDF.

    Uses the room_id as salt so the same secret produces different keys
    for different rooms. This prevents cross-room key reuse attacks.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=room_id.encode("utf-8"),
        info=b"agora-room-key-v1",
    )
    return hkdf.derive(shared_secret.encode("utf-8"))


def derive_message_keys(room_key: bytes) -> tuple[bytes, bytes]:
    """Derive separate encryption and MAC keys from the room key.

    Splitting keys prevents related-key attacks where the same key
    is used for both encryption and authentication.
    """
    enc_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"agora-enc-v1",
    ).derive(room_key)

    mac_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"agora-mac-v1",
    ).derive(room_key)

    return enc_key, mac_key


# ── Forward Secrecy Ratchet ─────────────────────────────────────

def ratchet_key(current_key: bytes) -> bytes:
    """Advance the key one step forward using a hash ratchet.

    After encrypting with the current key, advance to the next.
    Old keys are deleted, so compromising the current key doesn't
    expose past messages. This is a simplified version of the
    Double Ratchet (Signal Protocol).
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"agora-ratchet-v1",
    )
    return hkdf.derive(current_key)


# ── Authenticated Encryption ────────────────────────────────────

def encrypt(plaintext: bytes, key: bytes, associated_data: bytes = b"") -> bytes:
    """Encrypt with AES-256-GCM.

    Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)

    AES-GCM provides:
    - Confidentiality: ciphertext reveals nothing about plaintext
    - Integrity: any tampering is detected via the authentication tag
    - Associated data authentication: metadata (sender, timestamp) is
      authenticated but not encrypted, preventing tampering without
      hiding the structure
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data or None)
    return nonce + ciphertext


def decrypt(blob: bytes, key: bytes, associated_data: bytes = b"") -> bytes:
    """Decrypt AES-256-GCM.

    Input: nonce (12 bytes) || ciphertext || tag (16 bytes)
    Raises: cryptography.exceptions.InvalidTag on tamper/wrong key.
    """
    nonce = blob[:12]
    ciphertext = blob[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data or None)


# ── Zero-Knowledge Room Membership Proof ────────────────────────
#
# Proves you know the room key without revealing it.
# Protocol (Schnorr-like HMAC challenge-response):
#
#   Prover                          Verifier
#   ──────                          ────────
#   1. commitment = HMAC(key, nonce)
#      sends: (nonce, commitment)
#                                   2. challenge = random 32 bytes
#      sends: challenge
#   3. response = HMAC(key, nonce || challenge)
#      sends: response
#                                   4. verifies:
#                                      HMAC(key, nonce || challenge) == response
#
# The verifier also needs the key (shared secret), so this is
# technically a symmetric ZKP — it proves knowledge without
# transmitting the key over the wire.

def zkp_create_commitment(room_key: bytes) -> tuple[bytes, bytes]:
    """Create a ZKP commitment. Returns (nonce, commitment)."""
    nonce = os.urandom(32)
    commitment = hmac.new(room_key, nonce, hashlib.sha256).digest()
    return nonce, commitment


def zkp_create_challenge() -> bytes:
    """Create a random challenge for the prover."""
    return os.urandom(32)


def zkp_respond(room_key: bytes, nonce: bytes, challenge: bytes) -> bytes:
    """Prover responds to challenge, proving key knowledge."""
    return hmac.new(room_key, nonce + challenge, hashlib.sha256).digest()


def zkp_verify(room_key: bytes, nonce: bytes, challenge: bytes, response: bytes) -> bool:
    """Verify a ZKP response. Returns True if the prover knows the key."""
    expected = hmac.new(room_key, nonce + challenge, hashlib.sha256).digest()
    return hmac.compare_digest(expected, response)


# ── Key Generation Utilities ────────────────────────────────────

def generate_room_id() -> str:
    """Generate a random room identifier."""
    return "ag-" + secrets.token_hex(8)


def generate_secret() -> str:
    """Generate a 256-bit shared secret as hex string."""
    return secrets.token_hex(32)


def fingerprint(key: bytes) -> str:
    """Human-readable key fingerprint for verification.

    Two participants can compare fingerprints out-of-band to verify
    they share the same key (like Signal safety numbers).
    """
    digest = hashlib.sha256(key).hexdigest()
    # Group into 4-char blocks for readability
    return " ".join(digest[i:i+4] for i in range(0, 32, 4))
