"""Agora cryptographic core — Python implementation.

Matches the Rust implementation exactly:
- HKDF-SHA256 key derivation
- AES-256-GCM authenticated encryption
- Per-message random 96-bit nonces
"""

import base64
import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_private_key,
)

NONCE_LEN = 12
SIGNED_WIRE_VERSION = "3.1"
ED25519_PKCS8_RING_PREFIX = bytes.fromhex("3051020101300506032b657004220420")
ED25519_PKCS8_RING_PUBLIC_MARKER = bytes.fromhex("812100")
ED25519_PKCS8_V0_PREFIX = bytes.fromhex("302e020100300506032b657004220420")


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


def encrypt_envelope(
    envelope: dict,
    room_key: bytes,
    room_id: str,
    home: str | Path | None = None,
) -> str:
    """Encrypt and sign a JSON envelope for relay transport."""
    enc_key, _ = derive_message_keys(room_key)
    plaintext = json.dumps(envelope).encode()
    aad = room_id.encode()
    blob = encrypt(plaintext, enc_key, aad)
    payload = base64.b64encode(blob).decode()
    sender = str(envelope.get("from", ""))
    private_key, signing_pubkey = load_or_create_signing_keypair(sender, home)
    trust_signing_key(sender, signing_pubkey, home)
    signing_input = signing_message_bytes(room_id, sender, signing_pubkey, payload)
    sig = base64.b64encode(private_key.sign(signing_input)).decode()
    return json.dumps(
        {
            "v": SIGNED_WIRE_VERSION,
            "from": sender,
            "payload": payload,
            "signing_pubkey": signing_pubkey,
            "sig": sig,
        },
        separators=(",", ":"),
    )


def decrypt_payload(
    payload: str,
    room_key: bytes,
    room_id: str,
    home: str | Path | None = None,
) -> dict | None:
    """Decrypt a signed or legacy base64 wire payload into an envelope dict."""
    if payload.lstrip().startswith("{"):
        return decrypt_signed_payload(payload, room_key, room_id, home)

    enc_key, _ = derive_message_keys(room_key)
    try:
        blob = base64.b64decode(payload)
        aad = room_id.encode()
        plaintext = decrypt(blob, enc_key, aad)
        env = json.loads(plaintext.decode())
        env["_auth"] = "unsigned"
        return env
    except Exception:
        return None


def decrypt_signed_payload(
    raw: str,
    room_key: bytes,
    room_id: str,
    home: str | Path | None = None,
) -> dict | None:
    """Decrypt and verify a signed v3.1 wire payload."""
    try:
        wire = json.loads(raw)
        if wire.get("v") != SIGNED_WIRE_VERSION:
            return None
        sender = str(wire["from"])
        signing_pubkey = str(wire["signing_pubkey"])
        encrypted_payload = str(wire["payload"])
        sig = decode_signing_key(str(wire["sig"]))
        public_key_raw = decode_signing_key(signing_pubkey)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_raw)
        public_key.verify(
            sig,
            signing_message_bytes(room_id, sender, signing_pubkey, encrypted_payload),
        )

        trusted = trusted_signing_key(sender, home)
        if trusted is not None and not signing_keys_match(trusted, signing_pubkey):
            return None
        if trusted is None:
            trust_signing_key(sender, signing_pubkey, home)

        enc_key, _ = derive_message_keys(room_key)
        blob = base64.b64decode(encrypted_payload)
        plaintext = decrypt(blob, enc_key, room_id.encode())
        env = json.loads(plaintext.decode())
        if env.get("from") != sender:
            return None
        env["_auth"] = "verified"
        return env
    except Exception:
        return None


def signing_message_bytes(
    room_id: str,
    sender: str,
    signing_pubkey: str,
    payload: str,
) -> bytes:
    return f"agora-signed-wire-v1\n{room_id}\n{sender}\n{signing_pubkey}\n{payload}".encode()


def agora_dir(home: str | Path | None = None) -> Path:
    return (Path(home).expanduser() if home is not None else Path.home()) / ".agora"


def load_or_create_signing_keypair(
    agent_id: str,
    home: str | Path | None = None,
) -> tuple[ed25519.Ed25519PrivateKey, str]:
    keys_dir = agora_dir(home) / "signing-keys"
    keys_dir.mkdir(parents=True, exist_ok=True)
    path = keys_dir / f"{agent_id}.pkcs8"
    if path.exists():
        private_key = private_key_from_pkcs8(path.read_bytes())
        return private_key, public_key_base64(private_key)

    seed = os.urandom(32)
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    public_key_raw = public_key_raw_bytes(private_key)
    path.write_bytes(rust_compatible_pkcs8(seed, public_key_raw))
    return private_key, base64.b64encode(public_key_raw).decode()


def create_identity(home: str | Path | None = None) -> str:
    seed_phrase = os.environ.get("AGORA_IDENTITY_SEED")
    if seed_phrase:
        seed = hmac.new(b"agora-identity-v1", seed_phrase.encode(), hashlib.sha256).digest()
    else:
        seed = os.urandom(32)
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    public_key_raw = public_key_raw_bytes(private_key)
    agent_id = derive_agent_id(public_key_raw)

    directory = agora_dir(home)
    keys_dir = directory / "signing-keys"
    keys_dir.mkdir(parents=True, exist_ok=True)
    keys_dir.joinpath(f"{agent_id}.pkcs8").write_bytes(rust_compatible_pkcs8(seed, public_key_raw))
    directory.joinpath("identity.json").write_text(
        json.dumps(
            {
                "key_id": agent_id,
                "agent_id": agent_id,
                "public_key": public_key_raw.hex(),
                "created_at": int(time.time()),
                "ephemeral": seed_phrase is None,
            },
            indent=2,
        )
    )
    return agent_id


def derive_agent_id(public_key_raw: bytes) -> str:
    return hashlib.sha256(public_key_raw).digest()[:8].hex()


def private_key_from_pkcs8(der: bytes) -> ed25519.Ed25519PrivateKey:
    try:
        key = load_der_private_key(der, password=None)
        if isinstance(key, ed25519.Ed25519PrivateKey):
            return key
    except Exception:
        pass

    seed = seed_from_rust_compatible_pkcs8(der) or seed_from_v0_pkcs8(der)
    if seed is None:
        raise ValueError("unsupported Ed25519 PKCS#8 key")
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed)


def public_key_raw_bytes(private_key: ed25519.Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def public_key_base64(private_key: ed25519.Ed25519PrivateKey) -> str:
    return base64.b64encode(public_key_raw_bytes(private_key)).decode()


def rust_compatible_pkcs8(seed: bytes, public_key_raw: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("invalid Ed25519 seed length")
    if len(public_key_raw) != 32:
        raise ValueError("invalid Ed25519 public key length")
    return ED25519_PKCS8_RING_PREFIX + seed + ED25519_PKCS8_RING_PUBLIC_MARKER + public_key_raw


def seed_from_rust_compatible_pkcs8(der: bytes) -> bytes | None:
    seed_start = len(ED25519_PKCS8_RING_PREFIX)
    seed_end = seed_start + 32
    marker_end = seed_end + len(ED25519_PKCS8_RING_PUBLIC_MARKER)
    if len(der) != marker_end + 32:
        return None
    if der[:seed_start] != ED25519_PKCS8_RING_PREFIX:
        return None
    if der[seed_end:marker_end] != ED25519_PKCS8_RING_PUBLIC_MARKER:
        return None
    return der[seed_start:seed_end]


def seed_from_v0_pkcs8(der: bytes) -> bytes | None:
    if len(der) != len(ED25519_PKCS8_V0_PREFIX) + 32:
        return None
    if not der.startswith(ED25519_PKCS8_V0_PREFIX):
        return None
    return der[len(ED25519_PKCS8_V0_PREFIX):]


def trusted_signing_key(agent_id: str, home: str | Path | None = None) -> str | None:
    return load_trusted_signing_keys(home).get(agent_id)


def trust_signing_key(agent_id: str, signing_pubkey: str, home: str | Path | None = None) -> None:
    keys = load_trusted_signing_keys(home)
    keys[agent_id] = canonical_signing_key(signing_pubkey)
    path = agora_dir(home) / "trusted_signing_keys.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(keys, indent=2))


def load_trusted_signing_keys(home: str | Path | None = None) -> dict[str, str]:
    path = agora_dir(home) / "trusted_signing_keys.json"
    try:
        data = json.loads(path.read_text())
        return {str(key): canonical_signing_key(str(value)) for key, value in data.items()}
    except Exception:
        return {}


def canonical_signing_key(signing_pubkey: str) -> str:
    return base64.b64encode(decode_signing_key(signing_pubkey)).decode()


def signing_keys_match(left: str, right: str) -> bool:
    try:
        return canonical_signing_key(left) == canonical_signing_key(right)
    except Exception:
        return False


def decode_signing_key(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except Exception:
        padding = "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(value + padding)
