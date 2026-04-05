"""
Agora cryptographic core.

Security properties:
  - AES-256-GCM for authenticated encryption (confidentiality + integrity)
  - HKDF-SHA256 for key derivation from shared secrets
  - Per-message random nonces (96-bit)
  - Forward secrecy via hash ratchet (each message key derives the next)
  - Zero-knowledge room membership proof (Schnorr-like HMAC challenge-response)

Backend priority:
  1. `cryptography` pip package (if available)
  2. ctypes → libcrypto.so (system OpenSSL, zero pip deps)
"""

import hashlib
import hmac as _hmac
import os
import secrets
from typing import Optional

# ── Backend Selection ────────────────────────────────────────────
# Try `cryptography` first, fall back to ctypes + libcrypto

_BACKEND = None

try:
    # Pre-check: importing cryptography with a broken cffi causes an
    # unrecoverable pyo3 panic. Guard against it. (Fix by 01GceyMR)
    import importlib.util
    if importlib.util.find_spec("_cffi_backend") is None:
        raise ImportError("cffi backend not available")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF as _HKDF
    from cryptography.hazmat.primitives import hashes as _hashes
    _BACKEND = "cryptography"
except Exception:
    pass

if _BACKEND is None:
    try:
        import ctypes
        import ctypes.util
        _libcrypto_path = ctypes.util.find_library("crypto")
        if _libcrypto_path:
            _libcrypto = ctypes.CDLL(_libcrypto_path)
            # Set up function signatures for type safety
            c_void_p = ctypes.c_void_p
            c_int = ctypes.c_int
            c_char_p = ctypes.c_char_p

            _libcrypto.EVP_CIPHER_CTX_new.restype = c_void_p
            _libcrypto.EVP_CIPHER_CTX_new.argtypes = []
            _libcrypto.EVP_CIPHER_CTX_free.restype = None
            _libcrypto.EVP_CIPHER_CTX_free.argtypes = [c_void_p]
            _libcrypto.EVP_aes_256_gcm.restype = c_void_p
            _libcrypto.EVP_aes_256_gcm.argtypes = []

            _libcrypto.EVP_EncryptInit_ex.restype = c_int
            _libcrypto.EVP_EncryptInit_ex.argtypes = [c_void_p, c_void_p, c_void_p, c_char_p, c_char_p]
            _libcrypto.EVP_EncryptUpdate.restype = c_int
            _libcrypto.EVP_EncryptUpdate.argtypes = [c_void_p, c_char_p, ctypes.POINTER(c_int), c_char_p, c_int]
            _libcrypto.EVP_EncryptFinal_ex.restype = c_int
            _libcrypto.EVP_EncryptFinal_ex.argtypes = [c_void_p, c_char_p, ctypes.POINTER(c_int)]

            _libcrypto.EVP_DecryptInit_ex.restype = c_int
            _libcrypto.EVP_DecryptInit_ex.argtypes = [c_void_p, c_void_p, c_void_p, c_char_p, c_char_p]
            _libcrypto.EVP_DecryptUpdate.restype = c_int
            _libcrypto.EVP_DecryptUpdate.argtypes = [c_void_p, c_char_p, ctypes.POINTER(c_int), c_char_p, c_int]
            _libcrypto.EVP_DecryptFinal_ex.restype = c_int
            _libcrypto.EVP_DecryptFinal_ex.argtypes = [c_void_p, c_char_p, ctypes.POINTER(c_int)]

            _libcrypto.EVP_CIPHER_CTX_ctrl.restype = c_int
            _libcrypto.EVP_CIPHER_CTX_ctrl.argtypes = [c_void_p, c_int, c_int, c_void_p]

            _libcrypto.EVP_aes_256_gcm()  # Verify it exists
            _BACKEND = "libcrypto"
    except Exception:
        pass

if _BACKEND is None:
    raise ImportError(
        "No crypto backend available. Install 'cryptography' pip package "
        "or ensure libcrypto.so (OpenSSL) is on your system."
    )


# ── Pure Python HKDF-SHA256 (used by libcrypto backend) ─────────

def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract: PRK = HMAC-SHA256(salt, ikm)"""
    if not salt:
        salt = b"\x00" * 32
    return _hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand: OKM = T(1) || T(2) || ... truncated to length"""
    n = (length + 31) // 32
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = _hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


def _hkdf_derive(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """Full HKDF: extract then expand."""
    prk = _hkdf_extract(salt, ikm)
    return _hkdf_expand(prk, info, length)


# ── Key Derivation ──────────────────────────────────────────────

def derive_room_key(shared_secret: str, room_id: str) -> bytes:
    """Derive a 256-bit room key from a shared secret using HKDF.

    Uses the room_id as salt so the same secret produces different keys
    for different rooms. This prevents cross-room key reuse attacks.
    """
    if _BACKEND == "cryptography":
        hkdf = _HKDF(
            algorithm=_hashes.SHA256(),
            length=32,
            salt=room_id.encode("utf-8"),
            info=b"agora-room-key-v1",
        )
        return hkdf.derive(shared_secret.encode("utf-8"))
    else:
        return _hkdf_derive(
            shared_secret.encode("utf-8"),
            room_id.encode("utf-8"),
            b"agora-room-key-v1",
        )


def derive_message_keys(room_key: bytes) -> tuple[bytes, bytes]:
    """Derive separate encryption and MAC keys from the room key."""
    if _BACKEND == "cryptography":
        enc_key = _HKDF(
            algorithm=_hashes.SHA256(), length=32, salt=None, info=b"agora-enc-v1",
        ).derive(room_key)
        mac_key = _HKDF(
            algorithm=_hashes.SHA256(), length=32, salt=None, info=b"agora-mac-v1",
        ).derive(room_key)
    else:
        enc_key = _hkdf_derive(room_key, b"", b"agora-enc-v1")
        mac_key = _hkdf_derive(room_key, b"", b"agora-mac-v1")
    return enc_key, mac_key


# ── Forward Secrecy Ratchet ─────────────────────────────────────

def ratchet_key(current_key: bytes) -> bytes:
    """Advance the key one step forward using a hash ratchet."""
    if _BACKEND == "cryptography":
        return _HKDF(
            algorithm=_hashes.SHA256(), length=32, salt=None, info=b"agora-ratchet-v1",
        ).derive(current_key)
    else:
        return _hkdf_derive(current_key, b"", b"agora-ratchet-v1")


# ── AES-256-GCM via libcrypto ctypes ────────────────────────────

def _libcrypto_encrypt(plaintext: bytes, key: bytes, nonce: bytes, aad: bytes) -> bytes:
    """AES-256-GCM encrypt via ctypes → libcrypto.so"""
    ctx = _libcrypto.EVP_CIPHER_CTX_new()
    if not ctx:
        raise RuntimeError("EVP_CIPHER_CTX_new failed")
    try:
        cipher = _libcrypto.EVP_aes_256_gcm()
        outlen = ctypes.c_int(0)

        _libcrypto.EVP_EncryptInit_ex(ctx, cipher, None, None, None)
        _libcrypto.EVP_CIPHER_CTX_ctrl(ctx, 0x9, len(nonce), nonce)  # SET_IVLEN
        _libcrypto.EVP_EncryptInit_ex(ctx, None, None, key, nonce)

        if aad:
            _libcrypto.EVP_EncryptUpdate(ctx, None, ctypes.byref(outlen), aad, len(aad))

        ct_buf = (ctypes.c_char * (len(plaintext) + 32))()
        _libcrypto.EVP_EncryptUpdate(ctx, ct_buf, ctypes.byref(outlen), plaintext, len(plaintext))
        ct_len = outlen.value

        final_buf = (ctypes.c_char * 32)()
        _libcrypto.EVP_EncryptFinal_ex(ctx, final_buf, ctypes.byref(outlen))
        ct_len += outlen.value

        tag = (ctypes.c_char * 16)()
        _libcrypto.EVP_CIPHER_CTX_ctrl(ctx, 0x10, 16, tag)  # GET_TAG

        return bytes(ct_buf)[:ct_len] + bytes(tag)
    finally:
        _libcrypto.EVP_CIPHER_CTX_free(ctx)


def _libcrypto_decrypt(ciphertext_with_tag: bytes, key: bytes, nonce: bytes, aad: bytes) -> bytes:
    """AES-256-GCM decrypt via ctypes → libcrypto.so"""
    if len(ciphertext_with_tag) < 16:
        raise ValueError("Ciphertext too short")

    ct = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]

    ctx = _libcrypto.EVP_CIPHER_CTX_new()
    if not ctx:
        raise RuntimeError("EVP_CIPHER_CTX_new failed")
    try:
        cipher = _libcrypto.EVP_aes_256_gcm()
        outlen = ctypes.c_int(0)

        _libcrypto.EVP_DecryptInit_ex(ctx, cipher, None, None, None)
        _libcrypto.EVP_CIPHER_CTX_ctrl(ctx, 0x9, len(nonce), nonce)  # SET_IVLEN
        _libcrypto.EVP_DecryptInit_ex(ctx, None, None, key, nonce)

        if aad:
            _libcrypto.EVP_DecryptUpdate(ctx, None, ctypes.byref(outlen), aad, len(aad))

        pt_buf = (ctypes.c_char * (len(ct) + 32))()
        _libcrypto.EVP_DecryptUpdate(ctx, pt_buf, ctypes.byref(outlen), ct, len(ct))
        pt_len = outlen.value

        tag_buf = (ctypes.c_char * 16)(*tag)
        _libcrypto.EVP_CIPHER_CTX_ctrl(ctx, 0x11, 16, tag_buf)  # SET_TAG

        final_buf = (ctypes.c_char * 32)()
        ret = _libcrypto.EVP_DecryptFinal_ex(ctx, final_buf, ctypes.byref(outlen))
        if ret != 1:
            raise RuntimeError("Decryption failed (wrong key or tampered)")
        pt_len += outlen.value

        return bytes(pt_buf)[:pt_len]
    finally:
        _libcrypto.EVP_CIPHER_CTX_free(ctx)


# ── Authenticated Encryption (unified API) ──────────────────────

def encrypt(plaintext: bytes, key: bytes, associated_data: bytes = b"") -> bytes:
    """Encrypt with AES-256-GCM.

    Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
    """
    nonce = os.urandom(12)
    if _BACKEND == "cryptography":
        aesgcm = _AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data or None)
    else:
        ciphertext = _libcrypto_encrypt(plaintext, key, nonce, associated_data)
    return nonce + ciphertext


def decrypt(blob: bytes, key: bytes, associated_data: bytes = b"") -> bytes:
    """Decrypt AES-256-GCM.

    Input: nonce (12 bytes) || ciphertext || tag (16 bytes)
    Raises on tamper/wrong key.
    """
    nonce = blob[:12]
    ciphertext = blob[12:]
    if _BACKEND == "cryptography":
        aesgcm = _AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data or None)
    else:
        return _libcrypto_decrypt(ciphertext, key, nonce, associated_data)


# ── Zero-Knowledge Room Membership Proof ────────────────────────

def zkp_create_commitment(room_key: bytes) -> tuple[bytes, bytes]:
    """Create a ZKP commitment. Returns (nonce, commitment)."""
    nonce = os.urandom(32)
    commitment = _hmac.new(room_key, nonce, hashlib.sha256).digest()
    return nonce, commitment


def zkp_create_challenge() -> bytes:
    """Create a random challenge for the prover."""
    return os.urandom(32)


def zkp_respond(room_key: bytes, nonce: bytes, challenge: bytes) -> bytes:
    """Prover responds to challenge, proving key knowledge."""
    return _hmac.new(room_key, nonce + challenge, hashlib.sha256).digest()


def zkp_verify(room_key: bytes, nonce: bytes, challenge: bytes, response: bytes) -> bool:
    """Verify a ZKP response. Returns True if the prover knows the key."""
    expected = _hmac.new(room_key, nonce + challenge, hashlib.sha256).digest()
    return _hmac.compare_digest(expected, response)


# ── Key Generation Utilities ────────────────────────────────────

def generate_room_id() -> str:
    """Generate a random room identifier."""
    return "ag-" + secrets.token_hex(8)


def generate_secret() -> str:
    """Generate a 256-bit shared secret as hex string."""
    return secrets.token_hex(32)


def fingerprint(key: bytes) -> str:
    """Human-readable key fingerprint for verification."""
    digest = hashlib.sha256(key).hexdigest()
    return " ".join(digest[i:i+4] for i in range(0, 32, 4))


def backend() -> str:
    """Return which crypto backend is active."""
    return _BACKEND
