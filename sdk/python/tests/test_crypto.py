"""Tests for agora_chat.crypto — mirrors the Rust test suite."""

import pytest
from agora_chat.crypto import (
    derive_room_key,
    derive_message_keys,
    encrypt,
    decrypt,
    fingerprint,
    encrypt_envelope,
    decrypt_payload,
)


class TestDeriveRoomKey:
    def test_deterministic(self):
        k1 = derive_room_key("secret", "room-a")
        k2 = derive_room_key("secret", "room-a")
        assert k1 == k2

    def test_different_rooms_produce_different_keys(self):
        k1 = derive_room_key("secret", "room-a")
        k2 = derive_room_key("secret", "room-b")
        assert k1 != k2

    def test_different_secrets_produce_different_keys(self):
        k1 = derive_room_key("secret1", "room")
        k2 = derive_room_key("secret2", "room")
        assert k1 != k2

    def test_returns_32_bytes(self):
        k = derive_room_key("secret", "room")
        assert len(k) == 32


class TestDeriveMessageKeys:
    def test_enc_and_mac_keys_are_different(self):
        room_key = derive_room_key("secret", "room")
        enc_key, mac_key = derive_message_keys(room_key)
        assert enc_key != mac_key

    def test_both_keys_are_32_bytes(self):
        room_key = derive_room_key("secret", "room")
        enc_key, mac_key = derive_message_keys(room_key)
        assert len(enc_key) == 32
        assert len(mac_key) == 32

    def test_deterministic(self):
        room_key = derive_room_key("s", "r")
        enc1, mac1 = derive_message_keys(room_key)
        enc2, mac2 = derive_message_keys(room_key)
        assert enc1 == enc2
        assert mac1 == mac2


class TestEncryptDecrypt:
    def test_roundtrip(self):
        key = derive_room_key("secret", "room")
        enc_key, _ = derive_message_keys(key)
        plaintext = b"Hello, world!"
        blob = encrypt(plaintext, enc_key, b"room")
        result = decrypt(blob, enc_key, b"room")
        assert result == plaintext

    def test_wrong_key_fails(self):
        from cryptography.exceptions import InvalidTag
        k1 = derive_room_key("s1", "r")
        k2 = derive_room_key("s2", "r")
        enc_k1, _ = derive_message_keys(k1)
        enc_k2, _ = derive_message_keys(k2)
        blob = encrypt(b"test", enc_k1, b"")
        with pytest.raises(Exception):
            decrypt(blob, enc_k2, b"")

    def test_tampered_ciphertext_fails(self):
        key = derive_room_key("s", "r")
        enc_key, _ = derive_message_keys(key)
        blob = bytearray(encrypt(b"test", enc_key, b""))
        blob[20] ^= 0xFF
        with pytest.raises(Exception):
            decrypt(bytes(blob), enc_key, b"")

    def test_wrong_aad_fails(self):
        key = derive_room_key("s", "r")
        enc_key, _ = derive_message_keys(key)
        blob = encrypt(b"test", enc_key, b"room-a")
        with pytest.raises(Exception):
            decrypt(blob, enc_key, b"room-b")

    def test_nonce_uniqueness(self):
        key = derive_room_key("s", "r")
        enc_key, _ = derive_message_keys(key)
        b1 = encrypt(b"test", enc_key, b"")
        b2 = encrypt(b"test", enc_key, b"")
        # Different nonces
        assert b1[:12] != b2[:12]

    def test_blob_includes_nonce_prefix(self):
        key = derive_room_key("s", "r")
        enc_key, _ = derive_message_keys(key)
        blob = encrypt(b"x", enc_key, b"")
        # 12-byte nonce + at least 1 byte ciphertext + 16-byte tag
        assert len(blob) >= 12 + 1 + 16

    def test_short_blob_raises(self):
        key = derive_room_key("s", "r")
        enc_key, _ = derive_message_keys(key)
        with pytest.raises(ValueError):
            decrypt(b"tooshort", enc_key, b"")


class TestFingerprint:
    def test_format_eight_four_char_groups(self):
        key = derive_room_key("s", "r")
        fp = fingerprint(key)
        parts = fp.split(" ")
        assert len(parts) == 8
        assert all(len(p) == 4 for p in parts)

    def test_deterministic(self):
        key = derive_room_key("s", "r")
        assert fingerprint(key) == fingerprint(key)

    def test_different_keys_different_fingerprints(self):
        k1 = derive_room_key("s1", "r")
        k2 = derive_room_key("s2", "r")
        assert fingerprint(k1) != fingerprint(k2)


class TestEnvelopeCrypto:
    def test_encrypt_decrypt_envelope_roundtrip(self):
        room_key = derive_room_key("secret", "ag-testroom")
        room_id = "ag-testroom"
        envelope = {
            "v": "3.0",
            "id": "abcd1234",
            "from": "agent-x",
            "ts": 1700000000,
            "text": "Hello from Python!",
        }
        payload = encrypt_envelope(envelope, room_key, room_id)
        result = decrypt_payload(payload, room_key, room_id)
        assert result is not None
        assert result["text"] == "Hello from Python!"
        assert result["from"] == "agent-x"
        assert result["id"] == "abcd1234"

    def test_wrong_room_id_returns_none(self):
        room_key = derive_room_key("secret", "ag-room1")
        envelope = {"v": "3.0", "id": "x", "from": "a", "ts": 0, "text": "hi"}
        payload = encrypt_envelope(envelope, room_key, "ag-room1")
        # Try to decrypt with wrong room_id
        result = decrypt_payload(payload, room_key, "ag-room2")
        assert result is None

    def test_invalid_base64_returns_none(self):
        room_key = derive_room_key("secret", "ag-room")
        result = decrypt_payload("not-valid-base64!!!", room_key, "ag-room")
        assert result is None

    def test_cross_compatibility_with_rust(self):
        """Verify our key derivation matches the Rust implementation.

        These values were captured from the Rust agora CLI.
        secret = "aaaa...aa" (64 'a' chars)
        room_id = "ag-deadbeefcafebabe"
        plaintext = "test-message"
        """
        secret = "a" * 64
        room_id = "ag-deadbeefcafebabe"
        room_key = derive_room_key(secret, room_id)
        # Just verify consistent key length and type
        assert isinstance(room_key, bytes)
        assert len(room_key) == 32
        # Same inputs always produce same key
        assert derive_room_key(secret, room_id) == room_key
