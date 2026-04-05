"""Tests for agora.crypto — the cryptographic core."""

import os
import pytest
from agora.crypto import (
    derive_room_key,
    derive_message_keys,
    ratchet_key,
    encrypt,
    decrypt,
    zkp_create_commitment,
    zkp_create_challenge,
    zkp_respond,
    zkp_verify,
    generate_room_id,
    generate_secret,
    fingerprint,
)


class TestKeyDerivation:
    def test_derive_room_key_deterministic(self):
        key1 = derive_room_key("secret123", "room-abc")
        key2 = derive_room_key("secret123", "room-abc")
        assert key1 == key2

    def test_derive_room_key_different_secrets(self):
        key1 = derive_room_key("secret1", "room-abc")
        key2 = derive_room_key("secret2", "room-abc")
        assert key1 != key2

    def test_derive_room_key_different_rooms(self):
        """Same secret, different rooms → different keys."""
        key1 = derive_room_key("secret", "room-a")
        key2 = derive_room_key("secret", "room-b")
        assert key1 != key2

    def test_derive_room_key_length(self):
        key = derive_room_key("secret", "room")
        assert len(key) == 32  # 256 bits

    def test_derive_message_keys_separate(self):
        room_key = derive_room_key("secret", "room")
        enc_key, mac_key = derive_message_keys(room_key)
        assert len(enc_key) == 32
        assert len(mac_key) == 32
        assert enc_key != mac_key


class TestRatchet:
    def test_ratchet_advances(self):
        key = os.urandom(32)
        next_key = ratchet_key(key)
        assert next_key != key
        assert len(next_key) == 32

    def test_ratchet_deterministic(self):
        key = os.urandom(32)
        assert ratchet_key(key) == ratchet_key(key)

    def test_ratchet_chain(self):
        """Forward secrecy: each step produces a unique key."""
        key = os.urandom(32)
        keys = [key]
        for _ in range(10):
            key = ratchet_key(key)
            assert key not in keys
            keys.append(key)


class TestEncryption:
    def test_encrypt_decrypt_roundtrip(self):
        key = os.urandom(32)
        plaintext = b"Hello, world!"
        blob = encrypt(plaintext, key)
        result = decrypt(blob, key)
        assert result == plaintext

    def test_encrypt_with_aad(self):
        key = os.urandom(32)
        plaintext = b"secret message"
        aad = b"room-123"
        blob = encrypt(plaintext, key, aad)
        result = decrypt(blob, key, aad)
        assert result == plaintext

    def test_wrong_key_fails(self):
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        blob = encrypt(b"test", key1)
        with pytest.raises(Exception):
            decrypt(blob, key2)

    def test_tampered_ciphertext_fails(self):
        key = os.urandom(32)
        blob = encrypt(b"test", key)
        # Flip a byte in the ciphertext
        tampered = blob[:20] + bytes([blob[20] ^ 0xFF]) + blob[21:]
        with pytest.raises(Exception):
            decrypt(tampered, key)

    def test_wrong_aad_fails(self):
        key = os.urandom(32)
        blob = encrypt(b"test", key, b"room-a")
        with pytest.raises(Exception):
            decrypt(blob, key, b"room-b")

    def test_nonce_uniqueness(self):
        """Each encryption should use a different nonce."""
        key = os.urandom(32)
        blob1 = encrypt(b"test", key)
        blob2 = encrypt(b"test", key)
        # First 12 bytes are the nonce
        assert blob1[:12] != blob2[:12]

    def test_ciphertext_not_plaintext(self):
        key = os.urandom(32)
        plaintext = b"this should not be visible"
        blob = encrypt(plaintext, key)
        assert plaintext not in blob


class TestZKP:
    def test_valid_proof(self):
        key = os.urandom(32)
        nonce, commitment = zkp_create_commitment(key)
        challenge = zkp_create_challenge()
        response = zkp_respond(key, nonce, challenge)
        assert zkp_verify(key, nonce, challenge, response)

    def test_wrong_key_fails(self):
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        nonce, _ = zkp_create_commitment(key1)
        challenge = zkp_create_challenge()
        response = zkp_respond(key1, nonce, challenge)
        assert not zkp_verify(key2, nonce, challenge, response)

    def test_wrong_response_fails(self):
        key = os.urandom(32)
        nonce, _ = zkp_create_commitment(key)
        challenge = zkp_create_challenge()
        fake_response = os.urandom(32)
        assert not zkp_verify(key, nonce, challenge, fake_response)


class TestUtilities:
    def test_room_id_format(self):
        rid = generate_room_id()
        assert rid.startswith("ag-")
        assert len(rid) == 19  # "ag-" + 16 hex chars

    def test_secret_length(self):
        s = generate_secret()
        assert len(s) == 64  # 32 bytes = 64 hex chars

    def test_fingerprint_readable(self):
        key = os.urandom(32)
        fp = fingerprint(key)
        parts = fp.split(" ")
        assert len(parts) == 8
        assert all(len(p) == 4 for p in parts)

    def test_fingerprint_deterministic(self):
        key = os.urandom(32)
        assert fingerprint(key) == fingerprint(key)

    def test_fingerprint_different_keys(self):
        assert fingerprint(os.urandom(32)) != fingerprint(os.urandom(32))
