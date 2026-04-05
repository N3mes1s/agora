"""Tests for agora.chat — envelope and encryption integration."""

import json
import os
import pytest
from unittest.mock import patch

from agora.chat import (
    _make_envelope,
    _parse_envelope,
    _encrypt_envelope,
    _decrypt_payload,
)
from agora.crypto import derive_room_key


class TestEnvelope:
    def test_make_envelope(self):
        with patch("agora.store.get_agent_id", return_value="test1234"):
            env = _make_envelope("hello world")
        assert env["v"] == "3.0"
        assert env["text"] == "hello world"
        assert env["from"] == "test1234"
        assert len(env["id"]) == 8
        assert "ts" in env

    def test_make_envelope_with_reply(self):
        with patch("agora.store.get_agent_id", return_value="test1234"):
            env = _make_envelope("reply text", reply_to="abcd1234")
        assert env["reply_to"] == "abcd1234"

    def test_parse_v3_envelope(self):
        raw = json.dumps({"v": "3.0", "id": "abc", "from": "x", "ts": 1, "text": "hi"})
        env = _parse_envelope(raw)
        assert env["text"] == "hi"
        assert env["v"] == "3.0"

    def test_parse_v1_fallback(self):
        env = _parse_envelope("agent123: hello there")
        assert env["from"] == "agent123"
        assert env["text"] == "hello there"
        assert env["v"] == "1.0"


class TestEncryptDecrypt:
    def test_roundtrip(self):
        room_id = "ag-test123"
        secret = "supersecret" * 3
        room_key = derive_room_key(secret, room_id)

        with patch("agora.store.get_agent_id", return_value="test1234"):
            env = _make_envelope("confidential message")

        encrypted = _encrypt_envelope(env, room_key, room_id)
        decrypted = _decrypt_payload(encrypted, room_key, room_id)

        assert decrypted is not None
        assert decrypted["text"] == "confidential message"
        assert decrypted["from"] == "test1234"

    def test_wrong_key_returns_none(self):
        room_id = "ag-test123"
        key1 = derive_room_key("secret1", room_id)
        key2 = derive_room_key("secret2", room_id)

        with patch("agora.store.get_agent_id", return_value="test1234"):
            env = _make_envelope("secret")
        encrypted = _encrypt_envelope(env, key1, room_id)
        result = _decrypt_payload(encrypted, key2, room_id)
        assert result is None

    def test_wrong_room_id_returns_none(self):
        secret = "shared_secret_123"
        key_a = derive_room_key(secret, "room-a")
        key_b = derive_room_key(secret, "room-b")

        with patch("agora.store.get_agent_id", return_value="test1234"):
            env = _make_envelope("secret")
        encrypted = _encrypt_envelope(env, key_a, "room-a")
        # Decrypt with correct key derivation but wrong room AAD
        result = _decrypt_payload(encrypted, key_b, "room-b")
        assert result is None

    def test_plaintext_not_in_ciphertext(self):
        room_id = "ag-test"
        room_key = derive_room_key("secret", room_id)

        with patch("agora.store.get_agent_id", return_value="test1234"):
            env = _make_envelope("this is very secret")
        encrypted = _encrypt_envelope(env, room_key, room_id)
        assert "this is very secret" not in encrypted
