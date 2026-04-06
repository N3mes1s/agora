"""Tests for agora_chat.client."""

import json
import base64
import pytest
from unittest.mock import patch, MagicMock

from agora_chat import AgoraClient
from agora_chat.crypto import derive_room_key, derive_message_keys, decrypt, encrypt_envelope


ROOM_ID = "ag-testdeadbeef01"
SECRET = "b" * 64


def _make_encrypted_message(room_id: str, secret: str, text: str, sender: str = "other-agent", msg_id: str = "aabbccdd") -> str:
    """Helper to create a valid encrypted message payload."""
    room_key = derive_room_key(secret, room_id)
    envelope = {
        "v": "3.0",
        "id": msg_id,
        "from": sender,
        "ts": 1700000000,
        "text": text,
    }
    return encrypt_envelope(envelope, room_key, room_id)


class TestClientJoin:
    def test_join_sets_room(self):
        client = AgoraClient(agent_id="test-agent")
        with patch("agora_chat.transport.publish", return_value=True):
            room = client.join(ROOM_ID, SECRET, "testroom")
        assert room.room_id == ROOM_ID
        assert room.label == "testroom"
        assert client.room.room_id == ROOM_ID

    def test_join_publishes_join_message(self):
        client = AgoraClient(agent_id="test-agent")
        with patch("agora_chat.transport.publish", return_value=True) as mock_pub:
            client.join(ROOM_ID, SECRET, "testroom")
        mock_pub.assert_called_once()
        _, payload = mock_pub.call_args[0]
        # Decrypt and verify join announcement
        room_key = derive_room_key(SECRET, ROOM_ID)
        from agora_chat.crypto import decrypt_payload
        env = decrypt_payload(payload, room_key, ROOM_ID)
        assert env is not None
        assert "Joined" in env["text"]

    def test_fingerprint_after_join(self):
        client = AgoraClient(agent_id="test-agent")
        with patch("agora_chat.transport.publish", return_value=True):
            client.join(ROOM_ID, SECRET, "testroom")
        fp = client.fingerprint()
        parts = fp.split(" ")
        assert len(parts) == 8


class TestClientSend:
    def setup_method(self):
        self.client = AgoraClient(agent_id="test-agent")
        with patch("agora_chat.transport.publish", return_value=True):
            self.client.join(ROOM_ID, SECRET, "testroom")

    def test_send_returns_message_id(self):
        with patch("agora_chat.transport.publish", return_value=True):
            msg_id = self.client.send("Hello!")
        assert isinstance(msg_id, str)
        assert len(msg_id) == 8  # 4 bytes hex

    def test_send_publishes_encrypted_payload(self):
        with patch("agora_chat.transport.publish", return_value=True) as mock_pub:
            self.client.send("Test message")
        mock_pub.assert_called_once()
        topic, payload = mock_pub.call_args[0]
        assert topic == ROOM_ID
        # Verify it's valid encrypted content
        from agora_chat.crypto import decrypt_payload
        room_key = derive_room_key(SECRET, ROOM_ID)
        env = decrypt_payload(payload, room_key, ROOM_ID)
        assert env is not None
        assert env["text"] == "Test message"
        assert env["from"] == "test-agent"

    def test_send_with_reply_to(self):
        with patch("agora_chat.transport.publish", return_value=True) as mock_pub:
            self.client.send("Reply!", reply_to="parent-id")
        _, payload = mock_pub.call_args[0]
        from agora_chat.crypto import decrypt_payload
        room_key = derive_room_key(SECRET, ROOM_ID)
        env = decrypt_payload(payload, room_key, ROOM_ID)
        assert env["reply_to"] == "parent-id"

    def test_send_without_room_raises(self):
        client = AgoraClient(agent_id="orphan")
        with pytest.raises(RuntimeError):
            client.send("No room!")


class TestClientCheck:
    def setup_method(self):
        self.client = AgoraClient(agent_id="test-agent")
        with patch("agora_chat.transport.publish", return_value=True):
            self.client.join(ROOM_ID, SECRET, "testroom")

    def test_check_returns_messages(self):
        payload = _make_encrypted_message(ROOM_ID, SECRET, "Hi there!", "other-agent", "msg00001")
        with patch("agora_chat.transport.fetch", return_value=[(1700000000, payload)]):
            messages = self.client.check(mark_seen=False)
        assert len(messages) == 1
        assert messages[0].text == "Hi there!"
        assert messages[0].sender == "other-agent"

    def test_check_deduplicates_seen(self):
        payload = _make_encrypted_message(ROOM_ID, SECRET, "Hi there!", "other-agent", "msg00002")
        with patch("agora_chat.transport.fetch", return_value=[(1700000000, payload)]):
            msgs1 = self.client.check(mark_seen=True)
            msgs2 = self.client.check(mark_seen=True)
        assert len(msgs1) == 1
        assert len(msgs2) == 0  # already seen

    def test_check_skips_heartbeats(self):
        room_key = derive_room_key(SECRET, ROOM_ID)
        hb_env = {
            "v": "3.0",
            "id": "heartbeat1",
            "from": "other",
            "ts": 1700000000,
            "type": "heartbeat",
            "text": "",
        }
        hb_payload = encrypt_envelope(hb_env, room_key, ROOM_ID)
        with patch("agora_chat.transport.fetch", return_value=[(1700000000, hb_payload)]):
            messages = self.client.check(mark_seen=False)
        assert len(messages) == 0

    def test_check_skips_undecryptable_messages(self):
        with patch("agora_chat.transport.fetch", return_value=[(0, "not-valid-base64!!!!")]):
            messages = self.client.check(mark_seen=False)
        assert len(messages) == 0

    def test_check_empty_room(self):
        with patch("agora_chat.transport.fetch", return_value=[]):
            messages = self.client.check()
        assert messages == []


class TestClientHeartbeat:
    def setup_method(self):
        self.client = AgoraClient(agent_id="test-agent")
        with patch("agora_chat.transport.publish", return_value=True):
            self.client.join(ROOM_ID, SECRET, "testroom")

    def test_heartbeat_publishes_correct_type(self):
        with patch("agora_chat.transport.publish", return_value=True) as mock_pub:
            ok = self.client.heartbeat()
        assert ok is True
        _, payload = mock_pub.call_args[0]
        room_key = derive_room_key(SECRET, ROOM_ID)
        from agora_chat.crypto import decrypt_payload
        env = decrypt_payload(payload, room_key, ROOM_ID)
        assert env["type"] == "heartbeat"
        assert env["text"] == ""


class TestClientReact:
    def setup_method(self):
        self.client = AgoraClient(agent_id="test-agent")
        with patch("agora_chat.transport.publish", return_value=True):
            self.client.join(ROOM_ID, SECRET, "testroom")

    def test_react_sends_reaction_envelope(self):
        with patch("agora_chat.transport.publish", return_value=True) as mock_pub:
            self.client.react("msg12345", "👍")
        _, payload = mock_pub.call_args[0]
        room_key = derive_room_key(SECRET, ROOM_ID)
        from agora_chat.crypto import decrypt_payload
        env = decrypt_payload(payload, room_key, ROOM_ID)
        assert env["type"] == "reaction"
        assert env["target_id"] == "msg12345"
        assert env["emoji"] == "👍"


class TestClientCreate:
    def test_create_returns_room(self):
        client = AgoraClient(agent_id="test-agent")
        with patch("agora_chat.transport.publish", return_value=True):
            room = client.create("newroom")
        assert room.room_id.startswith("ag-")
        assert room.label == "newroom"
        assert len(room.secret) == 64

    def test_create_allows_subsequent_send(self):
        client = AgoraClient(agent_id="test-agent")
        with patch("agora_chat.transport.publish", return_value=True):
            client.create("newroom")
            msg_id = client.send("First message!")
        assert isinstance(msg_id, str)


class TestContextManager:
    def test_context_manager(self):
        with AgoraClient(agent_id="ctx-test") as client:
            with patch("agora_chat.transport.publish", return_value=True):
                client.join(ROOM_ID, SECRET)
                client.send("hello from context manager")


class TestModels:
    def test_message_from_envelope(self):
        from agora_chat.models import Message
        env = {
            "v": "3.0",
            "id": "deadbeef",
            "from": "alice",
            "ts": 1700000000,
            "text": "Hello!",
        }
        msg = Message.from_envelope(env)
        assert msg.id == "deadbeef"
        assert msg.sender == "alice"
        assert msg.text == "Hello!"
        assert msg.timestamp == 1700000000
        assert not msg.is_system

    def test_heartbeat_is_system(self):
        from agora_chat.models import Message
        env = {"id": "x", "from": "a", "ts": 0, "text": "", "type": "heartbeat"}
        msg = Message.from_envelope(env)
        assert msg.is_system

    def test_receipt_is_system(self):
        from agora_chat.models import Message
        env = {"id": "x", "from": "a", "ts": 0, "text": "", "type": "receipt"}
        msg = Message.from_envelope(env)
        assert msg.is_system

    def test_regular_message_not_system(self):
        from agora_chat.models import Message
        msg = Message(id="x", sender="a", text="hi", timestamp=0)
        assert not msg.is_system
