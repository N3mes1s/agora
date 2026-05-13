"""Tests for agora_chat.client."""

import json
import base64
import os
import shutil
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from agora_chat import AgoraClient, transport
from agora_chat.crypto import derive_room_key, derive_message_keys, decrypt, encrypt_envelope


ROOM_ID = "ag-testdeadbeef01"
SECRET = "b" * 64


def _make_encrypted_message(
    room_id: str,
    secret: str,
    text: str,
    sender: str = "other-agent",
    msg_id: str = "aabbccdd",
    home: Path | None = None,
) -> str:
    """Helper to create a valid encrypted message payload."""
    room_key = derive_room_key(secret, room_id)
    envelope = {
        "v": "3.0",
        "id": msg_id,
        "from": sender,
        "ts": 1700000000,
        "text": text,
    }
    return encrypt_envelope(envelope, room_key, room_id, home=home)


class TestClientJoin:
    def test_join_sets_room(self, tmp_path):
        client = AgoraClient(agent_id="test-agent", home=tmp_path)
        with patch("agora_chat.transport.publish", return_value=True):
            room = client.join(ROOM_ID, SECRET, "testroom")
        assert room.room_id == ROOM_ID
        assert room.label == "testroom"
        assert client.room.room_id == ROOM_ID

    def test_join_room_returns_session_contract(self, tmp_path):
        client = AgoraClient(agent_id="test-agent", home=tmp_path)
        with patch("agora_chat.transport.publish", return_value=True):
            session = client.join_room(ROOM_ID, SECRET, "testroom")
        assert session.room_id == ROOM_ID
        assert session.label == "testroom"
        assert session.agent_id == "test-agent"
        assert session.metadata.room_id == ROOM_ID

    def test_join_publishes_join_message(self, tmp_path):
        client = AgoraClient(agent_id="test-agent", home=tmp_path)
        with patch("agora_chat.transport.publish", return_value=True) as mock_pub:
            client.join(ROOM_ID, SECRET, "testroom")
        mock_pub.assert_called_once()
        _, payload = mock_pub.call_args[0]
        # Decrypt and verify join announcement
        room_key = derive_room_key(SECRET, ROOM_ID)
        from agora_chat.crypto import decrypt_payload
        env = decrypt_payload(payload, room_key, ROOM_ID, home=tmp_path)
        assert env is not None
        assert "Joined" in env["text"]

    def test_fingerprint_after_join(self, tmp_path):
        client = AgoraClient(agent_id="test-agent", home=tmp_path)
        with patch("agora_chat.transport.publish", return_value=True):
            client.join(ROOM_ID, SECRET, "testroom")
        fp = client.fingerprint()
        parts = fp.split(" ")
        assert len(parts) == 8

    def test_home_is_scoped_to_client(self, tmp_path):
        with patch.dict(os.environ, {}, clear=True):
            client = AgoraClient(home=tmp_path)
        assert client.agent_id
        identity_path = tmp_path / ".agora" / "identity.json"
        assert identity_path.exists()
        identity = json.loads(identity_path.read_text())
        assert identity["key_id"] == client.agent_id
        assert (tmp_path / ".agora" / "signing-keys" / f"{client.agent_id}.pkcs8").exists()

    def test_relay_options_are_passed_to_transport(self, tmp_path):
        client = AgoraClient(
            agent_id="test-agent",
            home=tmp_path,
            relay_url="memory://python-sdk",
            relay_token="secret-token",
            timeout=7,
            nats_stream="AGORA_PROD",
            nats_subject_prefix="prod.agora",
            nats_create_stream=False,
            nats_storage="memory",
            nats_max_bytes=1048576,
            nats_max_age="7d",
        )
        with patch("agora_chat.transport.publish", return_value=True) as mock_pub:
            client.join(ROOM_ID, SECRET, "testroom")
        assert mock_pub.call_args.kwargs["base_url"] == "memory://python-sdk"
        assert mock_pub.call_args.kwargs["token"] == "secret-token"
        assert mock_pub.call_args.kwargs["timeout"] == 7
        settings = mock_pub.call_args.kwargs["nats"]
        assert settings.stream_name == "AGORA_PROD"
        assert settings.subject_prefix == "prod.agora"
        assert settings.create_stream is False
        assert settings.storage == "memory"
        assert settings.max_bytes == 1048576
        assert settings.max_age == 7 * 86400


class TestNatsTransport:
    def test_settings_read_env_overrides(self):
        with patch.dict(
            os.environ,
            {
                "AGORA_NATS_STREAM": "prod.agora/stream",
                "AGORA_NATS_SUBJECT_PREFIX": ".prod/agora.room.",
                "AGORA_NATS_CREATE_STREAM": "false",
                "AGORA_NATS_STORAGE": "memory",
                "AGORA_NATS_MAX_BYTES": "1048576",
                "AGORA_NATS_MAX_AGE": "7d",
            },
            clear=True,
        ):
            settings = transport.NatsSettings.current()
        assert settings.stream_name == "prod_agora_stream"
        assert settings.subject_prefix == "prod_agora.room"
        assert settings.create_stream is False
        assert settings.storage == "memory"
        assert settings.max_bytes == 1048576
        assert settings.max_age == 7 * 86400

    def test_subject_for_topic_is_stable_and_nats_safe(self):
        settings = transport.NatsSettings()
        subject = transport.subject_for_topic(settings, "dm-agent.alice-agent:bob")
        assert subject.startswith("agora.")
        assert " " not in subject
        assert "*" not in subject
        assert ">" not in subject

    def test_nats_start_time_preserves_fractional_seconds(self):
        start = transport._nats_start_time(1700000000)
        assert start.isoformat() == "2023-11-14T22:13:19.999999+00:00"

    def test_publish_dispatches_to_nats_transport(self):
        calls = []

        async def fake_publish(relay_url, token, settings, topic, payload, timeout):
            calls.append((relay_url, token, settings, topic, payload, timeout))

        settings = transport.NatsSettings(stream_name="AGORA_TEST")
        with patch("agora_chat.transport._publish_nats", fake_publish):
            ok = transport.publish(
                ROOM_ID,
                "payload",
                base_url="nats://127.0.0.1:4222",
                token="secret-token",
                timeout=3,
                nats=settings,
            )
        assert ok is True
        assert calls == [
            ("nats://127.0.0.1:4222", "secret-token", settings, ROOM_ID, "payload", 3)
        ]

    def test_fetch_dispatches_to_nats_transport(self):
        async def fake_fetch(relay_url, token, settings, topic, since, timeout):
            assert relay_url == "tls://nats.example:4222"
            assert token == "secret-token"
            assert topic == ROOM_ID
            assert since == "1h"
            assert timeout == 4
            return [(1700000000, "payload")]

        settings = transport.NatsSettings(stream_name="AGORA_TEST")
        with patch("agora_chat.transport._fetch_nats", fake_fetch):
            events = transport.fetch(
                ROOM_ID,
                "1h",
                base_url="tls://nats.example:4222",
                token="secret-token",
                timeout=4,
                nats=settings,
            )
        assert events == [(1700000000, "payload")]


class TestClientSend:
    def setup_method(self):
        self.home = Path(tempfile.mkdtemp(prefix="agora-python-test-"))
        self.client = AgoraClient(agent_id="test-agent", home=self.home)
        with patch("agora_chat.transport.publish", return_value=True):
            self.client.join(ROOM_ID, SECRET, "testroom")

    def teardown_method(self):
        shutil.rmtree(self.home, ignore_errors=True)

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
        env = decrypt_payload(payload, room_key, ROOM_ID, home=self.home)
        assert env is not None
        assert env["text"] == "Test message"
        assert env["from"] == "test-agent"

    def test_send_with_reply_to(self):
        with patch("agora_chat.transport.publish", return_value=True) as mock_pub:
            self.client.send("Reply!", reply_to="parent-id")
        _, payload = mock_pub.call_args[0]
        from agora_chat.crypto import decrypt_payload
        room_key = derive_room_key(SECRET, ROOM_ID)
        env = decrypt_payload(payload, room_key, ROOM_ID, home=self.home)
        assert env["reply_to"] == "parent-id"

    def test_send_json_encodes_application_frame(self):
        frame = {"kind": "req", "id": "frame-1", "body": "payload"}
        with patch("agora_chat.transport.publish", return_value=True) as mock_pub:
            self.client.send_json(frame)
        _, payload = mock_pub.call_args[0]
        from agora_chat.crypto import decrypt_payload
        room_key = derive_room_key(SECRET, ROOM_ID)
        env = decrypt_payload(payload, room_key, ROOM_ID, home=self.home)
        assert json.loads(env["text"]) == frame

    def test_room_session_send_json_encodes_application_frame(self):
        frame = {"kind": "req", "id": "frame-2", "body": "payload"}
        with patch("agora_chat.transport.publish", return_value=True) as mock_pub:
            self.client.session.send_json(frame)
        _, payload = mock_pub.call_args[0]
        from agora_chat.crypto import decrypt_payload
        room_key = derive_room_key(SECRET, ROOM_ID)
        env = decrypt_payload(payload, room_key, ROOM_ID, home=self.home)
        assert json.loads(env["text"]) == frame

    def test_send_without_room_raises(self):
        client = AgoraClient(agent_id="orphan", home=self.home)
        with pytest.raises(RuntimeError):
            client.send("No room!")


class TestClientCheck:
    def setup_method(self):
        self.home = Path(tempfile.mkdtemp(prefix="agora-python-test-"))
        self.client = AgoraClient(agent_id="test-agent", home=self.home)
        with patch("agora_chat.transport.publish", return_value=True):
            self.client.join(ROOM_ID, SECRET, "testroom")

    def teardown_method(self):
        shutil.rmtree(self.home, ignore_errors=True)

    def test_check_returns_messages(self):
        payload = _make_encrypted_message(
            ROOM_ID, SECRET, "Hi there!", "other-agent", "msg00001", home=self.home
        )
        with patch("agora_chat.transport.fetch", return_value=[(1700000000, payload)]):
            messages = self.client.check(mark_seen=False)
        assert len(messages) == 1
        assert messages[0].text == "Hi there!"
        assert messages[0].sender == "other-agent"

    def test_check_deduplicates_seen(self):
        payload = _make_encrypted_message(
            ROOM_ID, SECRET, "Hi there!", "other-agent", "msg00002", home=self.home
        )
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
        hb_payload = encrypt_envelope(hb_env, room_key, ROOM_ID, home=self.home)
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

    def test_read_json_skips_regular_chat(self):
        json_payload = _make_encrypted_message(
            ROOM_ID,
            SECRET,
            json.dumps({"kind": "event", "id": "json-1"}),
            "bridge-agent",
            "msg00003",
            home=self.home,
        )
        plain_payload = _make_encrypted_message(
            ROOM_ID, SECRET, "plain chat", "human-agent", "msg00004", home=self.home
        )
        with patch(
            "agora_chat.transport.fetch",
            return_value=[(1700000000, json_payload), (1700000001, plain_payload)],
        ):
            messages = self.client.read_json()
        assert len(messages) == 1
        assert messages[0].message.sender == "bridge-agent"
        assert messages[0].value == {"kind": "event", "id": "json-1"}

    def test_room_session_fetch_json_skips_regular_chat(self):
        json_payload = _make_encrypted_message(
            ROOM_ID,
            SECRET,
            json.dumps({"kind": "event", "id": "json-2"}),
            "bridge-agent",
            "msg00005",
            home=self.home,
        )
        plain_payload = _make_encrypted_message(
            ROOM_ID, SECRET, "plain chat", "human-agent", "msg00006", home=self.home
        )
        with patch(
            "agora_chat.transport.fetch",
            return_value=[(1700000000, json_payload), (1700000001, plain_payload)],
        ):
            messages = self.client.session.fetch_json()
        assert len(messages) == 1
        assert messages[0].message.sender == "bridge-agent"
        assert messages[0].value == {"kind": "event", "id": "json-2"}


class TestClientHeartbeat:
    def setup_method(self):
        self.home = Path(tempfile.mkdtemp(prefix="agora-python-test-"))
        self.client = AgoraClient(agent_id="test-agent", home=self.home)
        with patch("agora_chat.transport.publish", return_value=True):
            self.client.join(ROOM_ID, SECRET, "testroom")

    def teardown_method(self):
        shutil.rmtree(self.home, ignore_errors=True)

    def test_heartbeat_publishes_correct_type(self):
        with patch("agora_chat.transport.publish", return_value=True) as mock_pub:
            ok = self.client.heartbeat()
        assert ok is True
        _, payload = mock_pub.call_args[0]
        room_key = derive_room_key(SECRET, ROOM_ID)
        from agora_chat.crypto import decrypt_payload
        env = decrypt_payload(payload, room_key, ROOM_ID, home=self.home)
        assert env["type"] == "heartbeat"
        assert env["text"] == ""


class TestClientReact:
    def setup_method(self):
        self.home = Path(tempfile.mkdtemp(prefix="agora-python-test-"))
        self.client = AgoraClient(agent_id="test-agent", home=self.home)
        with patch("agora_chat.transport.publish", return_value=True):
            self.client.join(ROOM_ID, SECRET, "testroom")

    def teardown_method(self):
        shutil.rmtree(self.home, ignore_errors=True)

    def test_react_sends_reaction_envelope(self):
        with patch("agora_chat.transport.publish", return_value=True) as mock_pub:
            self.client.react("msg12345", "👍")
        _, payload = mock_pub.call_args[0]
        room_key = derive_room_key(SECRET, ROOM_ID)
        from agora_chat.crypto import decrypt_payload
        env = decrypt_payload(payload, room_key, ROOM_ID, home=self.home)
        assert env["type"] == "reaction"
        assert env["target_id"] == "msg12345"
        assert env["emoji"] == "👍"


class TestClientCreate:
    def test_create_returns_room(self, tmp_path):
        client = AgoraClient(agent_id="test-agent", home=tmp_path)
        with patch("agora_chat.transport.publish", return_value=True):
            room = client.create("newroom")
        assert room.room_id.startswith("ag-")
        assert room.label == "newroom"
        assert len(room.secret) == 64

    def test_create_room_returns_session_contract(self, tmp_path):
        client = AgoraClient(agent_id="test-agent", home=tmp_path)
        with patch("agora_chat.transport.publish", return_value=True):
            session = client.create_room("newroom")
        assert session.room_id.startswith("ag-")
        assert session.label == "newroom"
        assert session.agent_id == "test-agent"

    def test_create_allows_subsequent_send(self, tmp_path):
        client = AgoraClient(agent_id="test-agent", home=tmp_path)
        with patch("agora_chat.transport.publish", return_value=True):
            client.create("newroom")
            msg_id = client.send("First message!")
        assert isinstance(msg_id, str)


class TestContextManager:
    def test_context_manager(self, tmp_path):
        with AgoraClient(agent_id="ctx-test", home=tmp_path) as client:
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
