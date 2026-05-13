"""Agora transport layer.

E2E encrypted before hitting the wire. Relays only see ciphertext.
"""

from __future__ import annotations

import asyncio
import base64
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
import os
import secrets
import ssl
import threading
from typing import Iterator
import requests

DEFAULT_RELAY_URL = "https://ntfy.theagora.dev"
DEFAULT_TIMEOUT = 15
DEFAULT_NATS_STREAM = "AGORA"
DEFAULT_NATS_SUBJECT_PREFIX = "agora"
NATS_FETCH_BATCH_SIZE = 256
NATS_FETCH_TIMEOUT = 1.0
NATS_STREAM_FETCH_TIMEOUT = 5.0
NATS_CONSUMER_INACTIVE_THRESHOLD = 10.0


@dataclass(frozen=True)
class NatsSettings:
    stream_name: str = DEFAULT_NATS_STREAM
    subject_prefix: str = DEFAULT_NATS_SUBJECT_PREFIX
    create_stream: bool = True
    storage: str = "file"
    max_bytes: int = 0
    max_age: float = 0.0

    @property
    def stream_subject(self) -> str:
        return f"{self.subject_prefix}.>"

    @classmethod
    def current(
        cls,
        stream_name: str | None = None,
        subject_prefix: str | None = None,
        create_stream: bool | str | None = None,
        storage: str | None = None,
        max_bytes: int | str | None = None,
        max_age: int | float | str | None = None,
    ) -> "NatsSettings":
        return cls(
            stream_name=normalize_stream_name(
                stream_name or os.environ.get("AGORA_NATS_STREAM") or DEFAULT_NATS_STREAM
            ),
            subject_prefix=normalize_subject_prefix(
                subject_prefix
                or os.environ.get("AGORA_NATS_SUBJECT_PREFIX")
                or DEFAULT_NATS_SUBJECT_PREFIX
            ),
            create_stream=parse_bool(
                create_stream
                if create_stream is not None
                else os.environ.get("AGORA_NATS_CREATE_STREAM"),
                True,
            ),
            storage=parse_storage(storage or os.environ.get("AGORA_NATS_STORAGE")),
            max_bytes=parse_nonnegative_int(
                max_bytes if max_bytes is not None else os.environ.get("AGORA_NATS_MAX_BYTES")
            ),
            max_age=parse_duration(
                max_age if max_age is not None else os.environ.get("AGORA_NATS_MAX_AGE")
            ),
        )


def _relay_url(base_url: str | None = None) -> str:
    return (base_url or os.environ.get("AGORA_RELAY_URL") or DEFAULT_RELAY_URL).rstrip("/")


def _headers(token: str | None = None) -> dict[str, str]:
    token = token or os.environ.get("AGORA_RELAY_TOKEN")
    return {"Authorization": f"Bearer {token}"} if token else {}


def _is_nats_url(url: str) -> bool:
    return url.startswith("nats://") or url.startswith("tls://")


def publish(
    topic: str,
    payload: str,
    timeout: int = DEFAULT_TIMEOUT,
    base_url: str | None = None,
    token: str | None = None,
    nats: NatsSettings | None = None,
) -> bool:
    """Publish an encrypted payload to a relay topic."""
    relay_url = _relay_url(base_url)
    if _is_nats_url(relay_url):
        try:
            _run_async(lambda: _publish_nats(relay_url, token, nats or NatsSettings.current(), topic, payload, timeout))
            return True
        except Exception:
            return False

    url = f"{relay_url}/{topic}"
    try:
        resp = requests.post(url, data=payload.encode(), headers=_headers(token), timeout=timeout)
        return resp.ok
    except requests.RequestException:
        return False


def fetch(
    topic: str,
    since: str = "all",
    timeout: int = DEFAULT_TIMEOUT,
    base_url: str | None = None,
    token: str | None = None,
    nats: NatsSettings | None = None,
) -> list[tuple[int, str]]:
    """Fetch recent messages from a relay topic.

    Returns list of (timestamp, raw_payload).
    """
    relay_url = _relay_url(base_url)
    if _is_nats_url(relay_url):
        try:
            return _run_async(lambda: _fetch_nats(relay_url, token, nats or NatsSettings.current(), topic, since, timeout))
        except Exception:
            return []

    import json as _json
    url = f"{relay_url}/{topic}/json?poll=1&since={since}"
    try:
        resp = requests.get(url, headers=_headers(token), timeout=timeout)
        resp.raise_for_status()
    except requests.RequestException:
        return []

    events = []
    for line in resp.text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            evt = _json.loads(line)
            if evt.get("event") == "message" and "message" in evt:
                events.append((evt.get("time", 0), evt["message"]))
        except _json.JSONDecodeError:
            continue
    return events


def stream(
    topic: str,
    since: str = "all",
    base_url: str | None = None,
    token: str | None = None,
    nats: NatsSettings | None = None,
) -> Iterator[tuple[int, str]]:
    """Stream relay messages from a topic.

    Yields (timestamp, raw_payload) for each message.
    Raises requests.RequestException on connection error.
    """
    relay_url = _relay_url(base_url)
    if _is_nats_url(relay_url):
        yield from _stream_nats(relay_url, token, nats or NatsSettings.current(), topic, since)
        return

    import json as _json
    url = f"{relay_url}/{topic}/json?since={since}"
    with requests.get(url, stream=True, headers=_headers(token), timeout=None) as resp:
        resp.raise_for_status()
        for line in resp.iter_lines():
            if not line:
                continue
            try:
                evt = _json.loads(line)
                if evt.get("event") == "message" and "message" in evt:
                    yield evt.get("time", 0), evt["message"]
            except _json.JSONDecodeError:
                continue


def normalize_stream_name(raw: str) -> str:
    normalized = "".join(ch if ch.isalnum() or ch in "_-" else "_" for ch in raw.strip()).strip("_")
    return normalized or DEFAULT_NATS_STREAM


def normalize_subject_prefix(raw: str) -> str:
    tokens = []
    for token in raw.strip().strip(".").split("."):
        normalized = "".join(ch if ch.isalnum() or ch in "_-" else "_" for ch in token).strip("_")
        if normalized:
            tokens.append(normalized)
    return ".".join(tokens) if tokens else DEFAULT_NATS_SUBJECT_PREFIX


def parse_bool(value: bool | str | None, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    match value.strip().lower():
        case "1" | "true" | "yes" | "on":
            return True
        case "0" | "false" | "no" | "off":
            return False
        case _:
            return default


def parse_storage(value: str | None) -> str:
    normalized = (value or "").strip().lower()
    return "memory" if normalized in {"memory", "mem"} else "file"


def parse_nonnegative_int(value: int | str | None) -> int:
    if value is None:
        return 0
    try:
        return max(0, int(str(value).strip()))
    except ValueError:
        return 0


def parse_duration(value: int | float | str | None) -> float:
    if value is None:
        return 0.0
    if isinstance(value, int | float):
        return max(0.0, float(value))
    raw = value.strip()
    if not raw:
        return 0.0
    digits = ""
    suffix = ""
    for idx, ch in enumerate(raw):
        if ch.isdigit():
            digits += ch
        else:
            suffix = raw[idx:]
            break
    if not digits:
        return 0.0
    amount = int(digits)
    match suffix or "s":
        case "s":
            return float(amount)
        case "m":
            return float(amount * 60)
        case "h":
            return float(amount * 3600)
        case "d":
            return float(amount * 86400)
        case _:
            return 0.0


def since_cutoff(since: str) -> int:
    if since in {"all", "0"}:
        return 0
    suffix = since[-1:]
    if suffix in {"s", "m", "h", "d"}:
        try:
            amount = int(since[:-1])
        except ValueError:
            return 0
        multiplier = {"s": 1, "m": 60, "h": 3600, "d": 86400}[suffix]
        return max(0, int(datetime.now(timezone.utc).timestamp()) - amount * multiplier)
    try:
        return max(0, int(since))
    except ValueError:
        return 0


def subject_for_topic(settings: NatsSettings, topic: str) -> str:
    encoded = base64.urlsafe_b64encode(topic.encode()).decode().rstrip("=")
    return f"{settings.subject_prefix}.{encoded}"


def _run_async(factory: Callable[[], asyncio.Future]):
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(factory())

    result = []
    errors = []

    def runner() -> None:
        try:
            result.append(asyncio.run(factory()))
        except BaseException as exc:  # pragma: no cover - defensive bridge
            errors.append(exc)

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    thread.join()
    if errors:
        raise errors[0]
    return result[0] if result else None


def _nats_modules():
    try:
        import nats as nats_module
        from nats.js import api
        from nats.js import errors as js_errors
        from nats import errors as nats_errors
    except ImportError as exc:  # pragma: no cover - exercised only without optional dep
        raise RuntimeError("NATS relay support requires the nats-py package") from exc
    return nats_module, api, js_errors, nats_errors


async def _connect_nats(relay_url: str, token: str | None, timeout: int):
    nats_module, _, _, _ = _nats_modules()
    kwargs = {
        "servers": [relay_url],
        "name": "agora-python-sdk",
        "connect_timeout": min(timeout, 5),
        "max_reconnect_attempts": 10,
    }
    if token:
        kwargs["token"] = token
    if relay_url.startswith("tls://"):
        kwargs["tls"] = ssl.create_default_context()
    return await nats_module.connect(**kwargs)


async def _ensure_nats_stream(js, settings: NatsSettings):
    _, api, js_errors, _ = _nats_modules()
    if not settings.create_stream:
        return await js.stream_info(settings.stream_name)
    try:
        return await js.stream_info(settings.stream_name)
    except js_errors.NotFoundError:
        storage = api.StorageType.MEMORY if settings.storage == "memory" else api.StorageType.FILE
        config = api.StreamConfig(
            name=settings.stream_name,
            subjects=[settings.stream_subject],
            retention=api.RetentionPolicy.LIMITS,
            storage=storage,
            max_bytes=settings.max_bytes,
            max_age=settings.max_age,
            allow_direct=True,
            description="Agora encrypted room relay events",
        )
        return await js.add_stream(config)


async def _publish_nats(
    relay_url: str,
    token: str | None,
    settings: NatsSettings,
    topic: str,
    payload: str,
    timeout: int,
) -> None:
    _, api, _, _ = _nats_modules()
    nc = await _connect_nats(relay_url, token, timeout)
    try:
        js = nc.jetstream()
        await _ensure_nats_stream(js, settings)
        await js.publish(
            subject_for_topic(settings, topic),
            payload.encode(),
            stream=settings.stream_name,
            headers={api.Header.MSG_ID: f"agora-{os.getpid()}-{secrets.token_hex(8)}"},
        )
        await nc.flush()
    finally:
        await nc.close()


async def _fetch_nats(
    relay_url: str,
    token: str | None,
    settings: NatsSettings,
    topic: str,
    since: str,
    timeout: int,
) -> list[tuple[int, str]]:
    _, api, _, nats_errors = _nats_modules()
    nc = await _connect_nats(relay_url, token, timeout)
    try:
        js = nc.jetstream()
        await _ensure_nats_stream(js, settings)
        cutoff = since_cutoff(since)
        config = api.ConsumerConfig(
            deliver_policy=api.DeliverPolicy.BY_START_TIME if cutoff else api.DeliverPolicy.ALL,
            opt_start_time=_rfc3339(cutoff) if cutoff else None,
            ack_policy=api.AckPolicy.EXPLICIT,
            replay_policy=api.ReplayPolicy.INSTANT,
            inactive_threshold=NATS_CONSUMER_INACTIVE_THRESHOLD,
        )
        sub = await js.pull_subscribe(
            subject_for_topic(settings, topic),
            stream=settings.stream_name,
            config=config,
        )
        try:
            events: list[tuple[int, str]] = []
            while True:
                try:
                    messages = await sub.fetch(NATS_FETCH_BATCH_SIZE, timeout=NATS_FETCH_TIMEOUT)
                except nats_errors.TimeoutError:
                    break
                if not messages:
                    break
                for msg in messages:
                    await msg.ack()
                    events.append(_nats_event(msg))
            return events
        finally:
            await sub.unsubscribe()
    finally:
        await nc.close()


def _stream_nats(
    relay_url: str,
    token: str | None,
    settings: NatsSettings,
    topic: str,
    since: str,
) -> Iterator[tuple[int, str]]:
    loop = asyncio.new_event_loop()
    sub = None
    nc = None
    try:
        nc, sub = loop.run_until_complete(_open_nats_stream(relay_url, token, settings, topic, since))
        _, _, _, nats_errors = _nats_modules()
        while True:
            try:
                messages = loop.run_until_complete(sub.fetch(1, timeout=NATS_STREAM_FETCH_TIMEOUT))
            except nats_errors.TimeoutError:
                continue
            for msg in messages:
                loop.run_until_complete(msg.ack())
                yield _nats_event(msg)
    finally:
        if sub is not None:
            loop.run_until_complete(sub.unsubscribe())
        if nc is not None:
            loop.run_until_complete(nc.close())
        loop.close()


async def _open_nats_stream(
    relay_url: str,
    token: str | None,
    settings: NatsSettings,
    topic: str,
    since: str,
):
    _, api, _, _ = _nats_modules()
    nc = await _connect_nats(relay_url, token, DEFAULT_TIMEOUT)
    try:
        js = nc.jetstream()
        await _ensure_nats_stream(js, settings)
        cutoff = since_cutoff(since)
        config = api.ConsumerConfig(
            deliver_policy=api.DeliverPolicy.BY_START_TIME if cutoff else api.DeliverPolicy.NEW,
            opt_start_time=_rfc3339(cutoff) if cutoff else None,
            ack_policy=api.AckPolicy.EXPLICIT,
            replay_policy=api.ReplayPolicy.INSTANT,
            inactive_threshold=NATS_CONSUMER_INACTIVE_THRESHOLD,
        )
        sub = await js.pull_subscribe(
            subject_for_topic(settings, topic),
            stream=settings.stream_name,
            config=config,
        )
        return nc, sub
    except Exception:
        await nc.close()
        raise


def _nats_event(msg) -> tuple[int, str]:
    return int(msg.metadata.timestamp.timestamp()), msg.data.decode()


def _rfc3339(timestamp: int) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat().replace("+00:00", "Z")
