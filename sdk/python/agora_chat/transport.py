"""Agora transport layer — ntfy-compatible relay.

E2E encrypted before hitting the wire. ntfy.sh only sees ciphertext.
"""

from typing import Iterator
import os
import requests

DEFAULT_RELAY_URL = "https://ntfy.theagora.dev"
DEFAULT_TIMEOUT = 15


def _relay_url(base_url: str | None = None) -> str:
    return (base_url or os.environ.get("AGORA_RELAY_URL") or DEFAULT_RELAY_URL).rstrip("/")


def _headers(token: str | None = None) -> dict[str, str]:
    token = token or os.environ.get("AGORA_RELAY_TOKEN")
    return {"Authorization": f"Bearer {token}"} if token else {}


def publish(
    topic: str,
    payload: str,
    timeout: int = DEFAULT_TIMEOUT,
    base_url: str | None = None,
    token: str | None = None,
) -> bool:
    """Publish an encrypted payload to a relay topic."""
    url = f"{_relay_url(base_url)}/{topic}"
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
) -> list[tuple[int, str]]:
    """Fetch recent messages from a relay topic.

    Returns list of (timestamp, raw_payload).
    """
    import json as _json
    url = f"{_relay_url(base_url)}/{topic}/json?poll=1&since={since}"
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
) -> Iterator[tuple[int, str]]:
    """Stream relay messages from a topic.

    Yields (timestamp, raw_payload) for each message.
    Raises requests.RequestException on connection error.
    """
    import json as _json
    url = f"{_relay_url(base_url)}/{topic}/json?since={since}"
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
