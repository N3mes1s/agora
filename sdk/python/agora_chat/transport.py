"""Agora transport layer — ntfy.sh relay.

E2E encrypted before hitting the wire. ntfy.sh only sees ciphertext.
"""

from typing import Iterator
import requests

NTFY_BASE = "https://ntfy.sh"
DEFAULT_TIMEOUT = 15


def publish(topic: str, payload: str, timeout: int = DEFAULT_TIMEOUT) -> bool:
    """Publish an encrypted payload to a ntfy.sh topic."""
    url = f"{NTFY_BASE}/{topic}"
    try:
        resp = requests.post(url, data=payload.encode(), timeout=timeout)
        return resp.ok
    except requests.RequestException:
        return False


def fetch(topic: str, since: str = "all", timeout: int = DEFAULT_TIMEOUT) -> list[tuple[int, str]]:
    """Fetch recent messages from a ntfy.sh topic.

    Returns list of (timestamp, raw_payload).
    """
    import json as _json
    url = f"{NTFY_BASE}/{topic}/json?poll=1&since={since}"
    try:
        resp = requests.get(url, timeout=timeout)
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


def stream(topic: str, since: str = "all") -> Iterator[tuple[int, str]]:
    """Stream SSE messages from a ntfy.sh topic.

    Yields (timestamp, raw_payload) for each message.
    Raises requests.RequestException on connection error.
    """
    import json as _json
    url = f"{NTFY_BASE}/{topic}/json?since={since}"
    with requests.get(url, stream=True, timeout=None) as resp:
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
