"""
Agora transport layer — ntfy.sh relay.

ntfy.sh is a free pub/sub service. We use it as a dumb pipe:
  - Messages are E2E encrypted before hitting the wire
  - ntfy.sh only sees ciphertext
  - Topic names are random (unguessable without the room ID)
  - No accounts, no auth, no setup

Transport is pluggable — swap this module for WebSocket, Redis, etc.
"""

import json
import subprocess
import sys
from typing import Optional


NTFY_BASE = "https://ntfy.sh"
CURL_TIMEOUT = 15


def publish(topic: str, payload: str) -> bool:
    """Publish an encrypted payload to a ntfy.sh topic.

    Returns True on success, False on failure.
    """
    try:
        r = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "-d", payload, f"{NTFY_BASE}/{topic}"],
            capture_output=True, text=True, timeout=CURL_TIMEOUT,
        )
        return r.stdout.strip() in ("200", "201")
    except (subprocess.TimeoutExpired, OSError):
        return False


def fetch(topic: str, since: str = "2h") -> list[dict]:
    """Fetch recent messages from a ntfy.sh topic.

    Returns raw ntfy.sh JSON events (only 'message' type).
    """
    try:
        r = subprocess.run(
            ["curl", "-s", f"{NTFY_BASE}/{topic}/json?poll=1&since={since}"],
            capture_output=True, text=True, timeout=CURL_TIMEOUT,
        )
    except (subprocess.TimeoutExpired, OSError):
        return []

    events = []
    for line in r.stdout.strip().split("\n"):
        if not line.strip():
            continue
        try:
            d = json.loads(line)
            if d.get("event") == "message":
                events.append(d)
        except json.JSONDecodeError:
            pass
    return events


def stream(topic: str):
    """Open a streaming connection to a ntfy.sh topic.

    Yields (timestamp, raw_payload) tuples as messages arrive.
    This is a blocking generator — use in a background thread/process.
    """
    try:
        proc = subprocess.Popen(
            ["curl", "-s", f"{NTFY_BASE}/{topic}/json"],
            stdout=subprocess.PIPE, text=True,
        )
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                if d.get("event") == "message":
                    yield d.get("time", 0), d.get("message", "")
            except json.JSONDecodeError:
                pass
    except KeyboardInterrupt:
        if proc:
            proc.kill()
