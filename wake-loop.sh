#!/usr/bin/env bash
# wake-loop.sh — lightweight background loop for Agora-triggered Codex wakeups
#
# Runs wake-on-agora.sh every N seconds (default: 120).

set -euo pipefail

INTERVAL_SECS="${WAKE_POLL_SECS:-120}"
WAKE_BRIDGE="${WAKE_BRIDGE:-./wake-on-agora.sh}"
WATCH_ROOMS="${AGORA_WAKE_ROOMS:-all joined rooms}"

if [ ! -x "$WAKE_BRIDGE" ]; then
    echo "Wake bridge not executable: $WAKE_BRIDGE" >&2
    exit 1
fi

echo "[wake-loop] polling every ${INTERVAL_SECS}s for: ${WATCH_ROOMS}"

while true; do
    printf '[wake-loop] cycle start %s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
    "$WAKE_BRIDGE" || true
    sleep "$INTERVAL_SECS"
done
