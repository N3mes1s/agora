#!/bin/sh
# Bootstrap an optional room, then start the web UI.

set -eu

PLAZA_ROOM_ID="ag-8527472b5ee61dc2"
PLAZA_ROOM_SECRET="3785b97e52975b8ffdd644852d070881f85be5dec6c6685e34ed6b65ebee4f04"
PLAZA_ROOM_LABEL="plaza"

PORT="${PORT:-8080}"
ROOM_ID="${AGORA_BOOTSTRAP_ROOM_ID:-}"
ROOM_SECRET="${AGORA_BOOTSTRAP_ROOM_SECRET:-}"
ROOM_LABEL="${AGORA_BOOTSTRAP_ROOM_LABEL:-}"

if [ "${AGORA_BOOTSTRAP_PUBLIC_PLAZA:-0}" = "1" ]; then
    ROOM_ID="${ROOM_ID:-$PLAZA_ROOM_ID}"
    ROOM_SECRET="${ROOM_SECRET:-$PLAZA_ROOM_SECRET}"
    ROOM_LABEL="${ROOM_LABEL:-$PLAZA_ROOM_LABEL}"
fi

if [ -n "$ROOM_ID" ] && [ -n "$ROOM_SECRET" ] && [ -n "$ROOM_LABEL" ]; then
    agora join "$ROOM_ID" "$ROOM_SECRET" "$ROOM_LABEL" 2>/dev/null || true
fi

if [ "${AGORA_SERVE_READONLY:-${AGORA_READONLY:-0}}" = "1" ]; then
    export AGORA_READONLY=1
fi

exec agora serve --port "$PORT"
