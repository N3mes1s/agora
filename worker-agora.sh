#!/usr/bin/env bash
# worker-agora.sh — run agora as the tmux worker identity without drifting keys

set -euo pipefail

WORKDIR="${WORKDIR:-$(pwd)}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/agora-env.sh"
load_agora_env_defaults "$WORKDIR"

AGORA_BIN="${AGORA_BIN:-$WORKDIR/target/release/agora}"
BASE_HOME="${BASE_HOME:-$HOME}"
WORKER_HOME="${WORKER_HOME:-$WORKDIR/.worker-home}"

if [ ! -x "$AGORA_BIN" ]; then
    echo "Agora binary not executable: $AGORA_BIN" >&2
    exit 1
fi

resolve_worker_id() {
    if [ -n "${AGORA_WORKER_ID:-}" ]; then
        printf '%s' "$AGORA_WORKER_ID"
        return
    fi

    local base_id
    base_id="$("$AGORA_BIN" id 2>/dev/null | extract_agora_agent_id || true)"
    if [ -n "$base_id" ]; then
        printf '%s-worker' "$base_id"
        return
    fi

    printf 'codex-worker'
}

sync_worker_home() {
    mkdir -p "$WORKER_HOME/.agora"

    if [ -f "$BASE_HOME/.agora/rooms.json" ]; then
        cp "$BASE_HOME/.agora/rooms.json" "$WORKER_HOME/.agora/rooms.json"
    fi

    if [ -f "$BASE_HOME/.agora/active_room" ]; then
        cp "$BASE_HOME/.agora/active_room" "$WORKER_HOME/.agora/active_room"
    fi

    if [ -f "$BASE_HOME/.agora/trusted_signing_keys.json" ]; then
        cp "$BASE_HOME/.agora/trusted_signing_keys.json" \
            "$WORKER_HOME/.agora/trusted_signing_keys.json"
    fi

    if [ -f "$BASE_HOME/.agora/aliases.json" ]; then
        cp "$BASE_HOME/.agora/aliases.json" "$WORKER_HOME/.agora/aliases.json"
    fi

    mkdir -p "$WORKER_HOME/.agora/signing-keys"

    local worker_id worker_key src_key dst_key
    worker_id="$(resolve_worker_id)"
    worker_key="${worker_id}.pkcs8"
    src_key="$BASE_HOME/.agora/signing-keys/$worker_key"
    dst_key="$WORKER_HOME/.agora/signing-keys/$worker_key"

    if [ -f "$src_key" ]; then
        cp "$src_key" "$dst_key"
    fi
}

sync_worker_home

export HOME="$WORKER_HOME"
export AGORA_AGENT_ID="$(resolve_worker_id)"

exec "$AGORA_BIN" "$@"
