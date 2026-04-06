#!/usr/bin/env bash
# wake-on-agora.sh — cron-friendly Agora -> Codex wake bridge
#
# Flow:
#   1. Ensure a per-room Agora daemon is running for each joined room.
#   2. Consume room notify flags via `agora notify`.
#   3. If any room has unread messages, wake the dedicated Codex tmux session
#      with a prompt telling it which rooms to inspect.
#
# Intended for cron or a lightweight poll loop.
#
# Example:
#   */1 * * * * cd ~/code/agora && ./wake-on-agora.sh

set -euo pipefail

AGORA="${AGORA_BIN:-./target/release/agora}"
WAKE_SCRIPT="${WAKE_SCRIPT:-./wake-codex.sh}"
SOURCE_THREAD="${CODEX_SOURCE_THREAD:-019d5e1a-b68c-70f2-b361-c6ba36537dd1}"
SINCE="${AGORA_NOTIFY_SINCE:-24h}"

usage() {
    cat <<'EOF'
Usage:
  ./wake-on-agora.sh

Environment:
  AGORA_BIN            Path to agora binary
  WAKE_SCRIPT          Path to wake-codex.sh
  CODEX_SOURCE_THREAD  Source thread id for the forked Codex session
  AGORA_NOTIFY_SINCE   Lookback window passed to local cache logic
  AGORA_WORKER_ID      Agora identity for the forked worker and notifier
  AGORA_WAKE_ROOMS     Space/comma-separated room labels to watch
  MAIN_CODEX_PANE      tmux pane target for the main local Codex session
EOF
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi

if [ ! -x "$AGORA" ]; then
    echo "Agora binary not executable: $AGORA" >&2
    exit 1
fi

if [ ! -x "$WAKE_SCRIPT" ]; then
    echo "Wake script not executable: $WAKE_SCRIPT" >&2
    exit 1
fi

resolve_worker_agora_id() {
    if [ -n "${AGORA_WORKER_ID:-}" ]; then
        printf '%s' "$AGORA_WORKER_ID"
        return
    fi

    local base_id
    base_id="$("$AGORA" id 2>/dev/null || true)"
    if [ -n "$base_id" ]; then
        printf '%s-worker' "$base_id"
        return
    fi

    printf 'codex-worker'
}

export AGORA_AGENT_ID="$(resolve_worker_agora_id)"

resolve_main_pane() {
    if [ -n "${MAIN_CODEX_PANE:-}" ]; then
        printf '%s' "$MAIN_CODEX_PANE"
        return
    fi

    tmux list-panes -a -F '#S:#I.#P #{pane_current_command} #{pane_title}' 2>/dev/null \
        | awk '
            $1 !~ /^codex_app_server:/ &&
            $1 !~ /^codex_remote_fork:/ &&
            $1 !~ /^codex_remote_resume:/ &&
            $1 !~ /^codex_wake_loop:/ &&
            $2 == "node" {
                print $1
                exit
            }
        '
}

notify_main_pane() {
    local room_list="$1"
    local pane
    pane="$(resolve_main_pane)"
    if [ -z "$pane" ]; then
        return
    fi

    tmux display-message -t "$pane" "[AGORA] activity in: $room_list (worker waking)"
}

list_rooms() {
    local configured="${AGORA_WAKE_ROOMS:-}"
    if [ -n "$configured" ]; then
        printf '%s\n' "$configured" | tr ',' ' ' | xargs -n1
        return
    fi

    "$AGORA" rooms 2>/dev/null | awk 'NR>2 && $1 !~ /^─/ {print $1}'
}

ensure_room_daemon() {
    local room="$1"
    # Start the room daemon if missing. The command is idempotent enough for cron.
    "$AGORA" --room "$room" daemon >/dev/null 2>&1 || true
}

collect_notifications() {
    local room="$1"
    "$AGORA" --room "$room" notify 2>/dev/null || true
}

rooms="$(list_rooms || true)"
if [ -z "$rooms" ]; then
    exit 0
fi

rooms_with_activity=()

for room in $rooms; do
    ensure_room_daemon "$room"

    output="$(collect_notifications "$room")"
    if [ -n "$output" ]; then
        rooms_with_activity+=("$room")
    fi
done

if [ "${#rooms_with_activity[@]}" -eq 0 ]; then
    exit 0
fi

room_list="$(printf '%s, ' "${rooms_with_activity[@]}")"
room_list="${room_list%, }"

prompt="You are the primary always-on Codex worker for Agora. New activity detected in room(s): ${room_list}. Read those rooms, check the latest messages, coordinate in Agora chat, and reply there when action is needed. Do not wait for the main terminal."

"$WAKE_SCRIPT" --source-thread "$SOURCE_THREAD" "$prompt" >/dev/null
notify_main_pane "$room_list"

printf '[wake-on-agora] woke Codex for rooms: %s\n' "$room_list"
