#!/usr/bin/env bash
# wake-codex.sh — wake a dedicated Codex session running behind codex app-server
#
# Starts two tmux sessions if needed:
#   1. codex app-server on ws://127.0.0.1:8765
#   2. a forked Codex TUI attached to that app-server
#
# Then sends a literal prompt into the forked Codex pane.
#
# Usage:
#   ./wake-codex.sh --source-thread <thread-id> "check local-sync and reply"
#
# Optional env overrides:
#   CODEX_WS_URL
#   CODEX_SERVER_SESSION
#   CODEX_AGENT_SESSION
#   CODEX_WORKDIR
#   CODEX_SOURCE_THREAD
#   AGORA_WORKER_ID

set -euo pipefail

WS_URL="${CODEX_WS_URL:-ws://127.0.0.1:8765}"
SERVER_SESSION="${CODEX_SERVER_SESSION:-codex_app_server}"
AGENT_SESSION="${CODEX_AGENT_SESSION:-codex_remote_fork}"
WORKDIR="${CODEX_WORKDIR:-$(pwd)}"
SOURCE_THREAD="${CODEX_SOURCE_THREAD:-}"
WORKER_AGORA_ID="${AGORA_WORKER_ID:-}"

usage() {
    cat <<'EOF'
Usage:
  ./wake-codex.sh --source-thread <thread-id> <message>

Example:
  ./wake-codex.sh --source-thread 019d5e1a-b68c-70f2-b361-c6ba36537dd1 \
    "Check Agora rooms and reply in local-sync"

Environment:
  AGORA_WORKER_ID=<base-id>-worker
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --source-thread)
            SOURCE_THREAD="${2:-}"
            shift 2
            ;;
        --ws-url)
            WS_URL="${2:-}"
            shift 2
            ;;
        --server-session)
            SERVER_SESSION="${2:-}"
            shift 2
            ;;
        --agent-session)
            AGENT_SESSION="${2:-}"
            shift 2
            ;;
        --workdir)
            WORKDIR="${2:-}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            break
            ;;
        -*)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
        *)
            break
            ;;
    esac
done

if [ -z "$SOURCE_THREAD" ]; then
    echo "Missing --source-thread" >&2
    usage >&2
    exit 1
fi

if [ $# -eq 0 ]; then
    echo "Missing wake message" >&2
    usage >&2
    exit 1
fi

MESSAGE="$*"

has_session() {
    tmux has-session -t "$1" 2>/dev/null
}

resolve_worker_agora_id() {
    if [ -n "$WORKER_AGORA_ID" ]; then
        printf '%s' "$WORKER_AGORA_ID"
        return
    fi

    local agora_bin
    agora_bin="$WORKDIR/target/release/agora"
    if [ -x "$agora_bin" ]; then
        local base_id
        base_id="$("$agora_bin" id 2>/dev/null || true)"
        if [ -n "$base_id" ]; then
            printf '%s-worker' "$base_id"
            return
        fi
    fi

    printf 'codex-worker'
}

ready_url() {
    local hostport
    hostport="${WS_URL#ws://}"
    hostport="${hostport#http://}"
    printf 'http://%s/readyz' "$hostport"
}

ensure_app_server() {
    if has_session "$SERVER_SESSION"; then
        return
    fi

    tmux new-session -d -s "$SERVER_SESSION" \
        "cd '$WORKDIR' && codex app-server --listen '$WS_URL'"
}

wait_for_app_server() {
    local url
    url="$(ready_url)"

    for _ in $(seq 1 20); do
        if curl -fsS "$url" >/dev/null 2>&1; then
            return
        fi
        sleep 1
    done

    echo "Codex app-server did not become ready at $url" >&2
    exit 1
}

ensure_agent_session() {
    if has_session "$AGENT_SESSION"; then
        return
    fi

    local worker_agora_id
    worker_agora_id="$(resolve_worker_agora_id)"

    tmux new-session -d -s "$AGENT_SESSION" \
        "cd '$WORKDIR' && export AGORA_AGENT_ID='$worker_agora_id' && codex --remote '$WS_URL' --no-alt-screen fork '$SOURCE_THREAD'"
    sleep 2
}

skip_update_prompt_if_needed() {
    local pane
    pane="$(tmux capture-pane -pt "$AGENT_SESSION" || true)"
    if [[ "$pane" == *"Update available!"* ]]; then
        tmux send-keys -t "$AGENT_SESSION" 2 Enter
        sleep 2
    fi
}

send_message() {
    tmux send-keys -t "$AGENT_SESSION" -l "$MESSAGE"
    tmux send-keys -t "$AGENT_SESSION" Enter
    sleep 1

    # Some Codex TUI states accept the text but require a second Enter to submit.
    local pane
    pane="$(tmux capture-pane -pt "$AGENT_SESSION" || true)"
    if [[ "$pane" == *"› $MESSAGE"* ]] && [[ "$pane" != *"  $MESSAGE"* ]]; then
        tmux send-keys -t "$AGENT_SESSION" Enter
        sleep 1
    fi
}

show_status() {
    local worker_agora_id
    worker_agora_id="$(resolve_worker_agora_id)"
    echo "[wake] app-server: $SERVER_SESSION ($WS_URL)"
    echo "[wake] agent:      $AGENT_SESSION"
    echo "[wake] agora id:   $worker_agora_id"
    echo "[wake] message:    $MESSAGE"
    echo
    tmux capture-pane -pt "$AGENT_SESSION"
}

ensure_app_server
wait_for_app_server
ensure_agent_session
skip_update_prompt_if_needed
send_message
show_status
