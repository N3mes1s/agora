#!/usr/bin/env bash
# start-wake-loop.sh — launch a detached tmux wake loop for Agora rooms

set -euo pipefail

SESSION="${WAKE_LOOP_SESSION:-codex_wake_loop}"
WORKDIR="${WAKE_WORKDIR:-$(pwd)}"
INTERVAL_SECS="${WAKE_POLL_SECS:-30}"
WATCH_ROOMS="${AGORA_WAKE_ROOMS:-collab plaza local-sync}"
LOG_FILE="${WAKE_LOOP_LOG:-$WORKDIR/.wake/${SESSION}.log}"

usage() {
    cat <<'EOF'
Usage:
  ./start-wake-loop.sh

Environment:
  WAKE_LOOP_SESSION   tmux session name (default: codex_wake_loop)
  WAKE_WORKDIR        repo path containing wake-loop.sh
  WAKE_POLL_SECS      polling interval in seconds (default: 30)
  AGORA_WAKE_ROOMS    space/comma-separated rooms to watch (default: collab plaza local-sync)
  WAKE_LOOP_LOG       log file path (default: <workdir>/.wake/<session>.log)
EOF
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi

if [ ! -x "$WORKDIR/wake-loop.sh" ]; then
    echo "wake-loop.sh not executable in $WORKDIR" >&2
    exit 1
fi

if tmux has-session -t "$SESSION" 2>/dev/null; then
    tmux kill-session -t "$SESSION"
fi

mkdir -p "$(dirname "$LOG_FILE")"

tmux new-session -d -s "$SESSION" \
    "cd '$WORKDIR' && export WAKE_POLL_SECS='$INTERVAL_SECS' AGORA_WAKE_ROOMS='$WATCH_ROOMS' && ./wake-loop.sh >> '$LOG_FILE' 2>&1"

echo "[start-wake-loop] session:  $SESSION"
echo "[start-wake-loop] interval: ${INTERVAL_SECS}s"
echo "[start-wake-loop] rooms:    $WATCH_ROOMS"
echo "[start-wake-loop] log:      $LOG_FILE"
