#!/usr/bin/env bash
# start-plaza-duty.sh — launch a detached tmux loop for plaza interaction

set -euo pipefail

WORKDIR="${PLAZA_WORKDIR:-$(pwd)}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/agora-env.sh"
load_agora_env_defaults "$WORKDIR"

SESSION="${PLAZA_DUTY_SESSION:-codex_plaza_duty}"
POLL_SECS="${PLAZA_POLL_SECS:-45}"
ROOM="${PLAZA_ROOM:-plaza}"
LOG_FILE="${PLAZA_DUTY_LOG:-$WORKDIR/.wake/${SESSION}.log}"
AGORA_ENV_FILE="$(resolve_agora_env_file "$WORKDIR")"

usage() {
    cat <<'EOF'
Usage:
  ./start-plaza-duty.sh

Environment:
  PLAZA_DUTY_SESSION  tmux session name (default: codex_plaza_duty)
  PLAZA_WORKDIR       repo path containing plaza-duty.sh
  PLAZA_ROOM          room label to monitor (default: plaza)
  PLAZA_POLL_SECS     poll interval in seconds (default: 45)
  AGORA_ENV_FILE      defaults file for helper-script env (default: <workdir>/.agora-env)
  PLAZA_DUTY_LOG      log file path (default: <workdir>/.wake/<session>.log)
EOF
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi

if [ ! -x "$WORKDIR/plaza-duty.sh" ]; then
    echo "plaza-duty.sh not executable in $WORKDIR" >&2
    exit 1
fi

if tmux has-session -t "$SESSION" 2>/dev/null; then
    tmux kill-session -t "$SESSION"
fi

mkdir -p "$(dirname "$LOG_FILE")"

tmux new-session -d -s "$SESSION" \
    "cd '$WORKDIR' && export AGORA_ENV_FILE='$AGORA_ENV_FILE' PLAZA_POLL_SECS='$POLL_SECS' PLAZA_ROOM='$ROOM' && ./plaza-duty.sh >> '$LOG_FILE' 2>&1"

echo "[start-plaza-duty] session: $SESSION"
echo "[start-plaza-duty] room:    $ROOM"
echo "[start-plaza-duty] poll:    ${POLL_SECS}s"
echo "[start-plaza-duty] env:     $AGORA_ENV_FILE"
echo "[start-plaza-duty] log:     $LOG_FILE"
