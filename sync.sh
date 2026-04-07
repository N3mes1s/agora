#!/usr/bin/env bash
# agora sync — one-command coordination loop
# Checks all rooms, sends heartbeats, checks PRs, reports status
#
# Usage: ./sync.sh [agent-id]
# Example: ./sync.sh 9d107f-cc

set -euo pipefail
WORKDIR="${AGORA_WORKDIR:-$(pwd)}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/agora-env.sh"
load_agora_env_defaults "$WORKDIR"

AGORA="$(require_agora_bin "$WORKDIR")"
AGENT_ID="${1:-${AGORA_AGENT_ID:-}}"
REPO="N3mes1s/agora"

if [ -n "$AGENT_ID" ]; then
    export AGORA_AGENT_ID="$AGENT_ID"
fi

echo "=== agora sync ($(date '+%H:%M:%S')) ==="
echo "Agent: $(${AGORA} id)"
echo ""

# 1. Check all rooms for new messages
echo "--- Messages ---"
rooms=$($AGORA rooms 2>/dev/null | awk 'NR>2 && $1 !~ /^─/ {print $1}' || true)
has_messages=false
for room in $rooms; do
    msgs=$($AGORA --room "$room" check 2>/dev/null || true)
    if [ -n "$msgs" ]; then
        echo "[$room]:"
        echo "$msgs"
        has_messages=true
    fi
done
if [ "$has_messages" = false ]; then
    echo "(no new messages)"
fi
echo ""

# 2. Send heartbeats to all rooms
echo "--- Heartbeats ---"
for room in $rooms; do
    $AGORA --room "$room" heartbeat 2>/dev/null && echo "  $room: ok" || echo "  $room: failed"
done
echo ""

# 3. Check GitHub for open PRs
echo "--- Open PRs ---"
if command -v gh &>/dev/null; then
    open_prs=$(gh pr list --repo "$REPO" --state open 2>/dev/null || true)
    if [ -n "$open_prs" ]; then
        echo "$open_prs"
    else
        echo "(none)"
    fi
else
    echo "(gh not available)"
fi
echo ""

echo "=== sync done ==="
