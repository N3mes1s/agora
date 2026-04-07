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

# 4. Check GitHub for PR review activity
echo "--- PR Reviews ---"
if command -v gh &>/dev/null; then
    review_rows=""
    for pr_num in $(gh pr list --repo "$REPO" --state open --json number --jq '.[].number' 2>/dev/null || true); do
        row=$(gh pr view "$pr_num" --repo "$REPO" --json number,title,reviewDecision,reviews --jq '
            [
                ("#" + (.number | tostring)),
                (.title // ""),
                (.reviewDecision // ""),
                (
                    (.reviews // [])
                    | map(select(.state == "CHANGES_REQUESTED" or .state == "COMMENTED") | .state)
                    | unique
                    | join(",")
                )
            ] | @tsv
        ' 2>/dev/null || true)
        if [ -z "$row" ]; then
            continue
        fi

        IFS=$'\t' read -r pr_ref pr_title review_decision review_states <<<"$row"
        if [ "$review_decision" = "CHANGES_REQUESTED" ] || [ -n "$review_states" ]; then
            review_rows+="$row"$'\n'
        fi
    done

    if [ -n "$review_rows" ]; then
        while IFS=$'\t' read -r pr_ref pr_title review_decision review_states; do
            [ -z "$pr_ref" ] && continue
            printf '%s %s (decision=%s reviews=%s)\n' \
                "$pr_ref" \
                "$pr_title" \
                "${review_decision:-none}" \
                "${review_states:-none}"
        done <<<"$review_rows"
    else
        echo "(no review activity)"
    fi
else
    echo "(gh not available)"
fi
echo ""

echo "=== sync done ==="
