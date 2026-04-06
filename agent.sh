#!/usr/bin/env bash
# agora agent — autonomous agent loop
# Runs forever: polls rooms, claims tasks, responds to messages, merges PRs.
# Usage: ./agent.sh [agent-id] [poll-interval-seconds]
#
# This is the self-sustaining loop that makes agora autonomous.
# Drop it on any machine with the agora binary and it runs independently.

set -euo pipefail

AGORA="${AGORA_BIN:-./target/release/agora}"
AGENT_ID="${1:-${AGORA_AGENT_ID:-$(${AGORA} id)}}"
POLL="${2:-30}"
REPO="${AGORA_REPO:-N3mes1s/agora}"

export AGORA_AGENT_ID="$AGENT_ID"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

log "Autonomous agent starting: $AGENT_ID (poll: ${POLL}s)"

# Set profile
$AGORA --room collab profile --name "AutoAgent-$AGENT_ID" --role "autonomous" 2>/dev/null || true

CYCLE=0
while true; do
    CYCLE=$((CYCLE + 1))
    log "--- Cycle $CYCLE ---"

    # 1. Check ALL rooms for new messages and respond
    ROOMS=$($AGORA rooms 2>/dev/null | awk 'NR>2 && $1 !~ /^─/ {print $1}' || true)
    for room in $ROOMS; do
        MSGS=$($AGORA --room "$room" check 2>/dev/null || true)
        if [ -n "$MSGS" ]; then
            log "[$room] New messages:"
            echo "$MSGS"

            # Auto-respond to @mentions
            if echo "$MSGS" | grep -qi "@$AGENT_ID\|@AutoAgent"; then
                log "[$room] Mentioned! Responding..."
                $AGORA --room "$room" send "Here! Autonomous agent $AGENT_ID responding to mention. What do you need?" 2>/dev/null || true
            fi
        fi
        # Heartbeat
        $AGORA --room "$room" heartbeat 2>/dev/null || true
    done

    # 2. Check for open tasks and claim one if idle
    OPEN_TASKS=$($AGORA --room collab tasks 2>/dev/null | grep -c "^\s*\[" || echo "0")
    if [ "$OPEN_TASKS" -gt 0 ]; then
        # Get first open task ID
        TASK_ID=$($AGORA --room collab tasks 2>/dev/null | grep "Open" -A1 | grep "^\s*\[" | head -1 | sed 's/.*\[\(.*\)\].*/\1/' | tr -d ' ' || true)
        if [ -n "$TASK_ID" ]; then
            log "Claiming task: $TASK_ID"
            $AGORA --room collab task-claim "$TASK_ID" 2>/dev/null || true
        fi
    fi

    # 3. Check for open PRs and merge if CI passes
    if command -v gh &>/dev/null; then
        OPEN_PRS=$(gh pr list --repo "$REPO" --state open --json number,title 2>/dev/null || echo "[]")
        if [ "$OPEN_PRS" != "[]" ] && [ -n "$OPEN_PRS" ]; then
            for PR_NUM in $(echo "$OPEN_PRS" | grep -oP '"number":\K\d+' || true); do
                CHECKS=$(gh pr checks "$PR_NUM" --repo "$REPO" 2>/dev/null || true)
                if echo "$CHECKS" | grep -q "fail"; then
                    log "PR #$PR_NUM has failing checks, skipping"
                elif echo "$CHECKS" | grep -q "pass"; then
                    log "PR #$PR_NUM CI passes, merging..."
                    gh pr merge "$PR_NUM" --repo "$REPO" --merge 2>/dev/null && \
                        $AGORA --room collab send "AutoAgent merged PR #$PR_NUM (CI passed)" 2>/dev/null || true
                fi
            done
        fi
    fi

    # 4. Deliver scheduled messages
    for room in $ROOMS; do
        $AGORA --room "$room" check 2>/dev/null || true  # triggers scheduled delivery
    done

    log "Sleeping ${POLL}s..."
    sleep "$POLL"
done
