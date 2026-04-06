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
AGENT_PROFILE="AutoAgent-$AGENT_ID"

export AGORA_AGENT_ID="$AGENT_ID"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

is_agent_mentioned() {
    local text="$1"
    local pattern="(^|[^[:alnum:]_-])@(${AGENT_ID}|${AGENT_PROFILE})([^[:alnum:]_-]|$)"
    printf '%s\n' "$text" | grep -Eiq "$pattern"
}

collab_tasks_output() {
    $AGORA --room collab tasks 2>/dev/null || true
}

first_open_task_id() {
    local tasks
    tasks="$(collab_tasks_output)"
    awk '
        /^  Open \([0-9]+\):/ { in_open=1; next }
        /^  [A-Za-z].*\([0-9]+\):/ { if (in_open) exit }
        in_open && match($0, /\[[[:alnum:]]+\]/) {
            print substr($0, RSTART + 1, RLENGTH - 2)
            exit
        }
    ' <<<"$tasks"
}

has_claimed_task() {
    local tasks
    tasks="$(collab_tasks_output)"
    awk -v agent_id="$AGENT_ID" -v agent_profile="$AGENT_PROFILE" '
        /^  In Progress \([0-9]+\):/ { in_progress=1; next }
        /^  [A-Za-z].*\([0-9]+\):/ { if (in_progress) exit }
        in_progress && (index($0, "(by " agent_profile) || index($0, "(" agent_id ")") || index($0, "(by " agent_id ")")) {
            found=1
            exit
        }
        END { exit found ? 0 : 1 }
    ' <<<"$tasks"
}

required_check_buckets() {
    local pr_num="$1"
    local output=""
    local status=0

    set +e
    output=$(gh pr checks "$pr_num" --repo "$REPO" --required --json bucket --jq 'if length == 0 then "none" else (map(.bucket) | unique | join(",")) end' 2>/dev/null)
    status=$?
    set -e

    if [ "$status" -eq 8 ]; then
        echo "pending"
        return 0
    fi
    if [ "$status" -ne 0 ]; then
        echo "error"
        return 0
    fi
    echo "$output"
}

should_merge_pr() {
    local is_draft="$1"
    local merge_state="$2"
    local review_decision="$3"
    local check_buckets="$4"

    if [ "$is_draft" = "true" ]; then
        return 1
    fi

    case "$merge_state" in
        CLEAN|HAS_HOOKS) ;;
        *) return 1 ;;
    esac

    case "$review_decision" in
        CHANGES_REQUESTED|REVIEW_REQUIRED) return 1 ;;
    esac

    case "$check_buckets" in
        ""|error|pending|*fail*|*cancel*|*skipping*) return 1 ;;
    esac

    return 0
}

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
            if is_agent_mentioned "$MSGS"; then
                log "[$room] Mentioned! Responding..."
                $AGORA --room "$room" send "Here! Autonomous agent $AGENT_ID responding to mention. What do you need?" 2>/dev/null || true
            fi
        fi
        # Heartbeat
        $AGORA --room "$room" heartbeat 2>/dev/null || true
    done

    # 2. Check for open tasks and claim one if available
    if has_claimed_task; then
        log "Already have in-progress work, skipping new task claim"
    else
        TASK_ID=$(first_open_task_id || true)
        if [ -n "$TASK_ID" ]; then
            log "Claiming task: $TASK_ID"
            $AGORA --room collab task-claim "$TASK_ID" 2>/dev/null || true
        else
            log "No open tasks to claim"
        fi
    fi

    # 3. Check for open PRs and merge if CI passes
    if command -v gh &>/dev/null; then
        OPEN_PRS=$(gh pr list --repo "$REPO" --state open --json number,title 2>/dev/null || echo "[]")
        if [ "$OPEN_PRS" != "[]" ] && [ -n "$OPEN_PRS" ]; then
            for PR_NUM in $(echo "$OPEN_PRS" | grep -oP '"number":\K\d+' || true); do
                PR_META=$(gh pr view "$PR_NUM" --repo "$REPO" --json isDraft,mergeStateStatus,reviewDecision --jq '[.isDraft, .mergeStateStatus, (.reviewDecision // "")] | @tsv' 2>/dev/null || true)
                if [ -z "$PR_META" ]; then
                    log "PR #$PR_NUM metadata unavailable, skipping"
                    continue
                fi

                IFS=$'\t' read -r IS_DRAFT MERGE_STATE REVIEW_DECISION <<<"$PR_META"
                CHECK_BUCKETS=$(required_check_buckets "$PR_NUM")

                if ! should_merge_pr "$IS_DRAFT" "$MERGE_STATE" "$REVIEW_DECISION" "$CHECK_BUCKETS"; then
                    log "PR #$PR_NUM not ready (draft=$IS_DRAFT merge=$MERGE_STATE review=${REVIEW_DECISION:-none} checks=$CHECK_BUCKETS), skipping"
                    continue
                fi

                log "PR #$PR_NUM ready (merge=$MERGE_STATE review=${REVIEW_DECISION:-none} checks=$CHECK_BUCKETS), merging..."
                gh pr merge "$PR_NUM" --repo "$REPO" --merge 2>/dev/null && \
                    $AGORA --room collab send "AutoAgent merged PR #$PR_NUM (required checks green)" 2>/dev/null || true
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
