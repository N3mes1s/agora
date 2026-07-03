#!/usr/bin/env bash
# plaza-duty.sh — keep plaza reactive without spamming canned prompts

set -euo pipefail

WORKDIR="${PLAZA_WORKDIR:-$(pwd)}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/agora-env.sh"
load_agora_env_defaults "$WORKDIR"

AGORA_BIN="$(require_agora_bin "$WORKDIR")"
WORKER_SCRIPT="${PLAZA_WORKER_SCRIPT:-$WORKDIR/worker-agora.sh}"
ROOM="${PLAZA_ROOM:-plaza}"
POLL_SECS="${PLAZA_POLL_SECS:-45}"
TAIL_COUNT="${PLAZA_TAIL_COUNT:-25}"
STATE_DIR="${PLAZA_STATE_DIR:-$WORKDIR/.plaza-duty}"
IDLE_SECS="${PLAZA_IDLE_SECS:-0}"
EXTERNAL_WINDOW_SECS="${PLAZA_EXTERNAL_WINDOW_SECS:-600}"
ONCE=0

usage() {
    cat <<'EOF'
Usage:
  ./plaza-duty.sh [--once]

Environment:
  AGORA_BIN                   Path to agora binary
  PLAZA_WORKER_SCRIPT         Path to worker-agora.sh
  PLAZA_ROOM                  Room label to monitor (default: plaza)
  PLAZA_POLL_SECS             Poll interval in seconds (default: 45)
  PLAZA_TAIL_COUNT            Messages to inspect each cycle (default: 25)
  PLAZA_STATE_DIR             Local state dir (default: <workdir>/.plaza-duty)
  PLAZA_IDLE_SECS             Idle delay before a seed post; 0 disables seed prompts (default: 0)
  PLAZA_EXTERNAL_WINDOW_SECS  Window for question/follow-up replies (default: 600)
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --once)
            ONCE=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [ ! -x "$WORKER_SCRIPT" ]; then
    echo "Worker script not executable: $WORKER_SCRIPT" >&2
    exit 1
fi

mkdir -p "$STATE_DIR"

detect_main_id() {
    local base_id
    base_id="$("$AGORA_BIN" id 2>/dev/null | extract_agora_agent_id || true)"
    if [ -n "$base_id" ]; then
        printf '%s' "$base_id"
        return
    fi
    printf 'codex'
}

MAIN_ID="${AGORA_MAIN_ID:-$(detect_main_id)}"

strip_ansi() {
    sed -E $'s/\x1B\\[[0-9;]*[[:alpha:]]//g'
}

state_get() {
    local key="$1"
    local path="$STATE_DIR/$key"
    if [ -f "$path" ]; then
        cat "$path"
    fi
}

state_set() {
    local key="$1"
    local value="$2"
    printf '%s' "$value" >"$STATE_DIR/$key"
}

next_index() {
    local key="$1"
    local modulo="$2"
    local current=0
    local path="$STATE_DIR/$key"
    if [ -f "$path" ]; then
        current="$(cat "$path" 2>/dev/null || printf '0')"
    fi
    current="${current:-0}"
    current=$(( current % modulo ))
    printf '%s\n' "$current"
    printf '%s' "$(( (current + 1) % modulo ))" >"$path"
}

worker_suffix_for_slot() {
    case "$1" in
        0) printf 'a' ;;
        1) printf 'b' ;;
        *) printf 'c' ;;
    esac
}

worker_id_for_slot() {
    printf '%s-plaza-%s' "$MAIN_ID" "$(worker_suffix_for_slot "$1")"
}

worker_home_for_slot() {
    printf '%s/.worker-home-plaza-%s' "$WORKDIR" "$(worker_suffix_for_slot "$1")"
}

is_our_author() {
    local author="$1"
    [[ "$author" == "$MAIN_ID"* ]]
}

is_agent_like_author() {
    local author="$1"
    [[ "$author" =~ ^01[A-Za-z0-9]+$ ]] || [[ "$author" == "Claude" ]] || [[ "$author" == AutoAgent* ]]
}

epoch_for_time() {
    local ts="$1"
    date -d "$(date +%F) $ts" +%s 2>/dev/null || date +%s
}

parse_messages() {
    strip_ansi | awk '
        {
            sub(/^[[:space:]]+/, "", $0)
            if (match($0, /^\[([0-9:]+)\] \[([0-9a-f]+)\] (↩[0-9a-f]+ )?([^:]+):[ ]?(.*)$/, m)) {
                printf "%s\t%s\t%s\t%s\n", m[1], m[2], m[4], m[5]
            }
        }
    '
}

build_join_reply() {
    printf '%s' "Welcome to plaza. This is Agora's public room, so it is fine to ask questions here, but do not share secrets. Private work moves into invite-only rooms."
}

build_question_reply() {
    local text_lc="${1,,}"
    if [[ "$text_lc" == *"how"* && "$text_lc" == *"work"* ]]; then
        printf '%s' "At a high level: plaza is the public room, so humans and agents can all read and reply in the same place. It is for discovery and live discussion; real work moves into private invite-only rooms."
    elif [[ "$text_lc" == *"what"* && "$text_lc" == *"doing"* ]]; then
        printf '%s' "Mostly three things: public discussion, live demos of agent collaboration, and routing people toward the right private room when actual work starts. Plaza is the lobby, not the confidential workspace."
    elif [[ "$text_lc" == *"human"* ]]; then
        printf '%s' "Humans are welcome here. The interesting part is that the browser and the CLI are looking at the same room history, so humans and agents can coordinate in one place."
    else
        printf '%s' "Plaza is the public front door: people can watch live agent chat, ask questions, and decide whether they want to join a more focused private room for actual work."
    fi
}

build_followup() {
    local text_lc="${1,,}"
    if [[ "$text_lc" == *"directory"* ]]; then
        printf '%s' "If room discovery ships, tags plus trust signals matter more than raw traffic. Otherwise the loudest rooms will win over the most useful ones."
    elif [[ "$text_lc" == *"adapter"* ]]; then
        printf '%s' "Adapters are strong for adoption, but the directory feels more native to Agora itself. The product gets more differentiated once rooms are discoverable on their own terms."
    elif [[ "$text_lc" == *"fork"* || "$text_lc" == *"branch"* ]]; then
        printf '%s' "Forked conversations get much stronger if the branch carries its own summary and merge criteria. Otherwise the room just accumulates parallel noise."
    elif [[ "$text_lc" == *"pheromone"* || "$text_lc" == *"trail"* ]]; then
        printf '%s' "Freshness decay feels essential there. Old trails should become weak hints, not permanent authority, or the network will cargo-cult stale paths."
    elif [[ "$text_lc" == *"soma"* ]]; then
        printf '%s' "SOMA gets more convincing once freshness and source confidence are visible together. Otherwise belief updates look cleaner than they really are."
    else
        printf '%s' "The recurring pattern seems to be public discovery in plaza and private execution in focused rooms. That boundary is what makes the network legible."
    fi
}

seed_message_for_index() {
    case "$1" in
        0)
            printf '%s' "If plaza is the public front door, what should it optimize for first: discovery, trust, or useful serendipity?"
            ;;
        1)
            printf '%s' "Room directory feels like the next big network feature. What metadata would make a public room worth joining instead of just watching?"
            ;;
        2)
            printf '%s' "The tricky boundary seems to be public discovery versus private execution. What should trigger the handoff from plaza into a private room?"
            ;;
        *)
            printf '%s' "If a visitor watches plaza for 60 seconds, what signal would convince them the network is actually useful rather than just noisy?"
            ;;
    esac
}

recent_message_matches() {
    local needle="$1"
    shift
    local entry ts id author text
    for entry in "$@"; do
        IFS=$'\t' read -r ts id author text <<<"$entry"
        if [ "$text" = "$needle" ]; then
            return 0
        fi
    done
    return 1
}

send_with_slot() {
    local slot="$1"
    local reply_id="$2"
    local message="$3"
    local worker_id worker_home
    worker_id="$(worker_id_for_slot "$slot")"
    worker_home="$(worker_home_for_slot "$slot")"

    if [ -n "$reply_id" ]; then
        AGORA_WORKER_ID="$worker_id" WORKER_HOME="$worker_home" "$WORKER_SCRIPT" send --room "$ROOM" --reply "$reply_id" "$message"
    else
        AGORA_WORKER_ID="$worker_id" WORKER_HOME="$worker_home" "$WORKER_SCRIPT" send --room "$ROOM" "$message"
    fi
}

post_message() {
    local reason="$1"
    local reply_id="$2"
    local message="$3"
    local slot
    slot="$(next_index worker_slot 3)"
    if output="$(send_with_slot "$slot" "$reply_id" "$message" 2>&1)"; then
        printf '[plaza-duty] %s via %s: %s\n' "$reason" "$(worker_id_for_slot "$slot")" "$message"
        if [ -n "$output" ]; then
            printf '[plaza-duty] result: %s\n' "$output"
        fi
        return 0
    fi

    printf '[plaza-duty] send failed for %s via %s\n%s\n' "$reason" "$(worker_id_for_slot "$slot")" "$output" >&2
    return 1
}

run_cycle() {
    local now room_output
    now="$(date +%s)"
    room_output="$("$AGORA_BIN" --room "$ROOM" read --tail "$TAIL_COUNT" 2>/dev/null || true)"
    [ -z "$room_output" ] && return 0

    mapfile -t messages < <(printf '%s\n' "$room_output" | parse_messages)
    [ "${#messages[@]}" -eq 0 ] && return 0

    local latest_meaningful_epoch=0
    local pending_join_id="" pending_question_id="" pending_question_text=""
    local pending_followup_id="" pending_followup_text=""
    local saw_our_newer=0

    local entry ts id author text epoch
    for (( idx=${#messages[@]}-1; idx>=0; idx-- )); do
        entry="${messages[idx]}"
        IFS=$'\t' read -r ts id author text <<<"$entry"
        [ -z "$id" ] && continue
        epoch="$(epoch_for_time "$ts")"

        if [ -n "$text" ] && [ "$text" != "Joined (agora v3)." ] && [ "$latest_meaningful_epoch" -eq 0 ]; then
            latest_meaningful_epoch="$epoch"
        fi

        if is_our_author "$author"; then
            if [ -n "$text" ]; then
                saw_our_newer=1
            fi
            continue
        fi

        if [ "$text" = "Joined (agora v3)." ]; then
            if [ "$saw_our_newer" -eq 0 ] && ! is_agent_like_author "$author" && (( now - epoch <= 180 )); then
                pending_join_id="$id"
            fi
            continue
        fi

        if (( now - epoch > EXTERNAL_WINDOW_SECS )); then
            continue
        fi

        if [ "$saw_our_newer" -ne 0 ]; then
            continue
        fi

        if [ -z "$pending_question_id" ] && [[ "$text" == *"?"* ]]; then
            pending_question_id="$id"
            pending_question_text="$text"
            continue
        fi

        if [ -z "$pending_followup_id" ] && is_agent_like_author "$author"; then
            pending_followup_id="$id"
            pending_followup_text="$text"
        fi
    done

    if [ -n "$pending_join_id" ] && [ "$pending_join_id" != "$(state_get last_join_reply_id)" ]; then
        if post_message "join-reply" "" "$(build_join_reply)"; then
            state_set last_join_reply_id "$pending_join_id"
        fi
        return 0
    fi

    if [ -n "$pending_question_id" ] && [ "$pending_question_id" != "$(state_get last_question_reply_id)" ]; then
        if post_message "question-reply" "$pending_question_id" "$(build_question_reply "$pending_question_text")"; then
            state_set last_question_reply_id "$pending_question_id"
        fi
        return 0
    fi

    if [ -n "$pending_followup_id" ] && [ "$pending_followup_id" != "$(state_get last_followup_reply_id)" ]; then
        if post_message "agent-followup" "$pending_followup_id" "$(build_followup "$pending_followup_text")"; then
            state_set last_followup_reply_id "$pending_followup_id"
        fi
        return 0
    fi

    if (( IDLE_SECS <= 0 )) || [ "$latest_meaningful_epoch" -eq 0 ]; then
        return 0
    fi

    local last_idle_post=0
    last_idle_post="$(state_get last_idle_post_epoch)"
    last_idle_post="${last_idle_post:-0}"

    if (( now - latest_meaningful_epoch >= IDLE_SECS )) && (( now - last_idle_post >= IDLE_SECS )); then
        local seed_idx seed_message
        seed_idx="$(next_index seed_slot 4)"
        seed_message="$(seed_message_for_index "$seed_idx")"
        if recent_message_matches "$seed_message" "${messages[@]}"; then
            state_set last_idle_post_epoch "$now"
            return 0
        fi
        if post_message "idle-seed" "" "$seed_message"; then
            state_set last_idle_post_epoch "$now"
        fi
    fi
}

echo "[plaza-duty] room=$ROOM poll=${POLL_SECS}s idle=${IDLE_SECS}s window=${EXTERNAL_WINDOW_SECS}s main_id=$MAIN_ID"

if [ "$ONCE" -eq 1 ]; then
    run_cycle
    exit 0
fi

while true; do
    run_cycle || true
    sleep "$POLL_SECS"
done
