#!/usr/bin/env bash
# rollout.sh — install agora as the local agent bus on this host.
#
# Installs the binary, writes ~/.agora/config.toml (local relay URL + token
# file), installs per-agent identity helpers (AGORA_AGENT_ID derived per tmux
# window), and wires the agora MCP server / skill / wake hook into the
# selected agent runtimes (Claude Code, Codex, OMP). Every change is printed;
# existing files are backed up (*.bak-agora-<ts>) before being edited, and
# re-running is idempotent.
#
# Usage:
#   scripts/rollout.sh --relay-url nats://127.0.0.1:4222 --token-file ./relay.token \
#       [--binary target/release/agora] [--runtimes claude-code,codex,omp] \
#       [--invite agr_...] [--room ops] [--prefix ~/.local] [--dry-run]
#
# Agent ids: every shell sources ~/.agora/env.sh, which exports
#   AGORA_AGENT_ID=<host>-<tmux session>-w<window index>   (inside tmux)
#   AGORA_AGENT_ID=<host>-<user>                            (outside tmux)
# unless AGORA_AGENT_ID is already set. One agent per tmux window.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELAY_URL=""
TOKEN_FILE=""
BINARY=""
RUNTIMES="claude-code,codex,omp"
INVITE=""
ROOM=""
PREFIX="$HOME/.local"
DRY_RUN=0
TS="$(date +%Y%m%d%H%M%S)"
AGORA_HOME="$HOME/.agora"

usage() { sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --relay-url) RELAY_URL="$2"; shift 2 ;;
    --token-file) TOKEN_FILE="$2"; shift 2 ;;
    --binary) BINARY="$2"; shift 2 ;;
    --runtimes) RUNTIMES="$2"; shift 2 ;;
    --invite) INVITE="$2"; shift 2 ;;
    --room) ROOM="$2"; shift 2 ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage 0 ;;
    *) echo "rollout: unknown argument: $1" >&2; usage 64 ;;
  esac
done

say() { printf '  %s\n' "$*"; }
changed() { printf '  \033[92m+\033[0m %s\n' "$*"; }
run() {
  if [ "$DRY_RUN" = 1 ]; then printf '  [dry-run] %s\n' "$*"; else "$@"; fi
}
backup() {
  [ -e "$1" ] || return 0
  run cp -p "$1" "$1.bak-agora-$TS"
  changed "backed up $1 -> $1.bak-agora-$TS"
}
has_runtime() { case ",$RUNTIMES," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }

# ── 1. binary ───────────────────────────────────────────────────────
if [ -z "$BINARY" ]; then
  for c in "$REPO/target/release/agora" "$(command -v agora 2>/dev/null || true)"; do
    if [ -n "$c" ] && [ -x "$c" ]; then BINARY="$c"; break; fi
  done
fi
[ -n "$BINARY" ] && [ -x "$BINARY" ] || {
  echo "rollout: no agora binary; build one (cargo build --release) or pass --binary" >&2; exit 1; }
DEST="$PREFIX/bin/agora"
if [ "$(readlink -f "$BINARY")" != "$(readlink -f "$DEST" 2>/dev/null || true)" ]; then
  run install -D -m 0755 "$BINARY" "$DEST"
  changed "installed $BINARY -> $DEST"
else
  say "binary already at $DEST"
fi
AGORA="$DEST"
[ "$DRY_RUN" = 1 ] && AGORA="$BINARY"

# ── 2. config + relay token ─────────────────────────────────────────
run install -d -m 0700 "$AGORA_HOME" "$AGORA_HOME/bin"
CONFIG="$AGORA_HOME/config.toml"
if [ -n "$TOKEN_FILE" ]; then
  [ -r "$TOKEN_FILE" ] || { echo "rollout: cannot read $TOKEN_FILE" >&2; exit 1; }
  run install -m 0600 "$TOKEN_FILE" "$AGORA_HOME/relay.token"
  changed "relay token -> $AGORA_HOME/relay.token (0600)"
fi
if [ -f "$CONFIG" ]; then
  say "keeping existing $CONFIG (edit it by hand to change relay settings)"
else
  [ -n "$RELAY_URL" ] || { echo "rollout: --relay-url is required for a new config" >&2; exit 64; }
  if [ "$DRY_RUN" = 1 ]; then
    say "[dry-run] would write $CONFIG"
  else
    umask 077
    {
      echo "# agora local bus — written by scripts/rollout.sh on $TS"
      echo "relay_url = \"$RELAY_URL\""
      [ -n "$TOKEN_FILE" ] && echo "relay_token_file = \"~/.agora/relay.token\""
      echo "local_only = true"
      echo "# JetStream stream limits used when agora creates the AGORA stream"
      echo "nats_max_age = \"30d\""
      echo "nats_max_bytes = \"1073741824\""
    } > "$CONFIG"
    chmod 600 "$CONFIG"
  fi
  changed "wrote $CONFIG (relay_url=$RELAY_URL, local_only=true)"
fi

# ── 3. identity helpers ─────────────────────────────────────────────
write_file() { # path mode content
  if [ "$DRY_RUN" = 1 ]; then say "[dry-run] would write $1"; return; fi
  printf '%s' "$3" > "$1"; chmod "$2" "$1"
}
write_file "$AGORA_HOME/bin/agora-agent-id" 0755 '#!/bin/sh
# Print the agent id for this shell: $AGORA_AGENT_ID, else derived from the
# tmux window (<host>-<session>-w<index>), else <host>-<user>. Pane ids are only
# unique within one tmux server, so only our own server ($TMUX pid) may name the
# window; a pane of an older server that lost its socket is <host>-t<pid>-p<pane>.
if [ -n "${AGORA_AGENT_ID:-}" ]; then echo "$AGORA_AGENT_ID"; exit 0; fi
host=$(hostname -s 2>/dev/null || hostname)
pid=$(printf "%s" "${TMUX:-}" | cut -d, -f2)
if [ -n "$pid" ] && [ -n "${TMUX_PANE:-}" ] && command -v tmux >/dev/null 2>&1; then
  out=$(tmux display-message -p -t "$TMUX_PANE" "#{pid} #S-w#I" 2>/dev/null || true)
  w=${out#"$pid "}; s=${w%-w*}; i=${w##*-w}
  if [ "$w" = "$out" ] || [ -z "$s" ] || [ "$s" = "$w" ] || [ -z "$i" ] || [ -n "$(printf "%s" "$i" | tr -d 0-9)" ]; then
    w="t$pid-p${TMUX_PANE#%}"
  fi
  printf "%s-%s\n" "$host" "$w" | tr -c "A-Za-z0-9._\n-" "-"; exit 0
fi
printf "%s-%s\n" "$host" "${USER:-agent}" | tr -c "A-Za-z0-9._\n-" "-"
'
changed "wrote $AGORA_HOME/bin/agora-agent-id"

write_file "$AGORA_HOME/bin/agora-mcp" 0755 '#!/bin/sh
# MCP launcher: some runtimes start MCP servers with a scrubbed environment,
# so recover AGORA_AGENT_ID from the parent (the agent process) if needed.
if [ -z "${AGORA_AGENT_ID:-}" ] && [ -r "/proc/$PPID/environ" ]; then
  id=$(tr "\0" "\n" < "/proc/$PPID/environ" | sed -n "s/^AGORA_AGENT_ID=//p" | head -n 1)
  [ -n "$id" ] && export AGORA_AGENT_ID="$id"
fi
exec AGORA_BIN mcp "$@"
'
if [ "$DRY_RUN" = 0 ]; then
  sed -i "s#AGORA_BIN#$DEST#" "$AGORA_HOME/bin/agora-mcp"
fi
changed "wrote $AGORA_HOME/bin/agora-mcp (execs $DEST)"

write_file "$AGORA_HOME/env.sh" 0644 '# agora local bus — sourced from your shell rc (scripts/rollout.sh)
for d in "$HOME/.agora/bin" "AGORA_PREFIX_BIN"; do
  case ":$PATH:" in *":$d:"*) ;; *) PATH="$d:$PATH" ;; esac
done
export PATH
if [ -z "${AGORA_AGENT_ID:-}" ] && [ -x "$HOME/.agora/bin/agora-agent-id" ]; then
  AGORA_AGENT_ID="$("$HOME/.agora/bin/agora-agent-id")"
  export AGORA_AGENT_ID
fi
'
if [ "$DRY_RUN" = 0 ]; then
  sed -i "s#AGORA_PREFIX_BIN#$PREFIX/bin#" "$AGORA_HOME/env.sh"
fi
changed "wrote $AGORA_HOME/env.sh (PATH += ~/.agora/bin $PREFIX/bin; AGORA_AGENT_ID per tmux window)"

for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
  [ -f "$rc" ] || continue
  if grep -q '# agora-local-bus' "$rc"; then
    say "$rc already sources ~/.agora/env.sh"
  else
    backup "$rc"
    if [ "$DRY_RUN" = 0 ]; then
      printf '\n[ -f "$HOME/.agora/env.sh" ] && . "$HOME/.agora/env.sh"  # agora-local-bus\n' >> "$rc"
    fi
    changed "$rc now sources ~/.agora/env.sh"
  fi
done

# ── 4. runtimes ─────────────────────────────────────────────────────
SKILL_SRC="$REPO/plugins/claude-code/skills/chat"
MCP_CMD="$AGORA_HOME/bin/agora-mcp"

if has_runtime claude-code; then
  run install -d "$HOME/.claude/skills/agora"
  run cp "$SKILL_SRC/SKILL.md" "$HOME/.claude/skills/agora/SKILL.md"
  changed "Claude Code skill -> ~/.claude/skills/agora/SKILL.md"
  if command -v claude >/dev/null 2>&1; then
    if claude mcp get agora >/dev/null 2>&1; then
      say "Claude Code MCP server 'agora' already registered (claude mcp get agora)"
    else
      run claude mcp add --scope user agora -- "$MCP_CMD"
      changed "claude mcp add --scope user agora -- $MCP_CMD"
    fi
  else
    say "claude not on PATH; register later: claude mcp add --scope user agora -- $MCP_CMD"
  fi
  SETTINGS="$HOME/.claude/settings.json"
  HOOK_CMD="$DEST check --wake"
  if [ -f "$SETTINGS" ] && grep -q "agora check --wake" "$SETTINGS"; then
    say "Claude Code wake hook already present in $SETTINGS"
  elif command -v jq >/dev/null 2>&1; then
    backup "$SETTINGS"
    if [ "$DRY_RUN" = 0 ]; then
      tmp="$(mktemp)"
      [ -f "$SETTINGS" ] || echo '{}' > "$SETTINGS"
      jq --arg cmd "$HOOK_CMD" '.hooks.PostToolUse = ((.hooks.PostToolUse // []) +
          [{"hooks": [{"type": "command", "command": $cmd, "asyncRewake": true, "timeout": 8}]}])' \
        "$SETTINGS" > "$tmp" && mv "$tmp" "$SETTINGS"
    fi
    changed "added PostToolUse asyncRewake hook '$HOOK_CMD' to $SETTINGS"
  else
    say "jq not found; add this PostToolUse hook to $SETTINGS by hand:"
    say "  {\"hooks\":{\"PostToolUse\":[{\"hooks\":[{\"type\":\"command\",\"command\":\"$HOOK_CMD\",\"asyncRewake\":true,\"timeout\":8}]}]}}"
  fi
fi

if has_runtime codex; then
  CODEX_CFG="$HOME/.codex/config.toml"
  if [ -f "$CODEX_CFG" ] && grep -q '^\[mcp_servers\.agora\]' "$CODEX_CFG"; then
    say "Codex already has [mcp_servers.agora] in $CODEX_CFG"
  else
    run install -d "$HOME/.codex"
    backup "$CODEX_CFG"
    if [ "$DRY_RUN" = 0 ]; then
      printf '\n# agora-plugin:agora begin\n[mcp_servers.agora]\ncommand = "%s"\nargs = []\n# agora-plugin:agora end\n' \
        "$MCP_CMD" >> "$CODEX_CFG"
    fi
    changed "added [mcp_servers.agora] (command = $MCP_CMD) to $CODEX_CFG"
  fi
  run install -d "$HOME/.codex/skills/agora"
  run cp "$SKILL_SRC/SKILL.md" "$HOME/.codex/skills/agora/SKILL.md"
  changed "Codex skill -> ~/.codex/skills/agora/SKILL.md"
fi

if has_runtime omp; then
  run install -d "$HOME/.omp/skills/agora"
  run cp "$REPO/plugins/omp/skills/agora/SKILL.md" "$HOME/.omp/skills/agora/SKILL.md"
  changed "OMP skill -> ~/.omp/skills/agora/SKILL.md"
  say "OMP MCP: add {\"mcpServers\":{\"agora\":{\"command\":\"$MCP_CMD\",\"args\":[]}}} to your OMP MCP config"
fi

# ── 5. relay check + optional room ──────────────────────────────────
if [ "$DRY_RUN" = 0 ]; then
  if "$AGORA" test >/dev/null 2>&1; then
    say "relay reachable: $("$AGORA" info 2>/dev/null | head -n 1 || true)"
  fi
  if [ -n "$INVITE" ]; then
    "$AGORA" accept "$INVITE" && changed "joined room from invite"
  fi
  if [ -n "$ROOM" ] && "$AGORA" switch "$ROOM" >/dev/null 2>&1; then
    changed "active room: $ROOM"
  fi
fi

echo
say "Done. Open a new shell (or: . ~/.agora/env.sh) and check:"
say "  agora id            # AGORA_AGENT_ID for this tmux window"
say "  agora lease list    # talks to the relay; fails closed if misconfigured"
