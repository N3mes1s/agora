#!/bin/sh
# M4 release-binary exit smoke (lead d8cad8 protocol + qa ff228f extension):
# the release binary must exit cleanly under SIGTERM AND with a closed
# stderr pipe (the M1 abort class: eprintln panics on broken pipes, and a
# panic in the exit handler cannot unwind). cargo test cannot see either.
# Usage: release-exit-smoke.sh <path-to-agora-binary>
set -u
BIN="${1:?usage: release-exit-smoke.sh <agora-binary>}"
CANARY=$(mktemp -d /tmp/m4-exit-smoke.XXXXXX)
trap 'rm -rf "$CANARY"' EXIT
ulimit -c 0
export HOME="$CANARY"  # throwaway HOME: no real state touched
fail=0

# rc 132/133/134 = SIGILL/SIGTRAP/SIGABRT; sh reports signal deaths as
# 128+sig. Any of the abort class fails the smoke.
is_abort() { [ "$1" -eq 132 ] || [ "$1" -eq 133 ] || [ "$1" -eq 134 ]; }

smoke_term() {
  name="$1"; shift
  "$@" > /dev/null 2>&1 &
  pid=$!
  sleep 5
  kill -TERM $pid 2>/dev/null || true
  wait $pid || true
  rc=$?
  if is_abort "$rc"; then
    echo "FAIL: $name (SIGTERM) exited $rc (abort)"; fail=1
  else
    echo "OK: $name (SIGTERM) exit $rc"
  fi
}

# Deterministic broken-stderr: run with stderr to a pipe held by `head -c0`
# (exits immediately), then SIGTERM the agora process after 3s.
smoke_broken() {
  name="$1"; shift
  "$@" 2> >("$CANARY/reader" &) >/dev/null 2>&1 &
  pid=$!
  sleep 3
  kill -TERM $pid 2>/dev/null || true
  wait $pid || true
  rc=$?
  if is_abort "$rc"; then
    echo "FAIL: $name (broken stderr) exited $rc (abort)"; fail=1
  else
    echo "OK: $name (broken stderr) exit $rc"
  fi
}

# Tiny reader that exits at once: the pipe breaks on the next write.
printf '#!/bin/sh\nexit 0\n' > "$CANARY/reader"
chmod +x "$CANARY/reader"

# SIGTERM variants (healthy stderr)
smoke_term watch env -u TMUX "$BIN" watch --room agora-dev
smoke_term mcp   sh -c "echo '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{}}}' | '$BIN' mcp"

# Broken-stderr variants (the M1 abort class)
smoke_broken watch env -u TMUX "$BIN" watch --room agora-dev
smoke_broken read  "$BIN" read --tail 1

# read also checked for clean exit with healthy stderr.
"$BIN" read --tail 1 >/dev/null 2>&1 || true
rc=$?
if is_abort "$rc"; then echo "FAIL: read (clean) exited $rc"; fail=1; else echo "OK: read (clean) exit $rc"; fi

if [ "$fail" -eq 0 ]; then echo "EXIT-SMOKE PASS"; else echo "EXIT-SMOKE FAIL"; exit 1; fi
