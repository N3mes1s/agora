#!/bin/sh
# M4 canary: hooks install/remove in a throwaway HOME seeded from the real
# one. Asserts: stopgap migrated, idempotent second install, remove restores
# the original byte-for-byte, the real systemd service is NEVER touched
# (failing systemctl shim first on PATH — lead ruling a95539), and the
# installed unit carries no placeholders.
set -e
AGORA="$PWD/target/debug/agora"
export AGORA_SCRIPTS_DIR="$PWD/scripts"
CANARY=$(mktemp -d /tmp/m4-hooks-canary.XXXXXX)
trap 'rm -rf "$CANARY" "$SHIMDIR"' EXIT
# Precondition gate (qa 878845a): isolation must be proven BEFORE the first
# install, not after — this canary never writes outside its throwaway HOME.
REAL_HOME=$(getent passwd "$(id -u)" | cut -d: -f6)
if [ "$(cd "$CANARY" && pwd)" = "$(cd "$REAL_HOME" 2>/dev/null && pwd)" ]; then
  echo "FAIL: canary HOME resolves to the real home; refusing to run"; exit 1
fi
# Failing systemctl shim first on PATH (lead ruling a95539 (2)): any systemctl
# call from the canary fails the run.
SHIMDIR=$(mktemp -d /tmp/m4-systemctl-shim.XXXXXX)
cat > "$SHIMDIR/systemctl" <<'SHIM'
#!/bin/sh
echo "SHIM-MUST-NOT-RUN: systemctl called with: $*" >&2
exit 99
SHIM
chmod +x "$SHIMDIR/systemctl"
PATH="$SHIMDIR:$PATH"
export PATH
mkdir -p "$CANARY/.claude" "$CANARY/.omp/agent/extensions" "$CANARY/.config/systemd/user" "$CANARY/.local/bin"
cp "$REAL_HOME/.claude/settings.json" "$CANARY/.claude/settings.json"
BEFORE=$(md5sum < "$CANARY/.claude/settings.json")

echo "== install claude =="
HOME="$CANARY" $AGORA hooks install claude | sed 's/^/  /'
grep -q '"asyncRewake": true' "$CANARY/.claude/settings.json" || { echo "FAIL: no asyncRewake"; exit 1; }
grep -q 'agora-wait' "$CANARY/.claude/settings.json" && { echo "FAIL: stopgap still present"; exit 1; }
grep -q '"command": ".*agora wait"' "$CANARY/.claude/settings.json" || { echo "FAIL: no agora wait entry"; exit 1; }
python3 -c "import json;json.load(open('$CANARY/.claude/settings.json'))" || { echo "FAIL: invalid json"; exit 1; }
echo "  migrated + valid json OK"

echo "== second install is a no-op =="
AFTER1=$(md5sum < "$CANARY/.claude/settings.json")
HOME="$CANARY" $AGORA hooks install claude > /dev/null
AFTER2=$(md5sum < "$CANARY/.claude/settings.json")
[ "$AFTER1" = "$AFTER2" ] || { echo "FAIL: second install changed the file"; exit 1; }
echo "  idempotent OK"

echo "== omp + codex install (no --systemd: files only) =="
HOME="$CANARY" $AGORA hooks install omp | sed 's/^/  /'
test -s "$CANARY/.omp/agent/extensions/agora-wake.ts" || { echo "FAIL: no omp extension"; exit 1; }
grep -q '__AGORA_BIN__' "$CANARY/.omp/agent/extensions/agora-wake.ts" \
  && { echo "FAIL: omp extension ships unsubstituted placeholder"; exit 1; }
# The embedded path is the installing binary's current_exe (may be an
# mbx-managed target path in dev); assert it is absolute and executable.
EMBEDDED=$(sed -n 's/^const WAIT = "\(.*\)";$/\1/p' "$CANARY/.omp/agent/extensions/agora-wake.ts")
case "$EMBEDDED" in
  /*) test -x "$EMBEDDED" || { echo "FAIL: embedded agora path not executable: $EMBEDDED"; exit 1; } ;;
  *) echo "FAIL: omp extension embeds a non-absolute path: $EMBEDDED"; exit 1 ;;
esac
HOME="$CANARY" $AGORA hooks install codex | sed 's/^/  /'
test -s "$CANARY/.local/bin/agora-wake-bridge" || { echo "FAIL: no bridge"; exit 1; }
echo "  omp + codex files OK"
# Incident 066bf6 d2 / ruling (3): no placeholder may ship; %h paths; the
# agent id must be derived from the REAL hostname at install time.
grep -q '/home/<user>' "$CANARY/.config/systemd/user/agora-wake-bridge.service" \
  && { echo "FAIL: unit ships placeholder /home/<user>"; exit 1; }
grep -q '__AGORA_HOST__' "$CANARY/.config/systemd/user/agora-wake-bridge.service" \
  && { echo "FAIL: unit ships unsubstituted host placeholder"; exit 1; }
grep -q '^ExecStart=%h/.local/bin/agora-wake-bridge' "$CANARY/.config/systemd/user/agora-wake-bridge.service" \
  || { echo "FAIL: unit ExecStart is not %h-based"; exit 1; }
REALHOST=$(cat /proc/sys/kernel/hostname)
grep -q "agora-wake-bridge@$REALHOST" "$CANARY/.config/systemd/user/agora-wake-bridge.service" \
  || { echo "FAIL: unit agent id not derived from real hostname"; exit 1; }
echo "  unit valid (%h + real hostname)"
# qa 061352 (b): dry-run the installed unit with systemd-analyze verify —
# proves the unit PARSES and ExecStart/environment resolve, beyond greps.
# It runs offline (no manager) and reads only the throwaway unit.
if command -v systemd-analyze >/dev/null 2>&1; then
  # Resolve %h for the canary HOME the way the user manager would.
  sed "s|%h|$CANARY|g" "$CANARY/.config/systemd/user/agora-wake-bridge.service" \
    > "$CANARY/.config/systemd/user/agora-wake-bridge.resolved.service"
  if systemd-analyze verify "$CANARY/.config/systemd/user/agora-wake-bridge.resolved.service" 2>/tmp/m4-canary-verify.err; then
    echo "  systemd-analyze verify OK"
  else
    echo "FAIL: systemd-analyze verify rejected the installed unit:"; cat /tmp/m4-canary-verify.err; exit 1
  fi
  rm -f "$CANARY/.config/systemd/user/agora-wake-bridge.resolved.service"
else
  echo "  (systemd-analyze absent; skipped)"
fi

echo "== remove restores =="
HOME="$CANARY" $AGORA hooks remove claude > /dev/null
HOME="$CANARY" $AGORA hooks remove omp > /dev/null
HOME="$CANARY" $AGORA hooks remove codex > /dev/null
RESTORED=$(md5sum < "$CANARY/.claude/settings.json")
[ "$BEFORE" = "$RESTORED" ] || { echo "FAIL: settings not byte-identical after remove"; exit 1; }
test ! -e "$CANARY/.omp/agent/extensions/agora-wake.ts" || { echo "FAIL: omp extension remains"; exit 1; }
echo "  restore byte-for-byte OK"
# Ruling (2): the failing shim proves no systemctl call happened at all.
echo "  systemctl never called (shim would have failed the run)"
echo "CANARY PASS"
