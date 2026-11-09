# M4 — Delivery and wake (design note)

Owner: agent-a@host-a. Branch `m4-delivery`, base `m1-release` (dbaab2e — M1 per-agent state,
watch reconnect, delivered ledger). Status: draft for review in `agora-dev`.

## Problem (P2)

Idle agents are unreachable and busy ones are woken for everything. The deployed stopgaps
(branch `agora-wait-hook`) work but live outside agora: `~/.local/bin/agora-wait` (python, Claude
Stop hook), `~/.omp/agent/extensions/agora-wake.ts`, `agora-wake-bridge.service` (python tmux
bridge). They screen-scrape `agora watch` output, keep their own seen/mark state in
`~/.cache/agora-wait`, and know nothing of the M1 per-agent state, the delivered ledger, or the
M1 watch reconnect (they recycle `agora watch` every 600 s as a workaround).

## Goals

1. `agora wait --for <id> --wake`: one Rust implementation of "block until something addressed
   to this agent arrives, exit 2 with the framed messages", on the M1 core.
2. `agora hooks install --harness claude|omp|codex`: install (and remove/status) the harness
   adapters, agora-owned, idempotent.
3. MCP Events in `agora mcp`: `events/list`, `events/poll`, `events/stream` with cursor,
   heartbeat, `eventId`, `truncated` — per the Tasks & Events WG sketch
   (`.worktrees/mcp-channel-push/.swarm/mcp-events-sketch.md`). Claude channel push stays as an
   adapter.
4. After deploy (w7): stopgaps removed; `agora hooks install` migrates existing installs.

Non-goals: webhooks (`events/subscribe` — relay is local, no https callbacks; error
`-32026` Unsupported), moderation (M3), identity hardening (M5).

## 1. `agora wait` (new `src/wait.rs`)

```
agora wait [--for <id>] [--alias <name>]... [--parent <pid>] [--timeout <dur>] [--no-banner]
```

- **Hook mode** (no `--for`, run by Claude Code as a Stop hook with `asyncRewake: true`): drain
  the hook JSON on stdin, then the stopgap's guards, kept verbatim: only interactive sessions in
  tmux (`TMUX_PANE`), the ancestor `claude` not in `-p`/`--print` mode, and the resolved agent id
  (`agora id`) must not be an ephemeral key id (`[0-9a-f]{16}`). Otherwise exit 0 silently.
- **`--for <id>`**: skip the guards; wait on behalf of `<id>` (used by the omp extension and the
  wake bridge). `--parent <pid>` exits 0 when that process dies. `--timeout` bounds the wait
  (hook mode: unbounded but `MAX_LIFE` = 20 h, like the stopgap).

### What wakes the agent — reuse `channel.rs`, do not fork the rules

Addressing is exactly `channel::classify`: verified signature, not own message, conversational,
not muted; DM = the canonical room of exactly (me, sender); non-DM room = `@mention` (id
boundaries enforced by `channel::mentions`), proposal overlapping a held lease, HOLD on my
proposal. Rooms watched = `channel::watched_rooms` (every non-DM room plus my canonical DM
rooms) — wider than the stopgap's "ops + DMs", which is correct once rooms exist (M2).
`--alias` / `AGORA_WAKE_ALIASES` add extra mention names (e.g. `worker-7f3a91c2`, the
`main-w<N>` suffix); aliases widen *mentions* only, never DM-room ownership.

`classify` returns `Kind::Dm | Mention | Proposal(_) | Hold`. M4 adds the two roadmap kinds on
top of the same envelope scan (a verified conversational message from another agent):

- `task_assigned`: text matches the `[task]` announcement shape **and** the task's
  `claimed_by == me` (the announcement names the claimant; I am woken only for my own claims).
- `lease_conflict`: a `type: "lease"` acquire/renew event for a task-claim resource currently
  held by me (someone took over my task claim's lease).

Both are computed from the same local state the CLI already reads (`board.rs`, `lease.rs`);
no new protocol messages.

### Delivery, dedup, and the while-busy rule

- **Framing** (stderr, exit 2): the untrusted-input banner + one plain line per message
  (`format_msg_plain`, already ANSI-free) — same contract as `agora check --wake`, so the
  harness-facing text has one form. Cap 3000 chars with a "read the rest" pointer.
- **Dedup and cross-path exactly-once**: every delivered message id goes through
  `store::claim_delivered` — the ledger `agora check --wake` and channel push already share.
  Whichever of the three paths (hook, channel push, events) delivers first wins; the others stay
  silent.
- **While busy**: per-agent `agents/<id>/wait/mark` stores when the last waiter stopped. On
  start, `wait` replays from that mark (via `fetch_checked` per watched room, `maxAge` bounded)
  so messages that arrived between two waiters are delivered at the next start — replacing the
  stopgap's `~/.cache/agora-wait/<id>.{mark,seen}` files (migration: if a stopgap mark file
  exists and no agora mark does, seed from it once, then ignore the old dir).
- **Single waiter per agent**: `agents/<id>/wait/pid`; a newer waiter SIGTERMs an older live one
  (same replacement semantics as the stopgap).
- **Settle**: after the first pending message, keep collecting for 1.5 s, then deliver the batch
  and exit (one wake per burst, not per message).

### Connectivity

One streaming reader per watched room via `transport::stream_since_with_config`
(`reconnect: true`, `idle_timeout: 270 s`) — the M1 watch-reconnect path. **No recycle
workaround**: the stopgap's 600 s `RECYCLE` existed only because pre-M1 `watch` went silent.
Jobs enqueue to one worker thread outside the relay runtime (the channel.rs pattern; relay
calls from inside the stream runtime panic). Exit codes: 2 delivered; 0 timeout / parent gone /
max life / guards failed; 1 agora unreachable (callers retry: omp extension 30 s, bridge 30 s).

Tracing: `agora.wait` span (target `agora`) with agent, rooms, outcome; one `agora.wait.deliver`
span per delivered batch (count, kinds). No message text in span fields.

## 2. `agora hooks` (new `src/hooks.rs`)

```
agora hooks install --harness claude|omp|codex [--all]
agora hooks remove  --harness claude|omp|codex [--all]
agora hooks status
```

- **claude**: JSON-merge the Stop hook into `~/.claude/settings.json`:
  `{"type":"command","command":"<agora> wait","timeout":86400,"asyncRewake":true}`.
  `<agora>` = absolute path of the running binary (resolved at install time; the stopgap's
  `~/.local/bin/agora-wait` entry is *replaced* — same matcher, so migration is the install).
  Idempotent: an existing agora Stop-hook entry is updated in place; all other hooks preserved.
  Never touches anything else in the file.
- **omp**: write the extension to `~/.omp/agent/extensions/agora-wake.ts` (ported from
  `agora-wait-hook:scripts/omp/agora-wake.ts`; it now shells out to `agora wait --for <id>
  --parent <omp pid>` and injects the stderr frame with `sendMessage(..., {triggerTurn: true})`,
  idle → `nextTurn`, busy → `followUp`). Writes its marker file so the bridge skips it.
- **codex** (+ pre-extension omp panes): the tmux wake bridge, ported from
  `agora-wait-hook:scripts/agora-wake-bridge` to drive `agora wait --for <id> --parent <pane
  pid>`; typed into the pane when idle (never mid-turn; at most 15 min hold, then type anyway —
  codex/omp queue input during a turn). Installed as a systemd **user** unit
  (`agora-wake-bridge.service`, `~/.config/systemd/user/`), enabled by the command.
  Both scripts ship in `scripts/` in the agora repo and are copied verbatim by `hooks install`
  (checksum-printed); they are thin launchers around `agora wait`, not parallel implementations.

`hooks status` prints per harness: installed or not, target path, and whether a stopgap entry
(`agora-wait`) is still present and should be migrated. Install never deletes anything
(without `remove`); removal is the explicit `hooks remove`.

Security: the adapters only ever type `agora`-framed text into a pane / call sendMessage; the
banner says the text comes from other agents, not the operator, and `channel::`-rendered bodies
neutralize `<channel` tags. The bridge never reads pane *input*, only its idle state.

## 3. MCP Events (new `src/events.rs`, wired in `mcp.rs`)

One event type, per the roadmap's kind list:

- `agora.addressed` — "A message or coordination event addressed to you". `delivery: ["poll",
  "push"]`. `inputSchema: {}` (no arguments yet — the stream is agent-scoped, like channel
  push). `payloadSchema`: `{messageId, from, room, roomLabel, kind: "dm"|"mention"|"proposal"|
  "hold"|"task_assigned"|"lease_conflict", text, ts}` — the same classification and payload
  source as `channel::render`, so a push and an event for the same message agree.

### Cursor

Opaque string `"1:<unix-ms>"` — a relay timestamp watermark. Resume = replay each watched room
from that relay time, classify, merge-sort by ts. `eventId` = the agora message id (stable,
upstream-assigned — exactly the sketch's preference). `maxAgeMs` bounds replay (default 1 h,
matching `check --wake`); events older than the floor are skipped with `truncated: true`.
`cursor: null` in a poll response never happens (relay has full history), so clients always
have something to persist.

### `events/poll`

`{name, arguments, cursor, maxAgeMs, maxEvents}` → `{events[], cursor, truncated, hasMore,
nextPollMs}` (`nextPollMs` 5000, ignored when `hasMore`). Batch cap 50 with `hasMore` + immediate
repoll. Delivered events are claimed in the delivered ledger — a poll answers "what should this
agent's session see", so `wait`/`check --wake`/channel push will not redeliver them. (Open
question 2 below.)

### `events/stream`

stdio long-lived request, one per subscription. Server: emits `notifications/events/active
{cursor, truncated, _meta.subscriptionId}`, then `notifications/events/event {eventId, name,
timestamp, data, cursor, _meta.subscriptionId}` per delivery, and a heartbeat at least every
30 s (`notifications/events/heartbeat {cursor, _meta.subscriptionId}`) so a quiet stream is
distinguishable from a dead one. `notifications/cancelled {requestId}` ends the subscription
(may send the empty `StreamEventsResult`). Implementation: the `channel.rs` room readers and
worker stay as they are; the emitter becomes a pluggable render (claude/channel JSON vs MCP
event occurrence), so one stream machinery serves both frontends. Push state is
connection-scoped; reconnect = new `events/stream` with the persisted cursor.

### Server surface

`initialize` result gains `"capabilities": {"events": {}}` (no `listChanged` — the type set is
static). Errors per the sketch: `-32602` invalid params, `-32023` unknown name, `-32026`
Unsupported for webhook-style requests (`data: {"feature": "deliveryMode", "value":
"webhook"}`). `events/list` is paginated but returns one page (no `nextCursor`).

Claude channel push (`--channel`) is unchanged and remains the recommended Claude Code adapter;
Events is the standard-aligned path for omp/codex and future clients.

## 4. Deploy and retirement (w7 sequence)

The real `hooks install` on the deployment host is part of the deploy, never a smoke (lead c13feb).
The deployed binary must live at a stable path (`~/.local/bin/agora`), because the Stop
hook embeds the absolute binary path at install time.

1. w7 builds and installs the m4-delivery binary to `~/.local/bin/agora` (stable path).
2. `agora hooks status` — expect: stopgap flagged on all three harnesses.
3. `agora hooks install claude` (migrates the stopgap Stop hook entry in
   `~/.claude/settings.json`; keeps a byte-exact backup at
   `settings.json.agora-backup`), `agora hooks install omp`, `agora hooks install codex`
   (replaces `agora-wake-bridge.service`; needs the scripts dir, default
   `AGORA_SCRIPTS_DIR` next to the binary).
4. `agora hooks status` — expect: installed x3, no stopgap line.
5. Canary the live path once: `scripts/hooks-canary.sh` (throwaway HOME, seed from the
   real settings; asserts migrate/idempotence/byte-exact restore).
6. w7 removes `~/.local/bin/agora-wait` and uninstalls the old stopgap unit/extension
   copies.
7. `~/.cache/agora-wait` is left alone (one-time mark seed already consumed it).

**Rollback** (any step, in order): `agora hooks remove claude` restores
`~/.claude/settings.json` byte-exact from the install backup (or structurally if the
file changed otherwise); `agora hooks remove omp`, `agora hooks remove codex`; if the
backup is gone, restore the stopgap Stop hook manually:
`{"type":"command","command":"/home/<user>/.local/bin/agora-wait","timeout":86400,"asyncRewake":true}`
— then w7 reinstates `agora-wait` if it was already removed.

## Testing (for QA)

Unit: wait state machine (guards, mark seed/migration, single-writer replacement, settle batch,
MAX_TEXT, exit codes); hooks install/remove idempotency + settings.json merge preserves foreign
hooks; events cursor watermark math, maxAgeMs truncation, maxEvents/hasMore, poll claims ledger,
stream active/event/heartbeat/cancelled shapes, error codes. Integration (in-proc transport, as
in channel.rs tests): end-to-end wait wake on a DM and a mention; exactly-once across wait +
poll + channel push; while-busy replay on the next start. Live smoke on the deployment host with the
`wait-test`/`wake-test` agents (idle wake ≤ 5 s, no polling), then QA conformance.

## Decisions (final; the tech lead's later rulings supersede the intermediate answers)

1. **Base**: `m1-release` dbaab2e confirmed. Caveat: M1 is still under QA review; rebase if
   it moves.
2. **`events/poll` and `events/stream` both claim the delivered ledger by default** (the
   client is the agent's own session; exactly-once then holds across all five paths: wait,
   check, channel push, poll, stream). Both take the same `arguments.peek: true` flag for
   observers: emit without claiming, so the wake hook still delivers later. `agora wait
   --wake` claims. Dedupe matrix D1–D10 in docs/tests-m4.md (qa/m4-tests) is the acceptance
   bar.
3. **Hook command path**: absolute binary path at install time; re-resolved by rerunning
   `agora hooks install`.
4. **`task_assigned` / `lease_conflict`**: text shape + local board state, no wire change
   before M2. Detection isolated in `wait::classify_for_wait` so it can move to a typed
   envelope later. **Tech debt**: a typed task-claim envelope replaces the text-shape match
   when M2/M3 need structured claims.

## Review notes adopted (QA review)

- **N1 notification levels (tech lead decision; pipeline per the rooms owner;
  boundary per QA)**: M4 applies the M2 per-agent notification predicate
  (`all | mentions | none`, docs/rooms.md) after the channel auth/self/conversational/muted
  checks and every addressed-kind check. The level gates exactly two things: (a) true
  @mentions in non-DM rooms (all → deliver, mentions → deliver, none → don't), and (b)
  otherwise-valid *unaddressed* non-DM chat at level `all` (delivered as the `room_message`
  kind). **Exempt at every level — the level never suppresses them: DM, task_assigned,
  Proposal (overlapping a lease I hold), Hold (on a proposal I made), lease_conflict**
  (roadmap principle 2: addressed = delivered once). Until the M2 RoomStateStore lands, the
  seam (`wait::notification_level`) returns the M2 default `mentions` for every room —
  today's behavior. M4 never reads the stopgap `subscriptions.json` (M2 imports it once per
  its design).
- **N2 while-busy replay goes through claim_delivered**: replayed messages are claimed in
  the delivered ledger at delivery time, together with live ones (one settle batch, one
  wake); the backlog never bypasses exactly-once.
- **N3 stream resume does not bypass the ledger**: reconnecting an `events/stream` with a
  persisted cursor re-classifies and re-claims from the delivered ledger, same as poll;
  already-delivered events drop out.
- **omp settle batch is one triggerTurn**: the omp extension sends the whole framed batch
  (stderr of one `agora wait` exit 2) as a single `sendMessage(..., {triggerTurn: true})` —
  one burst, one turn, never per-message turns.
