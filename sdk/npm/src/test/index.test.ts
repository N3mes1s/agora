/**
 * Tests for agora-chat SDK.
 *
 * These tests use the real agora binary pointed at an isolated AGORA_HOME.
 * They require the agora binary to be present at AGORA_BIN or on PATH.
 */

import { strict as assert } from "assert";
import { mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { AgoraClient, parseMessages, parseRooms, parseMembers, parseTasks, parseJsonMessages } from "../index";
import { buildEnv, stripAnsi } from "../runner";

// ─── Unit tests: parsers ─────────────────────────────────────────────────────

function testParseMessages() {
  const raw = `
  [05:29:35] [3fe144] 9d107f-cc: Hello world
  [05:30:01] [abcdef] agent2: Another message
  `;
  const msgs = parseMessages(raw);
  assert.equal(msgs.length, 2, "should parse 2 messages");
  assert.equal(msgs[0].agentId, "9d107f-cc");
  assert.equal(msgs[0].content, "Hello world");
  assert.equal(msgs[0].id, "3fe144");
  assert.equal(msgs[1].agentId, "agent2");
  console.log("  ✓ parseMessages");
}

function testParseRooms() {
  const raw = `
  Label                Room ID                Active   Joined
  ──────────────────── ────────────────────── ──────── ────────────────────
  collab               cc-30f6ed86f702         *       2026-04-06 05:34
  test-room            cc-aabbccdd1122                 2026-04-05 10:00
  `;
  const rooms = parseRooms(raw);
  assert.equal(rooms.length, 2, "should parse 2 rooms");
  assert.equal(rooms[0].label, "collab");
  assert.equal(rooms[0].roomId, "cc-30f6ed86f702");
  assert.equal(rooms[0].active, true);
  assert.equal(rooms[1].label, "test-room");
  assert.equal(rooms[1].active, false);
  console.log("  ✓ parseRooms");
}

function testParseMembers() {
  const raw = `
  Name                 Agent        Role     Status     Last seen
  ──────────────────── ──────────── ──────── ────────── ────────────────
                       01XCfA8v     Member   online     42s ago (you)
                       9d107f-cc    Admin    offline    5m ago
  `;
  const members = parseMembers(raw);
  assert.equal(members.length, 2, "should parse 2 members");
  assert.equal(members[0].agentId, "01XCfA8v");
  assert.equal(members[0].role, "Member");
  assert.equal(members[0].status, "online");
  assert.equal(members[1].agentId, "9d107f-cc");
  assert.equal(members[1].role, "Admin");
  assert.equal(members[1].status, "offline");
  console.log("  ✓ parseMembers");
}

function testParseTasks() {
  const raw = `
  [abc123] (open) Build a Python SDK
  [def456] (claimed by agent1) Create npm package
  [ghi789] (done) Add webhooks
  `;
  const tasks = parseTasks(raw);
  assert.equal(tasks.length, 3, "should parse 3 tasks");
  assert.equal(tasks[0].id, "abc123");
  assert.equal(tasks[0].status, "open");
  assert.equal(tasks[1].status, "claimed");
  assert.equal(tasks[1].claimedBy, "agent1");
  assert.equal(tasks[2].status, "done");
  console.log("  ✓ parseTasks");
}

function testStripAnsi() {
  const withAnsi = "\x1B[92monline\x1B[0m";
  assert.equal(stripAnsi(withAnsi), "online");
  console.log("  ✓ stripAnsi");
}

function testParseJsonMessages() {
  const messages = parseMessages(`
  [05:29:35] [3fe144] bridge-agent: {"kind":"req","id":"42","body":"payload"}
  [05:30:01] [abcdef] human: plain chat
  `);
  const frames = parseJsonMessages<{ kind: string; id: string; body: string }>(messages);
  assert.equal(frames.length, 1, "should skip non-JSON messages");
  assert.equal(frames[0].agentId, "bridge-agent");
  assert.equal(frames[0].value.kind, "req");
  assert.equal(frames[0].value.id, "42");
  assert.equal(frames[0].value.body, "payload");
  console.log("  ✓ parseJsonMessages");
}

function testBuildEnv() {
  const env = buildEnv(
    "/tmp/agora-js-home",
    "agent-js",
    "memory://js-sdk",
    "relay-token",
    "https://mirror.example"
  );
  assert.equal(env.HOME, "/tmp/agora-js-home");
  assert.equal(env.AGORA_HOME, "/tmp/agora-js-home");
  assert.equal(env.AGORA_AGENT_ID, "agent-js");
  assert.equal(env.AGORA_RELAY_URL, "memory://js-sdk");
  assert.equal(env.AGORA_RELAY_TOKEN, "relay-token");
  assert.equal(env.AGORA_RELAY_MIRROR, "https://mirror.example");
  console.log("  ✓ buildEnv");
}

// ─── Integration tests: real binary ──────────────────────────────────────────

async function testAgoraId(agora: AgoraClient) {
  const id = await agora.id();
  const alias = await agora.agentId();
  assert.ok(id.length > 0, "id should be non-empty");
  assert.match(id, /^[0-9A-Za-z-]+$/, "id should be alphanumeric");
  assert.equal(alias, id, "agentId should alias id");
  console.log(`  ✓ agora.id() = ${id}`);
}

async function testAgoraRooms(agora: AgoraClient) {
  const rooms = await agora.rooms();
  // After joining, there should be at least one room
  assert.ok(Array.isArray(rooms), "rooms should be an array");
  console.log(`  ✓ agora.rooms() = ${rooms.length} room(s)`);
}

async function testAgoraTasks(agora: AgoraClient) {
  // Tasks should return an array (may be empty)
  const tasks = await agora.tasks();
  assert.ok(Array.isArray(tasks), "tasks should be an array");
  console.log(`  ✓ agora.tasks() = ${tasks.length} task(s)`);
}

async function testJoinRoomSessionContract(agora: AgoraClient) {
  const room = await agora.joinRoom(
    "ag-js-sdk-contract",
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "contract-room"
  );
  assert.equal(room.roomId, "ag-js-sdk-contract");
  assert.equal(room.label, "contract-room");
  assert.ok(room.agentId.length > 0, "room session should expose agentId");
  assert.match(await room.fingerprint(), /^([0-9a-f]{4}\s+){7}[0-9a-f]{4}$/);
  await room.sendJson({ kind: "job", id: "contract-1" });
  const frames = await room.fetchJson<{ kind: string; id: string }>({ limit: 10 });
  assert.ok(frames.some((frame) => frame.value.id === "contract-1"));
  console.log("  ✓ joinRoom() RoomSession contract");
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main() {
  console.log("\nagora-chat SDK tests\n");

  // Unit tests (no binary needed)
  console.log("Unit tests:");
  testParseMessages();
  testParseRooms();
  testParseMembers();
  testParseTasks();
  testStripAnsi();
  testParseJsonMessages();
  testBuildEnv();

  // Integration tests (require binary)
  const binaryPath =
    process.env.AGORA_BIN ??
    join(__dirname, "../../../../target/release/agora");

  const home = mkdtempSync(join(tmpdir(), "agora-sdk-test-"));
  try {
    console.log("\nIntegration tests:");
    const agora = new AgoraClient({
      binaryPath,
      home,
      relayUrl: "memory://js-sdk-test",
    });

    await testAgoraId(agora);
    await testAgoraRooms(agora);
    await testAgoraTasks(agora);
    await testJoinRoomSessionContract(agora);

    console.log("\nAll tests passed.\n");
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error("Test failed:", err.message);
  process.exit(1);
});
