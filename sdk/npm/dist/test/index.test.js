"use strict";
/**
 * Tests for agora-chat SDK.
 *
 * These tests use the real agora binary pointed at an isolated AGORA_HOME.
 * They require the agora binary to be present at AGORA_BIN or on PATH.
 */
Object.defineProperty(exports, "__esModule", { value: true });
const assert_1 = require("assert");
const fs_1 = require("fs");
const os_1 = require("os");
const path_1 = require("path");
const index_1 = require("../index");
const runner_1 = require("../runner");
// ─── Unit tests: parsers ─────────────────────────────────────────────────────
function testParseMessages() {
    const raw = `
  [05:29:35] [3fe144] 9d107f-cc: Hello world
  [05:30:01] [abcdef] agent2: Another message
  `;
    const msgs = (0, index_1.parseMessages)(raw);
    assert_1.strict.equal(msgs.length, 2, "should parse 2 messages");
    assert_1.strict.equal(msgs[0].agentId, "9d107f-cc");
    assert_1.strict.equal(msgs[0].content, "Hello world");
    assert_1.strict.equal(msgs[0].id, "3fe144");
    assert_1.strict.equal(msgs[1].agentId, "agent2");
    console.log("  ✓ parseMessages");
}
function testParseRooms() {
    const raw = `
  Label                Room ID                Active   Joined
  ──────────────────── ────────────────────── ──────── ────────────────────
  collab               cc-30f6ed86f702         *       2026-04-06 05:34
  test-room            cc-aabbccdd1122                 2026-04-05 10:00
  `;
    const rooms = (0, index_1.parseRooms)(raw);
    assert_1.strict.equal(rooms.length, 2, "should parse 2 rooms");
    assert_1.strict.equal(rooms[0].label, "collab");
    assert_1.strict.equal(rooms[0].roomId, "cc-30f6ed86f702");
    assert_1.strict.equal(rooms[0].active, true);
    assert_1.strict.equal(rooms[1].label, "test-room");
    assert_1.strict.equal(rooms[1].active, false);
    console.log("  ✓ parseRooms");
}
function testParseMembers() {
    const raw = `
  Name                 Agent        Role     Status     Last seen
  ──────────────────── ──────────── ──────── ────────── ────────────────
                       01XCfA8v     Member   online     42s ago (you)
                       9d107f-cc    Admin    offline    5m ago
  `;
    const members = (0, index_1.parseMembers)(raw);
    assert_1.strict.equal(members.length, 2, "should parse 2 members");
    assert_1.strict.equal(members[0].agentId, "01XCfA8v");
    assert_1.strict.equal(members[0].role, "Member");
    assert_1.strict.equal(members[0].status, "online");
    assert_1.strict.equal(members[1].agentId, "9d107f-cc");
    assert_1.strict.equal(members[1].role, "Admin");
    assert_1.strict.equal(members[1].status, "offline");
    console.log("  ✓ parseMembers");
}
function testParseTasks() {
    const raw = `
  [abc123] (open) Build a Python SDK
  [def456] (claimed by agent1) Create npm package
  [ghi789] (done) Add webhooks
  `;
    const tasks = (0, index_1.parseTasks)(raw);
    assert_1.strict.equal(tasks.length, 3, "should parse 3 tasks");
    assert_1.strict.equal(tasks[0].id, "abc123");
    assert_1.strict.equal(tasks[0].status, "open");
    assert_1.strict.equal(tasks[1].status, "claimed");
    assert_1.strict.equal(tasks[1].claimedBy, "agent1");
    assert_1.strict.equal(tasks[2].status, "done");
    console.log("  ✓ parseTasks");
}
function testStripAnsi() {
    const withAnsi = "\x1B[92monline\x1B[0m";
    assert_1.strict.equal((0, runner_1.stripAnsi)(withAnsi), "online");
    console.log("  ✓ stripAnsi");
}
// ─── Integration tests: real binary ──────────────────────────────────────────
async function testAgoraId(agora) {
    const id = await agora.id();
    assert_1.strict.ok(id.length > 0, "id should be non-empty");
    assert_1.strict.match(id, /^[0-9A-Za-z-]+$/, "id should be alphanumeric");
    console.log(`  ✓ agora.id() = ${id}`);
}
async function testAgoraRooms(agora) {
    const rooms = await agora.rooms();
    // After joining, there should be at least one room
    assert_1.strict.ok(Array.isArray(rooms), "rooms should be an array");
    console.log(`  ✓ agora.rooms() = ${rooms.length} room(s)`);
}
async function testAgoraTasks(agora) {
    // Tasks should return an array (may be empty)
    const tasks = await agora.tasks();
    assert_1.strict.ok(Array.isArray(tasks), "tasks should be an array");
    console.log(`  ✓ agora.tasks() = ${tasks.length} task(s)`);
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
    // Integration tests (require binary)
    const binaryPath = process.env.AGORA_BIN ??
        (0, path_1.join)(__dirname, "../../../../target/release/agora");
    const home = (0, fs_1.mkdtempSync)((0, path_1.join)((0, os_1.tmpdir)(), "agora-sdk-test-"));
    try {
        console.log("\nIntegration tests:");
        const agora = new index_1.Agora({
            binaryPath,
            home,
        });
        await testAgoraId(agora);
        await testAgoraRooms(agora);
        await testAgoraTasks(agora);
        console.log("\nAll tests passed.\n");
    }
    finally {
        (0, fs_1.rmSync)(home, { recursive: true, force: true });
    }
}
main().catch((err) => {
    console.error("Test failed:", err.message);
    process.exit(1);
});
//# sourceMappingURL=index.test.js.map