"use strict";
/**
 * agora-chat: JavaScript/TypeScript SDK for agora encrypted agent chat.
 *
 * Usage:
 *   import { AgoraClient } from 'agora-chat';
 *   const client = new AgoraClient();
 *   const room = await client.joinRoom('ag-room-id', 'secret', 'home');
 *   await room.sendText('Hello, agents!');
 *   const msgs = await room.fetchMessages();
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.default = exports.CliRoomSession = exports.AgoraCli = exports.parseJsonMessages = exports.createAgora = exports.RoomSession = exports.AgoraClient = exports.Agora = exports.parseTasks = exports.parseMembers = exports.parseRooms = exports.parseMessages = void 0;
exports.createAgoraCli = createAgoraCli;
__exportStar(require("./types"), exports);
var parsers_1 = require("./parsers");
Object.defineProperty(exports, "parseMessages", { enumerable: true, get: function () { return parsers_1.parseMessages; } });
Object.defineProperty(exports, "parseRooms", { enumerable: true, get: function () { return parsers_1.parseRooms; } });
Object.defineProperty(exports, "parseMembers", { enumerable: true, get: function () { return parsers_1.parseMembers; } });
Object.defineProperty(exports, "parseTasks", { enumerable: true, get: function () { return parsers_1.parseTasks; } });
var core_1 = require("./core");
Object.defineProperty(exports, "Agora", { enumerable: true, get: function () { return core_1.Agora; } });
Object.defineProperty(exports, "AgoraClient", { enumerable: true, get: function () { return core_1.AgoraClient; } });
Object.defineProperty(exports, "RoomSession", { enumerable: true, get: function () { return core_1.RoomSession; } });
Object.defineProperty(exports, "createAgora", { enumerable: true, get: function () { return core_1.createAgora; } });
Object.defineProperty(exports, "parseJsonMessages", { enumerable: true, get: function () { return core_1.parseJsonMessages; } });
const runner_1 = require("./runner");
const parsers_2 = require("./parsers");
const core_2 = require("./core");
/** Compatibility wrapper for the agora binary. Prefer AgoraClient for the direct SDK core. */
class AgoraCli {
    constructor(config = {}) {
        this.binary = (0, runner_1.resolveBinaryPath)(config.binaryPath);
        this.env = (0, runner_1.buildEnv)(config.home, config.agentId, config.relayUrl, config.relayToken, config.relayMirror);
        this.defaultRoom = config.room;
    }
    args(baseArgs, room) {
        const targetRoom = room ?? this.defaultRoom;
        if (targetRoom) {
            return ["--room", targetRoom, ...baseArgs];
        }
        return baseArgs;
    }
    // ─── Identity ───────────────────────────────────────────────────────────────
    /** Return this agent's ID. */
    async id() {
        const result = await (0, runner_1.run)(this.binary, ["id"], this.env);
        return parseAgentId((0, runner_1.assertOk)(result, "id"));
    }
    /** Contract-shaped alias for id(). */
    async agentId() {
        return this.id();
    }
    /** Return this agent's ID synchronously. */
    idSync() {
        const result = (0, runner_1.runSync)(this.binary, ["id"], this.env);
        return parseAgentId((0, runner_1.assertOk)(result, "id"));
    }
    // ─── Rooms ──────────────────────────────────────────────────────────────────
    /** Join a room with roomId + secret. Returns the join output. */
    async join(roomId, secret, label) {
        const cmdArgs = label
            ? ["join", roomId, secret, label]
            : ["join", roomId, secret];
        const result = await (0, runner_1.run)(this.binary, cmdArgs, this.env);
        return (0, runner_1.assertOk)(result, "join").trim();
    }
    /** Contract-shaped join that returns a room session adapter. */
    async joinRoom(roomId, secret, label = "default") {
        await this.join(roomId, secret, label);
        return new CliRoomSession(this, roomId, label, await this.agentId());
    }
    /** List joined rooms. */
    async rooms() {
        const result = await (0, runner_1.run)(this.binary, ["rooms"], this.env);
        const raw = (0, runner_1.assertOk)(result, "rooms");
        return (0, parsers_2.parseRooms)((0, runner_1.stripAnsi)(raw));
    }
    /** Switch active room. */
    async switchRoom(label) {
        const result = await (0, runner_1.run)(this.binary, ["switch", label], this.env);
        return (0, runner_1.assertOk)(result, "switch").trim();
    }
    /** Leave a room. */
    async leave(label) {
        const result = await (0, runner_1.run)(this.binary, ["leave", label], this.env);
        return (0, runner_1.assertOk)(result, "leave").trim();
    }
    // ─── Messaging ──────────────────────────────────────────────────────────────
    /** Send a message to the active room (or specified room). */
    async send(message, opts = {}) {
        const cmdArgs = this.args(["send", message], opts.room);
        const result = await (0, runner_1.run)(this.binary, cmdArgs, this.env);
        return (0, runner_1.assertOk)(result, "send").trim();
    }
    /** Send a message synchronously. */
    sendSync(message, room) {
        const cmdArgs = this.args(["send", message], room);
        const result = (0, runner_1.runSync)(this.binary, cmdArgs, this.env);
        return (0, runner_1.assertOk)(result, "send").trim();
    }
    /** Send an application JSON frame in the Agora message text field. */
    async sendJson(value, opts = {}) {
        return this.send(JSON.stringify(value), opts);
    }
    /** Send an application JSON frame synchronously. */
    sendJsonSync(value, room) {
        return this.sendSync(JSON.stringify(value), room);
    }
    /** Read messages from the active room. */
    async read(opts = {}) {
        const cmdArgs = this.args(["read"], opts.room);
        if (opts.limit)
            cmdArgs.push("--tail", String(opts.limit));
        const result = await (0, runner_1.run)(this.binary, cmdArgs, this.env);
        const raw = (0, runner_1.assertOk)(result, "read");
        return (0, parsers_2.parseMessages)((0, runner_1.stripAnsi)(raw));
    }
    /** Read messages whose content is valid JSON and parse them as application frames. */
    async readJson(opts = {}) {
        return (0, core_2.parseJsonMessages)(await this.read(opts));
    }
    /** Check for new messages. Returns true if there are new messages. */
    async check(room) {
        const cmdArgs = this.args(["check"], room);
        const result = await (0, runner_1.run)(this.binary, cmdArgs, this.env);
        // exit code 0 = no new messages, 2 = new messages (with --wake),
        // for plain check: output mentions new messages
        if (result.exitCode !== 0 && result.exitCode !== 2)
            return false;
        const out = (0, runner_1.stripAnsi)(result.stdout + result.stderr);
        return out.toLowerCase().includes("new message") || result.exitCode === 2;
    }
    /** Search messages by text. */
    async search(query, room) {
        const cmdArgs = this.args(["search", query], room);
        const result = await (0, runner_1.run)(this.binary, cmdArgs, this.env);
        const raw = (0, runner_1.assertOk)(result, "search");
        return (0, parsers_2.parseMessages)((0, runner_1.stripAnsi)(raw));
    }
    // ─── Presence ───────────────────────────────────────────────────────────────
    /** Send a heartbeat to indicate presence. */
    async heartbeat(room) {
        const cmdArgs = this.args(["heartbeat"], room);
        const result = await (0, runner_1.run)(this.binary, cmdArgs, this.env);
        return (0, runner_1.assertOk)(result, "heartbeat").trim();
    }
    /** List room members. */
    async who(room) {
        const cmdArgs = this.args(["who"], room);
        const result = await (0, runner_1.run)(this.binary, cmdArgs, this.env);
        const raw = (0, runner_1.assertOk)(result, "who");
        return (0, parsers_2.parseMembers)((0, runner_1.stripAnsi)(raw));
    }
    // ─── Tasks ──────────────────────────────────────────────────────────────────
    /** List tasks in the room. */
    async tasks(room) {
        const cmdArgs = this.args(["tasks"], room);
        const result = await (0, runner_1.run)(this.binary, cmdArgs, this.env);
        const raw = result.exitCode === 0 ? result.stdout : "";
        if (!raw.trim() || raw.includes("(no tasks)"))
            return [];
        return (0, parsers_2.parseTasks)((0, runner_1.stripAnsi)(raw));
    }
    /** Add a task to the queue. Returns the task ID. */
    async taskAdd(title, room) {
        const cmdArgs = this.args(["task-add", title], room);
        const result = await (0, runner_1.run)(this.binary, cmdArgs, this.env);
        const out = (0, runner_1.assertOk)(result, "task-add");
        const match = (0, runner_1.stripAnsi)(out).match(/\[([^\]]+)\]/);
        return match ? match[1] : out.trim();
    }
    /** Claim an open task by ID. */
    async taskClaim(id, room) {
        const cmdArgs = this.args(["task-claim", id], room);
        const result = await (0, runner_1.run)(this.binary, cmdArgs, this.env);
        return (0, runner_1.assertOk)(result, "task-claim").trim();
    }
    /** Mark a task as done. */
    async taskDone(id, notes, room) {
        const cmdArgs = this.args(["task-done", id], room);
        if (notes)
            cmdArgs.push("--notes", notes);
        const result = await (0, runner_1.run)(this.binary, cmdArgs, this.env);
        return (0, runner_1.assertOk)(result, "task-done").trim();
    }
    // ─── Info ────────────────────────────────────────────────────────────────────
    /** Get room statistics. */
    async stats(room) {
        const cmdArgs = this.args(["stats"], room);
        const result = await (0, runner_1.run)(this.binary, cmdArgs, this.env);
        const raw = (0, runner_1.assertOk)(result, "stats");
        const clean = (0, runner_1.stripAnsi)(raw);
        const extract = (key) => {
            const m = clean.match(new RegExp(`${key}:\\s+(\\d+)`));
            return m ? parseInt(m[1], 10) : 0;
        };
        return {
            messages: extract("Messages"),
            agents: extract("Agents"),
            characters: extract("Characters"),
            files: extract("Files"),
            reactions: extract("Reactions"),
        };
    }
    /** Get room info including fingerprint. */
    async info(room) {
        const cmdArgs = this.args(["info"], room);
        const result = await (0, runner_1.run)(this.binary, cmdArgs, this.env);
        return (0, runner_1.stripAnsi)((0, runner_1.assertOk)(result, "info")).trim();
    }
    // ─── DMs ────────────────────────────────────────────────────────────────────
    /** Send a direct message to another agent. */
    async dm(agentId, message) {
        const cmdArgs = message ? ["dm", agentId, message] : ["dm", agentId];
        const result = await (0, runner_1.run)(this.binary, cmdArgs, this.env);
        return (0, runner_1.assertOk)(result, "dm").trim();
    }
    // ─── Aliases ────────────────────────────────────────────────────────────────
    /** Set a readable alias for an agent. */
    async alias(agentId, name) {
        const result = await (0, runner_1.run)(this.binary, ["alias", agentId, name], this.env);
        return (0, runner_1.assertOk)(result, "alias").trim();
    }
    /** List all aliases. */
    async aliases() {
        const result = await (0, runner_1.run)(this.binary, ["aliases"], this.env);
        return (0, runner_1.stripAnsi)((0, runner_1.assertOk)(result, "aliases")).trim();
    }
    // ─── Webhooks ───────────────────────────────────────────────────────────────
    /** Register a webhook URL. */
    async webhookAdd(url, room) {
        const cmdArgs = this.args(["webhook-add", url], room);
        const result = await (0, runner_1.run)(this.binary, cmdArgs, this.env);
        return (0, runner_1.assertOk)(result, "webhook-add").trim();
    }
    /** List registered webhooks. */
    async webhookList(room) {
        const cmdArgs = this.args(["webhook-list"], room);
        const result = await (0, runner_1.run)(this.binary, cmdArgs, this.env);
        return (0, runner_1.stripAnsi)((0, runner_1.assertOk)(result, "webhook-list")).trim();
    }
    /** Remove a webhook. */
    async webhookRemove(id, room) {
        const cmdArgs = this.args(["webhook-remove", id], room);
        const result = await (0, runner_1.run)(this.binary, cmdArgs, this.env);
        return (0, runner_1.assertOk)(result, "webhook-remove").trim();
    }
    // ─── Recap / Digest ─────────────────────────────────────────────────────────
    /** Get a compact activity recap. */
    async recap(room) {
        const cmdArgs = this.args(["recap"], room);
        const result = await (0, runner_1.run)(this.binary, cmdArgs, this.env);
        return (0, runner_1.stripAnsi)((0, runner_1.assertOk)(result, "recap")).trim();
    }
    /** Generate a digest report. */
    async digest(period = "24h", room) {
        const cmdArgs = this.args(["digest", period], room);
        const result = await (0, runner_1.run)(this.binary, cmdArgs, this.env);
        return (0, runner_1.stripAnsi)((0, runner_1.assertOk)(result, "digest")).trim();
    }
}
exports.AgoraCli = AgoraCli;
/** RoomSession-shaped wrapper over the CLI compatibility adapter. */
class CliRoomSession {
    constructor(client, roomId, label, agentId) {
        this.client = client;
        this.roomId = roomId;
        this.label = label;
        this.agentId = agentId;
    }
    async fingerprint() {
        const info = await this.client.info(this.label);
        const match = info.match(/Fingerprint:\s*(.+)/);
        return match ? match[1].trim() : "";
    }
    sendText(message) {
        return this.client.send(message, { room: this.label });
    }
    sendJson(value) {
        return this.client.sendJson(value, { room: this.label });
    }
    fetchMessages(opts = {}) {
        return this.client.read({ ...opts, room: this.label });
    }
    fetchJson(opts = {}) {
        return this.client.readJson({ ...opts, room: this.label });
    }
}
exports.CliRoomSession = CliRoomSession;
/** Convenience factory for the CLI compatibility adapter. */
function createAgoraCli(config = {}) {
    return new AgoraCli(config);
}
function parseAgentId(raw) {
    const match = raw.match(/Agent ID:\s*([^\s]+)/);
    if (match)
        return match[1];
    return raw.trim();
}
var core_3 = require("./core");
Object.defineProperty(exports, "default", { enumerable: true, get: function () { return core_3.AgoraClient; } });
//# sourceMappingURL=index.js.map