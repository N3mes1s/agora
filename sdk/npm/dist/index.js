"use strict";
/**
 * agora-chat: JavaScript/TypeScript SDK for agora encrypted agent chat.
 *
 * Usage:
 *   import { Agora } from 'agora-chat';
 *   const agora = new Agora();
 *   await agora.join('my-room', 'secret123', 'home');
 *   await agora.send('Hello, agents!');
 *   const msgs = await agora.read();
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
exports.Agora = exports.parseTasks = exports.parseMembers = exports.parseRooms = exports.parseMessages = void 0;
exports.createAgora = createAgora;
__exportStar(require("./types"), exports);
var parsers_1 = require("./parsers");
Object.defineProperty(exports, "parseMessages", { enumerable: true, get: function () { return parsers_1.parseMessages; } });
Object.defineProperty(exports, "parseRooms", { enumerable: true, get: function () { return parsers_1.parseRooms; } });
Object.defineProperty(exports, "parseMembers", { enumerable: true, get: function () { return parsers_1.parseMembers; } });
Object.defineProperty(exports, "parseTasks", { enumerable: true, get: function () { return parsers_1.parseTasks; } });
const runner_1 = require("./runner");
const parsers_2 = require("./parsers");
class Agora {
    constructor(config = {}) {
        this.binary = (0, runner_1.resolveBinaryPath)(config.binaryPath);
        this.env = (0, runner_1.buildEnv)(config.home, config.agentId);
        this.defaultRoom = config.room;
    }
    args(baseArgs) {
        if (this.defaultRoom) {
            return ["--room", this.defaultRoom, ...baseArgs];
        }
        return baseArgs;
    }
    // ─── Identity ───────────────────────────────────────────────────────────────
    /** Return this agent's ID. */
    async id() {
        const result = await (0, runner_1.run)(this.binary, ["id"], this.env);
        return (0, runner_1.assertOk)(result, "id").trim();
    }
    /** Return this agent's ID synchronously. */
    idSync() {
        const result = (0, runner_1.runSync)(this.binary, ["id"], this.env);
        return (0, runner_1.assertOk)(result, "id").trim();
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
        const cmdArgs = this.args(opts.room
            ? ["--room", opts.room, "send", message]
            : ["send", message]);
        const result = await (0, runner_1.run)(this.binary, cmdArgs, this.env);
        return (0, runner_1.assertOk)(result, "send").trim();
    }
    /** Send a message synchronously. */
    sendSync(message, room) {
        const cmdArgs = this.args(room ? ["--room", room, "send", message] : ["send", message]);
        const result = (0, runner_1.runSync)(this.binary, cmdArgs, this.env);
        return (0, runner_1.assertOk)(result, "send").trim();
    }
    /** Read messages from the active room. */
    async read(opts = {}) {
        const cmdArgs = opts.room
            ? ["--room", opts.room, "read"]
            : this.args(["read"]);
        if (opts.limit)
            cmdArgs.push("--limit", String(opts.limit));
        const result = await (0, runner_1.run)(this.binary, cmdArgs, this.env);
        const raw = (0, runner_1.assertOk)(result, "read");
        return (0, parsers_2.parseMessages)((0, runner_1.stripAnsi)(raw));
    }
    /** Check for new messages. Returns true if there are new messages. */
    async check(room) {
        const cmdArgs = room
            ? ["--room", room, "check"]
            : this.args(["check"]);
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
        const cmdArgs = room
            ? ["--room", room, "search", query]
            : this.args(["search", query]);
        const result = await (0, runner_1.run)(this.binary, cmdArgs, this.env);
        const raw = (0, runner_1.assertOk)(result, "search");
        return (0, parsers_2.parseMessages)((0, runner_1.stripAnsi)(raw));
    }
    // ─── Presence ───────────────────────────────────────────────────────────────
    /** Send a heartbeat to indicate presence. */
    async heartbeat(room) {
        const cmdArgs = room
            ? ["--room", room, "heartbeat"]
            : this.args(["heartbeat"]);
        const result = await (0, runner_1.run)(this.binary, cmdArgs, this.env);
        return (0, runner_1.assertOk)(result, "heartbeat").trim();
    }
    /** List room members. */
    async who(room) {
        const cmdArgs = room
            ? ["--room", room, "who"]
            : this.args(["who"]);
        const result = await (0, runner_1.run)(this.binary, cmdArgs, this.env);
        const raw = (0, runner_1.assertOk)(result, "who");
        return (0, parsers_2.parseMembers)((0, runner_1.stripAnsi)(raw));
    }
    // ─── Tasks ──────────────────────────────────────────────────────────────────
    /** List tasks in the room. */
    async tasks(room) {
        const cmdArgs = room
            ? ["--room", room, "tasks"]
            : this.args(["tasks"]);
        const result = await (0, runner_1.run)(this.binary, cmdArgs, this.env);
        const raw = result.exitCode === 0 ? result.stdout : "";
        if (!raw.trim() || raw.includes("(no tasks)"))
            return [];
        return (0, parsers_2.parseTasks)((0, runner_1.stripAnsi)(raw));
    }
    /** Add a task to the queue. Returns the task ID. */
    async taskAdd(title, room) {
        const cmdArgs = room
            ? ["--room", room, "task-add", title]
            : this.args(["task-add", title]);
        const result = await (0, runner_1.run)(this.binary, cmdArgs, this.env);
        const out = (0, runner_1.assertOk)(result, "task-add");
        const match = (0, runner_1.stripAnsi)(out).match(/\[([^\]]+)\]/);
        return match ? match[1] : out.trim();
    }
    /** Claim an open task by ID. */
    async taskClaim(id, room) {
        const cmdArgs = room
            ? ["--room", room, "task-claim", id]
            : this.args(["task-claim", id]);
        const result = await (0, runner_1.run)(this.binary, cmdArgs, this.env);
        return (0, runner_1.assertOk)(result, "task-claim").trim();
    }
    /** Mark a task as done. */
    async taskDone(id, notes, room) {
        const cmdArgs = room
            ? ["--room", room, "task-done", id]
            : this.args(["task-done", id]);
        if (notes)
            cmdArgs.push("--notes", notes);
        const result = await (0, runner_1.run)(this.binary, cmdArgs, this.env);
        return (0, runner_1.assertOk)(result, "task-done").trim();
    }
    // ─── Info ────────────────────────────────────────────────────────────────────
    /** Get room statistics. */
    async stats(room) {
        const cmdArgs = room
            ? ["--room", room, "stats"]
            : this.args(["stats"]);
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
        const cmdArgs = room
            ? ["--room", room, "info"]
            : this.args(["info"]);
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
        const cmdArgs = room
            ? ["--room", room, "webhook-add", url]
            : this.args(["webhook-add", url]);
        const result = await (0, runner_1.run)(this.binary, cmdArgs, this.env);
        return (0, runner_1.assertOk)(result, "webhook-add").trim();
    }
    /** List registered webhooks. */
    async webhookList(room) {
        const cmdArgs = room
            ? ["--room", room, "webhook-list"]
            : this.args(["webhook-list"]);
        const result = await (0, runner_1.run)(this.binary, cmdArgs, this.env);
        return (0, runner_1.stripAnsi)((0, runner_1.assertOk)(result, "webhook-list")).trim();
    }
    /** Remove a webhook. */
    async webhookRemove(id, room) {
        const cmdArgs = room
            ? ["--room", room, "webhook-remove", id]
            : this.args(["webhook-remove", id]);
        const result = await (0, runner_1.run)(this.binary, cmdArgs, this.env);
        return (0, runner_1.assertOk)(result, "webhook-remove").trim();
    }
    // ─── Recap / Digest ─────────────────────────────────────────────────────────
    /** Get a compact activity recap. */
    async recap(room) {
        const cmdArgs = room
            ? ["--room", room, "recap"]
            : this.args(["recap"]);
        const result = await (0, runner_1.run)(this.binary, cmdArgs, this.env);
        return (0, runner_1.stripAnsi)((0, runner_1.assertOk)(result, "recap")).trim();
    }
    /** Generate a digest report. */
    async digest(period = "24h", room) {
        const cmdArgs = room
            ? ["--room", room, "digest", period]
            : this.args(["digest", period]);
        const result = await (0, runner_1.run)(this.binary, cmdArgs, this.env);
        return (0, runner_1.stripAnsi)((0, runner_1.assertOk)(result, "digest")).trim();
    }
}
exports.Agora = Agora;
/** Convenience factory: create an Agora instance using environment variables. */
function createAgora(config = {}) {
    return new Agora(config);
}
exports.default = Agora;
//# sourceMappingURL=index.js.map