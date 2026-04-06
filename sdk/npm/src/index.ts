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

export * from "./types";
export { parseMessages, parseRooms, parseMembers, parseTasks } from "./parsers";

import {
  AgoraConfig,
  AgoraMessage,
  AgoraRoom,
  AgoraMember,
  AgoraTask,
  AgoraStats,
  SendOptions,
  ReadOptions,
} from "./types";
import { resolveBinaryPath, buildEnv, run, runSync, assertOk, stripAnsi } from "./runner";
import { parseMessages, parseRooms, parseMembers, parseTasks } from "./parsers";

export class Agora {
  private binary: string;
  private env: NodeJS.ProcessEnv;
  private defaultRoom?: string;

  constructor(config: AgoraConfig = {}) {
    this.binary = resolveBinaryPath(config.binaryPath);
    this.env = buildEnv(config.home, config.agentId);
    this.defaultRoom = config.room;
  }

  private args(baseArgs: string[]): string[] {
    if (this.defaultRoom) {
      return ["--room", this.defaultRoom, ...baseArgs];
    }
    return baseArgs;
  }

  // ─── Identity ───────────────────────────────────────────────────────────────

  /** Return this agent's ID. */
  async id(): Promise<string> {
    const result = await run(this.binary, ["id"], this.env);
    return assertOk(result, "id").trim();
  }

  /** Return this agent's ID synchronously. */
  idSync(): string {
    const result = runSync(this.binary, ["id"], this.env);
    return assertOk(result, "id").trim();
  }

  // ─── Rooms ──────────────────────────────────────────────────────────────────

  /** Join a room with roomId + secret. Returns the join output. */
  async join(roomId: string, secret: string, label?: string): Promise<string> {
    const cmdArgs = label
      ? ["join", roomId, secret, label]
      : ["join", roomId, secret];
    const result = await run(this.binary, cmdArgs, this.env);
    return assertOk(result, "join").trim();
  }

  /** List joined rooms. */
  async rooms(): Promise<AgoraRoom[]> {
    const result = await run(this.binary, ["rooms"], this.env);
    const raw = assertOk(result, "rooms");
    return parseRooms(stripAnsi(raw));
  }

  /** Switch active room. */
  async switchRoom(label: string): Promise<string> {
    const result = await run(this.binary, ["switch", label], this.env);
    return assertOk(result, "switch").trim();
  }

  /** Leave a room. */
  async leave(label: string): Promise<string> {
    const result = await run(this.binary, ["leave", label], this.env);
    return assertOk(result, "leave").trim();
  }

  // ─── Messaging ──────────────────────────────────────────────────────────────

  /** Send a message to the active room (or specified room). */
  async send(message: string, opts: Omit<SendOptions, "message"> = {}): Promise<string> {
    const cmdArgs = this.args(
      opts.room
        ? ["--room", opts.room, "send", message]
        : ["send", message]
    );
    const result = await run(this.binary, cmdArgs, this.env);
    return assertOk(result, "send").trim();
  }

  /** Send a message synchronously. */
  sendSync(message: string, room?: string): string {
    const cmdArgs = this.args(
      room ? ["--room", room, "send", message] : ["send", message]
    );
    const result = runSync(this.binary, cmdArgs, this.env);
    return assertOk(result, "send").trim();
  }

  /** Read messages from the active room. */
  async read(opts: ReadOptions = {}): Promise<AgoraMessage[]> {
    const cmdArgs = opts.room
      ? ["--room", opts.room, "read"]
      : this.args(["read"]);
    if (opts.limit) cmdArgs.push("--limit", String(opts.limit));
    const result = await run(this.binary, cmdArgs, this.env);
    const raw = assertOk(result, "read");
    return parseMessages(stripAnsi(raw));
  }

  /** Check for new messages. Returns true if there are new messages. */
  async check(room?: string): Promise<boolean> {
    const cmdArgs = room
      ? ["--room", room, "check"]
      : this.args(["check"]);
    const result = await run(this.binary, cmdArgs, this.env);
    // exit code 0 = no new messages, 2 = new messages (with --wake),
    // for plain check: output mentions new messages
    if (result.exitCode !== 0 && result.exitCode !== 2) return false;
    const out = stripAnsi(result.stdout + result.stderr);
    return out.toLowerCase().includes("new message") || result.exitCode === 2;
  }

  /** Search messages by text. */
  async search(query: string, room?: string): Promise<AgoraMessage[]> {
    const cmdArgs = room
      ? ["--room", room, "search", query]
      : this.args(["search", query]);
    const result = await run(this.binary, cmdArgs, this.env);
    const raw = assertOk(result, "search");
    return parseMessages(stripAnsi(raw));
  }

  // ─── Presence ───────────────────────────────────────────────────────────────

  /** Send a heartbeat to indicate presence. */
  async heartbeat(room?: string): Promise<string> {
    const cmdArgs = room
      ? ["--room", room, "heartbeat"]
      : this.args(["heartbeat"]);
    const result = await run(this.binary, cmdArgs, this.env);
    return assertOk(result, "heartbeat").trim();
  }

  /** List room members. */
  async who(room?: string): Promise<AgoraMember[]> {
    const cmdArgs = room
      ? ["--room", room, "who"]
      : this.args(["who"]);
    const result = await run(this.binary, cmdArgs, this.env);
    const raw = assertOk(result, "who");
    return parseMembers(stripAnsi(raw));
  }

  // ─── Tasks ──────────────────────────────────────────────────────────────────

  /** List tasks in the room. */
  async tasks(room?: string): Promise<AgoraTask[]> {
    const cmdArgs = room
      ? ["--room", room, "tasks"]
      : this.args(["tasks"]);
    const result = await run(this.binary, cmdArgs, this.env);
    const raw = result.exitCode === 0 ? result.stdout : "";
    if (!raw.trim() || raw.includes("(no tasks)")) return [];
    return parseTasks(stripAnsi(raw));
  }

  /** Add a task to the queue. Returns the task ID. */
  async taskAdd(title: string, room?: string): Promise<string> {
    const cmdArgs = room
      ? ["--room", room, "task-add", title]
      : this.args(["task-add", title]);
    const result = await run(this.binary, cmdArgs, this.env);
    const out = assertOk(result, "task-add");
    const match = stripAnsi(out).match(/\[([^\]]+)\]/);
    return match ? match[1] : out.trim();
  }

  /** Claim an open task by ID. */
  async taskClaim(id: string, room?: string): Promise<string> {
    const cmdArgs = room
      ? ["--room", room, "task-claim", id]
      : this.args(["task-claim", id]);
    const result = await run(this.binary, cmdArgs, this.env);
    return assertOk(result, "task-claim").trim();
  }

  /** Mark a task as done. */
  async taskDone(id: string, notes?: string, room?: string): Promise<string> {
    const cmdArgs = room
      ? ["--room", room, "task-done", id]
      : this.args(["task-done", id]);
    if (notes) cmdArgs.push("--notes", notes);
    const result = await run(this.binary, cmdArgs, this.env);
    return assertOk(result, "task-done").trim();
  }

  // ─── Info ────────────────────────────────────────────────────────────────────

  /** Get room statistics. */
  async stats(room?: string): Promise<AgoraStats> {
    const cmdArgs = room
      ? ["--room", room, "stats"]
      : this.args(["stats"]);
    const result = await run(this.binary, cmdArgs, this.env);
    const raw = assertOk(result, "stats");
    const clean = stripAnsi(raw);
    const extract = (key: string): number => {
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
  async info(room?: string): Promise<string> {
    const cmdArgs = room
      ? ["--room", room, "info"]
      : this.args(["info"]);
    const result = await run(this.binary, cmdArgs, this.env);
    return stripAnsi(assertOk(result, "info")).trim();
  }

  // ─── DMs ────────────────────────────────────────────────────────────────────

  /** Send a direct message to another agent. */
  async dm(agentId: string, message?: string): Promise<string> {
    const cmdArgs = message ? ["dm", agentId, message] : ["dm", agentId];
    const result = await run(this.binary, cmdArgs, this.env);
    return assertOk(result, "dm").trim();
  }

  // ─── Aliases ────────────────────────────────────────────────────────────────

  /** Set a readable alias for an agent. */
  async alias(agentId: string, name: string): Promise<string> {
    const result = await run(this.binary, ["alias", agentId, name], this.env);
    return assertOk(result, "alias").trim();
  }

  /** List all aliases. */
  async aliases(): Promise<string> {
    const result = await run(this.binary, ["aliases"], this.env);
    return stripAnsi(assertOk(result, "aliases")).trim();
  }

  // ─── Webhooks ───────────────────────────────────────────────────────────────

  /** Register a webhook URL. */
  async webhookAdd(url: string, room?: string): Promise<string> {
    const cmdArgs = room
      ? ["--room", room, "webhook-add", url]
      : this.args(["webhook-add", url]);
    const result = await run(this.binary, cmdArgs, this.env);
    return assertOk(result, "webhook-add").trim();
  }

  /** List registered webhooks. */
  async webhookList(room?: string): Promise<string> {
    const cmdArgs = room
      ? ["--room", room, "webhook-list"]
      : this.args(["webhook-list"]);
    const result = await run(this.binary, cmdArgs, this.env);
    return stripAnsi(assertOk(result, "webhook-list")).trim();
  }

  /** Remove a webhook. */
  async webhookRemove(id: string, room?: string): Promise<string> {
    const cmdArgs = room
      ? ["--room", room, "webhook-remove", id]
      : this.args(["webhook-remove", id]);
    const result = await run(this.binary, cmdArgs, this.env);
    return assertOk(result, "webhook-remove").trim();
  }

  // ─── Recap / Digest ─────────────────────────────────────────────────────────

  /** Get a compact activity recap. */
  async recap(room?: string): Promise<string> {
    const cmdArgs = room
      ? ["--room", room, "recap"]
      : this.args(["recap"]);
    const result = await run(this.binary, cmdArgs, this.env);
    return stripAnsi(assertOk(result, "recap")).trim();
  }

  /** Generate a digest report. */
  async digest(period: string = "24h", room?: string): Promise<string> {
    const cmdArgs = room
      ? ["--room", room, "digest", period]
      : this.args(["digest", period]);
    const result = await run(this.binary, cmdArgs, this.env);
    return stripAnsi(assertOk(result, "digest")).trim();
  }
}

/** Convenience factory: create an Agora instance using environment variables. */
export function createAgora(config: AgoraConfig = {}): Agora {
  return new Agora(config);
}

export default Agora;
