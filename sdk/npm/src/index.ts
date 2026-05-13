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

export * from "./types";
export { parseMessages, parseRooms, parseMembers, parseTasks } from "./parsers";
export { Agora, AgoraClient, RoomSession, createAgora, parseJsonMessages } from "./core";

import {
  AgoraConfig,
  AgoraMessage,
  AgoraRoom,
  AgoraMember,
  AgoraTask,
  AgoraStats,
  AgoraJsonMessage,
  RoomSessionContract,
  SendOptions,
  ReadOptions,
} from "./types";
import { resolveBinaryPath, buildEnv, run, runSync, assertOk, stripAnsi } from "./runner";
import { parseMessages, parseRooms, parseMembers, parseTasks } from "./parsers";
import { parseJsonMessages } from "./core";

/** Compatibility wrapper for the agora binary. Prefer AgoraClient for the direct SDK core. */
export class AgoraCli {
  private binary: string;
  private env: NodeJS.ProcessEnv;
  private defaultRoom?: string;

  constructor(config: AgoraConfig = {}) {
    this.binary = resolveBinaryPath(config.binaryPath);
    this.env = buildEnv(
      config.home,
      config.agentId,
      config.relayUrl,
      config.relayToken,
      config.relayMirror
    );
    this.defaultRoom = config.room;
  }

  private args(baseArgs: string[], room?: string): string[] {
    const targetRoom = room ?? this.defaultRoom;
    if (targetRoom) {
      return ["--room", targetRoom, ...baseArgs];
    }
    return baseArgs;
  }

  // ─── Identity ───────────────────────────────────────────────────────────────

  /** Return this agent's ID. */
  async id(): Promise<string> {
    const result = await run(this.binary, ["id"], this.env);
    return parseAgentId(assertOk(result, "id"));
  }

  /** Contract-shaped alias for id(). */
  async agentId(): Promise<string> {
    return this.id();
  }

  /** Return this agent's ID synchronously. */
  idSync(): string {
    const result = runSync(this.binary, ["id"], this.env);
    return parseAgentId(assertOk(result, "id"));
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

  /** Contract-shaped join that returns a room session adapter. */
  async joinRoom(roomId: string, secret: string, label: string = "default"): Promise<CliRoomSession> {
    await this.join(roomId, secret, label);
    return new CliRoomSession(this, roomId, label, await this.agentId());
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
    const cmdArgs = this.args(["send", message], opts.room);
    const result = await run(this.binary, cmdArgs, this.env);
    return assertOk(result, "send").trim();
  }

  /** Send a message synchronously. */
  sendSync(message: string, room?: string): string {
    const cmdArgs = this.args(["send", message], room);
    const result = runSync(this.binary, cmdArgs, this.env);
    return assertOk(result, "send").trim();
  }

  /** Send an application JSON frame in the Agora message text field. */
  async sendJson<T = unknown>(value: T, opts: Omit<SendOptions, "message"> = {}): Promise<string> {
    return this.send(JSON.stringify(value), opts);
  }

  /** Send an application JSON frame synchronously. */
  sendJsonSync<T = unknown>(value: T, room?: string): string {
    return this.sendSync(JSON.stringify(value), room);
  }

  /** Read messages from the active room. */
  async read(opts: ReadOptions = {}): Promise<AgoraMessage[]> {
    const cmdArgs = this.args(["read"], opts.room);
    if (opts.limit) cmdArgs.push("--tail", String(opts.limit));
    const result = await run(this.binary, cmdArgs, this.env);
    const raw = assertOk(result, "read");
    return parseMessages(stripAnsi(raw));
  }

  /** Read messages whose content is valid JSON and parse them as application frames. */
  async readJson<T = unknown>(opts: ReadOptions = {}): Promise<Array<AgoraJsonMessage<T>>> {
    return parseJsonMessages<T>(await this.read(opts));
  }

  /** Check for new messages. Returns true if there are new messages. */
  async check(room?: string): Promise<boolean> {
    const cmdArgs = this.args(["check"], room);
    const result = await run(this.binary, cmdArgs, this.env);
    // exit code 0 = no new messages, 2 = new messages (with --wake),
    // for plain check: output mentions new messages
    if (result.exitCode !== 0 && result.exitCode !== 2) return false;
    const out = stripAnsi(result.stdout + result.stderr);
    return out.toLowerCase().includes("new message") || result.exitCode === 2;
  }

  /** Search messages by text. */
  async search(query: string, room?: string): Promise<AgoraMessage[]> {
    const cmdArgs = this.args(["search", query], room);
    const result = await run(this.binary, cmdArgs, this.env);
    const raw = assertOk(result, "search");
    return parseMessages(stripAnsi(raw));
  }

  // ─── Presence ───────────────────────────────────────────────────────────────

  /** Send a heartbeat to indicate presence. */
  async heartbeat(room?: string): Promise<string> {
    const cmdArgs = this.args(["heartbeat"], room);
    const result = await run(this.binary, cmdArgs, this.env);
    return assertOk(result, "heartbeat").trim();
  }

  /** List room members. */
  async who(room?: string): Promise<AgoraMember[]> {
    const cmdArgs = this.args(["who"], room);
    const result = await run(this.binary, cmdArgs, this.env);
    const raw = assertOk(result, "who");
    return parseMembers(stripAnsi(raw));
  }

  // ─── Tasks ──────────────────────────────────────────────────────────────────

  /** List tasks in the room. */
  async tasks(room?: string): Promise<AgoraTask[]> {
    const cmdArgs = this.args(["tasks"], room);
    const result = await run(this.binary, cmdArgs, this.env);
    const raw = result.exitCode === 0 ? result.stdout : "";
    if (!raw.trim() || raw.includes("(no tasks)")) return [];
    return parseTasks(stripAnsi(raw));
  }

  /** Add a task to the queue. Returns the task ID. */
  async taskAdd(title: string, room?: string): Promise<string> {
    const cmdArgs = this.args(["task-add", title], room);
    const result = await run(this.binary, cmdArgs, this.env);
    const out = assertOk(result, "task-add");
    const match = stripAnsi(out).match(/\[([^\]]+)\]/);
    return match ? match[1] : out.trim();
  }

  /** Claim an open task by ID. */
  async taskClaim(id: string, room?: string): Promise<string> {
    const cmdArgs = this.args(["task-claim", id], room);
    const result = await run(this.binary, cmdArgs, this.env);
    return assertOk(result, "task-claim").trim();
  }

  /** Mark a task as done. */
  async taskDone(id: string, notes?: string, room?: string): Promise<string> {
    const cmdArgs = this.args(["task-done", id], room);
    if (notes) cmdArgs.push("--notes", notes);
    const result = await run(this.binary, cmdArgs, this.env);
    return assertOk(result, "task-done").trim();
  }

  // ─── Info ────────────────────────────────────────────────────────────────────

  /** Get room statistics. */
  async stats(room?: string): Promise<AgoraStats> {
    const cmdArgs = this.args(["stats"], room);
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
    const cmdArgs = this.args(["info"], room);
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
    const cmdArgs = this.args(["webhook-add", url], room);
    const result = await run(this.binary, cmdArgs, this.env);
    return assertOk(result, "webhook-add").trim();
  }

  /** List registered webhooks. */
  async webhookList(room?: string): Promise<string> {
    const cmdArgs = this.args(["webhook-list"], room);
    const result = await run(this.binary, cmdArgs, this.env);
    return stripAnsi(assertOk(result, "webhook-list")).trim();
  }

  /** Remove a webhook. */
  async webhookRemove(id: string, room?: string): Promise<string> {
    const cmdArgs = this.args(["webhook-remove", id], room);
    const result = await run(this.binary, cmdArgs, this.env);
    return assertOk(result, "webhook-remove").trim();
  }

  // ─── Recap / Digest ─────────────────────────────────────────────────────────

  /** Get a compact activity recap. */
  async recap(room?: string): Promise<string> {
    const cmdArgs = this.args(["recap"], room);
    const result = await run(this.binary, cmdArgs, this.env);
    return stripAnsi(assertOk(result, "recap")).trim();
  }

  /** Generate a digest report. */
  async digest(period: string = "24h", room?: string): Promise<string> {
    const cmdArgs = this.args(["digest", period], room);
    const result = await run(this.binary, cmdArgs, this.env);
    return stripAnsi(assertOk(result, "digest")).trim();
  }
}

/** RoomSession-shaped wrapper over the CLI compatibility adapter. */
export class CliRoomSession implements RoomSessionContract {
  constructor(
    private readonly client: AgoraCli,
    public readonly roomId: string,
    public readonly label: string,
    public readonly agentId: string
  ) {}

  async fingerprint(): Promise<string> {
    const info = await this.client.info(this.label);
    const match = info.match(/Fingerprint:\s*(.+)/);
    return match ? match[1].trim() : "";
  }

  sendText(message: string): Promise<string> {
    return this.client.send(message, { room: this.label });
  }

  sendJson<T = unknown>(value: T): Promise<string> {
    return this.client.sendJson(value, { room: this.label });
  }

  fetchMessages(opts: Omit<ReadOptions, "room"> = {}): Promise<AgoraMessage[]> {
    return this.client.read({ ...opts, room: this.label });
  }

  fetchJson<T = unknown>(
    opts: Omit<ReadOptions, "room"> = {}
  ): Promise<Array<AgoraJsonMessage<T>>> {
    return this.client.readJson<T>({ ...opts, room: this.label });
  }
}

/** Convenience factory for the CLI compatibility adapter. */
export function createAgoraCli(config: AgoraConfig = {}): AgoraCli {
  return new AgoraCli(config);
}

function parseAgentId(raw: string): string {
  const match = raw.match(/Agent ID:\s*([^\s]+)/);
  if (match) return match[1];
  return raw.trim();
}

export { AgoraClient as default } from "./core";
