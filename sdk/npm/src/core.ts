import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  hkdfSync,
  randomBytes,
  sign,
  verify,
  type KeyObject,
} from "crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "fs";
import { homedir } from "os";
import { join } from "path";
import {
  AckPolicy,
  DeliverPolicy,
  ReplayPolicy,
  RetentionPolicy,
  StorageType,
  StringCodec,
  connect as connectNats,
  type ConnectionOptions,
  type NatsConnection,
  type StreamConfig as NatsStreamConfig,
  type ConsumerConfig as NatsConsumerConfig,
  type JsMsg,
  type StreamInfo,
  type Consumer,
  type JetStreamManager,
  type JetStreamClient,
} from "nats";
import {
  AgoraConfig,
  AgoraJsonMessage,
  AgoraMember,
  AgoraMessage,
  AgoraRoom,
  AgoraStats,
  AgoraTask,
  ReadOptions,
  RoomSessionContract,
  SendOptions,
} from "./types";

const ENVELOPE_VERSION = "3.0";
const SIGNED_WIRE_VERSION = "3.1";
const DEFAULT_RELAY_URL = "https://ntfy.theagora.dev";
const DEFAULT_NATS_STREAM = "AGORA";
const DEFAULT_NATS_SUBJECT_PREFIX = "agora";
const NATS_FETCH_BATCH_SIZE = 256;
const NATS_FETCH_EXPIRES_MS = 1_000;
const NATS_CONSUMER_INACTIVE_NANOS = 10_000_000_000;
const NATS_CONSUMER_MAX_EXPIRES_NANOS = 30_000_000_000;
const NATS_CONSUMER_MAX_BYTES = 1_048_576;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const ED25519_PKCS8_V0_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const ED25519_PKCS8_RING_PREFIX = Buffer.from("3051020101300506032b657004220420", "hex");
const ED25519_PKCS8_RING_PUBLIC_MARKER = Buffer.from("812100", "hex");

type Role = "Admin" | "Member";

interface RoomMemberEntry {
  agent_id: string;
  role: Role;
  joined_at: number;
  nickname: string | null;
  last_seen: number;
}

interface RoomEntry {
  room_id: string;
  secret: string;
  label: string;
  joined_at: number;
  topic?: string | null;
  purpose?: string | null;
  dm_peer?: string | null;
  members: RoomMemberEntry[];
}

interface Envelope {
  v: string;
  id: string;
  from: string;
  ts: number;
  text: string;
  type?: string;
  reply_to?: string;
  _auth?: "verified" | "unsigned";
}

interface SignedWirePayload {
  v: string;
  from: string;
  payload: string;
  signing_pubkey: string;
  sig: string;
}

interface RelayEvent {
  time: number;
  message: string;
}

interface NatsSettings {
  streamName: string;
  subjectPrefix: string;
  streamSubject: string;
  createStream: boolean;
  storage: "file" | "memory";
  maxBytes: number;
  maxAgeNanos: number;
}

const memoryRelays = new Map<string, RelayEvent[]>();

/** Direct TypeScript Agora SDK client. */
export class AgoraClient {
  private readonly homeDir: string;
  private readonly relayUrl?: string;
  private readonly relayToken?: string;
  private readonly natsSettings: NatsSettings;
  private readonly defaultRoom?: string;
  private readonly configuredAgentId?: string;
  private _agentId?: string;
  private seenMessageIds = new Set<string>();

  constructor(config: AgoraConfig = {}) {
    this.homeDir = resolveHome(config.home);
    this.relayUrl = config.relayUrl ?? process.env.AGORA_RELAY_URL;
    this.relayToken = config.relayToken ?? process.env.AGORA_RELAY_TOKEN;
    this.natsSettings = natsSettingsFromConfig(config);
    this.defaultRoom = config.room;
    this.configuredAgentId = config.agentId ?? process.env.AGORA_AGENT_ID;
  }

  id(): Promise<string> {
    return Promise.resolve(this.agentIdSync());
  }

  idSync(): string {
    return this.agentIdSync();
  }

  agentId(): Promise<string> {
    return this.id();
  }

  async createRoom(label: string = "default"): Promise<RoomSession> {
    const session = this.mintRoomSession(label);
    await session.sendText("Room created (agora v3, TypeScript SDK).");
    return session;
  }

  /**
   * Create a new encrypted room without publishing the "Room created..."
   * presence envelope. Mirrors AgoraClient::create_room_silent in the Rust
   * SDK; use for embedders (cfs-mesh expose_uds, transient bridges, tests)
   * that don't want a stray system message landing as the first envelope
   * receivers see.
   */
  createRoomSilent(label: string = "default"): Promise<RoomSession> {
    return Promise.resolve(this.mintRoomSession(label));
  }

  /**
   * Eagerly materialize the local identity and return its agent id.
   * Mirrors AgoraClient::init_identity in the Rust SDK. The Node SDK
   * materializes identity on first agentId() call; this method is an
   * explicit-intent alias so embedder call sites can express "set up
   * identity now" without it reading like an accidental getter.
   */
  initIdentity(): Promise<string> {
    return Promise.resolve(this.agentIdSync());
  }

  private mintRoomSession(label: string): RoomSession {
    const roomId = `ag-${randomBytes(8).toString("hex")}`;
    const secret = randomBytes(32).toString("hex");
    return this.saveRoom(roomId, secret, label, "Admin");
  }

  async create(label: string = "default"): Promise<{ roomId: string; secret: string; label: string }> {
    const session = await this.createRoom(label);
    return { roomId: session.roomId, secret: session.secret, label: session.label };
  }

  async join(roomId: string, secret: string, label: string = "default"): Promise<string> {
    await this.joinRoom(roomId, secret, label);
    return `Joined room '${label}' (${roomId})`;
  }

  async joinRoom(roomId: string, secret: string, label: string = "default"): Promise<RoomSession> {
    const session = this.saveRoom(roomId, secret, label, "Member");
    await session.sendText("Joined (agora v3, TypeScript SDK).");
    return session;
  }

  openRoom(labelOrId?: string): Promise<RoomSession> {
    return Promise.resolve(this.openRoomSession(labelOrId));
  }

  rooms(): Promise<AgoraRoom[]> {
    const active = this.activeRoomLabel();
    return Promise.resolve(
      this.loadRooms().map((room) => ({
        label: room.label,
        roomId: room.room_id,
        active: active === room.label || active === room.room_id,
        joinedAt: new Date(room.joined_at * 1000).toISOString(),
      }))
    );
  }

  async switchRoom(label: string): Promise<string> {
    const room = this.findRoom(label);
    if (!room) throw new Error(`Room '${label}' not found.`);
    ensureDir(this.agoraDir());
    writeFileSync(join(this.agoraDir(), "active_room"), room.label);
    return room.label;
  }

  async leave(label: string): Promise<string> {
    const rooms = this.loadRooms();
    const room = rooms.find((candidate) => candidate.label === label || candidate.room_id === label);
    if (!room) throw new Error(`Room '${label}' not found.`);
    this.saveRooms(rooms.filter((candidate) => candidate.room_id !== room.room_id));
    rmSync(join(this.agoraDir(), "rooms", room.room_id), { recursive: true, force: true });
    const active = this.activeRoomLabel();
    if (active === room.label || active === room.room_id) {
      const next = this.loadRooms()[0];
      if (next) {
        writeFileSync(join(this.agoraDir(), "active_room"), next.label);
      } else {
        rmSync(join(this.agoraDir(), "active_room"), { force: true });
      }
    }
    return room.label;
  }

  async send(message: string, opts: Omit<SendOptions, "message"> = {}): Promise<string> {
    return this.openRoomSession(opts.room).sendText(message);
  }

  sendSync(message: string, room?: string): string {
    const session = this.openRoomSession(room);
    return session.sendTextSync(message);
  }

  async sendJson<T = unknown>(value: T, opts: Omit<SendOptions, "message"> = {}): Promise<string> {
    return this.openRoomSession(opts.room).sendJson(value);
  }

  sendJsonSync<T = unknown>(value: T, room?: string): string {
    return this.openRoomSession(room).sendJsonSync(value);
  }

  async read(opts: ReadOptions = {}): Promise<AgoraMessage[]> {
    return this.openRoomSession(opts.room).fetchMessages(opts);
  }

  async readJson<T = unknown>(opts: ReadOptions = {}): Promise<Array<AgoraJsonMessage<T>>> {
    return this.openRoomSession(opts.room).fetchJson<T>(opts);
  }

  async check(room?: string): Promise<boolean> {
    const me = this.agentIdSync();
    // On the first check() call, seed the seen set with all messages already
    // on the relay so we only surface messages that arrive *after* polling
    // begins — otherwise check() would report true for stale history.
    if (this.seenMessageIds.size === 0) {
      const existing = await this.read({ room, since: "all" });
      for (const message of existing) this.seenMessageIds.add(message.id);
    }
    const messages = await this.read({ room, since: "1h" });
    const hasNew = messages.some(
      (message) => message.agentId !== me && !this.seenMessageIds.has(message.id)
    );
    for (const message of messages) this.seenMessageIds.add(message.id);
    return hasNew;
  }

  async search(query: string, room?: string): Promise<AgoraMessage[]> {
    const messages = await this.read({ room, since: "all" });
    return messages.filter((message) => message.content.includes(query));
  }

  async heartbeat(room?: string): Promise<string> {
    return this.openRoomSession(room).sendEnvelope({
      ...this.makeEnvelope(""),
      type: "heartbeat",
    });
  }

  async who(room?: string): Promise<AgoraMember[]> {
    if (!this.resolveRoom(room)) return [];
    const messages = await this.read({ room, since: "all", includeSystem: true });
    const lastSeenByAgent = new Map<string, number>();
    for (const message of messages) {
      if (message.type !== "heartbeat") continue;
      const ts = message.timestamp.getTime();
      const prev = lastSeenByAgent.get(message.agentId);
      if (prev === undefined || ts > prev) lastSeenByAgent.set(message.agentId, ts);
    }
    const cutoff = Date.now() - 5 * 60_000; // 5 min window
    return Array.from(lastSeenByAgent.entries()).map(([agentId, lastSeen]) => ({
      name: agentId,
      agentId,
      role: "Member" as const,
      status: lastSeen >= cutoff ? "online" : "offline",
      lastSeen: new Date(lastSeen).toISOString(),
    }));
  }

  async tasks(room?: string): Promise<AgoraTask[]> {
    if (!this.resolveRoom(room)) return [];
    const messages = await this.read({ room, since: "all", includeSystem: true });
    const tasks = new Map<string, AgoraTask>();
    for (const message of messages) {
      const text = message.content;
      // New task: '[task] New: <title> (id: <id>)'
      const newMatch = /^\[task\]\s+New:\s+(.*?)\s*\(id:\s*([^)]+)\)\s*$/.exec(text);
      if (newMatch) {
        const id = newMatch[2].trim();
        tasks.set(id, {
          id,
          title: newMatch[1],
          status: "open",
          createdAt: message.timestamp.toISOString(),
          updatedAt: message.timestamp.toISOString(),
        });
        continue;
      }
      // Claim: '[task claim] <id>'
      const claimMatch = /^\[task\s+claim\]\s+(.+?)\s*$/.exec(text);
      if (claimMatch) {
        const id = claimMatch[1].trim();
        const existing = tasks.get(id);
        if (existing) {
          existing.status = "claimed";
          existing.claimedBy = message.agentId;
          existing.updatedAt = message.timestamp.toISOString();
        }
        continue;
      }
      // Done: '[task done] <id>' optionally followed by ' — <notes>'
      const doneMatch = /^\[task\s+done\]\s+([^—]+?)(?:\s+—\s+(.*))?\s*$/.exec(text);
      if (doneMatch) {
        const id = doneMatch[1].trim();
        const notes = doneMatch[2];
        const existing = tasks.get(id);
        if (existing) {
          existing.status = "done";
          existing.updatedAt = message.timestamp.toISOString();
          if (notes) existing.notes = notes;
        }
        continue;
      }
    }
    return Array.from(tasks.values());
  }

  async taskAdd(title: string, room?: string): Promise<string> {
    const session = this.openRoomSession(room);
    const taskId = randomBytes(4).toString("hex");
    const id = await session.sendEnvelope({
      ...this.makeEnvelope(`[task] New: ${title} (id: ${taskId})`),
    });
    return `Task added: ${title} (task id: ${taskId}, envelope ${id})`;
  }

  async taskClaim(taskId: string, room?: string): Promise<string> {
    const session = this.openRoomSession(room);
    const id = await session.sendEnvelope({
      ...this.makeEnvelope(`[task claim] ${taskId}`),
    });
    return `Claimed task ${taskId} (envelope ${id})`;
  }

  async taskDone(taskId: string, notes?: string, room?: string): Promise<string> {
    const text = `[task done] ${taskId}${notes ? ` — ${notes}` : ""}`;
    const session = this.openRoomSession(room);
    const id = await session.sendEnvelope({
      ...this.makeEnvelope(text),
    });
    return `Marked task ${taskId} done (envelope ${id})`;
  }

  async dm(agentId: string, message?: string, room?: string): Promise<string> {
    const me = this.agentIdSync();
    const sorted = [me, agentId].sort();
    const label = room ?? `dm-${sorted[0]}-${sorted[1]}`;
    // Reuse an existing DM room if we've already joined one with this label.
    const existing = this.findRoom(label);
    // Deterministic room secret so both agents derive the same key: hash the
    // two agent IDs (sorted) together. Without this each side would mint a
    // random secret and never decrypt each other's messages.
    const digest = createHash("sha256").update(`${sorted[0]}${sorted[1]}`).digest("hex");
    const roomId = `dm-${digest.slice(0, 16)}`;
    const secret = digest;
    const session = existing ? this.sessionFromEntry(existing) : this.saveRoom(roomId, secret, label, "Member");
    if (message) {
      await session.sendText(message);
    }
    return label;
  }

  async recap(room?: string): Promise<string> {
    return this.summarize("1h", room);
  }

  async digest(period: string = "24h", room?: string): Promise<string> {
    return this.summarize(period, room);
  }

  private async summarize(period: string, room?: string): Promise<string> {
    const session = this.openRoomSession(room);
    const messages = await this.read({ room: session.label, since: period });
    const agents = new Set<string>();
    let chars = 0;
    const snippets: string[] = [];
    for (const message of messages) {
      agents.add(message.agentId);
      chars += message.content.length;
      if (snippets.length < 5 && message.content.trim().length > 0) {
        const snippet = message.content.length > 80 ? message.content.slice(0, 77) + "..." : message.content;
        snippets.push(`  [${message.agentId}] ${snippet}`);
      }
    }
    const lines = [
      `Recap of '${session.label}' (last ${period})`,
      `Messages: ${messages.length}`,
      `Agents:   ${agents.size} (${Array.from(agents).join(", ")})`,
      `Volume:   ${chars} chars`,
    ];
    if (snippets.length > 0) {
      lines.push("Recent:");
      lines.push(...snippets);
    }
    return lines.join("\n");
  }

  _publish(roomId: string, payload: string): Promise<void> {
    return publish(this.effectiveRelayUrl(), this.relayToken, this.natsSettings, roomId, payload);
  }

  _publishSync(roomId: string, payload: string): void {
    publishSync(this.effectiveRelayUrl(), roomId, payload);
  }

  _fetch(roomId: string, since: string): Promise<RelayEvent[]> {
    return fetchRelay(this.effectiveRelayUrl(), this.relayToken, this.natsSettings, roomId, since);
  }

  _makeEnvelope(text: string, replyTo?: string): Envelope {
    return this.makeEnvelope(text, replyTo);
  }

  _encryptEnvelope(envelope: Envelope, roomKey: Buffer, roomId: string): string {
    return this.encryptEnvelope(envelope, roomKey, roomId);
  }

  _decryptPayload(payload: string, roomKey: Buffer, roomId: string): Envelope | null {
    return this.decryptPayload(payload, roomKey, roomId);
  }

  private saveRoom(roomId: string, secret: string, label: string, role: Role): RoomSession {
    const existing = this.findRoom(roomId);
    const entry =
      existing ??
      ({
        room_id: roomId,
        secret,
        label,
        joined_at: now(),
        topic: null,
        purpose: null,
        dm_peer: null,
        members: [
          {
            agent_id: this.agentIdSync(),
            role,
            joined_at: now(),
            nickname: null,
            last_seen: now(),
          },
        ],
      } satisfies RoomEntry);

    if (!existing) {
      this.saveRooms([...this.loadRooms(), entry]);
    } else if (existing.secret !== secret) {
      // Rejoining an already-known room with a different secret: update the
      // stored entry so the derived room key matches the new secret.
      // Load the array once, mutate the matching entry, and save that same
      // array — do NOT re-load from disk (which would lose the mutation).
      const rooms = this.loadRooms();
      const match = rooms.find((r) => r.room_id === roomId);
      if (match) {
        match.secret = secret;
        this.saveRooms(rooms);
      }
    }
    ensureDir(this.agoraDir());
    writeFileSync(join(this.agoraDir(), "active_room"), entry.label);
    return this.sessionFromEntry(entry);
  }

  private resolveRoom(labelOrId?: string): RoomEntry | undefined {
    const selected = labelOrId ?? this.defaultRoom ?? this.activeRoomLabel();
    return selected ? this.findRoom(selected) : this.loadRooms()[0];
  }

  private openRoomSession(labelOrId?: string): RoomSession {
    const room = this.resolveRoom(labelOrId);
    if (!room) throw new Error("No room selected. Call joinRoom() or createRoom() first.");
    return this.sessionFromEntry(room);
  }

  private sessionFromEntry(room: RoomEntry): RoomSession {
    return new RoomSession(this, room.room_id, room.secret, room.label, this.agentIdSync());
  }

  private makeEnvelope(text: string, replyTo?: string): Envelope {
    const envelope: Envelope = {
      v: ENVELOPE_VERSION,
      id: randomBytes(4).toString("hex"),
      from: this.agentIdSync(),
      ts: now(),
      text,
    };
    if (replyTo) envelope.reply_to = replyTo;
    return envelope;
  }

  private encryptEnvelope(envelope: Envelope, roomKey: Buffer, roomId: string): string {
    const encKey = deriveMessageKeys(roomKey).encKey;
    const payload = encrypt(Buffer.from(JSON.stringify(envelope)), encKey, Buffer.from(roomId)).toString("base64");
    const from = envelope.from;
    const { privateKey, publicKeyRaw } = this.loadOrCreateSigningKeypair(from);
    const signingPubkey = publicKeyRaw.toString("base64");
    this.trustSigningKey(from, signingPubkey);
    const signingInput = signingMessageBytes(roomId, from, signingPubkey, payload);
    const sig = sign(null, signingInput, privateKey).toString("base64");
    return JSON.stringify({
      v: SIGNED_WIRE_VERSION,
      from,
      payload,
      signing_pubkey: signingPubkey,
      sig,
    } satisfies SignedWirePayload);
  }

  private decryptPayload(payload: string, roomKey: Buffer, roomId: string): Envelope | null {
    if (payload.trimStart().startsWith("{")) {
      return this.decryptSignedPayload(payload, roomKey, roomId);
    }
    const encKey = deriveMessageKeys(roomKey).encKey;
    try {
      const plaintext = decrypt(Buffer.from(payload, "base64"), encKey, Buffer.from(roomId));
      return { ...JSON.parse(plaintext.toString("utf8")), _auth: "unsigned" } as Envelope;
    } catch {
      return null;
    }
  }

  private decryptSignedPayload(raw: string, roomKey: Buffer, roomId: string): Envelope | null {
    try {
      const wire = JSON.parse(raw) as SignedWirePayload;
      if (wire.v !== SIGNED_WIRE_VERSION) return null;
      const signingInput = signingMessageBytes(roomId, wire.from, wire.signing_pubkey, wire.payload);
      const publicKeyRaw = Buffer.from(wire.signing_pubkey, "base64");
      const publicKey = publicKeyObjectFromRaw(publicKeyRaw);
      const sig = Buffer.from(wire.sig, "base64");
      if (!verify(null, signingInput, publicKey, sig)) return null;

      const trusted = this.trustedSigningKey(wire.from);
      if (trusted && !signingKeysMatch(trusted, wire.signing_pubkey)) return null;
      if (!trusted) this.trustSigningKey(wire.from, wire.signing_pubkey);

      const encKey = deriveMessageKeys(roomKey).encKey;
      const plaintext = decrypt(Buffer.from(wire.payload, "base64"), encKey, Buffer.from(roomId));
      const envelope = JSON.parse(plaintext.toString("utf8")) as Envelope;
      if (envelope.from !== wire.from) return null;
      return { ...envelope, _auth: "verified" };
    } catch {
      return null;
    }
  }

  private loadOrCreateSigningKeypair(agentId: string): { privateKey: KeyObject; publicKeyRaw: Buffer } {
    const dir = join(this.agoraDir(), "signing-keys");
    ensureDir(dir);
    const path = join(dir, `${agentId}.pkcs8`);
    if (existsSync(path)) {
      const der = readFileSync(path);
      const privateKey = privateKeyFromStoredPkcs8(der);
      return { privateKey, publicKeyRaw: rawPublicKey(privateKey) };
    }

    const seed = randomBytes(32);
    const privateKey = privateKeyFromSeed(seed);
    const publicKeyRaw = rawPublicKey(privateKey);
    writeFileSync(path, rustCompatiblePkcs8(seed, publicKeyRaw));
    return { privateKey, publicKeyRaw };
  }

  private trustedSigningKey(agentId: string): string | undefined {
    return this.loadTrustedSigningKeys()[agentId];
  }

  private trustSigningKey(agentId: string, signingPubkey: string): void {
    const keys = this.loadTrustedSigningKeys();
    keys[agentId] = canonicalSigningKey(signingPubkey);
    ensureDir(this.agoraDir());
    writeFileSync(join(this.agoraDir(), "trusted_signing_keys.json"), JSON.stringify(keys, null, 2));
  }

  private loadTrustedSigningKeys(): Record<string, string> {
    const path = join(this.agoraDir(), "trusted_signing_keys.json");
    if (!existsSync(path)) return {};
    try {
      return JSON.parse(readFileSync(path, "utf8")) as Record<string, string>;
    } catch {
      return {};
    }
  }

  private agentIdSync(): string {
    if (this._agentId) return this._agentId;
    if (this.configuredAgentId) {
      this._agentId = this.configuredAgentId;
      return this._agentId;
    }

    const idFile = join(this.agoraDir(), "identity.json");
    if (existsSync(idFile)) {
      try {
        const data = JSON.parse(readFileSync(idFile, "utf8")) as { key_id?: string; agent_id?: string };
        this._agentId = data.key_id ?? data.agent_id;
        if (this._agentId) return this._agentId;
      } catch {
        // Fall through and create a new identity.
      }
    }

    const identity = this.generateIdentity();
    ensureDir(this.agoraDir());
    writeFileSync(
      idFile,
      JSON.stringify(
        {
          key_id: identity.agentId,
          agent_id: identity.agentId,
          public_key: identity.publicKeyRaw.toString("hex"),
          created_at: now(),
          ephemeral: process.env.AGORA_IDENTITY_SEED === undefined,
        },
        null,
        2
      )
    );
    const keysDir = join(this.agoraDir(), "signing-keys");
    ensureDir(keysDir);
    writeFileSync(join(keysDir, `${identity.agentId}.pkcs8`), identity.pkcs8);
    this._agentId = identity.agentId;
    return this._agentId;
  }

  private generateIdentity(): { agentId: string; pkcs8: Buffer; publicKeyRaw: Buffer } {
    const seedPhrase = process.env.AGORA_IDENTITY_SEED;
    if (seedPhrase) {
      const seed = createHmac("sha256", "agora-identity-v1").update(seedPhrase).digest();
      const privateKey = privateKeyFromSeed(seed);
      const publicKeyRaw = rawPublicKey(privateKey);
      const pkcs8 = rustCompatiblePkcs8(seed, publicKeyRaw);
      return { agentId: deriveAgentId(publicKeyRaw), pkcs8, publicKeyRaw };
    }

    const seed = randomBytes(32);
    const privateKey = privateKeyFromSeed(seed);
    const publicKeyRaw = rawPublicKey(privateKey);
    const pkcs8 = rustCompatiblePkcs8(seed, publicKeyRaw);
    return { agentId: deriveAgentId(publicKeyRaw), pkcs8, publicKeyRaw };
  }

  private loadRooms(): RoomEntry[] {
    const path = join(this.agoraDir(), "rooms.json");
    if (!existsSync(path)) return [];
    try {
      return JSON.parse(readFileSync(path, "utf8")) as RoomEntry[];
    } catch {
      return [];
    }
  }

  private saveRooms(rooms: RoomEntry[]): void {
    ensureDir(this.agoraDir());
    writeFileSync(join(this.agoraDir(), "rooms.json"), JSON.stringify(rooms, null, 2));
  }

  private findRoom(labelOrId: string): RoomEntry | undefined {
    return this.loadRooms().find((room) => room.label === labelOrId || room.room_id === labelOrId);
  }

  private activeRoomLabel(): string | undefined {
    const path = join(this.agoraDir(), "active_room");
    if (!existsSync(path)) return undefined;
    return readFileSync(path, "utf8").trim();
  }

  private agoraDir(): string {
    return join(this.homeDir, ".agora");
  }

  private effectiveRelayUrl(): string {
    return (this.relayUrl ?? DEFAULT_RELAY_URL).replace(/\/+$/, "");
  }
}

export class RoomSession implements RoomSessionContract {
  private readonly roomKey: Buffer;

  constructor(
    private readonly client: AgoraClient,
    public readonly roomId: string,
    public readonly secret: string,
    public readonly label: string,
    public readonly agentId: string
  ) {
    this.roomKey = deriveRoomKey(secret, roomId);
  }

  fingerprint(): Promise<string> {
    return Promise.resolve(fingerprint(this.roomKey));
  }

  sendText(message: string, replyTo?: string): Promise<string> {
    return this.sendEnvelope(this.client._makeEnvelope(message, replyTo));
  }

  sendTextSync(message: string, replyTo?: string): string {
    return this.sendEnvelopeSync(this.client._makeEnvelope(message, replyTo));
  }

  sendJson<T = unknown>(value: T): Promise<string> {
    return this.sendText(JSON.stringify(value));
  }

  sendJsonSync<T = unknown>(value: T): string {
    return this.sendTextSync(JSON.stringify(value));
  }

  async fetchMessages(opts: Omit<ReadOptions, "room"> = {}): Promise<AgoraMessage[]> {
    const events = await this.client._fetch(this.roomId, opts.since ?? "all");
    const messages: AgoraMessage[] = [];
    for (const event of events) {
      const envelope = this.client._decryptPayload(event.message, this.roomKey, this.roomId);
      if (!envelope) continue;
      if (!opts.includeSystem && envelope.type) continue;
      messages.push(envelopeToMessage(envelope, this.roomId));
    }
    return typeof opts.limit === "number" ? messages.slice(-opts.limit) : messages;
  }

  async fetchJson<T = unknown>(opts: Omit<ReadOptions, "room"> = {}): Promise<Array<AgoraJsonMessage<T>>> {
    return parseJsonMessages<T>(await this.fetchMessages(opts));
  }

  async sendEnvelope(envelope: Envelope): Promise<string> {
    const payload = this.client._encryptEnvelope(envelope, this.roomKey, this.roomId);
    await this.client._publish(this.roomId, payload);
    return envelope.id;
  }

  sendEnvelopeSync(envelope: Envelope): string {
    const payload = this.client._encryptEnvelope(envelope, this.roomKey, this.roomId);
    this.client._publishSync(this.roomId, payload);
    return envelope.id;
  }
}

/** Backward-compatible short class name for the direct SDK client. */
export { AgoraClient as Agora };

export function createAgora(config: AgoraConfig = {}): AgoraClient {
  return new AgoraClient(config);
}

export function parseJsonMessages<T = unknown>(
  messages: AgoraMessage[]
): Array<AgoraJsonMessage<T>> {
  const parsed: Array<AgoraJsonMessage<T>> = [];
  for (const message of messages) {
    try {
      parsed.push({ ...message, value: JSON.parse(message.content) as T });
    } catch {
      // Mixed rooms are common; ignore regular chat messages.
    }
  }
  return parsed;
}

function resolveHome(configHome?: string): string {
  return configHome ?? process.env.AGORA_HOME ?? process.env.HOME ?? homedir();
}

function now(): number {
  return Math.floor(Date.now() / 1000);
}

function ensureDir(path: string): void {
  mkdirSync(path, { recursive: true });
}

function deriveRoomKey(sharedSecret: string, roomId: string): Buffer {
  return Buffer.from(hkdfSync("sha256", Buffer.from(sharedSecret), Buffer.from(roomId), Buffer.from("agora-room-key-v1"), 32));
}

function deriveMessageKeys(roomKey: Buffer): { encKey: Buffer; macKey: Buffer } {
  return {
    encKey: Buffer.from(hkdfSync("sha256", roomKey, Buffer.alloc(0), Buffer.from("agora-enc-v1"), 32)),
    macKey: Buffer.from(hkdfSync("sha256", roomKey, Buffer.alloc(0), Buffer.from("agora-mac-v1"), 32)),
  };
}

function encrypt(plaintext: Buffer, key: Buffer, aad: Buffer): Buffer {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([nonce, ciphertext, cipher.getAuthTag()]);
}

function decrypt(blob: Buffer, key: Buffer, aad: Buffer): Buffer {
  if (blob.length < 28) throw new Error("encrypted payload too short");
  const nonce = blob.subarray(0, 12);
  const ciphertext = blob.subarray(12, -16);
  const tag = blob.subarray(-16);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function fingerprint(key: Buffer): string {
  const hex = createHash("sha256").update(key).digest().subarray(0, 16).toString("hex");
  return hex.match(/.{1,4}/g)?.join(" ") ?? hex;
}

function deriveAgentId(publicKeyRaw: Buffer): string {
  return createHash("sha256").update(publicKeyRaw).digest().subarray(0, 8).toString("hex");
}

function rawPublicKey(privateKey: KeyObject): Buffer {
  const publicDer = createPublicKey(privateKey).export({ format: "der", type: "spki" }) as Buffer;
  const prefix = publicDer.subarray(0, ED25519_SPKI_PREFIX.length);
  if (!prefix.equals(ED25519_SPKI_PREFIX) || publicDer.length !== ED25519_SPKI_PREFIX.length + 32) {
    throw new Error("unexpected Ed25519 SPKI public key format");
  }
  return publicDer.subarray(-32);
}

function privateKeyFromSeed(seed: Buffer): KeyObject {
  if (seed.length !== 32) throw new Error("invalid Ed25519 seed length");
  return createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_V0_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
}

function privateKeyFromStoredPkcs8(der: Buffer): KeyObject {
  try {
    return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  } catch (err) {
    const seed = seedFromRustCompatiblePkcs8(der);
    if (seed) return privateKeyFromSeed(seed);
    throw err;
  }
}

function rustCompatiblePkcs8(seed: Buffer, publicKeyRaw: Buffer): Buffer {
  if (seed.length !== 32) throw new Error("invalid Ed25519 seed length");
  if (publicKeyRaw.length !== 32) throw new Error("invalid Ed25519 public key length");
  return Buffer.concat([
    ED25519_PKCS8_RING_PREFIX,
    seed,
    ED25519_PKCS8_RING_PUBLIC_MARKER,
    publicKeyRaw,
  ]);
}

function seedFromRustCompatiblePkcs8(der: Buffer): Buffer | null {
  const seedStart = ED25519_PKCS8_RING_PREFIX.length;
  const seedEnd = seedStart + 32;
  const markerEnd = seedEnd + ED25519_PKCS8_RING_PUBLIC_MARKER.length;
  if (der.length !== markerEnd + 32) return null;
  if (!der.subarray(0, seedStart).equals(ED25519_PKCS8_RING_PREFIX)) return null;
  if (!der.subarray(seedEnd, markerEnd).equals(ED25519_PKCS8_RING_PUBLIC_MARKER)) return null;
  return der.subarray(seedStart, seedEnd);
}

function publicKeyObjectFromRaw(publicKeyRaw: Buffer): KeyObject {
  if (publicKeyRaw.length !== 32) throw new Error("invalid Ed25519 public key length");
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, publicKeyRaw]),
    format: "der",
    type: "spki",
  });
}

function signingMessageBytes(roomId: string, from: string, signingPubkey: string, payload: string): Buffer {
  return Buffer.from(`agora-signed-wire-v1\n${roomId}\n${from}\n${signingPubkey}\n${payload}`);
}

function canonicalSigningKey(signingPubkey: string): string {
  return Buffer.from(signingPubkey, "base64").toString("base64");
}

function signingKeysMatch(left: string, right: string): boolean {
  return canonicalSigningKey(left) === canonicalSigningKey(right);
}

function envelopeToMessage(envelope: Envelope, roomId: string): AgoraMessage {
  const message: AgoraMessage = {
    id: envelope.id,
    agentId: envelope.from,
    content: envelope.text,
    timestamp: new Date(envelope.ts * 1000),
    roomId,
  };
  if (envelope.type) message.type = envelope.type;
  if (envelope._auth) message.auth = envelope._auth;
  return message;
}

async function publish(
  relayUrl: string,
  token: string | undefined,
  natsSettings: NatsSettings,
  topic: string,
  payload: string
): Promise<void> {
  if (relayUrl.startsWith("memory://")) {
    publishMemory(relayUrl, topic, payload);
    return;
  }
  if (isNatsRelay(relayUrl)) {
    await publishNats(relayUrl, token, natsSettings, topic, payload);
    return;
  }

  const headers: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {};
  const response = await fetch(`${relayUrl}/${topic}`, {
    method: "POST",
    body: payload,
    headers,
  });
  if (!response.ok) throw new Error(`relay publish failed (${response.status})`);
}

function publishSync(relayUrl: string, topic: string, payload: string): void {
  if (!relayUrl.startsWith("memory://")) {
    throw new Error("sendSync is only supported with memory:// relays in the direct SDK core.");
  }
  publishMemory(relayUrl, topic, payload);
}

function publishMemory(relayUrl: string, topic: string, payload: string): void {
  const key = `${relayUrl}/${topic}`;
  const events = memoryRelays.get(key) ?? [];
  events.push({ time: now(), message: payload });
}

async function fetchRelay(
  relayUrl: string,
  token: string | undefined,
  natsSettings: NatsSettings,
  topic: string,
  since: string
): Promise<RelayEvent[]> {
  if (relayUrl.startsWith("memory://")) {
    const cutoff = sinceCutoff(since);
    return (memoryRelays.get(`${relayUrl}/${topic}`) ?? []).filter((event) => event.time >= cutoff);
  }
  if (isNatsRelay(relayUrl)) {
    return fetchNats(relayUrl, token, natsSettings, topic, since);
  }

  const headers: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {};
  const response = await fetch(`${relayUrl}/${topic}/json?poll=1&since=${encodeURIComponent(since)}`, { headers });
  if (!response.ok) throw new Error(`relay fetch failed (${response.status}): ${await response.text()}`);
  const text = await response.text();
  const events: RelayEvent[] = [];
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) continue;
    try {
      const event = JSON.parse(line) as { event?: string; time?: number; message?: string };
      if (event.event === "message" && typeof event.message === "string") {
        events.push({ time: event.time ?? 0, message: event.message });
      }
    } catch {
      // Ignore non-JSON relay keepalive lines.
    }
  }
  return events;
}

function sinceCutoff(since: string): number {
  if (since === "all" || since === "0") return 0;
  const match = since.match(/^(\d+)([smhd])$/);
  if (!match) return 0;
  const value = Number(match[1]);
  const unit = match[2];
  const multiplier = unit === "s" ? 1 : unit === "m" ? 60 : unit === "h" ? 3600 : 86400;
  return now() - value * multiplier;
}

function isNatsRelay(relayUrl: string): boolean {
  return relayUrl.startsWith("nats://") || relayUrl.startsWith("tls://");
}

async function publishNats(
  relayUrl: string,
  token: string | undefined,
  settings: NatsSettings,
  topic: string,
  payload: string
): Promise<void> {
  const nc = await connectNats(natsConnectionOptions(relayUrl, token));
  try {
    const { js } = await natsContexts(nc, settings);
    const subject = natsSubjectForTopic(settings, topic);
    await js.publish(subject, StringCodec().encode(payload), {
      msgID: `agora-${process.pid}-${now()}-${randomBytes(4).toString("hex")}`,
    });
    await nc.flush();
  } finally {
    await nc.close();
  }
}

async function fetchNats(
  relayUrl: string,
  token: string | undefined,
  settings: NatsSettings,
  topic: string,
  since: string
): Promise<RelayEvent[]> {
  const nc = await connectNats(natsConnectionOptions(relayUrl, token));
  const decoder = StringCodec();
  try {
    const { js, jsm } = await natsContexts(nc, settings);
    const subject = natsSubjectForTopic(settings, topic);
    const consumer = await createNatsFetchConsumer(jsm, settings, subject, sinceCutoff(since));
    try {
      const events: RelayEvent[] = [];
      while (true) {
        let sawMessages = false;
        const batch = await consumer.fetch({
          max_messages: NATS_FETCH_BATCH_SIZE,
          expires: NATS_FETCH_EXPIRES_MS,
        });
        for await (const message of batch) {
          sawMessages = true;
          events.push(natsMessageToEvent(message, decoder));
          message.ack();
        }
        if (!sawMessages) break;
      }
      return events;
    } finally {
      await consumer.delete().catch(() => undefined);
    }
  } finally {
    await nc.close();
  }
}

function natsConnectionOptions(relayUrl: string, token: string | undefined): ConnectionOptions {
  const options: ConnectionOptions = {
    servers: relayUrl,
    name: "agora-sdk",
    timeout: 5_000,
    maxReconnectAttempts: 10,
  };
  if (token) options.token = token;
  if (relayUrl.startsWith("tls://")) options.tls = {};
  return options;
}

async function natsContexts(
  nc: NatsConnection,
  settings: NatsSettings
): Promise<{ js: JetStreamClient; jsm: JetStreamManager }> {
  const jsm = await nc.jetstreamManager();
  await ensureNatsStream(jsm, settings);
  return { js: nc.jetstream(), jsm };
}

async function ensureNatsStream(jsm: JetStreamManager, settings: NatsSettings): Promise<StreamInfo> {
  if (!settings.createStream) {
    return jsm.streams.info(settings.streamName);
  }
  try {
    return await jsm.streams.info(settings.streamName);
  } catch {
    return jsm.streams.add(natsStreamConfig(settings));
  }
}

function natsStreamConfig(settings: NatsSettings): Partial<NatsStreamConfig> {
  return {
    name: settings.streamName,
    subjects: [settings.streamSubject],
    retention: RetentionPolicy.Limits,
    storage: settings.storage === "memory" ? StorageType.Memory : StorageType.File,
    max_bytes: settings.maxBytes,
    max_age: settings.maxAgeNanos,
    allow_direct: true,
    description: "Agora encrypted room relay events",
  };
}

async function createNatsFetchConsumer(
  jsm: JetStreamManager,
  settings: NatsSettings,
  subject: string,
  cutoff: number
): Promise<Consumer> {
  const name = `agora_fetch_${Date.now()}_${randomBytes(4).toString("hex")}`;
  const config: Partial<NatsConsumerConfig> = {
    name,
    ack_policy: AckPolicy.Explicit,
    deliver_policy: cutoff === 0 ? DeliverPolicy.All : DeliverPolicy.StartTime,
    replay_policy: ReplayPolicy.Instant,
    filter_subject: subject,
    inactive_threshold: NATS_CONSUMER_INACTIVE_NANOS,
    max_batch: NATS_FETCH_BATCH_SIZE,
    max_expires: NATS_CONSUMER_MAX_EXPIRES_NANOS,
    max_bytes: NATS_CONSUMER_MAX_BYTES,
  };
  if (cutoff > 0) {
    config.opt_start_time = new Date(cutoff * 1000).toISOString();
  }
  const info = await jsm.consumers.add(settings.streamName, config);
  return jsm.jetstream().consumers.get(settings.streamName, info.name);
}

function natsMessageToEvent(message: JsMsg, decoder: ReturnType<typeof StringCodec>): RelayEvent {
  return {
    time: Math.floor(message.info.timestampNanos / 1_000_000_000),
    message: decoder.decode(message.data),
  };
}

function natsSubjectForTopic(settings: NatsSettings, topic: string): string {
  return `${settings.subjectPrefix}.${base64Url(Buffer.from(topic, "utf8"))}`;
}

function base64Url(value: Buffer): string {
  return value.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function natsSettingsFromConfig(config: AgoraConfig): NatsSettings {
  const streamName = normalizeNatsStreamName(config.natsStream ?? process.env.AGORA_NATS_STREAM ?? DEFAULT_NATS_STREAM);
  const subjectPrefix = normalizeNatsSubjectPrefix(
    config.natsSubjectPrefix ?? process.env.AGORA_NATS_SUBJECT_PREFIX ?? DEFAULT_NATS_SUBJECT_PREFIX
  );
  return {
    streamName,
    subjectPrefix,
    streamSubject: `${subjectPrefix}.>`,
    createStream: parseBool(config.natsCreateStream ?? process.env.AGORA_NATS_CREATE_STREAM, true),
    storage: parseNatsStorage(config.natsStorage ?? process.env.AGORA_NATS_STORAGE),
    maxBytes: Math.max(0, Number(config.natsMaxBytes ?? process.env.AGORA_NATS_MAX_BYTES ?? 0) || 0),
    maxAgeNanos: parseNatsMaxAge(config.natsMaxAge ?? process.env.AGORA_NATS_MAX_AGE),
  };
}

function parseBool(value: boolean | string | undefined, defaultValue: boolean): boolean {
  if (typeof value === "boolean") return value;
  if (typeof value !== "string") return defaultValue;
  switch (value.trim().toLowerCase()) {
    case "1":
    case "true":
    case "yes":
    case "on":
      return true;
    case "0":
    case "false":
    case "no":
    case "off":
      return false;
    default:
      return defaultValue;
  }
}

function parseNatsStorage(value: string | undefined): "file" | "memory" {
  const normalized = (value ?? "").trim().toLowerCase();
  return normalized === "memory" || normalized === "mem" ? "memory" : "file";
}

function parseNatsMaxAge(value: number | string | undefined): number {
  if (typeof value === "number") return Math.max(0, value) * 1_000_000_000;
  if (!value) return 0;
  const match = value.trim().match(/^(\d+)([smhd])?$/);
  if (!match) return 0;
  const amount = Number(match[1]);
  const unit = match[2] ?? "s";
  const seconds = unit === "s" ? amount : unit === "m" ? amount * 60 : unit === "h" ? amount * 3600 : amount * 86_400;
  return seconds * 1_000_000_000;
}

function normalizeNatsStreamName(raw: string): string {
  const normalized = raw
    .trim()
    .replace(/[^0-9A-Za-z_-]/g, "_")
    .replace(/^_+|_+$/g, "");
  return normalized || DEFAULT_NATS_STREAM;
}

function normalizeNatsSubjectPrefix(raw: string): string {
  const tokens = raw
    .trim()
    .replace(/^\.+|\.+$/g, "")
    .split(".")
    .map((token) => token.replace(/[^0-9A-Za-z_-]/g, "_").replace(/^_+|_+$/g, ""))
    .filter(Boolean);
  return tokens.length > 0 ? tokens.join(".") : DEFAULT_NATS_SUBJECT_PREFIX;
}
