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

const memoryRelays = new Map<string, RelayEvent[]>();

/** Direct TypeScript Agora SDK client. */
export class AgoraClient {
  private readonly homeDir: string;
  private readonly relayUrl?: string;
  private readonly relayToken?: string;
  private readonly defaultRoom?: string;
  private readonly configuredAgentId?: string;
  private _agentId?: string;

  constructor(config: AgoraConfig = {}) {
    this.homeDir = resolveHome(config.home);
    this.relayUrl = config.relayUrl ?? process.env.AGORA_RELAY_URL;
    this.relayToken = config.relayToken ?? process.env.AGORA_RELAY_TOKEN;
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
    const roomId = `ag-${randomBytes(8).toString("hex")}`;
    const secret = randomBytes(32).toString("hex");
    const session = this.saveRoom(roomId, secret, label, "Admin");
    await session.sendText("Room created (agora v3, TypeScript SDK).");
    return session;
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
    const messages = await this.read({ room, since: "1h", limit: 1 });
    return messages.length > 0;
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

  async who(): Promise<AgoraMember[]> {
    return [];
  }

  async tasks(): Promise<AgoraTask[]> {
    return [];
  }

  taskAdd(): Promise<string> {
    return Promise.reject(new Error("taskAdd() is not part of the direct SDK core. Use AgoraCli for CLI task helpers."));
  }

  taskClaim(): Promise<string> {
    return Promise.reject(new Error("taskClaim() is not part of the direct SDK core. Use AgoraCli for CLI task helpers."));
  }

  taskDone(): Promise<string> {
    return Promise.reject(new Error("taskDone() is not part of the direct SDK core. Use AgoraCli for CLI task helpers."));
  }

  async stats(room?: string): Promise<AgoraStats> {
    const messages = await this.read({ room, since: "all", includeSystem: true });
    return {
      messages: messages.length,
      agents: new Set(messages.map((message) => message.agentId)).size,
      characters: messages.reduce((total, message) => total + message.content.length, 0),
      files: 0,
      reactions: 0,
    };
  }

  async info(room?: string): Promise<string> {
    const session = this.openRoomSession(room);
    const stats = await this.stats(session.label);
    return [
      `Room:        ${session.label}`,
      `ID:          ${session.roomId}`,
      "Encryption:  AES-256-GCM",
      "KDF:         HKDF-SHA256",
      `Messages:    ${stats.messages}`,
      `Fingerprint: ${await session.fingerprint()}`,
    ].join("\n");
  }

  dm(_agentId?: string, _message?: string): Promise<string> {
    return Promise.reject(new Error("dm() is not part of the direct SDK core. Use AgoraCli for CLI DM helpers."));
  }

  alias(_agentId?: string, _name?: string): Promise<string> {
    return Promise.reject(new Error("alias() is not part of the direct SDK core. Use AgoraCli for CLI alias helpers."));
  }

  aliases(): Promise<string> {
    return Promise.reject(new Error("aliases() is not part of the direct SDK core. Use AgoraCli for CLI alias helpers."));
  }

  webhookAdd(_url?: string, _room?: string): Promise<string> {
    return Promise.reject(new Error("webhookAdd() is not part of the direct SDK core. Use AgoraCli for CLI webhook helpers."));
  }

  webhookList(): Promise<string> {
    return Promise.reject(new Error("webhookList() is not part of the direct SDK core. Use AgoraCli for CLI webhook helpers."));
  }

  webhookRemove(_id?: string, _room?: string): Promise<string> {
    return Promise.reject(new Error("webhookRemove() is not part of the direct SDK core. Use AgoraCli for CLI webhook helpers."));
  }

  recap(): Promise<string> {
    return Promise.reject(new Error("recap() is not part of the direct SDK core. Use AgoraCli for CLI recap helpers."));
  }

  digest(_period?: string, _room?: string): Promise<string> {
    return Promise.reject(new Error("digest() is not part of the direct SDK core. Use AgoraCli for CLI digest helpers."));
  }

  _publish(roomId: string, payload: string): Promise<void> {
    return publish(this.effectiveRelayUrl(), this.relayToken, roomId, payload);
  }

  _publishSync(roomId: string, payload: string): void {
    publishSync(this.effectiveRelayUrl(), roomId, payload);
  }

  _fetch(roomId: string, since: string): Promise<RelayEvent[]> {
    return fetchRelay(this.effectiveRelayUrl(), this.relayToken, roomId, since);
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
    }
    ensureDir(this.agoraDir());
    writeFileSync(join(this.agoraDir(), "active_room"), entry.label);
    return this.sessionFromEntry(entry);
  }

  private openRoomSession(labelOrId?: string): RoomSession {
    const selected = labelOrId ?? this.defaultRoom ?? this.activeRoomLabel();
    const room = selected ? this.findRoom(selected) : this.loadRooms()[0];
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
  return {
    id: envelope.id,
    agentId: envelope.from,
    content: envelope.text,
    timestamp: new Date(envelope.ts * 1000),
    roomId,
  };
}

async function publish(relayUrl: string, token: string | undefined, topic: string, payload: string): Promise<void> {
  if (relayUrl.startsWith("memory://")) {
    publishMemory(relayUrl, topic, payload);
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
  memoryRelays.set(key, events);
}

async function fetchRelay(relayUrl: string, token: string | undefined, topic: string, since: string): Promise<RelayEvent[]> {
  if (relayUrl.startsWith("memory://")) {
    const cutoff = sinceCutoff(since);
    return (memoryRelays.get(`${relayUrl}/${topic}`) ?? []).filter((event) => event.time >= cutoff);
  }

  const headers: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {};
  const response = await fetch(`${relayUrl}/${topic}/json?poll=1&since=${encodeURIComponent(since)}`, { headers });
  if (!response.ok) return [];
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
