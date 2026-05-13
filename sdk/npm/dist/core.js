"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Agora = exports.RoomSession = exports.AgoraClient = void 0;
exports.createAgora = createAgora;
exports.parseJsonMessages = parseJsonMessages;
const crypto_1 = require("crypto");
const fs_1 = require("fs");
const os_1 = require("os");
const path_1 = require("path");
const nats_1 = require("nats");
const ENVELOPE_VERSION = "3.0";
const SIGNED_WIRE_VERSION = "3.1";
const DEFAULT_RELAY_URL = "https://ntfy.theagora.dev";
const DEFAULT_NATS_STREAM = "AGORA";
const DEFAULT_NATS_SUBJECT_PREFIX = "agora";
const NATS_FETCH_BATCH_SIZE = 256;
const NATS_FETCH_EXPIRES_MS = 1000;
const NATS_CONSUMER_INACTIVE_NANOS = 10000000000;
const NATS_CONSUMER_MAX_EXPIRES_NANOS = 30000000000;
const NATS_CONSUMER_MAX_BYTES = 1048576;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const ED25519_PKCS8_V0_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const ED25519_PKCS8_RING_PREFIX = Buffer.from("3051020101300506032b657004220420", "hex");
const ED25519_PKCS8_RING_PUBLIC_MARKER = Buffer.from("812100", "hex");
const memoryRelays = new Map();
/** Direct TypeScript Agora SDK client. */
class AgoraClient {
    constructor(config = {}) {
        this.homeDir = resolveHome(config.home);
        this.relayUrl = config.relayUrl ?? process.env.AGORA_RELAY_URL;
        this.relayToken = config.relayToken ?? process.env.AGORA_RELAY_TOKEN;
        this.natsSettings = natsSettingsFromConfig(config);
        this.defaultRoom = config.room;
        this.configuredAgentId = config.agentId ?? process.env.AGORA_AGENT_ID;
    }
    id() {
        return Promise.resolve(this.agentIdSync());
    }
    idSync() {
        return this.agentIdSync();
    }
    agentId() {
        return this.id();
    }
    async createRoom(label = "default") {
        const roomId = `ag-${(0, crypto_1.randomBytes)(8).toString("hex")}`;
        const secret = (0, crypto_1.randomBytes)(32).toString("hex");
        const session = this.saveRoom(roomId, secret, label, "Admin");
        await session.sendText("Room created (agora v3, TypeScript SDK).");
        return session;
    }
    async create(label = "default") {
        const session = await this.createRoom(label);
        return { roomId: session.roomId, secret: session.secret, label: session.label };
    }
    async join(roomId, secret, label = "default") {
        await this.joinRoom(roomId, secret, label);
        return `Joined room '${label}' (${roomId})`;
    }
    async joinRoom(roomId, secret, label = "default") {
        const session = this.saveRoom(roomId, secret, label, "Member");
        await session.sendText("Joined (agora v3, TypeScript SDK).");
        return session;
    }
    openRoom(labelOrId) {
        return Promise.resolve(this.openRoomSession(labelOrId));
    }
    rooms() {
        const active = this.activeRoomLabel();
        return Promise.resolve(this.loadRooms().map((room) => ({
            label: room.label,
            roomId: room.room_id,
            active: active === room.label || active === room.room_id,
            joinedAt: new Date(room.joined_at * 1000).toISOString(),
        })));
    }
    async switchRoom(label) {
        const room = this.findRoom(label);
        if (!room)
            throw new Error(`Room '${label}' not found.`);
        ensureDir(this.agoraDir());
        (0, fs_1.writeFileSync)((0, path_1.join)(this.agoraDir(), "active_room"), room.label);
        return room.label;
    }
    async leave(label) {
        const rooms = this.loadRooms();
        const room = rooms.find((candidate) => candidate.label === label || candidate.room_id === label);
        if (!room)
            throw new Error(`Room '${label}' not found.`);
        this.saveRooms(rooms.filter((candidate) => candidate.room_id !== room.room_id));
        (0, fs_1.rmSync)((0, path_1.join)(this.agoraDir(), "rooms", room.room_id), { recursive: true, force: true });
        const active = this.activeRoomLabel();
        if (active === room.label || active === room.room_id) {
            const next = this.loadRooms()[0];
            if (next) {
                (0, fs_1.writeFileSync)((0, path_1.join)(this.agoraDir(), "active_room"), next.label);
            }
            else {
                (0, fs_1.rmSync)((0, path_1.join)(this.agoraDir(), "active_room"), { force: true });
            }
        }
        return room.label;
    }
    async send(message, opts = {}) {
        return this.openRoomSession(opts.room).sendText(message);
    }
    sendSync(message, room) {
        const session = this.openRoomSession(room);
        return session.sendTextSync(message);
    }
    async sendJson(value, opts = {}) {
        return this.openRoomSession(opts.room).sendJson(value);
    }
    sendJsonSync(value, room) {
        return this.openRoomSession(room).sendJsonSync(value);
    }
    async read(opts = {}) {
        return this.openRoomSession(opts.room).fetchMessages(opts);
    }
    async readJson(opts = {}) {
        return this.openRoomSession(opts.room).fetchJson(opts);
    }
    async check(room) {
        const messages = await this.read({ room, since: "1h", limit: 1 });
        return messages.length > 0;
    }
    async search(query, room) {
        const messages = await this.read({ room, since: "all" });
        return messages.filter((message) => message.content.includes(query));
    }
    async heartbeat(room) {
        return this.openRoomSession(room).sendEnvelope({
            ...this.makeEnvelope(""),
            type: "heartbeat",
        });
    }
    async who() {
        return [];
    }
    async tasks() {
        return [];
    }
    taskAdd() {
        return Promise.reject(new Error("taskAdd() is not part of the direct SDK core. Use AgoraCli for CLI task helpers."));
    }
    taskClaim() {
        return Promise.reject(new Error("taskClaim() is not part of the direct SDK core. Use AgoraCli for CLI task helpers."));
    }
    taskDone() {
        return Promise.reject(new Error("taskDone() is not part of the direct SDK core. Use AgoraCli for CLI task helpers."));
    }
    async stats(room) {
        const messages = await this.read({ room, since: "all", includeSystem: true });
        return {
            messages: messages.length,
            agents: new Set(messages.map((message) => message.agentId)).size,
            characters: messages.reduce((total, message) => total + message.content.length, 0),
            files: 0,
            reactions: 0,
        };
    }
    async info(room) {
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
    dm(_agentId, _message) {
        return Promise.reject(new Error("dm() is not part of the direct SDK core. Use AgoraCli for CLI DM helpers."));
    }
    alias(_agentId, _name) {
        return Promise.reject(new Error("alias() is not part of the direct SDK core. Use AgoraCli for CLI alias helpers."));
    }
    aliases() {
        return Promise.reject(new Error("aliases() is not part of the direct SDK core. Use AgoraCli for CLI alias helpers."));
    }
    webhookAdd(_url, _room) {
        return Promise.reject(new Error("webhookAdd() is not part of the direct SDK core. Use AgoraCli for CLI webhook helpers."));
    }
    webhookList() {
        return Promise.reject(new Error("webhookList() is not part of the direct SDK core. Use AgoraCli for CLI webhook helpers."));
    }
    webhookRemove(_id, _room) {
        return Promise.reject(new Error("webhookRemove() is not part of the direct SDK core. Use AgoraCli for CLI webhook helpers."));
    }
    recap() {
        return Promise.reject(new Error("recap() is not part of the direct SDK core. Use AgoraCli for CLI recap helpers."));
    }
    digest(_period, _room) {
        return Promise.reject(new Error("digest() is not part of the direct SDK core. Use AgoraCli for CLI digest helpers."));
    }
    _publish(roomId, payload) {
        return publish(this.effectiveRelayUrl(), this.relayToken, this.natsSettings, roomId, payload);
    }
    _publishSync(roomId, payload) {
        publishSync(this.effectiveRelayUrl(), roomId, payload);
    }
    _fetch(roomId, since) {
        return fetchRelay(this.effectiveRelayUrl(), this.relayToken, this.natsSettings, roomId, since);
    }
    _makeEnvelope(text, replyTo) {
        return this.makeEnvelope(text, replyTo);
    }
    _encryptEnvelope(envelope, roomKey, roomId) {
        return this.encryptEnvelope(envelope, roomKey, roomId);
    }
    _decryptPayload(payload, roomKey, roomId) {
        return this.decryptPayload(payload, roomKey, roomId);
    }
    saveRoom(roomId, secret, label, role) {
        const existing = this.findRoom(roomId);
        const entry = existing ??
            {
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
            };
        if (!existing) {
            this.saveRooms([...this.loadRooms(), entry]);
        }
        ensureDir(this.agoraDir());
        (0, fs_1.writeFileSync)((0, path_1.join)(this.agoraDir(), "active_room"), entry.label);
        return this.sessionFromEntry(entry);
    }
    openRoomSession(labelOrId) {
        const selected = labelOrId ?? this.defaultRoom ?? this.activeRoomLabel();
        const room = selected ? this.findRoom(selected) : this.loadRooms()[0];
        if (!room)
            throw new Error("No room selected. Call joinRoom() or createRoom() first.");
        return this.sessionFromEntry(room);
    }
    sessionFromEntry(room) {
        return new RoomSession(this, room.room_id, room.secret, room.label, this.agentIdSync());
    }
    makeEnvelope(text, replyTo) {
        const envelope = {
            v: ENVELOPE_VERSION,
            id: (0, crypto_1.randomBytes)(4).toString("hex"),
            from: this.agentIdSync(),
            ts: now(),
            text,
        };
        if (replyTo)
            envelope.reply_to = replyTo;
        return envelope;
    }
    encryptEnvelope(envelope, roomKey, roomId) {
        const encKey = deriveMessageKeys(roomKey).encKey;
        const payload = encrypt(Buffer.from(JSON.stringify(envelope)), encKey, Buffer.from(roomId)).toString("base64");
        const from = envelope.from;
        const { privateKey, publicKeyRaw } = this.loadOrCreateSigningKeypair(from);
        const signingPubkey = publicKeyRaw.toString("base64");
        this.trustSigningKey(from, signingPubkey);
        const signingInput = signingMessageBytes(roomId, from, signingPubkey, payload);
        const sig = (0, crypto_1.sign)(null, signingInput, privateKey).toString("base64");
        return JSON.stringify({
            v: SIGNED_WIRE_VERSION,
            from,
            payload,
            signing_pubkey: signingPubkey,
            sig,
        });
    }
    decryptPayload(payload, roomKey, roomId) {
        if (payload.trimStart().startsWith("{")) {
            return this.decryptSignedPayload(payload, roomKey, roomId);
        }
        const encKey = deriveMessageKeys(roomKey).encKey;
        try {
            const plaintext = decrypt(Buffer.from(payload, "base64"), encKey, Buffer.from(roomId));
            return { ...JSON.parse(plaintext.toString("utf8")), _auth: "unsigned" };
        }
        catch {
            return null;
        }
    }
    decryptSignedPayload(raw, roomKey, roomId) {
        try {
            const wire = JSON.parse(raw);
            if (wire.v !== SIGNED_WIRE_VERSION)
                return null;
            const signingInput = signingMessageBytes(roomId, wire.from, wire.signing_pubkey, wire.payload);
            const publicKeyRaw = Buffer.from(wire.signing_pubkey, "base64");
            const publicKey = publicKeyObjectFromRaw(publicKeyRaw);
            const sig = Buffer.from(wire.sig, "base64");
            if (!(0, crypto_1.verify)(null, signingInput, publicKey, sig))
                return null;
            const trusted = this.trustedSigningKey(wire.from);
            if (trusted && !signingKeysMatch(trusted, wire.signing_pubkey))
                return null;
            if (!trusted)
                this.trustSigningKey(wire.from, wire.signing_pubkey);
            const encKey = deriveMessageKeys(roomKey).encKey;
            const plaintext = decrypt(Buffer.from(wire.payload, "base64"), encKey, Buffer.from(roomId));
            const envelope = JSON.parse(plaintext.toString("utf8"));
            if (envelope.from !== wire.from)
                return null;
            return { ...envelope, _auth: "verified" };
        }
        catch {
            return null;
        }
    }
    loadOrCreateSigningKeypair(agentId) {
        const dir = (0, path_1.join)(this.agoraDir(), "signing-keys");
        ensureDir(dir);
        const path = (0, path_1.join)(dir, `${agentId}.pkcs8`);
        if ((0, fs_1.existsSync)(path)) {
            const der = (0, fs_1.readFileSync)(path);
            const privateKey = privateKeyFromStoredPkcs8(der);
            return { privateKey, publicKeyRaw: rawPublicKey(privateKey) };
        }
        const seed = (0, crypto_1.randomBytes)(32);
        const privateKey = privateKeyFromSeed(seed);
        const publicKeyRaw = rawPublicKey(privateKey);
        (0, fs_1.writeFileSync)(path, rustCompatiblePkcs8(seed, publicKeyRaw));
        return { privateKey, publicKeyRaw };
    }
    trustedSigningKey(agentId) {
        return this.loadTrustedSigningKeys()[agentId];
    }
    trustSigningKey(agentId, signingPubkey) {
        const keys = this.loadTrustedSigningKeys();
        keys[agentId] = canonicalSigningKey(signingPubkey);
        ensureDir(this.agoraDir());
        (0, fs_1.writeFileSync)((0, path_1.join)(this.agoraDir(), "trusted_signing_keys.json"), JSON.stringify(keys, null, 2));
    }
    loadTrustedSigningKeys() {
        const path = (0, path_1.join)(this.agoraDir(), "trusted_signing_keys.json");
        if (!(0, fs_1.existsSync)(path))
            return {};
        try {
            return JSON.parse((0, fs_1.readFileSync)(path, "utf8"));
        }
        catch {
            return {};
        }
    }
    agentIdSync() {
        if (this._agentId)
            return this._agentId;
        if (this.configuredAgentId) {
            this._agentId = this.configuredAgentId;
            return this._agentId;
        }
        const idFile = (0, path_1.join)(this.agoraDir(), "identity.json");
        if ((0, fs_1.existsSync)(idFile)) {
            try {
                const data = JSON.parse((0, fs_1.readFileSync)(idFile, "utf8"));
                this._agentId = data.key_id ?? data.agent_id;
                if (this._agentId)
                    return this._agentId;
            }
            catch {
                // Fall through and create a new identity.
            }
        }
        const identity = this.generateIdentity();
        ensureDir(this.agoraDir());
        (0, fs_1.writeFileSync)(idFile, JSON.stringify({
            key_id: identity.agentId,
            agent_id: identity.agentId,
            public_key: identity.publicKeyRaw.toString("hex"),
            created_at: now(),
            ephemeral: process.env.AGORA_IDENTITY_SEED === undefined,
        }, null, 2));
        const keysDir = (0, path_1.join)(this.agoraDir(), "signing-keys");
        ensureDir(keysDir);
        (0, fs_1.writeFileSync)((0, path_1.join)(keysDir, `${identity.agentId}.pkcs8`), identity.pkcs8);
        this._agentId = identity.agentId;
        return this._agentId;
    }
    generateIdentity() {
        const seedPhrase = process.env.AGORA_IDENTITY_SEED;
        if (seedPhrase) {
            const seed = (0, crypto_1.createHmac)("sha256", "agora-identity-v1").update(seedPhrase).digest();
            const privateKey = privateKeyFromSeed(seed);
            const publicKeyRaw = rawPublicKey(privateKey);
            const pkcs8 = rustCompatiblePkcs8(seed, publicKeyRaw);
            return { agentId: deriveAgentId(publicKeyRaw), pkcs8, publicKeyRaw };
        }
        const seed = (0, crypto_1.randomBytes)(32);
        const privateKey = privateKeyFromSeed(seed);
        const publicKeyRaw = rawPublicKey(privateKey);
        const pkcs8 = rustCompatiblePkcs8(seed, publicKeyRaw);
        return { agentId: deriveAgentId(publicKeyRaw), pkcs8, publicKeyRaw };
    }
    loadRooms() {
        const path = (0, path_1.join)(this.agoraDir(), "rooms.json");
        if (!(0, fs_1.existsSync)(path))
            return [];
        try {
            return JSON.parse((0, fs_1.readFileSync)(path, "utf8"));
        }
        catch {
            return [];
        }
    }
    saveRooms(rooms) {
        ensureDir(this.agoraDir());
        (0, fs_1.writeFileSync)((0, path_1.join)(this.agoraDir(), "rooms.json"), JSON.stringify(rooms, null, 2));
    }
    findRoom(labelOrId) {
        return this.loadRooms().find((room) => room.label === labelOrId || room.room_id === labelOrId);
    }
    activeRoomLabel() {
        const path = (0, path_1.join)(this.agoraDir(), "active_room");
        if (!(0, fs_1.existsSync)(path))
            return undefined;
        return (0, fs_1.readFileSync)(path, "utf8").trim();
    }
    agoraDir() {
        return (0, path_1.join)(this.homeDir, ".agora");
    }
    effectiveRelayUrl() {
        return (this.relayUrl ?? DEFAULT_RELAY_URL).replace(/\/+$/, "");
    }
}
exports.AgoraClient = AgoraClient;
exports.Agora = AgoraClient;
class RoomSession {
    constructor(client, roomId, secret, label, agentId) {
        this.client = client;
        this.roomId = roomId;
        this.secret = secret;
        this.label = label;
        this.agentId = agentId;
        this.roomKey = deriveRoomKey(secret, roomId);
    }
    fingerprint() {
        return Promise.resolve(fingerprint(this.roomKey));
    }
    sendText(message, replyTo) {
        return this.sendEnvelope(this.client._makeEnvelope(message, replyTo));
    }
    sendTextSync(message, replyTo) {
        return this.sendEnvelopeSync(this.client._makeEnvelope(message, replyTo));
    }
    sendJson(value) {
        return this.sendText(JSON.stringify(value));
    }
    sendJsonSync(value) {
        return this.sendTextSync(JSON.stringify(value));
    }
    async fetchMessages(opts = {}) {
        const events = await this.client._fetch(this.roomId, opts.since ?? "all");
        const messages = [];
        for (const event of events) {
            const envelope = this.client._decryptPayload(event.message, this.roomKey, this.roomId);
            if (!envelope)
                continue;
            if (!opts.includeSystem && envelope.type)
                continue;
            messages.push(envelopeToMessage(envelope, this.roomId));
        }
        return typeof opts.limit === "number" ? messages.slice(-opts.limit) : messages;
    }
    async fetchJson(opts = {}) {
        return parseJsonMessages(await this.fetchMessages(opts));
    }
    async sendEnvelope(envelope) {
        const payload = this.client._encryptEnvelope(envelope, this.roomKey, this.roomId);
        await this.client._publish(this.roomId, payload);
        return envelope.id;
    }
    sendEnvelopeSync(envelope) {
        const payload = this.client._encryptEnvelope(envelope, this.roomKey, this.roomId);
        this.client._publishSync(this.roomId, payload);
        return envelope.id;
    }
}
exports.RoomSession = RoomSession;
function createAgora(config = {}) {
    return new AgoraClient(config);
}
function parseJsonMessages(messages) {
    const parsed = [];
    for (const message of messages) {
        try {
            parsed.push({ ...message, value: JSON.parse(message.content) });
        }
        catch {
            // Mixed rooms are common; ignore regular chat messages.
        }
    }
    return parsed;
}
function resolveHome(configHome) {
    return configHome ?? process.env.AGORA_HOME ?? process.env.HOME ?? (0, os_1.homedir)();
}
function now() {
    return Math.floor(Date.now() / 1000);
}
function ensureDir(path) {
    (0, fs_1.mkdirSync)(path, { recursive: true });
}
function deriveRoomKey(sharedSecret, roomId) {
    return Buffer.from((0, crypto_1.hkdfSync)("sha256", Buffer.from(sharedSecret), Buffer.from(roomId), Buffer.from("agora-room-key-v1"), 32));
}
function deriveMessageKeys(roomKey) {
    return {
        encKey: Buffer.from((0, crypto_1.hkdfSync)("sha256", roomKey, Buffer.alloc(0), Buffer.from("agora-enc-v1"), 32)),
        macKey: Buffer.from((0, crypto_1.hkdfSync)("sha256", roomKey, Buffer.alloc(0), Buffer.from("agora-mac-v1"), 32)),
    };
}
function encrypt(plaintext, key, aad) {
    const nonce = (0, crypto_1.randomBytes)(12);
    const cipher = (0, crypto_1.createCipheriv)("aes-256-gcm", key, nonce);
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return Buffer.concat([nonce, ciphertext, cipher.getAuthTag()]);
}
function decrypt(blob, key, aad) {
    if (blob.length < 28)
        throw new Error("encrypted payload too short");
    const nonce = blob.subarray(0, 12);
    const ciphertext = blob.subarray(12, -16);
    const tag = blob.subarray(-16);
    const decipher = (0, crypto_1.createDecipheriv)("aes-256-gcm", key, nonce);
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}
function fingerprint(key) {
    const hex = (0, crypto_1.createHash)("sha256").update(key).digest().subarray(0, 16).toString("hex");
    return hex.match(/.{1,4}/g)?.join(" ") ?? hex;
}
function deriveAgentId(publicKeyRaw) {
    return (0, crypto_1.createHash)("sha256").update(publicKeyRaw).digest().subarray(0, 8).toString("hex");
}
function rawPublicKey(privateKey) {
    const publicDer = (0, crypto_1.createPublicKey)(privateKey).export({ format: "der", type: "spki" });
    const prefix = publicDer.subarray(0, ED25519_SPKI_PREFIX.length);
    if (!prefix.equals(ED25519_SPKI_PREFIX) || publicDer.length !== ED25519_SPKI_PREFIX.length + 32) {
        throw new Error("unexpected Ed25519 SPKI public key format");
    }
    return publicDer.subarray(-32);
}
function privateKeyFromSeed(seed) {
    if (seed.length !== 32)
        throw new Error("invalid Ed25519 seed length");
    return (0, crypto_1.createPrivateKey)({
        key: Buffer.concat([ED25519_PKCS8_V0_PREFIX, seed]),
        format: "der",
        type: "pkcs8",
    });
}
function privateKeyFromStoredPkcs8(der) {
    try {
        return (0, crypto_1.createPrivateKey)({ key: der, format: "der", type: "pkcs8" });
    }
    catch (err) {
        const seed = seedFromRustCompatiblePkcs8(der);
        if (seed)
            return privateKeyFromSeed(seed);
        throw err;
    }
}
function rustCompatiblePkcs8(seed, publicKeyRaw) {
    if (seed.length !== 32)
        throw new Error("invalid Ed25519 seed length");
    if (publicKeyRaw.length !== 32)
        throw new Error("invalid Ed25519 public key length");
    return Buffer.concat([
        ED25519_PKCS8_RING_PREFIX,
        seed,
        ED25519_PKCS8_RING_PUBLIC_MARKER,
        publicKeyRaw,
    ]);
}
function seedFromRustCompatiblePkcs8(der) {
    const seedStart = ED25519_PKCS8_RING_PREFIX.length;
    const seedEnd = seedStart + 32;
    const markerEnd = seedEnd + ED25519_PKCS8_RING_PUBLIC_MARKER.length;
    if (der.length !== markerEnd + 32)
        return null;
    if (!der.subarray(0, seedStart).equals(ED25519_PKCS8_RING_PREFIX))
        return null;
    if (!der.subarray(seedEnd, markerEnd).equals(ED25519_PKCS8_RING_PUBLIC_MARKER))
        return null;
    return der.subarray(seedStart, seedEnd);
}
function publicKeyObjectFromRaw(publicKeyRaw) {
    if (publicKeyRaw.length !== 32)
        throw new Error("invalid Ed25519 public key length");
    return (0, crypto_1.createPublicKey)({
        key: Buffer.concat([ED25519_SPKI_PREFIX, publicKeyRaw]),
        format: "der",
        type: "spki",
    });
}
function signingMessageBytes(roomId, from, signingPubkey, payload) {
    return Buffer.from(`agora-signed-wire-v1\n${roomId}\n${from}\n${signingPubkey}\n${payload}`);
}
function canonicalSigningKey(signingPubkey) {
    return Buffer.from(signingPubkey, "base64").toString("base64");
}
function signingKeysMatch(left, right) {
    return canonicalSigningKey(left) === canonicalSigningKey(right);
}
function envelopeToMessage(envelope, roomId) {
    return {
        id: envelope.id,
        agentId: envelope.from,
        content: envelope.text,
        timestamp: new Date(envelope.ts * 1000),
        roomId,
    };
}
async function publish(relayUrl, token, natsSettings, topic, payload) {
    if (relayUrl.startsWith("memory://")) {
        publishMemory(relayUrl, topic, payload);
        return;
    }
    if (isNatsRelay(relayUrl)) {
        await publishNats(relayUrl, token, natsSettings, topic, payload);
        return;
    }
    const headers = token ? { Authorization: `Bearer ${token}` } : {};
    const response = await fetch(`${relayUrl}/${topic}`, {
        method: "POST",
        body: payload,
        headers,
    });
    if (!response.ok)
        throw new Error(`relay publish failed (${response.status})`);
}
function publishSync(relayUrl, topic, payload) {
    if (!relayUrl.startsWith("memory://")) {
        throw new Error("sendSync is only supported with memory:// relays in the direct SDK core.");
    }
    publishMemory(relayUrl, topic, payload);
}
function publishMemory(relayUrl, topic, payload) {
    const key = `${relayUrl}/${topic}`;
    const events = memoryRelays.get(key) ?? [];
    events.push({ time: now(), message: payload });
    memoryRelays.set(key, events);
}
async function fetchRelay(relayUrl, token, natsSettings, topic, since) {
    if (relayUrl.startsWith("memory://")) {
        const cutoff = sinceCutoff(since);
        return (memoryRelays.get(`${relayUrl}/${topic}`) ?? []).filter((event) => event.time >= cutoff);
    }
    if (isNatsRelay(relayUrl)) {
        return fetchNats(relayUrl, token, natsSettings, topic, since);
    }
    const headers = token ? { Authorization: `Bearer ${token}` } : {};
    const response = await fetch(`${relayUrl}/${topic}/json?poll=1&since=${encodeURIComponent(since)}`, { headers });
    if (!response.ok)
        return [];
    const text = await response.text();
    const events = [];
    for (const line of text.split(/\r?\n/)) {
        if (!line.trim())
            continue;
        try {
            const event = JSON.parse(line);
            if (event.event === "message" && typeof event.message === "string") {
                events.push({ time: event.time ?? 0, message: event.message });
            }
        }
        catch {
            // Ignore non-JSON relay keepalive lines.
        }
    }
    return events;
}
function sinceCutoff(since) {
    if (since === "all" || since === "0")
        return 0;
    const match = since.match(/^(\d+)([smhd])$/);
    if (!match)
        return 0;
    const value = Number(match[1]);
    const unit = match[2];
    const multiplier = unit === "s" ? 1 : unit === "m" ? 60 : unit === "h" ? 3600 : 86400;
    return now() - value * multiplier;
}
function isNatsRelay(relayUrl) {
    return relayUrl.startsWith("nats://") || relayUrl.startsWith("tls://");
}
async function publishNats(relayUrl, token, settings, topic, payload) {
    const nc = await (0, nats_1.connect)(natsConnectionOptions(relayUrl, token));
    try {
        const { js } = await natsContexts(nc, settings);
        const subject = natsSubjectForTopic(settings, topic);
        await js.publish(subject, (0, nats_1.StringCodec)().encode(payload), {
            msgID: `agora-${process.pid}-${now()}-${(0, crypto_1.randomBytes)(4).toString("hex")}`,
        });
        await nc.flush();
    }
    finally {
        await nc.close();
    }
}
async function fetchNats(relayUrl, token, settings, topic, since) {
    const nc = await (0, nats_1.connect)(natsConnectionOptions(relayUrl, token));
    const decoder = (0, nats_1.StringCodec)();
    try {
        const { js, jsm } = await natsContexts(nc, settings);
        const subject = natsSubjectForTopic(settings, topic);
        const consumer = await createNatsFetchConsumer(jsm, settings, subject, sinceCutoff(since));
        try {
            const events = [];
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
                if (!sawMessages)
                    break;
            }
            return events;
        }
        finally {
            await consumer.delete().catch(() => undefined);
        }
    }
    finally {
        await nc.close();
    }
}
function natsConnectionOptions(relayUrl, token) {
    const options = {
        servers: relayUrl,
        name: "agora-sdk",
        timeout: 5000,
        maxReconnectAttempts: 10,
    };
    if (token)
        options.token = token;
    if (relayUrl.startsWith("tls://"))
        options.tls = {};
    return options;
}
async function natsContexts(nc, settings) {
    const jsm = await nc.jetstreamManager();
    await ensureNatsStream(jsm, settings);
    return { js: nc.jetstream(), jsm };
}
async function ensureNatsStream(jsm, settings) {
    if (!settings.createStream) {
        return jsm.streams.info(settings.streamName);
    }
    try {
        return await jsm.streams.info(settings.streamName);
    }
    catch {
        return jsm.streams.add(natsStreamConfig(settings));
    }
}
function natsStreamConfig(settings) {
    return {
        name: settings.streamName,
        subjects: [settings.streamSubject],
        retention: nats_1.RetentionPolicy.Limits,
        storage: settings.storage === "memory" ? nats_1.StorageType.Memory : nats_1.StorageType.File,
        max_bytes: settings.maxBytes,
        max_age: settings.maxAgeNanos,
        allow_direct: true,
        description: "Agora encrypted room relay events",
    };
}
async function createNatsFetchConsumer(jsm, settings, subject, cutoff) {
    const name = `agora_fetch_${Date.now()}_${(0, crypto_1.randomBytes)(4).toString("hex")}`;
    const config = {
        name,
        ack_policy: nats_1.AckPolicy.Explicit,
        deliver_policy: cutoff === 0 ? nats_1.DeliverPolicy.All : nats_1.DeliverPolicy.StartTime,
        replay_policy: nats_1.ReplayPolicy.Instant,
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
function natsMessageToEvent(message, decoder) {
    return {
        time: Math.floor(message.info.timestampNanos / 1000000000),
        message: decoder.decode(message.data),
    };
}
function natsSubjectForTopic(settings, topic) {
    return `${settings.subjectPrefix}.${base64Url(Buffer.from(topic, "utf8"))}`;
}
function base64Url(value) {
    return value.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function natsSettingsFromConfig(config) {
    const streamName = normalizeNatsStreamName(config.natsStream ?? process.env.AGORA_NATS_STREAM ?? DEFAULT_NATS_STREAM);
    const subjectPrefix = normalizeNatsSubjectPrefix(config.natsSubjectPrefix ?? process.env.AGORA_NATS_SUBJECT_PREFIX ?? DEFAULT_NATS_SUBJECT_PREFIX);
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
function parseBool(value, defaultValue) {
    if (typeof value === "boolean")
        return value;
    if (typeof value !== "string")
        return defaultValue;
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
function parseNatsStorage(value) {
    const normalized = (value ?? "").trim().toLowerCase();
    return normalized === "memory" || normalized === "mem" ? "memory" : "file";
}
function parseNatsMaxAge(value) {
    if (typeof value === "number")
        return Math.max(0, value) * 1000000000;
    if (!value)
        return 0;
    const match = value.trim().match(/^(\d+)([smhd])?$/);
    if (!match)
        return 0;
    const amount = Number(match[1]);
    const unit = match[2] ?? "s";
    const seconds = unit === "s" ? amount : unit === "m" ? amount * 60 : unit === "h" ? amount * 3600 : amount * 86400;
    return seconds * 1000000000;
}
function normalizeNatsStreamName(raw) {
    const normalized = raw
        .trim()
        .replace(/[^0-9A-Za-z_-]/g, "_")
        .replace(/^_+|_+$/g, "");
    return normalized || DEFAULT_NATS_STREAM;
}
function normalizeNatsSubjectPrefix(raw) {
    const tokens = raw
        .trim()
        .replace(/^\.+|\.+$/g, "")
        .split(".")
        .map((token) => token.replace(/[^0-9A-Za-z_-]/g, "_").replace(/^_+|_+$/g, ""))
        .filter(Boolean);
    return tokens.length > 0 ? tokens.join(".") : DEFAULT_NATS_SUBJECT_PREFIX;
}
//# sourceMappingURL=core.js.map