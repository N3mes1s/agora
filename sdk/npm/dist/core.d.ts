import { AgoraConfig, AgoraJsonMessage, AgoraMember, AgoraMessage, AgoraRoom, AgoraStats, AgoraTask, ReadOptions, RoomSessionContract, SendOptions } from "./types";
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
interface RelayEvent {
    time: number;
    message: string;
}
/** Direct TypeScript Agora SDK client. */
export declare class AgoraClient {
    private readonly homeDir;
    private readonly relayUrl?;
    private readonly relayToken?;
    private readonly natsSettings;
    private readonly defaultRoom?;
    private readonly configuredAgentId?;
    private _agentId?;
    constructor(config?: AgoraConfig);
    id(): Promise<string>;
    idSync(): string;
    agentId(): Promise<string>;
    createRoom(label?: string): Promise<RoomSession>;
    /**
     * Create a new encrypted room without publishing the "Room created..."
     * presence envelope. Mirrors AgoraClient::create_room_silent in the Rust
     * SDK; use for embedders (cfs-mesh expose_uds, transient bridges, tests)
     * that don't want a stray system message landing as the first envelope
     * receivers see.
     */
    createRoomSilent(label?: string): Promise<RoomSession>;
    /**
     * Eagerly materialize the local identity and return its agent id.
     * Mirrors AgoraClient::init_identity in the Rust SDK. The Node SDK
     * materializes identity on first agentId() call; this method is an
     * explicit-intent alias so embedder call sites can express "set up
     * identity now" without it reading like an accidental getter.
     */
    initIdentity(): Promise<string>;
    private mintRoomSession;
    create(label?: string): Promise<{
        roomId: string;
        secret: string;
        label: string;
    }>;
    join(roomId: string, secret: string, label?: string): Promise<string>;
    joinRoom(roomId: string, secret: string, label?: string): Promise<RoomSession>;
    openRoom(labelOrId?: string): Promise<RoomSession>;
    rooms(): Promise<AgoraRoom[]>;
    switchRoom(label: string): Promise<string>;
    leave(label: string): Promise<string>;
    send(message: string, opts?: Omit<SendOptions, "message">): Promise<string>;
    sendSync(message: string, room?: string): string;
    sendJson<T = unknown>(value: T, opts?: Omit<SendOptions, "message">): Promise<string>;
    sendJsonSync<T = unknown>(value: T, room?: string): string;
    read(opts?: ReadOptions): Promise<AgoraMessage[]>;
    readJson<T = unknown>(opts?: ReadOptions): Promise<Array<AgoraJsonMessage<T>>>;
    check(room?: string): Promise<boolean>;
    search(query: string, room?: string): Promise<AgoraMessage[]>;
    heartbeat(room?: string): Promise<string>;
    who(): Promise<AgoraMember[]>;
    tasks(): Promise<AgoraTask[]>;
    taskAdd(): Promise<string>;
    taskClaim(): Promise<string>;
    taskDone(): Promise<string>;
    stats(room?: string): Promise<AgoraStats>;
    info(room?: string): Promise<string>;
    dm(_agentId?: string, _message?: string): Promise<string>;
    alias(_agentId?: string, _name?: string): Promise<string>;
    aliases(): Promise<string>;
    webhookAdd(_url?: string, _room?: string): Promise<string>;
    webhookList(): Promise<string>;
    webhookRemove(_id?: string, _room?: string): Promise<string>;
    recap(): Promise<string>;
    digest(_period?: string, _room?: string): Promise<string>;
    _publish(roomId: string, payload: string): Promise<void>;
    _publishSync(roomId: string, payload: string): void;
    _fetch(roomId: string, since: string): Promise<RelayEvent[]>;
    _makeEnvelope(text: string, replyTo?: string): Envelope;
    _encryptEnvelope(envelope: Envelope, roomKey: Buffer, roomId: string): string;
    _decryptPayload(payload: string, roomKey: Buffer, roomId: string): Envelope | null;
    private saveRoom;
    private openRoomSession;
    private sessionFromEntry;
    private makeEnvelope;
    private encryptEnvelope;
    private decryptPayload;
    private decryptSignedPayload;
    private loadOrCreateSigningKeypair;
    private trustedSigningKey;
    private trustSigningKey;
    private loadTrustedSigningKeys;
    private agentIdSync;
    private generateIdentity;
    private loadRooms;
    private saveRooms;
    private findRoom;
    private activeRoomLabel;
    private agoraDir;
    private effectiveRelayUrl;
}
export declare class RoomSession implements RoomSessionContract {
    private readonly client;
    readonly roomId: string;
    readonly secret: string;
    readonly label: string;
    readonly agentId: string;
    private readonly roomKey;
    constructor(client: AgoraClient, roomId: string, secret: string, label: string, agentId: string);
    fingerprint(): Promise<string>;
    sendText(message: string, replyTo?: string): Promise<string>;
    sendTextSync(message: string, replyTo?: string): string;
    sendJson<T = unknown>(value: T): Promise<string>;
    sendJsonSync<T = unknown>(value: T): string;
    fetchMessages(opts?: Omit<ReadOptions, "room">): Promise<AgoraMessage[]>;
    fetchJson<T = unknown>(opts?: Omit<ReadOptions, "room">): Promise<Array<AgoraJsonMessage<T>>>;
    sendEnvelope(envelope: Envelope): Promise<string>;
    sendEnvelopeSync(envelope: Envelope): string;
}
/** Backward-compatible short class name for the direct SDK client. */
export { AgoraClient as Agora };
export declare function createAgora(config?: AgoraConfig): AgoraClient;
export declare function parseJsonMessages<T = unknown>(messages: AgoraMessage[]): Array<AgoraJsonMessage<T>>;
//# sourceMappingURL=core.d.ts.map