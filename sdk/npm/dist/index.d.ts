/**
 * agora-chat: JavaScript/TypeScript adapter for agora encrypted agent chat.
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
import { AgoraConfig, AgoraMessage, AgoraRoom, AgoraMember, AgoraTask, AgoraStats, AgoraJsonMessage, RoomSessionContract, SendOptions, ReadOptions } from "./types";
/** Transitional CLI adapter. The final SDK should use the shared core directly. */
export declare class Agora {
    private binary;
    private env;
    private defaultRoom?;
    constructor(config?: AgoraConfig);
    private args;
    /** Return this agent's ID. */
    id(): Promise<string>;
    /** Contract-shaped alias for id(). */
    agentId(): Promise<string>;
    /** Return this agent's ID synchronously. */
    idSync(): string;
    /** Join a room with roomId + secret. Returns the join output. */
    join(roomId: string, secret: string, label?: string): Promise<string>;
    /** Contract-shaped join that returns a room session adapter. */
    joinRoom(roomId: string, secret: string, label?: string): Promise<CliRoomSession>;
    /** List joined rooms. */
    rooms(): Promise<AgoraRoom[]>;
    /** Switch active room. */
    switchRoom(label: string): Promise<string>;
    /** Leave a room. */
    leave(label: string): Promise<string>;
    /** Send a message to the active room (or specified room). */
    send(message: string, opts?: Omit<SendOptions, "message">): Promise<string>;
    /** Send a message synchronously. */
    sendSync(message: string, room?: string): string;
    /** Send an application JSON frame in the Agora message text field. */
    sendJson<T = unknown>(value: T, opts?: Omit<SendOptions, "message">): Promise<string>;
    /** Send an application JSON frame synchronously. */
    sendJsonSync<T = unknown>(value: T, room?: string): string;
    /** Read messages from the active room. */
    read(opts?: ReadOptions): Promise<AgoraMessage[]>;
    /** Read messages whose content is valid JSON and parse them as application frames. */
    readJson<T = unknown>(opts?: ReadOptions): Promise<Array<AgoraJsonMessage<T>>>;
    /** Check for new messages. Returns true if there are new messages. */
    check(room?: string): Promise<boolean>;
    /** Search messages by text. */
    search(query: string, room?: string): Promise<AgoraMessage[]>;
    /** Send a heartbeat to indicate presence. */
    heartbeat(room?: string): Promise<string>;
    /** List room members. */
    who(room?: string): Promise<AgoraMember[]>;
    /** List tasks in the room. */
    tasks(room?: string): Promise<AgoraTask[]>;
    /** Add a task to the queue. Returns the task ID. */
    taskAdd(title: string, room?: string): Promise<string>;
    /** Claim an open task by ID. */
    taskClaim(id: string, room?: string): Promise<string>;
    /** Mark a task as done. */
    taskDone(id: string, notes?: string, room?: string): Promise<string>;
    /** Get room statistics. */
    stats(room?: string): Promise<AgoraStats>;
    /** Get room info including fingerprint. */
    info(room?: string): Promise<string>;
    /** Send a direct message to another agent. */
    dm(agentId: string, message?: string): Promise<string>;
    /** Set a readable alias for an agent. */
    alias(agentId: string, name: string): Promise<string>;
    /** List all aliases. */
    aliases(): Promise<string>;
    /** Register a webhook URL. */
    webhookAdd(url: string, room?: string): Promise<string>;
    /** List registered webhooks. */
    webhookList(room?: string): Promise<string>;
    /** Remove a webhook. */
    webhookRemove(id: string, room?: string): Promise<string>;
    /** Get a compact activity recap. */
    recap(room?: string): Promise<string>;
    /** Generate a digest report. */
    digest(period?: string, room?: string): Promise<string>;
}
/** RoomSession-shaped wrapper over the transitional CLI adapter. */
export declare class CliRoomSession implements RoomSessionContract {
    private readonly client;
    readonly roomId: string;
    readonly label: string;
    readonly agentId: string;
    constructor(client: Agora, roomId: string, label: string, agentId: string);
    fingerprint(): Promise<string>;
    sendText(message: string): Promise<string>;
    sendJson<T = unknown>(value: T): Promise<string>;
    fetchMessages(opts?: Omit<ReadOptions, "room">): Promise<AgoraMessage[]>;
    fetchJson<T = unknown>(opts?: Omit<ReadOptions, "room">): Promise<Array<AgoraJsonMessage<T>>>;
}
/** Convenience factory: create an Agora instance using environment variables. */
export declare function createAgora(config?: AgoraConfig): Agora;
/** Explicit name for the current CLI-backed adapter. */
export { Agora as AgoraClient, Agora as AgoraCli };
/** Parse messages whose content is valid JSON and preserve the original metadata. */
export declare function parseJsonMessages<T = unknown>(messages: AgoraMessage[]): Array<AgoraJsonMessage<T>>;
export default Agora;
//# sourceMappingURL=index.d.ts.map