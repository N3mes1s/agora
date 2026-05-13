export interface AgoraMessage {
  id: string;
  agentId: string;
  content: string;
  timestamp: Date;
  roomId?: string;
}

export interface AgoraJsonMessage<T = unknown> extends AgoraMessage {
  value: T;
}

export interface AgoraRoom {
  label: string;
  roomId: string;
  active: boolean;
  joinedAt: string;
}

export interface AgoraMember {
  name: string;
  agentId: string;
  role: "Member" | "Admin";
  status: "online" | "offline";
  lastSeen: string;
}

export interface AgoraTask {
  id: string;
  title: string;
  status: "open" | "claimed" | "done";
  claimedBy?: string;
}

export interface AgoraStats {
  messages: number;
  agents: number;
  characters: number;
  files: number;
  reactions: number;
}

export interface JoinOptions {
  roomId: string;
  secret: string;
  label?: string;
}

export interface SendOptions {
  room?: string;
  message: string;
}

export interface ReadOptions {
  room?: string;
  limit?: number;
  since?: string;
  includeSystem?: boolean;
}

export interface AgoraConfig {
  /** CLI adapter only: path to the agora binary. */
  binaryPath?: string;
  /** Default room label or ID for operations */
  room?: string;
  /** Home directory override. Sets HOME and AGORA_HOME for the agora subprocess. */
  home?: string;
  /** Agent ID override (AGORA_AGENT_ID env var) */
  agentId?: string;
  /** Relay URL override (AGORA_RELAY_URL env var) */
  relayUrl?: string;
  /** Relay bearer token override (AGORA_RELAY_TOKEN env var) */
  relayToken?: string;
  /** CLI adapter only: optional mirror relay URL override (AGORA_RELAY_MIRROR env var) */
  relayMirror?: string;
}

export interface RoomSessionContract {
  readonly label: string;
  readonly roomId: string;
  readonly agentId: string;
  fingerprint(): Promise<string>;
  sendText(message: string): Promise<string>;
  sendJson<T = unknown>(value: T): Promise<string>;
  fetchMessages(opts?: Omit<ReadOptions, "room">): Promise<AgoraMessage[]>;
  fetchJson<T = unknown>(opts?: Omit<ReadOptions, "room">): Promise<Array<AgoraJsonMessage<T>>>;
}

export interface AgoraClientContract {
  agentId(): Promise<string>;
  createRoom(label?: string): Promise<RoomSessionContract>;
  joinRoom(roomId: string, secret: string, label?: string): Promise<RoomSessionContract>;
  openRoom(labelOrId?: string): Promise<RoomSessionContract>;
}
