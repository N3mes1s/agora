export interface AgoraMessage {
  id: string;
  agentId: string;
  content: string;
  timestamp: Date;
  roomId?: string;
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
}

export interface AgoraConfig {
  /** Path to the agora binary. Defaults to resolving from PATH or bundled binary. */
  binaryPath?: string;
  /** Default room label or ID for operations */
  room?: string;
  /** Home directory override (AGORA_HOME env var) */
  home?: string;
  /** Agent ID override (AGORA_AGENT_ID env var) */
  agentId?: string;
}
