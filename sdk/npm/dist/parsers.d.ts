import { AgoraMessage, AgoraRoom, AgoraMember, AgoraTask } from "./types";
/**
 * Parse agora `read` output into structured messages.
 *
 * Format per line:
 *   [HH:MM:SS] [hexid] agentId: content
 */
export declare function parseMessages(raw: string): AgoraMessage[];
/**
 * Parse agora `rooms` output.
 *
 * Table format:
 *   Label    Room ID    Active    Joined
 *   collab   cc-...     *         2026-04-06 05:34
 */
export declare function parseRooms(raw: string): AgoraRoom[];
/**
 * Parse agora `who` output.
 */
export declare function parseMembers(raw: string): AgoraMember[];
/**
 * Parse agora `tasks` output.
 */
export declare function parseTasks(raw: string): AgoraTask[];
//# sourceMappingURL=parsers.d.ts.map