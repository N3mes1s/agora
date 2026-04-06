"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseMessages = parseMessages;
exports.parseRooms = parseRooms;
exports.parseMembers = parseMembers;
exports.parseTasks = parseTasks;
/**
 * Parse agora `read` output into structured messages.
 *
 * Format per line:
 *   [HH:MM:SS] [hexid] agentId: content
 */
function parseMessages(raw) {
    const messages = [];
    const lines = raw.split("\n");
    for (const line of lines) {
        const trimmed = line.trim();
        // Match: [HH:MM:SS] [msgid] agentId: content
        const match = trimmed.match(/^\[(\d{2}:\d{2}:\d{2})\]\s+\[([0-9a-f]+)\]\s+(\S+):\s*(.*)$/);
        if (!match)
            continue;
        const [, time, id, agentId, content] = match;
        // Use today's date with the parsed time
        const today = new Date().toISOString().slice(0, 10);
        const timestamp = new Date(`${today}T${time}Z`);
        messages.push({ id, agentId, content, timestamp });
    }
    return messages;
}
/**
 * Parse agora `rooms` output.
 *
 * Table format:
 *   Label    Room ID    Active    Joined
 *   collab   cc-...     *         2026-04-06 05:34
 */
function parseRooms(raw) {
    const rooms = [];
    const lines = raw.split("\n");
    let inTable = false;
    for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed.startsWith("Label")) {
            inTable = true;
            continue;
        }
        if (!inTable || trimmed.startsWith("─") || !trimmed)
            continue;
        // Split on multiple spaces
        const parts = trimmed.split(/\s{2,}/);
        if (parts.length >= 3) {
            const active = parts[2] === "*";
            rooms.push({
                label: parts[0],
                roomId: parts[1],
                active,
                joinedAt: parts[3] ?? "",
            });
        }
    }
    return rooms;
}
/**
 * Parse agora `who` output.
 */
function parseMembers(raw) {
    const members = [];
    const lines = raw.split("\n");
    let inTable = false;
    for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed.startsWith("Name")) {
            inTable = true;
            continue;
        }
        if (!inTable || trimmed.startsWith("─") || !trimmed)
            continue;
        const parts = trimmed.split(/\s{2,}/);
        // The `who` table has columns: Name, Agent, Role, Status, Last seen
        // When Name is empty, trimming removes that column, shifting indices down by 1.
        // We detect this by checking if the first part looks like a role keyword.
        let name, agentId, role, statusRaw, lastSeen;
        const roleKeywords = ["Member", "Admin"];
        if (parts.length >= 4 && !roleKeywords.includes(parts[1])) {
            // Name is present: [name, agentId, role, status, lastSeen]
            [name, agentId, role, statusRaw, lastSeen] = parts;
        }
        else {
            // Name was empty and got trimmed: [agentId, role, status, lastSeen]
            name = "";
            [agentId, role, statusRaw, lastSeen] = parts;
        }
        const status = (statusRaw ?? "").toLowerCase().includes("online") ? "online" : "offline";
        if (agentId) {
            members.push({
                name: name ?? "",
                agentId,
                role: role ?? "Member",
                status,
                lastSeen: lastSeen ?? "",
            });
        }
    }
    return members;
}
/**
 * Parse agora `tasks` output.
 */
function parseTasks(raw) {
    const tasks = [];
    const lines = raw.split("\n");
    for (const line of lines) {
        const trimmed = line.trim();
        // Match patterns:
        //   [id] (open) Title
        //   [id] (claimed by agent) Title
        //   [id] (done) Title
        const match = trimmed.match(/^\[([^\]]+)\]\s+\(([^)]+)\)\s+(.+)$/);
        if (!match)
            continue;
        const [, id, statusRaw, title] = match;
        let status = "open";
        let claimedBy;
        if (statusRaw.startsWith("claimed by")) {
            status = "claimed";
            claimedBy = statusRaw.replace("claimed by", "").trim();
        }
        else if (statusRaw === "done") {
            status = "done";
        }
        tasks.push({ id, title, status, claimedBy });
    }
    return tasks;
}
//# sourceMappingURL=parsers.js.map