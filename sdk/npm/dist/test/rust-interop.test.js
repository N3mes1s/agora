"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const assert_1 = require("assert");
const child_process_1 = require("child_process");
const fs_1 = require("fs");
const http_1 = require("http");
const os_1 = require("os");
const path_1 = require("path");
const node_test_1 = require("node:test");
const util_1 = require("util");
const index_1 = require("../index");
const execFileAsync = (0, util_1.promisify)(child_process_1.execFile);
(0, node_test_1.test)("direct TypeScript SDK exchanges signed payloads with Rust agora", async (t) => {
    const binary = (0, path_1.resolve)(__dirname, "../../../../target/debug/agora");
    if (!(0, fs_1.existsSync)(binary)) {
        t.skip("target/debug/agora is not built");
        return;
    }
    const messages = new Map();
    const server = (0, http_1.createServer)((req, res) => handleRelay(req, res, messages));
    await new Promise((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
    const address = server.address();
    assert_1.strict.ok(address && typeof address === "object");
    const relayUrl = `http://127.0.0.1:${address.port}`;
    const home = (0, fs_1.mkdtempSync)((0, path_1.join)((0, os_1.tmpdir)(), "agora-node-rust-interop-"));
    const roomId = "ag-node-rust-interop";
    const secret = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    const label = "interop-room";
    try {
        const rustEnv = {
            ...process.env,
            HOME: home,
            AGORA_HOME: home,
            AGORA_AGENT_ID: "rust-interop",
            AGORA_RELAY_URL: relayUrl,
        };
        await execFileAsync(binary, ["join", roomId, secret, label], { env: rustEnv });
        const client = new index_1.AgoraClient({
            home,
            agentId: "node-interop",
            relayUrl,
        });
        const room = await client.joinRoom(roomId, secret, label);
        const afterRustJoin = await room.fetchMessages({ includeSystem: true });
        assert_1.strict.ok(afterRustJoin.some((message) => message.agentId === "rust-interop" && message.content.includes("Joined")), "Node direct SDK should decrypt Rust signed payloads");
        await room.sendText("node says hi");
        const { stdout } = await execFileAsync(binary, ["--room", label, "read", "--tail", "20"], {
            env: rustEnv,
        });
        assert_1.strict.match(stdout, /node says hi/, "Rust agora should decrypt Node signed payloads");
        await execFileAsync(binary, ["--room", label, "send", "rust reused node identity key"], {
            env: { ...rustEnv, AGORA_AGENT_ID: "node-interop" },
        });
        const afterRustUsedNodeKey = await room.fetchMessages({ includeSystem: true });
        assert_1.strict.ok(afterRustUsedNodeKey.some((message) => message.agentId === "node-interop" && message.content === "rust reused node identity key"), "Rust should be able to reuse the Node-created signing key");
    }
    finally {
        await new Promise((resolveClose) => server.close(() => resolveClose()));
        (0, fs_1.rmSync)(home, { recursive: true, force: true });
    }
});
function handleRelay(req, res, messages) {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    const topic = url.pathname.split("/").filter(Boolean)[0];
    if (!topic) {
        res.writeHead(404);
        res.end();
        return;
    }
    if (req.method === "POST") {
        let body = "";
        req.setEncoding("utf8");
        req.on("data", (chunk) => {
            body += chunk;
        });
        req.on("end", () => {
            const topicMessages = messages.get(topic) ?? [];
            topicMessages.push({ time: Math.floor(Date.now() / 1000), message: body });
            messages.set(topic, topicMessages);
            res.writeHead(200, { "content-type": "text/plain" });
            res.end("ok");
        });
        return;
    }
    if (req.method === "GET" && url.pathname === `/${topic}/json`) {
        const body = (messages.get(topic) ?? [])
            .map((message) => JSON.stringify({
            event: "message",
            time: message.time,
            message: message.message,
        }))
            .join("\n");
        res.writeHead(200, { "content-type": "application/x-ndjson" });
        res.end(body ? `${body}\n` : "");
        return;
    }
    res.writeHead(404);
    res.end();
}
//# sourceMappingURL=rust-interop.test.js.map