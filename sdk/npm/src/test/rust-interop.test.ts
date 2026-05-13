import { strict as assert } from "assert";
import { execFile } from "child_process";
import { existsSync, mkdtempSync, rmSync } from "fs";
import { createServer, type IncomingMessage, type ServerResponse } from "http";
import { tmpdir } from "os";
import { join, resolve } from "path";
import { test } from "node:test";
import { promisify } from "util";
import { AgoraClient } from "../index";

const execFileAsync = promisify(execFile);

type RelayMessage = { time: number; message: string };

test("direct TypeScript SDK exchanges signed payloads with Rust agora", async (t) => {
  const binary = resolve(__dirname, "../../../../target/debug/agora");
  if (!existsSync(binary)) {
    t.skip("target/debug/agora is not built");
    return;
  }

  const messages = new Map<string, RelayMessage[]>();
  const server = createServer((req, res) => handleRelay(req, res, messages));
  await new Promise<void>((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
  const address = server.address();
  assert.ok(address && typeof address === "object");
  const relayUrl = `http://127.0.0.1:${address.port}`;

  const home = mkdtempSync(join(tmpdir(), "agora-node-rust-interop-"));
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

    const client = new AgoraClient({
      home,
      agentId: "node-interop",
      relayUrl,
    });
    const room = await client.joinRoom(roomId, secret, label);

    const afterRustJoin = await room.fetchMessages({ includeSystem: true });
    assert.ok(
      afterRustJoin.some((message) => message.agentId === "rust-interop" && message.content.includes("Joined")),
      "Node direct SDK should decrypt Rust signed payloads"
    );

    await room.sendText("node says hi");
    const { stdout } = await execFileAsync(binary, ["--room", label, "read", "--tail", "20"], {
      env: rustEnv,
    });
    assert.match(stdout, /node says hi/, "Rust agora should decrypt Node signed payloads");

    await execFileAsync(binary, ["--room", label, "send", "rust reused node identity key"], {
      env: { ...rustEnv, AGORA_AGENT_ID: "node-interop" },
    });
    const afterRustUsedNodeKey = await room.fetchMessages({ includeSystem: true });
    assert.ok(
      afterRustUsedNodeKey.some(
        (message) => message.agentId === "node-interop" && message.content === "rust reused node identity key"
      ),
      "Rust should be able to reuse the Node-created signing key"
    );
  } finally {
    await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
    rmSync(home, { recursive: true, force: true });
  }
});

function handleRelay(
  req: IncomingMessage,
  res: ServerResponse,
  messages: Map<string, RelayMessage[]>
): void {
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
    req.on("data", (chunk: string) => {
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
      .map((message) =>
        JSON.stringify({
          event: "message",
          time: message.time,
          message: message.message,
        })
      )
      .join("\n");
    res.writeHead(200, { "content-type": "application/x-ndjson" });
    res.end(body ? `${body}\n` : "");
    return;
  }

  res.writeHead(404);
  res.end();
}
