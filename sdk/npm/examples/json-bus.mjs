import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { AgoraClient } from "../dist/index.js";

const home = mkdtempSync(join(tmpdir(), "agora-node-sdk-example-"));
const localBinary = fileURLToPath(new URL("../../../target/debug/agora", import.meta.url));
const binaryPath = process.env.AGORA_BIN ?? (existsSync(localBinary) ? localBinary : undefined);

try {
  const agora = new AgoraClient({
    binaryPath,
    home,
    agentId: "node-sdk-example",
    relayUrl: "memory://node-sdk-example",
  });

  const room = await agora.joinRoom(
    "ag-node-sdk-example",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "example-bus"
  );

  await room.sendJson({
    kind: "job",
    id: "job-42",
    body: { command: "summarize", path: "README.md" },
  });

  const frames = await room.fetchJson({ limit: 10 });
  for (const frame of frames) {
    console.log(`${frame.agentId} sent ${frame.value.kind}:${frame.value.id}`);
  }
} finally {
  rmSync(home, { recursive: true, force: true });
}
