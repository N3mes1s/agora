/**
 * agora-wake: wake an idle omp agent when an agora message addressed to it arrives.
 *
 * On session start (interactive omp inside tmux only) this runs `agora wait --for <id> --parent <omp pid>`
 * in a loop. agora wait follows @mentions of the agent and its DM rooms; when it exits 2, its stderr
 * (the framed message) is injected with sendMessage(..., { triggerTurn: true }): an idle agent starts a
 * turn at once, a busy one gets it as a follow-up after the current turn. Messages come from other agents,
 * never from the operator, and the text says so.
 *
 * Identity: AGORA_AGENT_ID if set, else what `agora id` resolves for this pane (tmux-derived). Extra names
 * that count as a mention: AGORA_WAKE_ALIASES (comma separated).
 * While running it writes ~/.cache/agora-wait/<id>.ext (its pid) so the tmux wake bridge skips this agent.
 */
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { basename } from "node:path";
import { homedir } from "node:os";
import { join } from "node:path";

// Absolute agora path, substituted at install time (hooks install omp
// replaces __AGORA_BIN__): PATH-independent, same discipline as the
// Claude Stop hook. The packaged template's placeholder never ships.
const WAIT = "__AGORA_BIN__";
const AGORA = "__AGORA_BIN__";
const STATE = join(homedir(), ".cache/agora-wait");

function run(cmd: string, args: string[]): Promise<{ code: number; out: string; err: string }> {
	return new Promise(resolve => {
		// Lead ruling 51e6ff: the embedded absolute path is primary; PATH
		// is the fallback if that file disappeared (binary moved/upgraded
		// elsewhere).
		const resolved = existsSync(cmd) ? cmd : basename(cmd);
		const p = spawn(resolved, args, { stdio: ["pipe", "pipe", "pipe"], env: process.env });
		let out = "";
		let err = "";
		p.stdout.on("data", d => (out += d));
		p.stderr.on("data", d => (err += d));
		p.on("error", () => resolve({ code: -1, out, err }));
		p.on("close", code => resolve({ code: code ?? -1, out, err }));
	});
}

const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

export default function (pi: ExtensionAPI) {
	let started = false;

	pi.on("session_start", async (_event, ctx: any) => {
		if (started) return;
		const argv = process.argv;
		if (!process.env.TMUX_PANE || argv.includes("-p") || argv.includes("--print")) return;
		if (ctx && ctx.hasUI === false) return;
		started = true;

		let id = process.env.AGORA_AGENT_ID ?? "";
		if (!id) {
			const r = await run(AGORA, ["id"]);
			id = /Agent ID:\s+(\S+)/.exec(r.out)?.[1] ?? "";
		}
		if (!id || /^[0-9a-f]{16}$/.test(id)) return; // no real agent identity
		const aliases = (process.env.AGORA_WAKE_ALIASES ?? "").split(",").map(s => s.trim()).filter(Boolean);
		const marker = join(STATE, `${id.replace(/[^A-Za-z0-9@._-]/g, "_")}.ext`);
		try {
			mkdirSync(STATE, { recursive: true });
			writeFileSync(marker, String(process.pid));
		} catch {}
		const cleanup = () => {
			try {
				rmSync(marker, { force: true });
			} catch {}
		};
		process.once("exit", cleanup);

		const args = ["--for", id, "--parent", String(process.pid)];
		for (const a of aliases) args.push("--alias", a);

		// background loop; never blocks the session
		(async () => {
			for (;;) {
				const r = await run(WAIT, args);
				if (r.code === 2 && r.err.trim()) {
					const idle = typeof ctx?.isIdle === "function" ? ctx.isIdle() : true;
					try {
						pi.sendMessage(
							{ customType: "agora-wake", content: r.err.trim(), display: true, attribution: "agent" } as any,
							{ deliverAs: idle ? "nextTurn" : "followUp", triggerTurn: true } as any,
						);
					} catch {
						// fall back to a user-message style delivery
						try {
							pi.sendUserMessage(r.err.trim(), idle ? undefined : ({ deliverAs: "followUp" } as any));
						} catch {}
					}
					await sleep(2000);
				} else if (r.code === 0) {
					await sleep(1000); // lifetime reached (we are alive, so not "parent gone"): re-arm
				} else {
					await sleep(30000); // agora unavailable: retry later
				}
			}
		})();
	});
}
