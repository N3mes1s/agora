import { spawn, spawnSync } from "child_process";
import { existsSync } from "fs";
import { join } from "path";

export interface RunResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

/**
 * Resolves the agora binary path.
 * Priority: explicit path → AGORA_BIN env → local ./target/release/agora → 'agora' on PATH
 */
export function resolveBinaryPath(explicit?: string): string {
  if (explicit) {
    if (!existsSync(explicit)) {
      throw new Error(`agora binary not found at: ${explicit}`);
    }
    return explicit;
  }
  if (process.env.AGORA_BIN) {
    return process.env.AGORA_BIN;
  }
  // Check for bundled binary next to this package
  const bundled = join(__dirname, "..", "bin", "agora");
  if (existsSync(bundled)) {
    return bundled;
  }
  // Fall back to PATH
  return "agora";
}

export function buildEnv(
  home?: string,
  agentId?: string
): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  if (home) env["AGORA_HOME"] = home;
  if (agentId) env["AGORA_AGENT_ID"] = agentId;
  return env;
}

/**
 * Run agora synchronously and return stdout/stderr/exitCode.
 */
export function runSync(
  binary: string,
  args: string[],
  env: NodeJS.ProcessEnv
): RunResult {
  const result = spawnSync(binary, args, {
    env,
    encoding: "utf8",
    maxBuffer: 10 * 1024 * 1024,
  });
  return {
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    exitCode: result.status ?? 1,
  };
}

/**
 * Run agora asynchronously and return a promise of RunResult.
 */
export function run(
  binary: string,
  args: string[],
  env: NodeJS.ProcessEnv
): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    const proc = spawn(binary, args, { env });
    let stdout = "";
    let stderr = "";

    proc.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString();
    });
    proc.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString();
    });
    proc.on("error", (err) => reject(err));
    proc.on("close", (code) => {
      resolve({ stdout, stderr, exitCode: code ?? 1 });
    });
  });
}

/**
 * Strip ANSI escape codes from terminal output.
 */
export function stripAnsi(str: string): string {
  // eslint-disable-next-line no-control-regex
  return str.replace(/\x1B\[[0-9;]*[mGKHF]/g, "").replace(/\x1B\[[0-9]*[A-Z]/g, "");
}

export function assertOk(result: RunResult, context: string): string {
  if (result.exitCode !== 0) {
    const msg = stripAnsi(result.stderr || result.stdout).trim();
    throw new Error(`agora ${context} failed (exit ${result.exitCode}): ${msg}`);
  }
  return stripAnsi(result.stdout);
}
