"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.resolveBinaryPath = resolveBinaryPath;
exports.buildEnv = buildEnv;
exports.runSync = runSync;
exports.run = run;
exports.stripAnsi = stripAnsi;
exports.assertOk = assertOk;
const child_process_1 = require("child_process");
const fs_1 = require("fs");
const path_1 = require("path");
/**
 * Resolves the agora binary path.
 * Priority: explicit path → AGORA_BIN env → local ./target/release/agora → 'agora' on PATH
 */
function resolveBinaryPath(explicit) {
    if (explicit) {
        if (!(0, fs_1.existsSync)(explicit)) {
            throw new Error(`agora binary not found at: ${explicit}`);
        }
        return explicit;
    }
    if (process.env.AGORA_BIN) {
        return process.env.AGORA_BIN;
    }
    // Check for bundled binary next to this package
    const bundled = (0, path_1.join)(__dirname, "..", "bin", "agora");
    if ((0, fs_1.existsSync)(bundled)) {
        return bundled;
    }
    // Fall back to PATH
    return "agora";
}
function buildEnv(home, agentId) {
    const env = { ...process.env };
    if (home)
        env["AGORA_HOME"] = home;
    if (agentId)
        env["AGORA_AGENT_ID"] = agentId;
    return env;
}
/**
 * Run agora synchronously and return stdout/stderr/exitCode.
 */
function runSync(binary, args, env) {
    const result = (0, child_process_1.spawnSync)(binary, args, {
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
function run(binary, args, env) {
    return new Promise((resolve, reject) => {
        const proc = (0, child_process_1.spawn)(binary, args, { env });
        let stdout = "";
        let stderr = "";
        proc.stdout.on("data", (chunk) => {
            stdout += chunk.toString();
        });
        proc.stderr.on("data", (chunk) => {
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
function stripAnsi(str) {
    // eslint-disable-next-line no-control-regex
    return str.replace(/\x1B\[[0-9;]*[mGKHF]/g, "").replace(/\x1B\[[0-9]*[A-Z]/g, "");
}
function assertOk(result, context) {
    if (result.exitCode !== 0) {
        const msg = stripAnsi(result.stderr || result.stdout).trim();
        throw new Error(`agora ${context} failed (exit ${result.exitCode}): ${msg}`);
    }
    return stripAnsi(result.stdout);
}
//# sourceMappingURL=runner.js.map