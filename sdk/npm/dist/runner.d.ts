export interface RunResult {
    stdout: string;
    stderr: string;
    exitCode: number;
}
/**
 * Resolves the agora binary path.
 * Priority: explicit path → AGORA_BIN env → local ./target/release/agora → 'agora' on PATH
 */
export declare function resolveBinaryPath(explicit?: string): string;
export declare function buildEnv(home?: string, agentId?: string): NodeJS.ProcessEnv;
/**
 * Run agora synchronously and return stdout/stderr/exitCode.
 */
export declare function runSync(binary: string, args: string[], env: NodeJS.ProcessEnv): RunResult;
/**
 * Run agora asynchronously and return a promise of RunResult.
 */
export declare function run(binary: string, args: string[], env: NodeJS.ProcessEnv): Promise<RunResult>;
/**
 * Strip ANSI escape codes from terminal output.
 */
export declare function stripAnsi(str: string): string;
export declare function assertOk(result: RunResult, context: string): string;
//# sourceMappingURL=runner.d.ts.map