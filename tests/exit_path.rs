//! The process exit path: the binary must leave cleanly even when its stderr is a pipe whose reader is gone.
//!
//! Regression for the M1 release abort: the slow-span line written at exit used `eprintln!`, which panics on a
//! broken pipe, and a panic inside the `atexit` handler aborted every long-running command (`agora watch`
//! under `agora-wait`'s `timeout`) with SIGABRT. `cargo test` never exited a real binary, so nothing saw it.
//!
//! The command used is `agora mcp`: a stdio server that runs until its stdin is closed and needs no relay to
//! start, so the test controls how long the command's span lasts.

use std::io::Read;
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn temp_home(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("agora-exit-path-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `agora mcp` in a scrubbed environment; every span of 100 ms or more is logged at exit.
fn spawn_mcp(home: &std::path::Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_agora"))
        .arg("mcp")
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("AGORA_AGENT_ID", "exit-path-test")
        .env("AGORA_RELAY_URL", "memory://exit-path-test")
        .env("AGORA_SLOW_SPAN_MS", "100")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn agora mcp")
}

fn wait(child: &mut Child) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(Instant::now() < deadline, "agora did not exit");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Control for the test below: under the same conditions the exit handler really does write a slow-span
/// line to stderr, so the broken-pipe test cannot pass just because nothing was written.
#[test]
fn the_exit_handler_writes_a_slow_span_line_for_a_long_command() {
    let home = temp_home("control");
    let mut child = spawn_mcp(&home);
    std::thread::sleep(Duration::from_millis(600));
    drop(child.stdin.take()); // EOF: the server ends
    let mut stderr = String::new();
    child.stderr.take().unwrap().read_to_string(&mut stderr).unwrap();
    let status = wait(&mut child);
    assert!(status.success(), "agora mcp failed: {status:?}; stderr: {stderr}");
    assert!(stderr.contains("slow span"), "no slow-span line on stderr: {stderr}");
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn exit_with_a_broken_stderr_pipe_is_clean() {
    let home = temp_home("broken-stderr");
    let mut child = spawn_mcp(&home);
    drop(child.stderr.take()); // the reader goes away: writes to stderr now fail with EPIPE
    std::thread::sleep(Duration::from_millis(600));
    drop(child.stdin.take()); // EOF: the server ends, and its exit handler writes the slow-span line
    let status = wait(&mut child);
    assert_eq!(status.signal(), None, "agora was killed by a signal (6 = SIGABRT): {status:?}");
    assert!(status.success(), "agora mcp failed: {status:?}");
    let _ = std::fs::remove_dir_all(&home);
}
