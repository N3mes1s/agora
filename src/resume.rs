//! Session resume. A task checkpoint made from inside an agent harness records which harness ran the task
//! (claude, omp, codex), its session id, its working directory and its tmux pane, so an agent whose pane
//! or process died can be brought back exactly where it was, with its last checkpoint as the first message:
//! `agora task-resume <id>` prints the line, `--exec` runs it in that pane.
//!
//! `--exec` never types into a pane, and touches nothing but the recorded pane, found by its pane id on
//! the same tmux server (pane ids are unique per server; window indexes get reused; the server is named by
//! pid and start time): a pane left with only a shell is restarted (`respawn-pane -k`, inside one tmux
//! command that re-checks it still runs only a shell), a closed pane is replaced by a new window in the same
//! session (and the session record moves to it), and a pane running anything else, or a different tmux
//! server, is refused.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;

/// Harnesses and the variables each one gives the tools it runs, holding its session id (first wins).
const SESSION_VARS: &[(&str, &str)] = &[
    ("claude", "CLAUDE_CODE_SESSION_ID"),
    ("omp", "PI_SESSION_ID"),
    ("codex", "CODEX_THREAD_ID"),
    ("codex", "CODEX_SESSION_ID"),
    ("codex", "CODEX_CLI_SESSION_ID"),
];
/// A pane running one of these holds nothing a respawn could lose.
const SHELLS: &[&str] = &["bash", "zsh", "sh", "fish", "dash", "ksh"];

/// Where a task's agent ran, as recorded at its last checkpoint.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Session {
    pub harness: String,
    pub session_id: String,
    pub cwd: String,
    /// tmux server socket and pid, the agent's pane id (`%12`) and `session:window`, when it ran in tmux.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tmux_socket: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tmux_server_pid: Option<u32>,
    /// The server's start time (clock ticks since boot): a new server that got the same pid is another one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tmux_server_start: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tmux_pane: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tmux_window: Option<String>,
    pub agent_id: String,
    pub recorded_at: u64,
}

/// The harness and session id from the environment a harness gives its tools.
pub fn from_env(env: &HashMap<String, String>) -> Option<(&'static str, String)> {
    SESSION_VARS
        .iter()
        .find_map(|(h, var)| env.get(*var).map(|v| v.trim()).filter(|v| !v.is_empty()).map(|v| (*h, v.to_string())))
}

fn stat_field(pid: u32, n: usize) -> Option<String> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    s.rsplit_once(')')?.1.split_whitespace().nth(n).map(str::to_string)
}

fn stat_ppid(pid: u32) -> Option<u32> {
    stat_field(pid, 1)?.parse().ok()
}

/// Start time of a process (clock ticks since boot): with its pid, it names one process.
fn proc_start(pid: u32) -> Option<u64> {
    stat_field(pid, 19)?.parse().ok()
}

/// The nearest ancestor process named `harness`, if this process runs under it.
fn harness_ancestor(harness: &str) -> Option<u32> {
    let mut pid = std::process::id();
    for _ in 0..64 {
        pid = stat_ppid(pid).filter(|p| *p > 1)?;
        if std::fs::read_to_string(format!("/proc/{pid}/comm")).is_ok_and(|c| c.trim() == harness) {
            return Some(pid);
        }
    }
    None
}

/// The tmux pane of `env`: `(socket, server pid, pane id, "session:window")`.
fn tmux_pane(env: &HashMap<String, String>) -> Option<(String, u32, String, String)> {
    let mut parts = env.get("TMUX")?.split(',');
    let socket = parts.next()?.to_string();
    let server: u32 = parts.next()?.parse().ok()?;
    let pane = env.get("TMUX_PANE")?.clone();
    let out = Command::new("tmux").args(["-S", &socket, "display", "-p", "-t", &pane, "#{session_name}:#{window_index}"]).output().ok()?;
    let w = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (out.status.success() && w.len() > 1 && w.contains(':')).then_some((socket, server, pane, w))
}

/// The session of the harness this process runs under, or None outside a known harness.
pub fn detect(agent_id: &str, now: u64) -> Option<Session> {
    let env: HashMap<String, String> = std::env::vars().collect();
    let (harness, session_id) = from_env(&env)?;
    let cwd = harness_ancestor(harness)
        .and_then(|pid| std::fs::read_link(format!("/proc/{pid}/cwd")).ok())
        .or_else(|| std::env::current_dir().ok())?
        .to_string_lossy()
        .into_owned();
    let tmux = tmux_pane(&env);
    Some(Session {
        harness: harness.into(),
        session_id,
        cwd,
        tmux_socket: tmux.as_ref().map(|t| t.0.clone()),
        tmux_server_pid: tmux.as_ref().map(|t| t.1),
        tmux_server_start: tmux.as_ref().and_then(|t| proc_start(t.1)),
        tmux_pane: tmux.as_ref().map(|t| t.2.clone()),
        tmux_window: tmux.map(|t| t.3),
        agent_id: agent_id.into(),
        recorded_at: now,
    })
}

/// The first message of the resumed session: what it was doing and where it left off.
pub fn context(task_id: &str, title: &str, room: &str, notes: Option<&str>, checkpoint_age_s: u64) -> String {
    let last = notes.map_or("none recorded".to_string(), |n| format!("\"{n}\""));
    format!(
        "Your previous process ended while you held agora task [{}] in room {room}: {title}. Your last checkpoint \
         ({} min ago): {last}. Continue from there, and keep checkpointing (agora task-checkpoint {} --notes ...).",
        &task_id[..task_id.len().min(6)],
        checkpoint_age_s / 60,
        &task_id[..task_id.len().min(6)]
    )
}

/// The command that resumes `s` with `prompt` as its first message, as argv.
pub fn command(s: &Session, prompt: &str) -> Vec<String> {
    let mut argv = vec!["env".to_string(), format!("AGORA_AGENT_ID={}", s.agent_id), s.harness.clone()];
    match s.harness.as_str() {
        "codex" => argv.extend(["resume".to_string(), s.session_id.clone()]),
        _ => argv.extend(["--resume".to_string(), s.session_id.clone()]),
    }
    argv.push(prompt.to_string());
    argv
}

/// POSIX shell quoting: words made only of safe characters stay bare, everything else is single-quoted.
pub fn quote(word: &str) -> String {
    let safe = |c: char| c.is_ascii_alphanumeric() || "-_./:=@%+,".contains(c);
    if !word.is_empty() && word.chars().all(safe) {
        word.to_string()
    } else {
        format!("'{}'", word.replace('\'', r"'\''"))
    }
}

pub fn shell_line(argv: &[String]) -> String {
    argv.iter().map(|w| quote(w)).collect::<Vec<_>>().join(" ")
}

/// How `--exec` gets the line into the agent's pane.
#[derive(Debug, PartialEq)]
pub enum Placement {
    /// The pane only runs a shell: restart that pane (and only it) with the line.
    Respawn,
    /// The pane is gone: open a new window in its session.
    NewWindow,
}

/// Decide from the pane's current command (None: no such pane). Anything but a shell is left alone.
pub fn placement(current_command: Option<&str>) -> Result<Placement, String> {
    match current_command {
        None => Ok(Placement::NewWindow),
        Some(c) if SHELLS.contains(&c) => Ok(Placement::Respawn),
        Some(c) => Err(format!("the pane still runs '{c}': not replacing it (is the agent alive?)")),
    }
}

fn tmux(socket: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new("tmux").arg("-S").arg(socket).args(args).output().map_err(|e| format!("tmux: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

/// The current command of pane `pane` (`%12`) on the server, or None when no such pane exists.
fn pane_command(socket: &str, pane: &str) -> Option<String> {
    tmux(socket, &["list-panes", "-a", "-F", "#{pane_id}\t#{pane_current_command}"])
        .ok()?
        .lines()
        .find_map(|l| l.split_once('\t').filter(|(p, _)| *p == pane).map(|(_, c)| c.to_string()))
}

/// A tmux format that is true when the target pane runs only a shell.
fn runs_a_shell() -> String {
    SHELLS.iter().rev().fold(String::new(), |rest, sh| {
        let this = format!("#{{==:#{{pane_current_command}},{sh}}}");
        if rest.is_empty() { this } else { format!("#{{||:{this},{rest}}}") }
    })
}

/// A word for tmux's command parser: double-quoted, with what tmux would expand inside escaped.
fn tmux_word(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"").replace('$', "\\$"))
}

/// Run `line` (a shell command) in the session's tmux pane, in its working directory. The caller holds
/// the task's resume lock and lease and persists `s` afterwards: a pane opened for a closed one becomes
/// the session's pane.
pub fn exec(s: &mut Session, line: &str) -> Result<String, String> {
    let span = tracing::info_span!("task.resume_exec", harness = %s.harness, placement = tracing::field::Empty);
    let _in = span.enter();
    let (Some(socket), Some(server), Some(pane), Some(window)) =
        (s.tmux_socket.clone(), s.tmux_server_pid, s.tmux_pane.clone(), s.tmux_window.clone())
    else {
        return Err("no tmux pane recorded for this session: run the printed line yourself".into());
    };
    // Pane ids are only unique within one server: a socket taken over by a newer server (even one that got
    // the same pid) means different panes behind the same ids.
    let live = tmux(&socket, &["display", "-p", "#{pid}"]).ok().and_then(|p| p.parse::<u32>().ok());
    let same_server = live == Some(server) && s.tmux_server_start.is_none_or(|st| proc_start(server) == Some(st));
    if !same_server {
        return Err(format!("the tmux server of pane {pane} (pid {server}) is gone: run the printed line yourself"));
    }
    let how = placement(pane_command(&socket, &pane).as_deref())?;
    span.record("placement", format!("{how:?}").as_str());
    match how {
        Placement::Respawn => {
            // Checked again inside tmux, in the same command: whatever was typed into that shell since the
            // check above is never killed.
            let respawn = format!("respawn-pane -k -t {pane} -c {} {}", tmux_word(&s.cwd), tmux_word(line));
            let out = tmux(&socket, &["if-shell", "-F", "-t", &pane, &runs_a_shell(), &respawn, "display -p not-a-shell"])?;
            if out.contains("not-a-shell") {
                return Err(format!("pane {pane} started running something else: not replacing it"));
            }
            Ok(format!("restarted in tmux pane {pane} ({window})"))
        }
        Placement::NewWindow => {
            let session = window.rsplit_once(':').map_or(window.as_str(), |(s, _)| s).to_string();
            let out = tmux(&socket, &["new-window", "-d", "-P", "-F", "#{pane_id} #{session_name}:#{window_index}", "-t",
                &format!("{session}:"), "-c", &s.cwd, line])?;
            if let Some((new_pane, new_window)) = out.trim().split_once(' ') {
                s.tmux_pane = Some(new_pane.to_string());
                s.tmux_window = Some(new_window.to_string());
            }
            Ok(format!("pane {pane} is gone: opened a new window in tmux session {session}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn session(harness: &str) -> Session {
        Session { harness: harness.into(), session_id: "d1c91049-7f72".into(), cwd: "/home/user/code/project".into(),
            tmux_window: Some("main:7".into()), agent_id: "host-a-main-w7".into(), recorded_at: 1, ..Default::default() }
    }

    #[test]
    fn the_harness_and_its_session_come_from_the_tool_environment() {
        assert_eq!(from_env(&env(&[("CLAUDE_CODE_SESSION_ID", "c-1"), ("CLAUDECODE", "1")])), Some(("claude", "c-1".into())));
        assert_eq!(from_env(&env(&[("PI_SESSION_ID", "o-1")])), Some(("omp", "o-1".into())));
        assert_eq!(from_env(&env(&[("CODEX_SESSION_ID", "x-1")])), Some(("codex", "x-1".into())));
        assert_eq!(from_env(&env(&[("CODEX_SESSION_ID", "x-1"), ("CODEX_THREAD_ID", "t-1")])), Some(("codex", "t-1".into())), "codex's thread id first");
        assert_eq!(from_env(&env(&[("CODEX_SESSION_ID", " ")])), None);
        assert_eq!(from_env(&env(&[("HOME", "/h")])), None);
    }

    #[test]
    fn each_harness_gets_its_own_resume_line() {
        let p = "Your previous process ended; it's task [abc]";
        assert_eq!(shell_line(&command(&session("claude"), p)),
            r#"env AGORA_AGENT_ID=host-a-main-w7 claude --resume d1c91049-7f72 'Your previous process ended; it'\''s task [abc]'"#);
        assert_eq!(shell_line(&command(&session("omp"), "go")), "env AGORA_AGENT_ID=host-a-main-w7 omp --resume d1c91049-7f72 go");
        assert_eq!(shell_line(&command(&session("codex"), "go")), "env AGORA_AGENT_ID=host-a-main-w7 codex resume d1c91049-7f72 go");
        assert_eq!(quote(""), "''");
    }

    #[test]
    fn the_context_carries_the_task_and_its_last_checkpoint() {
        let c = context("53bdfaee69", "session resume", "ops", Some("tests queued"), 1860);
        assert!(c.contains("[53bdfa]") && c.contains("room ops: session resume") && c.contains("(31 min ago): \"tests queued\""), "{c}");
        assert!(context("53bdfa", "t", "ops", None, 0).contains("none recorded"));
    }

    #[test]
    fn exec_restarts_only_a_shell_and_reopens_a_closed_pane() {
        assert_eq!(placement(Some("zsh")), Ok(Placement::Respawn));
        assert_eq!(placement(None), Ok(Placement::NewWindow));
        assert!(placement(Some("claude")).is_err());
        assert!(placement(Some("node")).is_err(), "a live agent's process or a dev server is never replaced");
    }

    /// A private tmux server: the recorded pane, left with a shell, is restarted while the other pane of
    /// its window keeps running; a closed pane gets a new window; a pane running something else, or a
    /// different server behind the socket, is refused.
    #[test]
    fn exec_in_a_real_tmux_server() {
        if Command::new("tmux").arg("-V").output().is_err() {
            return;
        }
        let dir = std::env::temp_dir().join(format!("agora-resume-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("tmux.sock").to_string_lossy().into_owned();
        let t = |args: &[&str]| tmux(&sock, args);
        t(&["-f", "/dev/null", "new-session", "-d", "-s", "s", "-n", "agent", "sh"]).unwrap();
        t(&["split-window", "-d", "-t", "s:0", "exec sleep 300"]).unwrap(); // the operator's build next to it
        t(&["new-window", "-d", "-t", "s:3", "exec sleep 300"]).unwrap();
        let pane = |target: &str| t(&["display", "-p", "-t", target, "#{pane_id}"]).unwrap();
        let (agent, beside, busy) = (pane("s:0.0"), pane("s:0.1"), pane("s:3.0"));
        // a fresh pane briefly shows tmux's own forked child before its command execs
        let runs = |p: &str, c: &str| (0..100).any(|_| {
            std::thread::sleep(std::time::Duration::from_millis(20));
            pane_command(&sock, p).is_some_and(|x| x == c)
        });
        assert!(runs(&agent, "sh") && runs(&beside, "sleep") && runs(&busy, "sleep"));
        let mut s = session("claude");
        s.tmux_socket = Some(sock.clone());
        s.tmux_server_pid = t(&["display", "-p", "#{pid}"]).unwrap().parse().ok();
        s.tmux_server_start = s.tmux_server_pid.and_then(proc_start);
        s.tmux_window = Some("s:0".into());
        s.cwd = dir.to_string_lossy().into_owned();
        let wait_for = |f: &str| (0..100).any(|_| { std::thread::sleep(std::time::Duration::from_millis(50)); dir.join(f).exists() });

        s.tmux_pane = Some(agent.clone());
        assert_eq!(exec(&mut s, "touch respawned; exec sleep 60").unwrap(), format!("restarted in tmux pane {agent} (s:0)"));
        assert!(wait_for("respawned"), "ran in the recorded pane, in the recorded cwd");
        assert!(runs(&beside, "sleep"), "the other pane of the window keeps running");

        t(&["kill-pane", "-t", &agent]).unwrap();
        assert_eq!(exec(&mut s, "touch reopened; exec sleep 60").unwrap(), format!("pane {agent} is gone: opened a new window in tmux session s"));
        assert!(wait_for("reopened"));
        assert!(runs(&beside, "sleep"));
        let reopened = s.tmux_pane.clone().unwrap();
        assert_ne!(reopened, agent, "the session now points at the new pane");
        assert!(runs(&reopened, "sleep"));
        assert!(exec(&mut s, "touch twice").unwrap_err().contains("still runs 'sleep'"), "a second resume finds the reopened agent, not a missing pane");

        s.tmux_pane = Some(busy.clone());
        assert!(exec(&mut s, "touch never").unwrap_err().contains("still runs 'sleep'"));
        let start = s.tmux_server_start;
        s.tmux_pane = Some(agent.clone());
        s.tmux_server_start = start.map(|st| st + 1);
        assert!(exec(&mut s, "touch never").unwrap_err().contains("is gone"), "a server that only shares the pid is refused");
        s.tmux_server_start = start;
        s.tmux_server_pid = s.tmux_server_pid.map(|p| p + 1);
        assert!(exec(&mut s, "touch never").unwrap_err().contains("is gone"), "another server behind the socket is refused");
        s.tmux_socket = None;
        assert!(exec(&mut s, "true").is_err());
        assert!(!dir.join("never").exists());
        let _ = t(&["kill-server"]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
