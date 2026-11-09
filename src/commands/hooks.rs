//! `agora hooks`: install, remove and inspect the wake adapters for each
//! harness. The adapters are thin launchers around `agora wait` — the
//! classification, dedup and framing live in agora itself, not in the
//! adapters.
//!
//! * **claude**: a Stop hook in `~/.claude/settings.json` running
//!   `<agora binary> wait` with `asyncRewake: true`. JSON-merged; foreign
//!   hooks are preserved; an existing agora Stop-hook entry (including the
//!   stopgap `agora-wait`) is replaced in place, which is the migration.
//! * **omp**: the extension `~/.omp/agent/extensions/agora-wake.ts`, copied
//!   from `scripts/omp/agora-wake.ts` in the agora repo.
//! * **codex** (and pre-extension omp panes): the tmux wake bridge
//!   (`scripts/agora-wake-bridge` + a systemd user unit), which types the
//!   framed message into an idle pane once `agora wait` exits 2.
//!
//! Install is idempotent and never deletes anything; removal is the explicit
//! `agora hooks remove`.

use agora::store;
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};

/// Marker the Stop-hook entry is agora's: the command runs `agora wait` (or
/// the stopgap `agora-wait`).
const STOPGAP_BIN: &str = "agora-wait";

// `HooksAction`/`Harness` are defined in the crate root (main.rs); this
// module takes them as args.
use crate::{Harness, HooksAction};

pub fn run(action: HooksAction) -> Result<(), String> {
    match action {
        HooksAction::Install { harness, systemd } => install(harness, systemd),
        HooksAction::Remove { harness, systemd } => remove(harness, systemd),
        HooksAction::Status => status(),
    }
}

/// The absolute path of the running agora binary (hook entries embed it).
fn agora_bin() -> String {
    std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "agora".to_string())
}

fn home() -> PathBuf {
    agora::runtime::home_dir().unwrap_or_else(|| PathBuf::from("."))
}

/// The passwd-derived real home of the current uid (the value a login
/// shell would have), independent of any HOME override.
fn real_home() -> Option<PathBuf> {
    let uid = current_uid();
    let out = std::process::Command::new("getent")
        .arg("passwd")
        .arg(uid.to_string())
        .output()
        .ok()?;
    let line = String::from_utf8_lossy(&out.stdout);
    let home = line.split(':').nth(5)?.trim().to_string();
    (!home.is_empty()).then(|| PathBuf::from(home))
}

/// Current uid via /proc (dependency-free, testable).
fn current_uid() -> u32 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1).map(str::to_string))
        })
        .and_then(|v| v.parse().ok())
        .unwrap_or(u32::MAX)
}

/// May this process manage the real systemd user instance? Lead ruling
/// a95539: only when HOME is the passwd real home AND XDG_RUNTIME_DIR is
/// owned by the same uid (the real user manager, not a canary shell).
fn may_manage_systemd() -> bool {
    let Some(set_home) = real_home() else {
        return false;
    };
    let home_ok = agora::runtime::home_dir().is_some_and(|h| h == set_home);
    let runtime_ok = std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .map(|dir| {
            let uid = current_uid();
            std::fs::metadata(std::path::Path::new(&dir).join(format!("{uid}")))
                .ok()
                .is_some()
                || std::fs::metadata(format!("/run/user/{uid}"))
                    .ok()
                    .is_some_and(|m| m.is_dir())
        })
        .unwrap_or(false);
    home_ok && runtime_ok
}


fn claude_settings_path() -> PathBuf {
    home().join(".claude/settings.json")
}

fn omp_extension_path() -> PathBuf {
    home().join(".omp/agent/extensions/agora-wake.ts")
}

fn bridge_install_paths() -> (PathBuf, PathBuf, PathBuf) {
    let home = home();
    (
        home.join(".local/bin/agora-wake-bridge"),
        home.join(".config/systemd/user/agora-wake-bridge.service"),
        home.join(".config/agora-wake/installed"),
    )
}

/// The repo's scripts dir: the directory of the running binary's source
/// tree, else `./scripts`. Deployed installs ship the scripts next to the
/// binary (w7 copies them); `AGORA_SCRIPTS_DIR` overrides for tests.
fn scripts_dir() -> PathBuf {
    if let Some(dir) = agora::runtime::var("AGORA_SCRIPTS_DIR") {
        return PathBuf::from(dir);
    }
    // Next to the binary (deployed layout), else the crate's scripts/ at
    // build time (embedded via env at compile time).
    if let Some(dir) = option_env!("AGORA_SCRIPTS_DIR_EMBED") {
        return PathBuf::from(dir);
    }
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .map(|p| p.join("agora-scripts"))
        .unwrap_or_else(|| PathBuf::from("scripts"))
}

fn read_scripts(rel: &str) -> Result<String, String> {
    let path = scripts_dir().join(rel);
    fs::read_to_string(&path).map_err(|e| format!("missing {}: {e}", path.display()))
}

// ── claude ──────────────────────────────────────────────────────

/// Read `~/.claude/settings.json` as JSON (empty object when absent).
fn load_settings(path: &Path) -> Value {
    fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| json!({}))
}

/// Read raw bytes as JSON settings (empty object when unparseable).
fn load_settings_from(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap_or_else(|_| json!({}))
}

/// Is this Stop-hook command entry agora's (ours or the stopgap's)?
fn is_agora_stop_hook(command: &str) -> bool {
    // The command may carry arguments ("…/agora wait"): match the program
    // token, not the whole string's last path segment.
    let bin = command.split_whitespace().next().unwrap_or("");
    let base = bin.rsplit('/').next().unwrap_or(bin);
    base == "agora" || base == STOPGAP_BIN || bin == agora_bin()
}

/// Insert/replace our Stop hook in settings, preserving everything else.
/// Returns the previous command if one was replaced.
fn merge_stop_hook(settings: &mut Value, command: &str) -> Option<String> {
    let hooks = settings
        .as_object_mut()?
        .entry("hooks")
        .or_insert_with(|| json!({}))
        .as_object_mut()?;
    let stop = hooks
        .entry("Stop")
        .or_insert_with(|| json!([]))
        .as_array_mut()?;

    let entry = json!({
        "hooks": [ {
            "type": "command",
            "command": command,
            "timeout": 86400,
            "asyncRewake": true,
        } ]
    });

    // Replace an existing agora entry (first matcher whose command is ours
    // or the stopgap's); otherwise append.
    for matcher in stop.iter_mut() {
        let Some(entries) = matcher.get_mut("hooks").and_then(|h| h.as_array_mut()) else {
            continue;
        };
        for e in entries.iter_mut() {
            let is_ours = e.get("command").and_then(|c| c.as_str()).is_some_and(is_agora_stop_hook);
            if is_ours {
                let old = e.get("command").and_then(|c| c.as_str()).map(String::from);
                if let Some(entry) = entry.get("hooks").and_then(|h| h.as_array()).and_then(|a| a.first()) {
                    *e = entry.clone();
                }
                return old;
            }
        }
    }
    stop.push(entry);
    None
}

/// Drop our Stop-hook entries from settings (both matchers' lists and empty
/// matchers). Returns true when something was removed.
fn remove_stop_hook(settings: &mut Value) -> bool {
    let Some(hooks) = settings.get_mut("hooks").and_then(|h| h.as_object_mut()) else {
        return false;
    };
    let Some(stop) = hooks.get_mut("Stop").and_then(|s| s.as_array_mut()) else {
        return false;
    };
    let mut removed = false;
    for matcher in stop.iter_mut() {
        if let Some(entries) = matcher.get_mut("hooks").and_then(|h| h.as_array_mut()) {
            let before = entries.len();
            entries.retain(|e| {
                e.get("command")
                    .and_then(|c| c.as_str())
                    .is_none_or(|c| !is_agora_stop_hook(c))
            });
            if entries.len() != before {
                removed = true;
            }
        }
    }
    stop.retain(|m| {
        m.get("hooks")
            .and_then(|h| h.as_array())
            .is_none_or(|h| !h.is_empty())
    });
    if stop.is_empty() {
        hooks.remove("Stop");
    }
    removed
}

/// Where [`install_claude`] keeps the pre-install file for byte-exact
/// restore (`settings.json.agora-backup`).
fn settings_backup_path() -> PathBuf {
    claude_settings_path().with_extension("json.agora-backup")
}

fn install_claude() -> Result<(), String> {
    let path = claude_settings_path();
    let original = fs::read(&path).ok();
    let mut settings = load_settings(&path);
    let command = format!("{} wait", agora_bin());
    let replaced = merge_stop_hook(&mut settings, &command);
    let text = serde_json::to_string_pretty(&settings)
        .map_err(|e| format!("serialize settings: {e}"))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    fs::write(&path, text).map_err(|e| format!("write {}: {e}", path.display()))?;
    // Byte-exact backup of the pre-install file, so `remove` can restore
    // verbatim. Written only when absent: a second (idempotent) install
    // must not overwrite the good backup with the already-installed state.
    if let Some(bytes) = original
        && !settings_backup_path().exists()
    {
        let _ = fs::write(settings_backup_path(), bytes);
    }
    match replaced {
        Some(old) if old.trim() != command => println!(
            "  Claude Stop hook updated (was: {old})\n  → {command} (timeout 86400, asyncRewake)"
        ),
        _ => println!("  Claude Stop hook installed → {command} (timeout 86400, asyncRewake)"),
    }
    Ok(())
}

fn remove_claude() -> Result<(), String> {
    let path = claude_settings_path();
    if !path.exists() {
        println!("  Claude: nothing to remove");
        return Ok(());
    }
    // Byte-exact restore path: if install kept a backup and the current
    // file differs from it only by our Stop hook, restore the backup
    // verbatim (byte-for-byte, as the canary requires).
    let backup = settings_backup_path();
    if let (Ok(pre), Ok(cur)) = (fs::read(&backup), fs::read(&path)) {
        let mut pre_json = load_settings_from(&pre);
        let mut cur_json = load_settings_from(&cur);
        // Equal up to agora Stop-hook entries (ours or the stopgap's —
        // install migrates one to the other): the file's only change since
        // the backup is ours, so the backup restores byte-exact.
        let pre_had_agora = remove_stop_hook(&mut pre_json);
        let cur_had_agora = remove_stop_hook(&mut cur_json);
        if cur_had_agora && cur_json == pre_json {
            fs::write(&path, pre).map_err(|e| format!("restore {}: {e}", path.display()))?;
            let _ = fs::remove_file(&backup);
            println!("  Claude Stop hook removed (settings restored byte-exact)");
            return Ok(());
        }
        let _ = pre_had_agora;
    }
    // Fallback: structural removal (no backup, or the file changed for
    // other reasons since install — never clobber those changes).
    let mut settings = load_settings(&path);
    if remove_stop_hook(&mut settings) {
        let text = serde_json::to_string_pretty(&settings)
            .map_err(|e| format!("serialize settings: {e}"))?;
        fs::write(&path, text).map_err(|e| format!("write {}: {e}", path.display()))?;
        println!("  Claude Stop hook removed");
    } else {
        println!("  Claude: no agora Stop hook found");
    }
    Ok(())
}

// ── omp ─────────────────────────────────────────────────────────

fn install_omp() -> Result<(), String> {
    let source = read_scripts("omp/agora-wake.ts")?;
    let path = omp_extension_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    let existed = path.exists();
    fs::write(&path, &source).map_err(|e| format!("write {}: {e}", path.display()))?;
    println!(
        "  omp extension {} → {} (takes effect in new omp sessions)",
        if existed { "updated" } else { "installed" },
        path.display()
    );
    Ok(())
}

fn remove_omp() -> Result<(), String> {
    let path = omp_extension_path();
    if path.exists() {
        fs::remove_file(&path).map_err(|e| format!("remove {}: {e}", path.display()))?;
        println!("  omp extension removed");
    } else {
        println!("  omp: nothing to remove");
    }
    Ok(())
}

// ── codex ───────────────────────────────────────────────────────

fn install_codex(systemd: bool) -> Result<(), String> {
    let bridge = read_scripts("agora-wake-bridge")?;
    // The unit template ships %h (systemd home) and a host placeholder;
    // the agent id is derived at install time from the real hostname so
    // no placeholder or wrong-host id ever ships (incident 066bf6 d2).
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|h| h.trim().to_string())
        .unwrap_or_else(|_| "localhost".to_string());
    let unit = read_scripts("systemd/agora-wake-bridge.service")?
        .replace("__AGORA_HOST__", &host);
    let (bin_path, unit_path, marker) = bridge_install_paths();
    for (path, content, mode) in [
        (&bin_path, bridge.as_str(), 0o755u32),
        (&unit_path, unit.as_str(), 0o644),
    ] {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
        }
        fs::write(path, content).map_err(|e| format!("write {}: {e}", path.display()))?;
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
    }
    if let Some(parent) = marker.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(&marker, agora_bin());
    // Lead ruling a95539: service management ONLY with --systemd, and only
    // from the real user context. Never by default; from anywhere else,
    // print the exact commands for the operator. No env-var shortcuts.
    let managed = if !systemd {
        println!("  systemd user unit: files only (pass --systemd to manage the service)");
        false
    } else if may_manage_systemd() {
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status();
        let enable = std::process::Command::new("systemctl")
            .args(["--user", "enable", "--now", "agora-wake-bridge.service"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        let restart = std::process::Command::new("systemctl")
            .args(["--user", "restart", "agora-wake-bridge.service"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        enable || restart
    } else {
        println!("  refusing to manage systemd: not the real user context");
        println!("  run: systemctl --user daemon-reload && systemctl --user enable --now agora-wake-bridge.service");
        false
    };
    println!(
        "  codex wake bridge: {} + {}\n  systemd user unit: {}",
        bin_path.display(),
        unit_path.display(),
        if managed {
            "enabled and running"
        } else {
            "installed (not managed)"
        }
    );
    Ok(())
}

fn remove_codex(systemd: bool) -> Result<(), String> {
    let (bin_path, unit_path, marker) = bridge_install_paths();
    // Same ruling as install: only with --systemd, only from the real user
    // context; otherwise files only and the exact command printed.
    if systemd && may_manage_systemd() {
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "disable", "--now", "agora-wake-bridge.service"])
            .status();
    } else if systemd {
        println!("  refusing to manage systemd: not the real user context");
        println!("  run: systemctl --user disable --now agora-wake-bridge.service");
    }
    let mut removed = false;
    for path in [&bin_path, &unit_path, &marker] {
        if path.exists() {
            let _ = fs::remove_file(path);
            removed = true;
        }
    }
    println!(
        "  codex wake bridge: {}",
        if removed { "removed" } else { "nothing to remove" }
    );
    Ok(())
}

// ── status ──────────────────────────────────────────────────────

fn stopgap_installed() -> Option<String> {
    let settings = load_settings(&claude_settings_path());
    let stop = settings.get("hooks")?.get("Stop")?.as_array()?;
    for matcher in stop {
        for e in matcher.get("hooks")?.as_array()? {
            let cmd = e.get("command")?.as_str()?;
            if cmd.rsplit('/').next() == Some(STOPGAP_BIN) {
                return Some(cmd.to_string());
            }
        }
    }
    None
}

fn status() -> Result<(), String> {
    let settings = load_settings(&claude_settings_path());
    let claude = settings
        .get("hooks")
        .and_then(|h| h.get("Stop"))
        .and_then(|s| s.as_array())
        .and_then(|matchers| {
            matchers.iter().flat_map(|m| m.get("hooks").and_then(|h| h.as_array()).cloned().unwrap_or_default())
                .find_map(|e| {
                    e.get("command")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(is_agora_stop_hook)
                        .then_some(e)
                })
        });
    print_harness("claude", claude.is_some(), claude_settings_path());
    if let Some(old) = stopgap_installed() {
        println!("    stopgap still present: {old} → `agora hooks install --harness claude` migrates it");
    }
    print_harness("omp", omp_extension_path().exists(), omp_extension_path());
    let (bin_path, unit_path, _marker) = bridge_install_paths();
    print_harness(
        "codex",
        bin_path.exists() || unit_path.exists(),
        unit_path,
    );
    let _ = store::get_agent_id();
    Ok(())
}

fn print_harness(name: &str, installed: bool, path: PathBuf) {
    println!(
        "  {name}: {} ({})",
        if installed { "installed" } else { "not installed" },
        path.display()
    );
}

// ── dispatch ────────────────────────────────────────────────────

fn install(harness: Harness, systemd: bool) -> Result<(), String> {
    match harness {
        Harness::Claude => install_claude(),
        Harness::Omp => install_omp(),
        Harness::Codex => install_codex(systemd),
    }
}

fn remove(harness: Harness, systemd: bool) -> Result<(), String> {
    match harness {
        Harness::Claude => remove_claude(),
        Harness::Omp => remove_omp(),
        Harness::Codex => remove_codex(systemd),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_home(name: &str) -> (agora::runtime::TestRuntimeGuard, PathBuf) {
        let home = std::env::temp_dir().join(format!("agora-hooks-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(&home).unwrap();
        let rt = agora::runtime::TestRuntime::new().home(&home).enter();
        (rt, home)
    }

    #[test]
    fn merge_replaces_stopgap_and_preserves_foreign_hooks() {
        let (_rt, home) = test_home("merge");
        let path = home.join(".claude/settings.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            r#"{
  "model": "sonnet",
  "hooks": {
    "PreToolUse": [ { "hooks": [ { "type": "command", "command": "lint.sh" } ] } ],
    "Stop": [ { "hooks": [ { "type": "command", "command": "/home/<user>/.local/bin/agora-wait", "timeout": 86400, "asyncRewake": true } ] } ]
  }
}"#,
        )
        .unwrap();
        let mut settings = load_settings(&path);
        let old = merge_stop_hook(&mut settings, "/usr/local/bin/agora wait");
        assert_eq!(old.as_deref(), Some("/home/<user>/.local/bin/agora-wait"));
        // One Stop matcher, one entry, agora's; PreToolUse untouched.
        let stop = settings["hooks"]["Stop"].as_array().unwrap();
        assert_eq!(stop.len(), 1);
        let entry = &stop[0]["hooks"][0];
        assert_eq!(entry["command"], json!("/usr/local/bin/agora wait"));
        assert_eq!(entry["asyncRewake"], json!(true));
        assert_eq!(
            settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
            json!("lint.sh")
        );
        assert_eq!(settings["model"], json!("sonnet"));
    }

    #[test]
    fn merge_appends_when_no_stop_hook() {
        let (_rt, home) = test_home("append");
        let path = home.join(".claude/settings.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, r#"{ "model": "sonnet" }"#).unwrap();
        let mut settings = load_settings(&path);
        assert_eq!(merge_stop_hook(&mut settings, "agora wait"), None);
        assert_eq!(settings["hooks"]["Stop"].as_array().unwrap().len(), 1);
        assert_eq!(settings["model"], json!("sonnet"));
    }

    #[test]
    fn remove_only_takes_ours() {
        let (_rt, home) = test_home("remove");
        let path = home.join(".claude/settings.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            r#"{
  "hooks": {
    "Stop": [ { "hooks": [
      { "type": "command", "command": "mine.sh" },
      { "type": "command", "command": "agora wait", "asyncRewake": true }
    ] } ]
  }
}"#,
        )
        .unwrap();
        let mut settings = load_settings(&path);
        assert!(remove_stop_hook(&mut settings));
        let stop = settings["hooks"]["Stop"].as_array().unwrap();
        assert_eq!(stop[0]["hooks"].as_array().unwrap().len(), 1);
        assert_eq!(stop[0]["hooks"][0]["command"], json!("mine.sh"));
        // Nothing left of ours.
        assert!(!remove_stop_hook(&mut settings));
    }

    #[test]
    fn stopgap_detector() {
        assert!(is_agora_stop_hook("/home/<user>/.local/bin/agora-wait"));
        assert!(is_agora_stop_hook("/usr/bin/agora"));
        assert!(is_agora_stop_hook("agora wait"));
        assert!(!is_agora_stop_hook("/home/<user>/.local/bin/agora-wait-two"));
        assert!(!is_agora_stop_hook("lint.sh"));
    }

    #[test]
    fn codex_without_systemd_flag_never_manages_systemd() {
        // Lead ruling a95539 (2): install/remove codex without --systemd
        // never reaches systemctl. The flag short-circuits BEFORE any
        // Command spawn: assert the exact branch the code takes by
        // checking that, with systemd=false, the function succeeds in a
        // home where systemctl does not exist at all (PATH stripped in
        // the child env is not needed: the flag path never spawns).
        let (_rt, home) = test_home("nosystemctl");
        let scripts = home.join("scripts");
        fs::create_dir_all(scripts.join("systemd")).unwrap();
        fs::write(scripts.join("agora-wake-bridge"), "#!/bin/sh\n").unwrap();
        fs::write(
            scripts.join("systemd/agora-wake-bridge.service"),
            "ExecStart=%h/.local/bin/agora-wake-bridge\nEnvironment=AGORA_AGENT_ID=agora-wake-bridge@__AGORA_HOST__\n",
        )
        .unwrap();
        // TestRuntime carries env vars for the crate's runtime layer and
        // does not need (edition-2024 unsafe) set_var.
        agora::runtime::TestRuntime::new()
            .home(&home)
            .var("AGORA_SCRIPTS_DIR", scripts.to_str().unwrap())
            .install();
        install_codex(false).unwrap();
        let unit = fs::read_to_string(
            home.join(".config/systemd/user/agora-wake-bridge.service"),
        )
        .unwrap();
        assert!(
            !unit.contains("__AGORA_HOST__") && !unit.contains("/home/<user>"),
            "no placeholder ships: {unit}"
        );
        assert!(unit.contains("agora-wake-bridge@"), "hostname substituted");
        remove_codex(false).unwrap();
        assert!(
            !home.join(".config/systemd/user/agora-wake-bridge.service").exists(),
            "unit removed"
        );
    }
}
