//! Coordination primitives end-to-end over the in-memory relay: leases
//! contended by two signed identities, propose/hold, and plugins.

use agora::lease::{self, Acquire, LeaseError};
use agora::{chat, runtime, store};
use serde_json::json;
use std::path::PathBuf;

fn temp_home(tag: &str) -> PathBuf {
    let home = std::env::temp_dir().join(format!(
        "agora-coord-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&home).unwrap();
    home
}

/// Enter a runtime as `agent` at fake time `now`. All agents share one HOME
/// (like tmux windows on one host), so they share the in-memory relay.
fn as_agent(home: &PathBuf, agent: &str, now: u64) -> runtime::TestRuntimeGuard {
    runtime::TestRuntime::new()
        .home(home)
        .var("AGORA_CONFIG", "/nonexistent/agora-test-config.toml")
        .var("AGORA_RELAY_URL", format!("memory://{}", home.display()))
        .unset_var("AGORA_IDENTITY_SEED")
        .var("AGORA_AGENT_ID", agent)
        .now(now)
        .advance_sleep()
        .enter()
}

fn setup_room(home: &PathBuf) {
    let _rt = as_agent(home, "agent-a", 900);
    chat::create_silent("ops").unwrap();
}

#[test]
fn lease_contention_between_two_identities() {
    let home = temp_home("lease");
    setup_room(&home);

    {
        let _rt = as_agent(&home, "agent-a", 1000);
        match lease::acquire("docker", 600, Some("cargo build"), 3, Some("ops")).unwrap() {
            Acquire::Acquired(l) => {
                assert_eq!(l.holder, "agent-a");
                assert_eq!(l.reason.as_deref(), Some("cargo build"));
            }
            other => panic!("expected acquired, got {other:?}"),
        }
    }
    {
        let _rt = as_agent(&home, "agent-b", 1010);
        match lease::acquire("docker", 600, None, 3, Some("ops")).unwrap() {
            Acquire::Held(l) => assert_eq!(l.holder, "agent-a"),
            other => panic!("agent-b must not get docker: {other:?}"),
        }
        let held = lease::check("docker", Some("ops")).unwrap().unwrap();
        assert_eq!(held.holder, "agent-a");
        assert!(matches!(
            lease::release("docker", Some("ops")),
            Err(LeaseError::Held(_))
        ));
        assert!(matches!(
            lease::renew("docker", 600, Some("ops")),
            Err(LeaseError::Held(_))
        ));
    }
    {
        let _rt = as_agent(&home, "agent-a", 1020);
        let renewed = lease::renew("docker", 900, Some("ops")).unwrap();
        assert_eq!(renewed.expires, 1020 + 900);
        assert!(lease::release("docker", Some("ops")).unwrap());
    }
    {
        let _rt = as_agent(&home, "agent-b", 1030);
        assert!(lease::check("docker", Some("ops")).unwrap().is_none());
        assert!(matches!(
            lease::acquire("docker", 60, None, 3, Some("ops")).unwrap(),
            Acquire::Acquired(_)
        ));
    }
    {
        // agent-b's 60s lease expires; agent-a can take it without a release.
        let _rt = as_agent(&home, "agent-a", 1200);
        assert!(lease::check("docker", Some("ops")).unwrap().is_none());
        assert!(matches!(
            lease::acquire("docker", 60, None, 3, Some("ops")).unwrap(),
            Acquire::Acquired(_)
        ));
    }
    let _ = std::fs::remove_dir_all(home);
}

fn raw_acquire(resource: &str, holder: &str, ts_now: u64, lease_id: &str) {
    chat::publish_event(
        Some("ops"),
        json!({
            "type": "lease", "action": "acquire", "resource": resource,
            "holder": holder, "lease_id": lease_id, "expires": ts_now + 600, "seq": 1
        }),
        &format!("[lease] {holder} acquired {resource}"),
    )
    .unwrap();
}

#[test]
fn concurrent_acquires_resolve_to_lower_ts_then_agent_id() {
    let home = temp_home("race");
    setup_room(&home);
    // agent-b's acquire reaches the relay first, agent-a's in the same second:
    // both published before seeing each other. Lower (ts, from) wins.
    {
        let _rt = as_agent(&home, "agent-b", 2000);
        raw_acquire("gpu0", "agent-b", 2000, "lb");
    }
    {
        let _rt = as_agent(&home, "agent-a", 2000);
        raw_acquire("gpu0", "agent-a", 2000, "la");
    }
    for viewer in ["agent-a", "agent-b", "agent-c"] {
        let _rt = as_agent(&home, viewer, 2005);
        let l = lease::check("gpu0", Some("ops")).unwrap().unwrap();
        assert_eq!(l.holder, "agent-a", "every reader folds the same winner");
    }
    let _ = std::fs::remove_dir_all(home);
}

#[test]
fn forged_holder_is_ignored() {
    let home = temp_home("forged");
    setup_room(&home);
    {
        // agent-c signs an event claiming agent-a holds the lease.
        let _rt = as_agent(&home, "agent-c", 3000);
        raw_acquire("db", "agent-a", 3000, "lx");
    }
    let _rt = as_agent(&home, "agent-b", 3005);
    assert!(lease::check("db", Some("ops")).unwrap().is_none());
    let _ = std::fs::remove_dir_all(home);
}

#[test]
fn leases_fail_closed_without_relay() {
    let home = temp_home("norelay");
    {
        let _rt = as_agent(&home, "agent-a", 900);
        chat::create_silent("ops").unwrap();
    }
    let _rt = runtime::TestRuntime::new()
        .home(&home)
        .var("AGORA_CONFIG", "/nonexistent/agora-test-config.toml")
        .unset_var("AGORA_RELAY_URL")
        .var("AGORA_AGENT_ID", "agent-a")
        .enter();
    let err = lease::check("docker", Some("ops")).unwrap_err();
    assert!(err.contains("relay not configured"), "{err}");
    assert!(store::find_room("ops").is_some());
    let _ = std::fs::remove_dir_all(home);
}

#[test]
fn task_claims_are_leases_with_ttl() {
    let home = temp_home("tasks");
    setup_room(&home);
    let task_id = {
        let _rt = as_agent(&home, "agent-a", 4000);
        let id = chat::task_add("Fix flaky test", Some("ops")).unwrap();
        chat::task_claim_as_ttl("agent-a", &id, 600, Some("ops")).unwrap();
        id
    };
    {
        let _rt = as_agent(&home, "agent-b", 4010);
        let err = chat::task_claim_as_ttl("agent-b", &task_id, 600, Some("ops")).unwrap_err();
        assert!(err.contains("currently claimed by 'agent-a'"), "{err}");
        let tasks = chat::task_list(Some("ops")).unwrap();
        let t = tasks.iter().find(|t| t.id == task_id).unwrap();
        assert_eq!(t.claimed_by.as_deref(), Some("agent-a"));
    }
    {
        // agent-a went dark: once the claim lease expires the task reopens.
        let _rt = as_agent(&home, "agent-b", 4000 + 700);
        let tasks = chat::task_list(Some("ops")).unwrap();
        let t = tasks.iter().find(|t| t.id == task_id).unwrap();
        assert_eq!(t.status, "open");
        chat::task_claim_as_ttl("agent-b", &task_id, 600, Some("ops")).unwrap();
        let held = lease::check(&chat::task_resource(&task_id), Some("ops"))
            .unwrap()
            .unwrap();
        assert_eq!(held.holder, "agent-b");
    }
    let _ = std::fs::remove_dir_all(home);
}

#[test]
fn propose_hold_and_auto_hold_by_lease_holder() {
    use agora::proposal::{self, Decision};
    let home = temp_home("propose");
    setup_room(&home);

    // A clean proposal clears once its deadline passes.
    let clean = {
        let _rt = as_agent(&home, "vigil", 5000);
        proposal::propose("rotate logs", &["logs".to_string()], 60, Some("ops")).unwrap()
    };
    {
        let _rt = as_agent(&home, "vigil", 5030);
        assert!(
            proposal::evaluate(&clean.id, Some("ops"))
                .unwrap()
                .is_none()
        );
        let _rt = as_agent(&home, "vigil", 5061);
        assert!(matches!(
            proposal::evaluate(&clean.id, Some("ops")).unwrap(),
            Some(Decision::Clear(_))
        ));
    }

    // A coding agent holds docker; vigil proposes to restart docker.
    {
        let _rt = as_agent(&home, "coder-1", 6000);
        assert!(matches!(
            lease::acquire("docker", 900, Some("cargo build"), 3, Some("ops")).unwrap(),
            Acquire::Acquired(_)
        ));
    }
    let risky = {
        let _rt = as_agent(&home, "vigil", 6010);
        proposal::propose("restart docker", &["docker".to_string()], 120, Some("ops")).unwrap()
    };
    {
        // coder-1's hook runs `agora check`: it auto-objects.
        let _rt = as_agent(&home, "coder-1", 6015);
        let msgs = chat::check("1h", Some("ops")).unwrap();
        let p = msgs
            .iter()
            .find(|m| m["type"] == "proposal" && m["action"] == "restart docker")
            .expect("proposal delivered");
        assert!(p["_auto_hold"].as_str().unwrap().contains("docker"));
    }
    {
        let _rt = as_agent(&home, "vigil", 6200);
        match proposal::wait(&risky.id[..6], 5, Some("ops")).unwrap() {
            Decision::Held(_, reasons) => {
                assert!(
                    reasons.iter().any(|r| r.contains("coder-1 objected")),
                    "{reasons:?}"
                );
                assert!(reasons.iter().any(|r| r.contains("holds lease on docker")));
            }
            other => panic!("expected held, got {other:?}"),
        }
    }

    // Manual HOLD from an agent without a lease.
    let third = {
        let _rt = as_agent(&home, "vigil", 7000);
        proposal::propose(
            "prune images",
            &["docker:images".to_string()],
            60,
            Some("ops"),
        )
        .unwrap()
    };
    {
        let _rt = as_agent(&home, "coder-2", 7010);
        proposal::hold(&third.id, "need the base image", Some("ops")).unwrap();
    }
    {
        let _rt = as_agent(&home, "vigil", 7100);
        let list = proposal::list(Some("ops")).unwrap();
        let (p, status) = list.iter().find(|(p, _)| p.id == third.id).unwrap();
        assert_eq!(*status, proposal::Status::Held);
        assert_eq!(p.objections[0].reason, "need the base image");
    }
    let _ = std::fs::remove_dir_all(home);
}

#[test]
fn plugin_publish_list_install_feedback_remove() {
    use agora::plugin::{self, SigStatus};
    let home = temp_home("plugin");
    setup_room(&home);

    // coder-1 writes and publishes a command plugin.
    let src = home.join("work").join("hello-tool");
    {
        let _rt = as_agent(&home, "coder-1", 8000);
        plugin::scaffold("hello-tool", "command", &src, Some("Say hello")).unwrap();
        std::fs::write(
            src.join("bin/hello-tool"),
            "#!/bin/sh\necho \"hello from $AGORA_AGENT_ID\"\n",
        )
        .unwrap();
        let p = plugin::publish(&src, Some("ops")).unwrap();
        assert_eq!(p.manifest.author, "coder-1");
        // Same name@version cannot be republished.
        assert!(
            plugin::publish(&src, Some("ops"))
                .unwrap_err()
                .contains("bump the version")
        );
    }

    // coder-2 discovers, previews and installs it.
    {
        let _rt = as_agent(&home, "coder-2", 8010);
        let list = plugin::list(Some("ops")).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].sig_status, SigStatus::Verified);
        assert_eq!(list[0].manifest.id(), "hello-tool@0.1.0");

        let prepared = plugin::prepare("hello-tool", Some("ops")).unwrap();
        assert!(
            !home.join(".agora/plugins/hello-tool").exists(),
            "prepare must not install anything"
        );
        let rec = plugin::install(&prepared, "codex", Some("ops")).unwrap();
        let installed = home.join(".agora/plugins/hello-tool/0.1.0/bin/hello-tool");
        assert!(installed.is_file());
        let link = home.join(".agora/bin/hello-tool");
        assert_eq!(std::fs::read_link(&link).unwrap(), installed);
        assert!(
            rec.changes
                .iter()
                .any(|c| matches!(c, plugin::Change::Symlink { .. }))
        );

        plugin::feedback("hello-tool", 1, "works", Some("ops")).unwrap();
        let info = plugin::info("hello-tool@0.1.0", Some("ops")).unwrap();
        assert_eq!(info.installs, 1);
        assert_eq!(info.score, 1);

        let done = plugin::remove("hello-tool", None).unwrap();
        assert!(!done.is_empty());
        assert!(!link.exists());
        assert!(!home.join(".agora/plugins/hello-tool/0.1.0").exists());
    }
    let _ = std::fs::remove_dir_all(home);
}

#[test]
fn plugin_install_refuses_hash_mismatch_and_unsigned() {
    use agora::plugin;
    let home = temp_home("plugin-tamper");
    setup_room(&home);
    let src = home.join("work").join("skill-a");
    {
        let _rt = as_agent(&home, "coder-1", 9000);
        plugin::scaffold("skill-a", "skill", &src, Some("A skill")).unwrap();
        // Sign the real bundle, but share a different file under it.
        let bundle = plugin::build_signed(&src, "coder-1").unwrap();
        let other = home.join("other.tar");
        std::fs::write(&other, b"not the signed bundle").unwrap();
        let (file_id, size) = chat::send_file(&other.to_string_lossy(), Some("ops")).unwrap();
        chat::publish_event(
            Some("ops"),
            json!({
                "type": "plugin_published", "name": "skill-a", "version": "0.1.0",
                "kind": "skill", "author": "coder-1", "manifest": bundle.manifest_text,
                "sha256": bundle.sha256, "size": size, "file_id": file_id,
                "signing_pubkey": bundle.signing_pubkey, "sig": bundle.sig
            }),
            "[plugin] skill-a",
        )
        .unwrap();
        // And an unsigned publication of another plugin.
        chat::publish_event(
            Some("ops"),
            json!({
                "type": "plugin_published", "name": "nosig", "version": "0.1.0",
                "kind": "command", "author": "coder-1",
                "manifest": "name = \"nosig\"\nversion = \"0.1.0\"\ndescription = \"x\"\nauthor = \"coder-1\"\nkind = \"command\"\nentry = \"x\"\nruntimes = [\"codex\"]\n",
                "sha256": "00", "file_id": "nope"
            }),
            "[plugin] nosig",
        )
        .unwrap();
    }
    let _rt = as_agent(&home, "coder-2", 9010);
    let err = plugin::prepare("skill-a", Some("ops")).unwrap_err();
    assert!(err.contains("hash mismatch"), "{err}");
    let err = plugin::prepare("nosig", Some("ops")).unwrap_err();
    assert!(err.contains("Unsigned"), "{err}");
    assert!(!home.join(".agora/plugins/skill-a").exists());
    let _ = std::fs::remove_dir_all(home);
}

#[test]
fn example_vigil_freeze_plugin_is_valid_and_calls_vigil() {
    use agora::plugin;
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("plugins/examples/vigil-freeze");
    let text = std::fs::read_to_string(src.join(plugin::MANIFEST_FILE)).unwrap();
    let m = plugin::Manifest::parse(&text).unwrap();
    assert_eq!(m.kind, "command");
    assert_eq!(m.entry, "bin/vigil-freeze");

    // Publishing requires the author to be the publisher.
    let home = temp_home("vigil-freeze");
    let copy = home.join("vigil-freeze");
    std::fs::create_dir_all(copy.join("bin")).unwrap();
    std::fs::write(
        copy.join(plugin::MANIFEST_FILE),
        text.replace("CHANGE-ME-to-your-AGORA_AGENT_ID", "coder-1"),
    )
    .unwrap();
    std::fs::copy(src.join("bin/vigil-freeze"), copy.join("bin/vigil-freeze")).unwrap();
    {
        let _rt = as_agent(&home, "coder-1", 1000);
        plugin::build_signed(&copy, "coder-1").unwrap();
    }

    // The wrapper calls `vigil freeze ... --by $AGORA_AGENT_ID`.
    let fakebin = home.join("fakebin");
    std::fs::create_dir_all(&fakebin).unwrap();
    let log = home.join("vigil.log");
    std::fs::write(
        fakebin.join("vigil"),
        format!("#!/bin/sh\necho \"$@\" > {}\n", log.display()),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        fakebin.join("vigil"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let out = std::process::Command::new("bash")
        .arg(src.join("bin/vigil-freeze"))
        .args([
            "docker:build-cache",
            "--minutes",
            "15",
            "--reason",
            "cargo build",
        ])
        .env("PATH", format!("{}:/usr/bin:/bin", fakebin.display()))
        .env("AGORA_AGENT_ID", "coder-1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&log).unwrap().trim(),
        "freeze docker:build-cache --minutes 15 --by coder-1 --reason cargo build"
    );
    let bad = std::process::Command::new("bash")
        .arg(src.join("bin/vigil-freeze"))
        .args(["docker", "--minutes", "0"])
        .env("PATH", format!("{}:/usr/bin:/bin", fakebin.display()))
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(64));
    let _ = std::fs::remove_dir_all(home);
}
