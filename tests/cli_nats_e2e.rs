use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_home(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "agora-cli-nats-e2e-{name}-{}-{unique}",
        std::process::id()
    ))
}

fn run_agora(
    home: &Path,
    agent_id: &str,
    nats_url: &str,
    stream: &str,
    subject_prefix: &str,
    args: &[&str],
) -> Output {
    let output = Command::new(env!("CARGO_BIN_EXE_agora"))
        .args(args)
        .env("HOME", home)
        .env("AGORA_AGENT_ID", agent_id)
        .env("AGORA_RELAY_URL", nats_url)
        .env("AGORA_NATS_STREAM", stream)
        .env("AGORA_NATS_SUBJECT_PREFIX", subject_prefix)
        .env("AGORA_NATS_STORAGE", "memory")
        .env("AGORA_NATS_CREATE_STREAM", "true")
        .env_remove("AGORA_RELAY_TOKEN")
        .output()
        .unwrap_or_else(|err| panic!("failed to run agora {args:?}: {err}"));
    output
}

fn expect_status(output: Output, allowed: &[i32], context: &str) -> String {
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(
        allowed.contains(&code),
        "{context} exited {code}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    format!("{stdout}{stderr}")
}

fn expect_ok(output: Output, context: &str) -> String {
    expect_status(output, &[0], context)
}

fn invite_token(output: &str) -> String {
    output
        .split_whitespace()
        .find(|word| word.starts_with("agr_"))
        .map(|word| {
            word.trim_matches(|ch: char| ch == '"' || ch == '\'')
                .to_string()
        })
        .expect("invite output should contain agr_ token")
}

#[test]
#[ignore = "requires AGORA_LIVE_NATS_URL pointing at a real NATS+JetStream server"]
fn cli_create_invite_send_read_check_round_trips_over_nats() {
    let nats_url = std::env::var("AGORA_LIVE_NATS_URL")
        .expect("AGORA_LIVE_NATS_URL must point at a live NATS server");
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let stream = format!("AGORA_CLI_E2E_{unique}");
    let subject_prefix = format!("clicert.{unique}");
    let room_label = format!("cert-{unique}");
    let alice_home = temp_home("alice");
    let bob_home = temp_home("bob");
    std::fs::create_dir_all(&alice_home).unwrap();
    std::fs::create_dir_all(&bob_home).unwrap();

    let created = expect_ok(
        run_agora(
            &alice_home,
            "alice-cert",
            &nats_url,
            &stream,
            &subject_prefix,
            &["create", &room_label],
        ),
        "alice create",
    );
    assert!(created.contains("Created encrypted room"));
    assert!(created.contains("AES-256-GCM"));

    let sent = expect_ok(
        run_agora(
            &alice_home,
            "alice-cert",
            &nats_url,
            &stream,
            &subject_prefix,
            &["send", "hello from alice"],
        ),
        "alice send",
    );
    assert!(sent.contains("Sent"));
    assert!(sent.contains("AES-256-GCM encrypted"));

    let alice_read = expect_ok(
        run_agora(
            &alice_home,
            "alice-cert",
            &nats_url,
            &stream,
            &subject_prefix,
            &["read", "--tail", "10"],
        ),
        "alice read after send",
    );
    assert!(alice_read.contains("hello from alice"));

    let invite = expect_ok(
        run_agora(
            &alice_home,
            "alice-cert",
            &nats_url,
            &stream,
            &subject_prefix,
            &["invite", "--max-uses", "1"],
        ),
        "alice invite",
    );
    let token = invite_token(&invite);

    let accepted = expect_ok(
        run_agora(
            &bob_home,
            "bob-cert",
            &nats_url,
            &stream,
            &subject_prefix,
            &["accept", &token],
        ),
        "bob accept",
    );
    assert!(accepted.contains("Joined room"));
    assert!(accepted.contains("Invite signature: verified"));
    assert!(accepted.contains("Invite uses: 1/1"));

    let bob_read = expect_ok(
        run_agora(
            &bob_home,
            "bob-cert",
            &nats_url,
            &stream,
            &subject_prefix,
            &["read", "--tail", "20"],
        ),
        "bob read",
    );
    assert!(bob_read.contains("hello from alice"));
    assert!(bob_read.contains("Joined (agora v3)."));

    let bob_sent = expect_ok(
        run_agora(
            &bob_home,
            "bob-cert",
            &nats_url,
            &stream,
            &subject_prefix,
            &["send", "hello from bob"],
        ),
        "bob send",
    );
    assert!(bob_sent.contains("Sent"));

    let alice_check = expect_status(
        run_agora(
            &alice_home,
            "alice-cert",
            &nats_url,
            &stream,
            &subject_prefix,
            &["check", "--wake"],
        ),
        &[2],
        "alice check --wake",
    );
    assert!(alice_check.contains("hello from bob"));

    let alice_final_read = expect_ok(
        run_agora(
            &alice_home,
            "alice-cert",
            &nats_url,
            &stream,
            &subject_prefix,
            &["read", "--tail", "20"],
        ),
        "alice final read",
    );
    assert!(alice_final_read.contains("hello from alice"));
    assert!(alice_final_read.contains("hello from bob"));
}
