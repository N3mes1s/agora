//! `agora propose` / `hold` / `ack` / `proposals`.
//!
//! `agora propose wait <id>` exit codes: 0 clear, 1 held, 2 error.

use crate::{ProposeAction, ProposeCommand};
use agora::proposal::{self, Decision, Status};
use agora::{lease, runtime};
use std::process;

const POLL_SECS: u64 = 5;

fn hhmmss(ts: u64) -> String {
    crate::ts(ts)
}

fn decide(id: &str, room: Option<&str>) -> ! {
    match proposal::wait(id, POLL_SECS, room) {
        Ok(Decision::Clear(p)) => {
            println!(
                "  CLEAR: no objection to [{}] \"{}\" by {} — go ahead.",
                p.short_id(),
                p.action,
                hhmmss(p.deadline)
            );
            process::exit(0);
        }
        Ok(Decision::Held(p, reasons)) => {
            println!("  HELD: [{}] \"{}\"", p.short_id(), p.action);
            for r in reasons {
                println!("    - {r}");
            }
            process::exit(1);
        }
        Err(e) => {
            eprintln!("  Error: {e}");
            process::exit(2);
        }
    }
}

pub(crate) fn run(cmd: ProposeCommand, room: Option<&str>) {
    if let Some(ProposeAction::Wait { proposal_id }) = cmd.action {
        decide(&proposal_id, room);
    }
    let action = cmd.text.join(" ");
    let wait = lease::parse_duration(&cmd.wait).unwrap_or_else(|e| {
        eprintln!("  Error: {e}");
        process::exit(2);
    });
    match proposal::propose(&action, &cmd.resources, wait, room) {
        Ok(p) => {
            println!(
                "  Proposed [{}] \"{}\" — objections accepted until {}.",
                p.id,
                p.action,
                hhmmss(p.deadline)
            );
            if cmd.block {
                decide(&p.id, room);
            }
            println!("  Then run: agora propose wait {}", p.short_id());
        }
        Err(e) => {
            eprintln!("  Error: {e}");
            process::exit(2);
        }
    }
}

pub(crate) fn hold(id: &str, reason: &str, room: Option<&str>) {
    match proposal::hold(id, reason, room) {
        Ok(p) => println!(
            "  Held [{}] \"{}\" ({})",
            p.short_id(),
            p.action,
            p.proposer
        ),
        Err(e) => {
            eprintln!("  Error: {e}");
            process::exit(1);
        }
    }
}

pub(crate) fn ack(id: &str, note: Option<&str>, room: Option<&str>) {
    match proposal::ack(id, note, room) {
        Ok(p) => println!("  Acknowledged [{}] \"{}\"", p.short_id(), p.action),
        Err(e) => {
            eprintln!("  Error: {e}");
            process::exit(1);
        }
    }
}

pub(crate) fn list(json: bool, room: Option<&str>) {
    match proposal::list(room) {
        Ok(items) => {
            if json {
                let rows: Vec<_> = items
                    .iter()
                    .map(|(p, s)| serde_json::json!({"proposal": p, "status": s}))
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&rows).unwrap_or_default()
                );
                return;
            }
            if items.is_empty() {
                println!("  No proposals in the last 24h.");
                return;
            }
            let now = runtime::unix_now();
            for (p, status) in items {
                let label = match status {
                    Status::Open => format!("open {}s", p.deadline.saturating_sub(now)),
                    Status::Held => "HELD".to_string(),
                    Status::Clear => "clear".to_string(),
                };
                println!(
                    "  [{}] {:<10} {} by {} (resources: {})",
                    p.short_id(),
                    label,
                    p.action,
                    p.proposer,
                    if p.resources.is_empty() {
                        "-".to_string()
                    } else {
                        p.resources.join(", ")
                    }
                );
                for o in &p.objections {
                    println!("         hold by {}: {}", o.from, o.reason);
                }
            }
        }
        Err(e) => {
            eprintln!("  Error: {e}");
            process::exit(1);
        }
    }
}
