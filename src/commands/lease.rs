//! `agora lease ...` — signed, TTL-bound resource leases.
//!
//! Exit codes: 0 success / free (or held by you), 3 held by another agent,
//! 1 error. `check` considers overlapping names: `docker` is held while
//! someone holds `docker:images`, and vice versa.

use crate::LeaseAction;
use agora::lease::{self, Acquire, Lease, LeaseError};
use agora::{runtime, store};
use std::process;

pub(crate) const EXIT_HELD: i32 = 3;

fn die(e: impl std::fmt::Display) -> ! {
    eprintln!("  Error: {e}");
    process::exit(1);
}

fn ttl_secs(raw: &str) -> u64 {
    lease::parse_duration(raw).unwrap_or_else(|e| die(e))
}

fn describe(l: &Lease) -> String {
    let now = runtime::unix_now();
    let until = chrono::DateTime::from_timestamp(l.expires as i64, 0)
        .map(|d| d.with_timezone(&chrono::Local).to_rfc3339())
        .unwrap_or_default();
    format!(
        "{} held by {} until {until} (expires={}, {}s left, lease {}){}",
        l.resource,
        l.holder,
        l.expires,
        l.remaining(now),
        l.lease_id,
        l.reason
            .as_deref()
            .map(|r| format!(" — {r}"))
            .unwrap_or_default()
    )
}

fn print_json(l: &Lease) {
    println!("{}", serde_json::to_string_pretty(l).unwrap_or_default());
}

fn held(l: &Lease) -> ! {
    eprintln!("  Held: {}", describe(l));
    process::exit(EXIT_HELD);
}

pub(crate) fn run(action: LeaseAction, room: Option<&str>) {
    match action {
        LeaseAction::Acquire {
            resource,
            ttl,
            reason,
            wait,
            json,
        } => {
            let ttl = ttl_secs(&ttl);
            let deadline = wait.map(|w| runtime::unix_now() + ttl_secs(&w));
            loop {
                match lease::acquire(
                    &resource,
                    ttl,
                    reason.as_deref(),
                    lease::SKEW_WINDOW_SECS + 1,
                    room,
                ) {
                    Ok(Acquire::Acquired(l)) => {
                        if json {
                            print_json(&l);
                        } else {
                            println!(
                                "  Acquired {} until {} (lease {}). Renew with: agora lease renew {}",
                                l.resource,
                                crate::ts(l.expires),
                                l.lease_id,
                                l.resource
                            );
                        }
                        return;
                    }
                    Ok(Acquire::Held(l)) => match deadline {
                        Some(d) if runtime::unix_now() < d => {
                            eprintln!("  Waiting: {}", describe(&l));
                            let pause = 5.min(d.saturating_sub(runtime::unix_now())).max(1);
                            runtime::sleep(std::time::Duration::from_secs(pause));
                        }
                        _ => {
                            if json {
                                print_json(&l);
                            }
                            held(&l);
                        }
                    },
                    Err(e) => die(e),
                }
            }
        }
        LeaseAction::Renew { resource, ttl } => {
            match lease::renew(&resource, ttl_secs(&ttl), room) {
                Ok(l) => println!(
                    "  Renewed {} until {} (lease {})",
                    l.resource,
                    crate::ts(l.expires),
                    l.lease_id
                ),
                Err(LeaseError::Held(l)) => held(&l),
                Err(e) => die(e),
            }
        }
        LeaseAction::Release {
            resource,
            lease: Some(lease_id),
            reason,
        } => {
            let me = store::get_agent_id();
            match lease::release_stranded(&me, &resource, &lease_id, reason.as_deref().unwrap_or(""), room) {
                Ok(l) => println!("  Released {resource} (lease {}, held by {})", l.lease_id, l.holder),
                Err(e) => die(e),
            }
        }
        LeaseAction::Release { resource, .. } => match lease::release(&resource, room) {
            Ok(true) => println!("  Released {resource}"),
            Ok(false) => println!("  {resource} was not held"),
            Err(LeaseError::Held(l)) => held(&l),
            Err(e) => die(e),
        },
        LeaseAction::Check { resource, json } => match lease::check(&resource, room) {
            Ok(None) => {
                if json {
                    println!("null");
                } else {
                    println!("{resource} is free");
                }
            }
            Ok(Some(l)) => {
                if json {
                    print_json(&l);
                }
                if l.holder == store::get_agent_id() {
                    if !json {
                        println!("{} (you)", describe(&l));
                    }
                } else {
                    if !json {
                        println!("{}", describe(&l));
                    }
                    process::exit(EXIT_HELD);
                }
            }
            Err(e) => die(e),
        },
        LeaseAction::List { json } => match lease::list(room) {
            Ok(leases) => {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&leases).unwrap_or_default()
                    );
                } else if leases.is_empty() {
                    println!("  No active leases.");
                } else {
                    for l in &leases {
                        println!("  {}", describe(l));
                    }
                }
            }
            Err(e) => die(e),
        },
    }
}
