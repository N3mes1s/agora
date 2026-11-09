//! `agora plugin ...` — agent-authored plugins.

use crate::PluginAction;
use agora::plugin::{self, Publication, SigStatus};
use std::path::PathBuf;
use std::process;

fn die(e: impl std::fmt::Display) -> ! {
    eprintln!("  Error: {e}");
    process::exit(1);
}

fn sig_label(s: SigStatus) -> &'static str {
    match s {
        SigStatus::Verified => "signed",
        SigStatus::Unsigned => "UNSIGNED",
        SigStatus::Invalid => "INVALID-SIG",
        SigStatus::UntrustedKey => "UNTRUSTED-KEY",
    }
}

fn print_details(p: &Publication) {
    let m = &p.manifest;
    println!("  {}  ({})", m.id(), m.kind);
    println!("    {}", m.description);
    println!("    author:    {}", m.author);
    println!(
        "    signature: {} (key {})",
        sig_label(p.sig_status),
        p.signing_pubkey
    );
    println!("    sha256:    {}", p.sha256);
    println!("    size:      {} bytes, file {}", p.size, p.file_id);
    println!("    entry:     {}", m.entry);
    println!("    runtimes:  {}", m.runtimes.join(", "));
    if let Some(notes) = &m.notes {
        println!("    notes:     {notes}");
    }
    println!(
        "    published: {}  installs: {}  score: {:+}",
        crate::ts(p.published_at),
        p.installs,
        p.score
    );
    for f in &p.feedback {
        println!("      {:+} {}: {}", f.score, f.from, f.comment);
    }
}

pub(crate) fn run(action: PluginAction, room: Option<&str>) {
    match action {
        PluginAction::New {
            name,
            kind,
            dir,
            description,
        } => {
            let dir = PathBuf::from(dir.unwrap_or_else(|| name.clone()));
            match plugin::scaffold(&name, &kind, &dir, description.as_deref()) {
                Ok(files) => {
                    println!("  Created {kind} plugin '{name}':");
                    for f in files {
                        println!("    {}", f.display());
                    }
                    println!("  Edit it, then: agora plugin publish {}", dir.display());
                }
                Err(e) => die(e),
            }
        }
        PluginAction::Publish { dir } => match plugin::publish(&PathBuf::from(&dir), room) {
            Ok(p) => {
                println!(
                    "  Published {} (sha256 {}, {} bytes, signed by {}).",
                    p.manifest.id(),
                    p.sha256,
                    p.size,
                    p.manifest.author
                );
                println!(
                    "  Others install with: agora plugin install {} --yes",
                    p.manifest.id()
                );
            }
            Err(e) => die(e),
        },
        PluginAction::List { installed, json } => {
            if installed {
                let items = plugin::load_installed();
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&items).unwrap_or_default()
                    );
                } else if items.is_empty() {
                    println!("  No plugins installed.");
                } else {
                    for i in items {
                        println!(
                            "  {}@{} ({}) for {} by {} — {}",
                            i.name, i.version, i.kind, i.runtime, i.author, i.path
                        );
                    }
                }
                return;
            }
            match plugin::list(room) {
                Ok(items) => {
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&items).unwrap_or_default()
                        );
                        return;
                    }
                    if items.is_empty() {
                        println!(
                            "  No plugins shared in this room yet. Write one: agora plugin new <name> --kind command"
                        );
                        return;
                    }
                    println!(
                        "  {:<24} {:<8} {:<8} {:<16} {:<14} {:<14} {:>4} {:>5}",
                        "NAME@VERSION",
                        "KIND",
                        "",
                        "AUTHOR",
                        "SHA256",
                        "SIGNATURE",
                        "INST",
                        "SCORE"
                    );
                    for p in items {
                        println!(
                            "  {:<24} {:<8} {:<8} {:<16} {:<14} {:<14} {:>4} {:>+5}",
                            p.manifest.id(),
                            p.manifest.kind,
                            "",
                            p.manifest.author,
                            &p.sha256[..12.min(p.sha256.len())],
                            sig_label(p.sig_status),
                            p.installs,
                            p.score
                        );
                    }
                }
                Err(e) => die(e),
            }
        }
        PluginAction::Info { spec, json } => match plugin::info(&spec, room) {
            Ok(p) => {
                if json {
                    println!("{}", serde_json::to_string_pretty(&p).unwrap_or_default());
                } else {
                    print_details(&p);
                    println!("\n  --- manifest ---\n{}", p.manifest_text);
                }
            }
            Err(e) => die(e),
        },
        PluginAction::Install { spec, runtime, yes } => {
            let runtime = runtime.unwrap_or_else(plugin::default_runtime);
            let prepared = plugin::prepare(&spec, room).unwrap_or_else(|e| die(e));
            let p = &prepared.publication;
            println!("  Verified signature and hash of {}:", p.manifest.id());
            print_details(p);
            println!("  Files:");
            for e in &prepared.entries {
                println!(
                    "    {}{} ({} bytes)",
                    e.path,
                    if e.executable { " [x]" } else { "" },
                    e.data.len()
                );
            }
            if let Some(entry) = prepared.entries.iter().find(|e| e.path == p.manifest.entry) {
                println!("  --- {} (first 40 lines) ---", entry.path);
                for line in String::from_utf8_lossy(&entry.data).lines().take(40) {
                    println!("  | {line}");
                }
            }
            if !yes {
                println!(
                    "\n  Nothing installed. Review the above, then re-run with --yes to install for {runtime}."
                );
                return;
            }
            match plugin::install(&prepared, &runtime, room) {
                Ok(rec) => {
                    println!(
                        "\n  Installed {}@{} for {}. Changes:",
                        rec.name, rec.version, rec.runtime
                    );
                    for c in &rec.changes {
                        println!("    - {c}");
                    }
                    println!(
                        "  Undo with: agora plugin remove {}@{}",
                        rec.name, rec.version
                    );
                }
                Err(e) => die(e),
            }
        }
        PluginAction::Remove { spec, runtime } => match plugin::remove(&spec, runtime.as_deref()) {
            Ok(done) => {
                println!("  Removed {spec}:");
                for d in done {
                    println!("    - {d}");
                }
            }
            Err(e) => die(e),
        },
        PluginAction::Feedback {
            spec,
            score,
            comment,
        } => {
            let score = match score.trim() {
                "+1" | "1" | "up" => 1,
                "-1" | "down" => -1,
                other => die(format!("score must be +1 or -1, got '{other}'")),
            };
            match plugin::feedback(&spec, score, &comment.join(" "), room) {
                Ok(p) => println!("  Rated {} {:+}.", p.manifest.id(), score),
                Err(e) => die(e),
            }
        }
    }
}
