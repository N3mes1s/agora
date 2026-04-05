//! Agora CLI — Encrypted agent-to-agent chat.
//!
//! Single binary, zero runtime dependencies.
//! AES-256-GCM + HKDF-SHA256 + ZKP membership proofs.

mod chat;
mod crypto;
mod mcp;
mod store;
mod transport;

use clap::{Parser, Subcommand};
use std::process;

#[derive(Parser)]
#[command(name = "agora", about = "Encrypted agent-to-agent chat", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new encrypted room
    Create {
        /// Room label
        #[arg(default_value = "default")]
        label: String,
    },

    /// Join an existing room
    Join {
        /// Room ID (ag-...)
        room_id: String,
        /// Shared secret (64 hex chars)
        secret: String,
        /// Room label
        label: Option<String>,
    },

    /// Send an encrypted message
    Send {
        /// Message text
        message: Vec<String>,
        /// Reply to a message ID
        #[arg(long)]
        reply: Option<String>,
    },

    /// Read messages
    Read {
        /// Show last N messages
        #[arg(long)]
        tail: Option<usize>,
    },

    /// Check for new messages (hook-friendly)
    Check {
        /// Exit code 2 on new messages (for asyncRewake)
        #[arg(long)]
        wake: bool,
    },

    /// List joined rooms
    Rooms,

    /// Switch active room
    Switch {
        /// Room label
        label: String,
    },

    /// Show room info + key fingerprint
    Info,

    /// List room members and roles
    Who,

    /// Set room topic (admin only)
    Topic {
        /// New topic text
        text: Vec<String>,
    },

    /// Promote a member to admin
    Promote {
        /// Agent ID to promote
        agent_id: String,
    },

    /// Kick a member from the room (admin only)
    Kick {
        /// Agent ID to kick
        agent_id: String,
    },

    /// ZKP membership proof
    Verify,

    /// Start MCP stdio server (for Claude Code integration)
    Mcp,

    /// Show agent identity
    Id,
}

fn ts(epoch: u64) -> String {
    let secs = epoch as i64;
    let dt = chrono::DateTime::from_timestamp(secs, 0).unwrap_or_default();
    dt.format("%H:%M:%S").to_string()
}

fn print_msg(env: &serde_json::Value) {
    let time = ts(env["ts"].as_u64().unwrap_or(0));
    let sender = env["from"].as_str().unwrap_or("?");
    let text = env["text"].as_str().unwrap_or("");
    let mid = &env["id"].as_str().unwrap_or("?")[..6.min(env["id"].as_str().unwrap_or("?").len())];
    let reply = if let Some(rt) = env["reply_to"].as_str() {
        format!(" ↩{}", &rt[..6.min(rt.len())])
    } else {
        String::new()
    };
    let me = store::get_agent_id();
    if sender == me {
        println!("  \x1b[92m[{time}] [{mid}] {sender}: {text}{reply}\x1b[0m");
    } else {
        println!("  \x1b[96m[{time}]\x1b[0m [{mid}]{reply} {sender}: {text}");
    }
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Create { label } => {
            match chat::create(&label) {
                Ok((room_id, secret)) => {
                    let room_key = crypto::derive_room_key(&secret, &room_id);
                    println!("  Created encrypted room '{label}'");
                    println!("  Room ID:    {room_id}");
                    println!("  Secret:     {secret}");
                    println!("  Encryption: AES-256-GCM + HKDF-SHA256");
                    println!();
                    println!("  Share this join command:");
                    println!("    agora join {room_id} {secret} {label}");
                    println!();
                    println!("  Key fingerprint (verify out-of-band):");
                    println!("    {}", crypto::fingerprint(&room_key));
                }
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Join { room_id, secret, label } => {
            let label = label.unwrap_or_else(|| room_id[..12.min(room_id.len())].to_string());
            match chat::join(&room_id, &secret, &label) {
                Ok(_) => {
                    let room_key = crypto::derive_room_key(&secret, &room_id);
                    println!("  Joined room '{label}'");
                    println!("  Encryption: AES-256-GCM + HKDF-SHA256");
                    println!("  Fingerprint: {}", crypto::fingerprint(&room_key));
                }
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Send { message, reply } => {
            let text = message.join(" ");
            if text.is_empty() {
                eprintln!("Usage: agora send <message>");
                process::exit(1);
            }
            match chat::send(&text, reply.as_deref(), None) {
                Ok(mid) => println!("  Sent [{}] (AES-256-GCM encrypted)", &mid[..6.min(mid.len())]),
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Read { tail } => {
            match chat::read("2h", 50, None) {
                Ok(msgs) => {
                    let msgs = if let Some(n) = tail {
                        if msgs.len() > n { &msgs[msgs.len() - n..] } else { &msgs }
                    } else {
                        &msgs
                    };
                    if msgs.is_empty() {
                        println!("  (no messages)");
                        return;
                    }
                    if let Some(room) = store::get_active_room() {
                        println!("  --- {} ({} messages, AES-256-GCM) ---\n", room.label, msgs.len());
                    }
                    for m in msgs {
                        print_msg(m);
                    }
                }
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Check { wake } => {
            match chat::check("5m", None) {
                Ok(msgs) => {
                    if !msgs.is_empty() {
                        for m in &msgs {
                            print_msg(m);
                        }
                        if wake {
                            process::exit(2);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Rooms => {
            let rooms = store::load_registry();
            if rooms.is_empty() {
                println!("  No rooms. Run: agora create <label>");
                return;
            }
            let active = store::get_active_room();
            let active_id = active.map(|r| r.room_id).unwrap_or_default();
            println!("  {:<20} {:<22} {:<8} Joined", "Label", "Room ID", "Active");
            println!("  {:<20} {:<22} {:<8} {}", "─".repeat(20), "─".repeat(22), "─".repeat(8), "─".repeat(20));
            for r in &rooms {
                let is_active = if r.room_id == active_id { " *" } else { "" };
                let joined = chrono::DateTime::from_timestamp(r.joined_at as i64, 0)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
                    .unwrap_or_default();
                println!("  {:<20} {:<22} {:<8} {joined}", r.label, r.room_id, is_active);
            }
        }

        Commands::Switch { label } => {
            match store::find_room(&label) {
                Some(_) => {
                    store::set_active_room(&label);
                    println!("  Switched to '{label}'");
                }
                None => {
                    eprintln!("  Room '{label}' not found. Run: agora rooms");
                    process::exit(1);
                }
            }
        }

        Commands::Info => {
            match chat::info(None) {
                Ok(info) => {
                    println!("  Room:        {}", info["label"].as_str().unwrap_or("?"));
                    println!("  ID:          {}", info["room_id"].as_str().unwrap_or("?"));
                    if let Some(topic) = info["topic"].as_str() {
                        println!("  Topic:       {topic}");
                    }
                    println!("  Encryption:  {}", info["encryption"].as_str().unwrap_or("?"));
                    println!("  KDF:         {}", info["key_derivation"].as_str().unwrap_or("?"));
                    println!("  Messages:    {}", info["messages"].as_u64().unwrap_or(0));
                    let member_count = info["members"].as_array().map(|a| a.len()).unwrap_or(0);
                    println!("  Members:     {member_count}");
                    println!("  Fingerprint: {}", info["fingerprint"].as_str().unwrap_or("?"));
                }
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Who => {
            match chat::who(None) {
                Ok(members) => {
                    if members.is_empty() {
                        println!("  No members tracked yet.");
                        return;
                    }
                    let me = store::get_agent_id();
                    println!("  {:<12} {:<8} Joined", "Agent", "Role");
                    println!("  {:<12} {:<8} {}", "─".repeat(12), "─".repeat(8), "─".repeat(20));
                    for m in &members {
                        let role = format!("{:?}", m.role);
                        let is_me = if m.agent_id == me { " (you)" } else { "" };
                        let joined = chrono::DateTime::from_timestamp(m.joined_at as i64, 0)
                            .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
                            .unwrap_or_default();
                        println!("  {:<12} {:<8} {joined}{is_me}", m.agent_id, role);
                    }
                }
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Topic { text } => {
            let topic = text.join(" ");
            if topic.is_empty() {
                eprintln!("Usage: agora topic <text>");
                process::exit(1);
            }
            match chat::topic(&topic, None) {
                Ok(()) => println!("  Topic set: {topic}"),
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Promote { agent_id } => {
            match chat::promote(&agent_id, None) {
                Ok(()) => println!("  Promoted {agent_id} to admin."),
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Kick { agent_id } => {
            match chat::kick(&agent_id, None) {
                Ok(()) => println!("  Kicked {agent_id}."),
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Verify => {
            match chat::verify(None) {
                Ok(proof) => {
                    let valid = proof["proof_valid"].as_bool().unwrap_or(false);
                    println!("  Room: {}", proof["room_id"].as_str().unwrap_or("?"));
                    println!("  ZKP membership proof: {}", if valid { "VALID" } else { "INVALID" });
                    let nonce = proof["nonce"].as_str().unwrap_or("");
                    let commitment = proof["commitment"].as_str().unwrap_or("");
                    let challenge = proof["challenge"].as_str().unwrap_or("");
                    let response = proof["response"].as_str().unwrap_or("");
                    println!("  Nonce:      {}...", &nonce[..32.min(nonce.len())]);
                    println!("  Commitment: {}...", &commitment[..32.min(commitment.len())]);
                    println!("  Challenge:  {}...", &challenge[..32.min(challenge.len())]);
                    println!("  Response:   {}...", &response[..32.min(response.len())]);
                }
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Mcp => {
            mcp::run();
        }

        Commands::Id => {
            println!("{}", store::get_agent_id());
        }
    }
}
