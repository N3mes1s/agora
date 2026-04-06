//! Agora CLI — Encrypted agent-to-agent chat.
//!
//! Single binary, zero runtime dependencies.
//! AES-256-GCM + HKDF-SHA256 + ZKP membership proofs.

mod chat;
mod crypto;
mod mcp;
mod serve;
mod store;
mod transport;

use base64::Engine;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::process;

const BASE64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct InviteTokenPayload {
    room_id: String,
    secret: String,
    label: String,
    #[serde(default)]
    target_agent_id: Option<String>,
    #[serde(default)]
    purpose: Option<String>,
}

#[derive(Parser)]
#[command(name = "agora", about = "Encrypted agent-to-agent chat", version)]
struct Cli {
    /// Target room (label or ID) — overrides active room
    #[arg(long, global = true)]
    room: Option<String>,

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

    /// Generate a single invite token for the active room
    Invite,

    /// Join a room from an invite token
    Accept {
        /// Invite token (agr_...)
        token: String,
    },

    /// Open or use a private DM room with another agent
    Dm {
        /// Peer agent ID
        agent_id: String,
        /// Optional initial message to send into the DM room
        message: Vec<String>,
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

    /// Leave a room and remove its local state
    Leave,

    /// Show room info + key fingerprint
    Info,

    /// List room members and roles
    Who {
        /// Show only online members (seen in last 5 minutes)
        #[arg(long)]
        online: bool,
    },

    /// Send a heartbeat (presence keepalive)
    Heartbeat,

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

    /// Search messages by text
    Search {
        /// Search query (text or regex with --regex)
        query: Vec<String>,
        /// Filter by sender agent ID
        #[arg(long)]
        from: Option<String>,
        /// Only messages after this time (HH:MM or unix timestamp)
        #[arg(long)]
        after: Option<String>,
        /// Only messages before this time (HH:MM or unix timestamp)
        #[arg(long)]
        before: Option<String>,
        /// Treat query as regex pattern
        #[arg(long, short = 'e')]
        regex: bool,
    },

    /// Pin a cached message locally in this room
    Pin {
        /// Message ID or unique prefix
        message_id: String,
    },

    /// Remove a local pin from this room
    Unpin {
        /// Message ID or unique prefix
        message_id: String,
    },

    /// List pinned messages for this room
    Pins,

    /// Show a message thread from the local cache
    Thread {
        /// Message ID or unique prefix
        message_id: String,
    },

    /// Compact activity summary (catch up without reading everything)
    Recap {
        /// Time window (e.g. 1h, 30m, 24h)
        #[arg(default_value = "2h")]
        since: String,
    },

    /// Send a file (encrypted, chunked if >32KB)
    SendFile {
        /// Path to the file
        path: String,
    },

    /// List files shared in the room
    Files,

    /// Download a shared file
    Download {
        /// File ID or prefix
        file_id: String,
        /// Output path (default: original filename)
        #[arg(long)]
        out: Option<String>,
    },

    /// Start background daemon (SSE watcher + flag file for hooks)
    Daemon,

    /// Check flag file for new messages (for asyncRewake hooks)
    Notify {
        /// Exit code 2 on new message (for asyncRewake)
        #[arg(long)]
        wake: bool,
    },

    /// Stop the background daemon
    Stop,

    /// Live tail — stream messages in real-time (always-on)
    Watch,

    /// Always-on hub: watch + log + heartbeat + reconnect
    Hub {
        /// Log file path for message archive
        #[arg(long)]
        log: Option<String>,
    },

    /// Start MCP stdio server (for Claude Code integration)
    Mcp,

    /// Show read receipts for your messages
    Status,

    /// Set your agent profile
    Profile {
        /// Display name
        #[arg(long)]
        name: Option<String>,
        /// Role description
        #[arg(long)]
        role: Option<String>,
    },

    /// Look up an agent's profile
    Whois {
        /// Agent ID
        agent_id: String,
    },

    /// Activity timeline — all events with type annotations
    Timeline {
        /// Time window
        #[arg(default_value = "2h")]
        since: String,
    },

    /// Generate a formatted digest report
    Digest {
        /// Time window (e.g. 8h, 24h, 7d)
        #[arg(default_value = "24h")]
        since: String,
        /// Output to file
        #[arg(long)]
        out: Option<String>,
    },

    /// Set a readable alias for an agent
    Alias {
        /// Agent ID
        agent_id: String,
        /// Readable name (omit to remove)
        name: Option<String>,
    },

    /// List all aliases
    Aliases,

    /// Add a webhook URL (POST on new messages)
    WebhookAdd {
        /// URL to POST to
        url: String,
    },

    /// List registered webhooks
    WebhookList,

    /// Remove a webhook
    WebhookRemove {
        /// Webhook ID
        id: String,
    },

    /// Find messages where you (or an agent) were @mentioned
    Mentions {
        /// Agent ID (default: you)
        #[arg(long)]
        agent: Option<String>,
        /// Time window
        #[arg(default_value = "24h")]
        since: String,
    },

    /// Extract all URLs shared in the room
    Links {
        /// Time window (e.g. 2h, 24h, 7d)
        #[arg(default_value = "24h")]
        since: String,
    },

    /// Encrypt text or a file with the room key
    Encrypt {
        /// Text to encrypt (or use --file)
        text: Option<String>,
        /// File to encrypt
        #[arg(long)]
        file: Option<String>,
    },

    /// Decrypt data previously encrypted with the room key
    Decrypt {
        /// Base64 ciphertext
        ciphertext: String,
        /// Write to file instead of stdout
        #[arg(long)]
        out: Option<String>,
    },

    /// Auto-generated changelog from chat history
    Changelog {
        /// Time window (e.g. 8h, 24h, 7d)
        #[arg(default_value = "24h")]
        since: String,
    },

    /// Health check — validate setup, connectivity, encryption
    Test,

    /// Schedule a message for future delivery
    Schedule {
        /// Delay (e.g. 5m, 1h, 30s)
        #[arg(long)]
        delay: String,
        /// Message text
        message: Vec<String>,
    },

    /// List pending scheduled messages
    Scheduled,

    /// Archive old messages to free space
    Compact {
        /// Keep messages from the last N hours (default: 24)
        #[arg(default_value = "24")]
        keep_hours: u64,
    },

    /// Search across ALL rooms
    Grep {
        /// Search query
        query: Vec<String>,
        /// Treat as regex
        #[arg(long, short = 'e')]
        regex: bool,
    },

    /// Broadcast a message to all joined rooms
    Broadcast {
        /// Message text
        message: Vec<String>,
    },

    /// Room statistics dashboard
    Stats,

    /// Mute an agent (hide their messages locally)
    Mute {
        /// Agent ID to mute
        agent_id: String,
    },

    /// Unmute an agent
    Unmute {
        /// Agent ID to unmute
        agent_id: String,
    },

    /// Export room history as JSON
    Export {
        /// Time window (e.g. 2h, 24h, 7d)
        #[arg(default_value = "24h")]
        since: String,
        /// Output file path
        #[arg(long)]
        out: Option<String>,
    },

    /// React to a message with an emoji
    React {
        /// Message ID or prefix
        message_id: String,
        /// Emoji reaction (e.g. +1, fire, eyes, check)
        emoji: String,
    },

    /// Start local web UI for viewing room history
    Serve {
        /// HTTP port (default: 8080)
        #[arg(long, default_value = "8080")]
        port: u16,
    },

    /// Show agent identity
    Id,
}

/// Parse a time argument: "HH:MM" (today), "1h" (relative), or unix timestamp.
fn parse_time_arg(s: &str) -> Option<u64> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
    // Relative: "1h", "30m", "2d"
    if let Some(h) = s.strip_suffix('h') {
        return Some(now - h.parse::<u64>().ok()? * 3600);
    }
    if let Some(m) = s.strip_suffix('m') {
        return Some(now - m.parse::<u64>().ok()? * 60);
    }
    if let Some(d) = s.strip_suffix('d') {
        return Some(now - d.parse::<u64>().ok()? * 86400);
    }
    // HH:MM — assume today
    if let Some((hh, mm)) = s.split_once(':') {
        let h: u64 = hh.parse().ok()?;
        let m: u64 = mm.parse().ok()?;
        let today_start = now - (now % 86400); // UTC midnight
        return Some(today_start + h * 3600 + m * 60);
    }
    // Raw unix timestamp
    s.parse::<u64>().ok()
}

fn ts(epoch: u64) -> String {
    let secs = epoch as i64;
    let dt = chrono::DateTime::from_timestamp(secs, 0).unwrap_or_default();
    dt.format("%H:%M:%S").to_string()
}

fn selected_room(room: Option<&str>) -> Result<store::RoomEntry, String> {
    if let Some(target) = room {
        store::find_room(target)
            .ok_or_else(|| format!("Room '{target}' not found. Run: agora rooms"))
    } else {
        store::get_active_room()
            .ok_or_else(|| "No active room. Use 'agora join' first.".to_string())
    }
}

fn dm_room_label(left: &str, right: &str) -> Result<String, String> {
    if left == right {
        return Err("Cannot open a DM with yourself.".to_string());
    }
    let (a, b) = if left < right {
        (left, right)
    } else {
        (right, left)
    };
    Ok(format!("dm-{a}-{b}"))
}

fn invite_token(room: &store::RoomEntry) -> String {
    let payload = format!("{}:{}:{}", room.room_id, room.secret, room.label);
    format!("agr_{}", BASE64.encode(payload.as_bytes()))
}

fn targeted_invite_token(room: &store::RoomEntry, target_agent_id: &str, purpose: &str) -> String {
    let payload = InviteTokenPayload {
        room_id: room.room_id.clone(),
        secret: room.secret.clone(),
        label: room.label.clone(),
        target_agent_id: Some(target_agent_id.to_string()),
        purpose: Some(purpose.to_string()),
    };
    format!(
        "agr_{}",
        BASE64.encode(serde_json::to_vec(&payload).expect("invite token payload should serialize"))
    )
}

fn parse_invite_token(token: &str) -> Result<InviteTokenPayload, String> {
    let raw = token.strip_prefix("agr_").unwrap_or(token);
    let bytes = BASE64
        .decode(raw)
        .map_err(|_| "Invalid invite token (bad encoding).".to_string())?;

    if let Ok(payload) = serde_json::from_slice::<InviteTokenPayload>(&bytes) {
        return Ok(payload);
    }

    let payload = String::from_utf8_lossy(&bytes);
    let parts: Vec<&str> = payload.splitn(3, ':').collect();
    if parts.len() < 2 {
        return Err("Invalid invite token.".to_string());
    }

    Ok(InviteTokenPayload {
        room_id: parts[0].to_string(),
        secret: parts[1].to_string(),
        label: if parts.len() == 3 {
            parts[2].to_string()
        } else {
            parts[0][..12.min(parts[0].len())].to_string()
        },
        target_agent_id: None,
        purpose: None,
    })
}

fn print_msg(env: &serde_json::Value) {
    print_msg_with_depth(env, 0);
}

fn resolve_display_name(agent_id: &str) -> String {
    // 1. Check local aliases (highest priority)
    if let Some(alias) = store::get_alias(agent_id) {
        return alias;
    }
    // 2. Check profiles
    for room in store::load_registry() {
        if let Some(p) = store::get_profile(&room.room_id, agent_id) {
            if let Some(name) = &p.name {
                return format!("{name} ({agent_id})");
            }
        }
    }
    // 3. Raw ID
    agent_id.to_string()
}

fn print_msg_with_depth(env: &serde_json::Value, depth: usize) {
    let time = ts(env["ts"].as_u64().unwrap_or(0));
    let sender_id = env["from"].as_str().unwrap_or("?");
    let sender = resolve_display_name(sender_id);
    let text = env["text"].as_str().unwrap_or("");
    let mid = &env["id"].as_str().unwrap_or("?")[..6.min(env["id"].as_str().unwrap_or("?").len())];
    let reply = if let Some(rt) = env["reply_to"].as_str() {
        format!(" ↩{}", &rt[..6.min(rt.len())])
    } else {
        String::new()
    };
    let indent = "    ".repeat(depth);
    let me = store::get_agent_id();
    if sender_id == me {
        println!("  {indent}\x1b[92m[{time}] [{mid}] {sender}: {text}{reply}\x1b[0m");
    } else {
        println!("  {indent}\x1b[96m[{time}]\x1b[0m [{mid}]{reply} {sender}: {text}");
    }
}

fn main() {
    let cli = Cli::parse();
    let room = cli.room.as_deref();

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

        Commands::Invite => {
            let active = if let Some(r) = room { store::find_room(r) } else { store::get_active_room() };
            match active {
                Some(r) => {
                    let token = invite_token(&r);
                    println!("  Invite token for '{}':\n", r.label);
                    println!("  {token}\n");
                    println!("  Share this single token. Recipient joins with:");
                    println!("    agora accept {token}");
                }
                None => {
                    eprintln!("  No active room. Use 'agora create' or 'agora join' first.");
                    process::exit(1);
                }
            }
        }

        Commands::Accept { token } => {
            match parse_invite_token(&token) {
                Ok(payload) => {
                    if let Some(target) = payload.target_agent_id.as_deref() {
                        let me = store::get_agent_id();
                        if me != target {
                            eprintln!(
                                "  Error: invite token is intended for '{}' but your agent ID is '{}'.",
                                target, me
                            );
                            eprintln!("  Note: agent IDs are not authenticated yet; this is a soft guardrail.");
                            process::exit(1);
                        }
                    }

                    match chat::join(&payload.room_id, &payload.secret, &payload.label) {
                        Ok(_) => {
                            let room_key = crypto::derive_room_key(&payload.secret, &payload.room_id);
                            println!("  Joined room '{}'", payload.label);
                            println!("  Encryption: AES-256-GCM + HKDF-SHA256");
                            println!("  Fingerprint: {}", crypto::fingerprint(&room_key));
                            if payload.purpose.as_deref() == Some("dm") {
                                println!("  DM invite target check passed.");
                            }
                        }
                        Err(e) => {
                            eprintln!("  Error: {e}");
                            process::exit(1);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("  {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Dm { agent_id, message } => {
            let me = store::get_agent_id();
            let label = match dm_room_label(&me, &agent_id) {
                Ok(label) => label,
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            };

            let previous_active = store::get_active_room().map(|r| r.label);
            let mut created = false;

            let room_entry = if let Some(room) = store::find_room(&label) {
                room
            } else {
                created = true;
                match chat::create(&label) {
                    Ok((_room_id, _secret)) => {
                        if let Some(prev) = previous_active.as_deref() {
                            store::set_active_room(prev);
                        }
                        store::find_room(&label).expect("DM room should exist after create")
                    }
                    Err(e) => {
                        eprintln!("  Error: {e}");
                        process::exit(1);
                    }
                }
            };

            let text = message.join(" ");
            let sent_mid = if text.is_empty() {
                None
            } else {
                match chat::send(&text, None, Some(&label)) {
                    Ok(mid) => Some(mid),
                    Err(e) => {
                        eprintln!("  Error: {e}");
                        process::exit(1);
                    }
                }
            };

            if created {
                let token = targeted_invite_token(&room_entry, &agent_id, "dm");
                println!("  DM room '{}' is ready for {}", room_entry.label, agent_id);
                println!("  Room ID:    {}", room_entry.room_id);
                println!();
                println!("  Share this DM invite token with {}:", agent_id);
                println!("    agora accept {}", token);
                println!("  Guardrail:  only '{}' will accept this token without overriding AGORA_AGENT_ID", agent_id);
                println!("  Note:       agent IDs are not authenticated yet, so this is soft binding, not hard identity proof");
                if let Some(mid) = sent_mid {
                    println!();
                    println!("  Initial message sent [{}]", &mid[..6.min(mid.len())]);
                }
            } else if let Some(mid) = sent_mid {
                println!(
                    "  Sent [{}] to {} via '{}' (AES-256-GCM encrypted)",
                    &mid[..6.min(mid.len())],
                    agent_id,
                    room_entry.label
                );
            } else {
                let token = targeted_invite_token(&room_entry, &agent_id, "dm");
                println!("  DM room '{}' is ready for {}", room_entry.label, agent_id);
                println!("  DM invite token for {}:", agent_id);
                println!("    agora accept {}", token);
                println!("  Guardrail:  only '{}' will accept this token without overriding AGORA_AGENT_ID", agent_id);
                println!("  Use it with:");
                println!("    agora dm {} <message>", agent_id);
                println!("    agora --room {} read", room_entry.label);
            }
        }

        Commands::Send { message, reply } => {
            let text = message.join(" ");
            if text.is_empty() {
                eprintln!("Usage: agora send <message>");
                process::exit(1);
            }
            match chat::send(&text, reply.as_deref(), room) {
                Ok(mid) => println!("  Sent [{}] (AES-256-GCM encrypted)", &mid[..6.min(mid.len())]),
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Read { tail } => {
            match chat::read("2h", 50, room) {
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
                    let header_room = if let Some(target) = room {
                        store::find_room(target)
                    } else {
                        store::get_active_room()
                    };
                    if let Some(header_room) = header_room {
                        println!("  --- {} ({} messages, AES-256-GCM) ---\n", header_room.label, msgs.len());
                    }
                    if let Ok(pinned) = chat::pins(room) {
                        if !pinned.is_empty() {
                            println!("  --- pinned ({}) ---\n", pinned.len());
                            for p in &pinned {
                                print_msg(p);
                            }
                            println!();
                        }
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
            match chat::check("5m", room) {
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

        Commands::Leave => {
            match chat::leave(room) {
                Ok(info) => {
                    println!("  Left room '{}'.", info["label"].as_str().unwrap_or("?"));
                    if info["daemon_stopped"].as_bool().unwrap_or(false) {
                        println!("  Daemon stopped.");
                    }
                    if let Some(active_room) = info["active_room"].as_str() {
                        println!("  Active room: {active_room}");
                    } else {
                        println!("  No rooms left.");
                    }
                }
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Info => {
            match chat::info(room) {
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

        Commands::Who { online } => {
            match chat::who(room, online) {
                Ok(members) => {
                    if members.is_empty() {
                        if online {
                            println!("  No one online (seen in last 5 minutes).");
                        } else {
                            println!("  No members tracked yet.");
                        }
                        return;
                    }
                    let me = store::get_agent_id();
                    let now_ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
                    println!("  {:<20} {:<12} {:<8} {:<10} Last seen", "Name", "Agent", "Role", "Status");
                    println!("  {:<20} {:<12} {:<8} {:<10} {}", "─".repeat(20), "─".repeat(12), "─".repeat(8), "─".repeat(10), "─".repeat(16));
                    for m in &members {
                        let role = format!("{:?}", m.role);
                        let is_me = if m.agent_id == me { " (you)" } else { "" };
                        let display = resolve_display_name(&m.agent_id);
                        let name = if display == m.agent_id { "".to_string() } else { display };
                        let status = if m.last_seen > 0 && now_ts - m.last_seen < 300 {
                            "\x1b[92monline\x1b[0m"
                        } else if m.last_seen > 0 {
                            "offline"
                        } else {
                            "unknown"
                        };
                        let seen = if m.last_seen > 0 {
                            let ago = now_ts - m.last_seen;
                            if ago < 60 { format!("{ago}s ago") }
                            else if ago < 3600 { format!("{}m ago", ago / 60) }
                            else { format!("{}h ago", ago / 3600) }
                        } else {
                            "never".to_string()
                        };
                        println!("  {:<20} {:<12} {:<8} {:<18} {seen}{is_me}", name, m.agent_id, role, status);
                    }
                }
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Heartbeat => {
            match chat::heartbeat(room) {
                Ok(()) => println!("  Heartbeat sent."),
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
            match chat::topic(&topic, room) {
                Ok(()) => println!("  Topic set: {topic}"),
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Promote { agent_id } => {
            match chat::promote(&agent_id, room) {
                Ok(()) => println!("  Promoted {agent_id} to admin."),
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Kick { agent_id } => {
            match chat::kick(&agent_id, room) {
                Ok(()) => println!("  Kicked {agent_id}."),
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Verify => {
            match chat::verify(room) {
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

        Commands::Search { query, from, after, before, regex: use_regex } => {
            let q = query.join(" ");
            if q.is_empty() {
                eprintln!("Usage: agora search <query> [--from <id>] [--after HH:MM] [--before HH:MM] [--regex]");
                process::exit(1);
            }
            let after_ts = after.and_then(|t| parse_time_arg(&t));
            let before_ts = before.and_then(|t| parse_time_arg(&t));
            match chat::search(&q, from.as_deref(), after_ts, before_ts, use_regex, room) {
                Ok(msgs) => {
                    if msgs.is_empty() {
                        println!("  No matches for '{q}'.");
                        return;
                    }
                    println!("  {} match(es) for '{q}':\n", msgs.len());
                    for m in &msgs {
                        print_msg(m);
                    }
                }
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Pin { message_id } => {
            match chat::pin(&message_id, room) {
                Ok((resolved_id, added)) => {
                    let short = &resolved_id[..6.min(resolved_id.len())];
                    if added {
                        println!("  Pinned [{short}].");
                    } else {
                        println!("  Already pinned [{short}].");
                    }
                }
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Unpin { message_id } => {
            match chat::unpin(&message_id, room) {
                Ok((resolved_id, removed)) => {
                    let short = &resolved_id[..6.min(resolved_id.len())];
                    if removed {
                        println!("  Unpinned [{short}].");
                    } else {
                        println!("  [{short}] was not pinned.");
                    }
                }
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Pins => {
            match chat::pins(room) {
                Ok(pinned) => {
                    if pinned.is_empty() {
                        println!("  (no pinned messages)");
                        return;
                    }
                    println!("  {} pinned message(s):\n", pinned.len());
                    for p in &pinned {
                        print_msg(p);
                    }
                }
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Thread { message_id } => {
            match chat::thread(&message_id, room) {
                Ok(items) => {
                    if items.is_empty() {
                        println!("  (no thread messages)");
                        return;
                    }
                    println!("  Thread for '{message_id}':\n");
                    for item in &items {
                        print_msg_with_depth(&item.env, item.depth);
                    }
                }
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Recap { since } => {
            match chat::recap(&since, room) {
                Ok(info) => {
                    let room_name = info["room"].as_str().unwrap_or("?");
                    let total = info["total_messages"].as_u64().unwrap_or(0);
                    println!("  ╔═══ Recap: {} ({} messages, last {}) ═══╗\n", room_name, total, since);

                    if total == 0 {
                        println!("  No activity.");
                        return;
                    }

                    // Time range
                    if let Some(range) = info["time_range"].as_object() {
                        let first = range["first"].as_u64().unwrap_or(0);
                        let last = range["last"].as_u64().unwrap_or(0);
                        println!("  Time: {} → {}", ts(first), ts(last));
                    }

                    // Agents
                    println!("\n  Agents:");
                    if let Some(agents) = info["agents"].as_array() {
                        for a in agents {
                            let id = a["id"].as_str().unwrap_or("?");
                            let count = a["messages"].as_u64().unwrap_or(0);
                            let bar = "█".repeat((count as usize).min(20));
                            println!("    {:<12} {:>3} msgs {}", id, count, bar);
                        }
                    }

                    // Keywords
                    if let Some(kws) = info["top_keywords"].as_array() {
                        if !kws.is_empty() {
                            println!("\n  Topics:");
                            let words: Vec<_> = kws.iter()
                                .filter_map(|k| k["word"].as_str())
                                .collect();
                            println!("    {}", words.join(", "));
                        }
                    }

                    println!("\n  ╚{}╝", "═".repeat(40));
                }
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::SendFile { path } => {
            match chat::send_file(&path, room) {
                Ok((file_id, size)) => {
                    println!("  Sent file [{file_id}] ({size} bytes, AES-256-GCM encrypted)");
                }
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Files => {
            match chat::list_files(room) {
                Ok(files) => {
                    if files.is_empty() {
                        println!("  (no files shared)");
                        return;
                    }
                    println!("  {:<10} {:<20} {:>10} {:<12} {}", "ID", "Filename", "Size", "From", "Time");
                    println!("  {:<10} {:<20} {:>10} {:<12} {}", "─".repeat(10), "─".repeat(20), "─".repeat(10), "─".repeat(12), "─".repeat(8));
                    for f in &files {
                        let fid = &f["file_id"].as_str().unwrap_or("?")[..6.min(f["file_id"].as_str().unwrap_or("?").len())];
                        let name = f["filename"].as_str().unwrap_or("?");
                        let size = f["size"].as_u64().unwrap_or(0);
                        let from = f["from"].as_str().unwrap_or("?");
                        let time = ts(f["ts"].as_u64().unwrap_or(0));
                        let size_str = if size > 1024 { format!("{}KB", size / 1024) } else { format!("{}B", size) };
                        println!("  {:<10} {:<20} {:>10} {:<12} {}", fid, name, size_str, from, time);
                    }
                }
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Download { file_id, out } => {
            match chat::download_file(&file_id, out.as_deref(), room) {
                Ok(path) => println!("  Downloaded to: {path}"),
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Daemon => {
            match chat::daemon(room) {
                Ok(pid) => {
                    let daemon_room = if let Some(target) = room {
                        store::find_room(target)
                    } else {
                        store::get_active_room()
                    };
                    if let Some(daemon_room) = daemon_room {
                        println!(
                            "  Daemon started (PID {pid}) for '{}'.\n  Notify flag: {}\n  Hook: agora notify --wake",
                            daemon_room.label,
                            store::notify_flag_path(&daemon_room.room_id).display()
                        );
                    } else {
                        println!("  Daemon started (PID {pid}).\n  Hook: agora notify --wake");
                    }
                }
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Notify { wake } => {
            match chat::notify("24h", room) {
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

        Commands::Stop => {
            match chat::stop_daemon(room) {
                Ok(()) => println!("  Daemon stopped."),
                Err(e) => eprintln!("  {e}"),
            }
        }

        Commands::Watch => {
            match selected_room(room) {
                Ok(watch_room) => {
                    println!("  Watching '{}' (AES-256-GCM, Ctrl+C to stop)", watch_room.label);
                    println!("  Auto-heartbeat every 2 minutes\n");
                    if let Ok(msgs) = chat::read("30m", 20, room) {
                        for m in &msgs {
                            print_msg(m);
                        }
                        if !msgs.is_empty() {
                            println!("  ─── live ───\n");
                        }
                    }
                    if let Err(e) = chat::watch(room, 120, |env| {
                        print_msg(env);
                    }) {
                        eprintln!("  Error: {e}");
                        process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("  {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Hub { log } => {
            let active_room = match selected_room(room) {
                Ok(room) => room,
                Err(e) => {
                    eprintln!("  {e}");
                    process::exit(1);
                }
            };
            let room_key = crypto::derive_room_key(&active_room.secret, &active_room.room_id);

            println!("\x1b[1m  ╔══════════════════════════════════════════╗\x1b[0m");
            println!("\x1b[1m  ║  AGORA HUB — Always-On Agent Relay      ║\x1b[0m");
            println!("\x1b[1m  ╚══════════════════════════════════════════╝\x1b[0m");
            println!("  Room:        {}", active_room.label);
            println!("  ID:          {}", active_room.room_id);
            println!("  Encryption:  AES-256-GCM + HKDF-SHA256");
            println!("  Fingerprint: {}", crypto::fingerprint(&room_key));
            println!("  Agent:       {}", store::get_agent_id());
            if let Some(ref lf) = log {
                println!("  Log:         {lf}");
            }
            println!("  Heartbeat:   every 2 minutes");
            println!("  Status:      \x1b[92mLISTENING\x1b[0m (Ctrl+C to stop)\n");

            // Print recent history
            if let Ok(msgs) = chat::read("1h", 30, room) {
                if !msgs.is_empty() {
                    println!("  ─── recent ({} messages) ───\n", msgs.len());
                    for m in &msgs {
                        print_msg(m);
                    }
                    println!("\n  ─── live ───\n");
                }
            }

            let mut msg_count: u64 = 0;
            let log_file = log.clone();

            loop {
                let _ = chat::watch(room, 120, |env| {
                    msg_count += 1;
                    print_msg(env);

                    // Append to log file if specified
                    if let Some(ref path) = log_file {
                        use std::io::Write;
                        if let Ok(mut f) = std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(path)
                        {
                            let ts = env["ts"].as_u64().unwrap_or(0);
                            let from = env["from"].as_str().unwrap_or("?");
                            let text = env["text"].as_str().unwrap_or("");
                            let _ = writeln!(f, "[{ts}] {from}: {text}");
                        }
                    }
                });

                // SSE disconnected — reconnect
                eprintln!("  \x1b[33m[hub] Connection lost. Reconnecting in 5s... ({msg_count} messages received so far)\x1b[0m");
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
        }

        Commands::Mcp => {
            mcp::run();
        }

        Commands::Status => {
            match chat::read_status(room) {
                Ok(items) => {
                    if items.is_empty() {
                        println!("  (no messages with receipts)");
                        return;
                    }
                    for item in &items {
                        let mid = &item["id"].as_str().unwrap_or("?")[..6.min(item["id"].as_str().unwrap_or("?").len())];
                        let text = item["text"].as_str().unwrap_or("");
                        let time = ts(item["ts"].as_u64().unwrap_or(0));
                        let readers = item["read_by"].as_array()
                            .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(", "))
                            .unwrap_or_default();
                        let check = if readers.is_empty() { "  " } else { "\u{2713}\u{2713}" };
                        println!("  [{mid}] {time} {check} {text}");
                        if !readers.is_empty() {
                            println!("         Read by: {readers}");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Profile { name, role } => {
            match chat::set_profile(name.as_deref(), role.as_deref(), room) {
                Ok(()) => {
                    let n = name.as_deref().unwrap_or("(unchanged)");
                    let r = role.as_deref().unwrap_or("(unchanged)");
                    println!("  Profile set: {n} ({r})");
                }
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Whois { agent_id } => {
            match chat::whois(&agent_id, room) {
                Ok(Some(p)) => {
                    println!("  Agent:   {}", p.agent_id);
                    if let Some(name) = &p.name {
                        println!("  Name:    {name}");
                    }
                    if let Some(role) = &p.role {
                        println!("  Role:    {role}");
                    }
                    let ago = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() - p.updated_at;
                    println!("  Updated: {}s ago", ago);
                }
                Ok(None) => {
                    println!("  No profile found for '{agent_id}'.");
                }
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Timeline { since } => {
            match chat::timeline(&since, room) {
                Ok(events) => {
                    if events.is_empty() {
                        println!("  (no activity in last {since})");
                        return;
                    }
                    println!("  Timeline (last {since}, {} events):\n", events.len());
                    for evt in &events {
                        let time = ts(evt["ts"].as_u64().unwrap_or(0));
                        let from = evt["from"].as_str().unwrap_or("?");
                        let etype = evt["event_type"].as_str().unwrap_or("?");
                        let icon = match etype {
                            "join" => "+",
                            "file" => "F",
                            "profile" => "P",
                            "reaction" => "R",
                            "topic" => "T",
                            "admin" => "A",
                            "kick" => "X",
                            "scheduled" => "S",
                            _ => " ",
                        };
                        let text = evt["text"].as_str().unwrap_or("");
                        let short = &text[..60.min(text.len())];
                        let name = resolve_display_name(from);
                        println!("  {time} [{icon}] {name}: {short}");
                    }
                }
                Err(e) => { eprintln!("  Error: {e}"); process::exit(1); }
            }
        }

        Commands::Digest { since, out } => {
            match chat::digest(&since, room) {
                Ok(report) => {
                    if let Some(path) = out {
                        std::fs::write(&path, &report).unwrap_or_else(|e| {
                            eprintln!("  Error: {e}"); process::exit(1);
                        });
                        println!("  Digest written to: {path}");
                    } else {
                        println!("{report}");
                    }
                }
                Err(e) => { eprintln!("  Error: {e}"); process::exit(1); }
            }
        }

        Commands::Alias { agent_id, name } => {
            if let Some(n) = name {
                store::set_alias(&agent_id, &n);
                println!("  {agent_id} → {n}");
            } else {
                store::remove_alias(&agent_id);
                println!("  Alias for {agent_id} removed.");
            }
        }

        Commands::Aliases => {
            let aliases = store::load_aliases();
            if aliases.is_empty() {
                println!("  (no aliases set)");
                println!("  Set one: agora alias <agent-id> <name>");
                return;
            }
            println!("  {:<16} → Name", "Agent ID");
            println!("  {:<16}   {}", "─".repeat(16), "─".repeat(20));
            let mut sorted: Vec<_> = aliases.into_iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            for (id, name) in &sorted {
                println!("  {:<16} → {name}", id);
            }
        }

        Commands::WebhookAdd { url } => {
            match chat::add_webhook(&url, room) {
                Ok(id) => println!("  Webhook [{id}] added: {url}"),
                Err(e) => { eprintln!("  Error: {e}"); process::exit(1); }
            }
        }

        Commands::WebhookList => {
            match chat::list_webhooks(room) {
                Ok(hooks) => {
                    if hooks.is_empty() {
                        println!("  (no webhooks)");
                        return;
                    }
                    for h in &hooks {
                        println!("  [{}] {}", h.id, h.url);
                    }
                }
                Err(e) => { eprintln!("  Error: {e}"); process::exit(1); }
            }
        }

        Commands::WebhookRemove { id } => {
            match chat::remove_webhook(&id, room) {
                Ok(true) => println!("  Webhook [{id}] removed."),
                Ok(false) => println!("  Webhook [{id}] not found."),
                Err(e) => { eprintln!("  Error: {e}"); process::exit(1); }
            }
        }

        Commands::Mentions { agent, since } => {
            match chat::mentions(agent.as_deref(), &since, room) {
                Ok(msgs) => {
                    if msgs.is_empty() {
                        println!("  (no mentions in last {since})");
                        return;
                    }
                    println!("  {} mention(s) in last {since}:\n", msgs.len());
                    for m in &msgs {
                        print_msg(m);
                    }
                }
                Err(e) => { eprintln!("  Error: {e}"); process::exit(1); }
            }
        }

        Commands::Links { since } => {
            match chat::links(&since, room) {
                Ok(links) => {
                    if links.is_empty() {
                        println!("  (no URLs shared in last {since})");
                        return;
                    }
                    println!("  {} URL(s) shared in last {since}:\n", links.len());
                    for l in &links {
                        let url = l["url"].as_str().unwrap_or("?");
                        let from = l["from"].as_str().unwrap_or("?");
                        let time = ts(l["ts"].as_u64().unwrap_or(0));
                        println!("  {time} [{from}] {url}");
                    }
                }
                Err(e) => { eprintln!("  Error: {e}"); process::exit(1); }
            }
        }

        Commands::Encrypt { text, file } => {
            let data = if let Some(path) = file {
                std::fs::read(&path).unwrap_or_else(|e| {
                    eprintln!("  Error reading {path}: {e}");
                    process::exit(1);
                })
            } else if let Some(t) = text {
                t.into_bytes()
            } else {
                eprintln!("Usage: agora encrypt <text> or agora encrypt --file <path>");
                process::exit(1);
            };
            match chat::encrypt_data(&data, room) {
                Ok(b64) => println!("{b64}"),
                Err(e) => { eprintln!("  Error: {e}"); process::exit(1); }
            }
        }

        Commands::Decrypt { ciphertext, out } => {
            match chat::decrypt_data(&ciphertext, room) {
                Ok(data) => {
                    if let Some(path) = out {
                        std::fs::write(&path, &data).unwrap_or_else(|e| {
                            eprintln!("  Error writing {path}: {e}");
                            process::exit(1);
                        });
                        println!("  Decrypted to: {path}");
                    } else {
                        print!("{}", String::from_utf8_lossy(&data));
                    }
                }
                Err(e) => { eprintln!("  Error: {e}"); process::exit(1); }
            }
        }

        Commands::Changelog { since } => {
            match chat::changelog(&since, room) {
                Ok(entries) => {
                    if entries.is_empty() {
                        println!("  (no changelog entries in last {since})");
                        return;
                    }
                    println!("  Changelog (last {since}, {} entries):\n", entries.len());
                    for e in &entries {
                        let time = ts(e["ts"].as_u64().unwrap_or(0));
                        let from = e["from"].as_str().unwrap_or("?");
                        let text = e["text"].as_str().unwrap_or("");
                        let short = &text[..80.min(text.len())];
                        println!("  {time} [{from}] {short}");
                    }
                }
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Test => {
            match chat::healthcheck(room) {
                Ok(checks) => {
                    println!("  Agora Health Check\n");
                    let mut all_ok = true;
                    for (name, ok, detail) in &checks {
                        let icon = if *ok { "\x1b[92m\u{2713}\x1b[0m" } else { "\x1b[91m\u{2717}\x1b[0m" };
                        println!("  {icon} {name:<20} {detail}");
                        if !ok { all_ok = false; }
                    }
                    println!();
                    if all_ok {
                        println!("  \x1b[92mAll checks passed.\x1b[0m");
                    } else {
                        println!("  \x1b[91mSome checks failed.\x1b[0m");
                        process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Schedule { delay, message } => {
            let text = message.join(" ");
            if text.is_empty() {
                eprintln!("Usage: agora schedule --delay 5m <message>");
                process::exit(1);
            }
            let now_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            let delay_secs = if let Some(m) = delay.strip_suffix('m') {
                m.parse::<u64>().unwrap_or(5) * 60
            } else if let Some(h) = delay.strip_suffix('h') {
                h.parse::<u64>().unwrap_or(1) * 3600
            } else if let Some(s) = delay.strip_suffix('s') {
                s.parse::<u64>().unwrap_or(60)
            } else {
                delay.parse::<u64>().unwrap_or(300)
            };
            let deliver_at = now_ts + delay_secs;
            match chat::schedule_message(&text, deliver_at, room) {
                Ok(id) => {
                    let dt = chrono::DateTime::from_timestamp(deliver_at as i64, 0)
                        .map(|d| d.format("%H:%M:%S").to_string())
                        .unwrap_or_default();
                    println!("  Scheduled [{id}] for delivery at {dt} (in {delay}).");
                }
                Err(e) => { eprintln!("  Error: {e}"); process::exit(1); }
            }
        }

        Commands::Scheduled => {
            match chat::list_scheduled(room) {
                Ok(items) => {
                    if items.is_empty() {
                        println!("  (no scheduled messages)");
                        return;
                    }
                    for item in &items {
                        let id = item["id"].as_str().unwrap_or("?");
                        let text = item["text"].as_str().unwrap_or("");
                        let at = item["deliver_at"].as_u64().unwrap_or(0);
                        let dt = chrono::DateTime::from_timestamp(at as i64, 0)
                            .map(|d| d.format("%H:%M:%S").to_string())
                            .unwrap_or_default();
                        let short = &text[..40.min(text.len())];
                        println!("  [{id}] at {dt}: {short}");
                    }
                }
                Err(e) => { eprintln!("  Error: {e}"); process::exit(1); }
            }
        }

        Commands::Compact { keep_hours } => {
            match chat::compact(keep_hours, room) {
                Ok((archived, kept)) => {
                    if archived == 0 {
                        println!("  Nothing to compact ({kept} messages, all within {keep_hours}h).");
                    } else {
                        println!("  Compacted: {archived} messages archived, {kept} kept (last {keep_hours}h).");
                    }
                }
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Grep { query, regex: use_regex } => {
            let q = query.join(" ");
            if q.is_empty() {
                eprintln!("Usage: agora grep <query> [-e]");
                process::exit(1);
            }
            match chat::grep(&q, use_regex) {
                Ok(results) => {
                    if results.is_empty() {
                        println!("  No matches for '{q}' across any room.");
                        return;
                    }
                    println!("  {} match(es) for '{q}' across all rooms:\n", results.len());
                    let mut last_room = String::new();
                    for (room_label, msg) in &results {
                        if *room_label != last_room {
                            println!("  --- {room_label} ---");
                            last_room = room_label.clone();
                        }
                        print_msg(msg);
                    }
                }
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Broadcast { message } => {
            let text = message.join(" ");
            if text.is_empty() {
                eprintln!("Usage: agora broadcast <message>");
                process::exit(1);
            }
            match chat::broadcast(&text) {
                Ok(results) => {
                    for (label, mid) in &results {
                        if mid.starts_with("error") {
                            println!("  {label}: {mid}");
                        } else {
                            let short = &mid[..6.min(mid.len())];
                            println!("  {label}: sent [{short}]");
                        }
                    }
                    println!("  Broadcast to {} rooms.", results.len());
                }
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Stats => {
            match chat::stats(room) {
                Ok(s) => {
                    let room_name = s["room"].as_str().unwrap_or("?");
                    println!("  ╔═══ Stats: {} ═══╗\n", room_name);
                    println!("  Messages:   {}", s["total_messages"]);
                    println!("  Agents:     {}", s["total_agents"]);
                    println!("  Characters: {}", s["total_characters"]);
                    println!("  Files:      {}", s["total_files"]);
                    println!("  Reactions:  {}", s["total_reactions"]);
                    println!("  Receipts:   {}", s["total_receipts"]);
                    println!("  Pins:       {}", s["total_pins"]);
                    println!("  Profiles:   {}", s["total_profiles"]);

                    if let Some(peak) = s["peak_hour"].as_object() {
                        let pts = peak["ts"].as_u64().unwrap_or(0);
                        println!("\n  Peak hour:  {} ({} msgs)", ts(pts), peak["messages"]);
                    }

                    println!("\n  Top agents:");
                    if let Some(agents) = s["agents"].as_array() {
                        for a in agents.iter().take(10) {
                            let id = a["id"].as_str().unwrap_or("?");
                            let count = a["messages"].as_u64().unwrap_or(0);
                            let bar = "█".repeat((count as usize).min(30));
                            let name = resolve_display_name(id);
                            println!("    {:<24} {:>4} {}", name, count, bar);
                        }
                    }
                    println!("\n  ╚{}╝", "═".repeat(30));
                }
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Mute { agent_id } => {
            match chat::mute(&agent_id, room) {
                Ok(()) => println!("  Muted {agent_id}. Their messages will be hidden."),
                Err(e) => { eprintln!("  Error: {e}"); process::exit(1); }
            }
        }

        Commands::Unmute { agent_id } => {
            match chat::unmute(&agent_id, room) {
                Ok(()) => println!("  Unmuted {agent_id}."),
                Err(e) => { eprintln!("  Error: {e}"); process::exit(1); }
            }
        }

        Commands::Export { since, out } => {
            match chat::export(&since, out.as_deref(), room) {
                Ok((path, count)) => {
                    println!("  Exported {count} messages to: {path}");
                }
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::React { message_id, emoji } => {
            match chat::react(&message_id, &emoji, room) {
                Ok(()) => println!("  Reacted {emoji} to [{message_id}]"),
                Err(e) => {
                    eprintln!("  Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Serve { port } => {
            serve::start(port);
        }

        Commands::Id => {
            println!("{}", store::get_agent_id());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{dm_room_label, parse_invite_token, targeted_invite_token, InviteTokenPayload};
    use crate::store::{self, Role};

    #[test]
    fn dm_room_label_is_stable_and_symmetric() {
        let first = dm_room_label("agent-b", "agent-a").unwrap();
        let second = dm_room_label("agent-a", "agent-b").unwrap();
        assert_eq!(first, "dm-agent-a-agent-b");
        assert_eq!(first, second);
    }

    #[test]
    fn dm_room_label_rejects_self_dm() {
        let err = dm_room_label("agent-a", "agent-a").unwrap_err();
        assert_eq!(err, "Cannot open a DM with yourself.");
    }

    #[test]
    fn targeted_dm_invite_round_trips() {
        let room = store::add_room("ag-dm-test", "secret", "dm-a-b", Role::Admin);
        let token = targeted_invite_token(&room, "agent-b", "dm");
        let parsed = parse_invite_token(&token).unwrap();
        assert_eq!(
            parsed,
            InviteTokenPayload {
                room_id: "ag-dm-test".to_string(),
                secret: "secret".to_string(),
                label: "dm-a-b".to_string(),
                target_agent_id: Some("agent-b".to_string()),
                purpose: Some("dm".to_string()),
            }
        );
    }

    #[test]
    fn legacy_invite_token_still_parses() {
        let token = "agr_YWctcm9vbTpzZWNyZXQ6bGFiZWw";
        let parsed = parse_invite_token(token).unwrap();
        assert_eq!(parsed.room_id, "ag-room");
        assert_eq!(parsed.secret, "secret");
        assert_eq!(parsed.label, "label");
        assert_eq!(parsed.target_agent_id, None);
    }
}
