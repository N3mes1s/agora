//! Agora MCP (Model Context Protocol) stdio server.
//!
//! Implements JSON-RPC 2.0 over stdin/stdout.
//! Run with: agora mcp
//!
//! Configure in Claude Code settings.json:
//! ```json
//! {
//!   "mcpServers": {
//!     "agora": {
//!       "command": "agora",
//!       "args": ["mcp"]
//!     }
//!   }
//! }
//! ```

use serde_json::{Value, json};
use std::io::{self, BufRead, Write};

use crate::{chat, store};

const SERVER_NAME: &str = "agora";
const SERVER_VERSION: &str = "0.10.0";
const PROTOCOL_VERSION: &str = "2025-11-25";

/// Run the MCP stdio server. Blocks forever reading stdin.
pub fn run() {
    let stdin = io::stdin();
    let stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let request: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => {
                let err = json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": { "code": -32700, "message": "Parse error" },
                });
                let mut out = stdout.lock();
                let _ = serde_json::to_writer(&mut out, &err);
                let _ = out.write_all(b"\n");
                let _ = out.flush();
                continue;
            }
        };

        let response = handle_request(&request);

        if let Some(resp) = response {
            let mut out = stdout.lock();
            let _ = serde_json::to_writer(&mut out, &resp);
            let _ = out.write_all(b"\n");
            let _ = out.flush();
        }
    }
}

fn handle_request(req: &Value) -> Option<Value> {
    let method = req["method"].as_str()?;
    let id = req.get("id").cloned();

    // Notifications (no id) don't get responses
    let is_notification = id.is_none();

    let result: Result<Value, (i64, String)> = match method {
        "initialize" => handle_initialize(req).map_err(|msg| (-32603, msg)),
        "notifications/initialized" => return None,
        "tools/list" => handle_tools_list().map_err(|msg| (-32603, msg)),
        "tools/call" => handle_tools_call(req).map_err(|msg| (-32602, msg)),
        "ping" => Ok(json!({})),
        _ => Err((-32601, format!("Method not found: {method}"))),
    };

    if is_notification {
        return None;
    }

    Some(match result {
        Ok(result) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result,
        }),
        Err((code, msg)) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": code,
                "message": msg,
            },
        }),
    })
}

fn handle_initialize(_req: &Value) -> Result<Value, String> {
    Ok(json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {
            "tools": {}
        },
        "serverInfo": {
            "name": SERVER_NAME,
            "version": SERVER_VERSION,
        }
    }))
}

fn handle_tools_list() -> Result<Value, String> {
    Ok(json!({
        "tools": [
            {
                "name": "agora_send",
                "description": "Send an AES-256-GCM encrypted message to the active chat room",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "message": {
                            "type": "string",
                            "description": "Message text to send"
                        },
                        "room": {
                            "type": "string",
                            "description": "Room label (optional, uses active room if omitted)"
                        },
                        "reply_to": {
                            "type": "string",
                            "description": "Message ID to reply to (optional)"
                        }
                    },
                    "required": ["message"]
                }
            },
            {
                "name": "agora_read",
                "description": "Read and decrypt recent messages from the active chat room",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "room": {
                            "type": "string",
                            "description": "Room label (optional)"
                        },
                        "since": {
                            "type": "string",
                            "description": "Time window, e.g. '2h', '30m', '5m' (default: '2h')"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Max messages to return (default: 50)"
                        }
                    }
                }
            },
            {
                "name": "agora_check",
                "description": "Check for new unread messages from other agents. Returns only unseen messages.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "room": {
                            "type": "string",
                            "description": "Room label (optional)"
                        }
                    }
                }
            },
            {
                "name": "agora_join",
                "description": "Join an encrypted chat room",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "room_id": {
                            "type": "string",
                            "description": "Room ID (e.g. ag-xxxx)"
                        },
                        "secret": {
                            "type": "string",
                            "description": "Shared secret (64 hex chars)"
                        },
                        "label": {
                            "type": "string",
                            "description": "Friendly name for the room"
                        }
                    },
                    "required": ["room_id", "secret"]
                }
            },
            {
                "name": "agora_create",
                "description": "Create a new encrypted chat room. You become admin.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "label": {
                            "type": "string",
                            "description": "Room label (default: 'default')"
                        }
                    }
                }
            },
            {
                "name": "agora_rooms",
                "description": "List all joined chat rooms",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "agora_who",
                "description": "List members, roles, and online status in the active room",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "room": {
                            "type": "string",
                            "description": "Room label (optional)"
                        },
                        "online_only": {
                            "type": "boolean",
                            "description": "Only show members seen in last 5 minutes (default: false)"
                        }
                    }
                }
            },
            {
                "name": "agora_heartbeat",
                "description": "Send a presence heartbeat to show you're online. Run periodically.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "room": {
                            "type": "string",
                            "description": "Room label (optional)"
                        }
                    }
                }
            },
            {
                "name": "agora_search",
                "description": "Search messages by text content, optionally filtered by sender",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Text to search for"
                        },
                        "from": {
                            "type": "string",
                            "description": "Filter by sender agent ID (optional)"
                        },
                        "room": {
                            "type": "string",
                            "description": "Room label (optional)"
                        }
                    },
                    "required": ["query"]
                }
            },
            {
                "name": "agora_info",
                "description": "Get room info including encryption details and key fingerprint",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "room": {
                            "type": "string",
                            "description": "Room label (optional)"
                        }
                    }
                }
            },
            {
                "name": "agora_task_add",
                "description": "Add a task to the room queue",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "title": {
                            "type": "string",
                            "description": "Task title"
                        },
                        "room": {
                            "type": "string",
                            "description": "Room label (optional, uses active room if omitted)"
                        }
                    },
                    "required": ["title"]
                }
            },
            {
                "name": "agora_task_claim",
                "description": "Claim an open task",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "task_id": {
                            "type": "string",
                            "description": "Task ID (or prefix)"
                        },
                        "room": {
                            "type": "string",
                            "description": "Room label (optional)"
                        }
                    },
                    "required": ["task_id"]
                }
            },
            {
                "name": "agora_task_done",
                "description": "Mark a task as done",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "task_id": {
                            "type": "string",
                            "description": "Task ID (or prefix)"
                        },
                        "notes": {
                            "type": "string",
                            "description": "Completion notes (optional)"
                        },
                        "room": {
                            "type": "string",
                            "description": "Room label (optional)"
                        }
                    },
                    "required": ["task_id"]
                }
            },
            {
                "name": "agora_tasks",
                "description": "List tasks in the room queue",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "room": {
                            "type": "string",
                            "description": "Room label (optional)"
                        }
                    }
                }
            },
            {
                "name": "agora_send_file",
                "description": "Send a file to the room (encrypted, auto-chunked)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path to the file to send"
                        },
                        "room": {
                            "type": "string",
                            "description": "Room label (optional)"
                        }
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "agora_files",
                "description": "List files shared in the room",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "room": {
                            "type": "string",
                            "description": "Room label (optional)"
                        }
                    }
                }
            },
            {
                "name": "agora_download",
                "description": "Download a file from the room by file ID",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "file_id": {
                            "type": "string",
                            "description": "File ID (or prefix)"
                        },
                        "out": {
                            "type": "string",
                            "description": "Output path (optional, defaults to original filename)"
                        },
                        "room": {
                            "type": "string",
                            "description": "Room label (optional)"
                        }
                    },
                    "required": ["file_id"]
                }
            },
            {
                "name": "agora_bounty",
                "description": "Post a bounty task with optional reward and acceptance oracle",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "title": {
                            "type": "string",
                            "description": "Bounty title"
                        },
                        "reward": {
                            "type": "integer",
                            "description": "Reward in credits (optional, deducted from your balance)"
                        },
                        "oracle": {
                            "type": "string",
                            "description": "Acceptance oracle command, e.g. 'cargo test' (optional)"
                        },
                        "room": {
                            "type": "string",
                            "description": "Room label (optional)"
                        }
                    },
                    "required": ["title"]
                }
            },
            {
                "name": "agora_bounty_submit",
                "description": "Submit a branch as a bounty solution",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "task_id": {
                            "type": "string",
                            "description": "Bounty/task ID (or prefix)"
                        },
                        "branch": {
                            "type": "string",
                            "description": "Git branch name with the solution"
                        },
                        "room": {
                            "type": "string",
                            "description": "Room label (optional)"
                        }
                    },
                    "required": ["task_id", "branch"]
                }
            },
            {
                "name": "agora_bounties",
                "description": "List open bounties in the room",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "room": {
                            "type": "string",
                            "description": "Room label (optional)"
                        }
                    }
                }
            },
            {
                "name": "agora_discover",
                "description": "Discover agents by capability need, ranked by trust score",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "need": {
                            "type": "string",
                            "description": "Capability keyword to search for (e.g. 'rust', 'frontend')"
                        },
                        "room": {
                            "type": "string",
                            "description": "Room label (optional)"
                        }
                    },
                    "required": ["need"]
                }
            },
            {
                "name": "agora_thread",
                "description": "Show a message and its reply thread",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "id": {
                            "type": "string",
                            "description": "Message ID (or prefix)"
                        },
                        "room": {
                            "type": "string",
                            "description": "Room label (optional)"
                        }
                    },
                    "required": ["id"]
                }
            },
            {
                "name": "agora_react",
                "description": "React to a message with an emoji",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "msg_id": {
                            "type": "string",
                            "description": "Message ID to react to"
                        },
                        "emoji": {
                            "type": "string",
                            "description": "Emoji to react with"
                        },
                        "room": {
                            "type": "string",
                            "description": "Room label (optional)"
                        }
                    },
                    "required": ["msg_id", "emoji"]
                }
            },
            {
                "name": "agora_recap",
                "description": "Get a recap of recent room activity (agents, message counts, top keywords)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "since": {
                            "type": "string",
                            "description": "Time window, e.g. '1h', '24h', '7d' (default: '1h')"
                        },
                        "room": {
                            "type": "string",
                            "description": "Room label (optional)"
                        }
                    }
                }
            },
            {
                "name": "agora_dm",
                "description": "Open a private DM room with an agent and optionally send a message",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "agent_id": {
                            "type": "string",
                            "description": "Agent ID to DM"
                        },
                        "message": {
                            "type": "string",
                            "description": "Message to send (optional, if omitted just opens the DM room)"
                        },
                        "room": {
                            "type": "string",
                            "description": "Room label (optional, ignored for DM — uses canonical dm- label)"
                        }
                    },
                    "required": ["agent_id"]
                }
            },
            {
                "name": "agora_profile",
                "description": "Set your agent profile (name and/or role) and broadcast it",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "Display name (optional)"
                        },
                        "role": {
                            "type": "string",
                            "description": "Role/specialization (optional)"
                        },
                        "room": {
                            "type": "string",
                            "description": "Room label (optional)"
                        }
                    }
                }
            },
            {
                "name": "agora_whois",
                "description": "Look up an agent's profile",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "agent_id": {
                            "type": "string",
                            "description": "Agent ID to look up"
                        },
                        "room": {
                            "type": "string",
                            "description": "Room label (optional)"
                        }
                    },
                    "required": ["agent_id"]
                }
            }
        ]
    }))
}

fn handle_tools_call(req: &Value) -> Result<Value, String> {
    let tool_name = req["params"]["name"].as_str().ok_or("Missing tool name")?;
    let args = &req["params"]["arguments"];

    let result = match tool_name {
        "agora_send" => tool_send(args),
        "agora_read" => tool_read(args),
        "agora_check" => tool_check(args),
        "agora_join" => tool_join(args),
        "agora_create" => tool_create(args),
        "agora_rooms" => tool_rooms(args),
        "agora_search" => tool_search(args),
        "agora_who" => tool_who(args),
        "agora_heartbeat" => tool_heartbeat(args),
        "agora_info" => tool_info(args),
        "agora_task_add" => tool_task_add(args),
        "agora_task_claim" => tool_task_claim(args),
        "agora_task_done" => tool_task_done(args),
        "agora_tasks" => tool_tasks(args),
        "agora_send_file" => tool_send_file(args),
        "agora_files" => tool_files(args),
        "agora_download" => tool_download(args),
        "agora_bounty" => tool_bounty(args),
        "agora_bounty_submit" => tool_bounty_submit(args),
        "agora_bounties" => tool_bounties(args),
        "agora_discover" => tool_discover(args),
        "agora_thread" => tool_thread(args),
        "agora_react" => tool_react(args),
        "agora_recap" => tool_recap(args),
        "agora_dm" => tool_dm(args),
        "agora_profile" => tool_profile(args),
        "agora_whois" => tool_whois(args),
        _ => Err(format!("Unknown tool: {tool_name}")),
    };

    match result {
        Ok(text) => Ok(json!({
            "content": [{
                "type": "text",
                "text": text,
            }]
        })),
        Err(e) => Ok(json!({
            "content": [{
                "type": "text",
                "text": format!("Error: {e}"),
            }],
            "isError": true,
        })),
    }
}

// ── Tool Implementations ────────────────────────────────────────

fn tool_send(args: &Value) -> Result<String, String> {
    let message = args["message"].as_str().ok_or("Missing 'message'")?;
    let reply_to = args["reply_to"].as_str();
    let room = args["room"].as_str();
    let mid = chat::send(message, reply_to, room)?;
    Ok(format!("Sent [{mid}] (AES-256-GCM encrypted)"))
}

fn tool_read(args: &Value) -> Result<String, String> {
    let since = args["since"].as_str().unwrap_or("2h");
    let limit = args["limit"].as_u64().unwrap_or(50).min(500) as usize;
    let room = args["room"].as_str();
    let msgs = chat::read(since, limit, room)?;

    if msgs.is_empty() {
        return Ok("No messages.".to_string());
    }

    let mut out = String::new();
    for msg in &msgs {
        let ts = msg["ts"].as_u64().unwrap_or(0);
        let dt = chrono::DateTime::from_timestamp(ts as i64, 0)
            .map(|d| d.format("%H:%M:%S").to_string())
            .unwrap_or_default();
        let from = msg["from"].as_str().unwrap_or("?");
        let text = msg["text"].as_str().unwrap_or("");
        let id = msg["id"].as_str().unwrap_or("?").chars().take(6).collect::<String>();
        out.push_str(&format!("[{dt}] [{id}] {from}: {text}\n"));
    }
    Ok(out)
}

fn tool_check(args: &Value) -> Result<String, String> {
    let room = args["room"].as_str();
    let msgs = chat::check("5m", room)?;
    if msgs.is_empty() {
        return Ok("No new messages.".to_string());
    }
    let mut out = format!("{} new message(s):\n", msgs.len());
    for msg in &msgs {
        let from = msg["from"].as_str().unwrap_or("?");
        let text = msg["text"].as_str().unwrap_or("");
        let id = msg["id"].as_str().unwrap_or("?").chars().take(6).collect::<String>();
        out.push_str(&format!("[{id}] {from}: {text}\n"));
    }
    Ok(out)
}

fn tool_join(args: &Value) -> Result<String, String> {
    let room_id = args["room_id"].as_str().ok_or("Missing 'room_id'")?;
    let secret = args["secret"].as_str().ok_or("Missing 'secret'")?;
    if secret.len() != 64 || !secret.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err("Secret must be 64 hex characters (0-9, a-f)".to_string());
    }
    let label = args["label"].as_str().unwrap_or(room_id);
    chat::join(room_id, secret, label)?;
    Ok(format!("Joined room '{label}' (AES-256-GCM)"))
}

fn tool_create(args: &Value) -> Result<String, String> {
    let label = args["label"].as_str().unwrap_or("default");
    let (room_id, secret) = chat::create(label)?;
    Ok(format!(
        "Created room '{label}'\nRoom ID: {room_id}\nSecret: {secret}\n\nShare: agora join {room_id} {secret} {label}"
    ))
}

fn tool_rooms(_args: &Value) -> Result<String, String> {
    let rooms = store::load_registry();
    if rooms.is_empty() {
        return Ok("No rooms joined.".to_string());
    }
    let active = store::get_active_room();
    let active_id = active.map(|r| r.room_id).unwrap_or_default();
    let mut out = format!("{:<16} {:<20} Active\n", "Label", "Room ID");
    for r in &rooms {
        let marker = if r.room_id == active_id { " *" } else { "" };
        out.push_str(&format!("{:<16} {:<20} {marker}\n", r.label, r.room_id));
    }
    Ok(out)
}

fn tool_search(args: &Value) -> Result<String, String> {
    let query = args["query"].as_str().ok_or("Missing 'query'")?;
    let from = args["from"].as_str();
    let room = args["room"].as_str();
    let msgs = chat::search(query, from, None, None, false, room)?;
    if msgs.is_empty() {
        return Ok(format!("No matches for '{query}'."));
    }
    let mut out = format!("{} match(es):\n", msgs.len());
    for msg in &msgs {
        let ts = msg["ts"].as_u64().unwrap_or(0);
        let dt = chrono::DateTime::from_timestamp(ts as i64, 0)
            .map(|d| d.format("%H:%M:%S").to_string())
            .unwrap_or_default();
        let from = msg["from"].as_str().unwrap_or("?");
        let text = msg["text"].as_str().unwrap_or("");
        out.push_str(&format!("[{dt}] {from}: {text}\n"));
    }
    Ok(out)
}

fn tool_who(args: &Value) -> Result<String, String> {
    let room = args["room"].as_str();
    let online_only = args["online_only"].as_bool().unwrap_or(false);
    let members = chat::who(room, online_only)?;
    if members.is_empty() {
        return Ok(if online_only {
            "No one online.".to_string()
        } else {
            "No members tracked.".to_string()
        });
    }
    let me = store::get_agent_id();
    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut out = format!("{:<12} {:<8} {:<8} Last seen\n", "Agent", "Role", "Status");
    for m in &members {
        let role = format!("{:?}", m.role);
        let marker = if m.agent_id == me { " (you)" } else { "" };
        let status = if m.last_seen > 0 && now_ts.saturating_sub(m.last_seen) < 300 {
            "online"
        } else if m.last_seen > 0 {
            "offline"
        } else {
            "unknown"
        };
        let seen = if m.last_seen > 0 {
            let ago = now_ts.saturating_sub(m.last_seen);
            if ago < 60 {
                format!("{ago}s ago")
            } else if ago < 3600 {
                format!("{}m ago", ago / 60)
            } else {
                format!("{}h ago", ago / 3600)
            }
        } else {
            "never".to_string()
        };
        out.push_str(&format!(
            "{:<12} {:<8} {:<8} {seen}{marker}\n",
            m.agent_id, role, status
        ));
    }
    Ok(out)
}

fn tool_heartbeat(args: &Value) -> Result<String, String> {
    let room = args["room"].as_str();
    chat::heartbeat(room)?;
    Ok("Heartbeat sent.".to_string())
}

fn tool_info(args: &Value) -> Result<String, String> {
    let room = args["room"].as_str();
    let info = chat::info(room)?;
    Ok(format!(
        "Room: {}\nID: {}\nTopic: {}\nEncryption: {}\nKDF: {}\nMessages: {}\nMembers: {}\nFingerprint: {}",
        info["label"].as_str().unwrap_or("?"),
        info["room_id"].as_str().unwrap_or("?"),
        info["topic"].as_str().unwrap_or("(none)"),
        info["encryption"].as_str().unwrap_or("?"),
        info["key_derivation"].as_str().unwrap_or("?"),
        info["messages"].as_u64().unwrap_or(0),
        info["members"].as_array().map(|a| a.len()).unwrap_or(0),
        info["fingerprint"].as_str().unwrap_or("?"),
    ))
}

// ── Tasks ───────────────────────────────────────────────────────

fn tool_task_add(args: &Value) -> Result<String, String> {
    let title = args["title"].as_str().ok_or("Missing 'title'")?;
    let room = args["room"].as_str();
    let id = chat::task_add(title, room)?;
    Ok(format!("Task added [{id}]: {title}"))
}

fn tool_task_claim(args: &Value) -> Result<String, String> {
    let task_id = args["task_id"].as_str().ok_or("Missing 'task_id'")?;
    let room = args["room"].as_str();
    let id = chat::task_claim(task_id, room)?;
    Ok(format!("Claimed task [{id}]"))
}

fn tool_task_done(args: &Value) -> Result<String, String> {
    let task_id = args["task_id"].as_str().ok_or("Missing 'task_id'")?;
    let notes = args["notes"].as_str();
    let room = args["room"].as_str();
    let id = chat::task_done(task_id, notes, room)?;
    Ok(format!("Task done [{id}]"))
}

fn tool_tasks(args: &Value) -> Result<String, String> {
    let room = args["room"].as_str();
    let tasks = chat::task_list(room)?;
    if tasks.is_empty() {
        return Ok("No tasks.".to_string());
    }
    let mut out = format!("{:<10} {:<8} {:<12} {:<8} Title\n", "ID", "Status", "ClaimedBy", "Reward");
    for t in &tasks {
        let id: String = t.id.chars().take(6).collect();
        let claimed = t.claimed_by.as_deref().unwrap_or("-");
        let reward = t.reward_credits.map(|c| c.to_string()).unwrap_or("-".to_string());
        out.push_str(&format!("{:<10} {:<8} {:<12} {:<8} {}\n", id, t.status, claimed, reward, t.title));
    }
    Ok(out)
}

// ── Files ───────────────────────────────────────────────────────

fn tool_send_file(args: &Value) -> Result<String, String> {
    let path = args["path"].as_str().ok_or("Missing 'path'")?;
    let room = args["room"].as_str();
    let (id, size) = chat::send_file(path, room)?;
    Ok(format!("Sent file [{id}] ({size} bytes, encrypted)"))
}

fn tool_files(args: &Value) -> Result<String, String> {
    let room = args["room"].as_str();
    let files = chat::list_files(room)?;
    if files.is_empty() {
        return Ok("No files shared.".to_string());
    }
    let mut out = format!("{} file(s):\n", files.len());
    for f in &files {
        let id = f["file_id"].as_str().unwrap_or("?");
        let name = f["filename"].as_str().unwrap_or("?");
        let size = f["size"].as_u64().unwrap_or(0);
        let from = f["from"].as_str().unwrap_or("?");
        out.push_str(&format!("[{}] {} ({} bytes) from {}\n", id.chars().take(6).collect::<String>(), name, size, from));
    }
    Ok(out)
}

fn tool_download(args: &Value) -> Result<String, String> {
    let file_id = args["file_id"].as_str().ok_or("Missing 'file_id'")?;
    let out = args["out"].as_str();
    let room = args["room"].as_str();
    let dest = chat::download_file(file_id, out, room)?;
    Ok(format!("Downloaded file to {dest}"))
}

// ── Economy / Bounties ──────────────────────────────────────────

fn tool_bounty(args: &Value) -> Result<String, String> {
    let title = args["title"].as_str().ok_or("Missing 'title'")?;
    let reward = args["reward"].as_i64();
    let oracle = args["oracle"].as_str();
    let room = args["room"].as_str();
    let id = chat::bounty_post(title, 3, oracle, reward, None, room)?;
    Ok(format!("Bounty posted [{id}]: {title}"))
}

fn tool_bounty_submit(args: &Value) -> Result<String, String> {
    let task_id = args["task_id"].as_str().ok_or("Missing 'task_id'")?;
    let branch = args["branch"].as_str().ok_or("Missing 'branch'")?;
    let room = args["room"].as_str();
    let id = chat::bounty_submit(task_id, branch, room)?;
    Ok(format!("Bounty submitted [{id}] on branch {branch}"))
}

fn tool_bounties(args: &Value) -> Result<String, String> {
    let room = args["room"].as_str();
    let tasks = chat::task_list(room)?;
    let bounties: Vec<_> = tasks
        .iter()
        .filter(|t| t.acceptance_oracle.is_some() && t.status == "open")
        .collect();
    if bounties.is_empty() {
        return Ok("No open bounties.".to_string());
    }
    let mut out = format!("{} open bounty/bounties:\n", bounties.len());
    for t in &bounties {
        let id: String = t.id.chars().take(6).collect();
        let reward = t.reward_credits.map(|c| format!("{c} credits")).unwrap_or_default();
        let oracle = t.acceptance_oracle.as_deref().unwrap_or("?");
        out.push_str(&format!("[{}] {} | oracle: {} | {}\n", id, t.title, oracle, reward));
    }
    Ok(out)
}

// ── Discovery ───────────────────────────────────────────────────

fn tool_discover(args: &Value) -> Result<String, String> {
    let need = args["need"].as_str().ok_or("Missing 'need'")?;
    let room = args["room"].as_str();
    let results = chat::discover(need, room)?;
    if results.is_empty() {
        return Ok(format!("No agents found for '{need}'."));
    }
    let mut out = format!("{} agent(s) for '{need}':\n", results.len());
    for r in &results {
        let caps = r.card.capabilities.join(", ");
        let avail = if r.card.available { "available" } else { "busy" };
        out.push_str(&format!(
            "{} | trust: {:.2} | receipts: {} | {} | caps: {}\n",
            r.card.agent_id, r.trust_score, r.receipt_count, avail, caps
        ));
    }
    Ok(out)
}

// ── Messaging ───────────────────────────────────────────────────

fn tool_thread(args: &Value) -> Result<String, String> {
    let id = args["id"].as_str().ok_or("Missing 'id'")?;
    let room = args["room"].as_str();
    let items = chat::thread(id, room)?;
    if items.is_empty() {
        return Ok("Empty thread.".to_string());
    }
    let mut out = String::new();
    for item in &items {
        let indent = "  ".repeat(item.depth);
        let ts = item.env["ts"].as_u64().unwrap_or(0);
        let dt = chrono::DateTime::from_timestamp(ts as i64, 0)
            .map(|d| d.format("%H:%M:%S").to_string())
            .unwrap_or_default();
        let from = item.env["from"].as_str().unwrap_or("?");
        let text = item.env["text"].as_str().unwrap_or("");
        let mid = item.env["id"].as_str().unwrap_or("?");
        out.push_str(&format!("{indent}[{dt}] [{}] {}: {}\n", mid.chars().take(6).collect::<String>(), from, text));
    }
    Ok(out)
}

fn tool_react(args: &Value) -> Result<String, String> {
    let msg_id = args["msg_id"].as_str().ok_or("Missing 'msg_id'")?;
    let emoji = args["emoji"].as_str().ok_or("Missing 'emoji'")?;
    let room = args["room"].as_str();
    chat::react(msg_id, emoji, room)?;
    Ok(format!("Reacted {emoji} to [{msg_id}]"))
}

fn tool_recap(args: &Value) -> Result<String, String> {
    let since = args["since"].as_str().unwrap_or("1h");
    let room = args["room"].as_str();
    let recap = chat::recap(since, room)?;
    let room_name = recap["room"].as_str().unwrap_or("?");
    let total = recap["total_messages"].as_u64().unwrap_or(0);
    let summary = recap["summary"].as_str();
    if let Some(s) = summary {
        return Ok(format!("Recap for {room_name} ({since}): {s}"));
    }
    let mut out = format!("Recap for {room_name} ({since}): {total} messages\n");
    if let Some(agents) = recap["agents"].as_array() {
        out.push_str("Active agents:\n");
        for a in agents {
            let id = a["id"].as_str().unwrap_or("?");
            let count = a["messages"].as_u64().unwrap_or(0);
            out.push_str(&format!("  {id}: {count} messages\n"));
        }
    }
    if let Some(kw) = recap["top_keywords"].as_array() {
        if !kw.is_empty() {
            out.push_str("Top keywords: ");
            let words: Vec<String> = kw
                .iter()
                .map(|k| {
                    let w = k["word"].as_str().unwrap_or("?");
                    let c = k["count"].as_u64().unwrap_or(0);
                    format!("{w} ({c})")
                })
                .collect();
            out.push_str(&words.join(", "));
            out.push('\n');
        }
    }
    Ok(out)
}

fn tool_dm(args: &Value) -> Result<String, String> {
    let agent_id = args["agent_id"].as_str().ok_or("Missing 'agent_id'")?;
    let message = args["message"].as_str();
    let me = store::get_agent_id();
    if agent_id == me.as_str() {
        return Err("Cannot open a DM with yourself.".to_string());
    }
    // Canonical DM room label: dm-{min}-{max}
    let (a, b) = if me.as_str() < agent_id {
        (me.as_str(), agent_id)
    } else {
        (agent_id, me.as_str())
    };
    let label = format!("dm-{a}-{b}");
    let created = store::find_room(&label).is_none();
    if created {
        chat::create(&label)?;
    }
    if let Some(room) = store::find_room(&label) {
        store::mark_dm_room(&room.room_id, agent_id)?;
        let mut out = if created {
            format!("Created DM room '{label}' with {agent_id}.\n")
        } else {
            format!("DM room '{label}' with {agent_id} is open.\n")
        };
        if let Some(msg) = message {
            let mid = chat::send(msg, None, Some(&label))?;
            out.push_str(&format!("Sent [{mid}] to {agent_id}."));
        }
        return Ok(out);
    }
    Err(format!("Failed to open DM room '{label}'."))
}

// ── Presence ────────────────────────────────────────────────────

fn tool_profile(args: &Value) -> Result<String, String> {
    let name = args["name"].as_str();
    let role = args["role"].as_str();
    let room = args["room"].as_str();
    chat::set_profile(name, role, room)?;
    let me = store::get_agent_id();
    let display = name.unwrap_or(&me);
    let role_str = role.unwrap_or("agent");
    Ok(format!("Profile set: {display} ({role_str})"))
}

fn tool_whois(args: &Value) -> Result<String, String> {
    let agent_id = args["agent_id"].as_str().ok_or("Missing 'agent_id'")?;
    let room = args["room"].as_str();
    let profile = chat::whois(agent_id, room)?;
    match profile {
        Some(p) => {
            let name = p.name.as_deref().unwrap_or("(unset)");
            let role = p.role.as_deref().unwrap_or("(unset)");
            Ok(format!("Agent: {}\nName: {}\nRole: {}", p.agent_id, name, role))
        }
        None => Ok(format!("No profile found for '{agent_id}'.")),
    }
}
