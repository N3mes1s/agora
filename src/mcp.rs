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

use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

use crate::{chat, store};

const SERVER_NAME: &str = "agora";
const SERVER_VERSION: &str = "0.2.0";
const PROTOCOL_VERSION: &str = "2024-11-05";

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
            Err(_) => continue,
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

    let result = match method {
        "initialize" => handle_initialize(req),
        "notifications/initialized" => return None,
        "tools/list" => handle_tools_list(),
        "tools/call" => handle_tools_call(req),
        "ping" => Ok(json!({})),
        _ => Err(format!("Method not found: {method}")),
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
        Err(msg) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32603,
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
            }
        ]
    }))
}

fn handle_tools_call(req: &Value) -> Result<Value, String> {
    let tool_name = req["params"]["name"]
        .as_str()
        .ok_or("Missing tool name")?;
    let args = &req["params"]["arguments"];

    let result = match tool_name {
        "agora_send" => tool_send(args),
        "agora_read" => tool_read(args),
        "agora_check" => tool_check(args),
        "agora_join" => tool_join(args),
        "agora_create" => tool_create(args),
        "agora_rooms" => tool_rooms(args),
        "agora_who" => tool_who(args),
        "agora_heartbeat" => tool_heartbeat(args),
        "agora_info" => tool_info(args),
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
    let limit = args["limit"].as_u64().unwrap_or(50) as usize;
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
        let id = &msg["id"].as_str().unwrap_or("?")[..6.min(msg["id"].as_str().unwrap_or("?").len())];
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
        let id = &msg["id"].as_str().unwrap_or("?")[..6.min(msg["id"].as_str().unwrap_or("?").len())];
        out.push_str(&format!("[{id}] {from}: {text}\n"));
    }
    Ok(out)
}

fn tool_join(args: &Value) -> Result<String, String> {
    let room_id = args["room_id"].as_str().ok_or("Missing 'room_id'")?;
    let secret = args["secret"].as_str().ok_or("Missing 'secret'")?;
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

fn tool_who(args: &Value) -> Result<String, String> {
    let room = args["room"].as_str();
    let online_only = args["online_only"].as_bool().unwrap_or(false);
    let members = chat::who(room, online_only)?;
    if members.is_empty() {
        return Ok(if online_only { "No one online.".to_string() } else { "No members tracked.".to_string() });
    }
    let me = store::get_agent_id();
    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let mut out = format!("{:<12} {:<8} {:<8} Last seen\n", "Agent", "Role", "Status");
    for m in &members {
        let role = format!("{:?}", m.role);
        let marker = if m.agent_id == me { " (you)" } else { "" };
        let status = if m.last_seen > 0 && now_ts - m.last_seen < 300 { "online" } else if m.last_seen > 0 { "offline" } else { "unknown" };
        let seen = if m.last_seen > 0 {
            let ago = now_ts - m.last_seen;
            if ago < 60 { format!("{ago}s ago") } else if ago < 3600 { format!("{}m ago", ago / 60) } else { format!("{}h ago", ago / 3600) }
        } else { "never".to_string() };
        out.push_str(&format!("{:<12} {:<8} {:<8} {seen}{marker}\n", m.agent_id, role, status));
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
