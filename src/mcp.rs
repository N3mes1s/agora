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
use std::sync::Arc;

use crate::{chat, store};
use agora::{channel, lease, plugin, proposal, runtime};

const SERVER_NAME: &str = "agora";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Protocol revisions this server speaks, newest first. Agora implements
/// only the legacy `initialize` handshake: it answers `server/discover` (the
/// 2026-07-28 handshake) with "method not found", so Claude Code falls back
/// to `initialize`. Keep it that way while channel mode matters: a channel
/// server that negotiates 2026-07-28 does not register on Claude Code's v2
/// MCP client runtime.
const PROTOCOL_VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

/// The client's requested revision if we speak it, else our newest.
fn negotiate_protocol(requested: Option<&str>) -> &'static str {
    PROTOCOL_VERSIONS
        .iter()
        .copied()
        .find(|v| Some(*v) == requested)
        .unwrap_or(PROTOCOL_VERSIONS[0])
}

/// Per-connection state.
struct Session {
    channel: channel::Mode,
    /// The client's `initialize` declared the channel capability.
    client_declares_channel: bool,
    pushing: bool,
    /// Relay time from which messages are pushed (server start).
    started_at: u64,
}

impl Session {
    fn new(channel: channel::Mode) -> Self {
        Self {
            channel,
            client_declares_channel: false,
            pushing: false,
            started_at: runtime::unix_now(),
        }
    }

    /// Start channel push once the client is initialized, if the mode says so.
    fn start_push(&mut self) {
        if self.pushing {
            return;
        }
        let go = match self.channel {
            channel::Mode::Off => false,
            channel::Mode::On => true,
            channel::Mode::Auto => {
                self.client_declares_channel
                    || channel::ancestor_loads_channel(&channel::server_name())
            }
        };
        if !go {
            if self.channel == channel::Mode::Auto {
                agora::elog!(
                    "agora mcp: channel push off (auto: this session did not load server:{} as a channel)",
                    channel::server_name()
                );
            }
            return;
        }
        self.pushing = true;
        let me = store::get_agent_id();
        agora::elog!("agora mcp: channel push on for {me}");
        channel::spawn(me, self.started_at, Arc::new(write_message));
    }
}

/// Write one JSON-RPC message as a single line. Responses (stdin loop) and
/// pushes (room reader threads) share the process-wide stdout lock, so lines
/// never interleave.
fn write_message(msg: &Value) {
    let Ok(mut line) = serde_json::to_vec(msg) else {
        return;
    };
    line.push(b'\n');
    let mut out = io::stdout().lock();
    let _ = out.write_all(&line);
    let _ = out.flush();
}

/// Run the MCP stdio server. Blocks until stdin closes.
pub fn run(channel_mode: channel::Mode) {
    let mut session = Session::new(channel_mode);
    let stdin = io::stdin();

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
                write_message(&json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": { "code": -32700, "message": "Parse error" },
                }));
                continue;
            }
        };

        if let Some(resp) = handle_request(&request, &mut session) {
            write_message(&resp);
        }
    }
}

fn handle_request(req: &Value, session: &mut Session) -> Option<Value> {
    let method = req["method"].as_str()?;
    let id = req.get("id").cloned();

    // Notifications (no id) don't get responses
    let is_notification = id.is_none();

    let result: Result<Value, (i64, String)> = match method {
        "initialize" => handle_initialize(req, session).map_err(|msg| (-32603, msg)),
        "notifications/initialized" => {
            session.start_push();
            return None;
        }
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

fn handle_initialize(req: &Value, session: &mut Session) -> Result<Value, String> {
    let params = &req["params"];
    let requested = params["protocolVersion"].as_str();
    let version = negotiate_protocol(requested);
    session.client_declares_channel = params["capabilities"]["experimental"]
        .get(channel::CAPABILITY)
        .is_some();
    agora::elog!(
        "agora mcp: initialize protocol {version} (client asked {}), channel {}, client declares channel: {}",
        requested
            .map(channel::meta_value)
            .unwrap_or_else(|| "none".to_string()),
        session.channel.as_str(),
        session.client_declares_channel
    );
    let mut result = json!({
        "protocolVersion": version,
        "capabilities": {
            "tools": {}
        },
        "serverInfo": {
            "name": SERVER_NAME,
            "version": SERVER_VERSION,
        }
    });
    if session.channel != channel::Mode::Off {
        // Never `claude/channel/permission`: whoever can post to the bus
        // could then approve tool use in this session.
        let mut experimental = serde_json::Map::new();
        experimental.insert(channel::CAPABILITY.to_string(), json!({}));
        result["capabilities"]["experimental"] = Value::Object(experimental);
        result["instructions"] = json!(channel::INSTRUCTIONS);
    }
    Ok(result)
}

fn handle_tools_list() -> Result<Value, String> {
    let mut list = core_tools();
    if let Some(tools) = list["tools"].as_array_mut() {
        tools.extend(coordination_tools());
    }
    Ok(list)
}

fn tool(name: &str, description: &str, properties: Value, required: &[&str]) -> Value {
    let mut props = properties;
    if let Some(obj) = props.as_object_mut() {
        obj.insert(
            "room".to_string(),
            json!({"type": "string", "description": "Room label (optional, uses active room)"}),
        );
    }
    json!({
        "name": name,
        "description": description,
        "inputSchema": {"type": "object", "properties": props, "required": required}
    })
}

/// Lease / proposal / plugin tools for the local agent bus.
fn coordination_tools() -> Vec<Value> {
    vec![
        tool(
            "agora_lease_acquire",
            "Acquire a signed, TTL-bound lease on a shared resource (e.g. 'docker', 'repo:agora'). \
             Fails with the current holder if someone else holds it. Waits ~3s to settle races.",
            json!({
                "resource": {"type": "string", "description": "Resource name"},
                "ttl": {"type": "string", "description": "Duration, e.g. '10m' (default), '2h'"},
                "reason": {"type": "string", "description": "Why you need it (shown to others)"}
            }),
            &["resource"],
        ),
        tool(
            "agora_lease_renew",
            "Extend a lease you hold.",
            json!({
                "resource": {"type": "string"},
                "ttl": {"type": "string", "description": "New duration from now (default '10m')"}
            }),
            &["resource"],
        ),
        tool(
            "agora_lease_release",
            "Release a lease you hold. With lease_id and reason, release that exact lease although \
             another agent id on this host holds it (stranded when its window reconnected under a \
             new id); the reason is posted to the room.",
            json!({
                "resource": {"type": "string"},
                "lease_id": {"type": "string", "description": "Exact lease id of a stranded lease"},
                "reason": {"type": "string", "description": "Why (required with lease_id)"}
            }),
            &["resource"],
        ),
        tool(
            "agora_lease_check",
            "Check whether a resource is free or who holds it (and until when).",
            json!({"resource": {"type": "string"}}),
            &["resource"],
        ),
        tool(
            "agora_lease_list",
            "List active leases in the room.",
            json!({}),
            &[],
        ),
        tool(
            "agora_propose",
            "Announce a risky action (e.g. 'restart docker') on resources and give other agents \
             until the deadline to object. Check the outcome later with agora_proposals \
             (or `agora propose wait <id>`: exit 0 clear / 1 held).",
            json!({
                "action": {"type": "string", "description": "What you intend to do"},
                "resources": {"type": "array", "items": {"type": "string"},
                              "description": "Resources touched, e.g. ['docker']"},
                "wait": {"type": "string", "description": "Objection window, default '5m'"}
            }),
            &["action"],
        ),
        tool(
            "agora_hold",
            "Object to (HOLD) another agent's proposal before its deadline.",
            json!({
                "proposal_id": {"type": "string", "description": "Proposal ID or prefix"},
                "reason": {"type": "string", "description": "Why it must not happen now"}
            }),
            &["proposal_id", "reason"],
        ),
        tool(
            "agora_ack",
            "Acknowledge a proposal (informational, does not shorten the deadline).",
            json!({
                "proposal_id": {"type": "string"},
                "note": {"type": "string"}
            }),
            &["proposal_id"],
        ),
        tool(
            "agora_plugin_list",
            "List plugins other agents shared in the room: name@version, kind, author, hash, \
             signature status, installs and feedback score. Use when you need a capability \
             another agent may already have built.",
            json!({}),
            &[],
        ),
        tool(
            "agora_plugin_info",
            "Show a plugin's signed manifest, author, sha256, signature status and feedback.",
            json!({"name": {"type": "string", "description": "name or name@version"}}),
            &["name"],
        ),
        tool(
            "agora_plugin_install",
            "Verify (signature + hash) and install a shared plugin for a runtime. Without \
             confirm=true this only returns a preview (manifest, files, entry source) and \
             changes nothing. Plugins are code from other agents: review the preview first.",
            json!({
                "name": {"type": "string", "description": "name or name@version"},
                "runtime": {"type": "string", "enum": ["claude-code", "codex", "omp"]},
                "confirm": {"type": "boolean", "description": "true to actually install"}
            }),
            &["name"],
        ),
        tool(
            "agora_plugin_new",
            "Scaffold a plugin directory you can then edit and publish. kind: command (script \
             on PATH), skill (SKILL.md), mcp (stdio MCP server), hook (event hook script).",
            json!({
                "name": {"type": "string"},
                "kind": {"type": "string", "enum": ["command", "skill", "mcp", "hook"]},
                "dir": {"type": "string", "description": "Target directory (default ./<name>)"},
                "description": {"type": "string"}
            }),
            &["name", "kind"],
        ),
        tool(
            "agora_plugin_publish",
            "Sign (with your agent key) and share a plugin directory containing \
             agora-plugin.toml with the room so other agents can install it.",
            json!({"dir": {"type": "string", "description": "Plugin directory"}}),
            &["dir"],
        ),
        tool(
            "agora_plugin_feedback",
            "Rate a plugin you used: score +1 or -1 with a short comment.",
            json!({
                "name": {"type": "string", "description": "name or name@version"},
                "score": {"type": "integer", "enum": [1, -1]},
                "comment": {"type": "string"}
            }),
            &["name", "score"],
        ),
        tool(
            "agora_proposals",
            "List recent proposals with status: open (window running), HELD (objection or \
             conflicting lease), clear (deadline passed, safe to proceed).",
            json!({}),
            &[],
        ),
    ]
}

fn core_tools() -> Value {
    json!({
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
    })
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
        "agora_discover" => tool_discover(args),
        "agora_thread" => tool_thread(args),
        "agora_react" => tool_react(args),
        "agora_recap" => tool_recap(args),
        "agora_dm" => tool_dm(args),
        "agora_profile" => tool_profile(args),
        "agora_whois" => tool_whois(args),
        "agora_lease_acquire" => tool_lease_acquire(args),
        "agora_lease_renew" => tool_lease_renew(args),
        "agora_lease_release" => tool_lease_release(args),
        "agora_lease_check" => tool_lease_check(args),
        "agora_lease_list" => tool_lease_list(args),
        "agora_propose" => tool_propose(args),
        "agora_hold" => tool_hold(args),
        "agora_ack" => tool_ack(args),
        "agora_proposals" => tool_proposals(args),
        "agora_plugin_list" => tool_plugin_list(args),
        "agora_plugin_info" => tool_plugin_info(args),
        "agora_plugin_install" => tool_plugin_install(args),
        "agora_plugin_new" => tool_plugin_new(args),
        "agora_plugin_publish" => tool_plugin_publish(args),
        "agora_plugin_feedback" => tool_plugin_feedback(args),
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
        let id = msg["id"]
            .as_str()
            .unwrap_or("?")
            .chars()
            .take(6)
            .collect::<String>();
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
        let id = msg["id"]
            .as_str()
            .unwrap_or("?")
            .chars()
            .take(6)
            .collect::<String>();
        out.push_str(&format!("[{id}] {from}: {text}\n"));
    }
    Ok(out)
}

fn tool_join(args: &Value) -> Result<String, String> {
    let room_id = args["room_id"].as_str().ok_or("Missing 'room_id'")?;
    let secret = args["secret"].as_str().ok_or("Missing 'secret'")?;
    if secret.len() != 64
        || !secret
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
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
    let mut out = format!("{:<10} {:<8} {:<16} Title\n", "ID", "Status", "ClaimedBy");
    for t in &tasks {
        let id: String = t.id.chars().take(6).collect();
        let claimed = t.claimed_by.as_deref().unwrap_or("-");
        out.push_str(&format!(
            "{:<10} {:<8} {:<16} {}\n",
            id, t.status, claimed, t.title
        ));
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
        out.push_str(&format!(
            "[{}] {} ({} bytes) from {}\n",
            id.chars().take(6).collect::<String>(),
            name,
            size,
            from
        ));
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
        let avail = if r.card.available {
            "available"
        } else {
            "busy"
        };
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
        out.push_str(&format!(
            "{indent}[{dt}] [{}] {}: {}\n",
            mid.chars().take(6).collect::<String>(),
            from,
            text
        ));
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
    if let Some(kw) = recap["top_keywords"].as_array()
        && !kw.is_empty()
    {
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
            Ok(format!(
                "Agent: {}\nName: {}\nRole: {}",
                p.agent_id, name, role
            ))
        }
        None => Ok(format!("No profile found for '{agent_id}'.")),
    }
}

// ── Leases ──────────────────────────────────────────────────────

fn ttl_arg(args: &Value) -> Result<u64, String> {
    lease::parse_duration(args["ttl"].as_str().unwrap_or("10m"))
}

fn describe_lease(l: &lease::Lease) -> String {
    format!(
        "{} held by {} until {} ({}s left, lease {}){}",
        l.resource,
        l.holder,
        chrono::DateTime::from_timestamp(l.expires as i64, 0)
            .map(|d| d.format("%H:%M:%S").to_string())
            .unwrap_or_default(),
        l.remaining(runtime::unix_now()),
        l.lease_id,
        l.reason
            .as_deref()
            .map(|r| format!(" — {r}"))
            .unwrap_or_default()
    )
}

fn tool_lease_acquire(args: &Value) -> Result<String, String> {
    let resource = args["resource"].as_str().ok_or("Missing 'resource'")?;
    let ttl = ttl_arg(args)?;
    let reason = args["reason"].as_str();
    let room = args["room"].as_str();
    match lease::acquire(resource, ttl, reason, lease::SKEW_WINDOW_SECS + 1, room)? {
        lease::Acquire::Acquired(l) => Ok(format!("Acquired: {}", describe_lease(&l))),
        lease::Acquire::Held(l) => Err(format!("Not acquired. {}", describe_lease(&l))),
    }
}

fn tool_lease_renew(args: &Value) -> Result<String, String> {
    let resource = args["resource"].as_str().ok_or("Missing 'resource'")?;
    let l = lease::renew(resource, ttl_arg(args)?, args["room"].as_str())?;
    Ok(format!("Renewed: {}", describe_lease(&l)))
}

fn tool_lease_release(args: &Value) -> Result<String, String> {
    let resource = args["resource"].as_str().ok_or("Missing 'resource'")?;
    if let Some(lease_id) = args["lease_id"].as_str() {
        let reason = args["reason"].as_str().unwrap_or("");
        let l = lease::release_stranded(&store::get_agent_id(), resource, lease_id, reason, args["room"].as_str())?;
        return Ok(format!("Released {resource} (lease {}, held by {}).", l.lease_id, l.holder));
    }
    Ok(if lease::release(resource, args["room"].as_str())? {
        format!("Released {resource}.")
    } else {
        format!("{resource} was not held.")
    })
}

fn tool_lease_check(args: &Value) -> Result<String, String> {
    let resource = args["resource"].as_str().ok_or("Missing 'resource'")?;
    Ok(match lease::check(resource, args["room"].as_str())? {
        None => format!("{resource} is free."),
        Some(l) if l.holder == store::get_agent_id() => format!("{} (you)", describe_lease(&l)),
        Some(l) => describe_lease(&l),
    })
}

fn tool_lease_list(args: &Value) -> Result<String, String> {
    let leases = lease::list(args["room"].as_str())?;
    if leases.is_empty() {
        return Ok("No active leases.".to_string());
    }
    Ok(leases
        .iter()
        .map(describe_lease)
        .collect::<Vec<_>>()
        .join("\n"))
}

// ── Propose / HOLD ──────────────────────────────────────────────

fn tool_propose(args: &Value) -> Result<String, String> {
    let action = args["action"].as_str().ok_or("Missing 'action'")?;
    let resources: Vec<String> = args["resources"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let wait = lease::parse_duration(args["wait"].as_str().unwrap_or("5m"))?;
    let p = proposal::propose(action, &resources, wait, args["room"].as_str())?;
    Ok(format!(
        "Proposed [{}] \"{}\"; objections accepted for {wait}s. Check with agora_proposals \
         or run `agora propose wait {}` (exit 0 clear / 1 held).",
        p.id,
        p.action,
        p.short_id()
    ))
}

fn tool_hold(args: &Value) -> Result<String, String> {
    let id = args["proposal_id"]
        .as_str()
        .ok_or("Missing 'proposal_id'")?;
    let reason = args["reason"].as_str().ok_or("Missing 'reason'")?;
    let p = proposal::hold(id, reason, args["room"].as_str())?;
    Ok(format!(
        "Held [{}] \"{}\" by {}",
        p.short_id(),
        p.action,
        p.proposer
    ))
}

fn tool_ack(args: &Value) -> Result<String, String> {
    let id = args["proposal_id"]
        .as_str()
        .ok_or("Missing 'proposal_id'")?;
    let p = proposal::ack(id, args["note"].as_str(), args["room"].as_str())?;
    Ok(format!("Acknowledged [{}] \"{}\"", p.short_id(), p.action))
}

fn tool_proposals(args: &Value) -> Result<String, String> {
    let items = proposal::list(args["room"].as_str())?;
    if items.is_empty() {
        return Ok("No proposals in the last 24h.".to_string());
    }
    let now = runtime::unix_now();
    let mut out = String::new();
    for (p, status) in items {
        let label = match status {
            proposal::Status::Open => format!("open ({}s left)", p.deadline.saturating_sub(now)),
            proposal::Status::Held => "HELD".to_string(),
            proposal::Status::Clear => "clear".to_string(),
        };
        out.push_str(&format!(
            "[{}] {label}: {} by {} (resources: {})\n",
            p.id,
            p.action,
            p.proposer,
            p.resources.join(", ")
        ));
        for o in &p.objections {
            out.push_str(&format!("    hold by {}: {}\n", o.from, o.reason));
        }
    }
    Ok(out)
}

// ── Plugins ─────────────────────────────────────────────────────

fn plugin_summary(p: &plugin::Publication) -> String {
    format!(
        "{} ({}) by {} — {} [sig: {:?}, sha256 {}, installs {}, score {:+}, runtimes {}]",
        p.manifest.id(),
        p.manifest.kind,
        p.manifest.author,
        p.manifest.description,
        p.sig_status,
        &p.sha256[..12.min(p.sha256.len())],
        p.installs,
        p.score,
        p.manifest.runtimes.join("/")
    )
}

fn tool_plugin_list(args: &Value) -> Result<String, String> {
    let items = plugin::list(args["room"].as_str())?;
    if items.is_empty() {
        return Ok("No plugins shared in this room yet.".to_string());
    }
    Ok(items
        .iter()
        .map(plugin_summary)
        .collect::<Vec<_>>()
        .join("\n"))
}

fn tool_plugin_info(args: &Value) -> Result<String, String> {
    let name = args["name"].as_str().ok_or("Missing 'name'")?;
    let p = plugin::info(name, args["room"].as_str())?;
    let mut out = plugin_summary(&p);
    out.push_str(&format!("\n\nmanifest:\n{}", p.manifest_text));
    for f in &p.feedback {
        out.push_str(&format!("\n{:+} {}: {}", f.score, f.from, f.comment));
    }
    Ok(out)
}

fn tool_plugin_install(args: &Value) -> Result<String, String> {
    let name = args["name"].as_str().ok_or("Missing 'name'")?;
    let runtime_name = args["runtime"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(plugin::default_runtime);
    let room = args["room"].as_str();
    let prepared = plugin::prepare(name, room)?;
    let p = &prepared.publication;
    let mut out = format!("Verified signature and hash: {}\n", plugin_summary(p));
    out.push_str("Files:\n");
    for e in &prepared.entries {
        out.push_str(&format!("  {} ({} bytes)\n", e.path, e.data.len()));
    }
    if let Some(entry) = prepared.entries.iter().find(|e| e.path == p.manifest.entry) {
        let src: String = String::from_utf8_lossy(&entry.data)
            .lines()
            .take(60)
            .collect::<Vec<_>>()
            .join("\n");
        out.push_str(&format!("--- {} ---\n{src}\n---\n", entry.path));
    }
    if args["confirm"].as_bool() != Some(true) {
        out.push_str(&format!(
            "Nothing installed. Call again with confirm=true to install for {runtime_name}."
        ));
        return Ok(out);
    }
    let rec = plugin::install(&prepared, &runtime_name, room)?;
    out.push_str(&format!("Installed for {}. Changes:\n", rec.runtime));
    for c in &rec.changes {
        out.push_str(&format!("  - {c}\n"));
    }
    Ok(out)
}

fn tool_plugin_new(args: &Value) -> Result<String, String> {
    let name = args["name"].as_str().ok_or("Missing 'name'")?;
    let kind = args["kind"].as_str().ok_or("Missing 'kind'")?;
    let dir = std::path::PathBuf::from(args["dir"].as_str().unwrap_or(name));
    let files = plugin::scaffold(name, kind, &dir, args["description"].as_str())?;
    Ok(format!(
        "Created:\n{}\nEdit the entry, then publish with agora_plugin_publish (dir: {}).",
        files
            .iter()
            .map(|f| format!("  {}", f.display()))
            .collect::<Vec<_>>()
            .join("\n"),
        dir.display()
    ))
}

fn tool_plugin_publish(args: &Value) -> Result<String, String> {
    let dir = args["dir"].as_str().ok_or("Missing 'dir'")?;
    let p = plugin::publish(std::path::Path::new(dir), args["room"].as_str())?;
    Ok(format!(
        "Published {} (sha256 {}, signed by {}).",
        p.manifest.id(),
        p.sha256,
        p.manifest.author
    ))
}

fn tool_plugin_feedback(args: &Value) -> Result<String, String> {
    let name = args["name"].as_str().ok_or("Missing 'name'")?;
    let score = args["score"].as_i64().ok_or("Missing 'score' (+1 or -1)")?;
    let comment = args["comment"].as_str().unwrap_or("");
    let p = plugin::feedback(name, score, comment, args["room"].as_str())?;
    Ok(format!("Rated {} {:+}.", p.manifest.id(), score))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn initialize(session: &mut Session, version: &str, client_caps: Value) -> Value {
        let req = json!({
            "jsonrpc": "2.0", "id": 0, "method": "initialize",
            "params": {"protocolVersion": version, "capabilities": client_caps,
                       "clientInfo": {"name": "claude-code", "version": "2.1.319"}},
        });
        handle_request(&req, session).expect("initialize answers")["result"].clone()
    }

    #[test]
    fn plain_server_declares_no_channel() {
        let mut session = Session::new(channel::Mode::Off);
        let result = initialize(&mut session, "2025-11-25", json!({}));
        assert_eq!(result["protocolVersion"], "2025-11-25");
        assert_eq!(result["capabilities"], json!({"tools": {}}));
        assert!(result.get("instructions").is_none());
    }

    #[test]
    fn channel_mode_declares_channel_but_never_permission_relay() {
        for mode in [channel::Mode::On, channel::Mode::Auto] {
            let mut session = Session::new(mode);
            let result = initialize(&mut session, "2025-11-25", json!({}));
            let experimental = &result["capabilities"]["experimental"];
            assert_eq!(experimental["claude/channel"], json!({}));
            assert!(experimental.get("claude/channel/permission").is_none());
            assert_eq!(result["capabilities"]["tools"], json!({}));
            let instructions = result["instructions"].as_str().unwrap();
            assert!(instructions.contains("not by the user"));
            assert!(instructions.contains("agora_send"));
        }
    }

    #[test]
    fn negotiates_legacy_revisions_only() {
        // What Claude Code 2.1.319 sends after its server/discover probe fails.
        assert_eq!(negotiate_protocol(Some("2025-11-25")), "2025-11-25");
        assert_eq!(negotiate_protocol(Some("2025-06-18")), "2025-06-18");
        assert_eq!(negotiate_protocol(Some("2024-11-05")), "2024-11-05");
        // A channel server must not negotiate 2026-07-28 (it would not register).
        assert_eq!(negotiate_protocol(Some("2026-07-28")), "2025-11-25");
        assert_eq!(negotiate_protocol(None), "2025-11-25");
        let mut session = Session::new(channel::Mode::On);
        assert_eq!(
            initialize(&mut session, "2026-07-28", json!({}))["protocolVersion"],
            "2025-11-25"
        );
    }

    #[test]
    fn server_discover_probe_is_method_not_found() {
        // Claude Code probes the 2026-07-28 handshake first; "method not
        // found" makes it fall back to `initialize`.
        let mut session = Session::new(channel::Mode::On);
        let probe = json!({
            "jsonrpc": "2.0", "id": "server-discover-probe-1", "method": "server/discover",
            "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}},
        });
        let resp = handle_request(&probe, &mut session).unwrap();
        assert_eq!(resp["error"]["code"], -32601);
        assert_eq!(resp["id"], "server-discover-probe-1");
        assert!(!session.pushing);
    }

    #[test]
    fn records_client_channel_capability() {
        let mut session = Session::new(channel::Mode::Auto);
        initialize(
            &mut session,
            "2025-11-25",
            json!({"experimental": {"claude/channel": {}}}),
        );
        assert!(session.client_declares_channel);
        let mut session = Session::new(channel::Mode::Auto);
        initialize(
            &mut session,
            "2025-11-25",
            json!({"roots": {"listChanged": true}}),
        );
        assert!(!session.client_declares_channel);
    }

    #[test]
    fn off_mode_never_starts_push() {
        let mut session = Session::new(channel::Mode::Off);
        initialize(
            &mut session,
            "2025-11-25",
            json!({"experimental": {"claude/channel": {}}}),
        );
        assert!(
            handle_request(
                &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                &mut session
            )
            .is_none()
        );
        assert!(!session.pushing);
    }
}
