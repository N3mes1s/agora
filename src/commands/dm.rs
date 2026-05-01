use crate::{DmAction, DmCommand, chat, commands::read, store};

pub(crate) fn handle(command: &DmCommand) -> Result<(), String> {
    if matches!(command.action.as_ref(), Some(DmAction::List)) {
        print_list();
        return Ok(());
    }

    let agent_id = command
        .agent_id
        .as_deref()
        .ok_or_else(|| "Usage: agora dm <agent-id> [message]".to_string())?;
    let dm = crate::open_dm_room(agent_id, command.switch)?;
    let room_entry = dm.room;
    let read_room = command.read || command.tail.is_some();

    let text = command.message.join(" ");
    let sent_mid = if text.is_empty() {
        None
    } else {
        Some(chat::send(&text, None, Some(&room_entry.label))?)
    };

    if dm.created {
        let token = crate::targeted_invite_token(&room_entry, agent_id, "dm")
            .map_err(|e| format!("failed to create DM invite token: {e}"))?;
        println!("  DM room '{}' is ready for {}", room_entry.label, agent_id);
        println!("  Room ID:    {}", room_entry.room_id);
        if command.switch {
            println!("  Active:     {}", room_entry.label);
        }
        println!();
        println!("  Share this DM invite token with {}:", agent_id);
        println!("    agora accept {}", token);
        if dm.target_key_known {
            println!(
                "  Guardrail:  only the trusted signing key for '{}' will accept this token",
                agent_id
            );
        } else {
            println!(
                "  Guardrail:  only '{}' will accept this token without overriding AGORA_AGENT_ID",
                agent_id
            );
            println!(
                "  Note:       no trusted signing key is known for '{}', so binding is still soft",
                agent_id
            );
        }
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
        if command.switch {
            println!("  Active room: {}", room_entry.label);
        }
    } else {
        println!("  DM room '{}' is ready for {}", room_entry.label, agent_id);
        if command.switch {
            println!("  Active room: {}", room_entry.label);
        }
        if !read_room && !command.switch {
            let token = crate::targeted_invite_token(&room_entry, agent_id, "dm")
                .map_err(|e| format!("failed to create DM invite token: {e}"))?;
            println!("  DM invite token for {}:", agent_id);
            println!("    agora accept {}", token);
            if dm.target_key_known {
                println!(
                    "  Guardrail:  only the trusted signing key for '{}' will accept this token",
                    agent_id
                );
            } else {
                println!(
                    "  Guardrail:  only '{}' will accept this token without overriding AGORA_AGENT_ID",
                    agent_id
                );
                println!(
                    "  Note:       no trusted signing key is known for '{}', so binding is still soft",
                    agent_id
                );
            }
            println!("  Use it with:");
            println!("    agora dm {} <message>", agent_id);
            println!("    agora dm {} --read --tail 20", agent_id);
            println!("    agora dm {} --switch", agent_id);
            println!("    agora --room {} read", room_entry.label);
        }
    }

    if read_room {
        println!();
        read::print(Some(&room_entry.label), command.tail)?;
    }

    Ok(())
}

fn print_list() {
    let rooms = chat::dm_room_summaries();
    if rooms.is_empty() {
        println!("  No DM rooms. Run: agora dm <agent-id>");
        return;
    }

    let active = store::get_active_room();
    let active_id = active.map(|r| r.room_id).unwrap_or_default();
    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    println!(
        "  {:<18} {:<24} {:<6} {:<12} Active",
        "Peer", "Label", "Unread", "Last Active"
    );
    println!(
        "  {:<18} {:<24} {:<6} {:<12} {}",
        "─".repeat(18),
        "─".repeat(24),
        "─".repeat(6),
        "─".repeat(12),
        "─".repeat(8)
    );
    for summary in &rooms {
        let is_active = if summary.room.room_id == active_id {
            " *"
        } else {
            ""
        };
        let ago = if summary.last_message_at > 0 {
            let d = now_ts.saturating_sub(summary.last_message_at);
            if d < 60 {
                format!("{d}s ago")
            } else if d < 3600 {
                format!("{}m ago", d / 60)
            } else if d < 86400 {
                format!("{}h ago", d / 3600)
            } else {
                format!("{}d ago", d / 86400)
            }
        } else {
            "never".to_string()
        };
        println!(
            "  {:<18} {:<24} {:<6} {:<12} {}",
            summary.room.dm_peer.as_deref().unwrap_or(""),
            summary.room.label,
            summary.unread_count,
            ago,
            is_active
        );
    }
}
