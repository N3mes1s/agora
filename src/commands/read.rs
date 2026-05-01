use crate::{chat, print_msg, store};

pub(crate) fn print(room: Option<&str>, tail: Option<usize>) -> Result<(), String> {
    let msgs = chat::read("2h", 50, room)?;
    let msgs = if let Some(n) = tail {
        if msgs.len() > n {
            msgs[msgs.len() - n..].to_vec()
        } else {
            msgs
        }
    } else {
        msgs
    };
    if msgs.is_empty() {
        println!("  (no messages)");
        return Ok(());
    }

    let header_room = if let Some(target) = room {
        store::find_room(target)
    } else {
        store::get_active_room()
    };
    if let Some(header_room) = header_room {
        println!(
            "  --- {} ({} messages, AES-256-GCM) ---\n",
            header_room.label,
            msgs.len()
        );
        if let Ok(pinned) = chat::pins(room)
            && !pinned.is_empty()
        {
            println!("  --- pinned ({}) ---\n", pinned.len());
            for p in &pinned {
                print_msg(p);
            }
            println!();
        }
        for msg in &msgs {
            print_msg(msg);
        }
        chat::mark_displayed_messages_read(&header_room.room_id, &msgs);
        return Ok(());
    }

    for msg in &msgs {
        print_msg(msg);
    }
    Ok(())
}
