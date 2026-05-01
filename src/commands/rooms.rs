use crate::{chat, store};

pub(crate) fn print() {
    let rooms = chat::room_summaries();
    if rooms.is_empty() {
        println!("  No rooms. Run: agora create <label>");
        return;
    }

    let active = store::get_active_room();
    let active_id = active.map(|r| r.room_id).unwrap_or_default();
    println!(
        "  {:<20} {:<22} {:<8} {:<18} {:<6} {:<8} Joined",
        "Label", "Room ID", "Kind", "Peer", "Unread", "Active"
    );
    println!(
        "  {:<20} {:<22} {:<8} {:<18} {:<6} {:<8} {}",
        "─".repeat(20),
        "─".repeat(22),
        "─".repeat(8),
        "─".repeat(18),
        "─".repeat(6),
        "─".repeat(8),
        "─".repeat(20)
    );
    for summary in &rooms {
        let is_active = if summary.room.room_id == active_id {
            " *"
        } else {
            ""
        };
        let joined = chrono::DateTime::from_timestamp(summary.room.joined_at as i64, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_default();
        let kind = summary.room.purpose.as_deref().unwrap_or("room");
        let peer = summary.room.dm_peer.as_deref().unwrap_or("");
        println!(
            "  {:<20} {:<22} {:<8} {:<18} {:<6} {:<8} {joined}",
            summary.room.label, summary.room.room_id, kind, peer, summary.unread_count, is_active
        );
    }
}
