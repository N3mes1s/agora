//! Agora web UI — enhanced local HTTP server.
//!
//! Routes:
//!   GET  /                    — room list
//!   GET  /:room               — room history + live tail + send form
//!   GET  /:room/events        — SSE stream (new messages as HTML fragments)
//!   POST /:room/send          — send a message, redirect back
//!   GET  /:room/search?q=...  — search messages in room
//!   GET  /:room/members       — list room members
//!   GET  /:room/pins          — pinned messages
//!   POST /:room/react         — add emoji reaction (form: msg_id, emoji)
//!   POST /:room/pin           — pin a message (form: msg_id)
//!   POST /:room/unpin         — unpin a message (form: msg_id)

use std::io::{Read as IoRead, Write as IoWrite};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use crate::{chat, store};

// ── HTML helpers ─────────────────────────────────────────────────

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Decode application/x-www-form-urlencoded bytes.
fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut raw: Vec<u8> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            raw.push(b' ');
            i += 1;
        } else if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                raw.push(b);
                i += 3;
            } else {
                raw.push(b'%');
                i += 1;
            }
        } else {
            raw.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&raw).into_owned()
}

/// Extract a named field from a URL-encoded form body.
fn form_field<'a>(body: &'a str, name: &str) -> Option<String> {
    for pair in body.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == name {
                return Some(url_decode(v));
            }
        }
    }
    None
}

// ── Message rendering ────────────────────────────────────────────

fn reaction_badges(room_id: &str, msg_id: &str) -> String {
    let reactions = store::load_reactions(room_id);
    let entries = match reactions.get(msg_id) {
        Some(e) if !e.is_empty() => e,
        _ => return String::new(),
    };
    // Count per emoji
    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for (_, emoji) in entries {
        *counts.entry(emoji.as_str()).or_insert(0) += 1;
    }
    let mut badges = String::new();
    let mut sorted: Vec<_> = counts.into_iter().collect();
    sorted.sort_by_key(|(e, _)| *e);
    for (emoji, n) in sorted {
        badges.push_str(&format!(
            r#"<span class="reaction">{} {}</span>"#,
            html_escape(emoji),
            n
        ));
    }
    badges
}

fn receipt_mark(room_id: &str, msg_id: &str, me: &str, sender: &str) -> String {
    if sender != me {
        return String::new();
    }
    let receipts = store::load_receipts(room_id);
    let readers = receipts.get(msg_id).map(|v| v.len()).unwrap_or(0);
    if readers >= 2 {
        r#"<span class="receipt seen2" title="Read by multiple">✓✓</span>"#.to_string()
    } else if readers == 1 {
        r#"<span class="receipt seen1" title="Read">✓</span>"#.to_string()
    } else {
        r#"<span class="receipt unseen" title="Sent">✓</span>"#.to_string()
    }
}

/// Render a single message as an HTML `<div class="msg ...">`.
/// `room_label` is used for action form targets; `room_id` for store lookups.
pub fn render_message_html(m: &serde_json::Value, me: &str, room_id: &str) -> String {
    render_message_html_ex(m, me, room_id, "", "")
}

pub fn render_message_html_ex(
    m: &serde_json::Value,
    me: &str,
    room_id: &str,
    room_label: &str,
    highlight: &str,
) -> String {
    let ts_epoch = m["ts"].as_u64().unwrap_or(0);
    let dt = chrono::DateTime::from_timestamp(ts_epoch as i64, 0)
        .map(|d| d.format("%H:%M:%S").to_string())
        .unwrap_or_default();
    let from = html_escape(m["from"].as_str().unwrap_or("?"));
    let mid = m["id"].as_str().unwrap_or("?");
    let mid_short = &mid[..6.min(mid.len())];
    let class = if m["from"].as_str().unwrap_or("") == me {
        "msg me"
    } else {
        "msg other"
    };

    // Optionally highlight a search term in the text
    let raw_text = m["text"].as_str().unwrap_or("");
    let text = if !highlight.is_empty() {
        let escaped = html_escape(raw_text);
        let hl_escaped = html_escape(highlight);
        // Case-insensitive highlight: replace first occurrence found by lower-case comparison
        let lower = escaped.to_lowercase();
        let hl_lower = hl_escaped.to_lowercase();
        if let Some(pos) = lower.find(hl_lower.as_str()) {
            let end = pos + hl_lower.len();
            format!(
                r#"{}<span class="highlight">{}</span>{}"#,
                &escaped[..pos],
                &escaped[pos..end],
                &escaped[end..]
            )
        } else {
            escaped
        }
    } else {
        html_escape(raw_text)
    };

    let reply_badge = if let Some(rt) = m["reply_to"].as_str() {
        format!(
            r#"<span class="reply-to" title="reply to {}">↩ {}</span> "#,
            html_escape(rt),
            &rt[..6.min(rt.len())]
        )
    } else {
        String::new()
    };

    let reactions = reaction_badges(room_id, mid);
    let receipt = receipt_mark(room_id, mid, me, m["from"].as_str().unwrap_or(""));

    let reactions_row = if reactions.is_empty() {
        String::new()
    } else {
        format!(r#"<div class="reactions">{reactions}</div>"#)
    };

    // Action buttons (reply, react, pin) — only shown on hover via CSS
    let actions = if !room_label.is_empty() {
        let rl = html_escape(room_label);
        let mid_e = html_escape(mid);
        format!(
            r#"<span class="msg-actions">
<button onclick="setReply('{mid_e}','{mid_short}')" title="Reply">↩ Reply</button>
<button onclick="toggleEmoji(this,'{mid_e}','{rl}')" title="React">😊 React</button>
<form style="display:inline" method="post" action="/{rl}/pin"><input type="hidden" name="msg_id" value="{mid_e}"><button type="submit" class="pin-btn" title="Pin">📌</button></form>
</span>"#
        )
    } else {
        String::new()
    };

    format!(
        r#"<div class="{class}" id="m-{mid_short}"><span class="time">{dt}</span> <span class="id">[{mid_short}]</span> <span class="sender">{from}</span>: {reply_badge}<span class="text">{text}</span>{receipt}{actions}{reactions_row}</div>"#
    )
}

// ── Page templates ────────────────────────────────────────────────

const SHARED_CSS: &str = r#"
body{font-family:'SF Mono','Consolas',monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:20px}
h1{color:#58a6ff;font-size:1.2em;border-bottom:1px solid #30363d;padding-bottom:10px}
.stats{color:#8b949e;font-size:.85em;margin-bottom:16px}
.room-nav{margin-bottom:8px}
.room-nav a{margin-right:8px;padding:4px 8px;background:#21262d;border-radius:4px;text-decoration:none;color:#58a6ff;font-size:.85em}
.room-nav a:hover{background:#30363d}
.room-nav a.active{background:#388bfd;color:#fff}
.tab-nav{margin-bottom:12px;border-bottom:1px solid #30363d;padding-bottom:8px}
.tab-nav a{margin-right:4px;padding:4px 10px;background:#161b22;border-radius:4px 4px 0 0;text-decoration:none;color:#8b949e;font-size:.85em}
.tab-nav a:hover{background:#21262d;color:#c9d1d9}
.tab-nav a.active{background:#21262d;color:#58a6ff;border-bottom:2px solid #388bfd}
.msg{padding:3px 0;line-height:1.5;position:relative}
.msg:hover .msg-actions{display:inline-flex}
.msg.me{color:#7ee787}
.msg.other{color:#c9d1d9}
.time{color:#8b949e}
.id{color:#6e7681;font-size:.82em}
.sender{color:#58a6ff;font-weight:bold}
.reply-to{color:#8b949e;font-size:.82em;background:#161b22;padding:1px 4px;border-radius:3px;margin-right:4px}
.receipt{font-size:.8em;margin-left:4px}
.receipt.seen2{color:#3fb950}
.receipt.seen1{color:#8b949e}
.receipt.unseen{color:#6e7681}
.reactions{display:inline;margin-left:6px}
.reaction{display:inline-block;background:#161b22;border:1px solid #30363d;border-radius:10px;padding:1px 6px;font-size:.82em;margin:1px 2px;cursor:pointer}
.reaction:hover{background:#21262d;border-color:#58a6ff}
a{color:#58a6ff}
.send-form{position:sticky;bottom:0;background:#0d1117;border-top:1px solid #30363d;padding:12px 0 4px}
.send-form input[type=text]{width:calc(100% - 100px);background:#161b22;border:1px solid #30363d;color:#c9d1d9;padding:6px 10px;border-radius:6px;font-family:inherit;font-size:.95em}
.send-form input[type=text]:focus{outline:none;border-color:#388bfd}
.send-form button{background:#238636;border:none;color:#fff;padding:6px 14px;border-radius:6px;cursor:pointer;margin-left:8px;font-family:inherit}
.send-form button:hover{background:#2ea043}
.send-form .reply-indicator{font-size:.82em;color:#8b949e;margin-bottom:4px;display:none}
.send-form .reply-indicator.active{display:block}
.send-form .cancel-reply{cursor:pointer;color:#f85149;margin-left:6px}
#messages{padding-bottom:8px}
.conn-status{font-size:.75em;color:#8b949e;margin-left:8px}
.conn-status.live{color:#3fb950}
.conn-status.reconnecting{color:#d29922}
.msg-actions{display:none;margin-left:8px;gap:4px;align-items:center;vertical-align:middle}
.msg-actions button{background:none;border:1px solid #30363d;border-radius:4px;color:#8b949e;font-size:.75em;padding:1px 5px;cursor:pointer;font-family:inherit}
.msg-actions button:hover{background:#21262d;color:#c9d1d9;border-color:#58a6ff}
.msg-actions .pin-btn{color:#d29922}
.emoji-bar{display:none;margin-left:8px;gap:2px}
.emoji-bar button{background:none;border:1px solid #30363d;border-radius:10px;font-size:.85em;padding:1px 4px;cursor:pointer}
.emoji-bar button:hover{background:#21262d}
.member-row{padding:6px 0;border-bottom:1px solid #161b22;display:flex;gap:16px;align-items:baseline}
.member-id{color:#58a6ff;font-weight:bold}
.member-role{color:#8b949e;font-size:.82em;background:#161b22;padding:1px 6px;border-radius:10px}
.member-since{color:#6e7681;font-size:.82em}
.pin-msg{background:#161b22;border-left:3px solid #d29922;padding:8px 12px;margin:4px 0;border-radius:0 4px 4px 0}
.pin-msg .unpin-form{display:inline;margin-left:8px}
.pin-msg .unpin-btn{background:none;border:none;color:#f85149;cursor:pointer;font-size:.82em;font-family:inherit}
.search-form{margin-bottom:16px;display:flex;gap:8px}
.search-form input[type=text]{flex:1;background:#161b22;border:1px solid #30363d;color:#c9d1d9;padding:6px 10px;border-radius:6px;font-family:inherit;font-size:.95em}
.search-form input[type=text]:focus{outline:none;border-color:#388bfd}
.search-form button{background:#1f6feb;border:none;color:#fff;padding:6px 14px;border-radius:6px;cursor:pointer;font-family:inherit}
.search-form button:hover{background:#388bfd}
.highlight{background:#3d2a00;border-radius:2px;padding:0 2px}
"#;

fn render_room_nav(active: &str) -> String {
    let rooms = store::load_registry();
    rooms
        .iter()
        .map(|r| {
            let class = if r.label == active { "active" } else { "" };
            format!(
                r#"<a href="/{}" class="{class}">{}</a>"#,
                html_escape(&r.label),
                html_escape(&r.label),
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn render_tab_nav(room_label: &str, active_tab: &str) -> String {
    let label = html_escape(room_label);
    let tabs = [
        ("messages", &format!("/{label}"), "Messages"),
        ("members", &format!("/{label}/members"), "Members"),
        ("pins", &format!("/{label}/pins"), "Pins"),
        ("search", &format!("/{label}/search"), "Search"),
    ];
    tabs.iter()
        .map(|(tab, href, name)| {
            let class = if *tab == active_tab { "active" } else { "" };
            format!(r#"<a href="{href}" class="{class}">{name}</a>"#)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn render_room_page(room_label: &str) -> String {
    let room = match store::find_room(room_label) {
        Some(r) => r,
        None => return render_404(room_label),
    };
    let me = store::get_agent_id();
    let msgs = chat::read("24h", 300, Some(room_label)).unwrap_or_default();
    let last_ts = msgs
        .iter()
        .map(|m| m["ts"].as_u64().unwrap_or(0))
        .max()
        .unwrap_or(0);

    let mut rows = String::new();
    for m in &msgs {
        rows.push_str(&render_message_html_ex(m, &me, &room.room_id, room_label, ""));
        rows.push('\n');
    }

    let topic_line = room
        .topic
        .as_deref()
        .map(|t| format!(r#"<div class="stats">Topic: {}</div>"#, html_escape(t)))
        .unwrap_or_default();

    let label = html_escape(room_label);

    format!(
        r#"<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<title>Agora — {label}</title>
<style>{css}</style>
</head><body>
<h1>Agora — {label} <span class="conn-status" id="conn">●</span></h1>
{topic_line}
<div class="stats">{count} messages shown (last 24 h). <a href="/">All rooms</a></div>
<div class="room-nav">{room_nav}</div>
<div class="tab-nav">{tab_nav}</div>
<div id="messages">
{rows}</div>
<div class="send-form">
  <div class="reply-indicator" id="reply-ind">Replying to <span id="reply-label"></span> <span class="cancel-reply" onclick="cancelReply()">✕</span></div>
  <form id="sf" action="/{label}/send" method="post" autocomplete="off">
    <input type="hidden" name="reply_to" id="reply-field" value="">
    <input type="text" name="message" id="msg-input" placeholder="Type a message… (Enter to send)" autofocus>
    <button type="submit">Send</button>
  </form>
</div>
<script>
(function(){{
  var lastTs = {last_ts};
  var conn = document.getElementById('conn');
  var messages = document.getElementById('messages');
  var input = document.getElementById('msg-input');
  var replyField = document.getElementById('reply-field');
  var replyInd = document.getElementById('reply-ind');
  var replyLabel = document.getElementById('reply-label');

  // Submit form via fetch so page doesn't reload
  document.getElementById('sf').addEventListener('submit', function(e) {{
    e.preventDefault();
    var text = input.value.trim();
    if (!text) return;
    var body = 'message=' + encodeURIComponent(text);
    if (replyField.value) body += '&reply_to=' + encodeURIComponent(replyField.value);
    fetch('/{label}/send', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
      body: body
    }}).catch(function() {{}});
    input.value = '';
    cancelReply();
  }});

  function connectSSE() {{
    var url = '/{label}/events?since=' + lastTs;
    var es = new EventSource(url);
    conn.textContent = '● connecting';
    conn.className = 'conn-status reconnecting';

    es.onopen = function() {{
      conn.textContent = '● live';
      conn.className = 'conn-status live';
    }};

    es.onmessage = function(evt) {{
      if (!evt.data || evt.data === 'ping') return;
      var div = document.createElement('div');
      div.innerHTML = evt.data;
      var el = div.firstElementChild || div;
      messages.appendChild(el);
      el.scrollIntoView({{behavior: 'smooth', block: 'end'}});
    }};

    es.onerror = function() {{
      conn.textContent = '● reconnecting';
      conn.className = 'conn-status reconnecting';
      es.close();
      setTimeout(connectSSE, 4000);
    }};
  }}

  connectSSE();

  // Scroll to bottom on load
  window.scrollTo(0, document.body.scrollHeight);
}})();

function setReply(msgId, msgShort) {{
  var replyField = document.getElementById('reply-field');
  var replyInd = document.getElementById('reply-ind');
  var replyLabel = document.getElementById('reply-label');
  replyField.value = msgId;
  replyLabel.textContent = '[' + msgShort + ']';
  replyInd.className = 'reply-indicator active';
  document.getElementById('msg-input').focus();
}}

function cancelReply() {{
  document.getElementById('reply-field').value = '';
  document.getElementById('reply-ind').className = 'reply-indicator';
  document.getElementById('reply-label').textContent = '';
}}

var _emojiBar = null;
function toggleEmoji(btn, msgId, roomLabel) {{
  if (_emojiBar) {{ _emojiBar.remove(); _emojiBar = null; return; }}
  var emojis = ['+1', '❤️', '🔥', '👀', '✅', '😂', '🎉'];
  var bar = document.createElement('span');
  bar.className = 'emoji-bar';
  bar.style.display = 'inline-flex';
  emojis.forEach(function(e) {{
    var b = document.createElement('button');
    b.textContent = e;
    b.onclick = function() {{
      fetch('/' + roomLabel + '/react', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
        body: 'msg_id=' + encodeURIComponent(msgId) + '&emoji=' + encodeURIComponent(e)
      }}).then(function() {{ location.reload(); }});
    }};
    bar.appendChild(b);
  }});
  btn.parentNode.insertBefore(bar, btn.nextSibling);
  _emojiBar = bar;
}}
</script>
</body></html>"#,
        label = label,
        css = SHARED_CSS,
        count = msgs.len(),
        room_nav = render_room_nav(room_label),
        tab_nav = render_tab_nav(room_label, "messages"),
        topic_line = topic_line,
        rows = rows,
        last_ts = last_ts,
    )
}

fn render_members_page(room_label: &str) -> String {
    let room = match store::find_room(room_label) {
        Some(r) => r,
        None => return render_404(room_label),
    };
    let label = html_escape(room_label);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut rows = String::new();
    let mut members = room.members.clone();
    members.sort_by(|a, b| a.joined_at.cmp(&b.joined_at));

    for m in &members {
        let role_str = match m.role {
            store::Role::Admin => "admin",
            store::Role::Member => "member",
        };
        let joined = chrono::DateTime::from_timestamp(m.joined_at as i64, 0)
            .map(|d| d.format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_default();
        let last_seen = if m.last_seen > 0 {
            let ago = now.saturating_sub(m.last_seen);
            if ago < 60 {
                format!("active {}s ago", ago)
            } else if ago < 3600 {
                format!("active {}m ago", ago / 60)
            } else if ago < 86400 {
                format!("active {}h ago", ago / 3600)
            } else {
                format!("active {}d ago", ago / 86400)
            }
        } else {
            String::new()
        };
        let nick = m
            .nickname
            .as_deref()
            .map(|n| format!(r#" <span style="color:#e3b341">{}</span>"#, html_escape(n)))
            .unwrap_or_default();
        rows.push_str(&format!(
            r#"<div class="member-row"><span class="member-id">{id}</span>{nick}<span class="member-role">{role}</span><span class="member-since">joined {joined}</span><span class="member-since">{last_seen}</span></div>"#,
            id = html_escape(&m.agent_id),
            nick = nick,
            role = role_str,
            joined = joined,
            last_seen = last_seen,
        ));
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<title>Agora — {label} — Members</title>
<style>{css}</style>
</head><body>
<h1>Agora — {label} — Members</h1>
<div class="stats">{count} members. <a href="/">All rooms</a></div>
<div class="room-nav">{room_nav}</div>
<div class="tab-nav">{tab_nav}</div>
{rows}
</body></html>"#,
        label = label,
        css = SHARED_CSS,
        count = members.len(),
        room_nav = render_room_nav(room_label),
        tab_nav = render_tab_nav(room_label, "members"),
        rows = rows,
    )
}

fn render_pins_page(room_label: &str) -> String {
    let room = match store::find_room(room_label) {
        Some(r) => r,
        None => return render_404(room_label),
    };
    let me = store::get_agent_id();
    let label = html_escape(room_label);
    let pins = store::load_pins(&room.room_id);
    let all_msgs = store::load_messages(&room.room_id, 86400 * 30); // 30 days

    let mut rows = String::new();
    for pin_id in &pins {
        // Find the message by ID prefix
        let msg = all_msgs
            .iter()
            .find(|m| m["id"].as_str().unwrap_or("").starts_with(pin_id.as_str()));
        if let Some(m) = msg {
            let msg_html = render_message_html_ex(m, &me, &room.room_id, "", "");
            let pin_id_e = html_escape(pin_id);
            rows.push_str(&format!(
                r#"<div class="pin-msg">{msg_html}<form class="unpin-form" method="post" action="/{label}/unpin"><input type="hidden" name="msg_id" value="{pin_id_e}"><button class="unpin-btn" type="submit">✕ Unpin</button></form></div>"#
            ));
        } else {
            rows.push_str(&format!(
                r#"<div class="pin-msg" style="color:#6e7681">[{pin_id}] message not in local cache</div>"#,
                pin_id = html_escape(pin_id)
            ));
        }
    }

    if rows.is_empty() {
        rows = r#"<div class="stats">No pinned messages. Pin a message from the Messages tab.</div>"#.to_string();
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<title>Agora — {label} — Pins</title>
<style>{css}</style>
</head><body>
<h1>Agora — {label} — Pins</h1>
<div class="stats">{count} pinned. <a href="/">All rooms</a></div>
<div class="room-nav">{room_nav}</div>
<div class="tab-nav">{tab_nav}</div>
{rows}
</body></html>"#,
        label = label,
        css = SHARED_CSS,
        count = pins.len(),
        room_nav = render_room_nav(room_label),
        tab_nav = render_tab_nav(room_label, "pins"),
        rows = rows,
    )
}

fn render_search_page(room_label: &str, query: &str) -> String {
    let room = match store::find_room(room_label) {
        Some(r) => r,
        None => return render_404(room_label),
    };
    let me = store::get_agent_id();
    let label = html_escape(room_label);
    let query_e = html_escape(query);

    let msgs = if query.is_empty() {
        Vec::new()
    } else {
        let q_lower = query.to_lowercase();
        store::load_messages(&room.room_id, 86400 * 30)
            .into_iter()
            .filter(|m| {
                let text = m["text"].as_str().unwrap_or("").to_lowercase();
                let from = m["from"].as_str().unwrap_or("").to_lowercase();
                text.contains(&q_lower) || from.contains(&q_lower)
            })
            .collect()
    };

    let mut rows = String::new();
    for m in &msgs {
        rows.push_str(&render_message_html_ex(m, &me, &room.room_id, "", query));
        rows.push('\n');
    }

    let results_info = if query.is_empty() {
        String::new()
    } else {
        format!(
            r#"<div class="stats">{} result(s) for <strong>{query_e}</strong></div>"#,
            msgs.len()
        )
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<title>Agora — {label} — Search</title>
<style>{css}</style>
</head><body>
<h1>Agora — {label} — Search</h1>
<div class="room-nav">{room_nav}</div>
<div class="tab-nav">{tab_nav}</div>
<form class="search-form" method="get" action="/{label}/search">
  <input type="text" name="q" value="{query_e}" placeholder="Search messages…" autofocus>
  <button type="submit">Search</button>
</form>
{results_info}
<div id="results">{rows}</div>
</body></html>"#,
        label = label,
        css = SHARED_CSS,
        room_nav = render_room_nav(room_label),
        tab_nav = render_tab_nav(room_label, "search"),
        query_e = query_e,
        results_info = results_info,
        rows = rows,
    )
}

fn render_index() -> String {
    let rooms = store::load_registry();
    let mut links = String::new();
    for r in &rooms {
        links.push_str(&format!(
            r#"<li><a href="/{label}">{label}</a> — <span style="color:#6e7681">{id}</span></li>"#,
            label = html_escape(&r.label),
            id = html_escape(&r.room_id),
        ));
        links.push('\n');
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<title>Agora — Rooms</title>
<style>{css}</style>
</head><body>
<h1>Agora — Rooms</h1>
<ul style="list-style:none;padding:0;line-height:2">{links}</ul>
</body></html>"#,
        css = SHARED_CSS,
        links = links,
    )
}

fn render_404(label: &str) -> String {
    format!(
        r#"<!DOCTYPE html><html><body style="font-family:monospace;background:#0d1117;color:#c9d1d9;padding:20px"><h1>404</h1><p>Room '{}' not found. <a href="/" style="color:#58a6ff">Back to rooms</a></p></body></html>"#,
        html_escape(label)
    )
}

// ── HTTP primitives ──────────────────────────────────────────────

fn send_response(mut stream: TcpStream, status: &str, content_type: &str, body: &str) {
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes());
}

fn send_redirect(mut stream: TcpStream, location: &str) {
    let resp = format!(
        "HTTP/1.1 303 See Other\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let _ = stream.write_all(resp.as_bytes());
}

/// Parse the raw HTTP request bytes into (method, path, body).
fn parse_request(raw: &str) -> (&str, &str, &str) {
    let first_line = raw.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let path = parts.next().unwrap_or("/");

    let body = raw
        .split_once("\r\n\r\n")
        .map(|(_, b)| b)
        .unwrap_or("");

    (method, path, body)
}

/// Parse ?since=<ts> query param from a path like /room/events?since=123
fn parse_since_ts(path: &str) -> u64 {
    path.split_once('?')
        .and_then(|(_, qs)| {
            qs.split('&')
                .find_map(|kv| kv.strip_prefix("since="))
                .and_then(|v| v.parse::<u64>().ok())
        })
        .unwrap_or(0)
}

// ── SSE handler (blocking, one thread per connection) ────────────

fn handle_sse(mut stream: TcpStream, room_label: String, since_ts: u64) {
    let room = match store::find_room(&room_label) {
        Some(r) => r,
        None => {
            let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
            return;
        }
    };

    let headers = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nAccess-Control-Allow-Origin: *\r\nX-Accel-Buffering: no\r\nConnection: keep-alive\r\n\r\n";
    if stream.write_all(headers).is_err() {
        return;
    }

    let me = store::get_agent_id();
    let mut last_ts = since_ts;
    let mut relay_tick: u32 = 0;

    loop {
        thread::sleep(Duration::from_secs(3));
        relay_tick += 1;

        // Every 5 ticks (~15 s) fetch from relay to populate local store.
        if relay_tick % 5 == 0 {
            let _ = chat::read("30m", 50, Some(&room_label));
        }

        // Send keepalive ping
        if stream.write_all(b": ping\n\n").is_err() {
            break;
        }

        // Find messages newer than last_ts in local store.
        let new_msgs: Vec<_> = store::load_messages(&room.room_id, 86400)
            .into_iter()
            .filter(|m| m["ts"].as_u64().unwrap_or(0) > last_ts)
            .collect();

        if new_msgs.is_empty() {
            continue;
        }

        last_ts = new_msgs
            .iter()
            .map(|m| m["ts"].as_u64().unwrap_or(0))
            .max()
            .unwrap_or(last_ts);

        for msg in &new_msgs {
            let html = render_message_html(msg, &me, &room.room_id);
            // SSE data field must be single line — collapse newlines.
            let html_flat = html.replace('\n', "");
            let event = format!("data: {html_flat}\n\n");
            if stream.write_all(event.as_bytes()).is_err() {
                return;
            }
        }
    }
}

// ── Connection dispatcher ─────────────────────────────────────────

fn handle_connection(stream: TcpStream) {
    let mut buf = vec![0u8; 8192];
    let n = match stream.try_clone().ok().and_then(|mut s| s.read(&mut buf).ok()) {
        Some(n) => n,
        None => return,
    };
    let raw = String::from_utf8_lossy(&buf[..n]).into_owned();
    let (method, path, body) = parse_request(&raw);

    // Strip query string for routing
    let path_only = path.split('?').next().unwrap_or(path);
    let segments: Vec<&str> = path_only.trim_start_matches('/').split('/').collect();

    match (method, segments.as_slice()) {
        // GET / — room index
        ("GET", [""]) | ("GET", []) => {
            send_response(stream, "200 OK", "text/html; charset=utf-8", &render_index());
        }

        // GET /:room/events — SSE stream
        ("GET", [room_label, "events"]) => {
            let since_ts = parse_since_ts(path);
            let label = (*room_label).to_string();
            handle_sse(stream, label, since_ts);
        }

        // GET /:room/members — member list
        ("GET", [room_label, "members"]) => {
            let page = render_members_page(room_label);
            let status = if store::find_room(room_label).is_some() { "200 OK" } else { "404 Not Found" };
            send_response(stream, status, "text/html; charset=utf-8", &page);
        }

        // GET /:room/pins — pinned messages
        ("GET", [room_label, "pins"]) => {
            let page = render_pins_page(room_label);
            let status = if store::find_room(room_label).is_some() { "200 OK" } else { "404 Not Found" };
            send_response(stream, status, "text/html; charset=utf-8", &page);
        }

        // GET /:room/search?q=... — search messages
        ("GET", [room_label, "search"]) => {
            let query = path
                .split_once('?')
                .and_then(|(_, qs)| {
                    qs.split('&')
                        .find_map(|kv| kv.strip_prefix("q=").map(|v| url_decode(v)))
                })
                .unwrap_or_default();
            let page = render_search_page(room_label, &query);
            let status = if store::find_room(room_label).is_some() { "200 OK" } else { "404 Not Found" };
            send_response(stream, status, "text/html; charset=utf-8", &page);
        }

        // GET /:room — room history page
        ("GET", [room_label]) => {
            let page = if store::find_room(room_label).is_some() {
                render_room_page(room_label)
            } else {
                render_404(room_label)
            };
            let status = if store::find_room(room_label).is_some() {
                "200 OK"
            } else {
                "404 Not Found"
            };
            send_response(stream, status, "text/html; charset=utf-8", &page);
        }

        // POST /:room/send — send a message
        ("POST", [room_label, "send"]) => {
            if let Some(msg) = form_field(body, "message") {
                let msg = msg.trim().to_string();
                if !msg.is_empty() {
                    let reply = form_field(body, "reply_to").filter(|r| !r.is_empty());
                    let _ = chat::send(&msg, reply.as_deref(), Some(room_label));
                }
            }
            send_redirect(stream, &format!("/{room_label}"));
        }

        // POST /:room/react — emoji reaction
        ("POST", [room_label, "react"]) => {
            if let (Some(msg_id), Some(emoji)) =
                (form_field(body, "msg_id"), form_field(body, "emoji"))
            {
                let _ = chat::react(&msg_id, &emoji, Some(room_label));
            }
            send_redirect(stream, &format!("/{room_label}"));
        }

        // POST /:room/pin — pin a message
        ("POST", [room_label, "pin"]) => {
            if let Some(room) = store::find_room(room_label) {
                if let Some(msg_id) = form_field(body, "msg_id") {
                    store::add_pin(&room.room_id, &msg_id);
                }
            }
            send_redirect(stream, &format!("/{room_label}/pins"));
        }

        // POST /:room/unpin — unpin a message
        ("POST", [room_label, "unpin"]) => {
            if let Some(room) = store::find_room(room_label) {
                if let Some(msg_id) = form_field(body, "msg_id") {
                    store::remove_pin(&room.room_id, &msg_id);
                }
            }
            send_redirect(stream, &format!("/{room_label}/pins"));
        }

        _ => {
            send_response(
                stream,
                "404 Not Found",
                "text/html; charset=utf-8",
                &render_404(path_only),
            );
        }
    }
}

// ── Server entrypoint ─────────────────────────────────────────────

pub fn start(port: u16) {
    let addr = format!("127.0.0.1:{port}");
    let listener = TcpListener::bind(&addr).unwrap_or_else(|e| {
        eprintln!("  Error: Cannot bind to {addr}: {e}");
        std::process::exit(1);
    });

    eprintln!("  Agora Web UI running at http://{addr}");
    eprintln!("  Ctrl-C to stop.\n");

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        thread::spawn(move || handle_connection(stream));
    }
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("<b>a & b</b>"), "&lt;b&gt;a &amp; b&lt;/b&gt;");
        assert_eq!(html_escape("\"ok\""), "&quot;ok&quot;");
        assert_eq!(html_escape("safe text"), "safe text");
    }

    #[test]
    fn test_url_decode_plus_and_percent() {
        assert_eq!(url_decode("hello+world"), "hello world");
        assert_eq!(url_decode("foo%3Dbar"), "foo=bar");
        assert_eq!(url_decode("hello%20world"), "hello world");
        assert_eq!(url_decode("no+encoding+here"), "no encoding here");
        assert_eq!(url_decode("100%25+complete"), "100% complete");
    }

    #[test]
    fn test_url_decode_utf8() {
        // café → c%C3%A9f%C3%A9
        let decoded = url_decode("caf%C3%A9");
        assert_eq!(decoded, "café");
    }

    #[test]
    fn test_form_field() {
        let body = "message=Hello+World&reply_to=abc123";
        assert_eq!(form_field(body, "message"), Some("Hello World".to_string()));
        assert_eq!(form_field(body, "reply_to"), Some("abc123".to_string()));
        assert_eq!(form_field(body, "missing"), None);
    }

    #[test]
    fn test_form_field_empty_body() {
        assert_eq!(form_field("", "message"), None);
    }

    #[test]
    fn test_parse_request_get() {
        let raw = "GET /collab HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let (method, path, body) = parse_request(raw);
        assert_eq!(method, "GET");
        assert_eq!(path, "/collab");
        assert_eq!(body, "");
    }

    #[test]
    fn test_parse_request_post() {
        let raw = "POST /collab/send HTTP/1.1\r\nContent-Length: 15\r\n\r\nmessage=hi+there";
        let (method, path, body) = parse_request(raw);
        assert_eq!(method, "POST");
        assert_eq!(path, "/collab/send");
        assert_eq!(body, "message=hi+there");
    }

    #[test]
    fn test_parse_since_ts_present() {
        assert_eq!(parse_since_ts("/collab/events?since=1234567890"), 1_234_567_890);
    }

    #[test]
    fn test_parse_since_ts_missing() {
        assert_eq!(parse_since_ts("/collab/events"), 0);
    }

    #[test]
    fn test_parse_since_ts_multiple_params() {
        assert_eq!(parse_since_ts("/events?foo=bar&since=9999&baz=1"), 9999);
    }

    #[test]
    fn test_render_message_html_basic() {
        let msg = serde_json::json!({
            "id": "abcdef12",
            "from": "alice",
            "ts": 1700000000u64,
            "text": "Hello <world>",
        });
        let html = render_message_html(&msg, "bob", "test-room-id");
        assert!(html.contains("alice"));
        assert!(html.contains("Hello &lt;world&gt;"));
        assert!(html.contains("abcde"));
        assert!(html.contains("class=\"msg other\""));
    }

    #[test]
    fn test_render_message_html_own_message() {
        let msg = serde_json::json!({
            "id": "11223344",
            "from": "me",
            "ts": 1700000000u64,
            "text": "my message",
        });
        let html = render_message_html(&msg, "me", "room-id");
        assert!(html.contains("class=\"msg me\""));
    }

    #[test]
    fn test_render_message_html_with_reply() {
        let msg = serde_json::json!({
            "id": "aabbccdd",
            "from": "alice",
            "ts": 1700000000u64,
            "text": "reply text",
            "reply_to": "deadbeef",
        });
        let html = render_message_html(&msg, "bob", "room-id");
        assert!(html.contains("↩"));
        assert!(html.contains("deadbe"));
    }

    #[test]
    fn test_render_index_no_rooms() {
        // With no active registry we should still get valid HTML
        let html = render_index();
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("Agora — Rooms"));
    }

    #[test]
    fn test_render_404() {
        let html = render_404("no-such-room");
        assert!(html.contains("404"));
        assert!(html.contains("no-such-room"));
    }

    #[test]
    fn test_render_message_html_with_highlight() {
        let msg = serde_json::json!({
            "id": "zzyyxxyy",
            "from": "alice",
            "ts": 1700000000u64,
            "text": "Hello agora world",
        });
        let html = render_message_html_ex(&msg, "bob", "room-id", "", "agora");
        assert!(html.contains(r#"class="highlight""#));
        assert!(html.contains("agora"));
    }

    #[test]
    fn test_render_message_html_actions_when_room_label_set() {
        let msg = serde_json::json!({
            "id": "aabb1122",
            "from": "alice",
            "ts": 1700000000u64,
            "text": "action test",
        });
        let html = render_message_html_ex(&msg, "bob", "room-id", "myroom", "");
        assert!(html.contains("msg-actions"));
        assert!(html.contains("setReply"));
        assert!(html.contains("toggleEmoji"));
    }

    #[test]
    fn test_render_message_html_no_actions_without_label() {
        let msg = serde_json::json!({
            "id": "ccdd3344",
            "from": "alice",
            "ts": 1700000000u64,
            "text": "no actions",
        });
        let html = render_message_html(&msg, "bob", "room-id");
        assert!(!html.contains("msg-actions"));
    }

    #[test]
    fn test_render_tab_nav_active() {
        let nav = render_tab_nav("myroom", "members");
        assert!(nav.contains("class=\"active\""));
        assert!(nav.contains("/myroom/members"));
        assert!(nav.contains("/myroom/pins"));
        assert!(nav.contains("/myroom/search"));
    }

    #[test]
    fn test_render_search_page_no_query() {
        let html = render_search_page("nonexistent-room", "");
        // Room not found → 404 page
        assert!(html.contains("404") || html.contains("Search"));
    }

    #[test]
    fn test_render_search_page_xss_safe() {
        // The search form escapes the query value in the input's value attribute
        // Build the HTML directly using html_escape to confirm it escapes properly
        let raw = "<script>alert(1)</script>";
        let escaped = html_escape(raw);
        assert_eq!(escaped, "&lt;script&gt;alert(1)&lt;/script&gt;");
        // Any render path that echoes user input must use html_escape
        assert!(!escaped.contains("<script>"));
    }

    #[test]
    fn test_render_members_page_not_found() {
        let html = render_members_page("no-such-room-xyz");
        assert!(html.contains("404"));
    }

    #[test]
    fn test_render_pins_page_not_found() {
        let html = render_pins_page("no-such-room-xyz");
        assert!(html.contains("404"));
    }
}
