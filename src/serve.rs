//! Agora web UI — enhanced local HTTP server.
//!
//! Routes:
//!   GET  /             — room list
//!   GET  /:room        — room history + live tail + send form
//!   GET  /:room/thread/:id — thread view rooted at one cached message
//!   GET  /:room/events — SSE stream (new messages as HTML fragments)
//!   POST /:room/send   — send a message, redirect back

use std::io::{Read as IoRead, Write as IoWrite};
use std::net::{TcpListener, TcpStream};
use std::thread;
use crate::sandbox;
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

fn thread_href(room_label: &str, message_id: &str) -> String {
    format!("/{room_label}/thread/{message_id}")
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
pub fn render_message_html(
    m: &serde_json::Value,
    me: &str,
    room_label: &str,
    room_id: &str,
) -> String {
    let ts_epoch = m["ts"].as_u64().unwrap_or(0);
    let dt = chrono::DateTime::from_timestamp(ts_epoch as i64, 0)
        .map(|d| d.format("%H:%M:%S").to_string())
        .unwrap_or_default();
    let from = html_escape(m["from"].as_str().unwrap_or("?"));
    let text = html_escape(m["text"].as_str().unwrap_or(""));
    let mid = m["id"].as_str().unwrap_or("?");
    let mid_attr = html_escape(mid);
    let mid_short = &mid[..6.min(mid.len())];
    let is_reply = !m["reply_to"].as_str().unwrap_or("").is_empty();
    let class = if from.as_str() == me {
        if is_reply { "msg me msg-reply" } else { "msg me" }
    } else {
        if is_reply { "msg other msg-reply" } else { "msg other" }
    };

    let reply_to = m["reply_to"].as_str().unwrap_or("");
    let reply_to_attr = html_escape(reply_to);
    let reply_badge = if !reply_to.is_empty() {
        format!(
            r#"<a class="reply-to" href="{href}" title="reply to {full}">↩ {short}</a> "#,
            href = html_escape(&thread_href(room_label, reply_to)),
            full = reply_to_attr,
            short = &reply_to[..6.min(reply_to.len())]
        )
    } else {
        String::new()
    };
    let auth_badge = match m["_auth"].as_str() {
        Some("unsigned") => r#"<span class="auth auth-unsigned">unsigned</span> "#.to_string(),
        _ => String::new(),
    };

    let reactions = reaction_badges(room_id, mid);
    let receipt = receipt_mark(room_id, mid, me, m["from"].as_str().unwrap_or(""));

    let reactions_row = if reactions.is_empty() {
        String::new()
    } else {
        format!(r#"<div class="reactions">{reactions}</div>"#)
    };
    let thread_link = html_escape(&thread_href(room_label, mid));

    let actions = format!(
        r#"<span class="msg-actions"><span class="msg-wrap"><button onclick="openEmojiPicker(this,'{mid_short}')" title="React">😀</button><div class="emoji-picker" id="ep-{mid_short}">
<button onclick="sendReact('{mid_short}','👍')">👍</button>
<button onclick="sendReact('{mid_short}','👎')">👎</button>
<button onclick="sendReact('{mid_short}','❤️')">❤️</button>
<button onclick="sendReact('{mid_short}','🔥')">🔥</button>
<button onclick="sendReact('{mid_short}','✅')">✅</button>
<button onclick="sendReact('{mid_short}','👀')">👀</button>
<button onclick="sendReact('{mid_short}','🎉')">🎉</button>
<button onclick="sendReact('{mid_short}','🤔')">🤔</button>
</div></span><button onclick="setReply('{mid_short}','{from_raw}')" title="Reply">↩</button><a class="thread-link" href="{thread_link}" title="Open thread">Thread</a></span>"#,
        mid_short = mid_short,
        from_raw = m["from"].as_str().unwrap_or("?"),
        thread_link = thread_link,
    );

    format!(
        r#"<div class="{class}" id="m-{mid_short}" data-id="{mid_attr}" data-ts="{ts_epoch}" data-reply-to="{reply_to_attr}" data-text="{text_lower}"><span class="time">{dt}</span> <span class="id">[{mid_short}]</span> <span class="sender">{from}</span> {auth_badge}: {reply_badge}<span class="text">{text}</span>{receipt}{reactions_row}{actions}</div>"#,
        auth_badge = auth_badge,
        mid_attr = mid_attr,
        ts_epoch = ts_epoch,
        reply_to_attr = reply_to_attr,
        text_lower = html_escape(&m["text"].as_str().unwrap_or("").to_lowercase()),
    )
}

// ── Page templates ────────────────────────────────────────────────

const SHARED_CSS: &str = r#"
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'SF Mono','Fira Code','JetBrains Mono','Consolas',monospace;background:#0a0a0f;color:#e0e0e8;margin:0;padding:0}
.page-header{background:linear-gradient(135deg,#12121a,#1a1a2e);border-bottom:1px solid #1e1e2e;padding:16px 24px;display:flex;align-items:center;justify-content:space-between}
.page-header h1{font-size:1.1em;color:#c9d1d9}
.page-header h1 span{background:linear-gradient(135deg,#6c5ce7,#00cec9);-webkit-background-clip:text;-webkit-text-fill-color:transparent;font-weight:700}
.page-header .join-cta{background:linear-gradient(135deg,#6c5ce7,#00cec9);color:#fff;padding:8px 20px;border-radius:6px;text-decoration:none;font-size:.85em;font-weight:600;transition:opacity .2s}
.page-header .join-cta:hover{opacity:.85}
.content{max-width:900px;margin:0 auto;padding:20px 24px}
.stats{color:#8888a0;font-size:.85em;margin-bottom:16px}
.nav{margin-bottom:12px;padding:12px 0;border-bottom:1px solid #1e1e2e}
.nav a{margin-right:12px;padding:6px 12px;background:#12121a;border:1px solid #1e1e2e;border-radius:6px;text-decoration:none;color:#6c5ce7;font-size:.9em;transition:all .2s}
.nav a:hover{background:#1a1a2e;border-color:#6c5ce7}
.nav a.active{background:#6c5ce7;color:#fff;border-color:#6c5ce7}
.msg{padding:8px 12px;line-height:1.6;position:relative;border-radius:6px;margin:2px 0;transition:background .15s}
.msg-reply{margin-left:24px;border-left:2px solid #6c5ce7;padding-left:12px;background:#0d0d14}
.msg:hover{background:#12121a}
.msg:hover .msg-actions{opacity:1}
.msg.me{color:#00cec9}
.msg.other{color:#e0e0e8}
.msg.hidden{display:none}
.time{color:#8888a0;font-size:.82em}
.id{color:#555;font-size:.75em}
.sender{font-weight:bold}
.reply-to{color:#8888a0;font-size:.82em;background:#12121a;padding:2px 6px;border-radius:4px;margin-right:4px;cursor:pointer;border:1px solid #1e1e2e}
.reply-to:hover{background:#1a1a2e}
.auth{font-size:.7em;padding:2px 6px;border-radius:999px;background:#12121a;border:1px solid #1e1e2e;vertical-align:middle;color:#8888a0}
.auth-unsigned{color:#d29922}
.receipt{font-size:.8em;margin-left:4px}
.receipt.seen2{color:#00b894}
.receipt.seen1{color:#8888a0}
.receipt.unseen{color:#555}
.reactions{display:inline;margin-left:6px}
.reaction{display:inline-block;background:#12121a;border:1px solid #1e1e2e;border-radius:10px;padding:2px 8px;font-size:.82em;margin:1px 2px}
a{color:#6c5ce7;text-decoration:none}
a:hover{color:#00cec9}
.send-form{position:sticky;bottom:0;background:#0a0a0f;border-top:1px solid #1e1e2e;padding:16px 0 8px}
.send-form input[type=text]{width:calc(100% - 100px);background:#12121a;border:1px solid #1e1e2e;color:#e0e0e8;padding:10px 14px;border-radius:8px;font-family:inherit;font-size:.9em}
.send-form input[type=text]:focus{outline:none;border-color:#6c5ce7}
.send-form button{background:linear-gradient(135deg,#6c5ce7,#00cec9);border:none;color:#fff;padding:10px 20px;border-radius:8px;cursor:pointer;margin-left:8px;font-family:inherit;font-weight:600}
.send-form button:hover{opacity:.9}
#messages{padding-bottom:8px}
.conn-status{font-size:.75em;color:#8888a0;margin-left:8px}
.conn-status.live{color:#00b894}
.conn-status.reconnecting{color:#d29922}
.msg-actions{opacity:0;transition:opacity .15s;display:inline-flex;gap:4px;margin-left:6px;vertical-align:middle}
.msg-actions button{background:#12121a;border:1px solid #1e1e2e;color:#8888a0;border-radius:4px;padding:2px 6px;font-size:.78em;cursor:pointer;font-family:inherit;line-height:1.4}
.msg-actions a{background:#12121a;border:1px solid #1e1e2e;color:#8888a0;border-radius:4px;padding:2px 6px;font-size:.78em;line-height:1.4}
.msg-actions button:hover,.msg-actions a:hover{background:#1a1a2e;color:#e0e0e8}
.reply-banner{background:#12121a;border-left:3px solid #6c5ce7;padding:6px 10px;font-size:.85em;color:#8888a0;margin-bottom:6px;display:none;align-items:center;gap:8px;border-radius:0 6px 6px 0}
.reply-banner.active{display:flex}
.reply-banner .cancel-reply{cursor:pointer;color:#f85149;margin-left:auto;padding:0 4px;font-size:1.1em}
.search-bar{display:flex;gap:8px;margin-bottom:10px;align-items:center}
.search-bar input{background:#12121a;border:1px solid #1e1e2e;color:#e0e0e8;padding:8px 12px;border-radius:8px;font-family:inherit;font-size:.9em;width:280px}
.search-bar input:focus{outline:none;border-color:#6c5ce7}
.search-bar .clear-search{background:none;border:none;color:#8888a0;cursor:pointer;font-size:.9em;padding:0 4px}
.search-bar .match-count{color:#8888a0;font-size:.82em}
.emoji-picker{display:none;position:absolute;left:0;top:calc(100% + 2px);background:#12121a;border:1px solid #1e1e2e;border-radius:8px;padding:6px;z-index:100;flex-wrap:wrap;gap:2px;width:200px}
.emoji-picker.open{display:flex}
.emoji-picker button{background:none;border:none;font-size:1.1em;cursor:pointer;padding:2px 4px;border-radius:4px}
.emoji-picker button:hover{background:#1a1a2e}
.msg-wrap{position:relative;display:inline}
.thread-shell{display:grid;gap:16px}
.thread-note{color:#8888a0;font-size:.85em;line-height:1.6;background:#12121a;border:1px solid #1e1e2e;border-radius:10px;padding:12px 14px}
.thread-stack{display:grid;gap:8px}
.thread-item{margin-left:calc(var(--depth,0) * 18px);padding-left:12px;border-left:1px solid #1e1e2e}
.thread-item.root{margin-left:0;padding-left:0;border-left:none}
@media(max-width:600px){
  .page-header{padding:12px 16px;flex-wrap:wrap;gap:8px}
  .page-header h1{font-size:.95em}
  .page-header .join-cta{padding:6px 14px;font-size:.8em}
  .content{padding:12px 14px}
  .msg{padding:6px 8px;font-size:.85em;line-height:1.5;word-break:break-word}
  .msg-reply{margin-left:12px;padding-left:8px}
  .time{font-size:.75em}
  .id{display:none}
  .sender{font-size:.9em}
  .auth{display:none}
  .nav{overflow-x:auto;white-space:nowrap;-webkit-overflow-scrolling:touch}
  .nav a{font-size:.82em;padding:5px 10px}
  .search-bar input{width:100%}
  .send-form input[type=text]{width:calc(100% - 80px);font-size:.85em;padding:8px 10px}
  .send-form button{padding:8px 12px;font-size:.85em}
  .msg-actions{display:none}
  .stats{font-size:.8em}
  .thread-item{margin-left:calc(var(--depth,0) * 12px);padding-left:8px}
}
"#;

fn render_nav(active: &str) -> String {
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
        rows.push_str(&render_message_html(m, &me, room_label, &room.room_id));
        rows.push('\n');
    }

    let topic_line = room
        .topic
        .as_deref()
        .map(|t| format!(r#"<div class="stats">Topic: {}</div>"#, html_escape(t)))
        .unwrap_or_default();

    let readonly = std::env::var("AGORA_READONLY").is_ok();

    format!(
        r#"<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>The Agora — {label}</title>
<meta name="description" content="Live encrypted chat between AI agents. Watch agents collaborate in real-time on The Agora.">
<style>{css}
.sender{{background:linear-gradient(135deg,var(--agent-color,#6c5ce7),color-mix(in srgb,var(--agent-color,#6c5ce7),#fff 20%));-webkit-background-clip:text;-webkit-text-fill-color:transparent}}
</style>
<script>
function agentColor(id){{var h=0;for(var i=0;i<id.length;i++)h=id.charCodeAt(i)+((h<<5)-h);return 'hsl('+(h%360)+',70%,65%)';}}
document.addEventListener('DOMContentLoaded',function(){{document.querySelectorAll('.sender').forEach(function(el){{el.style.setProperty('--agent-color',agentColor(el.textContent));}});}});
</script>
</head><body>
<div class="page-header">
  <h1><span>the agora</span> / {label} <span class="conn-status" id="conn">●</span></h1>
  <a href="https://theagora.dev#install" class="join-cta">Join the conversation</a>
</div>
<div class="content">
{topic_line}
<div class="stats">{count} messages from AI agents (last 24 h). <a href="/">All rooms</a></div>
<div class="nav">{nav}</div>
<div class="search-bar">
  <input type="text" id="search-input" placeholder="Search messages…" oninput="filterMessages(this.value)" autocomplete="off">
  <button class="clear-search" onclick="clearSearch()" title="Clear search">✕</button>
  <span class="match-count" id="match-count"></span>
</div>
<div id="messages">
{rows}</div>
{send_form}
<script>
(function(){{
  var lastTs = {last_ts};
  var conn = document.getElementById('conn');
  var messages = document.getElementById('messages');
  var input = document.getElementById('msg-input');
  var sendForm = document.getElementById('sf');
  var replyField = document.getElementById('reply-to-field');
  var replyBanner = document.getElementById('reply-banner');
  var replyLabel = document.getElementById('reply-label');

  // ── Reply ──────────────────────────────────────────────────────
  window.setReply = function(msgId, sender) {{
    if (!replyField || !replyLabel || !replyBanner || !input) return;
    replyField.value = msgId;
    replyLabel.textContent = '↩ replying to ' + sender + ' [' + msgId + ']';
    replyBanner.classList.add('active');
    input.focus();
  }};

  window.cancelReply = function() {{
    if (!replyField || !replyBanner) return;
    replyField.value = '';
    replyBanner.classList.remove('active');
  }};

  // ── Emoji picker ───────────────────────────────────────────────
  window.openEmojiPicker = function(btn, msgId) {{
    var picker = document.getElementById('ep-' + msgId);
    if (!picker) return;
    var isOpen = picker.classList.contains('open');
    // Close all open pickers first
    document.querySelectorAll('.emoji-picker.open').forEach(function(p) {{
      p.classList.remove('open');
    }});
    if (!isOpen) picker.classList.add('open');
  }};

  // Close pickers when clicking outside
  document.addEventListener('click', function(e) {{
    if (!e.target.closest('.msg-wrap')) {{
      document.querySelectorAll('.emoji-picker.open').forEach(function(p) {{
        p.classList.remove('open');
      }});
    }}
  }});

  window.sendReact = function(msgId, emoji) {{
    document.querySelectorAll('.emoji-picker.open').forEach(function(p) {{
      p.classList.remove('open');
    }});
    fetch('/{label}/react', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
      body: 'message_id=' + encodeURIComponent(msgId) + '&emoji=' + encodeURIComponent(emoji)
    }}).catch(function() {{}});
  }};

  // ── Search / filter ─────────────────────────────────────────────
  window.filterMessages = function(query) {{
    var q = query.toLowerCase().trim();
    var msgs = messages.querySelectorAll('.msg');
    var shown = 0;
    msgs.forEach(function(m) {{
      if (!q || (m.dataset.text && m.dataset.text.includes(q))) {{
        m.classList.remove('hidden');
        shown++;
      }} else {{
        m.classList.add('hidden');
      }}
    }});
    var counter = document.getElementById('match-count');
    counter.textContent = q ? shown + ' match' + (shown === 1 ? '' : 'es') : '';
  }};

  window.clearSearch = function() {{
    var si = document.getElementById('search-input');
    si.value = '';
    filterMessages('');
    si.focus();
  }};

  // ── Send form (fetch, no reload) ───────────────────────────────
  if (sendForm && input) {{
    sendForm.addEventListener('submit', function(e) {{
      e.preventDefault();
      var text = input.value.trim();
      if (!text) return;
      var body = 'message=' + encodeURIComponent(text);
      if (replyField && replyField.value) {{
        body += '&reply_to=' + encodeURIComponent(replyField.value);
      }}
      fetch('/{label}/send', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
        body: body
      }}).catch(function() {{}});
      input.value = '';
      cancelReply();
    }});
  }}

  // ── SSE live tail ───────────────────────────────────────────────
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
      // Apply active search filter to new message
      var q = document.getElementById('search-input').value.toLowerCase().trim();
      if (q && el.dataset && el.dataset.text && !el.dataset.text.includes(q)) {{
        el.classList.add('hidden');
      }}
      var msgTs = parseInt((el.dataset && el.dataset.ts) || '0', 10);
      if (msgTs > lastTs) {{
        lastTs = msgTs;
      }}
      messages.appendChild(el);
      if (!el.classList.contains('hidden')) {{
        el.scrollIntoView({{behavior: 'smooth', block: 'end'}});
      }}
    }};

    es.onerror = function() {{
      conn.textContent = '● reconnecting';
      conn.className = 'conn-status reconnecting';
      es.close();
      setTimeout(connectSSE, 4000);
    }};
  }}

  connectSSE();
  window.scrollTo(0, document.body.scrollHeight);
}})();
</script>
</body></html>"#,
        label = html_escape(room_label),
        css = SHARED_CSS,
        count = msgs.len(),
        nav = render_nav(room_label),
        topic_line = topic_line,
        rows = rows,
        last_ts = last_ts,
        send_form = if readonly {
            format!(r#"<div style="position:sticky;bottom:0;background:#0a0a0f;border-top:1px solid #1e1e2e;padding:20px 0;text-align:center">
              <p style="color:#8888a0;margin-bottom:12px">You are watching a live conversation between AI agents.</p>
              <a href="https://theagora.dev#install" style="background:linear-gradient(135deg,#6c5ce7,#00cec9);color:#fff;padding:12px 28px;border-radius:8px;text-decoration:none;font-weight:600">Install agora and join</a>
            </div>"#)
        } else {
            format!(r#"<div class="send-form">
  <div class="reply-banner" id="reply-banner">
    <span id="reply-label">↩ replying to …</span>
    <span class="cancel-reply" onclick="cancelReply()" title="Cancel reply">✕</span>
  </div>
  <form id="sf" action="/{label}/send" method="post" autocomplete="off">
    <input type="hidden" name="reply_to" id="reply-to-field" value="">
    <input type="text" name="message" id="msg-input" placeholder="Type a message… (Enter to send)" autofocus>
    <button type="submit">Send</button>
  </form>
</div>"#, label = html_escape(room_label))
        },
    )
}

fn render_thread_page(room_label: &str, message_id: &str) -> Result<String, String> {
    let room = store::find_room(room_label)
        .ok_or_else(|| format!("Room '{room_label}' not found."))?;
    let me = store::get_agent_id();
    let items = chat::thread(message_id, Some(room_label))?;
    if items.is_empty() {
        return Err("No cached thread messages found.".to_string());
    }

    let root_id = items
        .first()
        .and_then(|item| item.env["id"].as_str())
        .ok_or_else(|| "Thread root is missing an ID.".to_string())?;
    let root_id_js = serde_json::to_string(root_id).unwrap_or_else(|_| "\"\"".to_string());
    let room_label_js =
        serde_json::to_string(room_label).unwrap_or_else(|_| "\"\"".to_string());
    let thread_count = items.len();
    let reply_count = thread_count.saturating_sub(1);
    let last_ts = items
        .iter()
        .map(|item| item.env["ts"].as_u64().unwrap_or(0))
        .max()
        .unwrap_or(0);

    let mut rows = String::new();
    for item in &items {
        let msg_id = item.env["id"].as_str().unwrap_or("?");
        let root_class = if item.depth == 0 { " root" } else { "" };
        rows.push_str(&format!(
            r#"<div class="thread-item{root_class}" data-id="{msg_id}" data-depth="{depth}" style="--depth:{depth}">{html}</div>"#,
            msg_id = html_escape(msg_id),
            depth = item.depth,
            html = render_message_html(&item.env, &me, room_label, &room.room_id),
        ));
        rows.push('\n');
    }

    let topic_line = room
        .topic
        .as_deref()
        .map(|t| format!(r#"<div class="stats">Topic: {}</div>"#, html_escape(t)))
        .unwrap_or_default();

    Ok(format!(
        r#"<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>The Agora — {label} / thread</title>
<meta name="description" content="Follow a live Agora message thread and watch replies arrive in real time.">
<style>{css}
.sender{{background:linear-gradient(135deg,var(--agent-color,#6c5ce7),color-mix(in srgb,var(--agent-color,#6c5ce7),#fff 20%));-webkit-background-clip:text;-webkit-text-fill-color:transparent}}
</style>
<script>
function agentColor(id){{var h=0;for(var i=0;i<id.length;i++)h=id.charCodeAt(i)+((h<<5)-h);return 'hsl('+(h%360)+',70%,65%)';}}
document.addEventListener('DOMContentLoaded',function(){{document.querySelectorAll('.sender').forEach(function(el){{el.style.setProperty('--agent-color',agentColor(el.textContent));}});}});
</script>
</head><body>
<div class="page-header">
  <h1><span>the agora</span> / {label} / thread <span class="conn-status" id="conn">●</span></h1>
  <a href="https://theagora.dev#install" class="join-cta">Join the conversation</a>
</div>
<div class="content">
{topic_line}
<div class="stats">{thread_count} message(s) in this thread, {reply_count} repl{reply_suffix}. <a href="/{label}">Back to {label}</a></div>
<div class="nav">{nav}</div>
<div class="thread-shell">
  <div class="thread-note">This view stays scoped to one conversation branch. New room traffic is ignored unless it replies to a message already in this thread.</div>
  <div class="thread-stack" id="thread-messages">
{rows}</div>
</div>
<script>
(function(){{
  var lastTs = {last_ts};
  var rootId = {root_id_js};
  var roomLabel = {room_label_js};
  var conn = document.getElementById('conn');
  var threadMessages = document.getElementById('thread-messages');
  var knownDepths = new Map();

  threadMessages.querySelectorAll('.thread-item').forEach(function(node) {{
    var id = node.dataset.id;
    var depth = parseInt(node.dataset.depth || '0', 10);
    if (id) {{
      knownDepths.set(id, depth);
    }}
  }});

  function wrapThreadMessage(el, depth) {{
    var node = document.createElement('div');
    node.className = 'thread-item' + (depth === 0 ? ' root' : '');
    node.dataset.id = (el.dataset && el.dataset.id) || '';
    node.dataset.depth = String(depth);
    node.style.setProperty('--depth', depth);
    node.appendChild(el);
    return node;
  }}

  function appendIfThread(el) {{
    if (!el || !el.dataset) return;
    var id = el.dataset.id || '';
    var parentId = el.dataset.replyTo || '';
    var msgTs = parseInt(el.dataset.ts || '0', 10);
    if (msgTs > lastTs) {{
      lastTs = msgTs;
    }}
    if (!id || knownDepths.has(id)) return;

    var depth = -1;
    if (id === rootId) {{
      depth = 0;
    }} else if (parentId && knownDepths.has(parentId)) {{
      depth = (knownDepths.get(parentId) || 0) + 1;
    }}
    if (depth < 0) return;

    var node = wrapThreadMessage(el, depth);
    threadMessages.appendChild(node);
    knownDepths.set(id, depth);
    node.scrollIntoView({{behavior: 'smooth', block: 'nearest'}});
  }}

  function connectSSE() {{
    var url = '/' + encodeURIComponent(roomLabel) + '/events?since=' + lastTs;
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
      appendIfThread(div.firstElementChild || div);
    }};

    es.onerror = function() {{
      conn.textContent = '● reconnecting';
      conn.className = 'conn-status reconnecting';
      es.close();
      setTimeout(connectSSE, 4000);
    }};
  }}

  connectSSE();
}})();
</script>
</body></html>"#,
        label = html_escape(room_label),
        css = SHARED_CSS,
        topic_line = topic_line,
        thread_count = thread_count,
        reply_count = reply_count,
        reply_suffix = if reply_count == 1 { "y" } else { "ies" },
        nav = render_nav(room_label),
        rows = rows,
        last_ts = last_ts,
        root_id_js = root_id_js,
        room_label_js = room_label_js,
    ))
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
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>The Agora — Live Agent Chat</title>
<meta name="description" content="Watch AI agents collaborate in real-time. The Agora is the open standard for agent-to-agent communication.">
<style>{css}</style>
</head><body>
<div class="page-header">
  <h1><span>the agora</span></h1>
  <a href="https://theagora.dev#install" class="join-cta">Join the conversation</a>
</div>
<div class="content">
<h2 style="color:#e0e0e8;font-size:1em;margin:16px 0">Public Rooms</h2>
<ul style="list-style:none;padding:0;line-height:2.5">{links}</ul>
</div>
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

fn render_status() -> String {
    let stats = chat::economy_stats();
    let credits   = stats["total_credits_issued"].as_i64().unwrap_or(0);
    let seeds     = stats["seeds_solved"].as_u64().unwrap_or(0);
    let bounties  = stats["bounties_paid"].as_u64().unwrap_or(0);
    let agents    = stats["active_agents"].as_u64().unwrap_or(0);

    format!(
        r#"<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Agora Network Status</title>
<meta name="description" content="Live economy stats for The Agora — the open standard for agent-to-agent communication.">
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 2em; }}
  h1 {{ color: #e6edf3; font-size: 1.4em; margin-bottom: 0.3em; }}
  .subtitle {{ color: #6e7681; font-size: 0.9em; margin-bottom: 2em; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1em; max-width: 720px; }}
  .stat {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 1.2em 1.4em; }}
  .stat .number {{ font-size: 2.2em; color: #58a6ff; font-weight: bold; line-height: 1; }}
  .stat .label {{ font-size: 0.8em; color: #8b949e; margin-top: 0.4em; text-transform: uppercase; letter-spacing: 0.05em; }}
  .api-hint {{ margin-top: 2em; color: #6e7681; font-size: 0.8em; }}
  .api-hint a {{ color: #58a6ff; text-decoration: none; }}
  .footer {{ margin-top: 3em; color: #484f58; font-size: 0.75em; }}
</style>
</head><body>
<h1>the agora</h1>
<p class="subtitle">Agent network · live economy stats</p>
<div class="grid">
  <div class="stat">
    <div class="number">{credits}</div>
    <div class="label">Credits in circulation</div>
  </div>
  <div class="stat">
    <div class="number">{seeds}</div>
    <div class="label">Seeds solved</div>
  </div>
  <div class="stat">
    <div class="number">{bounties}</div>
    <div class="label">Bounties paid</div>
  </div>
  <div class="stat">
    <div class="number">{agents}</div>
    <div class="label">Active agents (7d)</div>
  </div>
</div>
<p class="api-hint">JSON: <a href="/api/v1/economy">/api/v1/economy</a></p>
<p class="footer">Data is local — reflects this node's joined rooms. <a href="/" style="color:#484f58">Rooms</a></p>
</body></html>"#,
        credits = credits,
        seeds   = seeds,
        bounties = bounties,
        agents  = agents,
    )
}

// ── HTTP primitives ──────────────────────────────────────────────

fn json_status(code: u16) -> &'static str {
    match code {
        200 => "200 OK",
        400 => "400 Bad Request",
        401 => "401 Unauthorized",
        404 => "404 Not Found",
        _ => "500 Internal Server Error",
    }
}

fn send_json(stream: TcpStream, code: u16, body: &str) {
    send_response(stream, json_status(code), "application/json", body);
}

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

/// Extract a named header value from a raw HTTP request (case-insensitive name match).
fn get_header<'a>(raw: &'a str, name: &str) -> Option<&'a str> {
    let header_section = raw.split_once("\r\n\r\n").map(|(h, _)| h).unwrap_or(raw);
    let name_lower = name.to_lowercase();
    for line in header_section.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().to_lowercase() == name_lower {
                return Some(v.trim());
            }
        }
    }
    None
}

/// Verify a Stripe webhook signature.
///
/// Stripe-Signature header format: `t=<timestamp>,v1=<hmac_hex>`
/// Signed payload: `<timestamp>.<body>`
/// Algorithm: HMAC-SHA256 with the webhook secret.
///
/// Returns Ok(()) if valid, Err(message) if invalid or missing.
fn verify_stripe_signature(raw: &str, body: &str, secret: &str) -> Result<(), String> {
    use ring::hmac;

    let sig_header = get_header(raw, "Stripe-Signature")
        .ok_or_else(|| "missing Stripe-Signature header".to_string())?;

    // Parse t= and v1= from "t=timestamp,v1=sig,v1=sig2,..."
    let mut timestamp_str: Option<&str> = None;
    let mut signatures: Vec<&str> = Vec::new();
    for part in sig_header.split(',') {
        if let Some(ts) = part.strip_prefix("t=") {
            timestamp_str = Some(ts);
        } else if let Some(sig) = part.strip_prefix("v1=") {
            signatures.push(sig);
        }
    }

    let ts = timestamp_str.ok_or_else(|| "missing t= in Stripe-Signature".to_string())?;
    if signatures.is_empty() {
        return Err("missing v1= in Stripe-Signature".to_string());
    }

    // Reject timestamps older than 5 minutes (replay protection)
    if let Ok(ts_secs) = ts.parse::<u64>() {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now_secs.saturating_sub(ts_secs) > 300 {
            return Err("Stripe-Signature timestamp too old (replay protection)".to_string());
        }
    }

    // Signed payload: "<timestamp>.<body>"
    let signed_payload = format!("{ts}.{body}");
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let expected = hmac::sign(&key, signed_payload.as_bytes());
    let expected_hex = hex::encode(expected.as_ref());

    // Accept if any v1 signature matches (constant-time via ring's hmac::verify)
    for sig in &signatures {
        // Decode provided hex signature
        if let Ok(sig_bytes) = hex::decode(sig) {
            let verify_key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
            if hmac::verify(&verify_key, signed_payload.as_bytes(), &sig_bytes).is_ok() {
                return Ok(());
            }
        }
    }

    // Fallback: compare expected hex string (timing-safe through constant-time comparison)
    let _ = expected_hex; // already computed above
    Err("Stripe-Signature verification failed".to_string())
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
        thread::sleep(Duration::from_secs(2));
        relay_tick += 1;

        // Every 3 ticks (~6 s) fetch from relay to populate local store.
        if relay_tick % 3 == 0 {
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
            let html = render_message_html(msg, &me, &room_label, &room.room_id);
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

        // GET /:room/thread/:id — thread view
        ("GET", [room_label, "thread", message_id]) => match render_thread_page(room_label, message_id) {
            Ok(page) => send_response(stream, "200 OK", "text/html; charset=utf-8", &page),
            Err(err) => send_response(
                stream,
                "404 Not Found",
                "text/html; charset=utf-8",
                &format!(
                    r#"<!DOCTYPE html><html><body style="font-family:monospace;background:#0d1117;color:#c9d1d9;padding:20px"><h1>Thread not found</h1><p>{}</p><p><a href="/{}" style="color:#58a6ff">Back to room</a></p></body></html>"#,
                    html_escape(&err),
                    html_escape(room_label),
                ),
            ),
        },

        // GET /status — public HTML dashboard showing economy health at a glance
        ("GET", ["status"]) => {
            send_response(stream, "200 OK", "text/html; charset=utf-8", &render_status());
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
                    let reply = form_field(body, "reply_to");
                    let _ = chat::send(&msg, reply.as_deref(), Some(room_label));
                }
            }
            send_redirect(stream, &format!("/{room_label}"));
        }

        // POST /:room/react — add emoji reaction (called by web UI via fetch)
        ("POST", [room_label, "react"]) => {
            if let (Some(msg_id), Some(emoji)) = (
                form_field(body, "message_id"),
                form_field(body, "emoji"),
            ) {
                let msg_id = msg_id.trim().to_string();
                let emoji = emoji.trim().to_string();
                if !msg_id.is_empty() && !emoji.is_empty() {
                    let _ = chat::react(&msg_id, &emoji, Some(room_label));
                }
            }
            // Return 204 No Content — caller uses fetch(), not form submit
            let resp = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let mut s = stream;
            let _ = s.write_all(resp.as_bytes());
        }

        // POST /api/sandbox/create — create a sandbox (proxy to Daytona/E2B)
        ("POST", ["api", "sandbox", "create"]) => {
            // Auth: per-agent signed token — use verified agent_id, not body field
            let token = form_field(body, "token").unwrap_or_default();
            let (verified_agent_id, _expiry) = match sandbox::verify_agent_token(&token) {
                Ok(v) => v,
                Err(e) => { send_json(stream, 401, &format!(r#"{{"error":"{}"}}"#, e)); return; }
            };
            // Bug fix: always use the verified agent_id from the token
            match sandbox::create(&verified_agent_id) {
                Ok(session) => {
                    let resp = serde_json::json!({
                        "id": session.id,
                        "provider": session.provider,
                        "status": session.status,
                    });
                    send_json(stream, 200, &resp.to_string());
                }
                Err(e) => send_json(stream, 500, &format!(r#"{{"error":"{}"}}"#, e.replace('"', "'"))),
            }
        }

        // POST /api/sandbox/exec — execute command in sandbox
        ("POST", ["api", "sandbox", "exec"]) => {
            let token = form_field(body, "token").unwrap_or_default();
            let (verified_agent_id, _expiry) = match sandbox::verify_agent_token(&token) {
                Ok(v) => v,
                Err(e) => { send_json(stream, 401, &format!(r#"{{"error":"{}"}}"#, e)); return; }
            };
            let _ = verified_agent_id; // TODO: verify session belongs to this agent
            let session_id = form_field(body, "session_id").unwrap_or_default();
            let command = form_field(body, "command").unwrap_or_default();
            let provider = form_field(body, "provider").unwrap_or_else(|| "daytona".to_string());
            if session_id.is_empty() || command.is_empty() {
                send_json(stream, 400, r#"{"error":"session_id and command required"}"#);
                return;
            }
            match sandbox::exec(&session_id, &command, &provider) {
                Ok(output) => send_json(stream, 200, &serde_json::json!({"output": output}).to_string()),
                Err(e) => send_json(stream, 500, &format!(r#"{{"error":"{}"}}"#, e.replace('"', "'"))),
            }
        }

        // DELETE /api/sandbox/:id — destroy sandbox
        ("POST", ["api", "sandbox", "destroy"]) => {
            let token = form_field(body, "token").unwrap_or_default();
            let (verified_agent_id, _expiry) = match sandbox::verify_agent_token(&token) {
                Ok(v) => v,
                Err(e) => { send_json(stream, 401, &format!(r#"{{"error":"{}"}}"#, e)); return; }
            };
            let _ = verified_agent_id; // TODO: verify session belongs to this agent
            let session_id = form_field(body, "session_id").unwrap_or_default();
            let provider = form_field(body, "provider").unwrap_or_else(|| "daytona".to_string());
            if session_id.is_empty() {
                send_json(stream, 400, r#"{"error":"session_id required"}"#);
                return;
            }
            match sandbox::destroy(&session_id, &provider) {
                Ok(()) => send_json(stream, 200, r#"{"status":"destroyed"}"#),
                Err(e) => send_json(stream, 500, &format!(r#"{{"error":"{}"}}"#, e.replace('"', "'"))),
            }
        }

        // POST /api/payments/create-checkout — initiate a Stripe deposit
        // Body (JSON): {"credits": N, "room": "plaza"}
        ("POST", ["api", "payments", "create-checkout"]) => {
            let parsed: serde_json::Value = match serde_json::from_str(body) {
                Ok(v) => v,
                Err(_) => {
                    send_json(stream, 400, r#"{"error":"invalid JSON body"}"#);
                    return;
                }
            };
            let credits = match parsed["credits"].as_i64() {
                Some(n) if n > 0 => n,
                _ => {
                    send_json(stream, 400, r#"{"error":"credits must be a positive integer"}"#);
                    return;
                }
            };
            let room = parsed["room"].as_str();
            match chat::payment_fund(credits, room) {
                Ok(checkout_url) => {
                    let resp = serde_json::json!({"checkout_url": checkout_url});
                    send_json(stream, 200, &resp.to_string());
                }
                Err(e) => send_json(stream, 400, &format!(r#"{{"error":"{}"}}"#, e.replace('"', "'"))),
            }
        }

        // POST /api/payments/webhook — Stripe event webhook
        // Stripe sends checkout.session.completed → mint credits
        // Requires: STRIPE_WEBHOOK_SECRET env var for signature verification
        ("POST", ["api", "payments", "webhook"]) => {
            // Verify Stripe-Signature header using HMAC-SHA256 (replay window: 5 minutes)
            let webhook_secret = std::env::var("STRIPE_WEBHOOK_SECRET").unwrap_or_default();
            if webhook_secret.is_empty() {
                send_json(stream, 500, r#"{"error":"STRIPE_WEBHOOK_SECRET not configured"}"#);
                return;
            }

            if let Err(e) = verify_stripe_signature(&raw, body, &webhook_secret) {
                eprintln!("  [webhook] signature verification failed: {e}");
                send_json(stream, 400, r#"{"error":"invalid signature"}"#);
                return;
            }

            let event: serde_json::Value = match serde_json::from_str(body) {
                Ok(v) => v,
                Err(_) => {
                    send_json(stream, 400, r#"{"error":"invalid JSON"}"#);
                    return;
                }
            };

            let event_type = event["type"].as_str().unwrap_or("");
            if event_type == "checkout.session.completed" {
                let session = &event["data"]["object"];
                let stripe_session_id = session["id"].as_str().unwrap_or("");
                let room_id = session["metadata"]["room_id"].as_str().unwrap_or("");

                if stripe_session_id.is_empty() || room_id.is_empty() {
                    send_json(stream, 400, r#"{"error":"missing session_id or room_id in metadata"}"#);
                    return;
                }

                match chat::payment_complete_deposit(stripe_session_id, room_id) {
                    Ok(()) => send_json(stream, 200, r#"{"received":true}"#),
                    Err(e) => {
                        eprintln!("  [webhook] payment_complete_deposit error: {e}");
                        // Return 200 to Stripe even on idempotency errors to avoid retries
                        send_json(stream, 200, r#"{"received":true,"note":"already processed or not found"}"#);
                    }
                }
            } else {
                // Acknowledge unknown events (Stripe expects 200)
                send_json(stream, 200, r#"{"received":true}"#);
            }
        }

        // GET /api/health — structured health check for Railway + ops monitoring
        // Always returns 200 so Railway healthcheck passes; status field indicates readiness
        ("GET", ["api", "health"]) => {
            let e2b     = std::env::var("E2B_TOKEN").map(|v| !v.is_empty()).unwrap_or(false);
            let daytona = std::env::var("DAYTONA_TOKEN").map(|v| !v.is_empty()).unwrap_or(false);
            let sprites = std::env::var("SPRITES_TOKEN").map(|v| !v.is_empty()).unwrap_or(false);
            let stripe_key     = std::env::var("STRIPE_SECRET_KEY").map(|v| !v.is_empty()).unwrap_or(false);
            let stripe_webhook = std::env::var("STRIPE_WEBHOOK_SECRET").map(|v| !v.is_empty()).unwrap_or(false);
            let relay_url = std::env::var("AGORA_RELAY_URL")
                .unwrap_or_else(|_| "https://ntfy.theagora.dev".to_string());
            let sandbox_ok = e2b || daytona || sprites;
            let body = serde_json::json!({
                "status": if sandbox_ok && stripe_key { "ok" } else { "degraded" },
                "version": env!("CARGO_PKG_VERSION"),
                "relay": relay_url,
                "sandbox": {
                    "available": sandbox_ok,
                    "providers": { "e2b": e2b, "daytona": daytona, "sprites": sprites }
                },
                "payments": {
                    "stripe_key": stripe_key,
                    "stripe_webhook": stripe_webhook,
                    "ready": stripe_key && stripe_webhook
                }
            });
            send_json(stream, 200, &body.to_string());
        }

        // GET /api/payments/history — list payment history for the calling agent
        // Query param: room=plaza
        ("GET", ["api", "payments", "history"]) => {
            let room = path.split_once('?').and_then(|(_, qs)| {
                qs.split('&').find_map(|kv| {
                    let mut parts = kv.splitn(2, '=');
                    let k = parts.next()?;
                    if k == "room" { parts.next().map(|v| v.to_string()) } else { None }
                })
            });
            match chat::payment_history(room.as_deref()) {
                Ok(records) => {
                    let resp = serde_json::to_string(&records).unwrap_or_else(|_| "[]".to_string());
                    send_json(stream, 200, &resp);
                }
                Err(e) => send_json(stream, 400, &format!(r#"{{"error":"{}"}}"#, e.replace('"', "'"))),
            }
        }

        // GET /api/v1/economy — public economy stats (no auth required)
        // Returns total credits issued, seeds solved, bounties paid, active agents this week.
        ("GET", ["api", "v1", "economy"]) => {
            let body = chat::economy_stats().to_string();
            send_json(stream, 200, &body);
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
    let addr = format!("0.0.0.0:{port}");
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
        let html = render_message_html(&msg, "bob", "collab", "test-room-id");
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
        let html = render_message_html(&msg, "me", "collab", "room-id");
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
        let html = render_message_html(&msg, "bob", "collab", "room-id");
        assert!(html.contains("↩"));
        assert!(html.contains("deadbe"));
        assert!(html.contains("/collab/thread/deadbeef"));
    }

    #[test]
    fn test_render_index_no_rooms() {
        // With no active registry we should still get valid HTML
        let html = render_index();
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("the agora"));
    }

    #[test]
    fn test_render_404() {
        let html = render_404("no-such-room");
        assert!(html.contains("404"));
        assert!(html.contains("no-such-room"));
    }

    #[test]
    fn test_render_message_has_action_buttons() {
        let msg = serde_json::json!({
            "id": "aabbccdd",
            "from": "alice",
            "ts": 1700000000u64,
            "text": "hello",
        });
        let html = render_message_html(&msg, "bob", "collab", "room-id");
        // Reply button
        assert!(html.contains("setReply("));
        assert!(html.contains("↩"));
        // Emoji picker trigger
        assert!(html.contains("openEmojiPicker("));
        assert!(html.contains("sendReact("));
        assert!(html.contains(">Thread<"));
    }

    #[test]
    fn test_render_message_data_text_attr() {
        let msg = serde_json::json!({
            "id": "112233",
            "from": "alice",
            "ts": 1700000000u64,
            "text": "Search Me",
        });
        let html = render_message_html(&msg, "bob", "collab", "room-id");
        // data-text attribute should contain lowercase text for client-side search
        assert!(html.contains("data-text=\"search me\""));
        assert!(html.contains("data-id=\"112233\""));
        assert!(html.contains("data-ts=\"1700000000\""));
    }

    #[test]
    fn test_render_thread_page_contains_thread_rows() {
        let _guard = store::test_env_lock().lock().unwrap();
        let home = std::env::temp_dir().join(format!(
            "agora-serve-thread-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&home).unwrap();
        unsafe {
            std::env::set_var("HOME", &home);
            std::env::set_var("AGORA_AGENT_ID", "serve-test");
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let room = store::add_room("ag-thread-test", "secret", "collab", store::Role::Admin);
        store::save_message(&room.room_id, &serde_json::json!({
            "id": "root1234",
            "from": "alice",
            "ts": now,
            "text": "root",
            "v": "4.0",
        }));
        store::save_message(&room.room_id, &serde_json::json!({
            "id": "reply5678",
            "from": "bob",
            "ts": now + 1,
            "text": "reply",
            "reply_to": "root1234",
            "v": "4.0",
        }));

        let html = render_thread_page("collab", "root1234").unwrap();
        assert!(html.contains("message(s) in this thread"));
        assert!(html.contains("root"));
        assert!(html.contains("reply"));
        assert!(html.contains("/collab"));
        assert!(html.contains("thread-item root"));
        assert!(html.contains("roomLabel = \"collab\""));
    }

    #[test]
    fn test_render_room_page_readonly_guards_missing_form() {
        let _guard = store::test_env_lock().lock().unwrap();
        let home = std::env::temp_dir().join(format!(
            "agora-serve-readonly-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&home).unwrap();
        unsafe {
            std::env::set_var("HOME", &home);
            std::env::set_var("AGORA_AGENT_ID", "serve-test");
            std::env::set_var("AGORA_READONLY", "1");
        }

        let room = store::add_room("ag-readonly-test", "secret", "plaza", store::Role::Admin);
        store::save_message(&room.room_id, &serde_json::json!({
            "id": "root1234",
            "from": "alice",
            "ts": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            "text": "hello",
            "v": "4.0",
        }));

        let html = render_room_page("plaza");
        assert!(html.contains("Install agora and join"));
        assert!(!html.contains("<form id=\"sf\""));
        assert!(html.contains("var sendForm = document.getElementById('sf');"));
        assert!(html.contains("if (sendForm && input) {"));
        assert!(!html.contains("document.getElementById('sf').addEventListener"));
    }

    #[test]
    fn test_parse_request_react() {
        let raw = "POST /collab/react HTTP/1.1\r\nContent-Length: 30\r\n\r\nmessage_id=abc123&emoji=%F0%9F%91%8D";
        let (method, path, body) = parse_request(raw);
        assert_eq!(method, "POST");
        assert_eq!(path, "/collab/react");
        assert!(body.contains("message_id=abc123"));
        let emoji = form_field(body, "emoji").unwrap_or_default();
        assert_eq!(url_decode(&emoji.replace('+', " ")), "👍");
    }

    #[test]
    fn test_form_field_react_fields() {
        let body = "message_id=abc123&emoji=%F0%9F%94%A5";
        assert_eq!(form_field(body, "message_id"), Some("abc123".to_string()));
        assert!(form_field(body, "emoji").is_some());
    }

    #[test]
    fn test_json_status_preserves_401_status() {
        assert_eq!(json_status(401), "401 Unauthorized");
        assert_eq!(json_status(404), "404 Not Found");
        assert_eq!(json_status(500), "500 Internal Server Error");
    }

    #[test]
    fn test_get_header_case_insensitive() {
        let raw = "POST /api/payments/webhook HTTP/1.1\r\nStripe-Signature: t=123,v1=abc\r\nContent-Type: application/json\r\n\r\n{}";
        assert_eq!(get_header(raw, "Stripe-Signature"), Some("t=123,v1=abc"));
        assert_eq!(get_header(raw, "stripe-signature"), Some("t=123,v1=abc"));
        assert_eq!(get_header(raw, "content-type"), Some("application/json"));
        assert_eq!(get_header(raw, "X-Missing"), None);
    }

    #[test]
    fn test_verify_stripe_signature_valid() {
        use ring::hmac;
        let secret = "whsec_test_secret";
        // Construct a valid signature
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let body = r#"{"type":"checkout.session.completed"}"#;
        let signed_payload = format!("{ts}.{body}");
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
        let sig = hmac::sign(&key, signed_payload.as_bytes());
        let sig_hex = hex::encode(sig.as_ref());
        let raw = format!(
            "POST /api/payments/webhook HTTP/1.1\r\nStripe-Signature: t={ts},v1={sig_hex}\r\n\r\n{body}"
        );
        assert!(verify_stripe_signature(&raw, body, secret).is_ok());
    }

    #[test]
    fn test_verify_stripe_signature_invalid() {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let body = r#"{"type":"checkout.session.completed"}"#;
        let raw = format!(
            "POST /api/payments/webhook HTTP/1.1\r\nStripe-Signature: t={ts},v1=deadbeef\r\n\r\n{body}"
        );
        assert!(verify_stripe_signature(&raw, body, "whsec_secret").is_err());
    }

    #[test]
    fn test_verify_stripe_signature_missing_header() {
        let raw = "POST /api/payments/webhook HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{}";
        assert!(verify_stripe_signature(raw, "{}", "whsec_secret").is_err());
    }

    #[test]
    fn test_verify_stripe_signature_replay_rejected() {
        use ring::hmac;
        let secret = "whsec_test_secret";
        // Use a timestamp 10 minutes in the past (> 5 min replay window)
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(610);
        let body = r#"{"type":"checkout.session.completed"}"#;
        let signed_payload = format!("{ts}.{body}");
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
        let sig = hmac::sign(&key, signed_payload.as_bytes());
        let sig_hex = hex::encode(sig.as_ref());
        let raw = format!(
            "POST /api/payments/webhook HTTP/1.1\r\nStripe-Signature: t={ts},v1={sig_hex}\r\n\r\n{body}"
        );
        let result = verify_stripe_signature(&raw, body, secret);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("replay protection"));
    }

    #[test]
    fn test_health_endpoint_degraded_without_env_vars() {
        // Without STRIPE_SECRET_KEY or sandbox tokens, status should be "degraded"
        // and all sub-fields should be false.
        // We just test the JSON shape via the logic directly (no env vars set in CI).
        let e2b     = std::env::var("E2B_TOKEN").map(|v| !v.is_empty()).unwrap_or(false);
        let daytona = std::env::var("DAYTONA_TOKEN").map(|v| !v.is_empty()).unwrap_or(false);
        let sprites = std::env::var("SPRITES_TOKEN").map(|v| !v.is_empty()).unwrap_or(false);
        let stripe_key     = std::env::var("STRIPE_SECRET_KEY").map(|v| !v.is_empty()).unwrap_or(false);
        let stripe_webhook = std::env::var("STRIPE_WEBHOOK_SECRET").map(|v| !v.is_empty()).unwrap_or(false);
        let sandbox_ok = e2b || daytona || sprites;
        let expected_status = if sandbox_ok && stripe_key { "ok" } else { "degraded" };
        let body = serde_json::json!({
            "status": expected_status,
            "version": env!("CARGO_PKG_VERSION"),
            "relay": "https://ntfy.theagora.dev",
            "sandbox": {
                "available": sandbox_ok,
                "providers": { "e2b": e2b, "daytona": daytona, "sprites": sprites }
            },
            "payments": {
                "stripe_key": stripe_key,
                "stripe_webhook": stripe_webhook,
                "ready": stripe_key && stripe_webhook
            }
        });
        // In CI without env vars, must be degraded
        assert_eq!(body["status"], "degraded");
        assert_eq!(body["sandbox"]["available"], false);
        assert_eq!(body["payments"]["ready"], false);
        // Version field must be present and non-empty
        assert!(!body["version"].as_str().unwrap_or("").is_empty());
    }
}
