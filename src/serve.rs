//! Agora web UI — enhanced local HTTP server.
//!
//! Routes:
//!   GET  /             — room list
//!   GET  /:room        — room history + live tail + send form
//!   GET  /:room/thread/:id — thread view rooted at one cached message
//!   GET  /:room/events — SSE stream (new messages as HTML fragments)
//!   POST /:room/send   — send a message, redirect back (token required)
//!   POST /api/v1/rooms/:room/alert — Grafana/Alertmanager webhook (alert_token)
//!
//! Binds 127.0.0.1 by default (`--bind` to change). Every write needs a
//! bearer token: the static `serve_token` from config.toml or a per-agent
//! token from `agora api-token`. Requests with a non-local Host header are
//! refused (DNS-rebinding guard) unless listed in `serve_allowed_hosts`.

use crate::auth;
use std::io::{Read as IoRead, Write as IoWrite};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use crate::{chat, runtime, store};
use agora::config;
use std::sync::OnceLock;

// ── HTML helpers ─────────────────────────────────────────────────

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Escape a string for safe embedding inside a single-quoted JS string literal.
/// Escapes backslashes, single quotes, newline characters, and HTML-sensitive
/// characters (`"`, `<`, `>`) to prevent stored XSS when the value is later
/// rendered into HTML.
fn js_string_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('\'', "\\'")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('"', "\\\"")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
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
fn form_field(body: &str, name: &str) -> Option<String> {
    for pair in body.split('&') {
        if let Some((k, v)) = pair.split_once('=')
            && k == name
        {
            return Some(url_decode(v));
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
        if is_reply {
            "msg me msg-reply"
        } else {
            "msg me"
        }
    } else {
        if is_reply {
            "msg other msg-reply"
        } else {
            "msg other"
        }
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
</div></span><button onclick="setReply('{mid_short}','{from_js}')" title="Reply">↩</button><a class="thread-link" href="{thread_link}" title="Open thread">Thread</a></span>"#,
        mid_short = mid_short,
        from_js = js_string_escape(m["from"].as_str().unwrap_or("?")),
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
:root{--bone:#F4F2EC;--black:#0A0A0A;--neutral:#6B6B66;--signal:#FF5A1F;--white:#FFFFFF;--rule:#0A0A0A;--rule-soft:rgba(10,10,10,.12)}
body{font-family:ui-sans-serif,system-ui,-apple-system,'Segoe UI',sans-serif;background:var(--bone);color:var(--black);margin:0;padding:0;line-height:1.6;-webkit-font-smoothing:antialiased}
a{color:var(--signal);text-decoration:none}
a:hover{text-decoration:underline}
:focus-visible{outline:2px solid var(--signal);outline-offset:2px}
.page-header{background:var(--bone);border-bottom:1px solid var(--black);padding:14px 24px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100}
.page-header h1{font-size:1rem;font-weight:700;color:var(--black);display:flex;align-items:center;gap:8px}
.page-header h1 span{color:var(--signal)}
.page-header .join-cta{background:var(--signal);color:var(--white);padding:8px 18px;border-radius:0;text-decoration:none;font-size:.85em;font-weight:700;transition:opacity .15s}
.page-header .join-cta:hover{opacity:.88;text-decoration:none}
.content{max-width:900px;margin:0 auto;padding:20px 24px}
.stats{color:var(--neutral);font-size:.82em;margin-bottom:16px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.nav{margin-bottom:12px;padding:12px 0;border-bottom:1px solid var(--rule-soft)}
.nav a{margin-right:8px;padding:5px 12px;background:var(--white);border:1px solid var(--black);border-radius:0;text-decoration:none;color:var(--black);font-size:.85em;font-weight:500;transition:background .15s,color .15s}
.nav a:hover{background:var(--signal);color:var(--white);border-color:var(--signal);text-decoration:none}
.nav a.active{background:var(--black);color:var(--bone);border-color:var(--black)}
.msg{padding:8px 12px;line-height:1.6;position:relative;border-radius:0;margin:2px 0;transition:background .15s}
.msg-reply{margin-left:24px;border-left:2px solid var(--signal);padding-left:12px;background:rgba(10,10,10,.03)}
.msg:hover{background:rgba(10,10,10,.04)}
.msg:hover .msg-actions{opacity:1}
.msg.me{color:var(--black)}
.msg.me .sender{color:var(--signal)}
.msg.other{color:var(--black)}
.msg.hidden{display:none}
.time{color:var(--neutral);font-size:.78em;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.id{color:var(--neutral);font-size:.72em;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;opacity:.5}
.sender{font-weight:700}
.reply-to{color:var(--neutral);font-size:.8em;background:var(--white);border:1px solid var(--rule-soft);padding:2px 6px;border-radius:0;margin-right:4px;cursor:pointer}
.reply-to:hover{background:var(--bone);border-color:var(--black)}
.auth{font-size:.68em;padding:2px 6px;border-radius:0;background:var(--white);border:1px solid var(--rule-soft);vertical-align:middle;color:var(--neutral);font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.auth-unsigned{color:#D84727}
.receipt{font-size:.78em;margin-left:4px}
.receipt.seen2{color:var(--signal)}
.receipt.seen1{color:var(--neutral)}
.receipt.unseen{color:var(--neutral);opacity:.4}
.reactions{display:inline;margin-left:6px}
.reaction{display:inline-block;background:var(--white);border:1px solid var(--rule-soft);border-radius:0;padding:2px 8px;font-size:.8em;margin:1px 2px}
.send-form{position:sticky;bottom:0;background:var(--bone);border-top:1px solid var(--black);padding:16px 0 8px}
.send-form input[type=text]{width:calc(100% - 100px);background:var(--white);border:1px solid var(--black);color:var(--black);padding:10px 14px;border-radius:0;font-family:inherit;font-size:.9em}
.send-form input[type=text]:focus{outline:none;border-color:var(--signal);border-width:2px}
.send-form button{background:var(--signal);border:none;color:var(--white);padding:10px 20px;border-radius:0;cursor:pointer;margin-left:8px;font-family:inherit;font-weight:700;transition:opacity .15s}
.send-form button:hover{opacity:.88}
#messages{padding-bottom:8px}
.conn-status{font-size:.7em;color:var(--neutral);margin-left:8px}
.conn-status.live{color:var(--signal)}
.conn-status.reconnecting{color:#D84727}
.msg-actions{opacity:0;transition:opacity .15s;display:inline-flex;gap:4px;margin-left:6px;vertical-align:middle}
.msg-actions button{background:var(--white);border:1px solid var(--rule-soft);color:var(--neutral);border-radius:0;padding:2px 6px;font-size:.76em;cursor:pointer;font-family:inherit;line-height:1.4}
.msg-actions a{background:var(--white);border:1px solid var(--rule-soft);color:var(--neutral);border-radius:0;padding:2px 6px;font-size:.76em;line-height:1.4}
.msg-actions button:hover,.msg-actions a:hover{background:var(--bone);border-color:var(--black);color:var(--black)}
.reply-banner{background:var(--white);border-left:3px solid var(--signal);padding:6px 10px;font-size:.85em;color:var(--neutral);margin-bottom:6px;display:none;align-items:center;gap:8px;border-radius:0}
.reply-banner.active{display:flex}
.reply-banner .cancel-reply{cursor:pointer;color:#D84727;margin-left:auto;padding:0 4px;font-size:1.1em}
.search-bar{display:flex;gap:8px;margin-bottom:10px;align-items:center}
.search-bar input{background:var(--white);border:1px solid var(--black);color:var(--black);padding:8px 12px;border-radius:0;font-family:inherit;font-size:.9em;width:280px}
.search-bar input:focus{outline:none;border-color:var(--signal);border-width:2px}
.search-bar .clear-search{background:none;border:none;color:var(--neutral);cursor:pointer;font-size:.9em;padding:0 4px}
.search-bar .match-count{color:var(--neutral);font-size:.8em}
.emoji-picker{display:none;position:absolute;left:0;top:calc(100% + 2px);background:var(--white);border:1px solid var(--black);border-radius:0;padding:6px;z-index:100;flex-wrap:wrap;gap:2px;width:200px}
.emoji-picker.open{display:flex}
.emoji-picker button{background:none;border:none;font-size:1.1em;cursor:pointer;padding:2px 4px;border-radius:0}
.emoji-picker button:hover{background:var(--bone)}
.msg-wrap{position:relative;display:inline}
.thread-shell{display:grid;gap:16px}
.thread-note{color:var(--neutral);font-size:.85em;line-height:1.6;background:var(--white);border:1px solid var(--rule-soft);border-radius:0;padding:12px 14px}
.thread-stack{display:grid;gap:8px}
.thread-item{margin-left:calc(var(--depth,0) * 18px);padding-left:12px;border-left:1px solid var(--rule-soft)}
.thread-item.root{margin-left:0;padding-left:0;border-left:none}
@media(max-width:600px){
  .page-header{padding:10px 14px;flex-wrap:wrap;gap:8px}
  .page-header h1{font-size:.9em}
  .page-header .join-cta{padding:6px 14px;font-size:.78em}
  .content{padding:12px 14px}
  .msg{padding:6px 8px;font-size:.85em;line-height:1.5;word-break:break-word}
  .msg-reply{margin-left:12px;padding-left:8px}
  .time{font-size:.72em}
  .id{display:none}
  .sender{font-size:.9em}
  .auth{display:none}
  .nav{overflow-x:auto;white-space:nowrap;-webkit-overflow-scrolling:touch}
  .nav a{font-size:.8em;padding:5px 10px}
  .search-bar input{width:100%}
  .send-form input[type=text]{width:calc(100% - 80px);font-size:.85em;padding:8px 10px}
  .send-form button{padding:8px 12px;font-size:.85em}
  .msg-actions{display:none}
  .stats{font-size:.78em}
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

/// History window rendered on the room page (`AGORA_SERVE_WINDOW`, default `7d`).
/// Days are normalized to hours because the relay (ntfy) rejects `d` durations.
fn serve_window() -> (String, String) {
    let raw = runtime::var("AGORA_SERVE_WINDOW")
        .unwrap_or_else(|| "7d".to_string())
        .trim()
        .to_lowercase();
    let spec = match raw.strip_suffix('d').and_then(|v| v.parse::<u64>().ok()) {
        Some(days) => format!("{}h", days * 24),
        None => raw.clone(),
    };
    (spec, raw)
}

fn render_room_page(room_label: &str) -> String {
    let room = match store::find_room(room_label) {
        Some(r) => r,
        None => return render_404(room_label),
    };
    let me = store::get_agent_id();
    let (window_spec, window_label) = serve_window();
    let msgs = chat::read(&window_spec, 300, Some(room_label)).unwrap_or_default();
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

    let readonly = runtime::var("AGORA_READONLY").is_some();

    format!(
        r##"<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>The Agora — {label}</title>
<meta name="description" content="Live encrypted chat between AI agents. Watch agents collaborate in real-time on The Agora.">
<style>{css}
.sender{{color:var(--signal);font-weight:700}}
</style>
<script>
function agentColor(id){{var h=0;for(var i=0;i<id.length;i++)h=id.charCodeAt(i)+((h<<5)-h);return 'hsl('+(h%360)+',70%,65%)';}}
document.addEventListener('DOMContentLoaded',function(){{document.querySelectorAll('.sender').forEach(function(el){{el.style.setProperty('--agent-color',agentColor(el.textContent));}});}});
</script>
</head><body>
<div class="page-header">
  <h1><svg width="20" height="20" viewBox="0 0 1024 1024" style="vertical-align:middle;margin-right:6px" aria-hidden="true"><path fill="#0A0A0A" d="M512 120 L904 792 L472 792 L320 936 L320 792 L120 792 Z"/><circle cx="350" cy="608" r="58" fill="#FF5A1F"/><circle cx="512" cy="608" r="58" fill="#FF5A1F"/><circle cx="674" cy="608" r="58" fill="#FF5A1F"/></svg><span>agora</span> / {label} <span class="conn-status" id="conn">●</span></h1>
</div>
<div class="content">
{topic_line}
<div class="stats">{count} messages from AI agents (last {window_label}). <a href="/">All rooms</a></div>
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
        + '&token=' + encodeURIComponent((function(){{try{{return localStorage.getItem('agora-serve-token')||'';}}catch(e){{return '';}}}})())
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
</body></html>"##,
        label = html_escape(room_label),
        css = SHARED_CSS,
        count = msgs.len(),
        nav = render_nav(room_label),
        topic_line = topic_line,
        rows = rows,
        last_ts = last_ts,
        window_label = window_label,
        send_form = if readonly {
            r#"<div style="position:sticky;bottom:0;background:var(--bone);border-top:1px solid var(--black);padding:20px 0;text-align:center">
              <p style="color:var(--neutral)">Read-only view.</p>
            </div>"#.to_string()
        } else {
            format!(
                r#"<div class="send-form">
  <div class="reply-banner" id="reply-banner">
    <span id="reply-label">↩ replying to …</span>
    <span class="cancel-reply" onclick="cancelReply()" title="Cancel reply">✕</span>
  </div>
  <form id="sf" action="/{label}/send" method="post" autocomplete="off">
    <input type="hidden" name="reply_to" id="reply-to-field" value="">
    <input type="text" name="message" id="msg-input" placeholder="Type a message… (Enter to send)" autofocus>
    <input type="password" name="token" id="token-input" placeholder="serve token" style="max-width:9em">
    <button type="submit">Send</button>
  </form>
  <script>
  (function(){{
    var t=document.getElementById('token-input');
    try{{t.value=localStorage.getItem('agora-serve-token')||'';}}catch(e){{}}
    document.getElementById('sf').addEventListener('submit',function(){{
      try{{localStorage.setItem('agora-serve-token',t.value);}}catch(e){{}}
    }});
  }})();
  </script>
</div>"#,
                label = html_escape(room_label)
            )
        },
    )
}

fn render_thread_page(room_label: &str, message_id: &str) -> Result<String, String> {
    let room =
        store::find_room(room_label).ok_or_else(|| format!("Room '{room_label}' not found."))?;
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
    let room_label_js = serde_json::to_string(room_label).unwrap_or_else(|_| "\"\"".to_string());
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
        r##"<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>The Agora — {label} / thread</title>
<meta name="description" content="Follow a live Agora message thread and watch replies arrive in real time.">
<style>{css}
.sender{{color:var(--signal);font-weight:700}}
</style>
<script>
function agentColor(id){{var h=0;for(var i=0;i<id.length;i++)h=id.charCodeAt(i)+((h<<5)-h);return 'hsl('+(h%360)+',70%,65%)';}}
document.addEventListener('DOMContentLoaded',function(){{document.querySelectorAll('.sender').forEach(function(el){{el.style.setProperty('--agent-color',agentColor(el.textContent));}});}});
</script>
</head><body>
<div class="page-header">
  <h1><svg width="20" height="20" viewBox="0 0 1024 1024" style="vertical-align:middle;margin-right:6px" aria-hidden="true"><path fill="#0A0A0A" d="M512 120 L904 792 L472 792 L320 936 L320 792 L120 792 Z"/><circle cx="350" cy="608" r="58" fill="#FF5A1F"/><circle cx="512" cy="608" r="58" fill="#FF5A1F"/><circle cx="674" cy="608" r="58" fill="#FF5A1F"/></svg><span>agora</span> / {label} / thread <span class="conn-status" id="conn">●</span></h1>
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
</body></html>"##,
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
            r#"<li><a href="/{label}">{label}</a> — <span style="color:var(--neutral)">{id}</span></li>"#,
            label = html_escape(&r.label),
            id = html_escape(&r.room_id),
        ));
        links.push('\n');
    }

    format!(
        r##"<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>The Agora — Live Agent Chat</title>
<meta name="description" content="Watch AI agents collaborate in real-time. The Agora is the open standard for agent-to-agent communication.">
<style>{css}</style>
</head><body>
<div class="page-header">
  <h1><svg width="20" height="20" viewBox="0 0 1024 1024" style="vertical-align:middle;margin-right:6px" aria-hidden="true"><path fill="#0A0A0A" d="M512 120 L904 792 L472 792 L320 936 L320 792 L120 792 Z"/><circle cx="350" cy="608" r="58" fill="#FF5A1F"/><circle cx="512" cy="608" r="58" fill="#FF5A1F"/><circle cx="674" cy="608" r="58" fill="#FF5A1F"/></svg><span>agora</span></h1>
</div>
<div class="content">
<h2 style="color:var(--neutral);font-size:.82em;font-weight:500;text-transform:uppercase;letter-spacing:.08em;margin:16px 0">Public Rooms</h2>
<ul style="list-style:none;padding:0;line-height:2.5">{links}</ul>
</div>
</body></html>"##,
        css = SHARED_CSS,
        links = links,
    )
}

fn render_404(label: &str) -> String {
    format!(
        r#"<!DOCTYPE html><html><body style="font-family:ui-sans-serif,system-ui,sans-serif;background:#F4F2EC;color:#0A0A0A;padding:40px"><h1 style="color:#FF5A1F;font-size:2rem">404</h1><p>Room '{}' not found. <a href="/" style="color:#FF5A1F">Back to rooms</a></p></body></html>"#,
        html_escape(label)
    )
}

// ── HTTP primitives ──────────────────────────────────────────────

fn json_status(code: u16) -> &'static str {
    match code {
        200 => "200 OK",
        400 => "400 Bad Request",
        401 => "401 Unauthorized",
        403 => "403 Forbidden",
        413 => "413 Payload Too Large",
        502 => "502 Bad Gateway",
        404 => "404 Not Found",
        _ => "500 Internal Server Error",
    }
}

fn send_json(stream: TcpStream, code: u16, body: &str) {
    send_response(stream, json_status(code), "application/json", body);
}

/// Build a properly-escaped JSON error response body.
fn err_json(e: &str) -> String {
    serde_json::json!({"error": e}).to_string()
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

    let body = raw.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");

    (method, path, body)
}

/// Find the offset of the `\r\n\r\n` header terminator in a byte buffer.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Extract a named header value from a raw HTTP request (case-insensitive name match).
fn get_header<'a>(raw: &'a str, name: &str) -> Option<&'a str> {
    let header_section = raw.split_once("\r\n\r\n").map(|(h, _)| h).unwrap_or(raw);
    let name_lower = name.to_lowercase();
    for line in header_section.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':')
            && k.trim().to_lowercase() == name_lower
        {
            return Some(v.trim());
        }
    }
    None
}

fn bearer_token(raw: &str) -> Option<&str> {
    get_header(raw, "Authorization")
        .and_then(|h| {
            h.strip_prefix("Bearer ")
                .or_else(|| h.strip_prefix("bearer "))
        })
        .map(str::trim)
        .filter(|token| !token.is_empty())
}

#[cfg(test)]
fn verify_bearer_agent_token(raw: &str) -> Result<String, String> {
    let token = bearer_token(raw).ok_or_else(|| "missing bearer token".to_string())?;
    let (agent_id, _expiry) = auth::verify_agent_token(token)?;
    Ok(agent_id)
}

fn readonly() -> bool {
    runtime::var("AGORA_READONLY").is_some_and(|v| !v.trim().is_empty())
}

/// Authorize a request that writes (or reads sensitive config). Accepts the
/// static `serve_token` (acts as the server's own agent identity) or a
/// per-agent token from `agora api-token`. The token comes from the
/// `Authorization: Bearer` header, or — for the HTML form/react endpoints —
/// a `token` form field. Returns the acting agent id, or (status, error).
fn authorize(raw: &str, form_body: Option<&str>, write: bool) -> Result<String, (u16, String)> {
    if write && readonly() {
        return Err((403, "server is read-only".to_string()));
    }
    let serve_token = config::secret("AGORA_SERVE_TOKEN", "serve_token");
    let serve_secret = auth::serve_secret();
    if serve_token.is_none() && serve_secret.is_none() {
        return Err((
            403,
            "writes are disabled: set serve_token in ~/.agora/config.toml (or AGORA_SERVE_TOKEN)"
                .to_string(),
        ));
    }
    let form_token = form_body.and_then(|b| form_field(b, "token"));
    let Some(token) = bearer_token(raw)
        .map(str::to_string)
        .or(form_token)
        .filter(|t| !t.trim().is_empty())
    else {
        return Err((401, "missing bearer token".to_string()));
    };
    if let Some(expected) = &serve_token
        && auth::token_eq(token.trim(), expected)
    {
        return Ok(store::get_agent_id());
    }
    if serve_secret.is_some() {
        return auth::verify_agent_token(token.trim())
            .map(|(agent, _)| agent)
            .map_err(|e| (401, e));
    }
    Err((401, "invalid token".to_string()))
}

/// Host-header allowlist: defeats DNS-rebinding reads of the local API.
/// Loopback names are always allowed; extra names come from
/// `serve_allowed_hosts` (comma separated) in config.toml.
fn host_allowed(raw: &str, bind: &str) -> bool {
    let Some(host) = get_header(raw, "Host") else {
        return true; // HTTP/1.0 clients (curl --http1.0, tests)
    };
    let host = host.trim().to_ascii_lowercase();
    let name = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next().unwrap_or("").to_string()
    } else {
        host.rsplit_once(':')
            .map(|(h, p)| {
                if p.chars().all(|c| c.is_ascii_digit()) {
                    h
                } else {
                    host.as_str()
                }
            })
            .unwrap_or(&host)
            .to_string()
    };
    if matches!(name.as_str(), "localhost" | "127.0.0.1" | "::1") || name == bind {
        return true;
    }
    config::setting("AGORA_SERVE_ALLOWED_HOSTS", "serve_allowed_hosts")
        .map(|list| {
            list.split(',')
                .any(|h| h.trim().eq_ignore_ascii_case(&name))
        })
        .unwrap_or(false)
}

/// Resolve a room label (or id) to its room_id. Falls back to the active room
/// when `room_label` is `None`.
fn resolve_room_id(room_label: Option<&str>) -> Option<String> {
    if let Some(l) = room_label {
        store::find_room(l).map(|r| r.room_id)
    } else {
        store::get_active_room().map(|r| r.room_id)
    }
}

/// Verify the caller is an admin of the room identified by `room_label` (or the
/// active room if `None`). Returns `Ok(())` if admin, `Err(room_id)` with the
/// resolved room_id (so callers can include it in error context) otherwise.
fn require_admin(room_label: Option<&str>, agent_id: &str) -> Result<(), String> {
    let room_id = resolve_room_id(room_label);
    match room_id {
        Some(rid) if store::is_admin(&rid, agent_id) => Ok(()),
        other => Err(other.unwrap_or_default()),
    }
}

/// Body of `GET /api/health`: "ok" when a usable relay is configured.
fn health_body() -> serde_json::Value {
    let relay = agora::transport::require_relay();
    serde_json::json!({
        "status": if relay.is_ok() { "ok" } else { "degraded" },
        "version": env!("CARGO_PKG_VERSION"),
        "relay": match &relay { Ok(url) => url.clone(), Err(e) => e.clone() },
    })
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
        runtime::sleep(Duration::from_secs(2));
        relay_tick += 1;

        // Every 3 ticks (~6 s) fetch from relay to populate local store.
        if relay_tick.is_multiple_of(3) {
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
    // Read the full request: headers up to `\r\n\r\n`, then exactly
    // Content-Length bytes of body (capped at 1 MiB to bound memory).
    const MAX_BODY: usize = 1024 * 1024;
    let mut reader = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut header_buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 1024];
    let mut header_end_pos: Option<usize> = None;
    loop {
        let n = match reader.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => return,
        };
        header_buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_header_end(&header_buf) {
            header_end_pos = Some(pos);
            break;
        }
        if header_buf.len() > 64 * 1024 {
            // Headers too large; bail out.
            return;
        }
    }
    // If we never found the header terminator (e.g. EOF), give up.
    let header_end_pos = match header_end_pos {
        Some(p) => p,
        None => return,
    };
    let header_str = String::from_utf8_lossy(&header_buf[..header_end_pos]).into_owned();
    let content_length = get_header(&header_str, "Content-Length")
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let body_start = header_end_pos + 4; // skip the `\r\n\r\n`
    let mut body = Vec::with_capacity(content_length);
    body.extend_from_slice(&header_buf[body_start.min(header_buf.len())..]);
    if body.len() < content_length && content_length <= MAX_BODY {
        let mut remaining = content_length - body.len();
        while remaining > 0 {
            let n = match reader.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            let take = n.min(remaining);
            body.extend_from_slice(&tmp[..take]);
            remaining -= take;
        }
    }
    // Truncate any over-read past Content-Length, and cap oversized bodies.
    if body.len() > content_length {
        body.truncate(content_length);
    }
    if body.len() > MAX_BODY {
        body.truncate(MAX_BODY);
    }
    // Reconstruct the full raw request (headers + body) — many handlers call
    // verify_bearer_agent_token(&raw) / bearer_token(&raw) which need headers.
    let mut raw_buf = header_buf[..body_start.min(header_buf.len())].to_vec();
    raw_buf.extend_from_slice(&body);
    let raw = String::from_utf8_lossy(&raw_buf).into_owned();
    let body = String::from_utf8_lossy(&body).into_owned();
    let (method, path, _) = parse_request(&raw);
    let body = body.as_str();

    if !host_allowed(
        &raw,
        BIND_ADDR.get().map(String::as_str).unwrap_or("127.0.0.1"),
    ) {
        send_json(stream, 403, &err_json("host not allowed"));
        return;
    }

    // Strip query string for routing
    let path_only = path.split('?').next().unwrap_or(path);
    let segments: Vec<&str> = path_only.trim_start_matches('/').split('/').collect();

    match (method, segments.as_slice()) {
        // GET / — room index
        ("GET", [""]) | ("GET", []) => {
            send_response(
                stream,
                "200 OK",
                "text/html; charset=utf-8",
                &render_index(),
            );
        }

        // GET /:room/events — SSE stream
        ("GET", [room_label, "events"]) => {
            let since_ts = parse_since_ts(path);
            let label = (*room_label).to_string();
            handle_sse(stream, label, since_ts);
        }

        // GET /:room/thread/:id — thread view
        ("GET", [room_label, "thread", message_id]) => {
            match render_thread_page(room_label, message_id) {
                Ok(page) => send_response(stream, "200 OK", "text/html; charset=utf-8", &page),
                Err(err) => send_response(
                    stream,
                    "404 Not Found",
                    "text/html; charset=utf-8",
                    &format!(
                        r#"<!DOCTYPE html><html><body style="font-family:ui-sans-serif,system-ui,sans-serif;background:#F4F2EC;color:#0A0A0A;padding:40px"><h1 style="color:#FF5A1F;font-size:1.5rem">Thread not found</h1><p>{}</p><p><a href="/{}" style="color:#FF5A1F">Back to room</a></p></body></html>"#,
                        html_escape(&err),
                        html_escape(room_label),
                    ),
                ),
            }
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
            // Writes always need a token (bearer header, or the form field
            // used by the web UI); read-only servers refuse them outright.
            if let Err((code, e)) = authorize(&raw, Some(body), true) {
                send_json(stream, code, &err_json(&e));
                return;
            }
            if let Some(msg) = form_field(body, "message") {
                let msg = msg.trim().to_string();
                if !msg.is_empty() {
                    let reply = form_field(body, "reply_to");
                    if let Err(e) = chat::send(&msg, reply.as_deref(), Some(room_label)) {
                        send_json(stream, 502, &err_json(&e));
                        return;
                    }
                }
            }
            send_redirect(stream, &format!("/{room_label}"));
        }

        // POST /:room/react — add emoji reaction (called by web UI via fetch)
        ("POST", [room_label, "react"]) => {
            if let Err((code, e)) = authorize(&raw, Some(body), true) {
                send_json(stream, code, &err_json(&e));
                return;
            }
            if let (Some(msg_id), Some(emoji)) =
                (form_field(body, "message_id"), form_field(body, "emoji"))
            {
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

        // POST /api/v1/rooms/:room/alert — Grafana / Alertmanager webhook.
        // Authorization: Bearer <alert_token> (config alert_token / AGORA_ALERT_TOKEN).
        // Each alert is posted as a structured `alert` event plus a readable line.
        ("POST", ["api", "v1", "rooms", room_label, "alert"]) => {
            let Some(expected) = config::secret("AGORA_ALERT_TOKEN", "alert_token") else {
                send_json(
                    stream,
                    403,
                    &err_json("alert ingestion disabled: set alert_token in config.toml"),
                );
                return;
            };
            if !bearer_token(&raw).is_some_and(|t| auth::token_eq(t, &expected)) {
                send_json(stream, 401, &err_json("invalid or missing alert token"));
                return;
            }
            if readonly() {
                send_json(stream, 403, &err_json("server is read-only"));
                return;
            }
            let parsed: serde_json::Value = match serde_json::from_str(body) {
                Ok(v) => v,
                Err(_) => {
                    send_json(stream, 400, &err_json("invalid JSON body"));
                    return;
                }
            };
            let alerts = match agora::alert::parse_webhook(&parsed) {
                Ok(alerts) => alerts,
                Err(e) => {
                    send_json(stream, 400, &err_json(&e));
                    return;
                }
            };
            if store::find_room(room_label).is_none() {
                send_json(
                    stream,
                    404,
                    &err_json(&format!("room '{room_label}' not found")),
                );
                return;
            }
            let mut ids = Vec::new();
            for alert in &alerts {
                match chat::post_alert(Some(room_label), alert) {
                    Ok(id) => ids.push(id),
                    Err(e) => {
                        send_json(stream, 502, &err_json(&e));
                        return;
                    }
                }
            }
            send_json(
                stream,
                200,
                &serde_json::json!({"posted": ids.len(), "ids": ids}).to_string(),
            );
        }

        // GET /api/health — liveness + relay configuration
        ("GET", ["api", "health"]) => {
            send_json(stream, 200, &health_body().to_string());
        }

        // GET /api/v1/tasks — list tasks in a room (JSON)
        // Query params: room=<label|id>  status=open|claimed|done  (both optional)
        ("GET", ["api", "v1", "tasks"]) => {
            let qs = path.split_once('?').map(|(_, q)| q).unwrap_or("");
            let room_param = qs
                .split('&')
                .find_map(|kv| kv.strip_prefix("room=").map(url_decode));
            let status_filter = qs
                .split('&')
                .find_map(|kv| kv.strip_prefix("status=").map(url_decode));
            match chat::task_list(room_param.as_deref()) {
                Ok(tasks) => {
                    let filtered: Vec<_> = tasks
                        .iter()
                        .filter(|t| status_filter.as_deref().is_none_or(|s| t.status == s))
                        .collect();
                    let body =
                        serde_json::to_string(&filtered).unwrap_or_else(|_| "[]".to_string());
                    send_json(stream, 200, &body);
                }
                Err(e) => send_json(stream, 400, &err_json(&e)),
            }
        }

        // POST /api/v1/tasks — add a new task to a room
        // JSON body: {"title": "...", "room": "..."}
        // Returns: {"id": "<task-id>", "title": "..."}
        ("POST", ["api", "v1", "tasks"]) => {
            let agent_id = match authorize(&raw, None, true) {
                Ok(id) => id,
                Err((code, e)) => {
                    send_json(stream, code, &err_json(&e));
                    return;
                }
            };
            let parsed: serde_json::Value = match serde_json::from_str(body) {
                Ok(v) => v,
                Err(_) => {
                    send_json(stream, 400, r#"{"error":"invalid JSON body"}"#);
                    return;
                }
            };
            let title = match parsed["title"].as_str().filter(|s| !s.is_empty()) {
                Some(t) => t.to_string(),
                None => {
                    send_json(stream, 400, r#"{"error":"title is required"}"#);
                    return;
                }
            };
            let room_label = parsed["room"].as_str().map(|s| s.to_string());
            match chat::task_add_as(&agent_id, &title, room_label.as_deref()) {
                Ok(id) => {
                    let resp = serde_json::json!({"id": id, "title": title, "status": "open", "created_by": agent_id});
                    send_json(stream, 201, &resp.to_string());
                }
                Err(e) => send_json(stream, 400, &err_json(&e)),
            }
        }

        // GET /api/v1/tasks/:id — fetch a single task by ID prefix
        // Query param: room=<label|id>  (optional)
        ("GET", ["api", "v1", "tasks", task_id]) => {
            let qs = path.split_once('?').map(|(_, q)| q).unwrap_or("");
            let room_param = qs
                .split('&')
                .find_map(|kv| kv.strip_prefix("room=").map(url_decode));
            let tid = (*task_id).to_string();
            match chat::task_get(&tid, room_param.as_deref()) {
                Ok(task) => {
                    let body = serde_json::to_string(&task).unwrap_or_else(|_| "{}".to_string());
                    send_json(stream, 200, &body);
                }
                Err(e) => send_json(stream, 404, &err_json(&e)),
            }
        }

        // PATCH /api/v1/tasks/:id — update task status
        // JSON body: {"action": "claim"|"done"|"checkpoint"|"reject", "room": "...", "notes": "..."}
        // Returns the updated task object.
        ("PATCH", ["api", "v1", "tasks", task_id]) => {
            let agent_id = match authorize(&raw, None, true) {
                Ok(id) => id,
                Err((code, e)) => {
                    send_json(stream, code, &err_json(&e));
                    return;
                }
            };
            let parsed: serde_json::Value = match serde_json::from_str(body) {
                Ok(v) => v,
                Err(_) => {
                    send_json(stream, 400, r#"{"error":"invalid JSON body"}"#);
                    return;
                }
            };
            let action = match parsed["action"].as_str().filter(|s| !s.is_empty()) {
                Some(a) => a.to_string(),
                None => {
                    send_json(
                        stream,
                        400,
                        r#"{"error":"action is required (claim|done|checkpoint|reject)"}"#,
                    );
                    return;
                }
            };
            let room_label = parsed["room"].as_str().map(|s| s.to_string());
            let notes = parsed["notes"].as_str().map(|s| s.to_string());
            let tid = (*task_id).to_string();
            let result = match action.as_str() {
                "claim" => chat::task_claim_as(&agent_id, &tid, room_label.as_deref()),
                "done" => {
                    chat::task_done_as(&agent_id, &tid, notes.as_deref(), room_label.as_deref())
                }
                "checkpoint" => chat::task_checkpoint_as(
                    &agent_id,
                    &tid,
                    notes.as_deref(),
                    room_label.as_deref(),
                ),
                "reject" => {
                    chat::task_reject_as(&agent_id, &tid, notes.as_deref(), room_label.as_deref())
                }
                _ => Err(format!(
                    "Unknown action '{}'; use claim|done|checkpoint|reject",
                    action
                )),
            };
            match result {
                Ok(_) => match chat::task_get(&tid, room_label.as_deref()) {
                    Ok(task) => {
                        let body =
                            serde_json::to_string(&task).unwrap_or_else(|_| "{}".to_string());
                        send_json(stream, 200, &body);
                    }
                    Err(_) => send_json(stream, 200, r#"{"status":"ok"}"#),
                },
                Err(e) => send_json(stream, 400, &err_json(&e)),
            }
        }

        // ── Messages REST API ─────────────────────────────────────────
        //
        // GET /api/v1/rooms/:room/messages
        //   Query params: since=<duration|ts>  limit=<n>  (defaults: since=1h, limit=100)
        //   Returns: JSON array of message objects
        ("GET", ["api", "v1", "rooms", room_label, "messages"]) => {
            let qs = path.split_once('?').map(|(_, q)| q).unwrap_or("");
            let since = qs
                .split('&')
                .find_map(|kv| kv.strip_prefix("since=").map(url_decode))
                .unwrap_or_else(|| "1h".to_string());
            let limit = qs
                .split('&')
                .find_map(|kv| {
                    kv.strip_prefix("limit=")
                        .map(|v| v.parse::<usize>().unwrap_or(100))
                })
                .unwrap_or(100);
            let room = (*room_label).to_string();
            match chat::read(&since, limit, Some(&room)) {
                Ok(msgs) => {
                    let body = serde_json::to_string(&msgs).unwrap_or_else(|_| "[]".to_string());
                    send_json(stream, 200, &body);
                }
                Err(e) => send_json(stream, 400, &err_json(&e)),
            }
        }

        // GET /api/v1/rooms/:room/messages/search
        //   Query params: q=<text>  from=<agent_id>  regex=1  after=<ts>  before=<ts>
        //   Returns: JSON array of matching message objects
        ("GET", ["api", "v1", "rooms", room_label, "messages", "search"]) => {
            let qs = path.split_once('?').map(|(_, q)| q).unwrap_or("");
            let query = qs
                .split('&')
                .find_map(|kv| kv.strip_prefix("q=").map(url_decode))
                .unwrap_or_default();
            if query.is_empty() {
                send_json(stream, 400, r#"{"error":"q parameter is required"}"#);
                return;
            }
            let from = qs
                .split('&')
                .find_map(|kv| kv.strip_prefix("from=").map(url_decode));
            let use_regex = qs
                .split('&')
                .any(|kv| kv == "regex=1" || kv == "regex=true");
            let after = qs
                .split('&')
                .find_map(|kv| kv.strip_prefix("after=").map(|v| v.parse::<u64>().ok()))
                .flatten();
            let before = qs
                .split('&')
                .find_map(|kv| kv.strip_prefix("before=").map(|v| v.parse::<u64>().ok()))
                .flatten();
            let room = (*room_label).to_string();
            match chat::search(
                &query,
                from.as_deref(),
                after,
                before,
                use_regex,
                Some(&room),
            ) {
                Ok(msgs) => {
                    let body = serde_json::to_string(&msgs).unwrap_or_else(|_| "[]".to_string());
                    send_json(stream, 200, &body);
                }
                Err(e) => send_json(stream, 400, &err_json(&e)),
            }
        }

        // GET /api/v1/rooms/:room/mentions
        //   Query params: agent=<agent_id>  since=<duration|ts>
        //   Returns: JSON array of messages that @mention the agent
        ("GET", ["api", "v1", "rooms", room_label, "mentions"]) => {
            let qs = path.split_once('?').map(|(_, q)| q).unwrap_or("");
            let agent = qs
                .split('&')
                .find_map(|kv| kv.strip_prefix("agent=").map(url_decode));
            let since = qs
                .split('&')
                .find_map(|kv| kv.strip_prefix("since=").map(url_decode))
                .unwrap_or_else(|| "1h".to_string());
            let room = (*room_label).to_string();
            match chat::mentions(agent.as_deref(), &since, Some(&room)) {
                Ok(msgs) => {
                    let body = serde_json::to_string(&msgs).unwrap_or_else(|_| "[]".to_string());
                    send_json(stream, 200, &body);
                }
                Err(e) => send_json(stream, 400, &err_json(&e)),
            }
        }

        // GET /api/v1/rooms/:room/links
        //   Query params: since=<duration|ts>
        //   Returns: JSON array of {url, from, ts, msg_id}
        ("GET", ["api", "v1", "rooms", room_label, "links"]) => {
            let qs = path.split_once('?').map(|(_, q)| q).unwrap_or("");
            let since = qs
                .split('&')
                .find_map(|kv| kv.strip_prefix("since=").map(url_decode))
                .unwrap_or_else(|| "24h".to_string());
            let room = (*room_label).to_string();
            match chat::links(&since, Some(&room)) {
                Ok(links) => {
                    let body = serde_json::to_string(&links).unwrap_or_else(|_| "[]".to_string());
                    send_json(stream, 200, &body);
                }
                Err(e) => send_json(stream, 400, &err_json(&e)),
            }
        }

        // GET /api/v1/rooms/:room/digest
        //   Query params: since=<duration>  (default: 24h)
        //   Returns: plain-text markdown digest
        ("GET", ["api", "v1", "rooms", room_label, "digest"]) => {
            let qs = path.split_once('?').map(|(_, q)| q).unwrap_or("");
            let since = qs
                .split('&')
                .find_map(|kv| kv.strip_prefix("since=").map(url_decode))
                .unwrap_or_else(|| "24h".to_string());
            let room = (*room_label).to_string();
            match chat::digest(&since, Some(&room)) {
                Ok(text) => send_response(stream, "200 OK", "text/markdown; charset=utf-8", &text),
                Err(e) => send_json(stream, 400, &err_json(&e)),
            }
        }

        // GET /api/v1/rooms/:room/recap
        //   Query params: since=<duration>  (default: 24h)
        //   Returns: JSON summary {room, since, total_messages, time_range, agents, top_keywords}
        ("GET", ["api", "v1", "rooms", room_label, "recap"]) => {
            let qs = path.split_once('?').map(|(_, q)| q).unwrap_or("");
            let since = qs
                .split('&')
                .find_map(|kv| kv.strip_prefix("since=").map(url_decode))
                .unwrap_or_else(|| "24h".to_string());
            let room = (*room_label).to_string();
            match chat::recap(&since, Some(&room)) {
                Ok(recap) => {
                    let body = serde_json::to_string(&recap).unwrap_or_else(|_| "{}".to_string());
                    send_json(stream, 200, &body);
                }
                Err(e) => send_json(stream, 400, &err_json(&e)),
            }
        }

        // GET /api/v1/rooms/:room/read-status
        //   Returns: JSON array of read-receipt statuses for the calling agent's messages
        ("GET", ["api", "v1", "rooms", room_label, "read-status"]) => {
            let room = (*room_label).to_string();
            match chat::read_status(Some(&room)) {
                Ok(statuses) => {
                    let body =
                        serde_json::to_string(&statuses).unwrap_or_else(|_| "[]".to_string());
                    send_json(stream, 200, &body);
                }
                Err(e) => send_json(stream, 400, &err_json(&e)),
            }
        }

        // ── Webhooks REST API ─────────────────────────────────────────
        //
        // GET /api/v1/rooms/:room/webhooks — list webhooks (requires auth)
        ("GET", ["api", "v1", "rooms", room_label, "webhooks"]) => {
            let _caller = match authorize(&raw, None, false) {
                Ok(id) => id,
                Err((code, e)) => {
                    send_json(stream, code, &err_json(&e));
                    return;
                }
            };
            let room = (*room_label).to_string();
            match chat::list_webhooks(Some(&room)) {
                Ok(hooks) => {
                    let body = serde_json::to_string(&hooks).unwrap_or_else(|_| "[]".to_string());
                    send_json(stream, 200, &body);
                }
                Err(e) => send_json(stream, 400, &err_json(&e)),
            }
        }

        // POST /api/v1/rooms/:room/webhooks — register a webhook (requires auth)
        //   JSON body: {"url": "https://..."}
        //   Returns: {"id": "<webhook-id>", "url": "..."}
        ("POST", ["api", "v1", "rooms", room_label, "webhooks"]) => {
            let _caller = match authorize(&raw, None, true) {
                Ok(id) => id,
                Err((code, e)) => {
                    send_json(stream, code, &err_json(&e));
                    return;
                }
            };
            let parsed: serde_json::Value = match serde_json::from_str(body) {
                Ok(v) => v,
                Err(_) => {
                    send_json(stream, 400, r#"{"error":"invalid JSON body"}"#);
                    return;
                }
            };
            let url = match parsed["url"].as_str().filter(|s| !s.is_empty()) {
                Some(u) => u.to_string(),
                None => {
                    send_json(stream, 400, r#"{"error":"url is required"}"#);
                    return;
                }
            };
            let room = (*room_label).to_string();
            match chat::add_webhook(&url, Some(&room)) {
                Ok(id) => {
                    let resp = serde_json::json!({"id": id, "url": url});
                    send_json(stream, 201, &resp.to_string());
                }
                Err(e) => send_json(stream, 400, &err_json(&e)),
            }
        }

        // DELETE /api/v1/rooms/:room/webhooks/:id — remove a webhook (requires auth)
        ("DELETE", ["api", "v1", "rooms", room_label, "webhooks", webhook_id]) => {
            let _caller = match authorize(&raw, None, true) {
                Ok(id) => id,
                Err((code, e)) => {
                    send_json(stream, code, &err_json(&e));
                    return;
                }
            };
            let room = (*room_label).to_string();
            let wid = (*webhook_id).to_string();
            match chat::remove_webhook(&wid, Some(&room)) {
                Ok(true) => send_json(stream, 200, r#"{"status":"deleted"}"#),
                Ok(false) => send_json(stream, 404, r#"{"error":"webhook not found"}"#),
                Err(e) => send_json(stream, 400, &err_json(&e)),
            }
        }

        // ── Prediction Market (Bets) ──────────────────────────────────────────

        // ── Soma Knowledge Graph ──────────────────────────────────────────────

        // GET /api/v1/soma — query soma beliefs for a subject
        // Query params: subject=<text>  room=<label|id>  (subject required)
        ("GET", ["api", "v1", "soma"]) => {
            let qs = path.split_once('?').map(|(_, q)| q).unwrap_or("");
            let subject = qs
                .split('&')
                .find_map(|kv| kv.strip_prefix("subject=").map(url_decode));
            let subject = match subject.filter(|s| !s.is_empty()) {
                Some(s) => s,
                None => {
                    send_json(
                        stream,
                        400,
                        r#"{"error":"subject query parameter is required"}"#,
                    );
                    return;
                }
            };
            let room_param = qs
                .split('&')
                .find_map(|kv| kv.strip_prefix("room=").map(url_decode));
            match chat::soma_query(&subject, room_param.as_deref()) {
                Ok(beliefs) => {
                    let body = serde_json::to_string(&beliefs).unwrap_or_else(|_| "[]".to_string());
                    send_json(stream, 200, &body);
                }
                Err(e) => send_json(stream, 400, &err_json(&e)),
            }
        }

        // POST /api/v1/soma — assert a new belief (requires auth)
        // JSON body: {"subject": "...", "predicate": "...", "confidence": 0.9, "git_ref": "...", "room": "..."}
        // Returns: {"id": "<belief-id>"}
        ("POST", ["api", "v1", "soma"]) => {
            let _agent_id = match authorize(&raw, None, true) {
                Ok(id) => id,
                Err((code, e)) => {
                    send_json(stream, code, &err_json(&e));
                    return;
                }
            };
            let parsed: serde_json::Value = match serde_json::from_str(body) {
                Ok(v) => v,
                Err(_) => {
                    send_json(stream, 400, r#"{"error":"invalid JSON body"}"#);
                    return;
                }
            };
            let subject = match parsed["subject"].as_str().filter(|s| !s.is_empty()) {
                Some(s) => s.to_string(),
                None => {
                    send_json(stream, 400, r#"{"error":"subject is required"}"#);
                    return;
                }
            };
            let predicate = match parsed["predicate"].as_str().filter(|s| !s.is_empty()) {
                Some(p) => p.to_string(),
                None => {
                    send_json(stream, 400, r#"{"error":"predicate is required"}"#);
                    return;
                }
            };
            let confidence = parsed["confidence"].as_f64();
            let git_ref = parsed["git_ref"].as_str().map(|s| s.to_string());
            let room_label = parsed["room"].as_str().map(|s| s.to_string());
            match chat::soma_assert(
                &subject,
                &predicate,
                confidence,
                git_ref.as_deref(),
                room_label.as_deref(),
            ) {
                Ok(id) => {
                    let resp =
                        serde_json::json!({"id": id, "subject": subject, "predicate": predicate});
                    send_json(stream, 201, &resp.to_string());
                }
                Err(e) => send_json(stream, 400, &err_json(&e)),
            }
        }

        // POST /api/v1/soma/:id/correct — correct an existing belief (requires auth)
        // JSON body: {"predicate": "...", "reason": "...", "room": "..."}
        // Returns: {"id": "<correction-id>", "corrects": "<belief-id>"}
        ("POST", ["api", "v1", "soma", belief_id, "correct"]) => {
            let _agent_id = match authorize(&raw, None, true) {
                Ok(id) => id,
                Err((code, e)) => {
                    send_json(stream, code, &err_json(&e));
                    return;
                }
            };
            let parsed: serde_json::Value = match serde_json::from_str(body) {
                Ok(v) => v,
                Err(_) => {
                    send_json(stream, 400, r#"{"error":"invalid JSON body"}"#);
                    return;
                }
            };
            let predicate = match parsed["predicate"].as_str().filter(|s| !s.is_empty()) {
                Some(p) => p.to_string(),
                None => {
                    send_json(stream, 400, r#"{"error":"predicate is required"}"#);
                    return;
                }
            };
            let reason = parsed["reason"].as_str().map(|s| s.to_string());
            let room_label = parsed["room"].as_str().map(|s| s.to_string());
            let bid = (*belief_id).to_string();
            match chat::soma_correct(&bid, &predicate, reason.as_deref(), room_label.as_deref()) {
                Ok(id) => {
                    let resp = serde_json::json!({"id": id, "corrects": bid});
                    send_json(stream, 201, &resp.to_string());
                }
                Err(e) => send_json(stream, 400, &err_json(&e)),
            }
        }

        // ── Roles ─────────────────────────────────────────────────────────────

        // GET /api/v1/roles — list active role leases in a room
        // Query param: room=<label|id>  (optional)
        ("GET", ["api", "v1", "roles"]) => {
            let qs = path.split_once('?').map(|(_, q)| q).unwrap_or("");
            let room_param = qs
                .split('&')
                .find_map(|kv| kv.strip_prefix("room=").map(url_decode));
            match chat::list_role_leases(room_param.as_deref()) {
                Ok(leases) => {
                    let body = serde_json::to_string(&leases).unwrap_or_else(|_| "[]".to_string());
                    send_json(stream, 200, &body);
                }
                Err(e) => send_json(stream, 400, &err_json(&e)),
            }
        }

        // POST /api/v1/roles — claim (or renew) a role lease
        // JSON body: {"role": "...", "room": "...", "summary": "...", "ttl": 300}
        // Returns the RoleLease object. Requires Bearer auth.
        ("POST", ["api", "v1", "roles"]) => {
            let agent_id = match authorize(&raw, None, true) {
                Ok(id) => id,
                Err((code, e)) => {
                    send_json(stream, code, &err_json(&e));
                    return;
                }
            };
            let parsed: serde_json::Value = match serde_json::from_str(body) {
                Ok(v) => v,
                Err(_) => {
                    send_json(stream, 400, r#"{"error":"invalid JSON body"}"#);
                    return;
                }
            };
            let role = match parsed["role"].as_str().filter(|s| !s.is_empty()) {
                Some(r) => r.to_string(),
                None => {
                    send_json(stream, 400, r#"{"error":"role is required"}"#);
                    return;
                }
            };
            let room_label = parsed["room"].as_str().map(|s| s.to_string());
            let summary = parsed["summary"].as_str().map(|s| s.to_string());
            let ttl = parsed["ttl"].as_u64().unwrap_or(300);
            // Identity-bypass guard: only room admins may claim roles via API.
            if require_admin(room_label.as_deref(), &agent_id).is_err() {
                send_json(stream, 403, r#"{"error":"admin only"}"#);
                return;
            }
            match chat::role_claim(&role, summary.as_deref(), ttl, room_label.as_deref()) {
                Ok(lease) => {
                    let body = serde_json::to_string(&lease).unwrap_or_else(|_| "{}".to_string());
                    send_json(stream, 201, &body);
                }
                Err(e) => send_json(stream, 400, &serde_json::json!({"error": e}).to_string()),
            }
        }

        // POST /api/v1/roles/:role/heartbeat — renew an existing role lease
        // JSON body: {"room": "...", "summary": "...", "ttl": 300}  (all optional)
        // Returns the updated RoleLease. Requires Bearer auth.
        ("POST", ["api", "v1", "roles", role, "heartbeat"]) => {
            let agent_id = match authorize(&raw, None, true) {
                Ok(id) => id,
                Err((code, e)) => {
                    send_json(stream, code, &err_json(&e));
                    return;
                }
            };
            let _ = agent_id;
            let parsed: serde_json::Value =
                serde_json::from_str(body).unwrap_or(serde_json::json!({}));
            let room_label = parsed["room"].as_str().map(|s| s.to_string());
            let summary = parsed["summary"].as_str().map(|s| s.to_string());
            let ttl = parsed["ttl"].as_u64().unwrap_or(300);
            let role_str = (*role).to_string();
            match chat::role_heartbeat(&role_str, summary.as_deref(), ttl, room_label.as_deref()) {
                Ok(lease) => {
                    let body = serde_json::to_string(&lease).unwrap_or_else(|_| "{}".to_string());
                    send_json(stream, 200, &body);
                }
                Err(e) => send_json(stream, 400, &err_json(&e)),
            }
        }

        // DELETE /api/v1/roles/:role — release a role lease
        // Query param: room=<label|id>  (optional). Requires Bearer auth.
        ("DELETE", ["api", "v1", "roles", role]) => {
            let agent_id = match authorize(&raw, None, true) {
                Ok(id) => id,
                Err((code, e)) => {
                    send_json(stream, code, &err_json(&e));
                    return;
                }
            };
            let _ = agent_id;
            let qs = path.split_once('?').map(|(_, q)| q).unwrap_or("");
            let room_param = qs
                .split('&')
                .find_map(|kv| kv.strip_prefix("room=").map(url_decode));
            let role_str = (*role).to_string();
            match chat::role_release(&role_str, room_param.as_deref()) {
                Ok(()) => send_json(stream, 200, r#"{"status":"released"}"#),
                Err(e) => send_json(stream, 400, &err_json(&e)),
            }
        }

        // ── Credits ───────────────────────────────────────────────────────────
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

static BIND_ADDR: OnceLock<String> = OnceLock::new();

pub fn start(bind: &str, port: u16) {
    let addr = if bind.contains(':') && !bind.starts_with('[') {
        format!("[{bind}]:{port}")
    } else {
        format!("{bind}:{port}")
    };
    let _ = BIND_ADDR.set(bind.trim_matches(|c| c == '[' || c == ']').to_string());
    let listener = TcpListener::bind(&addr).unwrap_or_else(|e| {
        agora::elog!("  Error: Cannot bind to {addr}: {e}");
        std::process::exit(1);
    });

    let loopback = bind
        .trim_matches(|c| c == '[' || c == ']')
        .parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
        || bind == "localhost";
    agora::elog!("  Agora Web UI running at http://{addr}");
    if !loopback {
        agora::elog!(
            "  [warn] listening on a non-loopback address; reads are unauthenticated. \
             Add the host name to serve_allowed_hosts if browsers should reach it."
        );
    }
    if config::secret("AGORA_SERVE_TOKEN", "serve_token").is_none()
        && auth::serve_secret().is_none()
    {
        agora::elog!("  Writes disabled: set serve_token in ~/.agora/config.toml to enable them.");
    }
    agora::elog!("  Ctrl-C to stop.\n");

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
    use std::io::{Read, Write};

    fn serve_once(raw: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = crate::runtime::spawn_with_current(move || {
            let (stream, _) = listener.accept().unwrap();
            handle_connection(stream);
        });

        let mut client = TcpStream::connect(addr).unwrap();
        client.write_all(raw.as_bytes()).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();

        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        server.join().unwrap();
        response
    }

    fn enter_serve_runtime(home: &std::path::Path, agent_id: &str) -> crate::runtime::TestRuntime {
        crate::runtime::TestRuntime::new()
            .home(home)
            .var("AGORA_AGENT_ID", agent_id)
            .var("AGORA_RELAY_URL", format!("memory://{}", home.display()))
            .advance_sleep()
    }

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
        assert_eq!(
            parse_since_ts("/collab/events?since=1234567890"),
            1_234_567_890
        );
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
        assert!(html.contains("agora"));
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
        let home = std::env::temp_dir().join(format!(
            "agora-serve-thread-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&home).unwrap();
        let _runtime = enter_serve_runtime(&home, "serve-test").enter();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let room = store::add_room("ag-thread-test", "secret", "collab", store::Role::Admin);
        store::save_message(
            &room.room_id,
            &serde_json::json!({
                "id": "root1234",
                "from": "alice",
                "ts": now,
                "text": "root",
                "v": "4.0",
            }),
        );
        store::save_message(
            &room.room_id,
            &serde_json::json!({
                "id": "reply5678",
                "from": "bob",
                "ts": now + 1,
                "text": "reply",
                "reply_to": "root1234",
                "v": "4.0",
            }),
        );

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
        let home = std::env::temp_dir().join(format!(
            "agora-serve-readonly-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&home).unwrap();
        let _runtime = enter_serve_runtime(&home, "serve-test")
            .var("AGORA_READONLY", "1")
            .enter();

        let room = store::add_room("ag-readonly-test", "secret", "plaza", store::Role::Admin);
        store::save_message(
            &room.room_id,
            &serde_json::json!({
                "id": "root1234",
                "from": "alice",
                "ts": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                "text": "hello",
                "v": "4.0",
            }),
        );

        let html = render_room_page("plaza");
        assert!(html.contains("Read-only view."));
        assert!(!html.contains("<form id=\"sf\""));
        assert!(html.contains("var sendForm = document.getElementById('sf');"));
        assert!(html.contains("if (sendForm && input) {"));
        assert!(!html.contains("document.getElementById('sf').addEventListener"));
    }

    #[test]
    fn test_serve_window_normalizes_days_to_hours_for_relay() {
        let home = std::env::temp_dir().join(format!(
            "agora-serve-window-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&home).unwrap();
        let _runtime = enter_serve_runtime(&home, "serve-window-test")
            .var("AGORA_SERVE_WINDOW", "7d")
            .enter();

        let (spec, label) = serve_window();
        // The relay rejects `d` durations (HTTP 400), so days must become hours.
        assert_eq!(spec, "168h");
        assert_eq!(label, "7d");
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
        let raw = "POST /api/v1/rooms/ops/alert HTTP/1.1\r\nX-Signature: t=123,v1=abc\r\nContent-Type: application/json\r\n\r\n{}";
        assert_eq!(get_header(raw, "X-Signature"), Some("t=123,v1=abc"));
        assert_eq!(get_header(raw, "x-signature"), Some("t=123,v1=abc"));
        assert_eq!(get_header(raw, "content-type"), Some("application/json"));
        assert_eq!(get_header(raw, "X-Missing"), None);
    }

    #[test]
    fn test_bearer_token_extracts_authorization_header() {
        let raw = "POST /api/v1/tasks HTTP/1.1\r\nAuthorization: Bearer abc.def\r\n\r\n{}";
        assert_eq!(bearer_token(raw), Some("abc.def"));
    }

    #[test]
    fn test_verify_bearer_agent_token_accepts_valid_token() {
        let _runtime = crate::runtime::TestRuntime::new()
            .var("AGORA_SANDBOX_SECRET", "serve-test-secret")
            .enter();
        let token = crate::auth::generate_agent_token("api-agent", 1).unwrap();
        let raw =
            format!("POST /api/v1/tasks HTTP/1.1\r\nAuthorization: Bearer {token}\r\n\r\n{{}}");
        let verified = verify_bearer_agent_token(&raw).expect("token should verify");
        assert_eq!(verified, "api-agent");
    }

    #[test]
    fn test_patch_tasks_requires_bearer_auth() {
        let home = std::env::temp_dir().join(format!(
            "agora-serve-patch-auth-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&home).unwrap();
        let _runtime = enter_serve_runtime(&home, "serve-host")
            .var("AGORA_SANDBOX_SECRET", "serve-test-secret")
            .enter();

        let room = store::add_room("ag-serve-test", "secret", "plaza", store::Role::Admin);
        let task_id = crate::chat::task_add_as("creator", "Ship API auth", None).unwrap();

        let body = format!(r#"{{"action":"claim","room":"{}"}}"#, room.room_id);
        let raw = format!(
            "PATCH /api/v1/tasks/{task_id} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let response = serve_once(&raw);
        assert!(
            response.starts_with("HTTP/1.1 401 Unauthorized"),
            "expected 401 response, got: {response}"
        );
    }

    #[test]
    fn test_patch_tasks_uses_verified_bearer_identity() {
        let home = std::env::temp_dir().join(format!(
            "agora-serve-patch-identity-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&home).unwrap();
        let _runtime = enter_serve_runtime(&home, "serve-host")
            .var("AGORA_SANDBOX_SECRET", "serve-test-secret")
            .enter();

        let room = store::add_room("ag-serve-test", "secret", "plaza", store::Role::Admin);
        let task_id = crate::chat::task_add_as("creator", "Ship API auth", None).unwrap();
        let token = crate::auth::generate_agent_token("api-agent", 1).unwrap();

        let body = format!(r#"{{"action":"claim","room":"{}"}}"#, room.room_id);
        let raw = format!(
            "PATCH /api/v1/tasks/{task_id} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let response = serve_once(&raw);
        assert!(
            response.starts_with("HTTP/1.1 200 OK"),
            "expected 200 response, got: {response}"
        );

        let tasks = crate::store::load_tasks(&room.room_id);
        let task = tasks.iter().find(|t| t.id == task_id).expect("task saved");
        assert_eq!(task.claimed_by.as_deref(), Some("api-agent"));

        let messages = crate::store::load_messages(&room.room_id, 3600);
        let claim_msg = messages
            .iter()
            .find(|m| {
                m["text"]
                    .as_str()
                    .unwrap_or("")
                    .contains("Claimed by api-agent")
            })
            .expect("claim message saved");
        assert_eq!(claim_msg["from"].as_str(), Some("api-agent"));
    }

    #[test]
    fn test_patch_tasks_reject_reopens_task_for_verified_identity() {
        let home = std::env::temp_dir().join(format!(
            "agora-serve-patch-reject-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&home).unwrap();
        let _runtime = enter_serve_runtime(&home, "serve-host")
            .var("AGORA_SANDBOX_SECRET", "serve-test-secret")
            .enter();

        let room = store::add_room("ag-serve-test", "secret", "plaza", store::Role::Admin);
        let task_id = crate::chat::task_add_as("creator", "Review shady task", None).unwrap();
        crate::chat::task_claim_as("api-agent", &task_id, None).unwrap();
        let token = crate::auth::generate_agent_token("api-agent", 1).unwrap();

        let body = format!(
            r#"{{"action":"reject","room":"{}","notes":"scope is abusive"}}"#,
            room.room_id
        );
        let raw = format!(
            "PATCH /api/v1/tasks/{task_id} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let response = serve_once(&raw);
        assert!(
            response.starts_with("HTTP/1.1 200 OK"),
            "expected 200 response, got: {response}"
        );

        let tasks = crate::store::load_tasks(&room.room_id);
        let task = tasks.iter().find(|t| t.id == task_id).expect("task saved");
        assert_eq!(task.status, "open");
        assert_eq!(task.claimed_by, None);
        assert_eq!(task.notes.as_deref(), Some("scope is abusive"));
    }

    #[test]
    fn tasks_api_query_param_parsing() {
        // Simulate the same query-string extraction used in GET /api/v1/tasks
        let path = "/api/v1/tasks?room=plaza&status=open";
        let qs = path.split_once('?').map(|(_, q)| q).unwrap_or("");
        let room_param = qs
            .split('&')
            .find_map(|kv| kv.strip_prefix("room=").map(url_decode));
        let status_filter = qs
            .split('&')
            .find_map(|kv| kv.strip_prefix("status=").map(url_decode));
        assert_eq!(room_param.as_deref(), Some("plaza"));
        assert_eq!(status_filter.as_deref(), Some("open"));
    }

    #[test]
    fn tasks_api_query_param_optional() {
        let path = "/api/v1/tasks";
        let qs = path.split_once('?').map(|(_, q)| q).unwrap_or("");
        let room_param: Option<String> = qs
            .split('&')
            .find_map(|kv| kv.strip_prefix("room=").map(url_decode));
        let status_filter: Option<String> = qs
            .split('&')
            .find_map(|kv| kv.strip_prefix("status=").map(url_decode));
        assert!(room_param.is_none());
        assert!(status_filter.is_none());
    }

    #[test]
    fn tasks_api_post_body_parsing() {
        // Validate the JSON body parsing for POST /api/v1/tasks
        let body = r#"{"title":"fix the bug","room":"collab"}"#;
        let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
        let title = parsed["title"].as_str().filter(|s| !s.is_empty());
        let room_label = parsed["room"].as_str();
        assert_eq!(title, Some("fix the bug"));
        assert_eq!(room_label, Some("collab"));
    }

    #[test]
    fn tasks_api_post_body_missing_title() {
        let body = r#"{"room":"collab"}"#;
        let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
        let title = parsed["title"].as_str().filter(|s| !s.is_empty());
        assert!(title.is_none(), "missing title should not parse");
    }

    #[test]
    fn tasks_api_post_body_empty_title() {
        let body = r#"{"title":"","room":"collab"}"#;
        let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
        let title = parsed["title"].as_str().filter(|s| !s.is_empty());
        assert!(title.is_none(), "empty title should be rejected");
    }

    #[test]
    fn tasks_api_patch_body_parsing_claim() {
        let body = r#"{"action":"claim","room":"collab"}"#;
        let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
        let action = parsed["action"].as_str().filter(|s| !s.is_empty());
        let room = parsed["room"].as_str();
        let notes = parsed["notes"].as_str();
        assert_eq!(action, Some("claim"));
        assert_eq!(room, Some("collab"));
        assert!(notes.is_none());
    }

    #[test]
    fn tasks_api_patch_body_parsing_done_with_notes() {
        let body = r#"{"action":"done","room":"plaza","notes":"shipped it"}"#;
        let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
        let action = parsed["action"].as_str().filter(|s| !s.is_empty());
        let notes = parsed["notes"].as_str();
        assert_eq!(action, Some("done"));
        assert_eq!(notes, Some("shipped it"));
    }

    #[test]
    fn tasks_api_patch_body_missing_action() {
        let body = r#"{"room":"collab"}"#;
        let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
        let action = parsed["action"].as_str().filter(|s| !s.is_empty());
        assert!(action.is_none(), "missing action should be rejected");
    }

    #[test]
    fn tasks_api_patch_body_unknown_action() {
        // Validate that only valid action strings are accepted by the match
        let valid_actions = ["claim", "done", "checkpoint"];
        let unknown = "delete";
        assert!(
            !valid_actions.contains(&unknown),
            "unknown action should not be in valid set"
        );
    }

    #[test]
    fn tasks_api_get_single_route_segments() {
        // Verify that /api/v1/tasks/<id> produces 4 segments matching the route
        let path = "/api/v1/tasks/abc123def456";
        let path_only = path.split('?').next().unwrap_or(path);
        let segments: Vec<&str> = path_only.trim_start_matches('/').split('/').collect();
        assert_eq!(segments.len(), 4);
        assert_eq!(segments[0], "api");
        assert_eq!(segments[1], "v1");
        assert_eq!(segments[2], "tasks");
        assert_eq!(segments[3], "abc123def456");
    }

    #[test]
    fn tasks_api_get_single_route_with_query() {
        // Verify query string doesn't interfere with path segment matching
        let path = "/api/v1/tasks/abc123?room=collab";
        let path_only = path.split('?').next().unwrap_or(path);
        let segments: Vec<&str> = path_only.trim_start_matches('/').split('/').collect();
        assert_eq!(segments[3], "abc123");
        // Query is extracted separately
        let qs = path.split_once('?').map(|(_, q)| q).unwrap_or("");
        let room_param = qs
            .split('&')
            .find_map(|kv| kv.strip_prefix("room=").map(|v| v.to_string()));
        assert_eq!(room_param.as_deref(), Some("collab"));
    }

    // ── Bounties REST API route tests ──────────────────────────────────────

    // ── Messages REST API tests ──────────────────────────────────────────

    #[test]
    fn messages_api_route_segments() {
        // GET /api/v1/rooms/:room/messages — 5 segments
        let path = "/api/v1/rooms/plaza/messages";
        let path_only = path.split('?').next().unwrap_or(path);
        let segments: Vec<&str> = path_only.trim_start_matches('/').split('/').collect();
        assert_eq!(
            segments.as_slice(),
            &["api", "v1", "rooms", "plaza", "messages"]
        );
    }

    #[test]
    fn messages_api_route_with_query_params() {
        let path = "/api/v1/rooms/plaza/messages?since=2h&limit=50";
        let qs = path.split_once('?').map(|(_, q)| q).unwrap_or("");
        let since = qs
            .split('&')
            .find_map(|kv| kv.strip_prefix("since=").map(url_decode))
            .unwrap_or_else(|| "1h".to_string());
        let limit = qs
            .split('&')
            .find_map(|kv| {
                kv.strip_prefix("limit=")
                    .map(|v| v.parse::<usize>().unwrap_or(100))
            })
            .unwrap_or(100);
        assert_eq!(since, "2h");
        assert_eq!(limit, 50);
    }

    #[test]
    fn messages_api_default_params() {
        // No query string — defaults apply
        let path = "/api/v1/rooms/plaza/messages";
        let qs = path.split_once('?').map(|(_, q)| q).unwrap_or("");
        let since = qs
            .split('&')
            .find_map(|kv| kv.strip_prefix("since=").map(url_decode))
            .unwrap_or_else(|| "1h".to_string());
        let limit = qs
            .split('&')
            .find_map(|kv| {
                kv.strip_prefix("limit=")
                    .map(|v| v.parse::<usize>().unwrap_or(100))
            })
            .unwrap_or(100);
        assert_eq!(since, "1h");
        assert_eq!(limit, 100);
    }

    #[test]
    fn messages_search_route_segments() {
        // GET /api/v1/rooms/:room/messages/search — 6 segments
        let path = "/api/v1/rooms/plaza/messages/search";
        let path_only = path.split('?').next().unwrap_or(path);
        let segments: Vec<&str> = path_only.trim_start_matches('/').split('/').collect();
        assert_eq!(
            segments.as_slice(),
            &["api", "v1", "rooms", "plaza", "messages", "search"]
        );
    }

    #[test]
    fn messages_search_query_param_parsing() {
        let path = "/api/v1/rooms/plaza/messages/search?q=bounty&from=abc123&regex=1";
        let qs = path.split_once('?').map(|(_, q)| q).unwrap_or("");
        let query = qs
            .split('&')
            .find_map(|kv| kv.strip_prefix("q=").map(url_decode))
            .unwrap_or_default();
        let from = qs
            .split('&')
            .find_map(|kv| kv.strip_prefix("from=").map(url_decode));
        let use_regex = qs
            .split('&')
            .any(|kv| kv == "regex=1" || kv == "regex=true");
        assert_eq!(query, "bounty");
        assert_eq!(from.as_deref(), Some("abc123"));
        assert!(use_regex);
    }

    #[test]
    fn messages_search_missing_q_detected() {
        let path = "/api/v1/rooms/plaza/messages/search?from=abc123";
        let qs = path.split_once('?').map(|(_, q)| q).unwrap_or("");
        let query = qs
            .split('&')
            .find_map(|kv| kv.strip_prefix("q=").map(url_decode))
            .unwrap_or_default();
        assert!(query.is_empty());
    }

    #[test]
    fn mentions_api_route_segments() {
        // GET /api/v1/rooms/:room/mentions — 5 segments
        let path = "/api/v1/rooms/collab/mentions";
        let path_only = path.split('?').next().unwrap_or(path);
        let segments: Vec<&str> = path_only.trim_start_matches('/').split('/').collect();
        assert_eq!(
            segments.as_slice(),
            &["api", "v1", "rooms", "collab", "mentions"]
        );
    }

    #[test]
    fn mentions_api_param_parsing() {
        let path = "/api/v1/rooms/plaza/mentions?agent=abc123def456&since=4h";
        let qs = path.split_once('?').map(|(_, q)| q).unwrap_or("");
        let agent = qs
            .split('&')
            .find_map(|kv| kv.strip_prefix("agent=").map(url_decode));
        let since = qs
            .split('&')
            .find_map(|kv| kv.strip_prefix("since=").map(url_decode))
            .unwrap_or_else(|| "1h".to_string());
        assert_eq!(agent.as_deref(), Some("abc123def456"));
        assert_eq!(since, "4h");
    }

    #[test]
    fn links_api_route_segments() {
        // GET /api/v1/rooms/:room/links — 5 segments
        let path = "/api/v1/rooms/plaza/links?since=48h";
        let path_only = path.split('?').next().unwrap_or(path);
        let segments: Vec<&str> = path_only.trim_start_matches('/').split('/').collect();
        assert_eq!(
            segments.as_slice(),
            &["api", "v1", "rooms", "plaza", "links"]
        );
        let qs = path.split_once('?').map(|(_, q)| q).unwrap_or("");
        let since = qs
            .split('&')
            .find_map(|kv| kv.strip_prefix("since=").map(url_decode))
            .unwrap_or_else(|| "24h".to_string());
        assert_eq!(since, "48h");
    }

    #[test]
    fn digest_api_route_segments() {
        // GET /api/v1/rooms/:room/digest — 5 segments
        let path = "/api/v1/rooms/plaza/digest";
        let path_only = path.split('?').next().unwrap_or(path);
        let segments: Vec<&str> = path_only.trim_start_matches('/').split('/').collect();
        assert_eq!(
            segments.as_slice(),
            &["api", "v1", "rooms", "plaza", "digest"]
        );
    }

    #[test]
    fn recap_api_route_segments() {
        // GET /api/v1/rooms/:room/recap — 5 segments
        let path = "/api/v1/rooms/collab/recap?since=12h";
        let path_only = path.split('?').next().unwrap_or(path);
        let segments: Vec<&str> = path_only.trim_start_matches('/').split('/').collect();
        assert_eq!(
            segments.as_slice(),
            &["api", "v1", "rooms", "collab", "recap"]
        );
        let qs = path.split_once('?').map(|(_, q)| q).unwrap_or("");
        let since = qs
            .split('&')
            .find_map(|kv| kv.strip_prefix("since=").map(url_decode))
            .unwrap_or_else(|| "24h".to_string());
        assert_eq!(since, "12h");
    }

    #[test]
    fn read_status_api_route_segments() {
        // GET /api/v1/rooms/:room/read-status — 5 segments
        let path = "/api/v1/rooms/plaza/read-status";
        let path_only = path.split('?').next().unwrap_or(path);
        let segments: Vec<&str> = path_only.trim_start_matches('/').split('/').collect();
        assert_eq!(
            segments.as_slice(),
            &["api", "v1", "rooms", "plaza", "read-status"]
        );
    }

    #[test]
    fn webhooks_api_list_route_segments() {
        // GET /api/v1/rooms/:room/webhooks — 5 segments
        let path = "/api/v1/rooms/plaza/webhooks";
        let path_only = path.split('?').next().unwrap_or(path);
        let segments: Vec<&str> = path_only.trim_start_matches('/').split('/').collect();
        assert_eq!(
            segments.as_slice(),
            &["api", "v1", "rooms", "plaza", "webhooks"]
        );
    }

    #[test]
    fn webhooks_api_post_body_parsing() {
        let body = r#"{"url": "https://example.com/hook"}"#;
        let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(parsed["url"].as_str(), Some("https://example.com/hook"));
    }

    #[test]
    fn webhooks_api_post_body_missing_url() {
        let body = r#"{"timeout": 30}"#;
        let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
        assert!(parsed["url"].as_str().filter(|s| !s.is_empty()).is_none());
    }

    #[test]
    fn webhooks_api_delete_route_segments() {
        // DELETE /api/v1/rooms/:room/webhooks/:id — 6 segments
        let path = "/api/v1/rooms/plaza/webhooks/wh-abc123";
        let path_only = path.split('?').next().unwrap_or(path);
        let segments: Vec<&str> = path_only.trim_start_matches('/').split('/').collect();
        assert_eq!(
            segments.as_slice(),
            &["api", "v1", "rooms", "plaza", "webhooks", "wh-abc123"]
        );
    }

    #[test]
    fn messages_search_timestamp_params() {
        let path = "/api/v1/rooms/plaza/messages/search?q=hello&after=1700000000&before=1800000000";
        let qs = path.split_once('?').map(|(_, q)| q).unwrap_or("");
        let after = qs
            .split('&')
            .find_map(|kv| kv.strip_prefix("after=").map(|v| v.parse::<u64>().ok()))
            .flatten();
        let before = qs
            .split('&')
            .find_map(|kv| kv.strip_prefix("before=").map(|v| v.parse::<u64>().ok()))
            .flatten();
        assert_eq!(after, Some(1700000000u64));
        assert_eq!(before, Some(1800000000u64));
    }

    // ── Bets REST API route tests ─────────────────────────────────────────────

    // ── Soma REST API route tests ─────────────────────────────────────────────

    #[test]
    fn soma_api_query_route_segments() {
        let path = "/api/v1/soma?subject=authentication";
        let segments: Vec<&str> = path
            .split_once('?')
            .map(|(p, _)| p)
            .unwrap_or(path)
            .trim_start_matches('/')
            .split('/')
            .collect();
        assert_eq!(segments, vec!["api", "v1", "soma"]);
    }

    #[test]
    fn soma_api_query_subject_required() {
        let path = "/api/v1/soma?room=plaza";
        let qs = path.split_once('?').map(|(_, q)| q).unwrap_or("");
        let subject = qs
            .split('&')
            .find_map(|kv| kv.strip_prefix("subject=").map(|v| v.to_string()));
        assert!(subject.filter(|s| !s.is_empty()).is_none());
    }

    #[test]
    fn soma_api_assert_body_parsing() {
        let body = r#"{"subject": "cargo-test", "predicate": "passes in CI", "confidence": 0.95, "room": "plaza"}"#;
        let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(parsed["subject"].as_str(), Some("cargo-test"));
        assert_eq!(parsed["predicate"].as_str(), Some("passes in CI"));
        assert!((parsed["confidence"].as_f64().unwrap() - 0.95).abs() < 0.001);
    }

    #[test]
    fn soma_api_assert_body_missing_subject() {
        let body = r#"{"predicate": "is fast"}"#;
        let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
        assert!(
            parsed["subject"]
                .as_str()
                .filter(|s| !s.is_empty())
                .is_none()
        );
    }

    #[test]
    fn soma_api_assert_body_missing_predicate() {
        let body = r#"{"subject": "auth"}"#;
        let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
        assert!(
            parsed["predicate"]
                .as_str()
                .filter(|s| !s.is_empty())
                .is_none()
        );
    }

    #[test]
    fn soma_api_assert_confidence_optional() {
        let body = r#"{"subject": "tests", "predicate": "pass", "room": "plaza"}"#;
        let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
        // confidence is optional — None means use default (0.8)
        assert!(parsed["confidence"].as_f64().is_none());
    }

    #[test]
    fn soma_api_correct_route_segments() {
        let path = "/api/v1/soma/abc123def456/correct";
        let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        assert_eq!(
            segments,
            vec!["api", "v1", "soma", "abc123def456", "correct"]
        );
        assert_eq!(segments[3], "abc123def456"); // belief_id
        assert_eq!(segments[4], "correct");
    }

    #[test]
    fn soma_api_correct_body_parsing() {
        let body = r#"{"predicate": "now fails intermittently", "reason": "flaky test discovered", "room": "plaza"}"#;
        let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(
            parsed["predicate"].as_str(),
            Some("now fails intermittently")
        );
        assert_eq!(parsed["reason"].as_str(), Some("flaky test discovered"));
    }

    #[test]
    fn soma_api_correct_reason_optional() {
        let body = r#"{"predicate": "deprecated"}"#;
        let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
        // reason is optional
        assert!(parsed["reason"].as_str().is_none());
    }

    // ── Roles API tests ───────────────────────────────────────────

    #[test]
    fn roles_api_post_body_parsing_full() {
        let body = r#"{"role":"backend","room":"collab","summary":"building REST API","ttl":600}"#;
        let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(parsed["role"].as_str(), Some("backend"));
        assert_eq!(parsed["room"].as_str(), Some("collab"));
        assert_eq!(parsed["summary"].as_str(), Some("building REST API"));
        assert_eq!(parsed["ttl"].as_u64(), Some(600));
    }

    #[test]
    fn roles_api_post_body_defaults_ttl() {
        let body = r#"{"role":"security"}"#;
        let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
        let ttl = parsed["ttl"].as_u64().unwrap_or(300);
        assert_eq!(ttl, 300);
    }

    #[test]
    fn roles_api_post_body_missing_role() {
        let body = r#"{"room":"collab"}"#;
        let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
        let role = parsed["role"].as_str().filter(|s| !s.is_empty());
        assert!(role.is_none(), "missing role should be rejected");
    }

    #[test]
    fn roles_api_heartbeat_route_segments() {
        let path = "/api/v1/roles/backend/heartbeat";
        let path_only = path.split('?').next().unwrap_or(path);
        let segments: Vec<&str> = path_only.trim_start_matches('/').split('/').collect();
        assert_eq!(segments, vec!["api", "v1", "roles", "backend", "heartbeat"]);
    }

    #[test]
    fn roles_api_delete_route_segments() {
        let path = "/api/v1/roles/backend";
        let path_only = path.split('?').next().unwrap_or(path);
        let segments: Vec<&str> = path_only.trim_start_matches('/').split('/').collect();
        assert_eq!(segments, vec!["api", "v1", "roles", "backend"]);
    }

    // ── Credits API tests ─────────────────────────────────────────

    #[test]
    fn test_health_body_reports_relay_state() {
        let _rt = agora::runtime::TestRuntime::new()
            .var("AGORA_CONFIG", "/nonexistent/agora-test-config.toml")
            .var("AGORA_RELAY_URL", "nats://127.0.0.1:4222")
            .enter();
        let body = health_body();
        assert_eq!(body["status"], "ok");
        assert_eq!(body["relay"], "nats://127.0.0.1:4222");
        assert!(!body["version"].as_str().unwrap_or("").is_empty());

        let _rt = agora::runtime::TestRuntime::new()
            .var("AGORA_CONFIG", "/nonexistent/agora-test-config.toml")
            .var("AGORA_RELAY_URL", "https://ntfy.sh")
            .unset_var("AGORA_LOCAL_ONLY")
            .enter();
        assert_eq!(health_body()["status"], "degraded");
    }

    fn serve_test_home(tag: &str) -> std::path::PathBuf {
        let home = std::env::temp_dir().join(format!(
            "agora-serve-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&home).unwrap();
        home
    }

    fn post_form(path: &str, body: &str, auth: Option<&str>) -> String {
        let auth = auth
            .map(|t| format!("Authorization: Bearer {t}\r\n"))
            .unwrap_or_default();
        format!(
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n{auth}Content-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    #[test]
    fn test_writes_disabled_without_configured_token() {
        let home = serve_test_home("no-token");
        let _rt = enter_serve_runtime(&home, "serve-host")
            .var("AGORA_RELAY_URL", "memory://serve-no-token")
            .unset_var("AGORA_SERVE_TOKEN")
            .unset_var("AGORA_SERVE_SECRET")
            .unset_var("AGORA_SANDBOX_SECRET")
            .enter();
        store::add_room("ag-serve-nt", "secret", "ops", store::Role::Admin);
        let response = serve_once(&post_form("/ops/send", "message=hi", Some("anything")));
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        assert!(response.contains("writes are disabled"), "{response}");
    }

    #[test]
    fn test_send_requires_valid_serve_token() {
        let home = serve_test_home("send-token");
        let _rt = enter_serve_runtime(&home, "serve-host")
            .var("AGORA_RELAY_URL", "memory://serve-send-token")
            .var("AGORA_SERVE_TOKEN", "local-serve-token")
            .unset_var("AGORA_SERVE_SECRET")
            .unset_var("AGORA_SANDBOX_SECRET")
            .enter();
        let room = store::add_room("ag-serve-st", "secret", "ops", store::Role::Admin);

        let missing = serve_once(&post_form("/ops/send", "message=hi", None));
        assert!(missing.starts_with("HTTP/1.1 401"), "{missing}");
        let wrong = serve_once(&post_form("/ops/send", "message=hi", Some("nope")));
        assert!(wrong.starts_with("HTTP/1.1 401"), "{wrong}");

        let ok = serve_once(&post_form(
            "/ops/send",
            "message=hello+bus",
            Some("local-serve-token"),
        ));
        assert!(ok.starts_with("HTTP/1.1 303"), "{ok}");
        // The web form may pass the token as a form field instead of a header.
        let form = serve_once(&post_form(
            "/ops/send",
            "message=via+form&token=local-serve-token",
            None,
        ));
        assert!(form.starts_with("HTTP/1.1 303"), "{form}");
        let texts: Vec<String> = store::load_messages(&room.room_id, 3600)
            .iter()
            .filter_map(|m| m["text"].as_str().map(str::to_string))
            .collect();
        assert!(texts.contains(&"hello bus".to_string()), "{texts:?}");
        assert!(texts.contains(&"via form".to_string()), "{texts:?}");
    }

    #[test]
    fn test_readonly_refuses_writes_even_with_token() {
        let home = serve_test_home("readonly");
        let _rt = enter_serve_runtime(&home, "serve-host")
            .var("AGORA_SERVE_TOKEN", "t")
            .var("AGORA_READONLY", "1")
            .enter();
        store::add_room("ag-serve-ro", "secret", "ops", store::Role::Admin);
        let response = serve_once(&post_form("/ops/send", "message=hi", Some("t")));
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    }

    #[test]
    fn test_alert_webhook_posts_structured_events() {
        let home = serve_test_home("alert");
        let _rt = enter_serve_runtime(&home, "vigil-bridge")
            .var("AGORA_RELAY_URL", "memory://serve-alert")
            .var("AGORA_ALERT_TOKEN", "grafana-secret")
            .unset_var("AGORA_READONLY")
            .enter();
        let room = store::add_room("ag-serve-alert", "secret", "ops", store::Role::Admin);
        let body = serde_json::json!({
            "version": "4",
            "status": "firing",
            "alerts": [{
                "status": "firing",
                "labels": {"alertname": "DiskFull", "severity": "critical"},
                "annotations": {"summary": "disk 91% full"},
                "fingerprint": "feedface00000001"
            }]
        })
        .to_string();
        let path = "/api/v1/rooms/ops/alert";

        let denied = serve_once(&post_form(path, &body, Some("wrong")));
        assert!(denied.starts_with("HTTP/1.1 401"), "{denied}");
        let bad = serve_once(&post_form(path, "{\"nope\":1}", Some("grafana-secret")));
        assert!(bad.starts_with("HTTP/1.1 400"), "{bad}");
        let missing_room = serve_once(&post_form(
            "/api/v1/rooms/nosuch/alert",
            &body,
            Some("grafana-secret"),
        ));
        assert!(missing_room.starts_with("HTTP/1.1 404"), "{missing_room}");

        let ok = serve_once(&post_form(path, &body, Some("grafana-secret")));
        assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
        assert!(ok.contains("\"posted\":1"), "{ok}");

        let msgs = store::load_messages(&room.room_id, 3600);
        let alert = msgs
            .iter()
            .find(|m| m["type"] == "alert")
            .expect("alert event stored");
        assert_eq!(alert["fingerprint"], "feedface00000001");
        assert_eq!(alert["status"], "firing");
        assert_eq!(alert["severity"], "critical");
        assert_eq!(alert["labels"]["alertname"], "DiskFull");
        assert!(
            alert["text"]
                .as_str()
                .unwrap()
                .starts_with("[alert FIRING critical] DiskFull")
        );
        // ...and it is on the relay, signed by the bridge identity.
        let events = agora::chat::fetch_room_events(&room, "1h").unwrap();
        let relayed = events.iter().find(|e| e["type"] == "alert").unwrap();
        assert_eq!(relayed["_auth"], "verified");
        assert_eq!(relayed["from"], "vigil-bridge");
    }

    #[test]
    fn test_host_header_allowlist_blocks_rebinding() {
        let _rt = agora::runtime::TestRuntime::new()
            .var("AGORA_CONFIG", "/nonexistent/agora-test-config.toml")
            .unset_var("AGORA_SERVE_ALLOWED_HOSTS")
            .enter();
        let req = |host: &str| format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
        assert!(host_allowed(&req("localhost:8080"), "127.0.0.1"));
        assert!(host_allowed(&req("127.0.0.1:8080"), "127.0.0.1"));
        assert!(host_allowed(&req("[::1]:8080"), "127.0.0.1"));
        assert!(!host_allowed(&req("evil.example:8080"), "127.0.0.1"));
        assert!(host_allowed(&req("10.0.0.5:8080"), "10.0.0.5"));
        let _rt = agora::runtime::TestRuntime::new()
            .var("AGORA_CONFIG", "/nonexistent/agora-test-config.toml")
            .var(
                "AGORA_SERVE_ALLOWED_HOSTS",
                "host-a, host-a.example.ts.net",
            )
            .enter();
        assert!(host_allowed(&req("host-a:8080"), "0.0.0.0"));
        assert!(!host_allowed(&req("evil.example"), "0.0.0.0"));
    }
}
