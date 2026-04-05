//! Agora web UI — enhanced local HTTP server.
//!
//! Routes:
//!   GET  /             — room list
//!   GET  /:room        — room history + live tail + send form
//!   GET  /:room/events — SSE stream (new messages as HTML fragments)
//!   POST /:room/send   — send a message, redirect back

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
pub fn render_message_html(m: &serde_json::Value, me: &str, room_id: &str) -> String {
    let ts_epoch = m["ts"].as_u64().unwrap_or(0);
    let dt = chrono::DateTime::from_timestamp(ts_epoch as i64, 0)
        .map(|d| d.format("%H:%M:%S").to_string())
        .unwrap_or_default();
    let from = html_escape(m["from"].as_str().unwrap_or("?"));
    let text = html_escape(m["text"].as_str().unwrap_or(""));
    let mid = m["id"].as_str().unwrap_or("?");
    let mid_short = &mid[..6.min(mid.len())];
    let class = if from.as_str() == me { "msg me" } else { "msg other" };

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

    format!(
        r#"<div class="{class}" id="m-{mid_short}"><span class="time">{dt}</span> <span class="id">[{mid_short}]</span> <span class="sender">{from}</span>: {reply_badge}<span class="text">{text}</span>{receipt}{reactions_row}</div>"#
    )
}

// ── Page templates ────────────────────────────────────────────────

const SHARED_CSS: &str = r#"
body{font-family:'SF Mono','Consolas',monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:20px}
h1{color:#58a6ff;font-size:1.2em;border-bottom:1px solid #30363d;padding-bottom:10px}
.stats{color:#8b949e;font-size:.85em;margin-bottom:16px}
.nav{margin-bottom:12px}
.nav a{margin-right:12px;padding:4px 8px;background:#21262d;border-radius:4px;text-decoration:none;color:#58a6ff}
.nav a:hover{background:#30363d}
.nav a.active{background:#388bfd;color:#fff}
.msg{padding:3px 0;line-height:1.5}
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
.reaction{display:inline-block;background:#161b22;border:1px solid #30363d;border-radius:10px;padding:1px 6px;font-size:.82em;margin:1px 2px}
a{color:#58a6ff}
.send-form{position:sticky;bottom:0;background:#0d1117;border-top:1px solid #30363d;padding:12px 0 4px}
.send-form input[type=text]{width:calc(100% - 100px);background:#161b22;border:1px solid #30363d;color:#c9d1d9;padding:6px 10px;border-radius:6px;font-family:inherit;font-size:.95em}
.send-form input[type=text]:focus{outline:none;border-color:#388bfd}
.send-form button{background:#238636;border:none;color:#fff;padding:6px 14px;border-radius:6px;cursor:pointer;margin-left:8px;font-family:inherit}
.send-form button:hover{background:#2ea043}
#messages{padding-bottom:8px}
.conn-status{font-size:.75em;color:#8b949e;margin-left:8px}
.conn-status.live{color:#3fb950}
.conn-status.reconnecting{color:#d29922}
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
        rows.push_str(&render_message_html(m, &me, &room.room_id));
        rows.push('\n');
    }

    let topic_line = room
        .topic
        .as_deref()
        .map(|t| format!(r#"<div class="stats">Topic: {}</div>"#, html_escape(t)))
        .unwrap_or_default();

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
<div class="nav">{nav}</div>
<div id="messages">
{rows}</div>
<div class="send-form">
  <form id="sf" action="/{label}/send" method="post" autocomplete="off">
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

  // Submit form via fetch so page doesn't reload
  document.getElementById('sf').addEventListener('submit', function(e) {{
    e.preventDefault();
    var text = input.value.trim();
    if (!text) return;
    fetch('/{label}/send', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
      body: 'message=' + encodeURIComponent(text)
    }}).catch(function() {{}});
    input.value = '';
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
</script>
</body></html>"#,
        label = html_escape(room_label),
        css = SHARED_CSS,
        count = msgs.len(),
        nav = render_nav(room_label),
        topic_line = topic_line,
        rows = rows,
        last_ts = last_ts,
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
}
