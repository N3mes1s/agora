//! Agora web UI — local HTTP server for viewing room history.
//!
//! Starts a read-only web interface at http://localhost:<port>.
//! Decrypts messages locally, renders as HTML. No data leaves the machine.

use std::io::{Read as IoRead, Write as IoWrite};
use std::net::TcpListener;

use crate::{chat, store};

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn render_room(room_label: &str) -> String {
    let msgs = chat::read("24h", 200, Some(room_label)).unwrap_or_default();
    let me = store::get_agent_id();

    let mut rows = String::new();
    for m in &msgs {
        let ts = m["ts"].as_u64().unwrap_or(0);
        let dt = chrono::DateTime::from_timestamp(ts as i64, 0)
            .map(|d| d.format("%H:%M:%S").to_string())
            .unwrap_or_default();
        let from = html_escape(m["from"].as_str().unwrap_or("?"));
        let text = html_escape(m["text"].as_str().unwrap_or(""));
        let mid = m["id"].as_str().unwrap_or("?");
        let mid_short = &mid[..6.min(mid.len())];
        let class = if from == me { "me" } else { "other" };

        rows.push_str(&format!(
            r#"<div class="msg {class}"><span class="time">{dt}</span> <span class="id">[{mid_short}]</span> <span class="sender">{from}</span>: <span class="text">{text}</span></div>"#,
        ));
        rows.push('\n');
    }

    format!(
        r#"<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<title>Agora — {room_label}</title>
<meta http-equiv="refresh" content="10">
<style>
  body {{ font-family: 'SF Mono', 'Consolas', monospace; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }}
  h1 {{ color: #58a6ff; font-size: 1.2em; border-bottom: 1px solid #30363d; padding-bottom: 10px; }}
  .stats {{ color: #8b949e; font-size: 0.85em; margin-bottom: 20px; }}
  .msg {{ padding: 4px 0; line-height: 1.5; }}
  .msg.me {{ color: #7ee787; }}
  .msg.other {{ color: #c9d1d9; }}
  .time {{ color: #8b949e; }}
  .id {{ color: #6e7681; font-size: 0.85em; }}
  .sender {{ color: #58a6ff; font-weight: bold; }}
  .text {{ }}
  a {{ color: #58a6ff; }}
  .nav {{ margin-bottom: 15px; }}
  .nav a {{ margin-right: 15px; padding: 4px 8px; background: #21262d; border-radius: 4px; text-decoration: none; }}
  .nav a:hover {{ background: #30363d; }}
  .nav a.active {{ background: #388bfd; color: #fff; }}
</style>
</head><body>
<h1>Agora — {room_label} (AES-256-GCM encrypted)</h1>
<div class="stats">{msg_count} messages, last 24h. Auto-refresh every 10s.</div>
<div class="nav">{nav}</div>
{rows}
</body></html>"#,
        room_label = html_escape(room_label),
        msg_count = msgs.len(),
        nav = render_nav(room_label),
        rows = rows,
    )
}

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

fn render_index() -> String {
    let rooms = store::load_registry();
    let mut links = String::new();
    for r in &rooms {
        links.push_str(&format!(
            r#"<li><a href="/{label}">{label}</a> — {id}</li>"#,
            label = html_escape(&r.label),
            id = html_escape(&r.room_id),
        ));
        links.push('\n');
    }

    format!(
        r#"<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<title>Agora — Rooms</title>
<style>
  body {{ font-family: 'SF Mono', 'Consolas', monospace; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }}
  h1 {{ color: #58a6ff; }}
  a {{ color: #58a6ff; }}
  li {{ margin: 8px 0; }}
</style>
</head><body>
<h1>Agora Rooms</h1>
<ul>{links}</ul>
</body></html>"#,
        links = links,
    )
}

pub fn start(port: u16) {
    let addr = format!("127.0.0.1:{port}");
    let listener = TcpListener::bind(&addr).unwrap_or_else(|e| {
        eprintln!("  Error: Cannot bind to {addr}: {e}");
        std::process::exit(1);
    });

    eprintln!("  Agora Web UI running at http://{addr}");
    eprintln!("  Rooms listed at http://{addr}/");
    eprintln!("  Press Ctrl+C to stop.\n");

    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };

        let mut buf = [0u8; 4096];
        let n = match stream.read(&mut buf) {
            Ok(n) => n,
            Err(_) => continue,
        };
        let request = String::from_utf8_lossy(&buf[..n]);

        // Parse path from "GET /path HTTP/1.1"
        let path = request
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or("/");

        let body = if path == "/" || path.is_empty() {
            render_index()
        } else {
            let room_label = path.trim_start_matches('/');
            if store::find_room(room_label).is_some() {
                render_room(room_label)
            } else {
                format!(
                    r#"<!DOCTYPE html><html><body style="font-family:monospace;background:#0d1117;color:#c9d1d9;padding:20px"><h1>404</h1><p>Room '{}' not found. <a href="/" style="color:#58a6ff">Back to rooms</a></p></body></html>"#,
                    html_escape(room_label)
                )
            }
        };

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(response.as_bytes());
    }
}
