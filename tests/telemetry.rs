//! OTLP export end to end: the `agora` binary, pointed at a local stand-in collector, posts its
//! command span there, also when the command ends in `process::exit`, and the span never carries the
//! command's arguments.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Accepts OTLP/HTTP posts, answers 200, and keeps each body.
fn collector() -> (String, Arc<Mutex<Vec<Vec<u8>>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let kept = bodies.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream);
            let mut len = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0; len];
            let _ = reader.read_exact(&mut body);
            kept.lock().unwrap().push(body);
            let _ = reader.get_mut().write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
        }
    });
    (url, bodies)
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn a_command_span_reaches_the_collector_even_on_exit_and_without_its_arguments() {
    let (url, bodies) = collector();
    let home = std::env::temp_dir().join(format!("agora-telemetry-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_agora"))
        .args(["--room", "SECRET-ROOM-4711", "read"])
        .env("HOME", &home)
        .env("AGORA_AGENT_ID", "telemetry-test")
        .env("OTEL_EXPORTER_OTLP_ENDPOINT", &url)
        .env("OTEL_SERVICE_NAME", "agora-telemetry-test")
        .env_remove("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
        .output()
        .unwrap();
    assert!(!out.status.success(), "an unknown room ends in process::exit(1)");
    let deadline = Instant::now() + Duration::from_secs(5);
    while bodies.lock().unwrap().is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    let bodies = bodies.lock().unwrap();
    let all: Vec<u8> = bodies.concat();
    assert!(contains(&all, b"agora.cli"), "the command span was exported");
    assert!(contains(&all, b"read") && contains(&all, b"exit"), "with the command name and its outcome");
    assert!(contains(&all, b"agora-telemetry-test"), "under OTEL_SERVICE_NAME");
    assert!(!contains(&all, b"SECRET-ROOM-4711"), "never the command's arguments");
    let _ = std::fs::remove_dir_all(&home);
}
