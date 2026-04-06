//! Agora sandbox abstraction — isolated compute for agents.
//!
//! Providers: E2B, Daytona, Sprites (auto-selected based on availability).
//! Tokens loaded from env vars — never in source code.
//! Agents pay credits for sandbox time.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxSession {
    pub id: String,
    pub provider: String,
    pub agent_id: String,
    pub created_at: u64,
    pub status: String, // "running", "stopped", "destroyed"
}

fn e2b_token() -> Option<String> {
    std::env::var("E2B_TOKEN").ok()
}

fn daytona_token() -> Option<String> {
    std::env::var("DAYTONA_TOKEN").ok()
}

fn sprites_token() -> Option<String> {
    std::env::var("SPRITES_TOKEN").ok()
}

fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| reqwest::blocking::Client::new())
}

/// Create a sandbox — picks the first available provider.
pub fn create(agent_id: &str) -> Result<SandboxSession, String> {
    // Try E2B first (simplest API)
    if let Some(token) = e2b_token() {
        return create_e2b(agent_id, &token);
    }
    // Try Daytona
    if let Some(token) = daytona_token() {
        return create_daytona(agent_id, &token);
    }
    // Try Sprites
    if let Some(token) = sprites_token() {
        return create_sprites(agent_id, &token);
    }
    Err("No sandbox provider configured. Set E2B_TOKEN, DAYTONA_TOKEN, or SPRITES_TOKEN.".to_string())
}

/// Execute a command in a sandbox.
pub fn exec(session_id: &str, command: &str, provider: &str) -> Result<String, String> {
    match provider {
        "e2b" => exec_e2b(session_id, command),
        "daytona" => exec_daytona(session_id, command),
        "sprites" => exec_sprites(session_id, command),
        _ => Err(format!("Unknown provider: {provider}")),
    }
}

/// Destroy a sandbox.
pub fn destroy(session_id: &str, provider: &str) -> Result<(), String> {
    match provider {
        "e2b" => destroy_e2b(session_id),
        "daytona" => destroy_daytona(session_id),
        "sprites" => destroy_sprites(session_id),
        _ => Err(format!("Unknown provider: {provider}")),
    }
}

/// List available providers.
pub fn providers() -> Vec<String> {
    let mut p = Vec::new();
    if e2b_token().is_some() { p.push("e2b".to_string()); }
    if daytona_token().is_some() { p.push("daytona".to_string()); }
    if sprites_token().is_some() { p.push("sprites".to_string()); }
    p
}

// ── E2B ────────────────────────────────────────────────────────

fn create_e2b(agent_id: &str, token: &str) -> Result<SandboxSession, String> {
    let resp = client()
        .post("https://api.e2b.dev/sandboxes")
        .header("X-E2B-API-Key", token)
        .json(&serde_json::json!({
            "templateID": "base",
            "metadata": {"agent_id": agent_id}
        }))
        .send()
        .map_err(|e| format!("E2B create failed: {e}"))?;

    let body: serde_json::Value = resp.json().map_err(|e| format!("E2B parse failed: {e}"))?;
    let sandbox_id = body["sandboxID"].as_str()
        .ok_or("E2B: no sandboxID in response")?
        .to_string();

    Ok(SandboxSession {
        id: sandbox_id,
        provider: "e2b".to_string(),
        agent_id: agent_id.to_string(),
        created_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        status: "running".to_string(),
    })
}

fn exec_e2b(session_id: &str, command: &str) -> Result<String, String> {
    let token = e2b_token().ok_or("E2B_TOKEN not set")?;
    let resp = client()
        .post(&format!("https://api.e2b.dev/sandboxes/{session_id}/execute"))
        .header("X-E2B-API-Key", &token)
        .json(&serde_json::json!({"command": command}))
        .send()
        .map_err(|e| format!("E2B exec failed: {e}"))?;

    let body: serde_json::Value = resp.json().map_err(|e| format!("E2B parse failed: {e}"))?;
    Ok(body["stdout"].as_str().unwrap_or("").to_string())
}

fn destroy_e2b(session_id: &str) -> Result<(), String> {
    let token = e2b_token().ok_or("E2B_TOKEN not set")?;
    client()
        .delete(&format!("https://api.e2b.dev/sandboxes/{session_id}"))
        .header("X-E2B-API-Key", &token)
        .send()
        .map_err(|e| format!("E2B destroy failed: {e}"))?;
    Ok(())
}

// ── Daytona ────────────────────────────────────────────────────

fn create_daytona(agent_id: &str, token: &str) -> Result<SandboxSession, String> {
    let resp = client()
        .post("https://api.daytona.io/v1/sandbox")
        .bearer_auth(token)
        .json(&serde_json::json!({
            "image": "ubuntu:22.04",
            "labels": {"agent_id": agent_id}
        }))
        .send()
        .map_err(|e| format!("Daytona create failed: {e}"))?;

    let body: serde_json::Value = resp.json().map_err(|e| format!("Daytona parse failed: {e}"))?;
    let id = body["id"].as_str().unwrap_or("unknown").to_string();

    Ok(SandboxSession {
        id, provider: "daytona".to_string(), agent_id: agent_id.to_string(),
        created_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        status: "running".to_string(),
    })
}

fn exec_daytona(session_id: &str, command: &str) -> Result<String, String> {
    let token = daytona_token().ok_or("DAYTONA_TOKEN not set")?;
    let resp = client()
        .post(&format!("https://api.daytona.io/v1/sandbox/{session_id}/exec"))
        .bearer_auth(&token)
        .json(&serde_json::json!({"command": command}))
        .send()
        .map_err(|e| format!("Daytona exec failed: {e}"))?;

    let body: serde_json::Value = resp.json().map_err(|e| format!("Daytona parse: {e}"))?;
    Ok(body["output"].as_str().unwrap_or("").to_string())
}

fn destroy_daytona(session_id: &str) -> Result<(), String> {
    let token = daytona_token().ok_or("DAYTONA_TOKEN not set")?;
    client()
        .delete(&format!("https://api.daytona.io/v1/sandbox/{session_id}"))
        .bearer_auth(&token)
        .send()
        .map_err(|e| format!("Daytona destroy failed: {e}"))?;
    Ok(())
}

// ── Sprites ────────────────────────────────────────────────────

fn create_sprites(agent_id: &str, token: &str) -> Result<SandboxSession, String> {
    let resp = client()
        .post("https://api.sprites.dev/v1/machines")
        .bearer_auth(token)
        .json(&serde_json::json!({
            "image": "ubuntu:22.04",
            "metadata": {"agent_id": agent_id}
        }))
        .send()
        .map_err(|e| format!("Sprites create failed: {e}"))?;

    let body: serde_json::Value = resp.json().map_err(|e| format!("Sprites parse failed: {e}"))?;
    let id = body["id"].as_str().unwrap_or("unknown").to_string();

    Ok(SandboxSession {
        id, provider: "sprites".to_string(), agent_id: agent_id.to_string(),
        created_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        status: "running".to_string(),
    })
}

fn exec_sprites(session_id: &str, command: &str) -> Result<String, String> {
    let token = sprites_token().ok_or("SPRITES_TOKEN not set")?;
    let resp = client()
        .post(&format!("https://api.sprites.dev/v1/machines/{session_id}/exec"))
        .bearer_auth(&token)
        .json(&serde_json::json!({"command": command}))
        .send()
        .map_err(|e| format!("Sprites exec failed: {e}"))?;

    let body: serde_json::Value = resp.json().map_err(|e| format!("Sprites parse: {e}"))?;
    Ok(body["output"].as_str().unwrap_or("").to_string())
}

fn destroy_sprites(session_id: &str) -> Result<(), String> {
    let token = sprites_token().ok_or("SPRITES_TOKEN not set")?;
    client()
        .delete(&format!("https://api.sprites.dev/v1/machines/{session_id}"))
        .bearer_auth(&token)
        .send()
        .map_err(|e| format!("Sprites destroy failed: {e}"))?;
    Ok(())
}
