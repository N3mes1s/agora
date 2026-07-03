//! Agora sandbox abstraction — isolated compute for agents.
//!
//! Providers: E2B, Daytona, Sprites (auto-selected based on availability).
//! Tokens loaded from env vars — never in source code.
//! Agents pay credits for sandbox time.


// ── Sandbox guardrails ───────────────────────────────────────────
/// Maximum concurrent sandboxes per agent (server-enforced).
const MAX_CONCURRENT_SANDBOXES: usize = 1;
/// Sandbox auto-destroy TTL in seconds (1 hour).
const SANDBOX_TTL_SECS: u64 = 3600;
/// Maximum sandbox creations per agent per day.
const MAX_DAILY_CREATIONS: usize = 5;
/// Maximum exec commands per agent per minute.
const MAX_EXEC_PER_MIN: usize = 60;
/// Credits charged per exec command.
pub const EXEC_COST_CREDITS: i64 = 1;

/// Registry of active sandboxes (agent_id → session). Stored in ~/.agora/sandbox_registry.json.
/// This is the server-side enforcement of max concurrent sandboxes — the local
/// sandbox_session.json is a convenience, but this file is the source of truth.
fn registry_path() -> std::path::PathBuf {
    crate::store::agora_dir().join("sandbox_registry.json")
}

/// Lock path guarding the sandbox registry read-modify-write cycle.
fn registry_lock_path() -> std::path::PathBuf {
    crate::store::agora_dir().join("sandbox_registry.json.lock")
}

/// Run `f` while holding an exclusive lock on the registry. Prevents the
/// TOCTOU race where two concurrent `check_can_create` calls both pass
/// `MAX_CONCURRENT_SANDBOXES` before either writes the registry.
fn with_registry_lock<T>(f: impl FnOnce() -> T) -> T {
    crate::store::with_file_lock(&registry_lock_path(), f)
}

/// Load the sandbox registry: Vec of (agent_id, session_id, provider, created_at).
fn load_registry() -> Vec<RegistryEntry> {
    let path = registry_path();
    if let Ok(data) = std::fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        Vec::new()
    }
}

/// Save the sandbox registry.
fn save_registry(entries: &[RegistryEntry]) {
    let path = registry_path();
    if let Ok(data) = serde_json::to_string_pretty(entries) {
        let _ = std::fs::write(&path, data);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RegistryEntry {
    agent_id: String,
    session_id: String,
    provider: String,
    created_at: u64,
}

/// Check if an agent can create a new sandbox. Returns Ok(()) or Err with reason.
pub fn check_can_create(agent_id: &str) -> Result<(), String> {
    let now = runtime::unix_now();
    with_registry_lock(|| {
        let mut entries = load_registry();

        // 1. Remove expired entries (auto-destroy TTL) and destroy stale sandboxes.
        // Use saturating_sub so a future-dated created_at (clock skew) doesn't
        // underflow u64.
        entries.retain(|e| {
            if now.saturating_sub(e.created_at) > SANDBOX_TTL_SECS {
                // Attempt to destroy the stale sandbox (best-effort)
                let _ = destroy(&e.session_id, &e.provider);
                false
            } else {
                true
            }
        });

        // 2. Check max concurrent sandboxes
        let active: Vec<_> = entries.iter().filter(|e| e.agent_id == agent_id).collect();
        if active.len() >= MAX_CONCURRENT_SANDBOXES {
            return Err(format!(
                "Agent already has {} active sandbox(es). Destroy it first with: agora sandbox-destroy {}",
                active.len(),
                active[0].session_id
            ));
        }

        // 3. Check daily creation cap — count only from the audit log, which
        // already covers both live and destroyed sessions. The registry would
        // double-count sessions that are still active (and under-count those
        // that were destroyed).
        let day_start = now.saturating_sub(86400); // 24h ago
        let audit = crate::store::load_sandbox_audit();
        let today_creates = audit
            .iter()
            .filter(|a| a.agent_id == agent_id && a.action == "create" && a.ts > day_start)
            .count();
        if today_creates >= MAX_DAILY_CREATIONS {
            return Err(format!(
                "Daily sandbox creation limit reached ({MAX_DAILY_CREATIONS}/day). Try again tomorrow."
            ));
        }

        save_registry(&entries);
        Ok(())
    })
}

/// Register a new sandbox after successful creation.
pub fn register(agent_id: &str, session_id: &str, provider: &str) {
    with_registry_lock(|| {
        let mut entries = load_registry();
        entries.push(RegistryEntry {
            agent_id: agent_id.to_string(),
            session_id: session_id.to_string(),
            provider: provider.to_string(),
            created_at: runtime::unix_now(),
        });
        save_registry(&entries);
    });
}

/// Unregister a sandbox after destruction.
pub fn unregister(session_id: &str) {
    with_registry_lock(|| {
        let mut entries = load_registry();
        entries.retain(|e| e.session_id != session_id);
        save_registry(&entries);
    });
}

/// Check if a sandbox is still within TTL. Returns Ok(()) if valid, Err if expired.
pub fn check_ttl(session_id: &str) -> Result<(), String> {
    let entries = load_registry();
    let now = runtime::unix_now();
    if let Some(entry) = entries.iter().find(|e| e.session_id == session_id) {
        // saturating_sub guards against clock skew (created_at in the future).
        if now.saturating_sub(entry.created_at) > SANDBOX_TTL_SECS {
            // Auto-destroy the expired sandbox
            let _ = destroy(&entry.session_id, &entry.provider);
            unregister(&entry.session_id);
            return Err(format!(
                "Sandbox {} expired (TTL: {}s). It has been auto-destroyed. Create a new one with: agora sandbox-create",
                &session_id[..8.min(session_id.len())],
                SANDBOX_TTL_SECS
            ));
        }
    }
    Ok(())
}

/// Look up the owning agent of a sandbox session.
/// Returns `Some(agent_id)` if the session is registered, `None` if not found.
pub fn session_owner(session_id: &str) -> Option<String> {
    load_registry()
        .iter()
        .find(|e| e.session_id == session_id)
        .map(|e| e.agent_id.clone())
}

/// In-memory exec attempt log: (agent_id, ts). The audit log only records
/// completed execs (appended after the provider call returns), so N concurrent
/// requests would all pass `MAX_EXEC_PER_MIN` by reading the audit alone. This
/// counter records the attempt *before* the exec call, closing the race.
static EXEC_ATTEMPTS: parking_lot::Mutex<Vec<(String, u64)>> = parking_lot::Mutex::new(Vec::new());

/// Record an exec attempt for `agent_id` at the current time. Must be called
/// BEFORE the provider exec call so concurrent requests are counted.
pub fn record_exec_attempt(agent_id: &str) {
    let now = runtime::unix_now();
    let mut attempts = EXEC_ATTEMPTS.lock();
    // Prune entries older than 60s to keep the vector bounded.
    let cutoff = now.saturating_sub(60);
    attempts.retain(|(_, ts)| *ts > cutoff);
    attempts.push((agent_id.to_string(), now));
}

/// Check exec rate limit for an agent. Returns Ok(()) or Err if rate limited.
pub fn check_exec_rate_limit(agent_id: &str) -> Result<(), String> {
    let now = runtime::unix_now();
    let minute_ago = now.saturating_sub(60);
    // Count in-memory attempts (recorded before the exec call) so concurrent
    // requests cannot all bypass the limit.
    let recent_execs = EXEC_ATTEMPTS
        .lock()
        .iter()
        .filter(|(aid, ts)| aid == agent_id && *ts > minute_ago)
        .count();
    if recent_execs >= MAX_EXEC_PER_MIN {
        return Err(format!(
            "Exec rate limit reached ({MAX_EXEC_PER_MIN}/min). Slow down."
        ));
    }
    Ok(())
}
use serde::{Deserialize, Serialize};

use crate::runtime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxSession {
    pub id: String,
    pub provider: String,
    pub agent_id: String,
    pub created_at: u64,
    pub status: String, // "running", "stopped", "destroyed"
}

/// Load sandbox tokens from env vars OR ~/.agora/sandbox-tokens.json
fn load_token(name: &str) -> Option<String> {
    // Env var first
    if let Some(val) = runtime::var(name)
        && !val.is_empty()
    {
        return Some(val);
    }
    // Fall back to tokens file
    let path = crate::store::agora_dir().join("sandbox-tokens.json");
    if let Ok(data) = std::fs::read_to_string(&path)
        && let Ok(v) = serde_json::from_str::<serde_json::Value>(&data)
        && let Some(val) = v[name].as_str()
    {
        return Some(val.to_string());
    }
    None
}

fn e2b_token() -> Option<String> {
    load_token("E2B_TOKEN")
}
fn daytona_token() -> Option<String> {
    load_token("DAYTONA_TOKEN")
}
fn sprites_token() -> Option<String> {
    load_token("SPRITES_TOKEN")
}

fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| reqwest::blocking::Client::new())
}

/// Create a sandbox — picks the first available provider.
pub fn create(agent_id: &str) -> Result<SandboxSession, String> {
    // Try Daytona first (tested working)
    if let Some(token) = daytona_token() {
        return create_daytona(agent_id, &token);
    }
    // Try E2B
    if let Some(token) = e2b_token() {
        return create_e2b(agent_id, &token);
    }
    // Try Sprites
    if let Some(token) = sprites_token() {
        return create_sprites(agent_id, &token);
    }
    Err(
        "No sandbox provider configured. Set E2B_TOKEN, DAYTONA_TOKEN, or SPRITES_TOKEN."
            .to_string(),
    )
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
    if e2b_token().is_some() {
        p.push("e2b".to_string());
    }
    if daytona_token().is_some() {
        p.push("daytona".to_string());
    }
    if sprites_token().is_some() {
        p.push("sprites".to_string());
    }
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
    let sandbox_id = body["sandboxID"]
        .as_str()
        .ok_or("E2B: no sandboxID in response")?
        .to_string();

    Ok(SandboxSession {
        id: sandbox_id,
        provider: "e2b".to_string(),
        agent_id: agent_id.to_string(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        status: "running".to_string(),
    })
}

fn exec_e2b(session_id: &str, command: &str) -> Result<String, String> {
    let token = e2b_token().ok_or("E2B_TOKEN not set")?;
    let resp = client()
        .post(format!(
            "https://api.e2b.dev/sandboxes/{session_id}/execute"
        ))
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
        .delete(format!("https://api.e2b.dev/sandboxes/{session_id}"))
        .header("X-E2B-API-Key", &token)
        .send()
        .map_err(|e| format!("E2B destroy failed: {e}"))?;
    Ok(())
}

// ── Daytona ────────────────────────────────────────────────────

fn create_daytona(agent_id: &str, token: &str) -> Result<SandboxSession, String> {
    let resp = client()
        .post("https://app.daytona.io/api/sandbox")
        .bearer_auth(token)
        .json(&serde_json::json!({
            "image": "ubuntu:22.04",
            "labels": {"agent_id": agent_id}
        }))
        .send()
        .map_err(|e| format!("Daytona create failed: {e}"))?;

    let body: serde_json::Value = resp
        .json()
        .map_err(|e| format!("Daytona parse failed: {e}"))?;
    let id = body["id"].as_str().unwrap_or("unknown").to_string();

    Ok(SandboxSession {
        id,
        provider: "daytona".to_string(),
        agent_id: agent_id.to_string(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        status: "running".to_string(),
    })
}

fn exec_daytona(session_id: &str, command: &str) -> Result<String, String> {
    let token = daytona_token().ok_or("DAYTONA_TOKEN not set")?;
    let resp = client()
        .post(format!(
            "https://proxy.app-eu.daytona.io/toolbox/{session_id}/process/execute"
        ))
        .bearer_auth(&token)
        .json(&serde_json::json!({"command": command}))
        .send()
        .map_err(|e| format!("Daytona exec failed: {e}"))?;

    let body: serde_json::Value = resp.json().map_err(|e| format!("Daytona parse: {e}"))?;
    let output = body["result"].as_str().unwrap_or("");
    let exit_code = body["exitCode"].as_i64().unwrap_or(-1);
    if exit_code != 0 {
        return Err(format!("Command failed (exit {}): {}", exit_code, output));
    }
    Ok(output.to_string())
}

fn destroy_daytona(session_id: &str) -> Result<(), String> {
    let token = daytona_token().ok_or("DAYTONA_TOKEN not set")?;
    client()
        .delete(format!("https://app.daytona.io/api/sandbox/{session_id}"))
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

    let body: serde_json::Value = resp
        .json()
        .map_err(|e| format!("Sprites parse failed: {e}"))?;
    let id = body["id"].as_str().unwrap_or("unknown").to_string();

    Ok(SandboxSession {
        id,
        provider: "sprites".to_string(),
        agent_id: agent_id.to_string(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        status: "running".to_string(),
    })
}

fn exec_sprites(session_id: &str, command: &str) -> Result<String, String> {
    let token = sprites_token().ok_or("SPRITES_TOKEN not set")?;
    let resp = client()
        .post(format!(
            "https://api.sprites.dev/v1/machines/{session_id}/exec"
        ))
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
        .delete(format!("https://api.sprites.dev/v1/machines/{session_id}"))
        .bearer_auth(&token)
        .send()
        .map_err(|e| format!("Sprites destroy failed: {e}"))?;
    Ok(())
}

// ── Per-agent sandbox tokens ───────────────────────────────────

/// Generate a time-limited sandbox access token for an agent.
/// Token = base64(agent_id:expiry:HMAC(agent_id:expiry, server_secret))
pub fn generate_agent_token(agent_id: &str, hours: u64) -> Result<String, String> {
    let secret = runtime::var("AGORA_SANDBOX_SECRET")
        .ok_or_else(|| "AGORA_SANDBOX_SECRET not set — refusing to use insecure default".to_string())?;
    let expiry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + hours * 3600;
    // Use JSON for canonical framing (prevents HMAC concatenation forgery)
    let payload = serde_json::json!({"a": agent_id, "e": expiry}).to_string();
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
    let sig = ring::hmac::sign(&key, payload.as_bytes());
    let token = format!("{payload}|{}", hex::encode(sig.as_ref()));
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.encode(token.as_bytes()))
}

/// Verify an agent sandbox token. Returns (agent_id, expiry) if valid.
pub fn verify_agent_token(token: &str) -> Result<(String, u64), String> {
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(token)
        .map_err(|_| "Invalid token encoding")?;
    let token_str = String::from_utf8(decoded).map_err(|_| "Invalid token UTF-8")?;
    // Split on | (JSON payload | hex signature)
    let parts: Vec<&str> = token_str.splitn(2, '|').collect();
    if parts.len() != 2 {
        return Err("Malformed token".to_string());
    }

    let payload = parts[0];
    let sig_hex = parts[1];

    // Parse JSON payload
    let v: serde_json::Value =
        serde_json::from_str(payload).map_err(|_| "Invalid token payload")?;
    let agent_id = v["a"].as_str().ok_or("Missing agent_id")?.to_string();
    let expiry = v["e"].as_u64().ok_or("Missing expiry")?;

    // Check expiry
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if now > expiry {
        return Err("Token expired".to_string());
    }

    // Verify HMAC over canonical JSON using constant-time comparison
    // (ring::hmac::verify) instead of a string `!=` to avoid timing
    // side-channels that could leak signature bytes.
    let secret = runtime::var("AGORA_SANDBOX_SECRET")
        .ok_or_else(|| "AGORA_SANDBOX_SECRET not set — refusing to use insecure default".to_string())?;
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
    let provided_sig = hex::decode(sig_hex).map_err(|_| "Invalid signature encoding")?;
    ring::hmac::verify(&key, payload.as_bytes(), &provided_sig)
        .map_err(|_| "Invalid signature".to_string())?;

    Ok((agent_id, expiry))
}
