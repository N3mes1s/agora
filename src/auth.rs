//! HTTP API credentials for `agora serve`.
//!
//! Two kinds of bearer tokens are accepted for write requests:
//!
//! * the static `serve_token` (config key, env `AGORA_SERVE_TOKEN`), which
//!   authorizes writes performed as the server's own agent identity, and
//! * per-agent tokens minted with `agora api-token`, which carry a verified
//!   agent id. They are `base64({"a":agent,"e":expiry}|hmac)` signed with
//!   `serve_secret` (env `AGORA_SERVE_SECRET`; the legacy
//!   `AGORA_SANDBOX_SECRET` is still honoured).

use agora::{config, runtime};
use base64::Engine;

/// HMAC secret used to mint and verify per-agent API tokens.
pub fn serve_secret() -> Option<String> {
    config::secret("AGORA_SERVE_SECRET", "serve_secret")
        .or_else(|| runtime::var("AGORA_SANDBOX_SECRET").filter(|v| !v.trim().is_empty()))
}

/// Generate a time-limited API token for an agent.
pub fn generate_agent_token(agent_id: &str, hours: u64) -> Result<String, String> {
    let secret = serve_secret().ok_or_else(|| {
        "serve_secret not configured (config.toml or AGORA_SERVE_SECRET) — refusing to mint tokens"
            .to_string()
    })?;
    let expiry = runtime::unix_now() + hours * 3600;
    // JSON gives canonical framing (prevents HMAC concatenation forgery).
    let payload = serde_json::json!({"a": agent_id, "e": expiry}).to_string();
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
    let sig = ring::hmac::sign(&key, payload.as_bytes());
    let token = format!("{payload}|{}", hex::encode(sig.as_ref()));
    Ok(base64::engine::general_purpose::STANDARD.encode(token.as_bytes()))
}

/// Verify a per-agent API token. Returns `(agent_id, expiry)` if valid.
pub fn verify_agent_token(token: &str) -> Result<(String, u64), String> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(token)
        .map_err(|_| "Invalid token encoding")?;
    let token_str = String::from_utf8(decoded).map_err(|_| "Invalid token UTF-8")?;
    let (payload, sig_hex) = token_str
        .split_once('|')
        .ok_or_else(|| "Malformed token".to_string())?;

    let v: serde_json::Value =
        serde_json::from_str(payload).map_err(|_| "Invalid token payload")?;
    let agent_id = v["a"].as_str().ok_or("Missing agent_id")?.to_string();
    let expiry = v["e"].as_u64().ok_or("Missing expiry")?;
    if runtime::unix_now() > expiry {
        return Err("Token expired".to_string());
    }

    let secret = serve_secret()
        .ok_or_else(|| "serve_secret not configured — per-agent tokens are disabled".to_string())?;
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
    let provided_sig = hex::decode(sig_hex).map_err(|_| "Invalid signature encoding")?;
    // Constant-time comparison.
    ring::hmac::verify(&key, payload.as_bytes(), &provided_sig)
        .map_err(|_| "Invalid signature".to_string())?;

    Ok((agent_id, expiry))
}

/// Constant-time equality for static bearer tokens.
pub fn token_eq(provided: &str, expected: &str) -> bool {
    let a = ring::digest::digest(&ring::digest::SHA256, provided.as_bytes());
    let b = ring::digest::digest(&ring::digest::SHA256, expected.as_bytes());
    let mut diff = 0u8;
    for (x, y) in a.as_ref().iter().zip(b.as_ref()) {
        diff |= x ^ y;
    }
    diff == 0 && !expected.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_token_round_trips_and_rejects_tampering() {
        let _rt = runtime::TestRuntime::new()
            .var("AGORA_CONFIG", "/nonexistent/agora-test-config.toml")
            .var("AGORA_SERVE_SECRET", "unit-secret")
            .enter();
        let token = generate_agent_token("agent-a", 1).unwrap();
        let (agent, _) = verify_agent_token(&token).unwrap();
        assert_eq!(agent, "agent-a");

        let decoded = String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(&token)
                .unwrap(),
        )
        .unwrap();
        let forged = decoded.replace("agent-a", "agent-b");
        let forged = base64::engine::general_purpose::STANDARD.encode(forged);
        assert!(verify_agent_token(&forged).is_err());
    }

    #[test]
    fn tokens_disabled_without_secret() {
        let _rt = runtime::TestRuntime::new()
            .var("AGORA_CONFIG", "/nonexistent/agora-test-config.toml")
            .unset_var("AGORA_SERVE_SECRET")
            .unset_var("AGORA_SANDBOX_SECRET")
            .enter();
        assert!(generate_agent_token("agent-a", 1).is_err());
    }

    #[test]
    fn static_token_compare() {
        assert!(token_eq("abc", "abc"));
        assert!(!token_eq("abd", "abc"));
        assert!(!token_eq("", ""));
    }
}
