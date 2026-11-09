//! Local Agora configuration.
//!
//! Settings are read from `~/.agora/config.toml` (or the file named by
//! `AGORA_CONFIG`) and can be overridden per process with environment
//! variables. There is deliberately **no built-in public relay**: when no
//! relay is configured every relay operation fails closed with a clear error.
//!
//! ```toml
//! # ~/.agora/config.toml
//! relay_url   = "nats://127.0.0.1:4222"   # env: AGORA_RELAY_URL
//! relay_token = "change-me"               # env: AGORA_RELAY_TOKEN
//! # or: relay_token_file = "~/.agora/relay.token" (same *_file form works
//! # for serve_token, serve_secret and alert_token)
//! mirror      = ""                        # env: AGORA_RELAY_MIRROR (ntfy only)
//! local_only  = true                      # env: AGORA_LOCAL_ONLY
//!
//! # agora serve
//! serve_token = "change-me-too"           # env: AGORA_SERVE_TOKEN
//! alert_token = "grafana-webhook-secret"  # env: AGORA_ALERT_TOKEN
//! ```
//!
//! With `local_only = true` (the default) Agora refuses relays whose host is
//! not loopback, RFC 1918, CGNAT/Tailscale (100.64.0.0/10), IPv6 ULA, a bare
//! hostname, `*.local`, `*.localhost` or `*.ts.net`.

use crate::runtime;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

/// Relay settings after applying config file + environment overrides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySettings {
    pub url: Option<String>,
    pub token: Option<String>,
    pub mirror: Option<String>,
    pub local_only: bool,
}

/// Path of the config file (`AGORA_CONFIG` or `~/.agora/config.toml`).
pub fn config_path() -> PathBuf {
    if let Some(path) = runtime::var("AGORA_CONFIG")
        && !path.trim().is_empty()
    {
        return PathBuf::from(path);
    }
    runtime::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".agora")
        .join("config.toml")
}

/// Load the flat key/value view of the config file. Missing file -> empty.
pub fn load_file() -> HashMap<String, String> {
    match std::fs::read_to_string(config_path()) {
        Ok(text) => parse_toml_subset(&text),
        Err(_) => HashMap::new(),
    }
}

/// Look up a setting: environment variable first, then config file key.
/// Empty values are treated as unset.
pub fn setting(env_name: &str, file_key: &str) -> Option<String> {
    setting_from(&load_file(), env_name, file_key)
}

/// Like [`setting`], but also accepts `<KEY>_FILE` / `<key>_file` pointing
/// at a file holding the secret (first line, trimmed) — handy for tokens
/// provisioned with 0600 files.
pub fn secret(env_name: &str, file_key: &str) -> Option<String> {
    secret_from(&load_file(), env_name, file_key)
}

fn secret_from(file: &HashMap<String, String>, env_name: &str, file_key: &str) -> Option<String> {
    if let Some(v) = setting_from(file, env_name, file_key) {
        return Some(v);
    }
    let path = setting_from(
        file,
        &format!("{env_name}_FILE"),
        &format!("{file_key}_file"),
    )?;
    let path = if let Some(rest) = path.strip_prefix("~/") {
        runtime::home_dir()?.join(rest)
    } else {
        PathBuf::from(path)
    };
    std::fs::read_to_string(path)
        .ok()
        .and_then(|t| t.lines().next().map(|l| l.trim().to_string()))
        .filter(|t| !t.is_empty())
}

fn setting_from(file: &HashMap<String, String>, env_name: &str, file_key: &str) -> Option<String> {
    if let Some(value) = runtime::var(env_name) {
        let value = value.trim().to_string();
        return if value.is_empty() { None } else { Some(value) };
    }
    file.get(file_key)
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn parse_bool(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// Resolve relay settings from the config file and environment.
pub fn relay_settings() -> RelaySettings {
    let file = load_file();
    let local_only = setting_from(&file, "AGORA_LOCAL_ONLY", "local_only")
        .and_then(|v| parse_bool(&v))
        .unwrap_or(true);
    RelaySettings {
        url: setting_from(&file, "AGORA_RELAY_URL", "relay_url")
            .or_else(|| file.get("relay.url").cloned().filter(|v| !v.is_empty())),
        token: secret_from(&file, "AGORA_RELAY_TOKEN", "relay_token")
            .or_else(|| file.get("relay.token").cloned().filter(|v| !v.is_empty())),
        mirror: setting_from(&file, "AGORA_RELAY_MIRROR", "mirror")
            .or_else(|| file.get("relay.mirror").cloned().filter(|v| !v.is_empty())),
        local_only,
    }
}

/// Validate relay settings: a relay must be configured, and with
/// `local_only` it (and any mirror) must point at a private address.
pub fn validate_relay(settings: &RelaySettings) -> Result<String, String> {
    let Some(url) = settings.url.clone() else {
        return Err(format!(
            "no relay configured. Set relay_url in {} (e.g. relay_url = \"nats://127.0.0.1:4222\") \
             or export AGORA_RELAY_URL. Agora has no public default relay.",
            config_path().display()
        ));
    };
    if settings.local_only {
        check_local_url(&url).map_err(|e| {
            format!("{e} (local_only = true; set local_only = false in the config to allow it)")
        })?;
        if let Some(mirror) = &settings.mirror {
            check_local_url(mirror).map_err(|e| {
                format!("mirror {e} (local_only = true; set local_only = false to allow it)")
            })?;
        }
    }
    Ok(url)
}

/// Check that a relay URL points at a local/private host.
pub fn check_local_url(raw: &str) -> Result<(), String> {
    let raw = raw.trim();
    if raw.starts_with("memory://") {
        return Ok(());
    }
    let url = url::Url::parse(raw).map_err(|e| format!("relay URL '{raw}' is invalid: {e}"))?;
    match url.scheme() {
        "nats" | "tls" | "http" | "https" | "ws" | "wss" => {}
        other => {
            return Err(format!(
                "relay URL '{raw}' uses unsupported scheme '{other}'"
            ));
        }
    }
    let host = match url.host() {
        Some(url::Host::Ipv4(ip)) => return check_ip(IpAddr::V4(ip), raw),
        Some(url::Host::Ipv6(ip)) => return check_ip(IpAddr::V6(ip), raw),
        Some(url::Host::Domain(d)) => {
            // Non-special schemes (nats://) keep IPv4 literals as opaque domains.
            if let Ok(ip) = d.parse::<IpAddr>() {
                return check_ip(ip, raw);
            }
            d.trim_end_matches('.').to_ascii_lowercase()
        }
        None => return Err(format!("relay URL '{raw}' has no host")),
    };
    if is_local_hostname(&host) {
        Ok(())
    } else {
        Err(format!("relay '{raw}' is not a local/private host"))
    }
}

fn is_local_hostname(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    host == "localhost"
        || !host.contains('.')
        || host.ends_with(".local")
        || host.ends_with(".localhost")
        || host.ends_with(".ts.net")
}

fn check_ip(ip: IpAddr, raw: &str) -> Result<(), String> {
    if is_private_ip(ip) {
        Ok(())
    } else {
        Err(format!("relay '{raw}' is not a loopback/private address"))
    }
}

/// Loopback, RFC 1918, 100.64.0.0/10 (CGNAT / Tailscale) and IPv6 ULA/loopback.
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => {
            if v6 == Ipv6Addr::LOCALHOST {
                return true;
            }
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_private_v4(v4);
            }
            (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

fn is_private_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_loopback()
        || o[0] == 10
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 100 && (64..=127).contains(&o[1]))
}

/// Parse the small TOML subset Agora uses: `[section]` headers, `key = value`
/// with basic/literal strings, booleans and integers, `#` comments.
/// Keys inside a section are returned as `section.key`.
pub fn parse_toml_subset(text: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut section = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_string();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().trim_matches('"').to_string();
        let value = parse_value(value.trim());
        let full = if section.is_empty() {
            key
        } else {
            format!("{section}.{key}")
        };
        out.insert(full, value);
    }
    out
}

fn parse_value(raw: &str) -> String {
    if let Some(rest) = raw.strip_prefix('"') {
        let mut out = String::new();
        let mut chars = rest.chars();
        while let Some(c) = chars.next() {
            match c {
                '"' => break,
                '\\' => match chars.next() {
                    Some('n') => out.push('\n'),
                    Some('t') => out.push('\t'),
                    Some(other) => out.push(other),
                    None => break,
                },
                c => out.push(c),
            }
        }
        return out;
    }
    if let Some(rest) = raw.strip_prefix('\'') {
        return rest.split('\'').next().unwrap_or("").to_string();
    }
    // bare value: strip trailing comment
    raw.split('#').next().unwrap_or("").trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_only_accepts_private_hosts() {
        for url in [
            "nats://127.0.0.1:4222",
            "nats://localhost:4222",
            "http://10.1.2.3:8080",
            "http://172.20.0.5",
            "http://192.168.1.10:2586",
            "nats://100.101.102.103:4222",
            "nats://host-a:4222",
            "http://relay.local:8080",
            "nats://host-b.example.ts.net:4222",
            "nats://[::1]:4222",
            "nats://[fd12:3456::1]:4222",
            "memory://tests",
        ] {
            assert!(check_local_url(url).is_ok(), "{url} should be local");
        }
    }

    #[test]
    fn local_only_rejects_public_hosts() {
        for url in [
            "https://ntfy.theagora.dev",
            "https://ntfy.sh",
            "nats://8.8.8.8:4222",
            "nats://172.32.0.1:4222",
            "nats://100.128.0.1:4222",
            "http://example.com",
            "nats://[2001:db8::1]:4222",
            "ftp://127.0.0.1",
        ] {
            assert!(check_local_url(url).is_err(), "{url} should be refused");
        }
    }

    #[test]
    fn missing_relay_fails_closed() {
        let settings = RelaySettings {
            url: None,
            token: None,
            mirror: None,
            local_only: true,
        };
        let err = validate_relay(&settings).unwrap_err();
        assert!(err.contains("no relay configured"), "{err}");
    }

    #[test]
    fn public_relay_refused_unless_local_only_disabled() {
        let mut settings = RelaySettings {
            url: Some("https://ntfy.sh".into()),
            token: None,
            mirror: None,
            local_only: true,
        };
        assert!(validate_relay(&settings).is_err());
        settings.local_only = false;
        assert_eq!(validate_relay(&settings).unwrap(), "https://ntfy.sh");
    }

    #[test]
    fn public_mirror_refused_in_local_only_mode() {
        let settings = RelaySettings {
            url: Some("http://127.0.0.1:2586".into()),
            token: None,
            mirror: Some("https://ntfy.sh".into()),
            local_only: true,
        };
        assert!(validate_relay(&settings).unwrap_err().contains("mirror"));
    }

    #[test]
    fn secrets_can_come_from_files() {
        let home = std::env::temp_dir().join(format!(
            "agora-config-secret-{}-{}",
            std::process::id(),
            runtime::unix_now()
        ));
        std::fs::create_dir_all(home.join(".agora")).unwrap();
        std::fs::write(home.join(".agora/alert.token"), "s3cret\n").unwrap();
        std::fs::write(
            home.join(".agora/config.toml"),
            "alert_token_file = \"~/.agora/alert.token\"\n",
        )
        .unwrap();
        let _rt = runtime::TestRuntime::new()
            .home(&home)
            .unset_var("AGORA_CONFIG")
            .unset_var("AGORA_ALERT_TOKEN")
            .unset_var("AGORA_ALERT_TOKEN_FILE")
            .enter();
        assert_eq!(
            secret("AGORA_ALERT_TOKEN", "alert_token").as_deref(),
            Some("s3cret")
        );
        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn parses_toml_subset() {
        let parsed = parse_toml_subset(
            "# comment\nrelay_url = \"nats://127.0.0.1:4222\" # trailing\nlocal_only = false\n\
             relay_token='tok'\n[serve]\ntoken = \"abc\"\n",
        );
        assert_eq!(parsed["relay_url"], "nats://127.0.0.1:4222");
        assert_eq!(parsed["local_only"], "false");
        assert_eq!(parsed["relay_token"], "tok");
        assert_eq!(parsed["serve.token"], "abc");
    }

    #[test]
    fn config_file_and_env_override() {
        let home = std::env::temp_dir().join(format!(
            "agora-config-test-{}-{}",
            std::process::id(),
            runtime::unix_now()
        ));
        std::fs::create_dir_all(home.join(".agora")).unwrap();
        std::fs::write(
            home.join(".agora/config.toml"),
            "relay_url = \"nats://127.0.0.1:4222\"\nrelay_token = \"file-token\"\n",
        )
        .unwrap();
        {
            let _rt = runtime::TestRuntime::new()
                .home(&home)
                .unset_var("AGORA_CONFIG")
                .unset_var("AGORA_RELAY_URL")
                .unset_var("AGORA_RELAY_TOKEN")
                .unset_var("AGORA_RELAY_MIRROR")
                .unset_var("AGORA_LOCAL_ONLY")
                .enter();
            let s = relay_settings();
            assert_eq!(s.url.as_deref(), Some("nats://127.0.0.1:4222"));
            assert_eq!(s.token.as_deref(), Some("file-token"));
            assert!(s.local_only);
        }
        {
            let _rt = runtime::TestRuntime::new()
                .home(&home)
                .unset_var("AGORA_CONFIG")
                .var("AGORA_RELAY_URL", "nats://10.0.0.2:4222")
                .var("AGORA_RELAY_TOKEN", "")
                .unset_var("AGORA_RELAY_MIRROR")
                .var("AGORA_LOCAL_ONLY", "0")
                .enter();
            let s = relay_settings();
            assert_eq!(s.url.as_deref(), Some("nats://10.0.0.2:4222"));
            assert_eq!(s.token, None, "empty env value disables file token");
            assert!(!s.local_only);
        }
        let _ = std::fs::remove_dir_all(home);
    }
}
