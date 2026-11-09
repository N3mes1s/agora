//! Agent-authored platform plugins: write, sign, share, discover, install.
//!
//! A plugin is a directory with an `agora-plugin.toml` manifest:
//!
//! ```toml
//! name        = "vigil-freeze"
//! version     = "0.1.0"
//! description = "Ask vigil not to touch a resource for N minutes"
//! author      = "coder-1"            # publishing agent id
//! kind        = "command"            # mcp | skill | hook | command
//! entry       = "bin/vigil-freeze"   # path inside the plugin dir
//! runtimes    = ["claude-code", "codex", "omp"]
//! notes       = "Needs the vigil CLI on PATH."
//! ```
//!
//! Publishing packs the directory into a deterministic tar (sorted entries,
//! mtime 0, uid/gid 0, regular files only), hashes it (SHA-256), signs
//! `manifest + hash` with the author's Ed25519 agent key, shares the tar as
//! an encrypted room file and posts a `plugin_published` event. Installing
//! re-verifies the signature (against the TOFU-trusted key of the author),
//! the hash and the embedded manifest, then unpacks to
//! `~/.agora/plugins/<name>/<version>/` and registers it for one runtime.
//! Nothing is ever installed automatically.

use crate::{chat, config, crypto, runtime, store};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

pub const MANIFEST_FILE: &str = "agora-plugin.toml";
pub const MAX_BUNDLE_BYTES: usize = 512 * 1024;
pub const MAX_FILES: usize = 256;
/// Relay history scanned for plugin events.
pub const REGISTRY_WINDOW: &str = "720h";
pub const KINDS: &[&str] = &["mcp", "skill", "hook", "command"];
pub const RUNTIMES: &[&str] = &["claude-code", "codex", "omp"];

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

// ── Manifest ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub kind: String,
    pub entry: String,
    pub runtimes: Vec<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

fn parse_array(raw: &str) -> Vec<String> {
    let inner = raw.trim().trim_start_matches('[').trim_end_matches(']');
    inner
        .split(',')
        .map(|s| s.trim().trim_matches('"').trim_matches('\'').to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn valid_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && b[0].is_ascii_lowercase() | b[0].is_ascii_digit()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

fn valid_version(v: &str) -> bool {
    let core = v.split(['-', '+']).next().unwrap_or("");
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
        && v.len() <= 64
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-+".contains(c))
}

/// Compare `a.b.c` versions numerically (pre-release suffix sorts lower).
pub fn version_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    fn key(v: &str) -> (Vec<u64>, bool, String) {
        let (core, pre) = match v.split_once('-') {
            Some((c, p)) => (c, Some(p)),
            None => (v.split('+').next().unwrap_or(v), None),
        };
        (
            core.split('.').map(|p| p.parse().unwrap_or(0)).collect(),
            pre.is_none(),
            pre.unwrap_or("").to_string(),
        )
    }
    key(a).cmp(&key(b))
}

impl Manifest {
    /// Parse and validate manifest text.
    pub fn parse(text: &str) -> Result<Self, String> {
        let kv = config::parse_toml_subset(text);
        let get = |k: &str| kv.get(k).cloned().unwrap_or_default();
        let m = Manifest {
            name: get("name"),
            version: get("version"),
            description: get("description"),
            author: get("author"),
            kind: get("kind"),
            entry: get("entry"),
            runtimes: kv
                .get("runtimes")
                .map(|r| parse_array(r))
                .unwrap_or_default(),
            notes: kv.get("notes").cloned().filter(|n| !n.is_empty()),
        };
        m.validate()?;
        Ok(m)
    }

    pub fn validate(&self) -> Result<(), String> {
        if !valid_name(&self.name) {
            return Err(format!(
                "manifest: invalid name '{}' (lowercase letters, digits, '-', max 64)",
                self.name
            ));
        }
        if !valid_version(&self.version) {
            return Err(format!(
                "manifest: invalid version '{}' (use MAJOR.MINOR.PATCH)",
                self.version
            ));
        }
        if self.description.trim().is_empty() || self.description.chars().count() > 300 {
            return Err("manifest: description is required (max 300 chars)".to_string());
        }
        if self.author.trim().is_empty() {
            return Err("manifest: author (your agent id) is required".to_string());
        }
        if !KINDS.contains(&self.kind.as_str()) {
            return Err(format!(
                "manifest: kind must be one of {} (got '{}')",
                KINDS.join(", "),
                self.kind
            ));
        }
        safe_rel_path(&self.entry).map_err(|e| format!("manifest: entry: {e}"))?;
        if self.runtimes.is_empty() {
            return Err("manifest: runtimes must list at least one runtime".to_string());
        }
        for r in &self.runtimes {
            if !RUNTIMES.contains(&r.as_str()) {
                return Err(format!(
                    "manifest: unknown runtime '{r}' (supported: {})",
                    RUNTIMES.join(", ")
                ));
            }
        }
        Ok(())
    }

    pub fn id(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }
}

/// Validate a relative path from a manifest or archive: only normal
/// components, no absolute paths, no `..`, no backslashes or NULs.
pub fn safe_rel_path(raw: &str) -> Result<PathBuf, String> {
    if raw.is_empty() || raw.len() > 255 || raw.contains('\\') || raw.contains('\0') {
        return Err(format!("unsafe path '{raw}'"));
    }
    let p = Path::new(raw);
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            _ => return Err(format!("unsafe path '{raw}'")),
        }
    }
    if out.as_os_str().is_empty() {
        return Err(format!("unsafe path '{raw}'"));
    }
    Ok(out)
}

// ── Deterministic tar ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub path: String,
    pub data: Vec<u8>,
    pub executable: bool,
}

fn collect(dir: &Path, rel: &str, out: &mut Vec<Entry>, total: &mut usize) -> Result<(), String> {
    let mut items: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| format!("cannot read {}: {e}", dir.display()))?
        .flatten()
        .collect();
    items.sort_by_key(|e| e.file_name());
    for item in items {
        let name = item.file_name().to_string_lossy().to_string();
        if name == ".git" || name == ".DS_Store" || name == "target" || name == "node_modules" {
            continue;
        }
        let path = item.path();
        let meta = std::fs::symlink_metadata(&path)
            .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
        let rel_path = if rel.is_empty() {
            name.clone()
        } else {
            format!("{rel}/{name}")
        };
        if meta.file_type().is_symlink() {
            return Err(format!("symlinks are not allowed in plugins: {rel_path}"));
        }
        if meta.is_dir() {
            collect(&path, &rel_path, out, total)?;
        } else if meta.is_file() {
            safe_rel_path(&rel_path)?;
            let data =
                std::fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            *total += data.len();
            if *total > MAX_BUNDLE_BYTES {
                return Err(format!(
                    "plugin is too large (> {} KiB)",
                    MAX_BUNDLE_BYTES / 1024
                ));
            }
            use std::os::unix::fs::PermissionsExt;
            out.push(Entry {
                path: rel_path,
                data,
                executable: meta.permissions().mode() & 0o111 != 0,
            });
            if out.len() > MAX_FILES {
                return Err(format!("plugin has too many files (> {MAX_FILES})"));
            }
        }
    }
    Ok(())
}

/// Read the plugin directory into sorted entries.
pub fn read_dir_entries(dir: &Path) -> Result<Vec<Entry>, String> {
    let mut out = Vec::new();
    let mut total = 0;
    collect(dir, "", &mut out, &mut total)?;
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

fn octal(buf: &mut [u8], value: u64) {
    let width = buf.len() - 1;
    let s = format!("{value:0width$o}");
    buf[..width].copy_from_slice(&s.as_bytes()[s.len() - width..]);
    buf[width] = 0;
}

/// Build a deterministic ustar archive from entries.
pub fn tar_pack(entries: &[Entry]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for e in entries {
        safe_rel_path(&e.path)?;
        let mut h = [0u8; 512];
        let (prefix, name) = if e.path.len() <= 100 {
            ("", e.path.as_str())
        } else {
            let split = e.path[..e.path.len().min(156)]
                .rfind('/')
                .filter(|i| e.path.len() - i - 1 <= 100)
                .ok_or_else(|| format!("path too long for tar: {}", e.path))?;
            (&e.path[..split], &e.path[split + 1..])
        };
        h[..name.len()].copy_from_slice(name.as_bytes());
        octal(&mut h[100..108], if e.executable { 0o755 } else { 0o644 });
        octal(&mut h[108..116], 0);
        octal(&mut h[116..124], 0);
        octal(&mut h[124..136], e.data.len() as u64);
        octal(&mut h[136..148], 0);
        h[148..156].copy_from_slice(b"        ");
        h[156] = b'0';
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        h[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
        let sum: u32 = h.iter().map(|b| *b as u32).sum();
        let chk = format!("{sum:06o}\0 ");
        h[148..156].copy_from_slice(chk.as_bytes());
        out.extend_from_slice(&h);
        out.extend_from_slice(&e.data);
        let pad = (512 - e.data.len() % 512) % 512;
        out.extend(std::iter::repeat_n(0u8, pad));
    }
    out.extend(std::iter::repeat_n(0u8, 1024));
    Ok(out)
}

fn parse_octal(field: &[u8]) -> Result<u64, String> {
    let s: String = field
        .iter()
        .take_while(|b| **b != 0)
        .map(|b| *b as char)
        .collect();
    let s = s.trim();
    if s.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(s, 8).map_err(|_| "corrupt tar header".to_string())
}

fn cstr(field: &[u8]) -> Result<String, String> {
    let end = field.iter().position(|b| *b == 0).unwrap_or(field.len());
    String::from_utf8(field[..end].to_vec()).map_err(|_| "non-UTF-8 path in tar".to_string())
}

/// Parse a tar archive (regular files only; directories are skipped, links
/// and devices rejected) with path validation and size limits.
pub fn tar_unpack(bytes: &[u8]) -> Result<Vec<Entry>, String> {
    let mut out = Vec::new();
    let mut off = 0usize;
    let mut total = 0usize;
    while off + 512 <= bytes.len() {
        let h = &bytes[off..off + 512];
        if h.iter().all(|b| *b == 0) {
            break;
        }
        let stored = parse_octal(&h[148..156])?;
        let sum: u64 = h
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    *b as u64
                }
            })
            .sum();
        if stored != sum {
            return Err("tar checksum mismatch".to_string());
        }
        let size = parse_octal(&h[124..136])? as usize;
        let mode = parse_octal(&h[100..108])?;
        let name = cstr(&h[0..100])?;
        let prefix = cstr(&h[345..500])?;
        let path = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let typeflag = h[156];
        off += 512;
        let end = off
            .checked_add(size)
            .filter(|e| *e <= bytes.len())
            .ok_or_else(|| "truncated tar".to_string())?;
        match typeflag {
            b'0' | 0 => {
                safe_rel_path(&path)?;
                total += size;
                if total > MAX_BUNDLE_BYTES || out.len() >= MAX_FILES {
                    return Err("plugin bundle exceeds size/file limits".to_string());
                }
                out.push(Entry {
                    path,
                    data: bytes[off..end].to_vec(),
                    executable: mode & 0o111 != 0,
                });
            }
            b'5' => {}
            other => {
                return Err(format!(
                    "unsupported tar entry type '{}' for {path}",
                    other as char
                ));
            }
        }
        off = end + (512 - size % 512) % 512;
    }
    Ok(out)
}

/// Write unpacked entries under `dest` (which must not exist yet).
pub fn extract(entries: &[Entry], dest: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dest).map_err(|e| format!("cannot create {}: {e}", dest.display()))?;
    for e in entries {
        let rel = safe_rel_path(&e.path)?;
        let path = dest.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|err| format!("cannot create {}: {err}", parent.display()))?;
        }
        std::fs::write(&path, &e.data)
            .map_err(|err| format!("cannot write {}: {err}", path.display()))?;
        let mode = if e.executable { 0o755 } else { 0o644 };
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode));
    }
    Ok(())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref())
}

// ── Signing ─────────────────────────────────────────────────────

/// Bytes covered by the author's signature: the manifest text + bundle hash.
pub fn signing_bytes(manifest: &Manifest, manifest_text: &str, sha256: &str) -> Vec<u8> {
    format!(
        "agora-plugin-v1\n{}\n{}\n{}\n{}\n{sha256}\n{manifest_text}",
        manifest.name, manifest.version, manifest.author, manifest.kind
    )
    .into_bytes()
}

/// A packed, hashed and signed plugin ready to share.
#[derive(Debug, Clone)]
pub struct SignedBundle {
    pub manifest: Manifest,
    pub manifest_text: String,
    pub tar: Vec<u8>,
    pub sha256: String,
    pub signing_pubkey: String,
    pub sig: String,
}

/// Pack + hash + sign a plugin directory as `author`.
pub fn build_signed(dir: &Path, author: &str) -> Result<SignedBundle, String> {
    let manifest_text = std::fs::read_to_string(dir.join(MANIFEST_FILE))
        .map_err(|e| format!("cannot read {}/{MANIFEST_FILE}: {e}", dir.display()))?;
    let manifest = Manifest::parse(&manifest_text)?;
    if manifest.author != author {
        return Err(format!(
            "manifest author '{}' is not your agent id '{author}' — you can only publish as yourself",
            manifest.author
        ));
    }
    let entry_path = dir.join(safe_rel_path(&manifest.entry)?);
    if !entry_path.is_file() {
        return Err(format!("entry '{}' not found in plugin", manifest.entry));
    }
    let entries = read_dir_entries(dir)?;
    let tar = tar_pack(&entries)?;
    let sha256 = sha256_hex(&tar);
    let pkcs8 = store::load_or_create_signing_keypair(author)?;
    let pubkey = crypto::signing_public_key(&pkcs8).map_err(|e| e.to_string())?;
    let signing_pubkey = store::encode_signing_pubkey(&pubkey);
    let sig = crypto::sign_message(&pkcs8, &signing_bytes(&manifest, &manifest_text, &sha256))
        .map_err(|e| e.to_string())?;
    Ok(SignedBundle {
        manifest,
        manifest_text,
        tar,
        sha256,
        signing_pubkey,
        sig: B64.encode(sig),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SigStatus {
    Verified,
    /// Envelope or plugin signature missing.
    Unsigned,
    /// Signature does not verify, or fields disagree with the manifest.
    Invalid,
    /// Signed by a key that is not the trusted key for the author.
    UntrustedKey,
}

/// Check a `plugin_published` event: verified envelope from the author, a
/// valid Ed25519 signature over manifest+hash by the author's trusted key,
/// and event fields that match the signed manifest.
pub fn verify_publication(env: &Value) -> SigStatus {
    if env["_auth"].as_str() != Some("verified") {
        return SigStatus::Unsigned;
    }
    let (Some(sig), Some(pk), Some(text), Some(sha)) = (
        env["sig"].as_str(),
        env["signing_pubkey"].as_str(),
        env["manifest"].as_str(),
        env["sha256"].as_str(),
    ) else {
        return SigStatus::Unsigned;
    };
    let Ok(manifest) = Manifest::parse(text) else {
        return SigStatus::Invalid;
    };
    if env["from"].as_str() != Some(manifest.author.as_str())
        || env["name"].as_str() != Some(manifest.name.as_str())
        || env["version"].as_str() != Some(manifest.version.as_str())
        || env["kind"].as_str() != Some(manifest.kind.as_str())
    {
        return SigStatus::Invalid;
    }
    let (Some(pubkey), Ok(sig)) = (store::decode_signing_pubkey(pk), B64.decode(sig)) else {
        return SigStatus::Invalid;
    };
    if !crypto::verify_message_signature(&pubkey, &signing_bytes(&manifest, text, sha), &sig) {
        return SigStatus::Invalid;
    }
    match store::get_trusted_signing_key(&manifest.author) {
        Some(trusted) if store::signing_pubkeys_match(&trusted, pk) => SigStatus::Verified,
        _ => SigStatus::UntrustedKey,
    }
}

// ── Registry (folded from room events) ──────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct Feedback {
    pub from: String,
    pub score: i64,
    pub comment: String,
    pub ts: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Publication {
    pub manifest: Manifest,
    pub manifest_text: String,
    pub sha256: String,
    pub size: u64,
    pub file_id: String,
    pub signing_pubkey: String,
    pub sig: String,
    pub published_at: u64,
    pub sig_status: SigStatus,
    pub installs: usize,
    pub score: i64,
    pub feedback: Vec<Feedback>,
}

/// Fold plugin events into publications keyed by `name@version`. The first
/// verified publication of a name@version wins (no silent replacement).
pub fn fold(events: &[Value]) -> BTreeMap<String, Publication> {
    let mut pubs: BTreeMap<String, Publication> = BTreeMap::new();
    for env in events.iter().filter(|e| e["type"] == "plugin_published") {
        let status = verify_publication(env);
        let Ok(manifest) = Manifest::parse(env["manifest"].as_str().unwrap_or("")) else {
            continue;
        };
        let key = manifest.id();
        let candidate = Publication {
            manifest_text: env["manifest"].as_str().unwrap_or("").to_string(),
            sha256: env["sha256"].as_str().unwrap_or("").to_string(),
            size: env["size"].as_u64().unwrap_or(0),
            file_id: env["file_id"].as_str().unwrap_or("").to_string(),
            signing_pubkey: env["signing_pubkey"].as_str().unwrap_or("").to_string(),
            sig: env["sig"].as_str().unwrap_or("").to_string(),
            published_at: env["ts"].as_u64().unwrap_or(0),
            sig_status: status,
            installs: 0,
            score: 0,
            feedback: Vec::new(),
            manifest,
        };
        match pubs.get(&key) {
            Some(existing) if existing.sig_status == SigStatus::Verified => {}
            Some(_) if status != SigStatus::Verified => {}
            _ => {
                pubs.insert(key, candidate);
            }
        }
    }
    let mut installers: BTreeMap<String, std::collections::BTreeSet<String>> = BTreeMap::new();
    let mut votes: BTreeMap<String, BTreeMap<String, Feedback>> = BTreeMap::new();
    for env in events {
        if env["_auth"].as_str() != Some("verified") {
            continue;
        }
        let (Some(name), Some(version), Some(from)) = (
            env["name"].as_str(),
            env["version"].as_str(),
            env["from"].as_str(),
        ) else {
            continue;
        };
        let key = format!("{name}@{version}");
        match env["type"].as_str() {
            Some("plugin_installed") => {
                installers.entry(key).or_default().insert(from.to_string());
            }
            Some("plugin_feedback") => {
                let score = env["score"].as_i64().unwrap_or(0).clamp(-1, 1);
                votes.entry(key).or_default().insert(
                    from.to_string(),
                    Feedback {
                        from: from.to_string(),
                        score,
                        comment: env["comment"].as_str().unwrap_or("").to_string(),
                        ts: env["ts"].as_u64().unwrap_or(0),
                    },
                );
            }
            _ => {}
        }
    }
    for (key, p) in pubs.iter_mut() {
        p.installs = installers.get(key).map(|s| s.len()).unwrap_or(0);
        if let Some(v) = votes.remove(key) {
            p.score = v.values().map(|f| f.score).sum();
            p.feedback = v.into_values().collect();
            p.feedback.sort_by_key(|f| f.ts);
        }
    }
    pubs
}

fn resolve_room(room_label: Option<&str>) -> Result<store::RoomEntry, String> {
    let room = match room_label {
        Some(l) => store::find_room(l),
        None => store::get_active_room(),
    };
    room.ok_or_else(|| match room_label {
        Some(l) => format!("Room '{l}' not found. Run: agora rooms"),
        None => "No active room. Use 'agora create' or 'agora accept' first.".to_string(),
    })
}

/// Fetch and fold the room's plugin registry.
pub fn registry(
    room: &store::RoomEntry,
) -> Result<(BTreeMap<String, Publication>, Vec<Value>), String> {
    let events = chat::fetch_room_events(room, REGISTRY_WINDOW)?;
    Ok((fold(&events), events))
}

/// List publications, newest version first per name.
pub fn list(room_label: Option<&str>) -> Result<Vec<Publication>, String> {
    let room = resolve_room(room_label)?;
    let (pubs, _) = registry(&room)?;
    let mut out: Vec<Publication> = pubs.into_values().collect();
    out.sort_by(|a, b| {
        a.manifest
            .name
            .cmp(&b.manifest.name)
            .then_with(|| version_cmp(&b.manifest.version, &a.manifest.version))
    });
    Ok(out)
}

/// Resolve `name` or `name@version` (latest verified version if omitted).
pub fn select<'a>(
    pubs: &'a BTreeMap<String, Publication>,
    spec: &str,
) -> Result<&'a Publication, String> {
    let (name, version) = match spec.split_once('@') {
        Some((n, v)) => (n, Some(v)),
        None => (spec, None),
    };
    if let Some(v) = version {
        return pubs
            .get(&format!("{name}@{v}"))
            .ok_or_else(|| format!("plugin {name}@{v} not found in this room"));
    }
    pubs.values()
        .filter(|p| p.manifest.name == name)
        .max_by(|a, b| {
            (a.sig_status == SigStatus::Verified)
                .cmp(&(b.sig_status == SigStatus::Verified))
                .then_with(|| version_cmp(&a.manifest.version, &b.manifest.version))
        })
        .ok_or_else(|| format!("plugin '{name}' not found in this room (try: agora plugin list)"))
}

pub fn info(spec: &str, room_label: Option<&str>) -> Result<Publication, String> {
    let room = resolve_room(room_label)?;
    let (pubs, _) = registry(&room)?;
    select(&pubs, spec).cloned()
}

// ── Publish ─────────────────────────────────────────────────────

/// Publish a plugin directory to a room. Returns the publication.
pub fn publish(dir: &Path, room_label: Option<&str>) -> Result<Publication, String> {
    let room = resolve_room(room_label)?;
    let me = store::get_agent_id();
    let bundle = build_signed(dir, &me)?;
    let (pubs, _) = registry(&room)?;
    if let Some(existing) = pubs.get(&bundle.manifest.id())
        && existing.sig_status == SigStatus::Verified
    {
        return Err(format!(
            "{} is already published in this room (sha256 {}); bump the version",
            bundle.manifest.id(),
            &existing.sha256[..12]
        ));
    }

    let outbox = store::agora_dir().join("plugins").join(".outbox");
    std::fs::create_dir_all(&outbox).map_err(|e| format!("cannot create outbox: {e}"))?;
    let tar_path = outbox.join(format!(
        "{}-{}.tar",
        bundle.manifest.name, bundle.manifest.version
    ));
    std::fs::write(&tar_path, &bundle.tar).map_err(|e| format!("cannot write bundle: {e}"))?;
    let (file_id, size) = chat::send_file(&tar_path.to_string_lossy(), Some(&room.room_id))?;

    let m = &bundle.manifest;
    let text = format!(
        "[plugin] {me} published {}@{} ({}): {} — inspect: agora plugin info {}@{}",
        m.name, m.version, m.kind, m.description, m.name, m.version
    );
    let env = chat::publish_event_in(
        &room,
        json!({
            "type": "plugin_published",
            "name": m.name,
            "version": m.version,
            "description": m.description,
            "author": m.author,
            "kind": m.kind,
            "entry": m.entry,
            "runtimes": m.runtimes,
            "notes": m.notes,
            "manifest": bundle.manifest_text,
            "sha256": bundle.sha256,
            "size": size,
            "file_id": file_id,
            "signing_pubkey": bundle.signing_pubkey,
            "sig": bundle.sig,
        }),
        &text,
    )?;
    Ok(Publication {
        manifest: bundle.manifest,
        manifest_text: bundle.manifest_text,
        sha256: bundle.sha256,
        size,
        file_id,
        signing_pubkey: bundle.signing_pubkey,
        sig: bundle.sig,
        published_at: env["ts"].as_u64().unwrap_or(0),
        sig_status: SigStatus::Verified,
        installs: 0,
        score: 0,
        feedback: Vec::new(),
    })
}

// ── Install ─────────────────────────────────────────────────────

/// One change made to the system while registering a plugin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Change {
    /// Unpacked plugin files.
    Dir { path: String },
    /// Symlink we created (removed on uninstall).
    Symlink { path: String, target: String },
    /// Marked block appended to a config file (removed on uninstall).
    ConfigBlock { file: String, marker: String },
    /// External command we ran (and its undo command).
    Command { run: String, undo: String },
    /// Manual step for the user/agent; nothing was changed.
    Manual { text: String },
}

impl std::fmt::Display for Change {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Change::Dir { path } => write!(f, "unpacked files into {path}"),
            Change::Symlink { path, target } => write!(f, "linked {path} -> {target}"),
            Change::ConfigBlock { file, marker } => {
                write!(f, "appended [{marker}] block to {file}")
            }
            Change::Command { run, .. } => write!(f, "ran: {run}"),
            Change::Manual { text } => write!(f, "manual step (nothing changed): {text}"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Installed {
    pub name: String,
    pub version: String,
    pub sha256: String,
    pub author: String,
    pub kind: String,
    pub runtime: String,
    pub path: String,
    pub installed_at: u64,
    pub changes: Vec<Change>,
}

fn plugins_root() -> PathBuf {
    store::agora_dir().join("plugins")
}

fn installed_path() -> PathBuf {
    plugins_root().join("installed.json")
}

pub fn load_installed() -> Vec<Installed> {
    std::fs::read_to_string(installed_path())
        .ok()
        .and_then(|d| serde_json::from_str(&d).ok())
        .unwrap_or_default()
}

fn save_installed(items: &[Installed]) -> Result<(), String> {
    std::fs::create_dir_all(plugins_root()).map_err(|e| e.to_string())?;
    let data = serde_json::to_string_pretty(items).map_err(|e| e.to_string())?;
    std::fs::write(installed_path(), data).map_err(|e| e.to_string())
}

/// Reassemble a shared file from relay events (falling back to the local
/// message cache). Only chunks sent by `author` are accepted (signature-
/// verified on the relay copy); the caller still checks the hash.
pub fn fetch_file(
    room: &store::RoomEntry,
    events: &[Value],
    file_id: &str,
    author: &str,
) -> Result<Vec<u8>, String> {
    let mut chunks: BTreeMap<u64, String> = BTreeMap::new();
    let mut total: Option<u64> = None;
    let local = store::load_messages(&room.room_id, 31 * 24 * 3600);
    let relay = events
        .iter()
        .filter(|e| e["_auth"].as_str() == Some("verified"));
    let cached = local
        .iter()
        .filter(|e| e["_auth"].is_null() || e["_auth"].as_str() == Some("verified"));
    for env in relay.chain(cached) {
        if env["type"] != "file"
            || env["file_id"].as_str() != Some(file_id)
            || env["from"].as_str() != Some(author)
        {
            continue;
        }
        let n = env["chunk_n"].as_u64().unwrap_or(0);
        total = total.or(env["total_chunks"].as_u64());
        chunks
            .entry(n)
            .or_insert_with(|| env["data"].as_str().unwrap_or("").to_string());
    }
    let total = total.ok_or_else(|| {
        format!(
            "plugin bundle (file {file_id}) is no longer on the relay; ask the author to republish"
        )
    })?;
    if chunks.len() as u64 != total {
        return Err(format!(
            "plugin bundle incomplete: {}/{} chunks",
            chunks.len(),
            total
        ));
    }
    let mut out = Vec::new();
    for data in chunks.values() {
        out.extend(
            B64.decode(data)
                .map_err(|e| format!("bundle decode error: {e}"))?,
        );
        if out.len() > MAX_BUNDLE_BYTES + 64 * 1024 {
            return Err("plugin bundle too large".to_string());
        }
    }
    Ok(out)
}

/// Verified, unpacked plugin awaiting confirmation.
#[derive(Debug, Clone)]
pub struct Prepared {
    pub publication: Publication,
    pub entries: Vec<Entry>,
}

/// Fetch + verify a plugin without installing anything. Refuses unsigned,
/// invalid, untrusted or hash-mismatched packages.
pub fn prepare(spec: &str, room_label: Option<&str>) -> Result<Prepared, String> {
    let room = resolve_room(room_label)?;
    let (pubs, events) = registry(&room)?;
    let p = select(&pubs, spec)?.clone();
    match p.sig_status {
        SigStatus::Verified => {}
        other => {
            return Err(format!(
                "refusing {}: signature status is {other:?}",
                p.manifest.id()
            ));
        }
    }
    let bytes = fetch_file(&room, &events, &p.file_id, &p.manifest.author)?;
    let actual = sha256_hex(&bytes);
    if actual != p.sha256 {
        return Err(format!(
            "refusing {}: bundle hash mismatch (expected {}, got {})",
            p.manifest.id(),
            p.sha256,
            actual
        ));
    }
    let entries = tar_unpack(&bytes)?;
    let embedded = entries
        .iter()
        .find(|e| e.path == MANIFEST_FILE)
        .ok_or_else(|| {
            format!(
                "refusing {}: bundle has no {MANIFEST_FILE}",
                p.manifest.id()
            )
        })?;
    if embedded.data != p.manifest_text.as_bytes() {
        return Err(format!(
            "refusing {}: bundled manifest differs from the signed manifest",
            p.manifest.id()
        ));
    }
    let entry_path = safe_rel_path(&p.manifest.entry)?;
    if !entries.iter().any(|e| Path::new(&e.path) == entry_path) {
        return Err(format!(
            "refusing {}: entry '{}' missing from bundle",
            p.manifest.id(),
            p.manifest.entry
        ));
    }
    Ok(Prepared {
        publication: p,
        entries,
    })
}

fn home() -> PathBuf {
    runtime::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"))
}

fn link(path: PathBuf, target: &Path, changes: &mut Vec<Change>) -> Result<(), String> {
    if let Ok(existing) = std::fs::read_link(&path) {
        if existing == target {
            return Ok(());
        }
        if existing.starts_with(plugins_root()) {
            std::fs::remove_file(&path).map_err(|e| e.to_string())?;
        } else {
            return Err(format!(
                "{} already exists (links to {}); not overwriting",
                path.display(),
                existing.display()
            ));
        }
    } else if path.exists() {
        return Err(format!(
            "{} already exists; not overwriting",
            path.display()
        ));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::os::unix::fs::symlink(target, &path)
        .map_err(|e| format!("cannot link {}: {e}", path.display()))?;
    changes.push(Change::Symlink {
        path: path.display().to_string(),
        target: target.display().to_string(),
    });
    Ok(())
}

fn marker(name: &str) -> String {
    format!("agora-plugin:{name}")
}

fn append_block(
    file: &Path,
    name: &str,
    body: &str,
    changes: &mut Vec<Change>,
) -> Result<(), String> {
    let existing = std::fs::read_to_string(file).unwrap_or_default();
    let m = marker(name);
    if existing.contains(&format!("# {m} begin")) {
        return Ok(());
    }
    if existing.contains(&format!("[mcp_servers.{name}]")) {
        return Err(format!(
            "{} already defines [mcp_servers.{name}]; not overwriting",
            file.display()
        ));
    }
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut out = existing;
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&format!("\n# {m} begin\n{body}# {m} end\n"));
    std::fs::write(file, out).map_err(|e| format!("cannot write {}: {e}", file.display()))?;
    changes.push(Change::ConfigBlock {
        file: file.display().to_string(),
        marker: m,
    });
    Ok(())
}

fn remove_block(file: &str, marker: &str) -> Result<(), String> {
    let Ok(text) = std::fs::read_to_string(file) else {
        return Ok(());
    };
    let begin = format!("# {marker} begin");
    let end = format!("# {marker} end");
    let mut out = String::new();
    let mut skipping = false;
    for line in text.lines() {
        if line.trim() == begin {
            skipping = true;
            continue;
        }
        if line.trim() == end {
            skipping = false;
            continue;
        }
        if !skipping {
            out.push_str(line);
            out.push('\n');
        }
    }
    let out = out.trim_end().to_string() + "\n";
    std::fs::write(file, out).map_err(|e| e.to_string())
}

fn toml_str(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Register an unpacked plugin for a runtime. Returns what changed.
fn register(m: &Manifest, dir: &Path, runtime_name: &str) -> Result<Vec<Change>, String> {
    let mut changes = Vec::new();
    let entry = dir.join(safe_rel_path(&m.entry)?);
    let h = home();
    match m.kind.as_str() {
        "command" => {
            link(
                store::agora_dir().join("bin").join(&m.name),
                &entry,
                &mut changes,
            )?;
            changes.push(Change::Manual {
                text: format!(
                    "make sure {} is on PATH (rollout.sh adds it)",
                    store::agora_dir().join("bin").display()
                ),
            });
        }
        "skill" => {
            let skill_dir = entry.parent().unwrap_or(dir).to_path_buf();
            let target = match runtime_name {
                "claude-code" => h.join(".claude/skills").join(&m.name),
                "omp" => h.join(".omp/skills").join(&m.name),
                _ => h.join(".codex/skills").join(&m.name),
            };
            link(target, &skill_dir, &mut changes)?;
        }
        "mcp" => match runtime_name {
            "codex" => {
                let body = format!(
                    "[mcp_servers.{}]\ncommand = {}\nargs = []\n",
                    m.name,
                    toml_str(&entry.display().to_string())
                );
                append_block(&h.join(".codex/config.toml"), &m.name, &body, &mut changes)?;
            }
            "claude-code" => {
                let spec = json!({"type": "stdio", "command": entry.display().to_string(), "args": []});
                let run = format!(
                    "claude mcp add-json --scope user {} '{}'",
                    m.name, spec
                );
                let undo = format!("claude mcp remove --scope user {}", m.name);
                let ran = std::process::Command::new("claude")
                    .args(["mcp", "add-json", "--scope", "user", &m.name, &spec.to_string()])
                    .output();
                match ran {
                    Ok(out) if out.status.success() => changes.push(Change::Command { run, undo }),
                    _ => changes.push(Change::Manual {
                        text: format!("could not run `claude`; register it yourself: {run}"),
                    }),
                }
            }
            _ => changes.push(Change::Manual {
                text: format!(
                    "add to your OMP MCP config: {}",
                    json!({"mcpServers": {m.name.clone(): {"command": entry.display().to_string(), "args": []}}})
                ),
            }),
        },
        "hook" => {
            let snippet = json!({"PostToolUse": [{"hooks": [{"type": "command", "command": entry.display().to_string(), "timeout": 10}]}]});
            changes.push(Change::Manual {
                text: format!(
                    "hooks run on every tool call, so they are never wired automatically; \
                     review {} and add to your {runtime_name} hook config: {snippet}",
                    entry.display()
                ),
            });
        }
        other => return Err(format!("unknown plugin kind '{other}'")),
    }
    Ok(changes)
}

/// Default runtime: AGORA_RUNTIME, else detected from the environment.
pub fn default_runtime() -> String {
    if let Some(r) = runtime::var("AGORA_RUNTIME").filter(|r| RUNTIMES.contains(&r.as_str())) {
        return r;
    }
    if runtime::var("CODEX_THREAD_ID").is_some() || runtime::var("CODEX_CLI_SESSION_ID").is_some() {
        return "codex".to_string();
    }
    if runtime::var("OMP_SESSION_ID").is_some() {
        return "omp".to_string();
    }
    "claude-code".to_string()
}

/// Install a prepared (verified) plugin for `runtime_name`.
pub fn install(
    prepared: &Prepared,
    runtime_name: &str,
    room_label: Option<&str>,
) -> Result<Installed, String> {
    let p = &prepared.publication;
    let m = &p.manifest;
    if !RUNTIMES.contains(&runtime_name) {
        return Err(format!("unknown runtime '{runtime_name}'"));
    }
    if !m.runtimes.iter().any(|r| r == runtime_name) {
        return Err(format!(
            "{} does not support runtime '{runtime_name}' (supports: {})",
            m.id(),
            m.runtimes.join(", ")
        ));
    }
    let dir = plugins_root().join(&m.name).join(&m.version);
    let mut changes = Vec::new();
    if dir.exists() {
        let same = load_installed()
            .iter()
            .any(|i| i.name == m.name && i.version == m.version && i.sha256 == p.sha256);
        if !same {
            return Err(format!(
                "{} exists but was not installed from this bundle; remove it first",
                dir.display()
            ));
        }
    } else {
        let staging = plugins_root().join(".staging").join(format!(
            "{}-{}-{}",
            m.name,
            m.version,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&staging);
        extract(&prepared.entries, &staging)?;
        if let Some(parent) = dir.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::rename(&staging, &dir)
            .map_err(|e| format!("cannot move plugin into place: {e}"))?;
        changes.push(Change::Dir {
            path: dir.display().to_string(),
        });
    }
    changes.extend(register(m, &dir, runtime_name)?);

    let record = Installed {
        name: m.name.clone(),
        version: m.version.clone(),
        sha256: p.sha256.clone(),
        author: m.author.clone(),
        kind: m.kind.clone(),
        runtime: runtime_name.to_string(),
        path: dir.display().to_string(),
        installed_at: runtime::unix_now(),
        changes,
    };
    let mut all = load_installed();
    all.retain(|i| {
        !(i.name == record.name && i.version == record.version && i.runtime == record.runtime)
    });
    all.push(record.clone());
    save_installed(&all)?;

    if let Ok(room) = resolve_room(room_label) {
        let me = store::get_agent_id();
        let _ = chat::publish_event_in(
            &room,
            json!({"type": "plugin_installed", "name": m.name, "version": m.version,
                   "sha256": p.sha256, "runtime": runtime_name}),
            &format!("[plugin] {me} installed {} for {runtime_name}", m.id()),
        );
    }
    Ok(record)
}

/// Uninstall: undo recorded registrations and delete the files.
pub fn remove(spec: &str, runtime_name: Option<&str>) -> Result<Vec<String>, String> {
    let (name, version) = match spec.split_once('@') {
        Some((n, v)) => (n, Some(v)),
        None => (spec, None),
    };
    let mut all = load_installed();
    let (gone, keep): (Vec<Installed>, Vec<Installed>) = all.drain(..).partition(|i| {
        i.name == name
            && version.is_none_or(|v| v == i.version)
            && runtime_name.is_none_or(|r| r == i.runtime)
    });
    if gone.is_empty() {
        return Err(format!("{spec} is not installed"));
    }
    let mut done = Vec::new();
    for item in &gone {
        for change in item.changes.iter().rev() {
            match change {
                Change::Symlink { path, .. } => {
                    if std::fs::read_link(path).is_ok() {
                        let _ = std::fs::remove_file(path);
                        done.push(format!("removed link {path}"));
                    }
                }
                Change::ConfigBlock { file, marker } => {
                    remove_block(file, marker)?;
                    done.push(format!("removed [{marker}] block from {file}"));
                }
                Change::Command { undo, .. } => {
                    let parts: Vec<&str> = undo.split_whitespace().collect();
                    if let Some((cmd, args)) = parts.split_first() {
                        let ok = std::process::Command::new(cmd)
                            .args(args)
                            .output()
                            .is_ok_and(|o| o.status.success());
                        done.push(if ok {
                            format!("ran: {undo}")
                        } else {
                            format!("could not run `{undo}`; run it yourself")
                        });
                    }
                }
                Change::Dir { .. } | Change::Manual { .. } => {}
            }
        }
        let still_used = keep
            .iter()
            .any(|k| k.name == item.name && k.version == item.version);
        if !still_used && Path::new(&item.path).starts_with(plugins_root()) {
            let _ = std::fs::remove_dir_all(&item.path);
            done.push(format!("deleted {}", item.path));
        }
    }
    save_installed(&keep)?;
    Ok(done)
}

/// Rate a plugin version (+1 / -1) with a comment.
pub fn feedback(
    spec: &str,
    score: i64,
    comment: &str,
    room_label: Option<&str>,
) -> Result<Publication, String> {
    if score != 1 && score != -1 {
        return Err("score must be +1 or -1".to_string());
    }
    let room = resolve_room(room_label)?;
    let (pubs, _) = registry(&room)?;
    let p = select(&pubs, spec)?.clone();
    let me = store::get_agent_id();
    chat::publish_event_in(
        &room,
        json!({"type": "plugin_feedback", "name": p.manifest.name, "version": p.manifest.version,
               "score": score, "comment": comment}),
        &format!(
            "[plugin] {me} rated {} {}: {comment}",
            p.manifest.id(),
            if score > 0 { "+1" } else { "-1" }
        ),
    )?;
    Ok(p)
}

/// Is this a plugin bookkeeping event (installs/feedback) that should not
/// wake agents?
pub fn is_quiet_event(env: &Value) -> bool {
    matches!(
        env["type"].as_str(),
        Some("plugin_installed") | Some("plugin_feedback")
    )
}

// ── Scaffold ────────────────────────────────────────────────────

/// Create a new plugin skeleton in `dir` (which must not exist).
pub fn scaffold(
    name: &str,
    kind: &str,
    dir: &Path,
    description: Option<&str>,
) -> Result<Vec<PathBuf>, String> {
    if !valid_name(name) {
        return Err(format!("invalid plugin name '{name}'"));
    }
    if !KINDS.contains(&kind) {
        return Err(format!("--kind must be one of {}", KINDS.join(", ")));
    }
    if dir.exists() {
        return Err(format!("{} already exists", dir.display()));
    }
    let author = store::get_agent_id();
    let description = description.unwrap_or("TODO: one-line description");
    let (entry, body, executable): (String, String, bool) = match kind {
        "command" => (
            format!("bin/{name}"),
            format!(
                "#!/usr/bin/env bash\n# {name}: {description}\n# Runs with the caller's environment (AGORA_AGENT_ID, PATH, ...).\nset -euo pipefail\n\necho \"{name}: not implemented yet\" >&2\nexit 1\n"
            ),
            true,
        ),
        "skill" => (
            "SKILL.md".to_string(),
            format!(
                "---\nname: {name}\ndescription: {description}\n---\n\n# {name}\n\nTODO: when to use this skill and the exact steps/commands.\n"
            ),
            false,
        ),
        "mcp" => (
            "server.py".to_string(),
            MCP_TEMPLATE.replace("{name}", name),
            true,
        ),
        _ => (
            format!("hooks/{name}.sh"),
            format!(
                "#!/usr/bin/env bash\n# {name}: {description}\n# Claude Code / Codex hook: receives the event JSON on stdin.\n# Exit 0 = continue; exit 2 = block (stderr is shown to the model).\nset -euo pipefail\ncat >/dev/null\nexit 0\n"
            ),
            true,
        ),
    };
    let manifest = format!(
        "name = \"{name}\"\nversion = \"0.1.0\"\ndescription = \"{description}\"\nauthor = \"{author}\"\nkind = \"{kind}\"\nentry = \"{entry}\"\nruntimes = [\"claude-code\", \"codex\", \"omp\"]\nnotes = \"\"\n"
    );
    let readme = format!(
        "# {name}\n\n{description}\n\nKind: `{kind}` · entry: `{entry}`\n\nPublish: `agora plugin publish .`\nInstall (others): `agora plugin install {name} --yes`\n"
    );
    let mut written = Vec::new();
    for (rel, content, exec) in [
        (MANIFEST_FILE.to_string(), manifest, false),
        ("README.md".to_string(), readme, false),
        (entry, body, executable),
    ] {
        let path = dir.join(&rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(&path, content).map_err(|e| e.to_string())?;
        if exec {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755));
        }
        written.push(path);
    }
    Ok(written)
}

const MCP_TEMPLATE: &str = r#"#!/usr/bin/env python3
"""{name}: minimal MCP stdio server (JSON-RPC 2.0, one message per line).

Add tools to TOOLS and handle them in call_tool(). Standard library only.
"""
import json
import sys

TOOLS = [
    {
        "name": "{name}_hello",
        "description": "Example tool: echo a greeting.",
        "inputSchema": {"type": "object", "properties": {"who": {"type": "string"}}},
    }
]


def call_tool(name, args):
    if name == "{name}_hello":
        return "hello, " + args.get("who", "agent")
    raise ValueError("unknown tool: " + name)


def handle(req):
    method = req.get("method")
    if method == "initialize":
        return {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                "serverInfo": {"name": "{name}", "version": "0.1.0"}}
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        p = req.get("params", {})
        try:
            text = call_tool(p.get("name"), p.get("arguments") or {})
            return {"content": [{"type": "text", "text": text}]}
        except Exception as exc:  # report tool errors to the model
            return {"content": [{"type": "text", "text": str(exc)}], "isError": True}
    if method == "ping":
        return {}
    raise KeyError(method)


for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    req = json.loads(line)
    if "id" not in req:
        continue  # notification
    try:
        resp = {"jsonrpc": "2.0", "id": req["id"], "result": handle(req)}
    except KeyError as exc:
        resp = {"jsonrpc": "2.0", "id": req["id"],
                "error": {"code": -32601, "message": "method not found: %s" % exc}}
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "agora-plugin-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    const MANIFEST: &str = "name = \"demo\"\nversion = \"1.2.3\"\ndescription = \"demo plugin\"\nauthor = \"coder-1\"\nkind = \"command\"\nentry = \"bin/demo\"\nruntimes = [\"claude-code\", \"codex\"]\n";

    #[test]
    fn manifest_parses_and_validates() {
        let m = Manifest::parse(MANIFEST).unwrap();
        assert_eq!(m.id(), "demo@1.2.3");
        assert_eq!(m.runtimes, vec!["claude-code", "codex"]);
        assert!(Manifest::parse(&MANIFEST.replace("command", "rootkit")).is_err());
        assert!(Manifest::parse(&MANIFEST.replace("bin/demo", "../../etc/passwd")).is_err());
        assert!(Manifest::parse(&MANIFEST.replace("bin/demo", "/usr/bin/x")).is_err());
        assert!(Manifest::parse(&MANIFEST.replace("1.2.3", "latest")).is_err());
        assert!(Manifest::parse(&MANIFEST.replace("\"demo\"", "\"Demo Plugin\"")).is_err());
        assert!(Manifest::parse(&MANIFEST.replace("\"codex\"", "\"vim\"")).is_err());
    }

    #[test]
    fn tar_round_trips_deterministically() {
        let entries = vec![
            Entry {
                path: "agora-plugin.toml".into(),
                data: MANIFEST.as_bytes().to_vec(),
                executable: false,
            },
            Entry {
                path: "bin/demo".into(),
                data: b"#!/bin/sh\necho hi\n".to_vec(),
                executable: true,
            },
            Entry {
                path: format!("{}/{}", "d".repeat(120), "long-name.txt"),
                data: vec![7u8; 1000],
                executable: false,
            },
        ];
        let a = tar_pack(&entries).unwrap();
        let b = tar_pack(&entries).unwrap();
        assert_eq!(a, b, "pack is deterministic");
        assert_eq!(a.len() % 512, 0);
        assert_eq!(tar_unpack(&a).unwrap(), entries);
    }

    #[test]
    fn tar_unpack_rejects_traversal_links_and_corruption() {
        let ok = tar_pack(&[Entry {
            path: "x".into(),
            data: b"1".to_vec(),
            executable: false,
        }])
        .unwrap();
        // Corrupt a data byte inside the header -> checksum mismatch.
        let mut bad = ok.clone();
        bad[0] = b'y';
        assert!(tar_unpack(&bad).unwrap_err().contains("checksum"));
        // Hand-craft a "../evil" entry with a valid checksum.
        let mut evil = ok.clone();
        evil[..7].copy_from_slice(b"../evil");
        evil[148..156].copy_from_slice(b"        ");
        let sum: u32 = evil[..512].iter().map(|b| *b as u32).sum();
        evil[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        assert!(tar_unpack(&evil).unwrap_err().contains("unsafe path"));
        // Symlink entry type.
        let mut link = ok.clone();
        link[156] = b'2';
        link[148..156].copy_from_slice(b"        ");
        let sum: u32 = link[..512].iter().map(|b| *b as u32).sum();
        link[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        assert!(tar_unpack(&link).unwrap_err().contains("unsupported"));
    }

    #[test]
    fn pack_refuses_symlinks_and_oversize() {
        let dir = tmp("pack");
        std::fs::write(dir.join("a.txt"), "a").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", dir.join("pw")).unwrap();
        assert!(read_dir_entries(&dir).unwrap_err().contains("symlinks"));
        std::fs::remove_file(dir.join("pw")).unwrap();
        std::fs::write(dir.join("big.bin"), vec![0u8; MAX_BUNDLE_BYTES + 1]).unwrap();
        assert!(read_dir_entries(&dir).unwrap_err().contains("too large"));
        let _ = std::fs::remove_dir_all(dir);
    }

    fn signed_env(home: &Path, tamper: &dyn Fn(&mut Value)) -> Value {
        let _rt = runtime::TestRuntime::new()
            .home(home)
            .var("AGORA_AGENT_ID", "coder-1")
            .unset_var("AGORA_IDENTITY_SEED")
            .enter();
        let dir = home.join("demo");
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        std::fs::write(dir.join(MANIFEST_FILE), MANIFEST).unwrap();
        std::fs::write(dir.join("bin/demo"), "#!/bin/sh\necho hi\n").unwrap();
        let b = build_signed(&dir, "coder-1").unwrap();
        store::trust_signing_key("coder-1", &b.signing_pubkey);
        let mut env = json!({
            "type": "plugin_published", "from": "coder-1", "_auth": "verified",
            "name": "demo", "version": "1.2.3", "kind": "command",
            "manifest": b.manifest_text, "sha256": b.sha256,
            "signing_pubkey": b.signing_pubkey, "sig": b.sig, "ts": 1
        });
        tamper(&mut env);
        env
    }

    #[test]
    fn signature_verification_detects_tampering() {
        let home = tmp("sig");
        fn status_with(home: &Path, f: &dyn Fn(&mut Value)) -> SigStatus {
            let env = signed_env(home, f);
            let _rt = runtime::TestRuntime::new().home(home).enter();
            verify_publication(&env)
        }
        let check = |f: &dyn Fn(&mut Value)| status_with(&home, f);
        assert_eq!(check(&|_: &mut Value| {}), SigStatus::Verified);
        assert_eq!(
            check(&|e: &mut Value| e["sha256"] = json!("00".repeat(32))),
            SigStatus::Invalid,
            "hash swapped"
        );
        assert_eq!(
            check(&|e: &mut Value| {
                let t = e["manifest"]
                    .as_str()
                    .unwrap()
                    .replace("demo plugin", "evil plugin");
                e["manifest"] = json!(t);
            }),
            SigStatus::Invalid,
            "manifest edited"
        );
        assert_eq!(
            check(&|e: &mut Value| e["from"] = json!("coder-2")),
            SigStatus::Invalid
        );
        assert_eq!(
            check(&|e: &mut Value| e["_auth"] = json!("unsigned")),
            SigStatus::Unsigned
        );
        assert_eq!(
            check(&|e: &mut Value| {
                e["sig"] = json!(null);
            }),
            SigStatus::Unsigned
        );
        // Signed with a key that is not the TOFU key for coder-1.
        let env = signed_env(&home, &|_: &mut Value| {});
        let _rt = runtime::TestRuntime::new().home(&home).enter();
        store::trust_signing_key("coder-1", &B64.encode([9u8; 32]));
        assert_eq!(verify_publication(&env), SigStatus::UntrustedKey);
        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn build_refuses_publishing_as_someone_else() {
        let home = tmp("author");
        let _rt = runtime::TestRuntime::new()
            .home(&home)
            .var("AGORA_AGENT_ID", "coder-2")
            .enter();
        let dir = home.join("demo");
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        std::fs::write(dir.join(MANIFEST_FILE), MANIFEST).unwrap();
        std::fs::write(dir.join("bin/demo"), "x").unwrap();
        assert!(
            build_signed(&dir, "coder-2")
                .unwrap_err()
                .contains("only publish as yourself")
        );
        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn version_ordering() {
        use std::cmp::Ordering::*;
        assert_eq!(version_cmp("1.10.0", "1.9.9"), Greater);
        assert_eq!(version_cmp("1.0.0-rc1", "1.0.0"), Less);
        assert_eq!(version_cmp("0.1.0", "0.1.0"), Equal);
    }

    #[test]
    fn config_block_append_and_remove() {
        let dir = tmp("block");
        let file = dir.join("config.toml");
        std::fs::write(&file, "model = \"o3\"\n").unwrap();
        let mut changes = Vec::new();
        append_block(
            &file,
            "demo",
            "[mcp_servers.demo]\ncommand = \"/x\"\n",
            &mut changes,
        )
        .unwrap();
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(text.contains("[mcp_servers.demo]"));
        let Change::ConfigBlock { file: f, marker } = &changes[0] else {
            panic!()
        };
        remove_block(f, marker).unwrap();
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "model = \"o3\"\n");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn scaffold_produces_a_valid_plugin() {
        let home = tmp("scaffold");
        let _rt = runtime::TestRuntime::new()
            .home(&home)
            .var("AGORA_AGENT_ID", "coder-1")
            .enter();
        for kind in KINDS {
            let dir = home.join(format!("p-{kind}"));
            scaffold(&format!("p-{kind}"), kind, &dir, Some("test plugin")).unwrap();
            let b = build_signed(&dir, "coder-1").unwrap();
            assert_eq!(b.manifest.kind, *kind);
        }
        let _ = std::fs::remove_dir_all(home);
    }
}
