//! Agora local message store.
//!
//! Persistence at ~/.agora/ (shared by every agent that runs as this unix user):
//!   rooms/<room_id>/messages/ — message files
//!   rooms.json                — room registry
//!   identity.json             — agent identity
//!
//! State that belongs to one reader is kept per agent (by `AGORA_AGENT_ID`):
//!   agents/<agent>/active_room
//!   agents/<agent>/rooms/<room_id>/read_cursor.json — read mark
//!   agents/<agent>/rooms/<room_id>/seen.txt         — ids `check`/`notify` handled
//!   agents/<agent>/rooms/<room_id>/notify.taken     — last daemon notify flag taken
//!   rooms/<room_id>/delivered/<agent>.txt          — delivered ledger
//!
//! An agent without its own file yet starts from the host-wide file older versions
//! wrote (`active_room`, `rooms/<id>/read_cursor.json`, `rooms/<id>/seen.txt`), so
//! upgrading marks nothing unread; from then on each agent writes only its own.

use crate::{crypto, runtime};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(test)]
use std::sync::{Mutex, OnceLock};

pub fn agora_dir() -> PathBuf {
    runtime::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".agora")
}

fn ensure_dir(path: &PathBuf) {
    let _ = fs::create_dir_all(path);
}

/// A file name for an agent id, one per id: `[A-Za-z0-9@._-]` kept, every other byte (and a leading dot)
/// percent-encoded, so `a/b`, `a_b` and `.a` never share state.
pub(crate) fn agent_key(agent_id: &str) -> String {
    if agent_id.is_empty() {
        return "%".to_string();
    }
    let mut out = String::new();
    for (i, b) in agent_id.bytes().enumerate() {
        let keep = b.is_ascii_alphanumeric() || b"@_-".contains(&b) || (b == b'.' && i > 0);
        if keep {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The name older versions used (unsafe characters as `_`, leading dots dropped): read once to seed the
/// new name's state.
fn legacy_agent_key(agent_id: &str) -> String {
    let name: String = agent_id.chars().map(|c| if c.is_ascii_alphanumeric() || "@._-".contains(c) { c } else { '_' }).collect();
    let name = name.trim_start_matches('.');
    if name.is_empty() { "_".to_string() } else { name.to_string() }
}

/// Copy `old` (a file or a directory tree) to `new` if `new` does not exist yet.
fn seed_from(old: &Path, new: &Path) {
    if new.exists() || !old.exists() {
        return;
    }
    if old.is_dir() {
        let _ = fs::create_dir_all(new);
        for e in fs::read_dir(old).into_iter().flatten().flatten() {
            seed_from(&e.path(), &new.join(e.file_name()));
        }
    } else {
        if let Some(dir) = new.parent() {
            let _ = fs::create_dir_all(dir);
        }
        let _ = fs::copy(old, new);
    }
}

/// The current agent's own state dir, `~/.agora/agents/<agent>/`.
pub fn agent_dir() -> PathBuf {
    let id = get_agent_id();
    let agents = agora_dir().join("agents");
    let dir = agents.join(agent_key(&id));
    let legacy = legacy_agent_key(&id);
    if legacy != agent_key(&id) {
        seed_from(&agents.join(legacy), &dir);
    }
    dir
}

/// `(own, legacy)` paths of a per-reader room file: the current agent's, and the host-wide one
/// older versions shared between all agents (read until the agent writes its own).
fn reader_file(room_id: &str, name: &str) -> (PathBuf, PathBuf) {
    (
        agent_dir().join("rooms").join(room_id).join(name),
        agora_dir().join("rooms").join(room_id).join(name),
    )
}

fn read_own_or_legacy((own, legacy): &(PathBuf, PathBuf)) -> Option<String> {
    fs::read_to_string(own).ok().or_else(|| fs::read_to_string(legacy).ok())
}

fn write_own(own: &Path, data: &str) {
    if let Some(dir) = own.parent() {
        ensure_dir(&dir.to_path_buf());
    }
    let _ = atomic_write(own, data);
}

fn now() -> u64 {
    runtime::unix_now()
}

static ATOMIC_WRITE_SEQ: AtomicU64 = AtomicU64::new(0);

// ── Identity ────────────────────────────────────────────────────
// Two-tier identity (SSH agent / Signal pattern):
// - Identity key: permanent Ed25519 keypair at ~/.agora/identity.json
// - Agent ID: first 16 hex chars of SHA-256(public_key) — unique, deterministic
// - AGORA_AGENT_ID: display alias override (not authoritative)
// - AGORA_IDENTITY_SEED: derive keypair from seed phrase (portable)

/// `<host>-<tmux session>-w<window index>` for processes running inside tmux, cached per process.
/// Pane ids are only unique within one tmux server: when an older server lost its socket to a
/// newer one, the new server answers for our pane id as some other window (or as `-w`), so an
/// answer from a server other than ours ($TMUX pid) falls back to `<host>-t<server pid>-p<pane>`.
fn tmux_window_agent_id() -> Option<String> {
    static CACHE: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    CACHE
        .get_or_init(|| {
            let pane = std::env::var("TMUX_PANE").ok().filter(|p| !p.is_empty())?;
            let server_pid = tmux_server_pid(&std::env::var("TMUX").ok()?)?;
            let window = std::process::Command::new("tmux")
                .args(["display-message", "-p", "-t", &pane, "#{pid} #S-w#I #{window_id}"])
                .stderr(std::process::Stdio::null())
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| own_tmux_window(&String::from_utf8_lossy(&o.stdout), &server_pid))
                .map(|(label, window_id)| pin_tmux_window_id(&server_pid, &window_id, &label));
            let host = fs::read_to_string("/proc/sys/kernel/hostname")
                .map(|h| h.trim().split('.').next().unwrap_or("").to_string())
                .unwrap_or_default();
            let raw = match window {
                Some(w) => format!("{host}-{w}"),
                None => format!("{host}-t{server_pid}-p{}", pane.trim_start_matches('%')),
            };
            Some(raw.chars().map(|c| if c.is_ascii_alphanumeric() || "._-".contains(c) { c } else { '-' }).collect())
        })
        .clone()
}

/// The server pid in `$TMUX` (`<socket>,<server pid>,<session index>`).
fn tmux_server_pid(tmux: &str) -> Option<String> {
    tmux.split(',').nth(1).filter(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())).map(str::to_string)
}

/// `(<session>-w<index>, <window_id>)` from `#{pid} #S-w#I #{window_id}`, only if our own server
/// answered. `window_id` (`@N`) never changes for the life of a tmux server, unlike the index.
fn own_tmux_window(out: &str, server_pid: &str) -> Option<(String, String)> {
    let mut parts = out.split_whitespace();
    let (pid, window, window_id) = (parts.next()?, parts.next()?, parts.next()?);
    let (session, index) = window.rsplit_once("-w")?;
    let id_ok = window_id.strip_prefix('@').is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
    (pid == server_pid
        && id_ok
        && !session.is_empty()
        && !index.is_empty()
        && index.bytes().all(|b| b.is_ascii_digit()))
    .then(|| (window.to_string(), window_id.to_string()))
}

/// The id a tmux window keeps for the life of its server: the `<session>-w<index>` it had when
/// first seen. Renumbering or renaming windows later must not change an agent's identity (P8).
/// Recorded in `<agora_dir>/tmux-ids/<server pid>-<window id>`; if another window already holds
/// the label, a `b`, `c`... suffix keeps ids unique. Falls back to the live label if unwritable.
fn pin_tmux_window_id(server_pid: &str, window_id: &str, label: &str) -> String {
    pin_tmux_window_id_in(&agora_dir().join("tmux-ids"), server_pid, window_id, label)
}

fn pin_tmux_window_id_in(dir: &std::path::Path, server_pid: &str, window_id: &str, label: &str) -> String {
    let file = dir.join(format!("{server_pid}-{}", window_id.trim_start_matches('@')));
    if let Ok(prev) = fs::read_to_string(&file) {
        let prev = prev.trim();
        if !prev.is_empty() {
            return prev.to_string();
        }
    }
    let taken: std::collections::HashSet<String> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with(&format!("{server_pid}-")))
        .filter_map(|e| fs::read_to_string(e.path()).ok())
        .map(|t| t.trim().to_string())
        .collect();
    let mut id = label.to_string();
    for suffix in ('b'..='z').map(String::from) {
        if !taken.contains(&id) {
            break;
        }
        id = format!("{label}{suffix}");
    }
    if fs::create_dir_all(dir).is_ok() {
        let _ = fs::write(&file, &id);
    }
    id
}

/// Does this host hold the signing key for `agent_id` (i.e. has it signed as that id)?
/// Never creates one, unlike [`load_signing_keypair`].
pub fn has_local_signing_key(agent_id: &str) -> bool {
    !agent_id.is_empty()
        && !agent_id.starts_with('.')
        && !agent_id.contains(['/', '\\'])
        && signing_keys_dir().join(format!("{agent_id}.pkcs8")).is_file()
}

pub fn get_agent_id() -> String {
    // Display alias override — not the authoritative identity, just cosmetic
    if let Some(id) = runtime::var("AGORA_AGENT_ID")
        && !id.is_empty()
    {
        return id;
    }

    // Inside tmux: one agent per window, named like ~/.agora/bin/agora-agent-id
    // (<host>-<session>-w<index>). This also covers agents started from shells that
    // predate the rollout, since every child of a tmux pane inherits TMUX_PANE.
    if let Some(id) = tmux_window_agent_id() {
        return id;
    }

    // Try to derive from existing identity key
    let id_file = agora_dir().join("identity.json");
    if let Ok(data) = fs::read_to_string(&id_file)
        && let Ok(v) = serde_json::from_str::<serde_json::Value>(&data)
    {
        // New format: key-derived ID
        if let Some(id) = v["key_id"].as_str() {
            return id.to_string();
        }
        // Legacy format: random ID
        if let Some(id) = v["agent_id"].as_str() {
            return id.to_string();
        }
    }

    // Generate new identity from seed or random
    let (agent_id, pkcs8) = generate_identity();

    let dir = agora_dir();
    if let Err(e) = fs::create_dir_all(&dir) {
        panic!(
            "agora: failed to create agora_dir at {}: {e}",
            dir.display()
        );
    }
    let pubkey = crypto::signing_public_key(&pkcs8).unwrap_or_default();
    let json = serde_json::json!({
        "key_id": agent_id,
        "agent_id": agent_id, // compat
        "public_key": hex::encode(&pubkey),
        "created_at": now(),
        "ephemeral": runtime::var("AGORA_IDENTITY_SEED").is_none(),
    });

    // Write signing-keys/<agent_id>.pkcs8 FIRST, then identity.json.
    // Atomicity-of-pair invariant: identity.json must NEVER exist on disk
    // without its corresponding signing-keys/<key_id>.pkcs8. Otherwise a
    // later get_agent_id() call would early-return the cached identity
    // (line 53-65) and downstream encrypt_envelope would fail to find the
    // signing key. Surfaced during the RFD-0029 dogfood (cfs-rfd-0029
    // [84efc2]) where pi-rs's SpritesProvider smoke hit exactly this
    // half-written state — silent `let _ = fs::write(...)` swallowed the
    // pkcs8 write error, identity.json got persisted alone, every
    // subsequent publish path panicked at the load_or_create_signing_keypair
    // refuse-to-fabricate check landed in 520f078.
    let keys_dir = agora_dir().join("signing-keys");
    if let Err(e) = fs::create_dir_all(&keys_dir) {
        panic!(
            "agora: failed to create signing-keys dir at {}: {e}",
            keys_dir.display()
        );
    }
    let pkcs8_path = keys_dir.join(format!("{agent_id}.pkcs8"));
    if let Err(e) = fs::write(&pkcs8_path, &pkcs8) {
        panic!(
            "agora: failed to persist signing keypair at {}: {e}",
            pkcs8_path.display()
        );
    }

    if let Err(e) = fs::write(&id_file, serde_json::to_string_pretty(&json).unwrap()) {
        panic!(
            "agora: failed to persist identity.json at {}: {e}",
            id_file.display()
        );
    }

    agent_id
}

fn generate_identity() -> (String, Vec<u8>) {
    // If seed phrase provided, derive keypair deterministically (portable identity).
    // HMAC-SHA256(key="agora-identity-v1", data=seed_phrase) -> 32-byte Ed25519 seed.
    if let Some(seed) = runtime::var("AGORA_IDENTITY_SEED") {
        let hk = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"agora-identity-v1");
        let derived = ring::hmac::sign(&hk, seed.as_bytes());
        let seed_bytes: [u8; 32] = derived.as_ref()[..32]
            .try_into()
            .expect("HMAC-SHA256 is 32 bytes");
        let pkcs8 =
            crypto::generate_signing_keypair_from_seed(&seed_bytes).expect("keygen from seed");
        let pubkey = crypto::signing_public_key(&pkcs8).unwrap();
        let id = derive_key_id(&pubkey);
        return (id, pkcs8);
    }

    // Generate random keypair
    let pkcs8 = crypto::generate_signing_keypair_pkcs8().expect("keygen");
    let pubkey = crypto::signing_public_key(&pkcs8).unwrap();
    let id = derive_key_id(&pubkey);
    (id, pkcs8)
}

/// Derive agent ID from public key: first 16 hex chars of SHA-256(pubkey)
fn derive_key_id(pubkey: &[u8]) -> String {
    use ring::digest;
    let hash = digest::digest(&digest::SHA256, pubkey);
    hex::encode(&hash.as_ref()[..8]) // 16 hex chars = 8 bytes
}

/// Get the cryptographic identity (key-derived ID), ignoring display alias.
pub fn get_key_id() -> String {
    let id_file = agora_dir().join("identity.json");
    if let Ok(data) = fs::read_to_string(&id_file)
        && let Ok(v) = serde_json::from_str::<serde_json::Value>(&data)
        && let Some(id) = v["key_id"].as_str()
    {
        return id.to_string();
    }
    get_agent_id() // fallback
}

/// Check if this agent has a persistent identity (not ephemeral).
pub fn is_persistent_identity() -> bool {
    let id_file = agora_dir().join("identity.json");
    if let Ok(data) = fs::read_to_string(&id_file)
        && let Ok(v) = serde_json::from_str::<serde_json::Value>(&data)
    {
        return v["ephemeral"].as_bool() == Some(false);
    }
    false
}

fn signing_keys_dir() -> PathBuf {
    agora_dir().join("signing-keys")
}

pub fn load_or_create_signing_keypair(agent_id: &str) -> Result<Vec<u8>, String> {
    let dir = signing_keys_dir();
    ensure_dir(&dir);
    let path = dir.join(format!("{agent_id}.pkcs8"));
    if let Ok(data) = fs::read(&path) {
        return Ok(data);
    }

    // When AGORA_IDENTITY_SEED is set, the caller expects a deterministic
    // seed-derived keypair. Silently generating a random keypair here for
    // an unknown `agent_id` produces a stable-but-WRONG key that
    // downstream TOFU caches as legitimate — and the next message signed
    // with the (different) seed-derived key fails verify with no signal
    // beyond `[auth] signing key no longer matches`. Surfaced during the
    // RFD-0029 dogfood (room cfs-rfd-0029 [b67570] / [d562fe]).
    //
    // Refuse the silent random-fabrication when a seed is configured.
    // Callers that intentionally want a random key for `agent_id` must
    // explicitly unset AGORA_IDENTITY_SEED before this call.
    if let Some(seed) = runtime::var("AGORA_IDENTITY_SEED")
        && !seed.is_empty()
    {
        return Err(format!(
            "refusing to fabricate random signing key for agent_id={agent_id} \
             at {} while AGORA_IDENTITY_SEED is set — the caller likely \
             passed an agent_id that does not match the seed-derived \
             identity, which would silently corrupt TOFU on the receiver \
             side. Either (a) clear AGORA_IDENTITY_SEED if random is \
             intended, (b) pass the correct seed-derived agent_id \
             (key_id from identity.json), or (c) pre-create the keypair \
             file out of band.",
            path.display()
        ));
    }

    let pkcs8 = crypto::generate_signing_keypair_pkcs8().map_err(|e| e.to_string())?;
    fs::write(&path, &pkcs8).map_err(|e| format!("failed to persist signing key: {e}"))?;
    Ok(pkcs8)
}

/// Load the signing keypair for `agent_id`, creating and persisting one on first use.
pub fn load_signing_keypair(agent_id: &str) -> Result<Vec<u8>, String> {
    load_or_create_signing_keypair(agent_id)
}

// ── Trusted Signing Keys (TOFU) ────────────────────────────────

pub fn load_trusted_signing_keys() -> HashMap<String, String> {
    let path = agora_dir().join("trusted_signing_keys.json");
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        HashMap::new()
    }
}

pub fn save_trusted_signing_keys(keys: &HashMap<String, String>) {
    let dir = agora_dir();
    ensure_dir(&dir);
    let data = serde_json::to_string_pretty(keys).unwrap();
    let _ = atomic_write(&dir.join("trusted_signing_keys.json"), &data);
}

pub fn encode_signing_pubkey(pubkey: &[u8]) -> String {
    STANDARD.encode(pubkey)
}

pub fn decode_signing_pubkey(signing_pubkey: &str) -> Option<Vec<u8>> {
    STANDARD
        .decode(signing_pubkey)
        .or_else(|_| URL_SAFE_NO_PAD.decode(signing_pubkey))
        .ok()
}

pub fn signing_pubkeys_match(left: &str, right: &str) -> bool {
    if left == right {
        return true;
    }

    match (decode_signing_pubkey(left), decode_signing_pubkey(right)) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
}

fn canonicalize_signing_pubkey(signing_pubkey: &str) -> String {
    decode_signing_pubkey(signing_pubkey)
        .map(|pubkey| encode_signing_pubkey(&pubkey))
        .unwrap_or_else(|| signing_pubkey.to_string())
}

pub fn get_trusted_signing_key(agent_id: &str) -> Option<String> {
    load_trusted_signing_keys()
        .get(agent_id)
        .map(|key| canonicalize_signing_pubkey(key))
}

pub fn trust_signing_key(agent_id: &str, signing_pubkey: &str) {
    let mut keys = load_trusted_signing_keys();
    keys.insert(
        agent_id.to_string(),
        canonicalize_signing_pubkey(signing_pubkey),
    );
    save_trusted_signing_keys(&keys);
}

#[cfg(test)]
pub fn test_env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

// ── Room Registry ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Role {
    Admin,
    Member,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomMember {
    pub agent_id: String,
    pub role: Role,
    pub joined_at: u64,
    pub nickname: Option<String>,
    #[serde(default)]
    pub last_seen: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomEntry {
    pub room_id: String,
    pub secret: String,
    pub label: String,
    pub joined_at: u64,
    #[serde(default)]
    pub topic: Option<String>,
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub dm_peer: Option<String>,
    #[serde(default)]
    pub members: Vec<RoomMember>,
}

pub fn load_registry() -> Vec<RoomEntry> {
    let path = agora_dir().join("rooms.json");
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        vec![]
    }
}

fn atomic_write_bytes(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("tmp");
    let seq = ATOMIC_WRITE_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = parent.join(format!(".{file_name}.{}.{}.tmp", std::process::id(), seq));
    fs::write(&tmp, data)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn atomic_write(path: &Path, data: &str) -> std::io::Result<()> {
    atomic_write_bytes(path, data.as_bytes())
}

// ── File-Level Advisory Locking ────────────────────────────────
//
// flock-based locks guard load→mutate→save cycles against concurrent
// writers from another process (daemon child ↔ CLI). In-process Mutexes
// are insufficient because the daemon forks+setsid into a separate
// process that shares no address space with the CLI.
//
// Strategy: LOCK_EX | LOCK_NB with 3 retries at 50ms intervals. If the
// lock cannot be acquired after 3 tries, proceed without it (better
// than hanging the CLI) and log a warning.

/// RAII guard for an advisory `flock` on a `.lock` sidecar file.
///
/// On creation it opens (creating if needed) `<path>.lock` and attempts to
/// acquire an exclusive lock. On `Drop` the lock is released and the file
/// handle closed. A `FileLock` that failed to acquire the lock is still
/// safe to hold — `acquired()` reports whether the kernel granted it.
pub struct FileLock {
    _file: Option<fs::File>,
    acquired: bool,
}

impl FileLock {
    /// Try to open `<file_path>.lock` and acquire an exclusive, non-blocking
    /// lock. Returns a guard whose `acquired()` is `false` if the lock was
    /// contended or the file could not be opened.
    #[cfg(test)]
    fn try_acquire(file_path: &Path) -> Self {
        let lock_path = lock_path_for(file_path);
        if let Some(parent) = lock_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let file = match fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .read(true)
            .open(&lock_path)
        {
            Ok(f) => f,
            Err(e) => {
                eprintln!(
                    "agora: warning: could not open lock file {}: {}",
                    lock_path.display(),
                    e
                );
                return FileLock {
                    _file: None,
                    acquired: false,
                };
            }
        };
        let acquired = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0;
        FileLock {
            _file: Some(file),
            acquired,
        }
    }

    /// Whether the kernel granted the exclusive lock.
    pub fn acquired(&self) -> bool {
        self.acquired
    }

    /// Open `<file_path>.lock` and acquire a blocking exclusive lock.
    /// Waits until the lock is available — correct for daemon/CLI coordination.
    fn acquire_blocking(file_path: &Path) -> Self {
        let lock_path = lock_path_for(file_path);
        if let Some(parent) = lock_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let file = match fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .read(true)
            .open(&lock_path)
        {
            Ok(f) => f,
            Err(_) => {
                return FileLock {
                    _file: None,
                    acquired: false,
                };
            }
        };
        // Blocking LOCK_EX — waits until the lock is available.
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        FileLock {
            _file: Some(file),
            acquired: true,
        }
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        if self.acquired
            && let Some(file) = &self._file
        {
            // LOCK_UN on the fd; closing the file also releases, but be explicit.
            unsafe {
                let _ = libc::flock(file.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}

/// `<file_path>.lock` — the lock sidecar path.
fn lock_path_for(file_path: &Path) -> PathBuf {
    let mut s = file_path.as_os_str().to_owned();
    s.push(".lock");
    PathBuf::from(s)
}

/// Acquire an advisory lock on `<file_path>.lock`, run `f`, release on drop.
///
/// Uses blocking `LOCK_EX` — waits until the lock is available. This is correct
/// for daemon/CLI coordination: the CLI may briefly block, but no data is lost.
/// The lock file is opened with create-if-missing and the fd is held for the
/// duration of `f`.
pub fn with_file_lock<T>(file_path: &Path, f: impl FnOnce() -> T) -> T {
    let _lock = FileLock::acquire_blocking(file_path);
    f()
}

/// Path to the room registry (`~/.agora/rooms.json`).
fn registry_path() -> PathBuf {
    agora_dir().join("rooms.json")
}
pub fn save_registry(rooms: &[RoomEntry]) {
    let dir = agora_dir();
    ensure_dir(&dir);
    let data = serde_json::to_string_pretty(rooms).unwrap();
    let _ = atomic_write(&dir.join("rooms.json"), &data);
}

pub fn add_room(room_id: &str, secret: &str, label: &str, role: Role) -> RoomEntry {
    let path = registry_path();
    with_file_lock(&path, || {
        let mut rooms = load_registry();
        let agent_id = get_agent_id();
        if let Some(existing) = rooms.iter_mut().find(|r| r.room_id == room_id) {
            // Another agent on this host joined it first: the room is shared, but this agent is
            // a member in its own right.
            if existing.members.iter().any(|m| m.agent_id == agent_id) {
                return existing.clone();
            }
            existing.members.push(RoomMember {
                agent_id,
                role,
                joined_at: now(),
                nickname: None,
                last_seen: now(),
            });
            let updated = existing.clone();
            save_registry(&rooms);
            return updated;
        }
        let entry = RoomEntry {
            room_id: room_id.to_string(),
            secret: secret.to_string(),
            label: label.to_string(),
            joined_at: now(),
            topic: None,
            purpose: None,
            dm_peer: None,
            members: vec![RoomMember {
                agent_id,
                role,
                joined_at: now(),
                nickname: None,
                last_seen: now(),
            }],
        };
        rooms.push(entry.clone());
        save_registry(&rooms);
        entry
    })
}

/// The other side of a canonical DM label `dm-<min>-<max>` when `me` is one side.
pub fn dm_label_peer<'a>(label: &'a str, me: &str) -> Option<&'a str> {
    let rest = label.strip_prefix("dm-")?;
    if let Some(peer) = rest.strip_prefix(me).and_then(|r| r.strip_prefix('-'))
        && !peer.is_empty()
        && peer > me
    {
        return Some(peer);
    }
    if let Some(peer) = rest.strip_suffix(me).and_then(|r| r.strip_suffix('-'))
        && !peer.is_empty()
        && peer < me
    {
        return Some(peer);
    }
    None
}

/// `me`'s peer in a DM room. All agents of a host share one registry entry, so the peer is read from
/// the canonical label, from whichever side looks: a `dm-` room that does not name `me` is someone
/// else's DM. Only a legacy DM with a non-canonical label falls back to the stored `dm_peer`.
pub fn room_dm_peer(room: &RoomEntry, me: &str) -> Option<String> {
    if let Some(peer) = dm_label_peer(&room.label, me) {
        return Some(peer.to_string());
    }
    // A canonical label (`dm-<a>-<b>`, which names its stored peer) that does not name `me` is someone
    // else's DM; a legacy label that does not follow the scheme keeps its stored peer.
    let peer = room.dm_peer.as_deref()?;
    if room.label.starts_with("dm-") && dm_label_peer(&room.label, peer).is_some() {
        return None;
    }
    Some(peer.to_string())
}

/// Registry format this binary writes; older registries are migrated once by `migrate_registry`.
pub const REGISTRY_VERSION: u32 = 2;

/// Bring `rooms` to the current format. v2: a DM's `dm_peer` was stored from its creator's side, so
/// the other agent sharing the registry saw itself as the peer and `agora dm` failed ("already bound
/// to DM peer"). For canonical DM labels the peer is now derived per reader, so the stored side is
/// dropped. Returns whether anything changed.
pub fn migrate_rooms(rooms: &mut [RoomEntry]) -> bool {
    let mut changed = false;
    for room in rooms.iter_mut().filter(|r| r.label.starts_with("dm-")) {
        if room.dm_peer.as_deref().is_some_and(|p| dm_label_peer(&room.label, p).is_some()) {
            room.dm_peer = None;
            changed = true;
        }
        if room.dm_peer.is_none() && room.purpose.is_none() {
            room.purpose = Some("dm".to_string());
            changed = true;
        }
    }
    changed
}

/// Migrate `rooms.json` to `REGISTRY_VERSION` once per host (`registry_version` marks it done).
pub fn migrate_registry() {
    let marker = agora_dir().join("registry_version");
    let current = fs::read_to_string(&marker).ok().and_then(|v| v.trim().parse::<u32>().ok()).unwrap_or(1);
    if current >= REGISTRY_VERSION || !registry_path().exists() {
        return;
    }
    let span = tracing::info_span!(target: "agora", "agora.state.migrate", from = current, to = REGISTRY_VERSION, changed = tracing::field::Empty);
    let _in = span.enter();
    with_file_lock(&registry_path(), || {
        let mut rooms = load_registry();
        let changed = migrate_rooms(&mut rooms);
        if changed {
            save_registry(&rooms);
        }
        span.record("changed", changed);
        let _ = atomic_write(&marker, &REGISTRY_VERSION.to_string());
    });
}

pub fn update_room(room: &RoomEntry) {
    let path = registry_path();
    with_file_lock(&path, || {
        let mut rooms = load_registry();
        let mut changed = false;
        if let Some(r) = rooms.iter_mut().find(|r| r.room_id == room.room_id) {
            *r = room.clone();
            changed = true;
        }
        if changed {
            save_registry(&rooms);
        }
    });
}

/// Mark a room as a DM with `peer_agent_id`. A canonical DM label names both sides, so the peer is
/// derived per reader (`room_dm_peer`) and not stored; only a non-canonical legacy label stores it.
pub fn mark_dm_room(room_id: &str, peer_agent_id: &str) -> Result<RoomEntry, String> {
    with_file_lock(&registry_path(), || {
        let mut rooms = load_registry();
        let Some(room) = rooms.iter_mut().find(|r| r.room_id == room_id) else {
            return Err(format!("Room '{room_id}' not found."));
        };
        let stored = if dm_label_peer(&room.label, peer_agent_id).is_some() { None } else { Some(peer_agent_id.to_string()) };
        let changed = room.purpose.as_deref() != Some("dm") || room.dm_peer != stored;
        room.purpose = Some("dm".to_string());
        room.dm_peer = stored;
        let updated = room.clone();
        if changed {
            save_registry(&rooms);
        }
        Ok(updated)
    })
}

pub fn remove_member_from_room(room_id: &str, agent_id: &str) {
    let mut rooms = load_registry();
    let mut changed = false;
    if let Some(room) = rooms.iter_mut().find(|r| r.room_id == room_id) {
        let before = room.members.len();
        room.members.retain(|m| m.agent_id != agent_id);
        changed = room.members.len() != before;
    }
    if changed {
        save_registry(&rooms);
    }
}

pub fn is_admin(room_id: &str, agent_id: &str) -> bool {
    load_registry()
        .iter()
        .find(|r| r.room_id == room_id)
        .and_then(|r| r.members.iter().find(|m| m.agent_id == agent_id))
        .is_some_and(|m| m.role == Role::Admin)
}

pub fn update_last_seen(room_id: &str, agent_id: &str) {
    let path = registry_path();
    with_file_lock(&path, || {
        let mut rooms = load_registry();
        let mut changed = false;
        if let Some(room) = rooms.iter_mut().find(|r| r.room_id == room_id) {
            if let Some(member) = room.members.iter_mut().find(|m| m.agent_id == agent_id) {
                member.last_seen = now();
                changed = true;
            } else {
                // First time seeing this agent — add as member
                room.members.push(RoomMember {
                    agent_id: agent_id.to_string(),
                    role: Role::Member,
                    joined_at: now(),
                    nickname: None,
                    last_seen: now(),
                });
                changed = true;
            }
        }
        if changed {
            save_registry(&rooms);
        }
    });
}

pub fn set_member_role(room_id: &str, agent_id: &str, role: Role) {
    let path = registry_path();
    with_file_lock(&path, || {
        let mut rooms = load_registry();
        let mut changed = false;
        if let Some(room) = rooms.iter_mut().find(|r| r.room_id == room_id)
            && let Some(member) = room.members.iter_mut().find(|m| m.agent_id == agent_id)
            && member.role != role
        {
            member.role = role;
            changed = true;
        }
        if changed {
            save_registry(&rooms);
        }
    });
}

pub fn find_room(label_or_id: &str) -> Option<RoomEntry> {
    load_registry()
        .into_iter()
        .find(|r| r.label == label_or_id || r.room_id == label_or_id)
}

fn active_room_paths() -> (PathBuf, PathBuf) {
    (agent_dir().join("active_room"), agora_dir().join("active_room"))
}

/// The current agent's active room (its own choice; before it made one, the host-wide one older
/// versions shared; else the first room).
pub fn get_active_room() -> Option<RoomEntry> {
    if let Some(label) = read_own_or_legacy(&active_room_paths())
        && let Some(room) = find_room(label.trim())
    {
        return Some(room);
    }
    load_registry().into_iter().next()
}

pub fn set_active_room(label: &str) {
    write_own(&active_room_paths().0, label);
}

pub fn remove_room(label_or_id: &str) -> Option<RoomEntry> {
    let mut rooms = load_registry();
    let idx = rooms
        .iter()
        .position(|r| r.label == label_or_id || r.room_id == label_or_id)?;
    let removed = rooms.remove(idx);
    save_registry(&rooms);

    let room_dir = agora_dir().join("rooms").join(&removed.room_id);
    if room_dir.exists() {
        let _ = fs::remove_dir_all(&room_dir);
    }

    if let Some(active) = read_own_or_legacy(&active_room_paths()) {
        let active = active.trim();
        if active == removed.label || active == removed.room_id {
            match rooms.first() {
                Some(next) => set_active_room(&next.label),
                None => {
                    let _ = fs::remove_file(active_room_paths().0);
                }
            }
        }
    }

    Some(removed)
}

// ── Message Persistence ─────────────────────────────────────────

pub fn save_message(room_id: &str, envelope: &serde_json::Value) {
    let dir = agora_dir().join("rooms").join(room_id).join("messages");
    ensure_dir(&dir);
    let ts = envelope["ts"].as_u64().unwrap_or_else(now);
    let mid = envelope["id"].as_str().unwrap_or("x");
    let path = dir.join(format!("{ts}_{mid}.json"));
    let _ = atomic_write_bytes(&path, serde_json::to_string(envelope).unwrap().as_bytes());
}

pub fn delete_message(room_id: &str, msg_id: &str) {
    let dir = agora_dir().join("rooms").join(room_id).join("messages");
    if !dir.exists() {
        return;
    }
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.contains(msg_id) {
                let _ = fs::remove_file(entry.path());
                return;
            }
        }
    }
}

pub fn load_messages(room_id: &str, since_secs: u64) -> Vec<serde_json::Value> {
    let dir = agora_dir().join("rooms").join(room_id).join("messages");
    if !dir.exists() {
        return vec![];
    }
    let cutoff = now().saturating_sub(since_secs);
    let mut msgs = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            if let Ok(data) = fs::read_to_string(entry.path())
                && let Ok(env) = serde_json::from_str::<serde_json::Value>(&data)
                && env["ts"].as_u64().unwrap_or(0) >= cutoff
            {
                msgs.push(env);
            }
        }
    }
    msgs.sort_by_key(|m| m["ts"].as_u64().unwrap_or(0));
    msgs
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReadCursor {
    pub ts: u64,
    pub id: String,
}

pub fn load_read_cursor(room_id: &str) -> Option<ReadCursor> {
    let data = read_own_or_legacy(&reader_file(room_id, "read_cursor.json"))?;
    serde_json::from_str(&data).ok()
}

/// Save the current agent's read mark in a room (other agents keep theirs).
pub fn save_read_cursor(room_id: &str, cursor: &ReadCursor) {
    let data = serde_json::to_string(cursor).unwrap();
    write_own(&reader_file(room_id, "read_cursor.json").0, &data);
}

fn cursor_from_message(message: &serde_json::Value) -> Option<ReadCursor> {
    Some(ReadCursor {
        ts: message["ts"].as_u64()?,
        id: message["id"].as_str().unwrap_or("").to_string(),
    })
}

pub fn mark_room_read(room_id: &str, messages: &[serde_json::Value]) -> Option<ReadCursor> {
    let latest = messages.iter().filter_map(cursor_from_message).max()?;
    if load_read_cursor(room_id)
        .as_ref()
        .is_none_or(|cursor| &latest > cursor)
    {
        save_read_cursor(room_id, &latest);
    }
    Some(latest)
}

pub fn notify_flag_path(room_id: &str) -> PathBuf {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    dir.join("notify.flag")
}

pub fn pins_path(room_id: &str) -> PathBuf {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    dir.join("pins.json")
}

pub fn load_pins(room_id: &str) -> Vec<String> {
    let path = pins_path(room_id);
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        Vec::new()
    }
}

pub fn save_pins(room_id: &str, pins: &[String]) {
    let path = pins_path(room_id);
    let _ = atomic_write(&path, &serde_json::to_string_pretty(pins).unwrap());
}

pub fn add_pin(room_id: &str, message_id: &str) -> bool {
    let path = pins_path(room_id);
    with_file_lock(&path, || {
        let mut pins = load_pins(room_id);
        if pins.iter().any(|id| id == message_id) {
            return false;
        }
        pins.push(message_id.to_string());
        save_pins(room_id, &pins);
        true
    })
}

pub fn remove_pin(room_id: &str, message_id: &str) -> bool {
    let path = pins_path(room_id);
    with_file_lock(&path, || {
        let mut pins = load_pins(room_id);
        let before = pins.len();
        pins.retain(|id| id != message_id);
        if pins.len() == before {
            return false;
        }
        save_pins(room_id, &pins);
        true
    })
}

// ── Agent Profiles ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentProfile {
    pub agent_id: String,
    pub name: Option<String>,
    pub role: Option<String>,
    pub updated_at: u64,
}

pub fn load_profiles(room_id: &str) -> Vec<AgentProfile> {
    let path = agora_dir()
        .join("rooms")
        .join(room_id)
        .join("profiles.json");
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        Vec::new()
    }
}

pub fn save_profiles(room_id: &str, profiles: &[AgentProfile]) {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    let path = dir.join("profiles.json");
    let data = serde_json::to_string_pretty(profiles).unwrap();
    with_file_lock(&path, || {
        let _ = atomic_write(&path, &data);
    });
}

pub fn upsert_profile(room_id: &str, profile: &AgentProfile) {
    let mut profiles = load_profiles(room_id);
    if let Some(p) = profiles.iter_mut().find(|p| p.agent_id == profile.agent_id) {
        *p = profile.clone();
    } else {
        profiles.push(profile.clone());
    }
    save_profiles(room_id, &profiles);
}

pub fn get_profile(room_id: &str, agent_id: &str) -> Option<AgentProfile> {
    load_profiles(room_id)
        .into_iter()
        .find(|p| p.agent_id == agent_id)
}

// ── Muted Agents ──────────────────────────────────────────────

pub fn load_muted(room_id: &str) -> HashSet<String> {
    let path = agora_dir().join("rooms").join(room_id).join("muted.json");
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        HashSet::new()
    }
}

pub fn save_muted(room_id: &str, muted: &HashSet<String>) {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    let data = serde_json::to_string(&muted).unwrap();
    let _ = atomic_write(&dir.join("muted.json"), &data);
}

pub fn mute_agent(room_id: &str, agent_id: &str) {
    let mut muted = load_muted(room_id);
    muted.insert(agent_id.to_string());
    save_muted(room_id, &muted);
}

pub fn unmute_agent(room_id: &str, agent_id: &str) {
    let mut muted = load_muted(room_id);
    muted.remove(agent_id);
    save_muted(room_id, &muted);
}

// ── Read Receipts ──────────────────────────────────────────────
// receipts.json: { "msg_id": ["agent1", "agent2"], ... }

pub fn load_receipts(room_id: &str) -> std::collections::HashMap<String, Vec<String>> {
    let path = agora_dir()
        .join("rooms")
        .join(room_id)
        .join("receipts.json");
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        std::collections::HashMap::new()
    }
}

pub fn save_receipts(room_id: &str, receipts: &std::collections::HashMap<String, Vec<String>>) {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    let data = serde_json::to_string(receipts).unwrap();
    let _ = atomic_write(&dir.join("receipts.json"), &data);
}

pub fn record_receipts(room_id: &str, msg_ids: &[String], reader: &str) {
    let mut receipts = load_receipts(room_id);
    for mid in msg_ids {
        let readers = receipts.entry(mid.clone()).or_default();
        if !readers.contains(&reader.to_string()) {
            readers.push(reader.to_string());
        }
    }
    save_receipts(room_id, &receipts);
}

// ── Reactions ──────────────────────────────────────────────────
// reactions.json: { "msg_id": [["agent", "emoji"], ...] }

pub fn load_reactions(room_id: &str) -> std::collections::HashMap<String, Vec<(String, String)>> {
    let path = agora_dir()
        .join("rooms")
        .join(room_id)
        .join("reactions.json");
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        std::collections::HashMap::new()
    }
}

pub fn save_reactions(
    room_id: &str,
    reactions: &std::collections::HashMap<String, Vec<(String, String)>>,
) {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    let path = dir.join("reactions.json");
    let data = serde_json::to_string(reactions).unwrap();
    with_file_lock(&path, || {
        let _ = atomic_write(&path, &data);
    });
}

pub fn add_reaction(room_id: &str, msg_id: &str, agent: &str, emoji: &str) {
    let mut reactions = load_reactions(room_id);
    let entries = reactions.entry(msg_id.to_string()).or_default();
    let pair = (agent.to_string(), emoji.to_string());
    if !entries.contains(&pair) {
        entries.push(pair);
    }
    save_reactions(room_id, &reactions);
}

pub fn daemon_pid_path(room_id: &str) -> PathBuf {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    dir.join("daemon.pid")
}

pub fn set_notify_flag(room_id: &str, envelope: &serde_json::Value) {
    let path = notify_flag_path(room_id);
    let mid = envelope["id"].as_str().unwrap_or("?");
    let ts = envelope["ts"].as_u64().unwrap_or_else(now);
    let payload = format!("{ts}\t{mid}\n");
    let _ = atomic_write(&path, &payload);
}

/// Whether the daemon flagged a message the current agent has not taken yet. The flag file is
/// shared (one daemon per room); each agent records the flag it last took, so one agent taking it
/// does not hide it from the others.
pub fn take_notify_flag(room_id: &str) -> bool {
    let Ok(flag) = fs::read_to_string(notify_flag_path(room_id)) else {
        return false;
    };
    let taken = reader_file(room_id, "notify.taken").0;
    if fs::read_to_string(&taken).is_ok_and(|t| t == flag) {
        return false;
    }
    write_own(&taken, &flag);
    true
}

// ── Capability Cards ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityCard {
    pub agent_id: String,
    pub capabilities: Vec<String>,
    pub available: bool,
    pub description: Option<String>,
    pub updated_at: u64,
}

pub fn save_card(card: &CapabilityCard) {
    let dir = agora_dir();
    ensure_dir(&dir);
    let data = serde_json::to_string_pretty(card).unwrap();
    let _ = atomic_write(&dir.join("card.json"), &data);
}
pub fn load_card() -> Option<CapabilityCard> {
    let path = agora_dir().join("card.json");
    fs::read_to_string(&path)
        .ok()
        .and_then(|d| serde_json::from_str(&d).ok())
}

pub fn save_peer_card(room_id: &str, card: &CapabilityCard) {
    let dir = agora_dir().join("rooms").join(room_id).join("cards");
    ensure_dir(&dir);
    let data = serde_json::to_string_pretty(card).unwrap();
    let _ = atomic_write(&dir.join(format!("{}.json", card.agent_id)), &data);
}

pub fn load_peer_cards(room_id: &str) -> Vec<CapabilityCard> {
    let dir = agora_dir().join("rooms").join(room_id).join("cards");
    if !dir.exists() {
        return Vec::new();
    }
    let mut cards = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Ok(data) = fs::read_to_string(entry.path())
                && let Ok(card) = serde_json::from_str::<CapabilityCard>(&data)
            {
                cards.push(card);
            }
        }
    }
    cards
}

// ── Task Queue ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub title: String,
    pub status: String, // open, claimed, done
    pub created_by: String,
    pub claimed_by: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
    pub notes: Option<String>,
    /// The agent session that last checkpointed it from inside a harness (see `resume`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume: Option<crate::resume::Session>,
}

pub fn load_tasks(room_id: &str) -> Vec<Task> {
    let path = agora_dir().join("rooms").join(room_id).join("tasks.json");
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        Vec::new()
    }
}

pub fn save_tasks(room_id: &str, tasks: &[Task]) {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    let path = dir.join("tasks.json");
    let data = serde_json::to_string_pretty(tasks).unwrap();
    with_file_lock(&path, || {
        let _ = atomic_write(&path, &data);
    });
}

/// Read, change and write a room's tasks under one lock, so two agents updating different tasks of one
/// room at once do not lose either update. Returns what `f` returns.
pub fn update_tasks<T>(room_id: &str, f: impl FnOnce(&mut Vec<Task>) -> T) -> T {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    let path = dir.join("tasks.json");
    with_file_lock(&path, || {
        let mut tasks = load_tasks(room_id);
        let out = f(&mut tasks);
        let _ = atomic_write(&path, &serde_json::to_string_pretty(&tasks).unwrap());
        out
    })
}

// ── Work Receipts ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkReceipt {
    pub id: String,
    pub task_id: String,
    pub task_title: String,
    pub agent_id: String,
    #[serde(default = "default_receipt_status")]
    pub status: String,
    #[serde(default)]
    pub notes: Option<String>,
    pub task_hash: String,
    #[serde(default)]
    pub witness_ids: Vec<String>,
    pub created_at: u64,
    #[serde(default = "default_receipt_auth")]
    pub auth: String,
}

fn default_receipt_auth() -> String {
    "unsigned".to_string()
}

fn default_receipt_status() -> String {
    "done".to_string()
}

pub fn load_work_receipts(room_id: &str) -> Vec<WorkReceipt> {
    let path = agora_dir()
        .join("rooms")
        .join(room_id)
        .join("work_receipts.json");
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        Vec::new()
    }
}

pub fn save_work_receipts(room_id: &str, receipts: &[WorkReceipt]) {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    let data = serde_json::to_string_pretty(receipts).unwrap();
    let _ = atomic_write(&dir.join("work_receipts.json"), &data);
}

pub fn upsert_work_receipt(room_id: &str, receipt: &WorkReceipt) {
    let mut receipts = load_work_receipts(room_id);
    if let Some(existing) = receipts.iter_mut().find(|r| r.id == receipt.id) {
        *existing = receipt.clone();
    } else {
        receipts.push(receipt.clone());
    }
    receipts.sort_by_key(|a| a.created_at);
    save_work_receipts(room_id, &receipts);
}

// ── Role Leases ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleLease {
    pub role: String,
    pub agent_id: String,
    pub lease_expires: u64,
    pub last_heartbeat: u64,
    #[serde(default)]
    pub context_summary: Option<String>,
    #[serde(default)]
    pub last_task_ids: Vec<String>,
    pub updated_at: u64,
}

pub fn load_role_leases(room_id: &str) -> Vec<RoleLease> {
    let path = agora_dir()
        .join("rooms")
        .join(room_id)
        .join("role_leases.json");
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        Vec::new()
    }
}

pub fn save_role_leases(room_id: &str, roles: &[RoleLease]) {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    let path = dir.join("role_leases.json");
    let data = serde_json::to_string_pretty(roles).unwrap();
    with_file_lock(&path, || {
        let _ = atomic_write(&path, &data);
    });
}

pub fn upsert_role_lease(room_id: &str, lease: &RoleLease) {
    let mut roles = load_role_leases(room_id);
    if let Some(existing) = roles.iter_mut().find(|r| r.role == lease.role) {
        *existing = lease.clone();
    } else {
        roles.push(lease.clone());
    }
    roles.sort_by(|a, b| a.role.cmp(&b.role));
    save_role_leases(room_id, &roles);
}

pub fn remove_role_lease(room_id: &str, role: &str) {
    let mut roles = load_role_leases(room_id);
    let before = roles.len();
    roles.retain(|r| r.role != role);
    if roles.len() != before {
        save_role_leases(room_id, &roles);
    }
}

pub fn get_role_lease(room_id: &str, role: &str) -> Option<RoleLease> {
    load_role_leases(room_id)
        .into_iter()
        .find(|lease| lease.role == role)
}

// ── Aliases ────────────────────────────────────────────────────
// Global agent aliases, stored at ~/.agora/aliases.json

pub fn load_aliases() -> std::collections::HashMap<String, String> {
    let path = agora_dir().join("aliases.json");
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        std::collections::HashMap::new()
    }
}

pub fn save_aliases(aliases: &std::collections::HashMap<String, String>) {
    let dir = agora_dir();
    ensure_dir(&dir);
    let path = dir.join("aliases.json");
    let data = serde_json::to_string_pretty(aliases).unwrap();
    with_file_lock(&path, || {
        let _ = atomic_write(&path, &data);
    });
}

pub fn set_alias(agent_id: &str, name: &str) {
    let mut aliases = load_aliases();
    aliases.insert(agent_id.to_string(), name.to_string());
    save_aliases(&aliases);
}

pub fn remove_alias(agent_id: &str) {
    let mut aliases = load_aliases();
    aliases.remove(agent_id);
    save_aliases(&aliases);
}

pub fn get_alias(agent_id: &str) -> Option<String> {
    load_aliases().get(agent_id).cloned()
}

// ── Webhooks ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Webhook {
    pub id: String,
    pub url: String,
    pub created_at: u64,
}

pub fn load_webhooks(room_id: &str) -> Vec<Webhook> {
    let path = agora_dir()
        .join("rooms")
        .join(room_id)
        .join("webhooks.json");
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        Vec::new()
    }
}

pub fn save_webhooks(room_id: &str, hooks: &[Webhook]) {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    let path = dir.join("webhooks.json");
    let data = serde_json::to_string_pretty(hooks).unwrap();
    with_file_lock(&path, || {
        let _ = atomic_write(&path, &data);
    });
}

pub fn add_webhook(room_id: &str, url: &str) -> String {
    let mut hooks = load_webhooks(room_id);
    let mut id_bytes = [0u8; 4];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut id_bytes).expect("RNG");
    let id = hex::encode(id_bytes);
    hooks.push(Webhook {
        id: id.clone(),
        url: url.to_string(),
        created_at: now(),
    });
    save_webhooks(room_id, &hooks);
    id
}

pub fn remove_webhook(room_id: &str, webhook_id: &str) -> bool {
    let mut hooks = load_webhooks(room_id);
    let before = hooks.len();
    hooks.retain(|h| h.id != webhook_id);
    if hooks.len() == before {
        return false;
    }
    save_webhooks(room_id, &hooks);
    true
}

// ── Scheduled Messages ─────────────────────────────────────────

pub fn load_scheduled(room_id: &str) -> Vec<serde_json::Value> {
    let path = agora_dir()
        .join("rooms")
        .join(room_id)
        .join("scheduled.json");
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        Vec::new()
    }
}

pub fn save_scheduled(room_id: &str, queue: &[serde_json::Value]) {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    let data = serde_json::to_string_pretty(queue).unwrap();
    let _ = atomic_write(&dir.join("scheduled.json"), &data);
}

pub fn archive_path(room_id: &str) -> PathBuf {
    let dir = agora_dir().join("rooms").join(room_id);
    ensure_dir(&dir);
    dir.join("archive.jsonl")
}

pub fn delete_messages_before(room_id: &str, before_ts: u64) {
    let dir = agora_dir().join("rooms").join(room_id).join("messages");
    if !dir.exists() {
        return;
    }
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let fname = entry.file_name().to_string_lossy().to_string();
            // Files are named: <ts>_<mid>.json
            if let Some(ts_str) = fname.split('_').next()
                && let Ok(ts) = ts_str.parse::<u64>()
                && ts < before_ts
            {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}

// ── Seen Tracking ───────────────────────────────────────────────

/// Ids the current agent's `check`/`notify` already handled in a room.
pub fn load_seen(room_id: &str) -> HashSet<String> {
    read_own_or_legacy(&reader_file(room_id, "seen.txt"))
        .map(|data| data.lines().map(|s| s.to_string()).collect())
        .unwrap_or_default()
}

/// Ids kept in an agent's seen list per room, oldest dropped first.
pub const SEEN_CAP: usize = 1000;

/// Record `msg_id` as seen by the current agent. Keeps insertion order and drops the oldest ids past
/// [`SEEN_CAP`] (sorting and keeping the largest, as before, dropped random newer ids and `check
/// --wake` delivered them again; same fix as seen-order-fix a4d80c3). Read-modify-write under a lock.
pub fn mark_seen(room_id: &str, msg_id: &str) {
    let files = reader_file(room_id, "seen.txt");
    if let Some(dir) = files.0.parent() {
        ensure_dir(&dir.to_path_buf());
    }
    with_file_lock(&files.0, || {
        let mut ids: Vec<String> = read_own_or_legacy(&files).map(|d| d.lines().map(str::to_string).collect()).unwrap_or_default();
        if ids.iter().any(|id| id == msg_id) {
            return;
        }
        ids.push(msg_id.to_string());
        if ids.len() > SEEN_CAP {
            ids.drain(..ids.len() - SEEN_CAP);
        }
        let _ = atomic_write(&files.0, &ids.join("\n"));
    })
}

// ── Delivered Ledger ───────────────────────────────────────────
// Ids of messages already put in front of one agent's session, by the MCP
// channel push or by the `check --wake` hook, so the other path skips them.
// Unlike seen.txt (shared by every agent on the host), it is per agent.

/// Entries kept per (room, agent) ledger, oldest dropped first.
pub const DELIVERED_LEDGER_CAP: usize = 2000;

fn delivered_path(room_id: &str, agent_id: &str) -> PathBuf {
    let dir = agora_dir().join("rooms").join(room_id).join("delivered");
    let path = dir.join(format!("{}.txt", agent_key(agent_id)));
    let legacy = legacy_agent_key(agent_id);
    if legacy != agent_key(agent_id) {
        seed_from(&dir.join(format!("{legacy}.txt")), &path);
    }
    path
}

/// Ids already delivered to `agent_id`'s session in this room.
pub fn load_delivered(room_id: &str, agent_id: &str) -> HashSet<String> {
    fs::read_to_string(delivered_path(room_id, agent_id))
        .map(|data| data.lines().map(str::to_string).collect())
        .unwrap_or_default()
}

/// Record `ids` as delivered to `agent_id` and return the ones that were not
/// already recorded, in input order. The check and the write happen under one
/// file lock, so two delivery paths racing on one id see exactly one winner.
pub fn claim_delivered(room_id: &str, agent_id: &str, ids: &[String]) -> Vec<String> {
    let path = delivered_path(room_id, agent_id);
    if let Some(parent) = path.parent() {
        ensure_dir(&parent.to_path_buf());
    }
    with_file_lock(&path, || {
        let mut lines: Vec<String> = fs::read_to_string(&path)
            .map(|data| data.lines().map(str::to_string).collect())
            .unwrap_or_default();
        let mut known: HashSet<String> = lines.iter().cloned().collect();
        let mut fresh = Vec::new();
        for id in ids {
            if id.is_empty() || id == "?" || !known.insert(id.clone()) {
                continue;
            }
            lines.push(id.clone());
            fresh.push(id.clone());
        }
        if !fresh.is_empty() {
            if lines.len() > DELIVERED_LEDGER_CAP {
                lines.drain(..lines.len() - DELIVERED_LEDGER_CAP);
            }
            let _ = atomic_write(&path, &lines.join("\n"));
        }
        fresh
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::runtime;

    #[test]
    fn tmux_window_id_survives_renumbering() {
        let dir = std::env::temp_dir().join(format!("agora-pin-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(pin_tmux_window_id_in(&dir, "9931", "@31", "main-w7"), "main-w7");
        // Windows renumbered: @31 is now index 6, and a new window @40 takes index 7.
        assert_eq!(pin_tmux_window_id_in(&dir, "9931", "@31", "main-w6"), "main-w7");
        assert_eq!(pin_tmux_window_id_in(&dir, "9931", "@40", "main-w7"), "main-w7b");
        assert_eq!(pin_tmux_window_id_in(&dir, "9931", "@40", "main-w3"), "main-w7b");
        // Another server starts fresh.
        assert_eq!(pin_tmux_window_id_in(&dir, "1155", "@31", "main-w6"), "main-w6");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn tmux_window_id_trusts_only_our_own_server() {
        assert_eq!(tmux_server_pid("/tmp/tmux-1000/default,9931,0").as_deref(), Some("9931"));
        assert_eq!(tmux_server_pid("/tmp/tmux-1000/default,,0"), None);
        let w = |l: &str, id: &str| Some((l.to_string(), id.to_string()));
        assert_eq!(own_tmux_window("9931 main-w7 @31\n", "9931"), w("main-w7", "@31"));
        assert_eq!(own_tmux_window("9931 a-wb-w12 @2", "9931"), w("a-wb-w12", "@2"));
        // An orphaned server's pane id, resolved by the newer server: another window, or nothing.
        assert_eq!(own_tmux_window("9931 main-w1 @1", "1155"), None);
        assert_eq!(own_tmux_window("9931 -w @1", "9931"), None);
        assert_eq!(own_tmux_window("9931 main-w @1", "9931"), None);
        assert_eq!(own_tmux_window("9931 main-w7", "9931"), None);
        assert_eq!(own_tmux_window("9931 main-w7 31", "9931"), None);
        assert_eq!(own_tmux_window("", "9931"), None);
    }

    #[test]
    fn local_signing_key_check_never_leaves_the_key_dir() {
        assert!(!has_local_signing_key(""));
        assert!(!has_local_signing_key("../identity"));
        assert!(!has_local_signing_key("a/b"));
    }

    fn test_home(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("agora-store-{name}-{}", std::process::id()))
    }

    fn enter_test_home(name: &str) -> (runtime::TestRuntimeGuard, PathBuf, PathBuf) {
        let home = test_home(name);
        let agora = home.join(".agora");
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(&agora).unwrap();
        let runtime = runtime::TestRuntime::new().home(&home).enter();
        (runtime, home, agora)
    }

    #[test]
    fn update_last_seen_does_not_clobber_invalid_registry() {
        let (_runtime, home, agora) = enter_test_home("invalid-registry");
        fs::write(agora.join("rooms.json"), "{not-json").unwrap();

        update_last_seen("missing-room", "agent-1");

        let persisted = fs::read_to_string(agora.join("rooms.json")).unwrap();
        assert_eq!(persisted, "{not-json");
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn save_registry_persists_valid_json() {
        let (_runtime, home, agora) = enter_test_home("atomic-save");

        let room = RoomEntry {
            room_id: "room-1".to_string(),
            secret: "secret".to_string(),
            label: "plaza".to_string(),
            joined_at: 1,
            topic: None,
            purpose: None,
            dm_peer: None,
            members: vec![],
        };
        save_registry(&[room]);

        let persisted = fs::read_to_string(agora.join("rooms.json")).unwrap();
        let parsed: Vec<RoomEntry> = serde_json::from_str(&persisted).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].label, "plaza");
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn mark_dm_room_persists_metadata() {
        let (_runtime, home, _agora) = enter_test_home("mark-dm-room");

        add_room("ag-dm-1", "secret", "dm-agent-a-agent-b", Role::Admin);
        let room = mark_dm_room("ag-dm-1", "agent-b").unwrap();
        assert_eq!(room.purpose.as_deref(), Some("dm"));
        assert_eq!(room.dm_peer, None, "a canonical label names both sides: nothing side-specific is stored");
        let persisted = find_room("ag-dm-1").unwrap();
        assert_eq!(persisted.purpose.as_deref(), Some("dm"));
        assert_eq!(room_dm_peer(&persisted, "agent-a").as_deref(), Some("agent-b"));
        assert_eq!(room_dm_peer(&persisted, "agent-b").as_deref(), Some("agent-a"));
        assert_eq!(room_dm_peer(&persisted, "agent-c"), None, "someone else's DM");

        add_room("ag-dm-2", "secret", "old-style-dm", Role::Admin);
        let legacy = mark_dm_room("ag-dm-2", "agent-z").unwrap();
        assert_eq!(room_dm_peer(&legacy, "agent-a").as_deref(), Some("agent-z"), "a non-canonical label keeps its stored peer");
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn legacy_dm_labels_keep_their_stored_peer() {
        let dm_legacy = room("dm-legacy", Some("bob"), Some("dm"));
        assert_eq!(room_dm_peer(&dm_legacy, "alice").as_deref(), Some("bob"), "a dm- label that is not canonical keeps its peer");
        let others = room("dm-alice-carol", Some("carol"), Some("dm"));
        assert_eq!(room_dm_peer(&others, "bob"), None, "a canonical label naming others is someone else's DM");
    }

    #[test]
    fn agent_state_names_are_one_per_id() {
        let ids = ["a/b", "a_b", "a:b", ".a", "a", "", "%2F", "agent-c@host-a", "a.b"];
        let keys: HashSet<String> = ids.iter().map(|i| agent_key(i)).collect();
        assert_eq!(keys.len(), ids.len(), "{keys:?}");
        assert_eq!(agent_key("agent-c@host-a"), "agent-c@host-a", "ordinary ids keep their name");
        assert!(keys.iter().all(|k| !k.starts_with('.') && !k.contains('/')));
    }

    fn room(label: &str, dm_peer: Option<&str>, purpose: Option<&str>) -> RoomEntry {
        RoomEntry {
            room_id: format!("ag-{label}"),
            secret: "s".into(),
            label: label.into(),
            joined_at: 1,
            topic: None,
            purpose: purpose.map(Into::into),
            dm_peer: dm_peer.map(Into::into),
            members: vec![],
        }
    }

    #[test]
    fn migration_drops_the_creator_side_peer_of_canonical_dms_only() {
        let mut rooms = vec![
            room("dm-agent-a-agent-b", Some("agent-b"), Some("dm")), // created by agent-a: the bug
            // the label is the two ids in sorted order: keep host-a-main-w7 < worker-c@host-a when renaming
            room("dm-host-a-main-w7-worker-c@host-a", Some("host-a-main-w7"), Some("dm")),
            room("dm-agent-a-agent-c", None, None),
            room("dm-legacy", Some("bob"), Some("dm")),
            room("ops", None, None),
        ];
        assert!(migrate_rooms(&mut rooms));
        let got: Vec<(Option<&str>, Option<&str>)> = rooms.iter().map(|r| (r.dm_peer.as_deref(), r.purpose.as_deref())).collect();
        assert_eq!(got, [(None, Some("dm")), (None, Some("dm")), (None, Some("dm")), (Some("bob"), Some("dm")), (None, None)]);
        assert!(!migrate_rooms(&mut rooms), "a migrated registry is left alone");
    }

    #[test]
    fn migrate_registry_runs_once_per_host() {
        let (_runtime, home, agora) = enter_test_home("migrate-registry");
        save_registry(&[room("dm-agent-a-agent-b", Some("agent-b"), Some("dm"))]);
        migrate_registry();
        assert_eq!(fs::read_to_string(agora.join("registry_version")).unwrap(), REGISTRY_VERSION.to_string());
        assert_eq!(find_room("dm-agent-a-agent-b").unwrap().dm_peer, None);
        // an old binary writes the creator side again: the per-reader peer is still right, and the
        // migration does not run twice
        save_registry(&[room("dm-agent-a-agent-b", Some("agent-b"), Some("dm"))]);
        migrate_registry();
        let r = find_room("dm-agent-a-agent-b").unwrap();
        assert_eq!(r.dm_peer.as_deref(), Some("agent-b"));
        assert_eq!(room_dm_peer(&r, "agent-b").as_deref(), Some("agent-a"));
        let _ = fs::remove_dir_all(&home);
    }

    fn as_agent(home: &Path, id: &str) -> runtime::TestRuntimeGuard {
        runtime::TestRuntime::new().home(home).var("AGORA_AGENT_ID", id).enter()
    }

    #[test]
    fn agents_sharing_a_home_keep_their_own_read_marks_seen_ids_and_active_room() {
        let (_runtime, home, agora) = enter_test_home("per-agent-state");
        // what an older agora left: one read mark, one seen list and one active room for everybody
        fs::create_dir_all(agora.join("rooms/ag-ops")).unwrap();
        fs::write(agora.join("rooms/ag-ops/read_cursor.json"), r#"{"ts":10,"id":"m10"}"#).unwrap();
        fs::write(agora.join("rooms/ag-ops/seen.txt"), "m10").unwrap();
        fs::write(agora.join("active_room"), "ops").unwrap();
        {
            let _a = as_agent(&home, "agent-a");
            add_room("ag-ops", "s", "ops", Role::Admin);
            add_room("ag-dev", "s", "dev", Role::Admin);
            assert_eq!(load_read_cursor("ag-ops").map(|c| c.ts), Some(10), "upgrading marks nothing unread");
            assert!(load_seen("ag-ops").contains("m10"));
            save_read_cursor("ag-ops", &ReadCursor { ts: 20, id: "m20".into() });
            mark_seen("ag-ops", "m20");
            set_active_room("dev");
        }
        {
            let _b = as_agent(&home, "agent-b");
            assert_eq!(load_read_cursor("ag-ops").map(|c| c.ts), Some(10), "agent-a's read mark is agent-a's");
            let seen = load_seen("ag-ops");
            assert!(seen.contains("m10") && !seen.contains("m20"));
            assert_eq!(get_active_room().unwrap().label, "ops");
            mark_seen("ag-ops", "m30");
        }
        let _a = as_agent(&home, "agent-a");
        assert_eq!(load_read_cursor("ag-ops").map(|c| c.ts), Some(20));
        assert!(!load_seen("ag-ops").contains("m30"));
        assert_eq!(get_active_room().unwrap().label, "dev");
        assert_eq!(fs::read_to_string(agora.join("rooms/ag-ops/read_cursor.json")).unwrap(), r#"{"ts":10,"id":"m10"}"#, "the shared file is never rewritten");
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn one_agent_taking_the_daemon_flag_does_not_hide_it_from_the_others() {
        let (_runtime, home, _agora) = enter_test_home("notify-flag");
        set_notify_flag("ag-ops", &serde_json::json!({"id": "m1", "ts": 5}));
        {
            let _a = as_agent(&home, "agent-a");
            assert!(take_notify_flag("ag-ops"));
            assert!(!take_notify_flag("ag-ops"), "taken once per agent");
        }
        {
            let _b = as_agent(&home, "agent-b");
            assert!(take_notify_flag("ag-ops"), "agent-b still sees it");
        }
        set_notify_flag("ag-ops", &serde_json::json!({"id": "m2", "ts": 6}));
        let _a = as_agent(&home, "agent-a");
        assert!(take_notify_flag("ag-ops"), "a new message flags again");
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn mark_seen_drops_the_oldest_ids_not_the_lowest() {
        let (_runtime, home, _agora) = enter_test_home("seen-cap");
        let _a = as_agent(&home, "agent-a");
        // ids that sort down as they get newer: the newest sorts lowest
        let ids: Vec<String> = (0..=SEEN_CAP).map(|i| format!("{:05}", 90_000 - i)).collect();
        for id in &ids {
            mark_seen("ag-seen", id);
        }
        mark_seen("ag-seen", &ids[SEEN_CAP]);
        let seen = load_seen("ag-seen");
        assert_eq!(seen.len(), SEEN_CAP);
        assert!(seen.contains(&ids[SEEN_CAP]) && !seen.contains(&ids[0]), "the oldest goes, the newest stays");
        let on_disk = fs::read_to_string(agent_dir().join("rooms/ag-seen/seen.txt")).unwrap();
        assert_eq!(on_disk.lines().last(), Some(ids[SEEN_CAP].as_str()), "insertion order, in agent-a's own file");
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn a_second_agent_joining_a_shared_room_becomes_a_member() {
        let (_runtime, home, _agora) = enter_test_home("shared-join");
        {
            let _a = as_agent(&home, "agent-a");
            add_room("ag-ops", "s", "ops", Role::Admin);
        }
        let _b = as_agent(&home, "agent-b");
        let r = add_room("ag-ops", "s", "ops", Role::Member);
        let members: Vec<(&str, &Role)> = r.members.iter().map(|m| (m.agent_id.as_str(), &m.role)).collect();
        assert_eq!(members, [("agent-a", &Role::Admin), ("agent-b", &Role::Member)]);
        assert_eq!(add_room("ag-ops", "s", "ops", Role::Member).members.len(), 2, "joining again changes nothing");
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn mark_room_read_persists_latest_cursor_and_never_rewinds() {
        let (_runtime, home, _agora) = enter_test_home("read-cursor");

        let first = serde_json::json!({
            "id": "m1",
            "ts": 10,
            "from": "peer",
            "text": "first",
        });
        let second = serde_json::json!({
            "id": "m2",
            "ts": 12,
            "from": "peer",
            "text": "second",
        });
        let older = serde_json::json!({
            "id": "m0",
            "ts": 8,
            "from": "peer",
            "text": "older",
        });

        let latest = mark_room_read("ag-room", &[first.clone(), second.clone()]).unwrap();
        assert_eq!(
            latest,
            ReadCursor {
                ts: 12,
                id: "m2".to_string()
            }
        );
        assert_eq!(load_read_cursor("ag-room"), Some(latest.clone()));

        mark_room_read("ag-room", &[older]).unwrap();
        assert_eq!(load_read_cursor("ag-room"), Some(latest));
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn load_messages_ignores_transient_tmp_files() {
        let (_runtime, home, agora) = enter_test_home("load-messages-tmp");
        let dir = agora.join("rooms").join("ag-room").join("messages");
        fs::create_dir_all(&dir).unwrap();

        fs::write(
            dir.join("10_good.json"),
            serde_json::json!({
                "id": "good",
                "ts": 10,
                "from": "peer",
                "text": "ok",
            })
            .to_string(),
        )
        .unwrap();
        fs::write(dir.join(".10_race.json.123.1.tmp"), "{\"id\":").unwrap();

        let msgs = load_messages("ag-room", u64::MAX);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0]["id"].as_str(), Some("good"));
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn signing_pubkeys_match_across_base64_alphabets() {
        let bytes = [0xfb, 0xef, 0xff];
        let standard = STANDARD.encode(bytes);
        let url_safe = URL_SAFE_NO_PAD.encode(bytes);

        assert_ne!(standard, url_safe);
        assert!(signing_pubkeys_match(&standard, &url_safe));
        assert_eq!(canonicalize_signing_pubkey(&url_safe), standard);
    }

    #[test]
    fn concurrent_update_room_no_lost_update() {
        let (_runtime, home, _agora) = enter_test_home("concurrent-update-room");

        // Seed a room with a single member (the "owner").
        add_room("race-room", "secret", "race", Role::Admin);

        // Two threads each add a distinct member to the same room by
        // calling update_last_seen (load→mutate→save on rooms.json).
        // Without the flock, one update can clobber the other; with it,
        // both members must be present in the final registry.
        let h1 = runtime::spawn_with_current(|| {
            update_last_seen("race-room", "agent-a");
        });
        let h2 = runtime::spawn_with_current(|| {
            update_last_seen("race-room", "agent-b");
        });
        h1.join().expect("thread-1 panicked");
        h2.join().expect("thread-2 panicked");

        let rooms = load_registry();
        let saved = rooms.iter().find(|r| r.room_id == "race-room").unwrap();
        let has_a = saved.members.iter().any(|m| m.agent_id == "agent-a");
        let has_b = saved.members.iter().any(|m| m.agent_id == "agent-b");
        assert!(has_a, "agent-a lost in concurrent update");
        assert!(has_b, "agent-b lost in concurrent update");
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn file_lock_acquires_and_releases() {
        let (_runtime, home, _agora) = enter_test_home("file-lock-basic");

        let path = registry_path();
        // First lock acquires immediately.
        let lock1 = FileLock::try_acquire(&path);
        assert!(lock1.acquired(), "first lock should acquire");
        // Second lock on the same file in the same process should fail
        // (flock is per-open-file-description, not recursive).
        let lock2 = FileLock::try_acquire(&path);
        assert!(!lock2.acquired(), "second lock should be contended");
        // Releasing lock1 allows a new lock.
        drop(lock1);
        let lock3 = FileLock::try_acquire(&path);
        assert!(lock3.acquired(), "lock should acquire after release");
        drop(lock2);
        drop(lock3);
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn with_file_lock_runs_closure() {
        let (_runtime, home, _agora) = enter_test_home("with-file-lock");

        let path = registry_path();
        let result = with_file_lock(&path, || 42);
        assert_eq!(result, 42);
        let _ = fs::remove_dir_all(&home);
    }
}
