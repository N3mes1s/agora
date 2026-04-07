//! Sandbox lease enforcement — SQLite-backed, atomic, heartbeat-gated.
//!
//! A lease is created when an agent opens a sandbox. It tracks accumulated
//! debt, enforces a ceiling, and detects stale sessions via heartbeat.

use ring::rand::SecureRandom;
use rusqlite::{Connection, OptionalExtension, params};
use std::time::{SystemTime, UNIX_EPOCH};

fn random_id(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    ring::rand::SystemRandom::new()
        .fill(&mut buf)
        .expect("rng");
    hex::encode(&buf)
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn db_path() -> std::path::PathBuf {
    crate::store::agora_dir().join("leases.db")
}

fn open_db() -> rusqlite::Result<Connection> {
    let conn = Connection::open(db_path())?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS leases (
            id               TEXT PRIMARY KEY,
            agent_id         TEXT NOT NULL,
            room_id          TEXT NOT NULL,
            status           TEXT NOT NULL CHECK(status IN ('open','closed','suspended')),
            max_cost         INTEGER NOT NULL,
            current_debt     INTEGER NOT NULL DEFAULT 0,
            credits_per_min  INTEGER NOT NULL DEFAULT 0,
            last_heartbeat   INTEGER NOT NULL,
            created_at       INTEGER NOT NULL,
            expires_at       INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tool_rates (
            lease_id  TEXT NOT NULL REFERENCES leases(id),
            tool_name TEXT NOT NULL,
            cost      INTEGER NOT NULL,
            PRIMARY KEY (lease_id, tool_name)
        );",
    )?;
    Ok(conn)
}

#[derive(Debug, Clone)]
pub struct Lease {
    pub id: String,
    pub agent_id: String,
    pub room_id: String,
    pub status: String,
    pub max_cost: i64,
    pub current_debt: i64,
    pub credits_per_min: i64,
    pub last_heartbeat: i64,
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Debug)]
pub enum LeaseError {
    DebtCeiling { current: i64, max: i64 },
    NotFound(String),
    Suspended(String),
    AlreadyClosed(String),
    Db(rusqlite::Error),
}

impl std::fmt::Display for LeaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LeaseError::DebtCeiling { current, max } =>
                write!(f, "debt ceiling: {current}/{max} credits"),
            LeaseError::NotFound(id) => write!(f, "lease not found: {id}"),
            LeaseError::Suspended(id) => write!(f, "lease suspended, submit receipts to drain debt: {id}"),
            LeaseError::AlreadyClosed(id) => write!(f, "lease already closed: {id}"),
            LeaseError::Db(e) => write!(f, "db error: {e}"),
        }
    }
}

impl From<rusqlite::Error> for LeaseError {
    fn from(e: rusqlite::Error) -> Self { LeaseError::Db(e) }
}

/// Open a new lease. Fails if agent already has an open lease for this room,
/// or if the agent's current_debt from any prior open lease hits the ceiling.
pub fn open_lease(
    agent_id: &str,
    room_id: &str,
    max_cost: i64,
    credits_per_min: i64,
    duration_secs: i64,
    tool_rates: &[(&str, i64)],
) -> Result<Lease, LeaseError> {
    let conn = open_db()?;
    let ts = now_secs();

    // Check for existing open lease for this agent+room
    let existing: Option<String> = conn.query_row(
        "SELECT id FROM leases WHERE agent_id=? AND room_id=? AND status='open'",
        params![agent_id, room_id],
        |r| r.get(0),
    ).optional()?;
    if let Some(existing_id) = existing {
        return Err(LeaseError::Suspended(existing_id));
    }

    // Debt ceiling gate: total open debt across all leases for this agent
    let total_debt: i64 = conn.query_row(
        "SELECT COALESCE(SUM(current_debt),0) FROM leases WHERE agent_id=? AND status='open'",
        params![agent_id],
        |r| r.get(0),
    )?;
    if total_debt >= max_cost {
        return Err(LeaseError::DebtCeiling { current: total_debt, max: max_cost });
    }

    let id = random_id(8);
    let expires_at = ts + duration_secs;

    conn.execute(
        "INSERT INTO leases (id, agent_id, room_id, status, max_cost, current_debt, credits_per_min, last_heartbeat, created_at, expires_at)
         VALUES (?1, ?2, ?3, 'open', ?4, 0, ?5, ?6, ?6, ?7)",
        params![id, agent_id, room_id, max_cost, credits_per_min, ts, expires_at],
    )?;

    for (tool_name, cost) in tool_rates {
        conn.execute(
            "INSERT INTO tool_rates (lease_id, tool_name, cost) VALUES (?1, ?2, ?3)",
            params![id, tool_name, cost],
        )?;
    }

    Ok(Lease {
        id,
        agent_id: agent_id.to_string(),
        room_id: room_id.to_string(),
        status: "open".to_string(),
        max_cost,
        current_debt: 0,
        credits_per_min,
        last_heartbeat: ts,
        created_at: ts,
        expires_at,
    })
}

/// Send a heartbeat for a lease, keeping it alive.
pub fn heartbeat(lease_id: &str) -> Result<(), LeaseError> {
    let conn = open_db()?;
    let rows = conn.execute(
        "UPDATE leases SET last_heartbeat=?1 WHERE id=?2 AND status='open'",
        params![now_secs(), lease_id],
    )?;
    if rows == 0 { return Err(LeaseError::NotFound(lease_id.to_string())); }
    Ok(())
}

/// Charge debt for a tool call. Suspends lease if debt ceiling is hit.
pub fn charge_tool_call(lease_id: &str, tool_name: &str) -> Result<i64, LeaseError> {
    let conn = open_db()?;

    // Look up tool rate
    let cost: Option<i64> = conn.query_row(
        "SELECT cost FROM tool_rates WHERE lease_id=?1 AND tool_name=?2",
        params![lease_id, tool_name],
        |r| r.get(0),
    ).optional()?;
    let cost = cost.unwrap_or(0);
    if cost == 0 { return Ok(0); }

    // Atomic increment + suspension check
    conn.execute(
        "UPDATE leases SET current_debt = current_debt + ?1 WHERE id = ?2 AND status = 'open'",
        params![cost, lease_id],
    )?;

    let (current_debt, max_cost): (i64, i64) = conn.query_row(
        "SELECT current_debt, max_cost FROM leases WHERE id=?1",
        params![lease_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;

    if current_debt >= max_cost {
        conn.execute(
            "UPDATE leases SET status='suspended' WHERE id=?1",
            params![lease_id],
        )?;
    }

    Ok(current_debt)
}

/// Submit a receipt to drain debt (only permitted in Suspended state).
/// If debt drops below 50% of max_cost, lease resumes to 'open'.
pub fn submit_receipt(lease_id: &str, credit_reduction: i64) -> Result<String, LeaseError> {
    let conn = open_db()?;

    let (status, current_debt, max_cost): (String, i64, i64) = conn.query_row(
        "SELECT status, current_debt, max_cost FROM leases WHERE id=?1",
        params![lease_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    ).optional()?.ok_or_else(|| LeaseError::NotFound(lease_id.to_string()))?;

    if status == "closed" {
        return Err(LeaseError::AlreadyClosed(lease_id.to_string()));
    }

    let new_debt = (current_debt - credit_reduction).max(0);
    let resume = new_debt < max_cost / 2;
    let new_status = if resume { "open" } else { &status as &str };

    conn.execute(
        "UPDATE leases SET current_debt=?1, status=?2, last_heartbeat=?3 WHERE id=?4",
        params![new_debt, new_status, now_secs(), lease_id],
    )?;

    Ok(new_status.to_string())
}

/// Close a lease. Computes actual cost from credits_per_min * elapsed_mins.
pub fn close_lease(lease_id: &str) -> Result<i64, LeaseError> {
    let conn = open_db()?;

    let lease: Option<Lease> = conn.query_row(
        "SELECT id, agent_id, room_id, status, max_cost, current_debt, credits_per_min, last_heartbeat, created_at, expires_at
         FROM leases WHERE id=?1",
        params![lease_id],
        |r| Ok(Lease {
            id: r.get(0)?,
            agent_id: r.get(1)?,
            room_id: r.get(2)?,
            status: r.get(3)?,
            max_cost: r.get(4)?,
            current_debt: r.get(5)?,
            credits_per_min: r.get(6)?,
            last_heartbeat: r.get(7)?,
            created_at: r.get(8)?,
            expires_at: r.get(9)?,
        }),
    ).optional()?;

    let lease = lease.ok_or_else(|| LeaseError::NotFound(lease_id.to_string()))?;
    if lease.status == "closed" {
        return Err(LeaseError::AlreadyClosed(lease_id.to_string()));
    }

    let elapsed_mins = ((now_secs() - lease.created_at).max(0) as f64 / 60.0).ceil() as i64;
    let time_cost = lease.credits_per_min * elapsed_mins;
    let actual_cost = time_cost.max(lease.current_debt); // take the higher of time vs debt

    conn.execute(
        "UPDATE leases SET status='closed', current_debt=?1 WHERE id=?2",
        params![actual_cost, lease_id],
    )?;

    Ok(actual_cost)
}

/// Recover stale leases (last_heartbeat > 5 min ago) and close them.
/// Returns the number of leases recovered.
pub fn recover_stale() -> Result<usize, LeaseError> {
    let conn = open_db()?;
    let stale_cutoff = now_secs() - 300; // 5 minutes
    let rows = conn.execute(
        "UPDATE leases SET status='closed' WHERE status IN ('open','suspended') AND last_heartbeat < ?1",
        params![stale_cutoff],
    )?;
    Ok(rows)
}

/// Get lease by id.
pub fn get_lease(lease_id: &str) -> Result<Option<Lease>, LeaseError> {
    let conn = open_db()?;
    let result = conn.query_row(
        "SELECT id, agent_id, room_id, status, max_cost, current_debt, credits_per_min, last_heartbeat, created_at, expires_at
         FROM leases WHERE id=?1",
        params![lease_id],
        |r| Ok(Lease {
            id: r.get(0)?,
            agent_id: r.get(1)?,
            room_id: r.get(2)?,
            status: r.get(3)?,
            max_cost: r.get(4)?,
            current_debt: r.get(5)?,
            credits_per_min: r.get(6)?,
            last_heartbeat: r.get(7)?,
            created_at: r.get(8)?,
            expires_at: r.get(9)?,
        }),
    ).optional()?;
    Ok(result)
}

/// List open leases for an agent.
pub fn open_leases_for(agent_id: &str) -> Result<Vec<Lease>, LeaseError> {
    let conn = open_db()?;
    let mut stmt = conn.prepare(
        "SELECT id, agent_id, room_id, status, max_cost, current_debt, credits_per_min, last_heartbeat, created_at, expires_at
         FROM leases WHERE agent_id=?1 AND status='open'"
    )?;
    let leases = stmt.query_map(params![agent_id], |r| Ok(Lease {
        id: r.get(0)?,
        agent_id: r.get(1)?,
        room_id: r.get(2)?,
        status: r.get(3)?,
        max_cost: r.get(4)?,
        current_debt: r.get(5)?,
        credits_per_min: r.get(6)?,
        last_heartbeat: r.get(7)?,
        created_at: r.get(8)?,
        expires_at: r.get(9)?,
    }))?.collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(leases)
}
