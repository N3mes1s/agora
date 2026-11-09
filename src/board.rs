//! Operator board: what `agora tui` shows beside the live messages, folded
//! from decrypted room events: tasks, open proposals and HOLDs, leases, and
//! which agents are active, idle, stuck or gone.
//!
//! Pure apart from reading the shared local task store: no relay calls and no
//! writes, so the TUI recomputes it every tick from events it already holds.
//!
//! Agent status, from signed events only:
//!
//! * **stuck**: holds a task claim with no checkpoint (work receipt) and no
//!   new claim for [`STUCK_NO_PROGRESS_SECS`];
//! * **active**: sent something other than a heartbeat (a message, lease or
//!   task event, a read receipt) within [`ACTIVE_WITHIN_SECS`];
//! * **idle**: seen (heartbeats count) within [`GONE_AFTER_SECS`] but quiet;
//! * **gone**: not seen for [`GONE_AFTER_SECS`].
//!
//! A heartbeat only proves that a listener runs under the agent's id (e.g.
//! `agora watch`), not that its session works, so heartbeats never make an
//! agent active.

use crate::{chat, lease, proposal, store};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

/// Activity more recent than this makes an agent active.
pub const ACTIVE_WITHIN_SECS: u64 = 10 * 60;
/// Not seen at all for this long: gone.
pub const GONE_AFTER_SECS: u64 = 2 * 3600;
/// A claimed task with no checkpoint for this long: stuck.
pub const STUCK_NO_PROGRESS_SECS: u64 = 45 * 60;

/// Relay receipt time of an event (a clock the sender does not control).
pub fn relay_ts(env: &Value) -> u64 {
    env["_relay_ts"]
        .as_u64()
        .or_else(|| env["ts"].as_u64())
        .unwrap_or(0)
}

/// Sender of a signature-verified event.
fn verified_from(env: &Value) -> Option<&str> {
    if env["_auth"].as_str() != Some("verified") {
        return None;
    }
    env["from"]
        .as_str()
        .filter(|f| !f.is_empty() && *f != "[auth]")
}

/// Short task id as used in claim lease resources (`task:<6 chars>`).
fn task_key(task_id: &str) -> String {
    task_id.chars().take(6).collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AgentStatus {
    Stuck,
    Active,
    Idle,
    Gone,
}

impl AgentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            AgentStatus::Stuck => "stuck",
            AgentStatus::Active => "active",
            AgentStatus::Idle => "idle",
            AgentStatus::Gone => "gone",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRow {
    pub agent: String,
    pub status: AgentStatus,
    /// Last signed event of any kind (heartbeats included).
    pub last_seen: Option<u64>,
    /// Last signed event that is not a heartbeat.
    pub last_active: Option<u64>,
    /// Short ids of tasks it holds claims on.
    pub claims: Vec<String>,
    /// Other resources it holds leases on.
    pub leases: Vec<String>,
    /// Why the status, for the operator.
    pub why: String,
}

/// Presence and task progress per agent, accumulated from every room's
/// events as they arrive.
#[derive(Debug, Default, Clone)]
pub struct Presence {
    seen: HashMap<String, u64>,
    active: HashMap<String, u64>,
    /// (agent, short task id) -> last checkpoint or completion.
    progress: HashMap<(String, String), u64>,
}

impl Presence {
    pub fn observe(&mut self, env: &Value) {
        let Some(from) = verified_from(env) else {
            return;
        };
        let ts = relay_ts(env);
        let seen = self.seen.entry(from.to_string()).or_default();
        *seen = (*seen).max(ts);
        if env["type"].as_str() == Some("heartbeat") {
            return;
        }
        let active = self.active.entry(from.to_string()).or_default();
        *active = (*active).max(ts);
        if env["type"].as_str() == Some("work_receipt")
            && let Some(task) = env["task_id"].as_str()
        {
            let at = self
                .progress
                .entry((from.to_string(), task_key(task)))
                .or_default();
            *at = (*at).max(ts);
        }
    }

    /// One row per agent seen or holding a lease, most urgent first.
    pub fn agents(&self, table: &BTreeMap<String, lease::Lease>, now: u64) -> Vec<AgentRow> {
        let mut claims: BTreeMap<&str, Vec<&lease::Lease>> = BTreeMap::new();
        let mut leases: BTreeMap<&str, Vec<&lease::Lease>> = BTreeMap::new();
        for l in table.values() {
            if l.resource.starts_with("task:") {
                claims.entry(&l.holder).or_default().push(l);
            } else {
                leases.entry(&l.holder).or_default().push(l);
            }
        }
        let mut names: Vec<&str> = self.seen.keys().map(String::as_str).collect();
        names.extend(claims.keys().copied());
        names.extend(leases.keys().copied());
        names.sort_unstable();
        names.dedup();

        let mut rows: Vec<AgentRow> = names
            .into_iter()
            .map(|agent| {
                let last_seen = self.seen.get(agent).copied();
                let last_active = self.active.get(agent).copied();
                let held = claims.get(agent).cloned().unwrap_or_default();
                // Oldest progress among its claims decides "stuck".
                let stalled = held
                    .iter()
                    .map(|l| {
                        let key = task_key(l.resource.trim_start_matches("task:"));
                        let checkpoint = self
                            .progress
                            .get(&(agent.to_string(), key.clone()))
                            .copied()
                            .unwrap_or(0);
                        (key, checkpoint.max(l.acquired_at))
                    })
                    .min_by_key(|(_, at)| *at);
                let ago = |ts: u64| fmt_age(now.saturating_sub(ts));
                let (status, why) = match (stalled, last_active, last_seen) {
                    (Some((task, at)), _, _) if now.saturating_sub(at) > STUCK_NO_PROGRESS_SECS => {
                        (
                            AgentStatus::Stuck,
                            format!("task {task}: no checkpoint for {}", ago(at)),
                        )
                    }
                    (_, Some(a), _) if now.saturating_sub(a) <= ACTIVE_WITHIN_SECS => {
                        (AgentStatus::Active, format!("active {} ago", ago(a)))
                    }
                    (_, _, Some(s)) if now.saturating_sub(s) <= GONE_AFTER_SECS => (
                        AgentStatus::Idle,
                        match last_active {
                            Some(a) => format!("quiet {}, heartbeat {} ago", ago(a), ago(s)),
                            None => format!("heartbeats only, last {} ago", ago(s)),
                        },
                    ),
                    (_, _, Some(s)) => (AgentStatus::Gone, format!("not seen for {}", ago(s))),
                    (_, _, None) => (AgentStatus::Gone, "not seen in the window".to_string()),
                };
                AgentRow {
                    agent: agent.to_string(),
                    status,
                    last_seen,
                    last_active,
                    claims: held
                        .iter()
                        .map(|l| task_key(l.resource.trim_start_matches("task:")))
                        .collect(),
                    leases: leases
                        .get(agent)
                        .map(|ls| ls.iter().map(|l| l.resource.clone()).collect())
                        .unwrap_or_default(),
                    why,
                }
            })
            .collect();
        rows.sort_by(|a, b| {
            (a.status, std::cmp::Reverse(a.last_seen), &a.agent).cmp(&(
                b.status,
                std::cmp::Reverse(b.last_seen),
                &b.agent,
            ))
        });
        rows
    }
}

/// `90` -> `1m`, `7200` -> `2h`.
pub fn fmt_age(secs: u64) -> String {
    match secs {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m", s / 60),
        s if s < 86400 => format!("{}h{:02}m", s / 3600, (s % 3600) / 60),
        s => format!("{}d", s / 86400),
    }
}

/// Everything the board panes show for one room.
#[derive(Debug, Clone, Default)]
pub struct Board {
    /// Active leases that are not task claims.
    pub leases: Vec<lease::Lease>,
    /// Open and HELD proposals, newest first.
    pub proposals: Vec<(proposal::Proposal, proposal::Status)>,
    /// Open and claimed tasks (claimed first).
    pub tasks: Vec<store::Task>,
    pub agents: Vec<AgentRow>,
    /// Events folded (for the span and the status bar).
    pub events: usize,
}

/// Fold `events` (decrypted, any order) of the board room `room_id` into the
/// panes. Tasks also come from the shared local store and its message cache.
pub fn build(room_id: &str, events: &[Value], presence: &Presence, now: u64) -> Board {
    let span = tracing::info_span!(
        target: "agora",
        "agora.tui.board",
        events = events.len(),
        tasks = tracing::field::Empty,
        proposals = tracing::field::Empty,
        leases = tracing::field::Empty,
        agents = tracing::field::Empty,
        stuck = tracing::field::Empty,
    );
    let _entered = span.enter();

    let parsed: Vec<lease::LeaseEvent> = events.iter().filter_map(lease::parse_event).collect();
    let table = lease::fold(&parsed, now);

    let mut proposals: Vec<(proposal::Proposal, proposal::Status)> = proposal::fold(events)
        .into_values()
        .filter_map(|p| {
            let mut status = p.status(now);
            if status != proposal::Status::Held
                && !proposal::conflicting_leases(&p, &table).is_empty()
            {
                status = proposal::Status::Held;
            }
            (status != proposal::Status::Clear).then_some((p, status))
        })
        .collect();
    proposals.sort_by_key(|(p, _)| std::cmp::Reverse(p.created_at));

    let mut msgs = store::load_messages(room_id, 7 * 86400);
    msgs.extend(events.iter().cloned());
    msgs.sort_by_key(relay_ts);
    let mut tasks = chat::fold_task_announcements(store::load_tasks(room_id), &msgs);
    chat::apply_task_claims(&mut tasks, &table);
    tasks.retain(|t| t.status != "done");
    tasks.sort_by(|a, b| {
        (a.status != "claimed", std::cmp::Reverse(a.created_at))
            .cmp(&(b.status != "claimed", std::cmp::Reverse(b.created_at)))
    });

    let agents = presence.agents(&table, now);
    let leases: Vec<lease::Lease> = table
        .into_values()
        .filter(|l| !l.resource.starts_with("task:"))
        .collect();

    span.record("tasks", tasks.len());
    span.record("proposals", proposals.len());
    span.record("leases", leases.len());
    span.record("agents", agents.len());
    span.record(
        "stuck",
        agents
            .iter()
            .filter(|a| a.status == AgentStatus::Stuck)
            .count(),
    );
    Board {
        leases,
        proposals,
        tasks,
        agents,
        events: events.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{chat, runtime, transport};
    use std::path::PathBuf;

    fn temp_home() -> PathBuf {
        let home = std::env::temp_dir().join(format!(
            "agora-board-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&home).unwrap();
        home
    }

    fn as_agent(home: &PathBuf, agent: &str, now: u64) -> runtime::TestRuntimeGuard {
        runtime::TestRuntime::new()
            .home(home)
            .var("AGORA_CONFIG", "/nonexistent/agora-test-config.toml")
            .var("AGORA_RELAY_URL", format!("memory://{}", home.display()))
            .unset_var("AGORA_IDENTITY_SEED")
            .var("AGORA_AGENT_ID", agent)
            .now(now)
            .advance_sleep()
            .enter()
    }

    #[test]
    fn fmt_age_is_compact() {
        assert_eq!(fmt_age(5), "5s");
        assert_eq!(fmt_age(90), "1m");
        assert_eq!(fmt_age(3 * 3600 + 5 * 60), "3h05m");
        assert_eq!(fmt_age(3 * 86400), "3d");
    }

    #[test]
    fn heartbeats_never_make_an_agent_active() {
        let mut p = Presence::default();
        let hb = |from: &str, ts: u64| json_env(from, ts, Some("heartbeat"));
        p.observe(&hb("listener-only", 1000));
        p.observe(&json_env("worker", 1000, None));
        let unsigned = serde_json::json!({"from": "spoof", "_relay_ts": 1000, "text": "hi", "_auth": "unsigned"});
        p.observe(&unsigned);
        let rows = p.agents(&BTreeMap::new(), 1060);
        let status = |a: &str| rows.iter().find(|r| r.agent == a).map(|r| r.status);
        assert_eq!(status("worker"), Some(AgentStatus::Active));
        assert_eq!(status("listener-only"), Some(AgentStatus::Idle));
        assert_eq!(status("spoof"), None, "unsigned senders are not agents");
        let rows = p.agents(&BTreeMap::new(), 1000 + GONE_AFTER_SECS + 1);
        assert!(rows.iter().all(|r| r.status == AgentStatus::Gone));
    }

    fn json_env(from: &str, ts: u64, kind: Option<&str>) -> Value {
        let mut env = serde_json::json!({
            "from": from, "_relay_ts": ts, "ts": ts, "text": "x", "_auth": "verified",
        });
        if let Some(kind) = kind {
            env["type"] = serde_json::json!(kind);
        }
        env
    }

    /// Fetch, observe and build as the operator would, without writing.
    fn board_at(home: &PathBuf, now: u64) -> (Board, usize) {
        let _rt = as_agent(home, "operator-view", now);
        let room = store::find_room("ops").unwrap();
        let before = transport::fetch_checked(&room.room_id, "0").unwrap().len();
        let events = chat::fetch_room_events(&room, "0").unwrap();
        let mut presence = Presence::default();
        for env in &events {
            presence.observe(env);
        }
        let board = build(&room.room_id, &events, &presence, now);
        let after = transport::fetch_checked(&room.room_id, "0").unwrap().len();
        assert_eq!(before, after, "building the board must not publish");
        (board, after)
    }

    #[test]
    fn board_folds_tasks_proposals_leases_and_stuck_agents() {
        let home = temp_home();
        {
            let _rt = as_agent(&home, "agent-a", 900);
            chat::create_silent("ops").unwrap();
        }
        let task = {
            let _rt = as_agent(&home, "agent-a", 1000);
            assert!(matches!(
                lease::acquire("docker", 7200, Some("build"), 3, Some("ops")).unwrap(),
                lease::Acquire::Acquired(_)
            ));
            let id = chat::task_add("ship the tui", Some("ops")).unwrap();
            chat::task_add("write docs", Some("ops")).unwrap();
            chat::task_claim(&id, Some("ops")).unwrap();
            id
        };
        {
            let _rt = as_agent(&home, "agent-b", 1100);
            proposal::propose("restart docker", &["docker".to_string()], 300, Some("ops")).unwrap();
            chat::heartbeat(Some("ops")).unwrap();
        }

        let (board, _) = board_at(&home, 1200);
        assert_eq!(
            board.leases.len(),
            1,
            "task claims are not listed as leases"
        );
        assert_eq!(board.leases[0].resource, "docker");
        assert_eq!(board.proposals.len(), 1);
        assert_eq!(
            board.proposals[0].1,
            proposal::Status::Held,
            "docker is leased"
        );
        assert_eq!(board.tasks.len(), 2);
        assert_eq!(board.tasks[0].status, "claimed");
        assert_eq!(board.tasks[0].claimed_by.as_deref(), Some("agent-a"));
        let a = board.agents.iter().find(|r| r.agent == "agent-a").unwrap();
        assert_eq!(a.status, AgentStatus::Active);
        assert_eq!(a.claims, vec![task_key(&task)]);
        assert_eq!(a.leases, vec!["docker".to_string()]);

        // 50 minutes later without a checkpoint: stuck.
        let later = 1000 + STUCK_NO_PROGRESS_SECS + 300;
        let (board, _) = board_at(&home, later);
        let a = board.agents.iter().find(|r| r.agent == "agent-a").unwrap();
        assert_eq!(a.status, AgentStatus::Stuck, "{a:?}");
        assert!(a.why.contains("no checkpoint"));
        assert_eq!(board.agents[0].agent, "agent-a", "stuck agents sort first");
        // Past its deadline but still conflicting with agent-a's live lease:
        // HELD, as `agora proposals` shows it.
        assert_eq!(board.proposals[0].1, proposal::Status::Held);

        // A checkpoint clears it.
        {
            let _rt = as_agent(&home, "agent-a", later + 10);
            chat::task_checkpoint(&task, Some("half way"), Some("ops")).unwrap();
        }
        let (board, _) = board_at(&home, later + 20);
        let a = board.agents.iter().find(|r| r.agent == "agent-a").unwrap();
        assert_eq!(a.status, AgentStatus::Active, "{a:?}");
    }
}
