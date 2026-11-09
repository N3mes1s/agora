//! `agora tui`: operator console. One view follows every room and DM live;
//! switch to any channel; panes show the board room's tasks, open proposals
//! and HOLDs, leases, and which agents are active, idle, stuck or gone.
//!
//! Read-only by default: it streams and decrypts, and never publishes. No
//! heartbeats, no read receipts, and no `agora check` (that would mark the
//! shared seen.txt and take messages away from agents' wake hooks).
//! `--write` adds a compose line that sends as the current agent id.
//!
//! One streaming reader per room, from `--history` ago; every pane is folded
//! in memory from those events (see `agora::board`), so there is no polling.

use agora::board::{self, AgentStatus, Board, Presence};
use agora::{chat, crypto, proposal, runtime, store, transport};
use ratatui::Frame;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, List, ListItem, ListState, Paragraph, Row, Table,
};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Input poll interval (also the redraw cadence).
const TICK: Duration = Duration::from_millis(200);
/// Board panes are refolded this often.
const BOARD_EVERY: Duration = Duration::from_secs(3);
/// The room registry is rescanned this often (new DM rooms, ended readers).
const RESCAN_EVERY: Duration = Duration::from_secs(10);
/// Events kept per room, newest first, on top of the history window.
const MAX_EVENTS_PER_ROOM: usize = 20_000;
/// A board fold slower than this is logged to ~/.agora/tui.log.
const SLOW_BOARD: Duration = Duration::from_millis(500);

pub struct Options {
    /// Allow sending (compose with `i`).
    pub write: bool,
    /// Initial board room (label or id); default: the active room.
    pub board_room: Option<String>,
    /// How far back each reader starts.
    pub history_secs: u64,
}

/// What the room readers hand to the UI thread.
pub enum Feed {
    Event { room_id: String, env: Value },
    Status(String),
}

struct RoomView {
    room: store::RoomEntry,
    /// Events by relay time.
    events: Vec<Value>,
    ids: HashSet<String>,
    unread: usize,
    /// Relay time of the last displayable message.
    last_ts: u64,
}

fn is_dm(room: &store::RoomEntry) -> bool {
    room.label.starts_with("dm-")
}

/// Shown in the message list: chat, task and proposal posts, and auth
/// warnings (security relevant for an operator).
fn displayable(env: &Value) -> bool {
    chat::is_conversational(env) || env["type"].as_str() == Some("auth_warning")
}

pub struct App {
    write_as: Option<String>,
    history_secs: u64,
    rooms: BTreeMap<String, RoomView>,
    /// `None` = every room.
    selected: Option<String>,
    /// Rows scrolled up from the newest message.
    scroll: usize,
    board_room: Option<String>,
    board: Board,
    presence: Presence,
    status: String,
    compose: Option<String>,
    help: bool,
    quit: bool,
}

impl App {
    pub fn new(write_as: Option<String>, history_secs: u64) -> Self {
        Self {
            write_as,
            history_secs,
            rooms: BTreeMap::new(),
            selected: None,
            scroll: 0,
            board_room: None,
            board: Board::default(),
            presence: Presence::default(),
            status: String::new(),
            compose: None,
            help: false,
            quit: false,
        }
    }

    /// Add rooms from the registry; returns the ones that are new.
    pub fn add_rooms(&mut self, rooms: Vec<store::RoomEntry>) -> Vec<store::RoomEntry> {
        let mut added = Vec::new();
        for room in rooms {
            if self.rooms.contains_key(&room.room_id) {
                continue;
            }
            added.push(room.clone());
            self.rooms.insert(
                room.room_id.clone(),
                RoomView {
                    room,
                    events: Vec::new(),
                    ids: HashSet::new(),
                    unread: 0,
                    last_ts: 0,
                },
            );
        }
        added
    }

    /// Board room by label or id, if it is a known non-DM room.
    pub fn set_board_room(&mut self, label_or_id: &str) -> bool {
        let found = self
            .rooms
            .values()
            .find(|v| {
                !is_dm(&v.room) && (v.room.label == label_or_id || v.room.room_id == label_or_id)
            })
            .map(|v| v.room.room_id.clone());
        if found.is_some() {
            self.board_room = found;
        }
        self.board_room.is_some()
    }

    /// Channel list: every room first, then rooms by label, then DMs by
    /// latest activity.
    fn channels(&self) -> Vec<Option<String>> {
        let mut rooms: Vec<&RoomView> = self.rooms.values().filter(|v| !is_dm(&v.room)).collect();
        rooms.sort_by(|a, b| a.room.label.cmp(&b.room.label));
        let mut dms: Vec<&RoomView> = self.rooms.values().filter(|v| is_dm(&v.room)).collect();
        dms.sort_by(|a, b| {
            (std::cmp::Reverse(a.last_ts), &a.room.label)
                .cmp(&(std::cmp::Reverse(b.last_ts), &b.room.label))
        });
        std::iter::once(None)
            .chain(
                rooms
                    .into_iter()
                    .chain(dms)
                    .map(|v| Some(v.room.room_id.clone())),
            )
            .collect()
    }

    fn select(&mut self, delta: isize) {
        let channels = self.channels();
        let at = channels
            .iter()
            .position(|c| *c == self.selected)
            .unwrap_or(0) as isize;
        let next = (at + delta).rem_euclid(channels.len() as isize) as usize;
        self.selected = channels[next].clone();
        self.scroll = 0;
        if let Some(id) = &self.selected
            && let Some(view) = self.rooms.get_mut(id)
        {
            view.unread = 0;
            if !is_dm(&view.room) {
                self.board_room = Some(id.clone());
            }
        }
    }

    pub fn ingest(&mut self, room_id: &str, env: Value) {
        let selected = self.selected.as_deref() == Some(room_id);
        let Some(view) = self.rooms.get_mut(room_id) else {
            return;
        };
        if let Some(id) = env["id"].as_str().filter(|id| !id.is_empty() && *id != "?")
            && !view.ids.insert(id.to_string())
        {
            return;
        }
        self.presence.observe(&env);
        let ts = board::relay_ts(&env);
        if displayable(&env) {
            view.last_ts = view.last_ts.max(ts);
            if !selected {
                view.unread += 1;
            }
        }
        let at = view.events.partition_point(|e| board::relay_ts(e) <= ts);
        view.events.insert(at, env);
        if view.events.len() > MAX_EVENTS_PER_ROOM {
            let drop = view.events.len() - MAX_EVENTS_PER_ROOM;
            view.events.drain(..drop);
        }
    }

    /// Drop events older than the history window.
    fn prune(&mut self, now: u64) {
        let cutoff = now.saturating_sub(self.history_secs);
        for view in self.rooms.values_mut() {
            let keep_from = view.events.partition_point(|e| board::relay_ts(e) < cutoff);
            view.events.drain(..keep_from);
        }
    }

    pub fn rebuild_board(&mut self, now: u64) {
        let Some(view) = self.board_room.as_ref().and_then(|id| self.rooms.get(id)) else {
            return;
        };
        let started = Instant::now();
        self.board = board::build(&view.room.room_id, &view.events, &self.presence, now);
        let elapsed = started.elapsed();
        if elapsed >= SLOW_BOARD {
            slow_log(&format!(
                "slow unit name=agora.tui.board elapsed_ms={} events={} tasks={} proposals={} leases={} agents={}",
                elapsed.as_millis(),
                self.board.events,
                self.board.tasks.len(),
                self.board.proposals.len(),
                self.board.leases.len(),
                self.board.agents.len()
            ));
        }
    }

    fn label(&self, room_id: &str) -> String {
        self.rooms
            .get(room_id)
            .map(|v| v.room.label.clone())
            .unwrap_or_else(|| room_id.to_string())
    }

    /// Displayable events of the selected channel, oldest first, with their room.
    fn messages(&self) -> Vec<(&str, &Value)> {
        let mut out: Vec<(&str, &Value)> = match &self.selected {
            Some(id) => self
                .rooms
                .get(id)
                .map(|v| {
                    v.events
                        .iter()
                        .filter(|e| displayable(e))
                        .map(|e| (id.as_str(), e))
                        .collect()
                })
                .unwrap_or_default(),
            None => self
                .rooms
                .iter()
                .flat_map(|(id, v)| {
                    v.events
                        .iter()
                        .filter(|e| displayable(e))
                        .map(move |e| (id.as_str(), e))
                })
                .collect(),
        };
        if self.selected.is_none() {
            out.sort_by_key(|(_, e)| board::relay_ts(e));
        }
        out
    }

    /// Handle one key press.
    pub fn key(&mut self, key: KeyEvent) {
        if let Some(text) = self.compose.as_mut() {
            match key.code {
                KeyCode::Esc => self.compose = None,
                KeyCode::Enter => {
                    let text = std::mem::take(text);
                    self.compose = None;
                    self.send(&text);
                }
                KeyCode::Backspace => {
                    text.pop();
                }
                KeyCode::Char(c) => text.push(c),
                _ => {}
            }
            return;
        }
        match key.code {
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => self.quit = true,
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Char('?') => self.help = !self.help,
            KeyCode::Esc => self.help = false,
            KeyCode::Up | KeyCode::Char('k') => self.select(-1),
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => self.select(1),
            KeyCode::Char('a') => {
                self.selected = None;
                self.scroll = 0;
            }
            KeyCode::PageUp | KeyCode::Char('u') => self.scroll = self.scroll.saturating_add(10),
            KeyCode::PageDown | KeyCode::Char('d') => self.scroll = self.scroll.saturating_sub(10),
            KeyCode::End | KeyCode::Char('G') => self.scroll = 0,
            KeyCode::Char('b') => match self.selected.clone() {
                Some(id) if self.rooms.get(&id).is_some_and(|v| !is_dm(&v.room)) => {
                    self.board_room = Some(id);
                    self.rebuild_board(runtime::unix_now());
                }
                _ => self.status = "board: select a room (not a DM) first".to_string(),
            },
            KeyCode::Char('r') => self.rebuild_board(runtime::unix_now()),
            KeyCode::Char('i') => {
                if self.write_as.is_none() {
                    self.status = "read-only: start with `agora tui --write` to send".to_string();
                } else if self.selected.is_none() {
                    self.status = "select a room or DM to send to (not 'every room')".to_string();
                } else {
                    self.compose = Some(String::new());
                }
            }
            _ => {}
        }
    }

    fn send(&mut self, text: &str) {
        let text = text.trim();
        if text.is_empty() || self.write_as.is_none() {
            return;
        }
        let Some(label) = self.selected.as_ref().map(|id| self.label(id)) else {
            return;
        };
        self.status = match chat::send(text, None, Some(&label)) {
            Ok(id) => format!(
                "sent [{}] to {label}",
                id.chars().take(6).collect::<String>()
            ),
            Err(e) => format!("send failed: {e}"),
        };
    }

    pub fn draw(&self, frame: &mut Frame) {
        let [top, boardrow, agents, status] = Layout::vertical([
            Constraint::Min(8),
            Constraint::Length(9),
            Constraint::Length(8),
            Constraint::Length(1),
        ])
        .areas(frame.area());
        let [chans, msgs] =
            Layout::horizontal([Constraint::Length(30), Constraint::Min(20)]).areas(top);
        let [tasks, props, leases] = Layout::horizontal([
            Constraint::Percentage(42),
            Constraint::Percentage(33),
            Constraint::Percentage(25),
        ])
        .areas(boardrow);
        self.draw_channels(frame, chans);
        self.draw_messages(frame, msgs);
        self.draw_tasks(frame, tasks);
        self.draw_proposals(frame, props);
        self.draw_leases(frame, leases);
        self.draw_agents(frame, agents);
        self.draw_status(frame, status);
        if self.help {
            draw_help(frame, frame.area());
        }
    }

    fn draw_channels(&self, frame: &mut Frame, area: Rect) {
        let channels = self.channels();
        let width = area.width.saturating_sub(4) as usize;
        let items: Vec<ListItem> = channels
            .iter()
            .map(|c| match c {
                None => ListItem::new(Line::from(Span::styled(
                    "* every room and DM",
                    Style::default().add_modifier(Modifier::BOLD),
                ))),
                Some(id) => {
                    let view = &self.rooms[id];
                    let name = if is_dm(&view.room) {
                        format!("@ {}", view.room.label.trim_start_matches("dm-"))
                    } else {
                        format!("# {}", view.room.label)
                    };
                    let unread = if view.unread > 0 {
                        format!(" {}", view.unread)
                    } else {
                        String::new()
                    };
                    let room = truncate(&name, width.saturating_sub(unread.chars().count()));
                    let mut spans = vec![Span::raw(room)];
                    if !unread.is_empty() {
                        spans.push(Span::styled(
                            unread,
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD),
                        ));
                    }
                    if self.board_room.as_deref() == Some(id.as_str()) {
                        spans.push(Span::styled(" ◆", Style::default().fg(Color::Cyan)));
                    }
                    ListItem::new(Line::from(spans))
                }
            })
            .collect();
        let mut state = ListState::default();
        state.select(channels.iter().position(|c| *c == self.selected));
        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" channels (↑↓ a b) "),
            )
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
        frame.render_stateful_widget(list, area, &mut state);
    }

    fn draw_messages(&self, frame: &mut Frame, area: Rect) {
        let title = match &self.selected {
            None => " every room and DM, live ".to_string(),
            Some(id) => format!(" {} ", self.label(id)),
        };
        let title = if self.scroll > 0 {
            format!("{title}[scrolled {} up, End: live] ", self.scroll)
        } else {
            title
        };
        let inner_width = area.width.saturating_sub(2) as usize;
        let height = area.height.saturating_sub(2) as usize;
        let all = self.selected.is_none();
        let mut rows: Vec<Line> = Vec::new();
        // Build from the newest message back until the window is full.
        for (room_id, env) in self.messages().into_iter().rev() {
            let mut lines = message_lines(env, all.then(|| self.label(room_id)), inner_width);
            lines.reverse();
            rows.extend(lines);
            if rows.len() >= height + self.scroll {
                break;
            }
        }
        let skip = self
            .scroll
            .min(rows.len().saturating_sub(height.min(rows.len())));
        let mut visible: Vec<Line> = rows.into_iter().skip(skip).take(height).collect();
        visible.reverse();
        frame.render_widget(
            Paragraph::new(visible).block(Block::default().borders(Borders::ALL).title(title)),
            area,
        );
    }

    fn board_title(&self, what: &str) -> String {
        let room = self
            .board_room
            .as_ref()
            .map(|id| self.label(id))
            .unwrap_or_else(|| "-".to_string());
        format!(" {what} ({room}) ")
    }

    fn draw_tasks(&self, frame: &mut Frame, area: Rect) {
        let rows: Vec<Row> = self
            .board
            .tasks
            .iter()
            .map(|t| {
                let style = if t.status == "claimed" {
                    Style::default().fg(Color::Green)
                } else {
                    Style::default()
                };
                Row::new(vec![
                    Cell::from(t.id.chars().take(6).collect::<String>()),
                    Cell::from(t.status.clone()).style(style),
                    Cell::from(t.claimed_by.clone().unwrap_or_default()),
                    Cell::from(t.title.clone()),
                ])
            })
            .collect();
        let table = Table::new(
            rows,
            [
                Constraint::Length(6),
                Constraint::Length(7),
                Constraint::Length(20),
                Constraint::Min(10),
            ],
        )
        .header(
            Row::new(vec!["id", "status", "claimed by", "title"])
                .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(self.board_title(&format!("tasks {}", self.board.tasks.len()))),
        );
        frame.render_widget(table, area);
    }

    fn draw_proposals(&self, frame: &mut Frame, area: Rect) {
        let now = runtime::unix_now();
        let rows: Vec<Row> = self
            .board
            .proposals
            .iter()
            .map(|(p, status)| {
                let (label, style) = match status {
                    proposal::Status::Held => (
                        "HELD".to_string(),
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    ),
                    _ => (
                        format!("{}s", p.deadline.saturating_sub(now)),
                        Style::default().fg(Color::Yellow),
                    ),
                };
                let holds = p
                    .objections
                    .first()
                    .map(|o| format!("{}: {}", o.from, o.reason))
                    .unwrap_or_default();
                Row::new(vec![
                    Cell::from(label).style(style),
                    Cell::from(p.proposer.clone()),
                    Cell::from(format!("{} [{}] {holds}", p.action, p.resources.join(","))),
                ])
            })
            .collect();
        let table = Table::new(
            rows,
            [
                Constraint::Length(5),
                Constraint::Length(16),
                Constraint::Min(10),
            ],
        )
        .header(
            Row::new(vec!["state", "by", "action [resources] hold"])
                .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(self.board_title("proposals/HOLDs")),
        );
        frame.render_widget(table, area);
    }

    fn draw_leases(&self, frame: &mut Frame, area: Rect) {
        let now = runtime::unix_now();
        let rows: Vec<Row> = self
            .board
            .leases
            .iter()
            .map(|l| {
                Row::new(vec![
                    Cell::from(l.resource.clone()),
                    Cell::from(l.holder.clone()),
                    Cell::from(board::fmt_age(l.remaining(now))),
                ])
            })
            .collect();
        let table = Table::new(
            rows,
            [
                Constraint::Min(8),
                Constraint::Min(10),
                Constraint::Length(6),
            ],
        )
        .header(
            Row::new(vec!["resource", "holder", "left"])
                .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(self.board_title("leases")),
        );
        frame.render_widget(table, area);
    }

    fn draw_agents(&self, frame: &mut Frame, area: Rect) {
        let rows: Vec<Row> = self
            .board
            .agents
            .iter()
            .map(|a| {
                let style = match a.status {
                    AgentStatus::Stuck => {
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
                    }
                    AgentStatus::Active => Style::default().fg(Color::Green),
                    AgentStatus::Idle => Style::default().fg(Color::Yellow),
                    AgentStatus::Gone => Style::default().fg(Color::DarkGray),
                };
                let mut holds: Vec<String> = a.claims.iter().map(|c| format!("task {c}")).collect();
                holds.extend(a.leases.iter().cloned());
                Row::new(vec![
                    Cell::from(a.status.as_str()).style(style),
                    Cell::from(a.agent.clone()),
                    Cell::from(holds.join(", ")),
                    Cell::from(a.why.clone()),
                ])
            })
            .collect();
        let stuck = self
            .board
            .agents
            .iter()
            .filter(|a| a.status == AgentStatus::Stuck)
            .count();
        let title = format!(
            " agents {} ({stuck} stuck; heartbeats alone never count as active) ",
            self.board.agents.len()
        );
        let table = Table::new(
            rows,
            [
                Constraint::Length(6),
                Constraint::Length(28),
                Constraint::Length(30),
                Constraint::Min(10),
            ],
        )
        .header(
            Row::new(vec!["status", "agent", "holds", "why"])
                .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .block(Block::default().borders(Borders::ALL).title(title));
        frame.render_widget(table, area);
    }

    fn draw_status(&self, frame: &mut Frame, area: Rect) {
        let line = if let Some(text) = &self.compose {
            let to = self
                .selected
                .as_ref()
                .map(|id| self.label(id))
                .unwrap_or_default();
            Line::from(vec![
                Span::styled(
                    format!(" to {to} > "),
                    Style::default().fg(Color::Black).bg(Color::Yellow),
                ),
                Span::raw(format!(" {text}▏ (Enter send, Esc cancel)")),
            ])
        } else {
            let mode = match &self.write_as {
                None => Span::styled(
                    " READ-ONLY ",
                    Style::default().fg(Color::Black).bg(Color::Green),
                ),
                Some(id) => Span::styled(
                    format!(" WRITE as {id} "),
                    Style::default().fg(Color::Black).bg(Color::Red),
                ),
            };
            let events: usize = self.rooms.values().map(|v| v.events.len()).sum();
            Line::from(vec![
                mode,
                Span::raw(format!(
                    " {} rooms, {events} events  {}  ? help  q quit",
                    self.rooms.len(),
                    self.status
                )),
            ])
        };
        frame.render_widget(Paragraph::new(line), area);
    }
}

fn draw_help(frame: &mut Frame, area: Rect) {
    let text = vec![
        Line::from("agora tui: keys"),
        Line::from(""),
        Line::from("↑/k ↓/j Tab  previous / next channel"),
        Line::from("a            every room and DM (merged, live)"),
        Line::from("PgUp/u PgDn/d End/G   scroll messages / back to live"),
        Line::from("b            show the selected room on the board panes"),
        Line::from("r            refold the board now"),
        Line::from("i            compose (only with --write); Enter send, Esc cancel"),
        Line::from("q Ctrl-C     quit        ? Esc  close this help"),
        Line::from(""),
        Line::from("Read-only by default: no heartbeats, receipts or check."),
        Line::from("stuck: claimed task, no checkpoint for 45m. active: non-heartbeat"),
        Line::from("activity in 10m. idle: seen in 2h. gone: not seen for 2h."),
    ];
    let w = 72.min(area.width);
    let h = (text.len() as u16 + 2).min(area.height);
    let rect = Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    );
    frame.render_widget(Clear, rect);
    frame.render_widget(
        Paragraph::new(text).block(Block::default().borders(Borders::ALL).title(" help ")),
        rect,
    );
}

fn truncate(s: &str, width: usize) -> String {
    if s.chars().count() <= width {
        return s.to_string();
    }
    let mut out: String = s.chars().take(width.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Rows for one message: `HH:MM:SS [room] sender: text`, wrapped.
fn message_lines(env: &Value, room: Option<String>, width: usize) -> Vec<Line<'static>> {
    let ts = board::relay_ts(env);
    let time = chrono::DateTime::from_timestamp(ts as i64, 0)
        .map(|d| {
            d.with_timezone(&chrono::Local)
                .format("%H:%M:%S")
                .to_string()
        })
        .unwrap_or_default();
    let from = env["from"].as_str().unwrap_or("?").to_string();
    let text = env["text"].as_str().unwrap_or("").replace('\t', "  ");
    let warning = env["type"].as_str() == Some("auth_warning");
    let unsigned = env["_auth"].as_str() == Some("unsigned");
    let mut head = vec![Span::styled(
        format!("{time} "),
        Style::default().fg(Color::DarkGray),
    )];
    if let Some(room) = room {
        head.push(Span::styled(
            format!("[{room}] "),
            Style::default().fg(Color::Cyan),
        ));
    }
    if warning || unsigned {
        head.push(Span::styled(
            if warning { "[auth] " } else { "[unsigned] " },
            Style::default().fg(Color::White).bg(Color::Red),
        ));
    }
    head.push(Span::styled(
        format!("{from}: "),
        Style::default()
            .fg(sender_color(&from))
            .add_modifier(Modifier::BOLD),
    ));
    let prefix: usize = head.iter().map(|s| s.content.chars().count()).sum();
    let body_style = if warning {
        Style::default().fg(Color::Red)
    } else {
        Style::default()
    };
    let mut rows = wrap_hanging(
        &text,
        width.saturating_sub(prefix).max(10),
        width.saturating_sub(2).max(10),
    )
    .into_iter();
    let mut first = head;
    first.push(Span::styled(rows.next().unwrap_or_default(), body_style));
    std::iter::once(Line::from(first))
        .chain(rows.map(|row| Line::from(vec![Span::raw("  "), Span::styled(row, body_style)])))
        .collect()
}

/// Split `text` into rows: the first row at most `first` characters wide,
/// the rest at most `rest` (a hanging indent).
pub fn wrap_hanging(text: &str, first: usize, rest: usize) -> Vec<String> {
    let mut rows = Vec::new();
    for line in text.split('\n') {
        let chars: Vec<char> = line.chars().collect();
        let mut at = 0;
        loop {
            let width = if rows.is_empty() { first } else { rest }.max(1);
            let end = (at + width).min(chars.len());
            rows.push(chars[at..end].iter().collect());
            at = end;
            if at >= chars.len() {
                break;
            }
        }
    }
    rows
}

fn sender_color(from: &str) -> Color {
    const PALETTE: [Color; 6] = [
        Color::Green,
        Color::Cyan,
        Color::Magenta,
        Color::Yellow,
        Color::Blue,
        Color::LightRed,
    ];
    let hash = from
        .bytes()
        .fold(0u32, |h, b| h.wrapping_mul(31).wrapping_add(b as u32));
    PALETTE[hash as usize % PALETTE.len()]
}

fn slow_log(line: &str) {
    use std::io::Write;
    let path = store::agora_dir().join("tui.log");
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(f, "{} {line}", runtime::unix_now());
    }
}

// ── Readers ─────────────────────────────────────────────────────

type Running = Arc<Mutex<HashSet<String>>>;

/// Frees a room's reader slot when its thread ends (also by panic).
struct ReaderSlot {
    room_id: String,
    running: Running,
}

impl Drop for ReaderSlot {
    fn drop(&mut self) {
        self.running
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.room_id);
    }
}

/// One streaming reader per room: decrypt and hand events to the UI thread.
/// Readers only read; nothing here publishes.
fn spawn_reader(room: store::RoomEntry, since: u64, running: Running, feed: Sender<Feed>) {
    if !running
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(room.room_id.clone())
    {
        return;
    }
    let slot = ReaderSlot {
        room_id: room.room_id.clone(),
        running,
    };
    let short = room_id_short(&room.room_id);
    let name = format!("agora-tui-{short}");
    let spawned = std::thread::Builder::new().name(name).spawn(move || {
        let _slot = slot;
        let key = crypto::derive_room_key(&room.secret, &room.room_id);
        let config = transport::StreamConfig {
            reconnect: true,
            ..Default::default()
        };
        transport::stream_since_with_config(
            &room.room_id,
            &since.to_string(),
            &config,
            |ts, payload| {
                if let Some(mut env) = chat::decrypt_payload(payload, &key, &room.room_id) {
                    if env["ts"].as_u64().unwrap_or(0) == 0 {
                        env["ts"] = serde_json::json!(ts);
                    }
                    env["_relay_ts"] = serde_json::json!(ts);
                    let _ = feed.send(Feed::Event {
                        room_id: room.room_id.clone(),
                        env,
                    });
                }
            },
            |error, retry| {
                let _ = feed.send(Feed::Status(match retry {
                    Some(wait) => format!("{}: {error}; retry in {}s", room.label, wait.as_secs()),
                    None => format!("{}: {error}", room.label),
                }));
            },
        );
    });
    if let Err(e) = spawned {
        slow_log(&format!("reader for {short} not started: {e}"));
    }
}

fn room_id_short(id: &str) -> String {
    id.chars().take(12).collect()
}

fn sync_rooms(app: &mut App, since: u64, running: &Running, feed: &Sender<Feed>) {
    app.add_rooms(store::load_registry());
    for view in app.rooms.values() {
        spawn_reader(view.room.clone(), since, running.clone(), feed.clone());
    }
}

fn drain(app: &mut App, rx: &Receiver<Feed>) {
    while let Ok(feed) = rx.try_recv() {
        match feed {
            Feed::Event { room_id, env } => app.ingest(&room_id, env),
            Feed::Status(s) => app.status = s,
        }
    }
}

pub fn run(opts: Options) -> Result<(), String> {
    transport::require_relay()?;
    let write_as = opts.write.then(store::get_agent_id);
    let mut app = App::new(write_as, opts.history_secs);
    let since = runtime::unix_now().saturating_sub(opts.history_secs);
    let running: Running = Arc::new(Mutex::new(HashSet::new()));
    let (tx, rx) = channel();
    sync_rooms(&mut app, since, &running, &tx);
    let board_room = opts
        .board_room
        .or_else(|| store::get_active_room().map(|r| r.label))
        .unwrap_or_else(|| "ops".to_string());
    if !app.set_board_room(&board_room) {
        // Fall back to the first non-DM room.
        let first = app.channels().into_iter().flatten().next();
        if let Some(id) = first {
            app.set_board_room(&id);
        }
    }

    let mut terminal =
        ratatui::try_init().map_err(|e| format!("cannot start the terminal UI: {e}"))?;
    let mut last_board = Instant::now() - BOARD_EVERY;
    let mut last_scan = Instant::now();
    let result: Result<(), String> = loop {
        drain(&mut app, &rx);
        if last_scan.elapsed() >= RESCAN_EVERY {
            sync_rooms(&mut app, since, &running, &tx);
            last_scan = Instant::now();
        }
        if last_board.elapsed() >= BOARD_EVERY {
            let now = runtime::unix_now();
            app.prune(now);
            app.rebuild_board(now);
            last_board = Instant::now();
        }
        if let Err(e) = terminal.draw(|f| app.draw(f)) {
            break Err(format!("draw failed: {e}"));
        }
        match event::poll(TICK) {
            Ok(true) => match event::read() {
                Ok(Event::Key(key)) if key.kind == KeyEventKind::Press => app.key(key),
                Ok(_) => {}
                Err(e) => break Err(format!("input failed: {e}")),
            },
            Ok(false) => {}
            Err(e) => break Err(format!("input failed: {e}")),
        }
        if app.quit {
            break Ok(());
        }
    };
    ratatui::restore();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use serde_json::json;

    fn room(label: &str) -> store::RoomEntry {
        store::RoomEntry {
            room_id: format!("ag-{label}"),
            secret: "00".repeat(32),
            label: label.to_string(),
            joined_at: 0,
            topic: None,
            purpose: None,
            dm_peer: None,
            members: Vec::new(),
        }
    }

    fn msg(id: &str, from: &str, ts: u64, text: &str) -> Value {
        json!({"v": "3.0", "id": id, "from": from, "ts": ts, "_relay_ts": ts, "text": text, "_auth": "verified"})
    }

    fn screen(app: &App, w: u16, h: u16) -> String {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| app.draw(f)).unwrap();
        let buf = term.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..h {
            for x in 0..w {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    /// Keep board reads (local task store) out of the real ~/.agora.
    fn sandbox() -> runtime::TestRuntimeGuard {
        let home = std::env::temp_dir().join(format!(
            "agora-tui-unit-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&home).unwrap();
        runtime::TestRuntime::new()
            .home(&home)
            .var("AGORA_CONFIG", "/nonexistent/agora-test-config.toml")
            .var("AGORA_RELAY_URL", format!("memory://{}", home.display()))
            .now(10_000)
            .enter()
    }

    fn app() -> App {
        let mut app = App::new(None, 25 * 3600);
        app.add_rooms(vec![
            room("ops"),
            room("test-room"),
            room("dm-agent-a-agent-b"),
        ]);
        app.set_board_room("ops");
        app
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn every_room_view_merges_rooms_in_relay_order_and_dedupes() {
        let _rt = sandbox();
        let mut app = app();
        app.ingest("ag-ops", msg("m2", "agent-b", 9_002, "second in ops"));
        app.ingest(
            "ag-dm-agent-a-agent-b",
            msg("m1", "agent-a", 9_001, "first, a DM"),
        );
        app.ingest("ag-test-room", msg("m3", "agent-c", 9_003, "third"));
        app.ingest("ag-ops", msg("m2", "agent-b", 9_002, "second in ops"));
        let texts: Vec<&str> = app
            .messages()
            .iter()
            .map(|(_, e)| e["text"].as_str().unwrap())
            .collect();
        assert_eq!(texts, vec!["first, a DM", "second in ops", "third"]);
        let shown = screen(&app, 140, 40);
        assert!(shown.contains("[ops] agent-b: second in ops"), "{shown}");
        assert!(shown.contains("[dm-agent-a-agent-b] agent-a: first, a DM"));
        assert!(shown.contains("READ-ONLY"));
    }

    #[test]
    fn switching_channels_filters_and_clears_unread() {
        let _rt = sandbox();
        let mut app = app();
        app.ingest("ag-ops", msg("m1", "agent-b", 9_001, "ops chatter"));
        app.ingest("ag-test-room", msg("m2", "agent-c", 9_002, "test chatter"));
        app.ingest("ag-test-room", json!({"id": "h1", "from": "agent-c", "_relay_ts": 9_003, "v": "3.0", "text": "", "type": "heartbeat", "_auth": "verified"}));
        assert_eq!(
            app.rooms["ag-test-room"].unread, 1,
            "heartbeats are not unread messages"
        );
        app.key(key(KeyCode::Down)); // ops
        app.key(key(KeyCode::Down)); // test-room
        assert_eq!(app.selected.as_deref(), Some("ag-test-room"));
        assert_eq!(app.rooms["ag-test-room"].unread, 0);
        assert_eq!(
            app.board_room.as_deref(),
            Some("ag-test-room"),
            "the board follows a selected room"
        );
        let shown = screen(&app, 140, 40);
        assert!(shown.contains("agent-c: test chatter"));
        assert!(!shown.contains("ops chatter"));
        app.key(key(KeyCode::Down)); // the DM: board stays on test-room
        assert_eq!(app.selected.as_deref(), Some("ag-dm-agent-a-agent-b"));
        assert_eq!(app.board_room.as_deref(), Some("ag-test-room"));
        app.key(key(KeyCode::Char('a')));
        assert_eq!(app.selected, None);
    }

    #[test]
    fn read_only_refuses_compose_and_write_mode_needs_a_channel() {
        let _rt = sandbox();
        let mut app = app();
        app.key(key(KeyCode::Char('i')));
        assert!(app.compose.is_none());
        assert!(app.status.contains("read-only"));

        let mut app = App::new(Some("operator@host-a".to_string()), 3600);
        app.add_rooms(vec![room("ops")]);
        app.key(key(KeyCode::Char('i')));
        assert!(app.compose.is_none(), "not on 'every room'");
        app.key(key(KeyCode::Down));
        app.key(key(KeyCode::Char('i')));
        assert_eq!(app.compose.as_deref(), Some(""));
        app.key(key(KeyCode::Char('h')));
        app.key(key(KeyCode::Esc));
        assert!(app.compose.is_none());
        assert!(screen(&app, 140, 40).contains("WRITE as operator@host-a"));
    }

    #[test]
    fn auth_problems_are_flagged() {
        let _rt = sandbox();
        let mut app = app();
        let mut unsigned = msg("u1", "agent-x", 9_001, "trust me");
        unsigned["_auth"] = json!("unsigned");
        app.ingest("ag-ops", unsigned);
        app.ingest("ag-ops", json!({"v": "3.0", "id": "auth-1", "from": "[auth]", "ts": 0, "_relay_ts": 9_002,
            "type": "auth_warning", "text": "[auth] Dropped message from 'agent-y' due to invalid signature."}));
        let shown = screen(&app, 160, 40);
        assert!(shown.contains("[unsigned] agent-x: trust me"), "{shown}");
        assert!(shown.contains("[auth] [auth]: [auth] Dropped message"));
    }

    #[test]
    fn board_panes_show_the_board_room() {
        let _rt = sandbox();
        let mut app = app();
        let lease = json!({"v": "3.0", "id": "l1", "from": "agent-a", "holder": "agent-a", "ts": 9_000,
            "_relay_ts": 9_000, "_auth": "verified", "type": "lease", "action": "acquire",
            "resource": "docker", "lease_id": "lease-1", "expires": 12_600, "seq": 1, "text": ""});
        app.ingest("ag-ops", lease);
        app.rebuild_board(9_100);
        assert_eq!(app.board.leases.len(), 1);
        let shown = screen(&app, 160, 45);
        assert!(shown.contains("leases (ops)"), "{shown}");
        assert!(shown.contains("docker"));
        assert!(shown.contains("tasks 0 (ops)"));
        assert!(shown.contains("agents"));
    }

    #[test]
    fn wrap_splits_long_and_multi_line_text() {
        assert_eq!(wrap_hanging("abcdef", 4, 4), vec!["abcd", "ef"]);
        assert_eq!(wrap_hanging("ab\ncd", 10, 10), vec!["ab", "cd"]);
        assert_eq!(wrap_hanging("", 5, 5), vec![""]);
        assert_eq!(wrap_hanging("héllo", 2, 2), vec!["hé", "ll", "o"]);
        assert_eq!(wrap_hanging("abcdefgh", 3, 5), vec!["abc", "defgh"]);
        assert_eq!(wrap_hanging("ab\ncdefg", 3, 4), vec!["ab", "cdef", "g"]);
    }

    #[test]
    fn scrolling_shows_older_rows() {
        let _rt = sandbox();
        let mut app = app();
        for i in 0..60u64 {
            app.ingest(
                "ag-ops",
                msg(
                    &format!("m{i}"),
                    "agent-b",
                    9_000 + i,
                    &format!("line {i:02}"),
                ),
            );
        }
        let live = screen(&app, 140, 40);
        assert!(live.contains("line 59") && !live.contains("line 05"));
        app.key(key(KeyCode::PageUp));
        app.key(key(KeyCode::PageUp));
        app.key(key(KeyCode::PageUp));
        let up = screen(&app, 140, 40);
        assert!(!up.contains("line 59"), "{up}");
        assert!(up.contains("scrolled 30 up"));
        app.key(key(KeyCode::End));
        assert_eq!(app.scroll, 0);
    }
}
