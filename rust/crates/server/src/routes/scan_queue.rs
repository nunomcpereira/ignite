//! Server-wide scan admission. Every pipeline run — interactive upload,
//! `validate-all` (pre-push hook / CLI / CI / MCP), `onboard`, and the
//! GitHub Org view's org scans — takes a slot here before doing any heavy
//! work, so N users scanning at once queue up instead of all running
//! semgrep/CodeQL/trivy side by side on one machine.
//!
//! Two lanes:
//! - **user** (someone is waiting on it: pre-push hook, upload, onboard,
//!   a single "Scan now") may take any free slot and always goes before
//!   every background entry;
//! - **background** (auto-rescan sweep, "Scan all", webhook baseline
//!   scans, the `scheduled-rescan`/`org-onboard` CLIs) only starts while
//!   doing so still leaves `scanQueue.userReservedSlots` slots free.
//!
//! With the defaults (3 slots, 1 reserved) that means at most 2 background
//! scans, and a background scan never starts while fewer than 2 slots are
//! free — so a user's scan finds an empty slot unless 3 user scans are
//! already running. Running scans are never paused or preempted.
//!
//! A waiting entry is only bound to a slot at the moment one frees up, so
//! reordering/removing waiting entries takes effect immediately.
//!
//! - `GET /api/scan-queue`: running scans and both waiting lanes, in order.
//! - `POST /api/scan-queue/:id/move` `{direction: up|down|top|bottom}`
//!   (within the entry's own lane).
//! - `DELETE /api/scan-queue/:id`: drop one waiting entry. A request that
//!   was waiting on it (upload, validate-all, onboard) fails with a
//!   "removed from the scan queue" error.
//! - `DELETE /api/scan-queue`: drop every waiting entry.
//!
//! In-memory and process-local: a restart empties the queue (the hourly
//! sweep re-queues whatever is still stale; a waiting HTTP caller's
//! connection drops with the process anyway).
use crate::auth::RequireAuth;
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use ignite_scheduled_rescan::RescanTarget;
use once_cell::sync::{Lazy, OnceCell};
use parking_lot::Mutex;
use serde::Deserialize;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Header an in-process org scan sends on its own `validate-all` call to
/// say "this run already holds a slot" (see `lease_is_active`).
pub(crate) const LEASE_HEADER: &str = "x-ignite-scan-lease";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Priority {
    User,
    Background,
}

impl Priority {
    fn as_str(self) -> &'static str {
        match self {
            Priority::User => "user",
            Priority::Background => "background",
        }
    }
}

/// What the entry is, for the queue panel and the org view's status column.
#[derive(Debug, Clone)]
pub(crate) struct ScanInfo {
    pub org: String,
    pub repo: String,
    /// `upload`, `validate-all`, `onboard`, `manual`, `scan-all`, `auto-rescan`, ...
    pub source: &'static str,
    pub actor: Option<String>,
}

enum Starter {
    /// An HTTP request is awaiting its slot.
    Waiter(tokio::sync::oneshot::Sender<ScanLease>),
    /// An org-repo scan the queue runs itself once it gets a slot.
    /// `app_token`: `token` is a GitHub App installation token, which
    /// expires after ~1h, so a fresh one is minted when the scan starts.
    Org { target: RescanTarget, token: String, app_token: bool, sweep: bool, background: bool },
}

struct Entry {
    id: u64,
    info: ScanInfo,
    enqueued_at: DateTime<Utc>,
    starter: Starter,
}

struct Running {
    priority: Priority,
    info: ScanInfo,
    started_at: DateTime<Utc>,
}

#[derive(Default)]
struct Scheduler {
    user: VecDeque<Entry>,
    background: VecDeque<Entry>,
    running: HashMap<String, Running>,
    capacity: usize,
    reserved: usize,
}

impl Scheduler {
    fn lane(&mut self, p: Priority) -> &mut VecDeque<Entry> {
        match p {
            Priority::User => &mut self.user,
            Priority::Background => &mut self.background,
        }
    }

    fn find(&self, id: u64) -> Option<(Priority, usize)> {
        if let Some(i) = self.user.iter().position(|e| e.id == id) {
            return Some((Priority::User, i));
        }
        self.background.iter().position(|e| e.id == id).map(|i| (Priority::Background, i))
    }
}

static SCHED: Lazy<Mutex<Scheduler>> = Lazy::new(|| Mutex::new(Scheduler { capacity: 1, ..Default::default() }));
static STATE: OnceCell<Arc<AppState>> = OnceCell::new();
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Which lane may start next given the current load, or `None` if nothing
/// can start. Pure so the slot rule is unit-testable.
fn next_lane(capacity: usize, reserved: usize, running: usize, user_waiting: bool, background_waiting: bool) -> Option<Priority> {
    let free = capacity.saturating_sub(running);
    if free == 0 {
        return None;
    }
    if user_waiting {
        return Some(Priority::User);
    }
    if background_waiting && free > reserved {
        return Some(Priority::Background);
    }
    None
}

/// Sizes the scheduler from config and remembers the app state (needed to
/// start org scans). Idempotent; called on every enqueue/acquire.
fn init(state: &Arc<AppState>) {
    let _ = STATE.set(state.clone());
    let cfg = &state.config.scan_queue;
    let capacity = cfg.max_concurrent.max(1) as usize;
    let reserved = (cfg.user_reserved_slots as usize).min(capacity - 1);
    let mut s = SCHED.lock();
    s.capacity = capacity;
    s.reserved = reserved;
}

/// A held slot. Dropping it frees the slot and starts the next entry.
pub(crate) struct ScanLease {
    id: String,
}

impl ScanLease {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }
}

impl Drop for ScanLease {
    fn drop(&mut self) {
        SCHED.lock().running.remove(&self.id);
        dispatch();
    }
}

/// Starts as many waiting entries as the slot rule allows. Channel sends and
/// task spawns happen after the lock is released: a failed send drops the
/// lease, and `ScanLease::drop` re-enters the lock.
fn dispatch() {
    let mut started: Vec<(Entry, ScanLease)> = Vec::new();
    {
        let mut s = SCHED.lock();
        while let Some(lane) = next_lane(s.capacity, s.reserved, s.running.len(), !s.user.is_empty(), !s.background.is_empty()) {
            let Some(entry) = s.lane(lane).pop_front() else { break };
            let lease = uuid::Uuid::new_v4().to_string();
            s.running.insert(lease.clone(), Running { priority: lane, info: entry.info.clone(), started_at: Utc::now() });
            started.push((entry, ScanLease { id: lease }));
        }
    }
    for (entry, lease) in started {
        match entry.starter {
            // The receiver is gone when the waiting request was cancelled;
            // the returned lease is dropped here, freeing the slot again.
            Starter::Waiter(tx) => drop(tx.send(lease)),
            Starter::Org { target, token, app_token, sweep, background: lane_is_background } => {
                let Some(state) = STATE.get().cloned() else { continue };
                tokio::spawn(async move {
                    if sweep && !state.db.is_auto_rescan_repo_selected(&target.org, &target.repo) {
                        tracing::info!("auto-rescan: skipping {}/{} — removed from the auto-rescan selection while queued", target.org, target.repo);
                        return;
                    }
                    let token = if app_token { crate::auth::github_app_token(&state, &target.org).await.unwrap_or(token) } else { token };
                    let server_base = super::org_repos::resolve_server_base(&state);
                    super::org_repos::run_and_record_scan(&state.runner, &server_base, &token, &target, &state.db, lease.id(), lane_is_background).await;
                    drop(lease);
                });
            }
        }
    }
}

/// Removes a waiting entry if its request stops waiting (client gone,
/// handler future dropped) before it got a slot.
struct WaitGuard(u64);
impl Drop for WaitGuard {
    fn drop(&mut self) {
        let mut s = SCHED.lock();
        if let Some((lane, i)) = s.find(self.0) {
            s.lane(lane).remove(i);
        }
    }
}

/// Called by a waiting request each time its position might have changed.
pub(crate) type PositionFn = Box<dyn Fn(usize) + Send>;

/// Waits for a slot. `Err` means the entry was removed from the queue
/// (by someone in the queue panel) before it started.
pub(crate) async fn acquire(state: &Arc<AppState>, priority: Priority, info: ScanInfo, on_queued: Option<PositionFn>) -> Result<ScanLease, String> {
    init(state);
    let (tx, rx) = tokio::sync::oneshot::channel();
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let label = format!("{}/{}", info.org, info.repo);
    SCHED.lock().lane(priority).push_back(Entry { id, info, enqueued_at: Utc::now(), starter: Starter::Waiter(tx) });
    dispatch();
    let guard = WaitGuard(id);
    if let Some(report) = on_queued {
        if let Some(pos) = position_of(id) {
            tracing::info!("scan queue: {label} waiting ({} priority, position {pos})", priority.as_str());
            report(pos);
        }
    }
    let result = rx.await.map_err(|_| "Removed from the scan queue before it started.".to_string());
    drop(guard);
    result
}

/// 1-based overall position (user lane first) of a waiting entry.
fn position_of(id: u64) -> Option<usize> {
    let s = SCHED.lock();
    s.user.iter().chain(s.background.iter()).position(|e| e.id == id).map(|i| i + 1)
}

/// True when `lease` is a slot currently held — lets an org scan's own
/// `validate-all` call skip queueing a second time. Lease ids are random
/// UUIDs only ever handed to in-process tasks.
pub(crate) fn lease_is_active(lease: &str) -> bool {
    SCHED.lock().running.contains_key(lease)
}

/// Resolves the slot for an incoming pipeline request: `Ok(None)` when it
/// already holds one (an org scan's `X-Ignite-Scan-Lease`), otherwise waits.
pub(crate) async fn acquire_for_request(state: &Arc<AppState>, headers: &axum::http::HeaderMap, priority: Priority, info: ScanInfo) -> Result<Option<ScanLease>, String> {
    if let Some(lease) = headers.get(LEASE_HEADER).and_then(|v| v.to_str().ok()) {
        if lease_is_active(lease) {
            return Ok(None);
        }
    }
    acquire(state, priority, info, None).await.map(Some)
}

/// Server-set body field carrying the caller's email into the queue panel.
pub(crate) const ACTOR_FIELD: &str = "_queueActor";

/// Overwrites (or removes) `ACTOR_FIELD` so a client can never supply it.
pub(crate) fn set_actor(body: &mut serde_json::Value, email: Option<&str>) {
    if let Some(obj) = body.as_object_mut() {
        match email {
            Some(e) => {
                obj.insert(ACTOR_FIELD.to_string(), serde_json::json!(e));
            }
            None => {
                obj.remove(ACTOR_FIELD);
            }
        }
    }
}

/// `"background"` in a request body lowers its priority. Callers can only
/// ever lower their own priority this way, never raise it.
pub(crate) fn priority_from_body(body: &serde_json::Value) -> Priority {
    match body.get("priority").and_then(|v| v.as_str()) {
        Some("background") => Priority::Background,
        _ => Priority::User,
    }
}

pub(super) fn scan_key(org: &str, repo: &str) -> (String, String) {
    (org.to_ascii_lowercase(), repo.to_ascii_lowercase())
}

/// True while a scan of this repo is queued or executing — a second
/// trigger (double click, overlapping sweep) is dropped instead of stacked.
pub(super) fn is_scan_active(org: &str, repo: &str) -> bool {
    let k = scan_key(org, repo);
    let s = SCHED.lock();
    s.running.values().any(|r| scan_key(&r.info.org, &r.info.repo) == k) || s.user.iter().chain(s.background.iter()).any(|e| scan_key(&e.info.org, &e.info.repo) == k)
}

/// Lowercased `(org, repo)` keys of every waiting entry.
pub(super) fn queued_keys() -> Vec<(String, String)> {
    let s = SCHED.lock();
    s.user.iter().chain(s.background.iter()).map(|e| scan_key(&e.info.org, &e.info.repo)).collect()
}

/// Lowercased `(org, repo)` keys of every executing scan.
pub(super) fn running_keys() -> Vec<(String, String)> {
    SCHED.lock().running.values().map(|r| scan_key(&r.info.org, &r.info.repo)).collect()
}

/// True when a new user-priority entry would have to wait.
pub(super) fn user_would_wait() -> bool {
    let s = SCHED.lock();
    !s.user.is_empty() || s.running.len() >= s.capacity
}

/// Appends org-repo scans to a lane (skipping any repo already queued or
/// running) and starts what the slot rule allows. Returns how many were added.
pub(super) fn enqueue_org_scans(state: &Arc<AppState>, token: &str, app_token: bool, targets: Vec<RescanTarget>, priority: Priority, sweep: bool, source: &'static str) -> usize {
    init(state);
    let mut added = 0;
    for target in targets {
        if is_scan_active(&target.org, &target.repo) {
            continue;
        }
        let info = ScanInfo { org: target.org.clone(), repo: target.repo.clone(), source, actor: None };
        let entry = Entry { id: NEXT_ID.fetch_add(1, Ordering::Relaxed), info, enqueued_at: Utc::now(), starter: Starter::Org { target, token: token.to_string(), app_token, sweep, background: priority == Priority::Background } };
        SCHED.lock().lane(priority).push_back(entry);
        added += 1;
    }
    if added > 0 {
        dispatch();
    }
    added
}

fn info_json(info: &ScanInfo) -> serde_json::Value {
    serde_json::json!({ "org": info.org, "repo": info.repo, "source": info.source, "actor": info.actor })
}

pub(super) fn queue_json() -> serde_json::Value {
    let s = SCHED.lock();
    let mut running: Vec<&Running> = s.running.values().collect();
    running.sort_by_key(|r| r.started_at);
    let running: Vec<serde_json::Value> = running
        .into_iter()
        .map(|r| {
            let mut v = info_json(&r.info);
            v["priority"] = serde_json::json!(r.priority.as_str());
            v["startedAt"] = serde_json::json!(r.started_at.to_rfc3339());
            v
        })
        .collect();
    let lane_json = |lane: &VecDeque<Entry>, p: Priority, offset: usize| -> Vec<serde_json::Value> {
        lane.iter()
            .enumerate()
            .map(|(i, e)| {
                let mut v = info_json(&e.info);
                v["id"] = serde_json::json!(e.id);
                v["position"] = serde_json::json!(offset + i + 1);
                v["priority"] = serde_json::json!(p.as_str());
                v["enqueuedAt"] = serde_json::json!(e.enqueued_at.to_rfc3339());
                v
            })
            .collect()
    };
    let user = lane_json(&s.user, Priority::User, 0);
    let background = lane_json(&s.background, Priority::Background, s.user.len());
    let queued: Vec<serde_json::Value> = user.into_iter().chain(background).collect();
    serde_json::json!({ "maxConcurrent": s.capacity, "userReservedSlots": s.reserved, "running": running, "queued": queued })
}

async fn get_queue(State(state): State<Arc<AppState>>, RequireAuth(_user): RequireAuth) -> Response {
    init(&state);
    Json(queue_json()).into_response()
}

async fn clear_queue(State(state): State<Arc<AppState>>, RequireAuth(user): RequireAuth) -> Response {
    init(&state);
    // Dropping the entries (outside the lock) drops each waiter's sender,
    // which fails that request with "removed from the scan queue".
    let removed: Vec<Entry> = {
        let mut s = SCHED.lock();
        let mut all: Vec<Entry> = s.user.drain(..).collect();
        all.extend(s.background.drain(..));
        all
    };
    tracing::info!("scan queue: {} cleared {} waiting scan(s)", user.email, removed.len());
    let count = removed.len();
    drop(removed);
    let mut body = queue_json();
    body["removed"] = serde_json::json!(count);
    Json(body).into_response()
}

const NOT_WAITING: &str = "That scan is no longer waiting in the queue (it may have started).";

async fn remove_entry(State(state): State<Arc<AppState>>, RequireAuth(user): RequireAuth, Path(id): Path<u64>) -> Response {
    init(&state);
    let removed = {
        let mut s = SCHED.lock();
        match s.find(id) {
            Some((lane, i)) => s.lane(lane).remove(i),
            None => None,
        }
    };
    match removed {
        Some(e) => {
            tracing::info!("scan queue: {} removed {}/{} ({})", user.email, e.info.org, e.info.repo, e.info.source);
            drop(e);
            Json(queue_json()).into_response()
        }
        None => (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": NOT_WAITING }))).into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct MoveBody {
    direction: String,
}

/// New index for an entry at `from` in a lane of `len`, or `None` for an
/// unknown direction.
fn move_target(from: usize, len: usize, direction: &str) -> Option<usize> {
    let last = len.saturating_sub(1);
    Some(match direction {
        "up" => from.saturating_sub(1),
        "down" => (from + 1).min(last),
        "top" => 0,
        "bottom" => last,
        _ => return None,
    })
}

async fn move_entry(State(state): State<Arc<AppState>>, RequireAuth(_user): RequireAuth, Path(id): Path<u64>, Json(body): Json<MoveBody>) -> Response {
    init(&state);
    {
        let mut s = SCHED.lock();
        let Some((lane, from)) = s.find(id) else {
            return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": NOT_WAITING }))).into_response();
        };
        let q = s.lane(lane);
        let Some(to) = move_target(from, q.len(), &body.direction) else {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "direction must be one of up, down, top, bottom." }))).into_response();
        };
        if let Some(entry) = q.remove(from) {
            q.insert(to, entry);
        }
    }
    Json(queue_json()).into_response()
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/scan-queue", get(get_queue).delete(clear_queue))
        .route("/api/scan-queue/:id", delete(remove_entry))
        .route("/api/scan-queue/:id/move", post(move_entry))
}

#[cfg(test)]
mod tests {
    use super::{move_target, next_lane, Priority};

    #[test]
    fn move_target_clamps_at_both_ends() {
        assert_eq!(move_target(0, 3, "up"), Some(0));
        assert_eq!(move_target(2, 3, "down"), Some(2));
        assert_eq!(move_target(1, 3, "up"), Some(0));
        assert_eq!(move_target(1, 3, "down"), Some(2));
        assert_eq!(move_target(2, 3, "top"), Some(0));
        assert_eq!(move_target(0, 3, "bottom"), Some(2));
        assert_eq!(move_target(0, 3, "sideways"), None);
    }

    // 3 slots, 1 kept for users.
    #[test]
    fn background_scans_always_leave_one_slot_for_users() {
        // Idle: background fills up to 2, never the 3rd.
        assert_eq!(next_lane(3, 1, 0, false, true), Some(Priority::Background));
        assert_eq!(next_lane(3, 1, 1, false, true), Some(Priority::Background));
        assert_eq!(next_lane(3, 1, 2, false, true), None);
        // 2 background + 1 user running, one background finishes (2 running):
        // the freed slot stays empty.
        assert_eq!(next_lane(3, 1, 2, false, true), None);
        // 2 users running: the 3rd slot is the buffer.
        assert_eq!(next_lane(3, 1, 2, false, true), None);
        // 1 user running: one background may start.
        assert_eq!(next_lane(3, 1, 1, false, true), Some(Priority::Background));
    }

    #[test]
    fn users_take_any_free_slot_and_go_first() {
        assert_eq!(next_lane(3, 1, 2, true, true), Some(Priority::User));
        assert_eq!(next_lane(3, 1, 0, true, true), Some(Priority::User));
        assert_eq!(next_lane(3, 1, 3, true, true), None);
    }

    fn info(repo: &str) -> super::ScanInfo {
        super::ScanInfo { org: "acme".into(), repo: repo.into(), source: "test", actor: None }
    }

    fn running_count() -> usize {
        super::SCHED.lock().running.len()
    }

    /// Spawns a waiter and returns a receiver for its outcome.
    fn spawn_waiter(state: &std::sync::Arc<crate::state::AppState>, p: Priority, repo: &str) -> tokio::sync::oneshot::Receiver<Result<super::ScanLease, String>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let state = state.clone();
        let info = info(repo);
        tokio::spawn(async move {
            let _ = tx.send(super::acquire(&state, p, info, None).await);
        });
        rx
    }

    async fn settle() {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    // nextest runs each test in its own process, so the global scheduler
    // is fresh here.
    #[tokio::test]
    async fn user_scans_keep_a_free_slot_and_background_waits_for_two() {
        let db_dir = tempfile::tempdir().unwrap();
        let db = ignite_db_store::DbStore::open(&db_dir.path().join("t.db")).unwrap();
        let mut config = ignite_config::Config::default();
        config.scan_queue = ignite_config::ScanQueueConfig { max_concurrent: 3, user_reserved_slots: 1 };
        let state = std::sync::Arc::new(crate::state::test_state(db, config));

        // Three background scans: only two start.
        let b1 = spawn_waiter(&state, Priority::Background, "b1");
        let b2 = spawn_waiter(&state, Priority::Background, "b2");
        let mut b3 = spawn_waiter(&state, Priority::Background, "b3");
        settle().await;
        let b1 = b1.await.unwrap().unwrap();
        let _b2 = b2.await.unwrap().unwrap();
        assert_eq!(running_count(), 2);
        assert!(b3.try_recv().is_err(), "third background scan must wait");

        // A user scan takes the buffer slot straight away.
        let u1 = super::acquire(&state, Priority::User, info("u1"), None).await.unwrap();
        assert_eq!(running_count(), 3);

        // A background scan finishes: 1 background + 1 user running, one
        // slot free — kept for users, so b3 still waits.
        drop(b1);
        settle().await;
        assert_eq!(running_count(), 2);
        assert!(b3.try_recv().is_err(), "the freed slot stays free for users");

        // Another user scan arrives and takes it.
        let u2 = super::acquire(&state, Priority::User, info("u2"), None).await.unwrap();
        assert_eq!(running_count(), 3);

        // Users go first even when a background scan waited longer.
        let mut u3 = spawn_waiter(&state, Priority::User, "u3");
        settle().await;
        drop(u1);
        settle().await;
        let u3 = u3.try_recv().expect("user waiter started first").unwrap();
        assert!(b3.try_recv().is_err());

        // Two users + one background running; users finish until two slots
        // are free, then b3 starts.
        drop(u2);
        settle().await;
        assert!(b3.try_recv().is_err(), "only one slot free: still reserved");
        drop(u3);
        settle().await;
        assert!(b3.try_recv().unwrap().is_ok(), "two slots free: background may start");
    }

    #[tokio::test]
    async fn removing_a_waiting_entry_fails_its_request() {
        let db_dir = tempfile::tempdir().unwrap();
        let db = ignite_db_store::DbStore::open(&db_dir.path().join("t.db")).unwrap();
        let mut config = ignite_config::Config::default();
        config.scan_queue = ignite_config::ScanQueueConfig { max_concurrent: 1, user_reserved_slots: 0 };
        let state = std::sync::Arc::new(crate::state::test_state(db, config));

        let _running = super::acquire(&state, Priority::User, info("a"), None).await.unwrap();
        let waiter = spawn_waiter(&state, Priority::User, "b");
        settle().await;
        let id = super::SCHED.lock().user.front().unwrap().id;
        let removed = { let mut s = super::SCHED.lock(); s.user.remove(0) };
        assert_eq!(removed.map(|e| e.id), Some(id));
        assert!(waiter.await.unwrap().is_err());
    }

    #[test]
    fn a_single_slot_still_runs_background_work() {
        // Reserved is clamped to capacity-1 by init; with 0 reserved the
        // only slot is shared.
        assert_eq!(next_lane(1, 0, 0, false, true), Some(Priority::Background));
    }
}
