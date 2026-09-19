//! `GET /api/org-repos/:org` — the web UI's "GitHub Org" view: explore
//! every repo in a connected GitHub org and force a scan on any of them,
//! for an org that already has hundreds of repos on GitHub Ignite never
//! saw a single upload/push/webhook for (so nothing else in this codebase
//! ever discovered them). Discovery itself never writes to `ignite.db` —
//! it's read-only, backed by `ignite_org_onboard::discover_org`'s
//! paginated `GET orgs/{org}/repos` (same crate the standalone
//! `org-onboard` CLI uses; this route is that same discovery step, just
//! reachable from the browser instead of a terminal).
//!
//! Each discovered repo is annotated with whatever Ignite already knows
//! about it (`known`/`status`/`lastScanAt`/`findingsCount`/`latestJobId`/
//! `latestProjectId`, sourced from `DbStore::list_onboarded_repo_summaries`
//! the same way the Onboarded Repos view already reads them — including a
//! `status` of `"running"` for a scan still in flight, since that query's
//! `MAX(id)`-per-`(org,repo)` join picks up the latest project row
//! regardless of whether it has finished) so the UI can show "never
//! scanned" vs. "scanning…" vs. "last scanned 3 days ago" by polling this
//! same endpoint, without a second round trip or a separate status API.
//!
//! `POST /api/org-repos/:org/:repo/scan` is the *asynchronous* forced-scan
//! trigger this view uses — deliberately a different endpoint from
//! `POST /api/onboarded-repos/:org/:repo/rescan` (which stays unchanged,
//! still synchronous, since the Onboarded Repos view's own "Scan now"
//! button already depends on that blocking-until-done shape). A real full
//! scan is a 5-16+ minute `rescan_one` call (clone -> validate-all ->
//! github-check); blocking an HTTP response on that is fine for one repo
//! from the Onboarded Repos table, but the whole point of the GitHub Org
//! view is exploring/scanning across a few hundred repos, where a
//! synchronous button would just hang the tab. This route instead spawns
//! `rescan_one` in the background (`tokio::spawn`, the same
//! fire-and-forget convention `routes/repository_events_webhook.rs`'s
//! baseline-scan step already uses) and returns `202 Accepted`
//! immediately; the frontend polls `GET /api/org-repos/:org` afterward to
//! watch `status` move from absent -> `"running"` -> a terminal state.
//! `validate-all` itself creates the real `projects` row moments after
//! the spawn starts, which is exactly what makes the scan show up in the
//! existing "Recent Checks" history feed too — no extra wiring needed for
//! that.
use crate::auth::{resolve_effective_github_token, RequireAuth};
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ignite_github_api::GithubApi;
use ignite_org_onboard::discover_org;
use ignite_scheduled_rescan::{auto_fix_mode_from_env, rescan_one, RescanTarget};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// A scan that fails before `validate-all`'s `create_project` ever runs
/// (a clone/auth failure, a bad default-branch lookup — exactly what
/// happened diagnosing a real GitHub SSO-enforcement 404 while building
/// this) leaves **no** `projects` row at all, so `list_onboarded_repo_summaries`
/// has nothing to report and the repo's row would otherwise silently
/// revert from "Scanning…" straight back to "Never scanned" with zero
/// trace — a real gap, not just this one SSO case. This process-local,
/// best-effort map is what closes it: `scan_org_repo`'s spawned task
/// records the outcome here, and `list_org_repos` folds a still-recent
/// failure into the row it returns. Deliberately not persisted to
/// `ignite.db` — this is a "did the attempt I just kicked off fail"
/// signal for the operator watching this screen right now, not a durable
/// audit record (a *successful* run already gets one, via the real
/// `projects` row `validate-all` creates). Cleared the moment a fresh
/// scan is kicked off for that repo, so retrying never shows a stale error.
static RECENT_SCAN_FAILURES: Lazy<Mutex<HashMap<(String, String), String>>> = Lazy::new(|| Mutex::new(HashMap::new()));

/// Repos whose `rescan_one` is executing right now. The real `projects`
/// row only appears once `validate-all` starts (after the clone), so
/// without this a poll landing in that gap reports no status and the UI
/// flips "Scanning…" back to "Never scanned" (or a stale old status).
static IN_FLIGHT_SCANS: Lazy<Mutex<std::collections::HashSet<(String, String)>>> = Lazy::new(|| Mutex::new(std::collections::HashSet::new()));

/// Repos accepted for scanning but still waiting for a free slot (see
/// `enqueue_scans`); reported as status `"queued"`.
static QUEUED_SCANS: Lazy<Mutex<std::collections::HashSet<(String, String)>>> = Lazy::new(|| Mutex::new(std::collections::HashSet::new()));

/// Global cap on concurrently executing scans, sized once from
/// `orgRepos.maxConcurrentScans`. A tokio `Semaphore` hands out permits
/// FIFO, so the queue order is the order scans were requested in.
static SCAN_SLOTS: once_cell::sync::OnceCell<Arc<tokio::sync::Semaphore>> = once_cell::sync::OnceCell::new();

fn scan_slots(max: u32) -> Arc<tokio::sync::Semaphore> {
    SCAN_SLOTS.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(max.max(1) as usize))).clone()
}

fn scan_key(org: &str, repo: &str) -> (String, String) {
    (org.to_ascii_lowercase(), repo.to_ascii_lowercase())
}

/// True while a scan of this repo is queued or executing — a second
/// trigger (double click, overlapping sweep) is dropped instead of stacked.
fn is_scan_active(org: &str, repo: &str) -> bool {
    let k = scan_key(org, repo);
    IN_FLIGHT_SCANS.lock().contains(&k) || QUEUED_SCANS.lock().contains(&k)
}

/// Removes the repo from `IN_FLIGHT_SCANS` on drop, so a panicking scan
/// task can't leave it stuck on "Scanning…" forever.
struct InFlightGuard((String, String));
impl Drop for InFlightGuard {
    fn drop(&mut self) {
        IN_FLIGHT_SCANS.lock().remove(&self.0);
    }
}

#[derive(Debug, Deserialize)]
struct DiscoverQuery {
    #[serde(default, rename = "includeArchived")]
    include_archived: bool,
    #[serde(default, rename = "includeForks")]
    include_forks: bool,
}

/// Everything Ignite itself knows about one repo's scans (as opposed to
/// what GitHub says exists) — served both inline with discovery and, on its
/// own, by `GET /api/org-repos/:org/status`, so the browser can cache the
/// (slow, GitHub-backed) repo list and still keep scan status live.
#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct RepoStatus {
    known: bool,
    status: Option<String>,
    last_scan_at: Option<String>,
    findings_count: Option<i64>,
    latest_job_id: Option<String>,
    latest_project_id: Option<i64>,
    scan_error: Option<String>,
    /// Full override/justification history for this repo, across every
    /// past run — same field (and same `OverrideRow` shape, deliberately
    /// still plain-snake_case, unlike this struct's own camelCase — see
    /// `OnboardedRepoSummary`'s own doc) the Onboarded Repos view already
    /// reads to power its "download acknowledgments" button, so the
    /// GitHub Org view can reuse that exact same frontend code unchanged.
    acknowledgments: Vec<ignite_db_store::OverrideRow>,
    /// Three-tier breakdown of `findings_count` — lets the UI color the
    /// findings badge by its most critical tier (error > warning > nice
    /// to have) instead of a flat count, matching Studio's own severity
    /// vocabulary. `None` whenever `findings_count` is `None`/0 (nothing
    /// to break down); see `DbStore::issue_tier_counts`.
    error_count: Option<i64>,
    warning_count: Option<i64>,
    nice_to_have_count: Option<i64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OrgRepoRow {
    org: String,
    repo: String,
    archived: bool,
    fork: bool,
    /// `size == 0` on GitHub's own repo object — surfaced straight from
    /// discovery (see `ignite_org_onboard::DiscoveredRepo::empty`'s own
    /// doc), independent of `known`/`scan_error`, so the UI can show
    /// "Empty" before a scan is ever attempted rather than only after a
    /// clone fails with a generic "remote branch not found".
    empty: bool,
    #[serde(flatten)]
    status: RepoStatus,
}

#[derive(Debug, Serialize)]
struct RepoStatusRow {
    repo: String,
    #[serde(flatten)]
    status: RepoStatus,
}

/// Scan status for every repo of `org` that Ignite has any record of (a
/// past scan, a queued/running one, or a recent failure), keyed by
/// lowercased repo name. One aggregation query, filtered in-process to this
/// org — cheaper than a per-repo DB lookup for an org with hundreds of
/// repos, and `list_onboarded_repo_summaries` already does the join work.
fn collect_repo_statuses(state: &AppState, org: &str) -> HashMap<String, RepoStatusRow> {
    let sla = &state.config.sla;
    let mut out: HashMap<String, RepoStatusRow> = HashMap::new();
    for s in state.db.list_onboarded_repo_summaries(sla.critical_days, sla.high_days, sla.medium_days).into_iter().filter(|s| s.org.eq_ignore_ascii_case(org)) {
        let (error_count, warning_count, nice_to_have_count) =
            if s.findings_count > 0 { let (e, w, n) = state.db.issue_tier_counts(s.latest_project_id); (Some(e), Some(w), Some(n)) } else { (None, None, None) };
        out.insert(
            s.repo.to_ascii_lowercase(),
            RepoStatusRow {
                repo: s.repo.clone(),
                status: RepoStatus {
                    known: true,
                    status: Some(s.status.clone()),
                    last_scan_at: Some(s.last_scan_at.clone()),
                    findings_count: Some(s.findings_count),
                    latest_job_id: Some(s.latest_job_id.clone()),
                    latest_project_id: Some(s.latest_project_id),
                    scan_error: None,
                    acknowledgments: s.acknowledgments.clone(),
                    error_count,
                    warning_count,
                    nice_to_have_count,
                },
            },
        );
    }
    let org_lc = org.to_ascii_lowercase();
    // Live state wins over whatever the last finished scan's row says.
    for (set, label) in [(QUEUED_SCANS.lock().clone(), "queued"), (IN_FLIGHT_SCANS.lock().clone(), "running")] {
        for (o, repo) in set.into_iter().filter(|(o, _)| *o == org_lc) {
            let _ = o;
            out.entry(repo.clone()).or_insert_with(|| RepoStatusRow { repo: repo.clone(), status: RepoStatus::default() }).status.status = Some(label.to_string());
        }
    }
    for ((o, repo), err) in RECENT_SCAN_FAILURES.lock().iter() {
        if o.eq_ignore_ascii_case(org) {
            out.entry(repo.to_ascii_lowercase()).or_insert_with(|| RepoStatusRow { repo: repo.clone(), status: RepoStatus::default() }).status.scan_error = Some(err.clone());
        }
    }
    out
}

/// `GET /api/org-repos/:org/status` — scan status only, no GitHub call.
/// The browser caches the repo list itself and polls this.
async fn org_repo_statuses(State(state): State<Arc<AppState>>, RequireAuth(_user): RequireAuth, Path(org): Path<String>) -> Response {
    if !ignite_github_api::is_valid_github_owner(&org) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid GitHub org name." }))).into_response();
    }
    Json(collect_repo_statuses(&state, &org).into_values().collect::<Vec<_>>()).into_response()
}

async fn list_org_repos(State(state): State<Arc<AppState>>, RequireAuth(_user): RequireAuth, headers: HeaderMap, Path(org): Path<String>, Query(q): Query<DiscoverQuery>) -> Response {
    if !ignite_github_api::is_valid_github_owner(&org) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid GitHub org name." }))).into_response();
    }
    let token = resolve_effective_github_token(&headers, &state.db);
    if token.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "No GitHub token available — connect GitHub or set GH_TOKEN/GITHUB_TOKEN on the server." })),
        )
            .into_response();
    }

    let api = GithubApi::new(&state.runner);
    let discovered = match discover_org(&api, &org, &token, q.include_archived, q.include_forks).await {
        Ok(repos) => repos,
        Err(e) => return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({ "error": format!("Failed to list repositories for {org}: {e}") }))).into_response(),
    };

    let mut statuses = collect_repo_statuses(&state, &org);
    let rows: Vec<OrgRepoRow> = discovered
        .into_iter()
        .map(|r| {
            let status = statuses.remove(&r.repo.to_ascii_lowercase()).map(|row| row.status).unwrap_or_default();
            OrgRepoRow { org: r.org, repo: r.repo, archived: r.archived, fork: r.fork, empty: r.empty, status }
        })
        .collect();

    Json(rows).into_response()
}

/// `GET repos/{full_name}` just for the one `size` field — a repo that's
/// genuinely empty (nothing ever pushed) always fails a naive clone with
/// a generic "remote branch not found" error indistinguishable from a
/// real access problem; checking this up front means the UI can say
/// "Empty" outright and this handler never even attempts (and waits out)
/// a clone that's guaranteed to fail. Best-effort: any lookup failure
/// (network hiccup, unexpected shape) just proceeds with the scan as
/// before, `rescan_one`'s own error surfaces exactly like it always did.
async fn is_empty_repo(api: &GithubApi<'_>, full_name: &str, token: &str) -> bool {
    api.gh_api_get(&format!("repos/{full_name}"), token).await.ok().flatten().and_then(|v| v.get("size").and_then(|s| s.as_i64())).map(|s| s == 0).unwrap_or(false)
}

/// Runs one `rescan_one` call and records its outcome in
/// `RECENT_SCAN_FAILURES` — the one piece of work `scan_org_repo` and
/// both `scan_selected_org_repos` modes (sequential/parallel) all need done
/// identically per repo, so it only lives in one place.
async fn run_and_record_scan(runner: &ignite_tool_runner::ToolRunner, server_base: &str, token: &str, target: &RescanTarget, db: &ignite_db_store::DbStore) {
    let http = reqwest::Client::new();
    let _in_flight = InFlightGuard(scan_key(&target.org, &target.repo));
    let outcome = rescan_one(runner, &http, server_base, token, target, auto_fix_mode_from_env()).await;
    // Org scans keep only the latest scan per repo — see
    // `DbStore::prune_superseded_scans` for what is (and isn't) deleted.
    if let Some(job_id) = &outcome.job_id {
        let pruned = db.prune_superseded_scans(job_id);
        if pruned > 0 {
            tracing::info!("org-repos scan: {}/{} pruned {pruned} superseded scan(s)", target.org, target.repo);
        }
    }
    if let Some(e) = &outcome.error {
        tracing::warn!("org-repos scan: {}/{} failed: {e}", target.org, target.repo);
        RECENT_SCAN_FAILURES.lock().insert((target.org.clone(), target.repo.clone()), e.clone());
    } else {
        tracing::info!("org-repos scan: {}/{} completed ({} issue(s))", target.org, target.repo, outcome.issue_count);
        RECENT_SCAN_FAILURES.lock().remove(&(target.org.clone(), target.repo.clone()));
    }
}

fn resolve_server_base(state: &AppState) -> String {
    let port: u16 = std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(state.config.port);
    std::env::var("IGNITE_SERVER_URL").unwrap_or_else(|_| format!("http://127.0.0.1:{port}"))
}

async fn scan_org_repo(State(state): State<Arc<AppState>>, RequireAuth(_user): RequireAuth, headers: HeaderMap, Path((org, repo)): Path<(String, String)>) -> Response {
    if !ignite_github_api::is_valid_github_owner(&org) || !ignite_github_api::is_valid_github_repo(&repo) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid GitHub org/repo name." }))).into_response();
    }
    let token = resolve_effective_github_token(&headers, &state.db);
    if token.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "No GitHub token available — connect GitHub or set GH_TOKEN/GITHUB_TOKEN on the server." })),
        )
            .into_response();
    }

    let full_name = format!("{org}/{repo}");
    let api = GithubApi::new(&state.runner);
    if is_empty_repo(&api, &full_name, &token).await {
        return (StatusCode::OK, Json(serde_json::json!({ "empty": true, "error": "Repository is empty — nothing to scan." }))).into_response();
    }

    // A fresh attempt always clears whatever an earlier attempt left
    // behind — retrying a repo that previously failed shouldn't keep
    // showing that stale error once a new scan is actually in flight.
    RECENT_SCAN_FAILURES.lock().remove(&(org.clone(), repo.clone()));

    let runner = state.runner.clone();
    let server_base = resolve_server_base(&state);
    let target = RescanTarget { org: org.clone(), repo: repo.clone() };
    if is_scan_active(&org, &repo) {
        return (StatusCode::ACCEPTED, Json(serde_json::json!({ "queued": true, "alreadyActive": true, "state": "queued", "org": org, "repo": repo }))).into_response();
    }
    let slots = scan_slots(state.config.org_repos.max_concurrent_scans);
    let state_str = if slots.available_permits() == 0 { "queued" } else { "running" };
    enqueue_scans(runner, server_base, token, vec![target], state.clone(), false, slots);

    (StatusCode::ACCEPTED, Json(serde_json::json!({ "queued": true, "state": state_str, "org": org, "repo": repo }))).into_response()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScanSelectedBody {
    #[serde(default)]
    include_archived: bool,
    #[serde(default)]
    include_forks: bool,
    orgs: Vec<SelectedOrg>,
}

#[derive(Debug, Deserialize)]
struct SelectedOrg {
    org: String,
    /// The repos left checked in the tree view for this org.
    repos: Vec<String>,
}

/// `POST /api/org-repos/scan-selected` — the "Scan all" button: scans every
/// checked repo across every org in the tree view, and saves that selection
/// (for orgs with auto-rescan on) as the daily auto-rescan set. For each org the server re-discovers its
/// repos and only ever scans the intersection of the client's list with
/// what discovery returned (never an arbitrary client-named repo); the
/// discovered-but-unchecked repos are stored as the org's exclusions, so a
/// repo created later defaults to checked/included. An org whose discovery
/// fails is skipped (reported in `failedOrgs`) and left out of the
/// enrollment, so a typo'd/inaccessible org never lands in the list.
async fn scan_selected_org_repos(State(state): State<Arc<AppState>>, RequireAuth(_user): RequireAuth, headers: HeaderMap, Json(body): Json<ScanSelectedBody>) -> Response {
    if body.orgs.is_empty() || body.orgs.iter().any(|o| !ignite_github_api::is_valid_github_owner(&o.org)) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid or missing GitHub org name." }))).into_response();
    }
    let token = resolve_effective_github_token(&headers, &state.db);
    if token.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "No GitHub token available — connect GitHub or set GH_TOKEN/GITHUB_TOKEN on the server." })),
        )
            .into_response();
    }

    let api = GithubApi::new(&state.runner);
    let mut targets: Vec<RescanTarget> = Vec::new();
    let mut failed_orgs: Vec<serde_json::Value> = Vec::new();
    for sel in &body.orgs {
        let discovered = match discover_org(&api, &sel.org, &token, body.include_archived, body.include_forks).await {
            Ok(repos) => repos,
            Err(e) => {
                failed_orgs.push(serde_json::json!({ "org": sel.org, "error": e.to_string() }));
                continue;
            }
        };
        let checked: std::collections::HashSet<String> = sel.repos.iter().map(|r| r.to_ascii_lowercase()).collect();
        let mut excluded: Vec<String> = Vec::new();
        for r in discovered.into_iter().filter(|r| !r.empty) {
            if checked.contains(&r.repo.to_ascii_lowercase()) {
                targets.push(RescanTarget { org: r.org, repo: r.repo });
            } else {
                excluded.push(r.repo);
            }
        }
        state.db.save_org(&sel.org);
        // Scan all no longer enrolls an org in auto-rescan (that's the
        // per-org toggle); it only keeps an already-enrolled org's
        // exclusions in step with what's checked.
        if state.db.list_auto_rescan_selection().iter().any(|(o, _)| o.eq_ignore_ascii_case(&sel.org)) {
            state.db.set_auto_rescan_org_selection(&sel.org, &excluded);
        }
    }
    if targets.is_empty() {
        return (StatusCode::OK, Json(serde_json::json!({ "queued": false, "count": 0, "failedOrgs": failed_orgs }))).into_response();
    }

    targets.retain(|t| !is_scan_active(&t.org, &t.repo));
    let count = targets.len();
    let slots = scan_slots(state.config.org_repos.max_concurrent_scans);
    enqueue_scans(state.runner.clone(), resolve_server_base(&state), token, targets, state.clone(), false, slots);
    (StatusCode::ACCEPTED, Json(serde_json::json!({ "queued": true, "count": count, "maxConcurrent": state.config.org_repos.max_concurrent_scans.max(1), "failedOrgs": failed_orgs }))).into_response()
}

/// Queues every target behind the global `SCAN_SLOTS` cap. All targets are
/// marked queued synchronously (so the very next poll shows "Queued"), then
/// one dispatcher task walks them in order: wait for a free slot, move the
/// repo queued -> in-flight, run it in its own task holding the slot, and
/// move straight on to waiting for the next slot — so when a scan ends the
/// next one in the queue starts. When `sweep` is set (auto-rescan),
/// a repo unchecked/removed from the auto-rescan selection while it waited
/// is skipped instead of started.
fn enqueue_scans(runner: ignite_tool_runner::ToolRunner, server_base: String, token: String, targets: Vec<RescanTarget>, state: Arc<AppState>, sweep: bool, slots: Arc<tokio::sync::Semaphore>) {
    for t in &targets {
        RECENT_SCAN_FAILURES.lock().remove(&(t.org.clone(), t.repo.clone()));
        QUEUED_SCANS.lock().insert(scan_key(&t.org, &t.repo));
    }
    tokio::spawn(async move {
        for target in targets {
            let key = scan_key(&target.org, &target.repo);
            let Ok(permit) = slots.clone().acquire_owned().await else {
                QUEUED_SCANS.lock().remove(&key);
                continue;
            };
            if sweep && !state.db.is_auto_rescan_repo_selected(&target.org, &target.repo) {
                tracing::info!("auto-rescan: skipping {}/{} — removed from the auto-rescan selection while queued", target.org, target.repo);
                QUEUED_SCANS.lock().remove(&key);
                continue;
            }
            IN_FLIGHT_SCANS.lock().insert(key.clone());
            QUEUED_SCANS.lock().remove(&key);
            let runner = runner.clone();
            let server_base = server_base.clone();
            let token = token.clone();
            let state = state.clone();
            tokio::spawn(async move {
                run_and_record_scan(&runner, &server_base, &token, &target, &state.db).await;
                drop(permit);
            });
        }
    });
}

async fn get_auto_rescan_config(State(state): State<Arc<AppState>>, RequireAuth(_user): RequireAuth) -> Response {
    Json(serde_json::json!({
        "orgs": auto_rescan_selection_json(&state),
        "savedOrgs": state.db.list_saved_orgs(),
        "staleAfterHours": state.config.org_repos.auto_rescan_stale_after_hours,
    }))
    .into_response()
}

/// `DELETE /api/org-repos/auto-rescan/orgs/:org` — takes an org back out of
/// the auto-rescan list (it is added by "Scan all"). An in-flight
/// sequential sweep notices before its next repo and skips the org's
/// remaining repos.
async fn remove_auto_rescan_org(State(state): State<Arc<AppState>>, RequireAuth(_user): RequireAuth, Path(org): Path<String>) -> Response {
    let removed = state.db.unenroll_auto_rescan_org(&org);
    state.db.unsave_org(&org);
    Json(serde_json::json!({ "removed": removed, "orgs": auto_rescan_selection_json(&state) })).into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AutoRescanToggleBody {
    enabled: bool,
    /// Repos left unchecked in the tree; only used when enabling.
    #[serde(default)]
    excluded_repos: Vec<String>,
    /// Set only by the button click that turns auto-rescan on (not by the
    /// debounced exclusion re-sync a checkbox change sends): queue every
    /// stale/never-scanned repo of the org right away.
    #[serde(default)]
    trigger_scan: bool,
}

/// `PUT /api/org-repos/auto-rescan/orgs/:org` — the per-org "Auto-rescan"
/// button. Enabling enrolls the org (with the given unchecked repos as
/// exclusions, replacing any earlier selection) and saves it in the org
/// list; disabling only takes it out of the sweep, the org stays listed.
async fn set_auto_rescan_org(State(state): State<Arc<AppState>>, RequireAuth(_user): RequireAuth, headers: HeaderMap, Path(org): Path<String>, Json(body): Json<AutoRescanToggleBody>) -> Response {
    if !ignite_github_api::is_valid_github_owner(&org) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid GitHub org name." }))).into_response();
    }
    let mut triggered = 0usize;
    if body.enabled {
        state.db.save_org(&org);
        state.db.set_auto_rescan_org_selection(&org, &body.excluded_repos);
        if body.trigger_scan {
            let token = resolve_effective_github_token(&headers, &state.db);
            if !token.is_empty() {
                let targets = collect_stale_targets(&state, &token, &[(org.clone(), body.excluded_repos.clone())]).await;
                triggered = targets.len();
                if triggered > 0 {
                    let slots = scan_slots(state.config.org_repos.max_concurrent_scans);
                    enqueue_scans(state.runner.clone(), resolve_server_base(&state), token, targets, state.clone(), true, slots);
                }
            }
        }
    } else {
        state.db.unenroll_auto_rescan_org(&org);
    }
    Json(serde_json::json!({ "orgs": auto_rescan_selection_json(&state), "triggered": triggered, "maxConcurrent": state.config.org_repos.max_concurrent_scans.max(1) })).into_response()
}

#[derive(Deserialize)]
struct SaveOrgBody {
    org: String,
}

/// `POST /api/org-repos/saved-orgs` — persists an org in the GitHub Org
/// view's list so it is still there after a reload (removed again via
/// `DELETE /api/org-repos/auto-rescan/orgs/:org`).
async fn save_org(State(state): State<Arc<AppState>>, RequireAuth(_user): RequireAuth, Json(body): Json<SaveOrgBody>) -> Response {
    let org = body.org.trim();
    if !ignite_github_api::is_valid_github_owner(org) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid GitHub org name." }))).into_response();
    }
    state.db.save_org(org);
    Json(serde_json::json!({ "savedOrgs": state.db.list_saved_orgs() })).into_response()
}

fn auto_rescan_selection_json(state: &AppState) -> Vec<serde_json::Value> {
    state.db.list_auto_rescan_selection().into_iter().map(|(org, excluded)| serde_json::json!({ "org": org, "excludedRepos": excluded })).collect()
}

/// The repos the auto-rescan should scan right now: for each `(org,
/// excluded repos)` in `selection`, every non-empty, non-archived,
/// non-forked repo that isn't excluded, isn't already queued/running, and
/// was never scanned or last scanned longer ago than
/// `orgRepos.autoRescanStaleAfterHours`. Shared by the hourly sweep and the
/// per-org "Auto-rescan on" toggle (which queues these immediately).
async fn collect_stale_targets(state: &Arc<AppState>, token: &str, selection: &[(String, Vec<String>)]) -> Vec<RescanTarget> {
    let api = GithubApi::new(&state.runner);
    let sla = &state.config.sla;
    let stale_before = chrono::Utc::now() - chrono::Duration::hours(state.config.org_repos.auto_rescan_stale_after_hours as i64);
    let stale_before_str = stale_before.format("%Y-%m-%d %H:%M:%S").to_string();
    let mut targets: Vec<RescanTarget> = Vec::new();
    for (org, excluded) in selection {
        let discovered = match discover_org(&api, org, token, false, false).await {
            Ok(repos) => repos,
            Err(e) => {
                tracing::warn!("auto-rescan: failed to list repositories for {org}: {e}");
                continue;
            }
        };
        let known: HashMap<String, ignite_db_store::OnboardedRepoSummary> =
            state.db.list_onboarded_repo_summaries(sla.critical_days, sla.high_days, sla.medium_days).into_iter().filter(|s| s.org.eq_ignore_ascii_case(org)).map(|s| (s.repo.clone(), s)).collect();
        for r in discovered {
            if r.empty || excluded.iter().any(|e| e.eq_ignore_ascii_case(&r.repo)) {
                continue;
            }
            let stale = match known.get(&r.repo) {
                // Already in flight — never pile a second sweep-triggered
                // scan onto one a human (or a previous sweep tick) already
                // started.
                Some(s) if s.status == "running" => false,
                _ if is_scan_active(&r.org, &r.repo) => false,
                Some(s) => s.last_scan_at.as_str() < stale_before_str.as_str(),
                None => true, // never scanned at all — always stale
            };
            if stale {
                targets.push(RescanTarget { org: r.org, repo: r.repo });
            }
        }
    }

    targets
}

/// `POST /api/org-repos/auto-rescan/run` — meant to be hit once an hour by
/// an external OS-level timer (launchd/cron/systemd; see
/// `docs-site/docs/ci-integration.md`'s equivalent guidance for
/// `scheduled-rescan`), the same "an unattended job authenticates with a
/// real `IGNITE_API_KEY`, which `resolve_effective_github_token` then
/// resolves through to that key's owning user's connected GitHub token"
/// pattern every other unattended entry point in this codebase already
/// uses — no separate token-provisioning story needed for this to work.
///
/// A no-op (200, `{"skipped": true}`) whenever no org is enrolled — safe
/// for the external timer to call unconditionally every hour. Sweeps every
/// org enrolled by clicking "Scan all" in the GitHub Org view
/// (`auto_rescan_orgs`, minus the repos left unchecked there), always with archived/forked repos excluded — an
/// unattended sweep should never surprise-scan something a human
/// explicitly excluded by hand there.
async fn run_auto_rescan(State(state): State<Arc<AppState>>, RequireAuth(_user): RequireAuth, headers: HeaderMap) -> Response {
    let selection = state.db.list_auto_rescan_selection();
    if selection.is_empty() {
        return Json(serde_json::json!({ "skipped": true, "reason": "no orgs enrolled (click Scan all on an org)" })).into_response();
    }
    let token = resolve_effective_github_token(&headers, &state.db);
    if token.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "No GitHub token available — connect GitHub or set GH_TOKEN/GITHUB_TOKEN on the server." })),
        )
            .into_response();
    }
    let targets = collect_stale_targets(&state, &token, &selection).await;

    if targets.is_empty() {
        return Json(serde_json::json!({ "skipped": false, "triggered": 0 })).into_response();
    }
    let count = targets.len();
    let slots = scan_slots(state.config.org_repos.max_concurrent_scans);
    enqueue_scans(state.runner.clone(), resolve_server_base(&state), token, targets, state.clone(), true, slots);
    (StatusCode::ACCEPTED, Json(serde_json::json!({ "skipped": false, "triggered": count, "maxConcurrent": state.config.org_repos.max_concurrent_scans.max(1) }))).into_response()
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/org-repos/:org", get(list_org_repos))
        .route("/api/org-repos/:org/status", get(org_repo_statuses))
        .route("/api/org-repos/scan-selected", post(scan_selected_org_repos))
        .route("/api/org-repos/:org/:repo/scan", post(scan_org_repo))
        .route("/api/org-repos/saved-orgs", post(save_org))
        .route("/api/org-repos/auto-rescan", get(get_auto_rescan_config))
        .route("/api/org-repos/auto-rescan/orgs/:org", axum::routing::delete(remove_auto_rescan_org).put(set_auto_rescan_org))
        .route("/api/org-repos/auto-rescan/run", post(run_auto_rescan))
}
