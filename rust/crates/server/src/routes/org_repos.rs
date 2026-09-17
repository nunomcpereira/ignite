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

#[derive(Debug, Deserialize)]
struct DiscoverQuery {
    #[serde(default, rename = "includeArchived")]
    include_archived: bool,
    #[serde(default, rename = "includeForks")]
    include_forks: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OrgRepoRow {
    org: String,
    repo: String,
    archived: bool,
    fork: bool,
    known: bool,
    status: Option<String>,
    last_scan_at: Option<String>,
    findings_count: Option<i64>,
    latest_job_id: Option<String>,
    latest_project_id: Option<i64>,
    scan_error: Option<String>,
    /// `size == 0` on GitHub's own repo object — surfaced straight from
    /// discovery (see `ignite_org_onboard::DiscoveredRepo::empty`'s own
    /// doc), independent of `known`/`scan_error`, so the UI can show
    /// "Empty" before a scan is ever attempted rather than only after a
    /// clone fails with a generic "remote branch not found".
    empty: bool,
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

    // One aggregation query, filtered in-process to this org — cheaper
    // than a per-repo DB lookup for an org with hundreds of repos, and
    // `list_onboarded_repo_summaries` already does the real join work.
    let sla = &state.config.sla;
    let known: HashMap<String, ignite_db_store::OnboardedRepoSummary> = state
        .db
        .list_onboarded_repo_summaries(sla.critical_days, sla.high_days, sla.medium_days)
        .into_iter()
        .filter(|s| s.org == org)
        .map(|s| (s.repo.clone(), s))
        .collect();

    let failures = RECENT_SCAN_FAILURES.lock();
    let rows: Vec<OrgRepoRow> = discovered
        .into_iter()
        .map(|r| {
            let scan_error = failures.get(&(r.org.clone(), r.repo.clone())).cloned();
            match known.get(&r.repo) {
                Some(s) => {
                    let (error_count, warning_count, nice_to_have_count) =
                        if s.findings_count > 0 { let (e, w, n) = state.db.issue_tier_counts(s.latest_project_id); (Some(e), Some(w), Some(n)) } else { (None, None, None) };
                    OrgRepoRow {
                        org: r.org,
                        repo: r.repo,
                        archived: r.archived,
                        fork: r.fork,
                        known: true,
                        status: Some(s.status.clone()),
                        last_scan_at: Some(s.last_scan_at.clone()),
                        findings_count: Some(s.findings_count),
                        latest_job_id: Some(s.latest_job_id.clone()),
                        latest_project_id: Some(s.latest_project_id),
                        scan_error,
                        empty: r.empty,
                        acknowledgments: s.acknowledgments.clone(),
                        error_count,
                        warning_count,
                        nice_to_have_count,
                    }
                }
                None => OrgRepoRow {
                    org: r.org,
                    repo: r.repo,
                    archived: r.archived,
                    fork: r.fork,
                    known: false,
                    status: None,
                    last_scan_at: None,
                    findings_count: None,
                    latest_job_id: None,
                    latest_project_id: None,
                    scan_error,
                    empty: r.empty,
                    acknowledgments: vec![],
                    error_count: None,
                    warning_count: None,
                    nice_to_have_count: None,
                },
            }
        })
        .collect();
    drop(failures);

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
/// both `scan_all_org_repos` modes (sequential/parallel) all need done
/// identically per repo, so it only lives in one place.
async fn run_and_record_scan(runner: &ignite_tool_runner::ToolRunner, server_base: &str, token: &str, target: &RescanTarget) {
    let http = reqwest::Client::new();
    let outcome = rescan_one(runner, &http, server_base, token, target, auto_fix_mode_from_env()).await;
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
    tokio::spawn(async move { run_and_record_scan(&runner, &server_base, &token, &target).await });

    (StatusCode::ACCEPTED, Json(serde_json::json!({ "queued": true, "org": org, "repo": repo }))).into_response()
}

async fn scan_all_org_repos(State(state): State<Arc<AppState>>, RequireAuth(_user): RequireAuth, headers: HeaderMap, Path(org): Path<String>, Query(q): Query<DiscoverQuery>) -> Response {
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
    let targets: Vec<RescanTarget> = discovered.into_iter().filter(|r| !r.empty).map(|r| RescanTarget { org: r.org, repo: r.repo }).collect();
    if targets.is_empty() {
        return (StatusCode::OK, Json(serde_json::json!({ "queued": false, "count": 0 }))).into_response();
    }

    for t in &targets {
        RECENT_SCAN_FAILURES.lock().remove(&(t.org.clone(), t.repo.clone()));
    }

    let runner = state.runner.clone();
    let server_base = resolve_server_base(&state);
    let count = targets.len();
    let parallel = spawn_targets(runner, server_base, token, targets, &state.config.org_repos.scan_all_mode);

    (StatusCode::ACCEPTED, Json(serde_json::json!({ "queued": true, "count": count, "mode": if parallel { "parallel" } else { "sequential" } }))).into_response()
}

/// Shared by `scan_all_org_repos` and the auto-rescan sweep below —
/// `"parallel"` is the one recognized opt-in value; anything else (unset,
/// a typo, `"sequential"` itself) fails safe to sequential, matching this
/// codebase's standing "a misconfigured config value never silently
/// escalates to the more resource-intensive behavior" convention (see
/// e.g. `auto_fix_mode_from_env`'s own doc comment). Returns whether it
/// ran parallel, for the caller's own response body.
fn spawn_targets(runner: ignite_tool_runner::ToolRunner, server_base: String, token: String, targets: Vec<RescanTarget>, mode: &str) -> bool {
    for t in &targets {
        RECENT_SCAN_FAILURES.lock().remove(&(t.org.clone(), t.repo.clone()));
    }
    let parallel = mode == "parallel";
    if parallel {
        for target in targets {
            let runner = runner.clone();
            let server_base = server_base.clone();
            let token = token.clone();
            tokio::spawn(async move { run_and_record_scan(&runner, &server_base, &token, &target).await });
        }
    } else {
        tokio::spawn(async move {
            for target in &targets {
                run_and_record_scan(&runner, &server_base, &token, target).await;
            }
        });
    }
    parallel
}

const AUTO_RESCAN_ENABLED_SETTING: &str = "auto_rescan_enabled";

async fn get_auto_rescan_config(State(state): State<Arc<AppState>>, RequireAuth(_user): RequireAuth) -> Response {
    Json(serde_json::json!({
        "enabled": state.db.get_bool_setting(AUTO_RESCAN_ENABLED_SETTING, false),
        "staleAfterHours": state.config.org_repos.auto_rescan_stale_after_hours,
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
struct SetAutoRescanBody {
    enabled: bool,
}

async fn set_auto_rescan_config(State(state): State<Arc<AppState>>, RequireAuth(_user): RequireAuth, Json(body): Json<SetAutoRescanBody>) -> Response {
    state.db.set_setting(AUTO_RESCAN_ENABLED_SETTING, if body.enabled { "true" } else { "false" });
    Json(serde_json::json!({ "enabled": body.enabled, "staleAfterHours": state.config.org_repos.auto_rescan_stale_after_hours })).into_response()
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
/// A no-op (200, `{"skipped": true}`) whenever the runtime-toggleable
/// `auto_rescan_enabled` app-setting is off — safe for the external timer
/// to call unconditionally every hour regardless of whether the feature
/// is currently switched on; the UI's own toggle is what actually decides
/// whether anything happens on a given tick, not the timer's own
/// schedule. Sweeps every org in `github.orgs` (the same comma-separated
/// config value that already seeds the main upload form's org field),
/// always with archived/forked repos excluded — an unattended sweep
/// should never surprise-scan something a human explicitly excluded by
/// hand in the GitHub Org view.
async fn run_auto_rescan(State(state): State<Arc<AppState>>, RequireAuth(_user): RequireAuth, headers: HeaderMap) -> Response {
    if !state.db.get_bool_setting(AUTO_RESCAN_ENABLED_SETTING, false) {
        return Json(serde_json::json!({ "skipped": true, "reason": "disabled" })).into_response();
    }
    let token = resolve_effective_github_token(&headers, &state.db);
    if token.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "No GitHub token available — connect GitHub or set GH_TOKEN/GITHUB_TOKEN on the server." })),
        )
            .into_response();
    }
    let orgs: Vec<String> = state.config.github.orgs.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect();
    if orgs.is_empty() {
        return Json(serde_json::json!({ "skipped": true, "reason": "no orgs configured (github.orgs)" })).into_response();
    }

    let api = GithubApi::new(&state.runner);
    let sla = &state.config.sla;
    let stale_before = chrono::Utc::now() - chrono::Duration::hours(state.config.org_repos.auto_rescan_stale_after_hours as i64);
    let stale_before_str = stale_before.format("%Y-%m-%d %H:%M:%S").to_string();

    let mut targets: Vec<RescanTarget> = Vec::new();
    for org in &orgs {
        let discovered = match discover_org(&api, org, &token, false, false).await {
            Ok(repos) => repos,
            Err(e) => {
                tracing::warn!("auto-rescan: failed to list repositories for {org}: {e}");
                continue;
            }
        };
        let known: HashMap<String, ignite_db_store::OnboardedRepoSummary> =
            state.db.list_onboarded_repo_summaries(sla.critical_days, sla.high_days, sla.medium_days).into_iter().filter(|s| &s.org == org).map(|s| (s.repo.clone(), s)).collect();
        for r in discovered {
            if r.empty {
                continue;
            }
            let stale = match known.get(&r.repo) {
                // Already in flight — never pile a second sweep-triggered
                // scan onto one a human (or a previous sweep tick) already
                // started.
                Some(s) if s.status == "running" => false,
                Some(s) => s.last_scan_at.as_str() < stale_before_str.as_str(),
                None => true, // never scanned at all — always stale
            };
            if stale {
                targets.push(RescanTarget { org: r.org, repo: r.repo });
            }
        }
    }

    if targets.is_empty() {
        return Json(serde_json::json!({ "skipped": false, "triggered": 0 })).into_response();
    }
    let count = targets.len();
    let parallel = spawn_auto_rescan_targets(state, targets, token);
    (StatusCode::ACCEPTED, Json(serde_json::json!({ "skipped": false, "triggered": count, "mode": if parallel { "parallel" } else { "sequential" } }))).into_response()
}

/// Same shape as `spawn_targets`, but specifically for the auto-rescan
/// sweep, which — unlike `scan_all_org_repos`'s explicit, one-off,
/// user-clicked "Scan all" — can be handed a genuinely large target list
/// (every stale repo across every configured org) that an operator may
/// reasonably want to abort mid-run by flipping the toggle back off. The
/// sequential branch re-checks `auto_rescan_enabled` before *each* repo,
/// not just once up front — turning the toggle off stops the next repo
/// from starting; the repo already mid-scan when it's flipped still
/// finishes normally (a real `rescan_one` in flight isn't cancelled, just
/// not chained into). Confirmed necessary the hard way while building
/// this: an earlier version had no such check, and disabling the toggle
/// while a 260-repo sweep was mid-run didn't stop the remaining 258 —
/// only killing the server process did.
fn spawn_auto_rescan_targets(state: Arc<AppState>, targets: Vec<RescanTarget>, token: String) -> bool {
    for t in &targets {
        RECENT_SCAN_FAILURES.lock().remove(&(t.org.clone(), t.repo.clone()));
    }
    let parallel = state.config.org_repos.scan_all_mode == "parallel";
    let runner = state.runner.clone();
    let server_base = resolve_server_base(&state);
    if parallel {
        // Parallel mode has no natural "check between iterations" point —
        // everything is already spawned as one generation the moment this
        // function returns, the same limitation the explicit "Scan all"
        // button's own parallel mode already has. Choosing "parallel" for
        // an unattended sweep is a deliberate, documented tradeoff (see
        // `OrgReposConfig::scan_all_mode`'s own doc comment), not
        // something this function can retroactively make abortable.
        for target in targets {
            let runner = runner.clone();
            let server_base = server_base.clone();
            let token = token.clone();
            tokio::spawn(async move { run_and_record_scan(&runner, &server_base, &token, &target).await });
        }
    } else {
        tokio::spawn(async move {
            let total = targets.len();
            for (i, target) in targets.iter().enumerate() {
                if !state.db.get_bool_setting(AUTO_RESCAN_ENABLED_SETTING, false) {
                    tracing::info!("auto-rescan: sweep aborted — toggle switched off ({} of {total} repo(s) left unscanned)", total - i);
                    break;
                }
                run_and_record_scan(&runner, &server_base, &token, target).await;
            }
        });
    }
    parallel
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/org-repos/:org", get(list_org_repos))
        .route("/api/org-repos/:org/scan-all", post(scan_all_org_repos))
        .route("/api/org-repos/:org/:repo/scan", post(scan_org_repo))
        .route("/api/org-repos/auto-rescan", get(get_auto_rescan_config).post(set_auto_rescan_config))
        .route("/api/org-repos/auto-rescan/run", post(run_auto_rescan))
}
