//! `GET /api/onboarded-repos` — one row per distinct (org, repo) ever
//! onboarded, backing the web UI's "Onboarded Repos" nav view: the latest
//! run's open-issue counts (license-compliance + total), plus every
//! acknowledgment and PR Ignite has ever recorded for that repo across all
//! its runs. Thin pass-through to `db-store`'s own aggregation query — see
//! `DbStore::list_onboarded_repo_summaries`.
//!
//! `POST /api/onboarded-repos/:org/:repo/rescan` — manual "Scan Now" for a
//! single onboarded repo, wired to the same UI view. Synchronous equivalent
//! of `ignite-scheduled-rescan`'s `rescan_one` (its own doc comment covers
//! the clone -> validate-all -> github-check sequence in full) run for one
//! repo instead of every onboarded repo on a timer; reuses that crate's
//! function directly rather than duplicating it.

use crate::auth::resolve_effective_github_token;
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ignite_scheduled_rescan::{auto_fix_mode_from_env, rescan_one, RescanTarget};
use serde_json::json;
use std::sync::Arc;

async fn list_onboarded_repos(State(state): State<Arc<AppState>>) -> Response {
    Json(state.db.list_onboarded_repo_summaries()).into_response()
}

async fn rescan_repo(State(state): State<Arc<AppState>>, headers: HeaderMap, Path((org, repo)): Path<(String, String)>) -> Response {
    let gh_token = resolve_effective_github_token(&headers, &state.db);
    if gh_token.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "No GitHub token available — connect GitHub or set GH_TOKEN/GITHUB_TOKEN on the server." })),
        )
            .into_response();
    }
    // Same self-referencing convention as the scheduled-rescan binary
    // (IGNITE_SERVER_URL, defaulting to this server's own default port) —
    // validate-all is called over real HTTP rather than in-process so this
    // route reuses the exact same code path a scheduled/CI-triggered scan
    // does, not a second parallel implementation.
    let server_base = std::env::var("IGNITE_SERVER_URL").unwrap_or_else(|_| "http://127.0.0.1:51337".to_string());
    let http = reqwest::Client::new();
    let target = RescanTarget { org, repo };
    let outcome = rescan_one(&state.runner, &http, &server_base, &gh_token, &target, auto_fix_mode_from_env()).await;
    Json(json!({
        "org": outcome.org,
        "repo": outcome.repo,
        "jobId": outcome.job_id,
        "issueCount": outcome.issue_count,
        "posted": outcome.posted,
        "error": outcome.error,
    }))
    .into_response()
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/onboarded-repos", get(list_onboarded_repos))
        .route("/api/onboarded-repos/:org/:repo/rescan", post(rescan_repo))
}
