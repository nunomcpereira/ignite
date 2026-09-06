//! `POST /api/pipeline/:job_id/fix-pr/preview` and
//! `POST /api/pipeline/:job_id/fix-pr/apply` — the scan-wide "generate a
//! PR that fixes every finding" feature. Two steps, no server-side
//! session state kept between them (mirrors `routes/issues.rs`'s
//! stateless per-issue explain/suggest-fix calls): `preview` runs the
//! LLM suggest-fix pass over every open issue that has a stored snippet
//! and returns the candidate diffs for the UI to show; `apply` takes
//! back the exact candidate list the user confirmed (after dropping any
//! they don't want), clones the repo fresh, applies them, and opens one
//! PR.
//!
//! `preview` runs as a background job (`AppState::fix_pr_previews`)
//! rather than inline in the request: it can be one LLM call per open
//! issue, serially, so blocking the whole HTTP response on it left the
//! UI's progress bar sitting on a fake asymptotic animation for however
//! long that took — indistinguishable from a hang. `POST .../preview`
//! now just starts (or returns the existing) job and returns
//! immediately; the frontend polls `GET .../preview/status` for real
//! per-issue progress.

use crate::routes::job_issues::lookup_job_issues;
use crate::state::{AppState, FixPrPreviewJob};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ignite_fix_pr::{FixCandidate, FixIssueInput};
use serde_json::{json, Value};
use std::sync::Arc;

fn err(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(json!({ "ok": false, "error": message.into() }))).into_response()
}

fn resolve_org_repo(state: &AppState, job_id: &str) -> Option<(i64, String, String)> {
    let project_id = state.db.get_project_id_by_job_id(job_id)?;
    let project = state.db.get_project(project_id)?;
    Some((project_id, project.org, project.repo))
}

fn job_status_json(job: &FixPrPreviewJob) -> Value {
    json!({
        "ok": true,
        "done": job.done,
        "cancelled": job.cancelled,
        "completed": job.completed,
        "total": job.total,
        "consideredCount": job.considered_count,
        "candidates": job.candidates,
        "reason": job.reason,
    })
}

/// Persists a job that just reached a terminal state (done, whether
/// successful/cancelled/skipped-for-a-reason) so the — potentially
/// expensive, one-LLM-call-per-issue — result survives a server restart.
/// Never called for a still-running job; see `DbStore::save_fix_pr_preview`'s
/// own doc comment for why.
fn persist_finished_job(db: &ignite_db_store::DbStore, job_id: &str, job: &FixPrPreviewJob) {
    let candidates_value = serde_json::to_value(&job.candidates).unwrap_or(Value::Array(Vec::new()));
    db.save_fix_pr_preview(job_id, job.total as i64, job.completed as i64, job.cancelled, job.considered_count as i64, job.reason.as_deref(), &candidates_value);
}

fn job_from_saved_row(row: ignite_db_store::FixPrPreviewRow) -> FixPrPreviewJob {
    FixPrPreviewJob {
        total: row.total as usize,
        completed: row.completed as usize,
        done: true,
        cancelled: row.cancelled,
        candidates: serde_json::from_value(row.candidates).unwrap_or_default(),
        considered_count: row.considered_count as usize,
        reason: row.reason,
        abort_handle: None,
    }
}

/// Starts a new preview job if none is already running/finished for this
/// `job_id`, then always returns the current (possibly just-started)
/// status — so a retried/duplicate click never spawns a second job.
/// Checks the DB-persisted result before running anything: a job that
/// already finished (possibly in a previous server process — see
/// `persist_finished_job`) is served straight from there instead of
/// re-running what can be an expensive LLM pass.
async fn preview(State(state): State<Arc<AppState>>, Path(job_id): Path<String>) -> Response {
    let job_id = job_id.trim().to_string();

    if state.fix_pr_previews.lock().contains_key(&job_id) {
        let job = state.fix_pr_previews.lock();
        return Json(job_status_json(job.get(&job_id).unwrap())).into_response();
    }

    if let Some(row) = state.db.get_fix_pr_preview(&job_id) {
        let job = job_from_saved_row(row);
        let response = job_status_json(&job);
        state.fix_pr_previews.lock().insert(job_id, job);
        return Json(response).into_response();
    }

    let Some(issues) = lookup_job_issues(&state, &job_id) else {
        return err(StatusCode::NOT_FOUND, "Unknown job id.");
    };

    let http = reqwest::Client::new();
    if !ignite_llm_client::llm_available(&http, &state.llm_config).await {
        let job = FixPrPreviewJob { done: true, reason: Some("AI service unavailable.".to_string()), considered_count: issues.len(), ..Default::default() };
        let response = job_status_json(&job);
        persist_finished_job(&state.db, &job_id, &job);
        state.fix_pr_previews.lock().insert(job_id, job);
        return Json(response).into_response();
    }

    let inputs: Vec<FixIssueInput> = issues
        .iter()
        .filter(|i| i.status == "open" && i.file.is_some() && i.line.is_some())
        .map(|i| FixIssueInput { issue_id: i.id.clone(), category: i.category.clone(), severity: i.severity.clone(), file: i.file.clone().unwrap(), line: i.line.unwrap(), summary: i.summary.clone(), snippet: i.snippet.clone() })
        .collect();
    let considered_count = inputs.len();

    let job = FixPrPreviewJob { total: considered_count, considered_count, ..Default::default() };
    let response = job_status_json(&job);
    state.fix_pr_previews.lock().insert(job_id.clone(), job);

    let task_state = state.clone();
    let task_job_id = job_id.clone();
    let handle = tokio::spawn(async move {
        let llm_config = task_state.llm_config.clone();
        let progress_state = task_state.clone();
        let progress_job_id = task_job_id.clone();
        let candidates = ignite_fix_pr::generate_fix_candidates_with_progress(&http, &llm_config, &inputs, |_| {}, move |completed, total| {
            if let Some(job) = progress_state.fix_pr_previews.lock().get_mut(&progress_job_id) {
                job.completed = completed;
                job.total = total;
            }
        })
        .await;

        let mut jobs = task_state.fix_pr_previews.lock();
        if let Some(job) = jobs.get_mut(&task_job_id) {
            job.candidates = candidates;
            job.done = true;
            job.abort_handle = None;
            persist_finished_job(&task_state.db, &task_job_id, job);
        }
    });

    if let Some(job) = state.fix_pr_previews.lock().get_mut(&job_id) {
        // Guard against the (rare, e.g. zero eligible issues) race where the
        // spawned task already finished and cleared `abort_handle` before
        // we got the lock back here — don't resurrect a handle to a
        // finished task onto an already-`done` job.
        if !job.done {
            job.abort_handle = Some(handle.abort_handle());
        }
    }

    Json(response).into_response()
}

async fn preview_status(State(state): State<Arc<AppState>>, Path(job_id): Path<String>) -> Response {
    let job_id = job_id.trim();
    if let Some(job) = state.fix_pr_previews.lock().get(job_id) {
        return Json(job_status_json(job)).into_response();
    }
    // Not in memory — e.g. the server restarted after this job finished.
    // Check the DB-persisted result before reporting "unknown job".
    if let Some(row) = state.db.get_fix_pr_preview(job_id) {
        let job = job_from_saved_row(row);
        let response = job_status_json(&job);
        state.fix_pr_previews.lock().insert(job_id.to_string(), job);
        return Json(response).into_response();
    }
    err(StatusCode::NOT_FOUND, "No fix-PR preview job for this job id — call POST .../fix-pr/preview first.")
}

/// Terminates a still-running preview job outright — aborts the
/// `tokio::spawn`'d task (including whatever LLM request is in flight),
/// not just a "stop after the current issue" flag, since a single
/// in-flight LLM call can itself take up to 60s. A no-op (but still
/// `ok: true`) if the job already finished or doesn't exist — cancelling
/// something that's already done isn't an error.
async fn cancel_preview(State(state): State<Arc<AppState>>, Path(job_id): Path<String>) -> Response {
    let job_id = job_id.trim();
    let mut jobs = state.fix_pr_previews.lock();
    let Some(job) = jobs.get_mut(job_id) else {
        return Json(json!({ "ok": true, "cancelled": false })).into_response();
    };
    if let Some(handle) = job.abort_handle.take() {
        handle.abort();
        job.cancelled = true;
        job.done = true;
        persist_finished_job(&state.db, job_id, job);
    }
    Json(job_status_json(job)).into_response()
}

async fn apply(State(state): State<Arc<AppState>>, crate::auth::RequireAuth(_user): crate::auth::RequireAuth, Path(job_id): Path<String>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    let job_id = job_id.trim();
    let Some((project_id, org, repo)) = resolve_org_repo(&state, job_id) else {
        return err(StatusCode::NOT_FOUND, "This job has no associated GitHub repository yet — it must have already shipped before a fix PR can be opened against it.");
    };

    let candidates: Vec<FixCandidate> = match body.get("candidates").cloned().map(serde_json::from_value) {
        Some(Ok(c)) => c,
        Some(Err(e)) => return err(StatusCode::BAD_REQUEST, format!("Invalid candidates: {e}")),
        None => return err(StatusCode::BAD_REQUEST, "candidates is required — pass back the (possibly trimmed) list from /fix-pr/preview."),
    };
    if candidates.is_empty() {
        return err(StatusCode::BAD_REQUEST, "candidates must not be empty.");
    }

    let token = crate::auth::resolve_effective_github_token(&headers, &state.db);
    if token.is_empty() {
        return err(StatusCode::UNAUTHORIZED, "No GitHub token available — connect a GitHub account or configure a server token.");
    }

    let full_name = format!("{org}/{repo}");
    let github_api = ignite_github_api::GithubApi::new(&state.runner);
    let base_branch = match github_api.default_branch(&full_name, &token).await {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_GATEWAY, format!("Failed to resolve default branch for {full_name}: {e}")),
    };

    let outcome = ignite_fix_pr::open_fix_pr(&state.runner, &github_api, &full_name, &base_branch, job_id, &candidates, &token).await;
    if outcome.already_open {
        return Json(json!({ "ok": true, "alreadyOpen": true, "branch": outcome.branch })).into_response();
    }
    if let Some(e) = &outcome.error {
        return err(StatusCode::BAD_GATEWAY, e.clone());
    }
    if let Some(pr_url) = &outcome.pr_url {
        state.db.record_pull_request(project_id, "fix-pr", pr_url, Some(&outcome.branch), Some(outcome.files_changed.len() as i64));
    }
    Json(json!({ "ok": true, "prUrl": outcome.pr_url, "branch": outcome.branch, "filesChanged": outcome.files_changed })).into_response()
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/pipeline/:job_id/fix-pr/preview", post(preview).delete(cancel_preview))
        .route("/api/pipeline/:job_id/fix-pr/preview/status", get(preview_status))
        .route("/api/pipeline/:job_id/fix-pr/apply", post(apply))
}
