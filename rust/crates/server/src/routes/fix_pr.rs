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

use crate::routes::job_issues::lookup_job_issues;
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
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

async fn preview(State(state): State<Arc<AppState>>, Path(job_id): Path<String>) -> Response {
    let job_id = job_id.trim();
    let Some(issues) = lookup_job_issues(&state, job_id) else {
        return err(StatusCode::NOT_FOUND, "Unknown job id.");
    };

    let http = reqwest::Client::new();
    if !ignite_llm_client::llm_available(&http, &state.llm_config).await {
        return Json(json!({ "ok": true, "candidates": [], "consideredCount": issues.len(), "reason": "AI service unavailable." })).into_response();
    }

    let inputs: Vec<FixIssueInput> = issues
        .iter()
        .filter(|i| i.status == "open" && i.file.is_some() && i.line.is_some())
        .map(|i| FixIssueInput { issue_id: i.id.clone(), category: i.category.clone(), severity: i.severity.clone(), file: i.file.clone().unwrap(), line: i.line.unwrap(), summary: i.summary.clone(), snippet: i.snippet.clone() })
        .collect();
    let considered_count = inputs.len();

    let candidates = ignite_fix_pr::generate_fix_candidates(&http, &state.llm_config, &inputs, |_| {}).await;
    Json(json!({ "ok": true, "candidates": candidates, "consideredCount": considered_count })).into_response()
}

async fn apply(State(state): State<Arc<AppState>>, Path(job_id): Path<String>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
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
    Router::new().route("/api/pipeline/:job_id/fix-pr/preview", post(preview)).route("/api/pipeline/:job_id/fix-pr/apply", post(apply))
}
