//! /api/projects/*, /api/documents/:id — faithful port of routes/history.js.

use crate::routes::job_issues::lookup_job_issues;
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use once_cell::sync::Lazy;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;

fn codeql_db_root() -> PathBuf {
    let data_dir = std::env::var("IGNITE_DATA_DIR").map(PathBuf::from).unwrap_or_else(|_| dirs_home().join(".ignite"));
    data_dir.join("codeql-dbs")
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("."))
}

fn err(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(json!({ "error": message.into() }))).into_response()
}

async fn list_projects(State(state): State<Arc<AppState>>, crate::auth::RequireAuth(_user): crate::auth::RequireAuth) -> Response {
    Json(state.db.list_projects()).into_response()
}

// Registered before /api/projects/:id — Express-era bug fixed in the JS
// original (see routes/history.js's comment): a literal-segment route
// must be matched before the parameterized one that would otherwise
// shadow it. axum's router doesn't have that ordering pitfall (it always
// prefers the more specific literal match), but the route stays doc'd
// here for parity with the JS source.
async fn list_effectivated(State(state): State<Arc<AppState>>, crate::auth::RequireAuth(_user): crate::auth::RequireAuth) -> Response {
    Json(json!({ "projects": state.db.list_effectivated_projects() })).into_response()
}

fn parse_id(raw: &str) -> Option<i64> {
    raw.parse::<i64>().ok()
}

async fn project_details(State(state): State<Arc<AppState>>, crate::auth::RequireAuth(_user): crate::auth::RequireAuth, Path(id_raw): Path<String>) -> Response {
    let Some(id) = parse_id(&id_raw) else { return err(StatusCode::BAD_REQUEST, "Invalid project id.") };
    match state.db.get_project_details(id) {
        Some(project) => Json(project).into_response(),
        None => err(StatusCode::NOT_FOUND, "Project not found."),
    }
}

async fn project_issues(State(state): State<Arc<AppState>>, crate::auth::RequireAuth(_user): crate::auth::RequireAuth, Path(id_raw): Path<String>) -> Response {
    let Some(id) = parse_id(&id_raw) else { return err(StatusCode::BAD_REQUEST, "Invalid project id.") };
    if !state.db.project_exists(id) {
        return err(StatusCode::NOT_FOUND, "Project not found.");
    }
    Json(json!({ "ok": true, "issues": state.db.get_project_issues(id) })).into_response()
}

/// GET /api/repositories/:org/:repo — US-01's new, additive endpoint:
/// the durable repository identity plus every scan run ever recorded
/// against it (including enrollment-only rows, each labeled), independent
/// of which `projects.id`/`job_id` any one of those runs happens to carry.
/// Existing `/api/projects*` endpoints are untouched by this story.
async fn repository_history(State(state): State<Arc<AppState>>, crate::auth::RequireAuth(_user): crate::auth::RequireAuth, Path((org, repo)): Path<(String, String)>) -> Response {
    let Some(repository) = state.db.get_repository_by_org_repo(&org, &repo) else {
        return err(StatusCode::NOT_FOUND, "Repository not found.");
    };
    let scan_runs = state.db.list_scan_runs_for_repository(repository.id);
    Json(json!({ "ok": true, "repository": repository, "scanRuns": scan_runs })).into_response()
}

async fn job_issues_handler(State(state): State<Arc<AppState>>, Path(job_id): Path<String>) -> Response {
    let job_id = job_id.trim();
    // live-run branch also needs a projectId alongside the issues, which
    // the shared job_issues helper doesn't carry — mirrored inline here
    // rather than widening that helper's return shape for one caller.
    let running = state.running_runs.lock();
    if running.contains_key(job_id) {
        let issues = &running.get(job_id).unwrap().all_issues;
        return Json(json!({ "ok": true, "running": true, "issues": issues, "projectId": Value::Null })).into_response();
    }
    drop(running);
    let Some(issues) = lookup_job_issues(&state, job_id) else { return err(StatusCode::NOT_FOUND, "Unknown job id.") };
    let project_id = state.db.get_project_id_by_job_id(job_id);
    Json(json!({ "ok": true, "running": false, "issues": issues, "projectId": project_id })).into_response()
}

/// GET /api/pipeline/:job_id/status - reconnect-by-polling snapshot for a
/// browser tab that lost its live NDJSON connection (page refresh, or
/// switching the main view to a job this tab didn't originate). Unifies
/// live (`running_runs`) vs. finished (DB) state by job_id, same pattern
/// as `job_issues_handler` above. `steps` (phase/title/state/logs) is the
/// actual reconnect payload - `EventLog::persist` already durably writes
/// every log/status change there as the job runs, so a client can rebuild
/// its whole phase timeline from it regardless of whether the job is
/// still running or already finished.
async fn job_status(State(state): State<Arc<AppState>>, Path(job_id): Path<String>) -> Response {
    let job_id = job_id.trim();
    let (live_project_id, review_active) = {
        let running = state.running_runs.lock();
        match running.get(job_id) {
            Some(live) => (Some(live.project_id), live.review_active),
            None => return job_status_from_db(&state, job_id),
        }
    };
    let Some(Some(pid)) = live_project_id else {
        // Live but no project row yet (Phase 1 hasn't created it) - nothing
        // to rebuild from yet, just report that it's running.
        return Json(json!({ "ok": true, "running": true, "reviewActive": review_active, "project": Value::Null, "steps": Value::Array(vec![]) })).into_response();
    };
    match state.db.get_project_details(pid) {
        Some(details) => Json(json!({ "ok": true, "running": true, "reviewActive": review_active, "project": details.project, "steps": details.steps, "lifecycle": lifecycle_summary(&state, pid) })).into_response(),
        None => Json(json!({ "ok": true, "running": true, "reviewActive": review_active, "project": Value::Null, "steps": Value::Array(vec![]) })).into_response(),
    }
}

fn job_status_from_db(state: &AppState, job_id: &str) -> Response {
    let Some(pid) = state.db.get_project_id_by_job_id(job_id) else {
        return err(StatusCode::NOT_FOUND, "Unknown job id.");
    };
    let Some(details) = state.db.get_project_details(pid) else {
        return err(StatusCode::NOT_FOUND, "Project not found.");
    };
    // US-04: `running: false` here covers two genuinely different cases a
    // client reconnecting with just a job id can't otherwise tell apart —
    // a run that finished normally, and a run that was `awaiting_review`
    // when the server restarted and lost the in-memory task that would
    // have resumed it. `lifecycle` (and, when still unresolved,
    // `pendingReview`) makes that distinction explicit instead of leaving
    // the client to infer it from `project.status` alone.
    Json(json!({ "ok": true, "running": false, "project": details.project, "steps": details.steps, "lifecycle": lifecycle_summary(state, pid) })).into_response()
}

/// `lifecycleState` (from `scan_runs`, US-04) plus, when a review is
/// still unresolved, the durable `pending_reviews` snapshot — issues,
/// owner, and when it was raised — so a client can render "still awaiting
/// review" accurately even when nothing is currently running in this
/// process to ask.
fn lifecycle_summary(state: &AppState, project_id: i64) -> Value {
    let Some(run) = state.db.get_scan_run_for_legacy_project(project_id) else { return Value::Null };
    let pending_review = if run.lifecycle_state == "awaiting_review" { state.db.get_pending_review(run.id).filter(|r| r.resolved_at.is_none()) } else { None };
    json!({
        "runId": run.id,
        "state": run.lifecycle_state,
        "pendingReview": pending_review,
    })
}

async fn delete_project(State(state): State<Arc<AppState>>, crate::auth::RequireAuth(user): crate::auth::RequireAuth, Path(id_raw): Path<String>) -> Response {
    let Some(id) = parse_id(&id_raw) else { return err(StatusCode::BAD_REQUEST, "Invalid project id.") };
    let Some(project) = state.db.get_project(id) else {
        return err(StatusCode::NOT_FOUND, "Project not found.");
    };
    if let Some(retained_dir) = state.db.get_retained_source(id) {
        let _ = std::fs::remove_dir_all(retained_dir);
    }
    let _ = std::fs::remove_dir_all(codeql_db_root().join(id.to_string()));
    state.db.delete_project_by_id(id);
    // No per-project ownership model exists in this codebase (a single
    // Ignite deployment is one org's shared instance, not multi-tenant
    // SaaS — see auth.rs's own note that no role/permission tiers exist
    // at all) — every authenticated user already has equal standing to
    // delete any project. What was missing is attribution: unlike nearly
    // every other mutating action here, this destructive, irreversible
    // delete previously left no audit trail of who did it at all.
    state.emit_audit_event(ignite_audit_log::AuditEvent::new("project.deleted", "warning", format!("project {id} ({}/{}) deleted", project.org, project.repo)).actor(user.email).repo(&project.org, &project.repo).metadata(json!({ "projectId": id })));
    Json(json!({ "ok": true })).into_response()
}

async fn delete_all_projects(State(state): State<Arc<AppState>>, crate::auth::RequireAuth(user): crate::auth::RequireAuth) -> Response {
    for source in state.db.list_retained_sources() {
        let _ = std::fs::remove_dir_all(source.dir_path);
    }
    let _ = std::fs::remove_dir_all(codeql_db_root());
    state.db.delete_all_projects();
    state.emit_audit_event(ignite_audit_log::AuditEvent::new("project.deleted_all", "critical", "every project's history was deleted".to_string()).actor(user.email));
    Json(json!({ "ok": true })).into_response()
}

static SCHEDULE_INTERVALS: Lazy<Vec<&'static str>> = Lazy::new(|| ignite_scheduled_rechecks::SCHEDULE_INTERVALS.to_vec());

async fn set_schedule(State(state): State<Arc<AppState>>, crate::auth::RequireAuth(_user): crate::auth::RequireAuth, Path(id_raw): Path<String>, Json(body): Json<Value>) -> Response {
    let Some(id) = parse_id(&id_raw) else { return err(StatusCode::BAD_REQUEST, "Invalid project id.") };
    if !state.db.project_exists(id) {
        return err(StatusCode::NOT_FOUND, "Project not found.");
    }
    let enabled = body.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
    let interval = body.get("interval").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
    if enabled && !SCHEDULE_INTERVALS.contains(&interval.as_str()) {
        return err(StatusCode::BAD_REQUEST, format!("interval must be one of: {}", SCHEDULE_INTERVALS.join(", ")));
    }
    let next_run_at = if enabled { Some(ignite_scheduled_rechecks::compute_next_run_at(&interval, chrono::Utc::now())) } else { None };
    state.db.set_project_schedule(id, enabled, if enabled { Some(interval.as_str()) } else { None }, next_run_at.as_deref());
    Json(json!({ "ok": true, "enabled": enabled, "interval": if enabled { Some(interval) } else { None }, "nextRunAt": next_run_at })).into_response()
}

/// A "link" document's URL is only ever redirected to when it's plainly
/// an ordinary web URL — rejects any other scheme (`javascript:`,
/// `data:`, `file:`, a schemeless value that could be reinterpreted, ...)
/// rather than blindly trusting whatever was stored, which is what made
/// this an open-redirect (and potentially worse) vector in the first
/// place.
fn is_safe_redirect_url(url: &str) -> bool {
    url.starts_with("https://") || url.starts_with("http://")
}

async fn get_document(State(state): State<Arc<AppState>>, crate::auth::RequireAuth(_user): crate::auth::RequireAuth, Path(id_raw): Path<String>) -> Response {
    let Some(id) = parse_id(&id_raw) else { return err(StatusCode::BAD_REQUEST, "Invalid document id.") };
    let Some(doc) = state.db.get_document(id) else { return err(StatusCode::NOT_FOUND, "Document not found.") };
    if doc.kind == "link" {
        return match doc.url.as_deref() {
            Some(url) if is_safe_redirect_url(url) => Redirect::to(url).into_response(),
            _ => err(StatusCode::BAD_REQUEST, "This document's link is not a valid http(s) URL."),
        };
    }
    let mime = doc.mime.unwrap_or_else(|| "application/octet-stream".to_string());
    let filename = urlencoding::encode(&doc.name);
    let headers = [(header::CONTENT_TYPE, mime), (header::CONTENT_DISPOSITION, format!("attachment; filename*=UTF-8''{filename}"))];
    (headers, doc.data.unwrap_or_default()).into_response()
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/projects", get(list_projects).delete(delete_all_projects))
        .route("/api/projects/effectivated", get(list_effectivated))
        .route("/api/projects/:id", get(project_details).delete(delete_project))
        .route("/api/projects/:id/issues", get(project_issues))
        .route("/api/projects/:id/schedule", post(set_schedule))
        .route("/api/repositories/:org/:repo", get(repository_history))
        .route("/api/pipeline/:job_id/issues", get(job_issues_handler))
        .route("/api/pipeline/:job_id/status", get(job_status))
        .route("/api/pipeline/:job_id/evidence", get(job_evidence))
        .route("/api/documents/:id", get(get_document))
}

/// GET /api/pipeline/:jobId/evidence — US-05's versioned evidence
/// manifest for one scan run. The stored JSON (`ignite_evidence::EvidenceManifest`,
/// built in `pipeline_validate.rs` right after Phase 4 completes) is
/// already redacted by construction — digests, counts, timestamps, and
/// `ignite_policy::CheckCoverage` entries only, never a raw file path or a
/// config secret — so this handler returns it as-is rather than filtering
/// it a second time.
async fn job_evidence(State(state): State<Arc<AppState>>, crate::auth::RequireAuth(_user): crate::auth::RequireAuth, Path(job_id): Path<String>) -> Response {
    let Some(project_id) = state.db.get_project_id_by_job_id(job_id.trim()) else {
        return err(StatusCode::NOT_FOUND, "Unknown job id.");
    };
    let Some(run) = state.db.get_scan_run_for_legacy_project(project_id) else {
        return err(StatusCode::NOT_FOUND, "No scan run recorded for this job id.");
    };
    match state.db.get_evidence_manifest(run.id) {
        Some(manifest_json) => match serde_json::from_str::<Value>(&manifest_json) {
            Ok(manifest) => Json(json!({ "ok": true, "runId": run.id, "manifest": manifest })).into_response(),
            Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "Stored evidence manifest is corrupt."),
        },
        // Not every entry point builds a manifest yet (see CLAUDE.md's
        // US-05 note: only validate-all does, so far), and a run that
        // failed before reaching it never gets one either — both are a
        // clear, honest 404, not a fabricated empty manifest.
        None => err(StatusCode::NOT_FOUND, "No evidence manifest recorded for this run."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    use crate::state::LiveRun;
    use serde_json::Value;
    
    

    async fn spawn_test_server() -> (String, Arc<AppState>) {
        let db_dir = tempfile::tempdir().unwrap();
        let db = ignite_db_store::DbStore::open(&db_dir.path().join("test.db")).unwrap();
        let app_state = Arc::new(crate::state::test_state(db, ignite_config::Config::default()));
        let router = axum::Router::new().merge(router()).with_state(app_state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        std::mem::forget(db_dir);
        (format!("http://{addr}"), app_state)
    }

    #[tokio::test]
    async fn job_status_reports_running_true_with_steps_for_a_live_job() {
        let (base, state) = spawn_test_server().await;
        let job_id = "live-job".to_string();
        let project_id = state.db.create_project(&job_id, "acme", "widgets", false, "ui", None).unwrap();
        state.db.upsert_step(project_id, 3, "Extraction", "running", "line 1");
        state.running_runs.lock().insert(
            job_id.clone(),
            LiveRun { org: "acme".to_string(), repo: "widgets".to_string(), project_id: Some(project_id), all_issues: vec![], project_root: None, source_backup_dir: None, review_active: false },
        );

        let client = reqwest::Client::new();
        let body: Value = client.get(format!("{base}/api/pipeline/{job_id}/status")).send().await.unwrap().json().await.unwrap();
        assert_eq!(body["ok"], true);
        assert_eq!(body["running"], true);
        assert_eq!(body["steps"][0]["title"], "Extraction");
    }

    #[tokio::test]
    async fn job_status_reports_running_false_for_a_finished_job() {
        let (base, state) = spawn_test_server().await;
        let job_id = "finished-job".to_string();
        let project_id = state.db.create_project(&job_id, "acme", "widgets", false, "ui", None).unwrap();
        state.db.upsert_step(project_id, 3, "Extraction", "success", "done");
        state.db.finish_project("success", None, None, None, project_id);

        let client = reqwest::Client::new();
        let body: Value = client.get(format!("{base}/api/pipeline/{job_id}/status")).send().await.unwrap().json().await.unwrap();
        assert_eq!(body["ok"], true);
        assert_eq!(body["running"], false);
        assert_eq!(body["project"]["status"], "success");
        assert_eq!(body["steps"][0]["title"], "Extraction");
    }

    fn auth_header(state: &AppState) -> String {
        let user_id = state.db.create_local_user("tester@example.com", Some("Tester"), "unused-hash").unwrap();
        let raw_key = ignite_auth::generate_api_key();
        state.db.create_api_key(user_id, &ignite_auth::hash_api_key(&raw_key), None, None, "test");
        format!("Bearer {raw_key}")
    }

    #[tokio::test]
    async fn repository_history_returns_repository_and_its_scan_runs() {
        let (base, state) = spawn_test_server().await;
        let job_id = "job-a".to_string();
        let project_id = state.db.create_project(&job_id, "acme", "widgets", false, "ui", None).unwrap();
        state.db.finish_project("success", None, None, None, project_id);

        let client = reqwest::Client::new();
        let body: Value = client.get(format!("{base}/api/repositories/acme/widgets")).header("Authorization", auth_header(&state)).send().await.unwrap().json().await.unwrap();
        assert_eq!(body["ok"], true);
        assert_eq!(body["repository"]["org"], "acme");
        assert_eq!(body["scanRuns"].as_array().unwrap().len(), 1);
        assert_eq!(body["scanRuns"][0]["legacyJobId"], "job-a");
        assert_eq!(body["scanRuns"][0]["lifecycleState"], "published");
    }

    #[tokio::test]
    async fn repository_history_404s_for_an_unknown_repository() {
        let (base, state) = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.get(format!("{base}/api/repositories/acme/does-not-exist")).header("Authorization", auth_header(&state)).send().await.unwrap();
        assert_eq!(res.status(), 404);
    }

    #[tokio::test]
    async fn job_status_404s_for_an_unknown_job_id() {
        let (base, _state) = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.get(format!("{base}/api/pipeline/does-not-exist/status")).send().await.unwrap();
        assert_eq!(res.status(), 404);
    }
}
