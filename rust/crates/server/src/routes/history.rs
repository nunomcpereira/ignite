//! /api/projects/*, /api/documents/:id — faithful port of routes/history.js.
//! `auth.requireAuth` on the schedule endpoint isn't enforced yet — no
//! session/auth middleware exists.

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

async fn list_projects(State(state): State<Arc<AppState>>) -> Response {
    Json(state.db.list_projects()).into_response()
}

// Registered before /api/projects/:id — Express-era bug fixed in the JS
// original (see routes/history.js's comment): a literal-segment route
// must be matched before the parameterized one that would otherwise
// shadow it. axum's router doesn't have that ordering pitfall (it always
// prefers the more specific literal match), but the route stays doc'd
// here for parity with the JS source.
async fn list_effectivated(State(state): State<Arc<AppState>>) -> Response {
    Json(json!({ "projects": state.db.list_effectivated_projects() })).into_response()
}

fn parse_id(raw: &str) -> Option<i64> {
    raw.parse::<i64>().ok()
}

async fn project_details(State(state): State<Arc<AppState>>, Path(id_raw): Path<String>) -> Response {
    let Some(id) = parse_id(&id_raw) else { return err(StatusCode::BAD_REQUEST, "Invalid project id.") };
    match state.db.get_project_details(id) {
        Some(project) => Json(project).into_response(),
        None => err(StatusCode::NOT_FOUND, "Project not found."),
    }
}

async fn project_issues(State(state): State<Arc<AppState>>, Path(id_raw): Path<String>) -> Response {
    let Some(id) = parse_id(&id_raw) else { return err(StatusCode::BAD_REQUEST, "Invalid project id.") };
    if !state.db.project_exists(id) {
        return err(StatusCode::NOT_FOUND, "Project not found.");
    }
    Json(json!({ "ok": true, "issues": state.db.get_project_issues(id) })).into_response()
}

async fn job_issues_handler(State(state): State<Arc<AppState>>, Path(job_id): Path<String>) -> Response {
    let job_id = job_id.trim();
    // live-run branch also needs a projectId alongside the issues, which
    // the shared job_issues helper doesn't carry — mirrored inline here
    // rather than widening that helper's return shape for one caller.
    let running = state.running_runs.lock().unwrap();
    if running.contains_key(job_id) {
        let issues = &running.get(job_id).unwrap().all_issues;
        return Json(json!({ "ok": true, "running": true, "issues": issues, "projectId": Value::Null })).into_response();
    }
    drop(running);
    let Some(issues) = lookup_job_issues(&state, job_id) else { return err(StatusCode::NOT_FOUND, "Unknown job id.") };
    let project_id = state.db.get_project_id_by_job_id(job_id);
    Json(json!({ "ok": true, "running": false, "issues": issues, "projectId": project_id })).into_response()
}

async fn delete_project(State(state): State<Arc<AppState>>, Path(id_raw): Path<String>) -> Response {
    let Some(id) = parse_id(&id_raw) else { return err(StatusCode::BAD_REQUEST, "Invalid project id.") };
    if !state.db.project_exists(id) {
        return err(StatusCode::NOT_FOUND, "Project not found.");
    }
    if let Some(retained_dir) = state.db.get_retained_source(id) {
        let _ = std::fs::remove_dir_all(retained_dir);
    }
    let _ = std::fs::remove_dir_all(codeql_db_root().join(id.to_string()));
    state.db.delete_project_by_id(id);
    Json(json!({ "ok": true })).into_response()
}

async fn delete_all_projects(State(state): State<Arc<AppState>>) -> Response {
    for source in state.db.list_retained_sources() {
        let _ = std::fs::remove_dir_all(source.dir_path);
    }
    let _ = std::fs::remove_dir_all(codeql_db_root());
    state.db.delete_all_projects();
    Json(json!({ "ok": true })).into_response()
}

static SCHEDULE_INTERVALS: Lazy<Vec<&'static str>> = Lazy::new(|| ignite_scheduled_rechecks::SCHEDULE_INTERVALS.to_vec());

async fn set_schedule(State(state): State<Arc<AppState>>, Path(id_raw): Path<String>, Json(body): Json<Value>) -> Response {
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

async fn get_document(State(state): State<Arc<AppState>>, Path(id_raw): Path<String>) -> Response {
    let Some(id) = parse_id(&id_raw) else { return err(StatusCode::BAD_REQUEST, "Invalid document id.") };
    let Some(doc) = state.db.get_document(id) else { return err(StatusCode::NOT_FOUND, "Document not found.") };
    if doc.kind == "link" {
        return Redirect::to(doc.url.as_deref().unwrap_or("/")).into_response();
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
        .route("/api/pipeline/:job_id/issues", get(job_issues_handler))
        .route("/api/documents/:id", get(get_document))
}
