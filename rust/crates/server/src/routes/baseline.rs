//! /api/baseline/:org/:repo — faithful port of routes/baseline.js.

use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};
use std::sync::Arc;

async fn save_baseline(State(state): State<Arc<AppState>>, Path((org, repo)): Path<(String, String)>, Json(body): Json<Value>) -> Response {
    let Some(issue_ids) = body.get("issueIds").and_then(|v| v.as_array()) else {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Request body must include issueIds: string[] — typically the `issues[].id` list from a prior validate-all response." }))).into_response();
    };
    let issue_ids: Vec<String> = issue_ids.iter().map(|v| v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string())).collect();
    let saved = state.db.save_baseline(&org, &repo, &issue_ids);
    Json(json!({ "ok": true, "org": org, "repo": repo, "savedCount": saved })).into_response()
}

async fn get_baseline(State(state): State<Arc<AppState>>, Path((org, repo)): Path<(String, String)>) -> Response {
    let ids: Vec<String> = state.db.get_baseline_issue_ids(&org, &repo).into_iter().collect();
    let count = ids.len();
    Json(json!({ "ok": true, "org": org, "repo": repo, "issueIds": ids, "count": count })).into_response()
}

async fn delete_baseline(State(state): State<Arc<AppState>>, Path((org, repo)): Path<(String, String)>) -> Response {
    let removed = state.db.clear_baseline(&org, &repo);
    Json(json!({ "ok": true, "org": org, "repo": repo, "removed": removed })).into_response()
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/baseline/:org/:repo", post(save_baseline).get(get_baseline).delete(delete_baseline))
}
