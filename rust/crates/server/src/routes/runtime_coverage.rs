//! /api/runtime-coverage/:org/:repo — faithful port of
//! routes/runtime-coverage.js.

use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use ignite_runtime_coverage::CoverageFormat;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

async fn ingest(State(state): State<Arc<AppState>>, Path((org, repo)): Path<(String, String)>, Query(query): Query<HashMap<String, String>>, Json(body): Json<Value>) -> Response {
    if !body.is_object() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Request body must be a JSON coverage report." }))).into_response();
    }
    let project_root = query.get("projectRoot").map(String::as_str);
    let result = ignite_runtime_coverage::normalize_coverage_report(&body, project_root);
    let file_count = state.db.ingest_runtime_coverage(&org, &repo, &result.normalized);
    let format = match result.format {
        CoverageFormat::Istanbul => "istanbul",
        CoverageFormat::Simple => "simple",
    };
    Json(json!({ "ok": true, "org": org, "repo": repo, "format": format, "filesIngested": file_count })).into_response()
}

async fn get_coverage(State(state): State<Arc<AppState>>, Path((org, repo)): Path<(String, String)>) -> Response {
    let map = state.db.get_runtime_coverage_map(&org, &repo);
    let files: serde_json::Map<String, Value> = map.into_iter().map(|(k, v)| (k, json!({ "hitCount": v.hit_count, "coveredPct": v.covered_pct }))).collect();
    Json(json!({ "ok": true, "org": org, "repo": repo, "files": files })).into_response()
}

async fn delete_coverage(State(state): State<Arc<AppState>>, Path((org, repo)): Path<(String, String)>) -> Response {
    let removed = state.db.clear_runtime_coverage(&org, &repo);
    Json(json!({ "ok": true, "org": org, "repo": repo, "removed": removed })).into_response()
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/runtime-coverage/:org/:repo", post(ingest).get(get_coverage).delete(delete_coverage))
}
