//! GET /api/pipeline/:jobId/annotations — faithful port of
//! routes/github-annotations.js.

use crate::routes::job_issues::lookup_job_issues;
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use axum::Json;
use serde_json::json;
use std::sync::Arc;

async fn annotations_handler(State(state): State<Arc<AppState>>, Path(job_id): Path<String>) -> Response {
    let job_id = job_id.trim();
    let Some(issues) = lookup_job_issues(&state, job_id) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": "Unknown job id." }))).into_response();
    };
    let body = ignite_github_annotations::build_github_annotations(&issues);
    (StatusCode::OK, [(header::CONTENT_TYPE, "text/plain; charset=utf-8")], body).into_response()
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/pipeline/:job_id/annotations", get(annotations_handler))
}
