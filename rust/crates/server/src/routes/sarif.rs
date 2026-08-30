//! GET /api/pipeline/:jobId/sarif — faithful port of routes/sarif.js.

use crate::routes::job_issues::lookup_job_issues;
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;
use std::sync::Arc;

async fn sarif_handler(State(state): State<Arc<AppState>>, Path(job_id): Path<String>) -> Response {
    let job_id = job_id.trim();
    let Some(issues) = lookup_job_issues(&state, job_id) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": "Unknown job id." }))).into_response();
    };
    let doc = ignite_sarif::build_sarif(&issues);
    (StatusCode::OK, [(header::CONTENT_TYPE, "application/sarif+json")], Json(doc)).into_response()
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/pipeline/:job_id/sarif", get(sarif_handler))
}
