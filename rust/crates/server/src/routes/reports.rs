//! /api/reports/* — faithful port of routes/reports.js.

use crate::state::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;

fn resolve_project_path(body: &Value) -> Result<PathBuf, Response> {
    let raw_path = body.get("projectPath").and_then(|v| v.as_str()).unwrap_or("");
    let project_path = ignite_tool_runner::sanitize_absolute_project_path(raw_path).map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))).into_response())?;
    let meta = std::fs::metadata(&project_path).ok();
    if meta.as_ref().map(|m| !m.is_dir()).unwrap_or(true) {
        return Err((StatusCode::BAD_REQUEST, Json(json!({ "error": format!("projectPath does not exist or is not a directory: {}", project_path.display()) }))).into_response());
    }
    Ok(project_path)
}

async fn sbom(State(state): State<Arc<AppState>>, Json(body): Json<Value>) -> Response {
    let project_path = match resolve_project_path(&body) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let manifests = ignite_package_hallucination::default_manifests();
    match ignite_sbom::generate_sbom(&project_path, &state.runner, true, &manifests, 1000).await {
        Ok(result) => Json(json!({ "ok": true, "projectPath": project_path, "engine": result.engine, "sbom": result.sbom })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))).into_response(),
    }
}

async fn loc_metrics(State(state): State<Arc<AppState>>, Json(body): Json<Value>) -> Response {
    let project_path = match resolve_project_path(&body) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let result = ignite_loc_metrics::generate_loc_metrics(&project_path, &state.runner, true).await;
    Json(json!({ "ok": true, "projectPath": project_path, "engine": result.engine, "metrics": result.metrics })).into_response()
}

async fn posture(State(state): State<Arc<AppState>>, Json(body): Json<Value>) -> Response {
    let project_path = match resolve_project_path(&body) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let config = ignite_feature_posture::FeaturePostureConfig { enabled: true, ruleset: String::new(), max_scan_file_bytes: 1_000_000 };
    match ignite_feature_posture::check_feature_posture(&project_path, &state.runner, &config).await {
        Ok(result) => Json(json!({ "ok": true, "projectPath": project_path, "engine": result.engine, "posture": result.posture })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))).into_response(),
    }
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/reports/sbom", post(sbom)).route("/api/reports/loc-metrics", post(loc_metrics)).route("/api/reports/posture", post(posture))
}
