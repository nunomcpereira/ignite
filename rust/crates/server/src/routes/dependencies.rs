//! /api/dependencies/* — faithful port of routes/dependencies.js.

use crate::state::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;

fn sanitize_project_path(body: &Value) -> Result<PathBuf, Response> {
    let raw_path = body.get("projectPath").and_then(|v| v.as_str()).unwrap_or("");
    let project_path = ignite_tool_runner::sanitize_absolute_project_path(raw_path).map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))).into_response())?;
    let meta = std::fs::metadata(&project_path).ok();
    if meta.as_ref().map(|m| !m.is_dir()).unwrap_or(true) {
        return Err((StatusCode::BAD_REQUEST, Json(json!({ "error": format!("projectPath does not exist or is not a directory: {}", project_path.display()) }))).into_response());
    }
    Ok(project_path)
}

async fn check_licenses(State(state): State<Arc<AppState>>, Json(body): Json<Value>) -> Response {
    let project_path = match sanitize_project_path(&body) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let client = ignite_deps_dev_client::DepsDevClient::new();
    let npm_http = reqwest::Client::new();
    match ignite_dependency_license_scan::scan_dependency_licenses(&project_path, &state.runner, &client, &npm_http, |_| {}).await {
        Ok(scan) => Json(json!({
            "ok": true,
            "projectPath": project_path,
            "engine": scan.engine,
            "projectLicense": scan.project_license.map(|p| json!({ "spdxId": p.spdx_id, "confidence": p.confidence, "tier": p.tier, "reason": p.reason })),
            "manifests": scan.manifests,
        }))
        .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))).into_response(),
    }
}

async fn check_vulnerabilities(State(_state): State<Arc<AppState>>, Json(body): Json<Value>) -> Response {
    let project_path = match sanitize_project_path(&body) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let client = ignite_deps_dev_client::DepsDevClient::new();
    match ignite_dependency_license_scan::scan_dependency_vulnerabilities(&project_path, &client).await {
        Ok(manifests) => {
            let mut critical = 0u32;
            let mut advisory = 0u32;
            for m in &manifests {
                for d in &m.dependencies {
                    for v in &d.vulnerabilities {
                        if v.severity == "error" {
                            critical += 1;
                        } else {
                            advisory += 1;
                        }
                    }
                }
            }
            Json(json!({ "ok": true, "projectPath": project_path, "manifests": manifests, "counts": { "critical": critical, "advisory": advisory } })).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))).into_response(),
    }
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/dependencies/check", post(check_licenses)).route("/api/dependencies/vulnerabilities", post(check_vulnerabilities))
}
