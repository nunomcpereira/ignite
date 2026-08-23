//! POST /api/pipeline/auto-fix — faithful port of routes/auto-fix.js.

use crate::state::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use ignite_auto_fix::{FindingInput, FixAction};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

fn action_to_json(result: &ignite_auto_fix::FixResult) -> Value {
    let (kind, extra) = match &result.action {
        FixAction::DeleteFile { file, detail } => ("delete-file", json!({ "file": file, "detail": detail })),
        FixAction::RemoveDependency { file, dependency, detail } => ("remove-dependency", json!({ "file": file, "dependency": dependency, "detail": detail })),
        FixAction::NarrowExportListOrManual { file, line, name, detail } => ("narrow-export-list-or-manual", json!({ "file": file, "line": line, "name": name, "detail": detail })),
        FixAction::AddRecursionLimitOrManual { file, line, detail } => ("add-recursion-limit-or-manual", json!({ "file": file, "line": line, "detail": detail })),
    };
    let mut obj = extra.as_object().cloned().unwrap_or_default();
    obj.insert("type".to_string(), json!(kind));
    obj.insert("applied".to_string(), json!(result.applied));
    if result.manual {
        obj.insert("manual".to_string(), json!(true));
    }
    if let Some(err) = &result.error {
        obj.insert("error".to_string(), json!(err));
    }
    Value::Object(obj)
}

async fn auto_fix(State(state): State<Arc<AppState>>, Json(body): Json<Value>) -> Response {
    let _ = &state; // no shared state needed today — kept for parity with other handlers
    let raw_path = body.get("projectPath").and_then(|v| v.as_str()).unwrap_or("");
    let project_path = match ignite_tool_runner::sanitize_absolute_project_path(raw_path) {
        Ok(p) => p,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))).into_response(),
    };
    let meta = std::fs::metadata(&project_path).ok();
    if meta.as_ref().map(|m| !m.is_dir()).unwrap_or(true) {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": format!("projectPath does not exist or is not a directory: {}", project_path.display()) }))).into_response();
    }

    let dry_run = body.get("dryRun").and_then(|v| v.as_bool()).unwrap_or(true);
    let categories: std::collections::HashSet<String> = body
        .get("categories")
        .and_then(|v| v.as_array())
        .filter(|a| !a.is_empty())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_else(|| ["dead-code".to_string(), "ai-governance".to_string()].into_iter().collect());

    let mut findings = Vec::new();
    if categories.contains("dead-code") {
        match ignite_dead_code::check_dead_code(&project_path, &ignite_dead_code::DeadCodeConfig { enabled: true }) {
            Ok(result) => findings.extend(result.findings.into_iter().map(|f| FindingInput { kind: f.kind, file: f.file, line: Some(f.line), message: Some(f.message) })),
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))).into_response(),
        }
    }
    if categories.contains("ai-governance") {
        match ignite_ai_governance::check_ai_governance(&project_path, &HashMap::new()) {
            Ok((result, _)) => findings.extend(result.findings.into_iter().map(|f| FindingInput { kind: "ungoverned-ai-invocation".to_string(), file: f.file, line: Some(f.line), message: None })),
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))).into_response(),
        }
    }

    let plan = ignite_auto_fix::compute_auto_fix_plan(&findings);
    let (_, results) = ignite_auto_fix::apply_auto_fix_plan(plan, &project_path, dry_run);
    let actions: Vec<Value> = results.iter().map(action_to_json).collect();
    let action_count = actions.len();
    Json(json!({ "ok": true, "projectPath": project_path, "dryRun": dry_run, "actionCount": action_count, "actions": actions })).into_response()
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/pipeline/auto-fix", post(auto_fix))
}
