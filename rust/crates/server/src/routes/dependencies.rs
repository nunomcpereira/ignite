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

#[allow(clippy::result_large_err)]
fn sanitize_project_path(body: &Value) -> Result<PathBuf, Response> {
    let raw_path = body.get("projectPath").and_then(|v| v.as_str()).unwrap_or("");
    let project_path = ignite_tool_runner::sanitize_absolute_project_path(raw_path).map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))).into_response())?;
    let meta = std::fs::metadata(&project_path).ok();
    if meta.as_ref().map(|m| !m.is_dir()).unwrap_or(true) {
        return Err((StatusCode::BAD_REQUEST, Json(json!({ "error": format!("projectPath does not exist or is not a directory: {}", project_path.display()) }))).into_response());
    }
    Ok(project_path)
}

async fn check_licenses(State(state): State<Arc<AppState>>, crate::auth::RequireAuth(_user): crate::auth::RequireAuth, Json(body): Json<Value>) -> Response {
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

const DEPENDENCY_VALIDATE_PROMPT: &str = "You are a software-licensing/dependency-compliance reviewer. You are given a list of dependencies from a project's manifest, each already classified by an automated scanner into a compliance tier (open source / copyleft / commercial-risk) with a license and a reason.\nYour job: sanity-check these classifications using your own knowledge of these specific packages and licenses. Flag ONLY entries you have good reason to believe are misclassified (e.g. a well-known permissive open-source license reported as commercial/risk because the scanner didn't recognize its SPDX identifier, a copyleft license miscategorized as open source, or a package/version that doesn't plausibly exist). Do not flag anything you are not reasonably confident about — false alarms are worse than staying silent here.\nRespond in plain text, concise, structured as:\nSUMMARY: <one sentence: overall assessment>\nFLAGGED: <for each flagged entry, one line: \"<package> — <what looks wrong> — <what it should probably be>\"; write \"None.\" if nothing is flagged>\nDo not include any other text, headers, or formatting.";

/// `POST /api/dependencies/validate-ai` — takes the dependency list the UI
/// already has rendered (from a prior `/api/dependencies/check` or
/// `/studio/dependencies` call) and asks the configured LLM to sanity-check
/// the scanner's own tier/license classifications, the same "ask an LLM to
/// double-check a specific automated result" pattern `routes/issues.rs`'s
/// `explain`/`suggest_fix` already use. Stateless/no caching (unlike
/// `explain`, there's no single stable hash key for an arbitrary dependency
/// list) — cheap enough to just re-run per click.
async fn validate_dependencies_ai(State(state): State<Arc<AppState>>, crate::auth::RequireAuth(_user): crate::auth::RequireAuth, Json(body): Json<Value>) -> Response {
    let Some(deps) = body.get("dependencies").and_then(|v| v.as_array()).filter(|a| !a.is_empty()) else {
        return err_json(StatusCode::BAD_REQUEST, "dependencies (non-empty array) is required.");
    };
    if deps.len() > 500 {
        return err_json(StatusCode::BAD_REQUEST, "Too many dependencies for one AI validation pass (max 500) — narrow the manifest first.");
    }

    let http = reqwest::Client::new();
    if !ignite_llm_client::llm_available(&http, &state.llm_config).await {
        return Json(json!({ "ok": true, "report": Value::Null, "reason": "AI validation service unavailable." })).into_response();
    }

    let lines: Vec<String> = deps
        .iter()
        .map(|d| {
            let name = d.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            let version = d.get("version").or_else(|| d.get("versionRange")).and_then(|v| v.as_str()).unwrap_or("?");
            let licenses = d.get("licenses").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|l| l.as_str()).collect::<Vec<_>>().join(", ")).filter(|s| !s.is_empty()).unwrap_or_else(|| "?".to_string());
            let tier = d.get("tier").and_then(|v| v.as_str()).unwrap_or("?");
            let reason = d.get("reason").and_then(|v| v.as_str()).unwrap_or("");
            format!("- {name}@{version} | license(s): {licenses} | tier: {tier} | reason: {reason}")
        })
        .collect();
    let user_content = format!("Dependencies ({} total):\n{}", deps.len(), lines.join("\n"));

    match ignite_llm_client::llm_complete(
        &ignite_llm_client::LlmCompleteRequest { client: &http, config: &state.llm_config, system_prompt: DEPENDENCY_VALIDATE_PROMPT, user_content: &user_content, temperature: 0.1, timeout_ms: 60_000, label: "dependency-validate-ai" },
        |_| {},
    )
    .await
    {
        Ok(report) => Json(json!({ "ok": true, "report": report })).into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, Json(json!({ "ok": false, "error": e.to_string() }))).into_response(),
    }
}

fn err_json(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(json!({ "error": message.into() }))).into_response()
}

async fn check_vulnerabilities(State(_state): State<Arc<AppState>>, crate::auth::RequireAuth(_user): crate::auth::RequireAuth, Json(body): Json<Value>) -> Response {
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
    Router::new()
        .route("/api/dependencies/check", post(check_licenses))
        .route("/api/dependencies/vulnerabilities", post(check_vulnerabilities))
        .route("/api/dependencies/validate-ai", post(validate_dependencies_ai))
}
