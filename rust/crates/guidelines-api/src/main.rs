//! REST API exposing the same company AI validation guidelines as
//! mcp-server.js, for callers that want plain HTTP instead of MCP.
//! Faithful port of `guidelines-api.js`.

use axum::extract::{ConnectInfo, Path, Query};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ignite_guidelines::catalog::Severity;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;

/// `/check-project` resolves and reads arbitrary paths on the host
/// filesystem by design — this is a local dev/CI tool for scanning your
/// own checkouts, not a multi-tenant service, so there is no per-path
/// allowlist to enforce. The real boundary is that nothing here should
/// ever be reachable except from the same machine: binding to 127.0.0.1
/// (the default) is the primary control; this middleware is defense in
/// depth for that same invariant, enforced per-request regardless of how/
/// where the process ends up bound.
fn is_loopback_address(addr: &std::net::IpAddr) -> bool {
    match addr {
        std::net::IpAddr::V4(v4) => v4.is_loopback(),
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.to_ipv4_mapped().map(|v4| v4.is_loopback()).unwrap_or(false),
    }
}

async fn loopback_only(ConnectInfo(addr): ConnectInfo<SocketAddr>, req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    if !is_loopback_address(&addr.ip()) {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "This API only accepts connections from localhost." }))).into_response();
    }
    next.run(req).await
}

async fn health() -> Json<Value> {
    Json(json!({ "ok": true }))
}

async fn list_guidelines(Query(query): Query<HashMap<String, String>>) -> Response {
    let category = query.get("category").map(String::as_str);
    let severity = match query.get("severity").map(String::as_str) {
        None => None,
        Some("error") => Some(Severity::Error),
        Some("warning") => Some(Severity::Warning),
        Some(_) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": "severity must be \"error\" or \"warning\"" }))).into_response(),
    };
    let guidelines = ignite_guidelines::catalog::list_guidelines(category, severity);
    let categories = ignite_guidelines::catalog::list_categories();
    Json(json!({ "guidelines": guidelines, "categories": categories })).into_response()
}

async fn get_guideline(Path(id): Path<String>) -> Response {
    match ignite_guidelines::catalog::get_guideline(&id) {
        Some(g) => Json(g).into_response(),
        None => (StatusCode::NOT_FOUND, Json(json!({ "error": format!("No guideline with id \"{id}\".") }))).into_response(),
    }
}

async fn check(Json(body): Json<Value>) -> Response {
    let content = body.get("content").and_then(|v| v.as_str());
    let Some(content) = content.filter(|c| !c.is_empty()) else {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "\"content\" (string) is required." }))).into_response();
    };
    let rel_path = body.get("path").and_then(|v| v.as_str()).unwrap_or("");
    let violations = ignite_guidelines::checks::check_content(content, rel_path);
    let has_blocking = violations.iter().any(|v| v.severity == Severity::Error);
    Json(json!({ "violations": violations, "hasBlockingViolations": has_blocking })).into_response()
}

async fn check_project(Json(body): Json<Value>) -> Response {
    let project_path = body.get("projectPath").and_then(|v| v.as_str());
    let Some(project_path) = project_path.filter(|p| !p.is_empty()) else {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "\"projectPath\" (string, absolute path) is required." }))).into_response();
    };
    let root = match std::fs::canonicalize(project_path) {
        Ok(r) => r,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": format!("Path does not exist: {project_path}") }))).into_response(),
    };
    if !root.is_dir() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": format!("Path is not a directory: {}", root.display()) }))).into_response();
    }
    match ignite_guidelines::checks::check_project(&root) {
        Ok(result) => {
            let has_blocking = result.violations.iter().any(|v| v.severity == Severity::Error);
            Json(json!({ "scanned": result.scanned, "violations": result.violations, "hasBlockingViolations": has_blocking })).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))).into_response(),
    }
}

fn build_router() -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/guidelines", get(list_guidelines))
        .route("/guidelines/:id", get(get_guideline))
        .route("/check", post(check))
        .route("/check-project", post(check_project))
        .layer(axum::middleware::from_fn(loopback_only))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let port: u16 = std::env::var("GUIDELINES_API_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8090);
    let host = std::env::var("GUIDELINES_API_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let addr: SocketAddr = format!("{host}:{port}").parse().expect("invalid GUIDELINES_API_HOST/PORT");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("failed to bind port");
    tracing::info!("AI validation guidelines API listening on {host}:{port}");
    axum::serve(listener, build_router().into_make_service_with_connect_info::<SocketAddr>()).await.expect("server error");
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn loopback_address_recognizes_v4_and_v6_loopback() {
        assert!(is_loopback_address(&"127.0.0.1".parse().unwrap()));
        assert!(is_loopback_address(&"::1".parse().unwrap()));
        assert!(!is_loopback_address(&"10.0.0.5".parse().unwrap()));
        assert!(!is_loopback_address(&"8.8.8.8".parse().unwrap()));
    }

    async fn spawn_test_server() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, build_router().into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn health_returns_ok() {
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.get(format!("{base}/health")).send().await.unwrap();
        assert_eq!(res.status(), 200);
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["ok"], true);
    }

    #[tokio::test]
    async fn list_guidelines_returns_catalog() {
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.get(format!("{base}/guidelines")).send().await.unwrap();
        assert_eq!(res.status(), 200);
        let body: Value = res.json().await.unwrap();
        assert!(body["guidelines"].as_array().unwrap().len() > 0);
        assert!(body["categories"].as_array().unwrap().len() > 0);
    }

    #[tokio::test]
    async fn list_guidelines_rejects_invalid_severity() {
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.get(format!("{base}/guidelines?severity=critical")).send().await.unwrap();
        assert_eq!(res.status(), 400);
    }

    #[tokio::test]
    async fn get_guideline_returns_404_for_unknown_id() {
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.get(format!("{base}/guidelines/no-such-guideline")).send().await.unwrap();
        assert_eq!(res.status(), 404);
    }

    #[tokio::test]
    async fn check_rejects_missing_content() {
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.post(format!("{base}/check")).json(&serde_json::json!({})).send().await.unwrap();
        assert_eq!(res.status(), 400);
    }

    #[tokio::test]
    async fn check_project_rejects_missing_path() {
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.post(format!("{base}/check-project")).json(&serde_json::json!({})).send().await.unwrap();
        assert_eq!(res.status(), 400);
    }

    #[tokio::test]
    async fn check_project_rejects_nonexistent_path() {
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.post(format!("{base}/check-project")).json(&serde_json::json!({ "projectPath": "/no/such/directory/ignite-test" })).send().await.unwrap();
        assert_eq!(res.status(), 400);
    }

    #[tokio::test]
    async fn check_project_scans_a_real_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.js"), "console.log('hi');\n").unwrap();
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.post(format!("{base}/check-project")).json(&serde_json::json!({ "projectPath": dir.path().to_string_lossy() })).send().await.unwrap();
        assert_eq!(res.status(), 200);
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["scanned"], 1);
    }
}
