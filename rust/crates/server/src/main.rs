//! Ignite's HTTP server — Rust port of `server.js`'s route layer.
//! Session auth, the streaming pipeline endpoints, and upload handling
//! aren't ported yet — see each `routes/*.rs` module's doc comment for
//! what it covers.

mod routes;
mod state;

use state::AppState;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

fn build_router(state: Arc<AppState>) -> axum::Router {
    axum::Router::new()
        .merge(routes::tools_status::router())
        .merge(routes::sarif::router())
        .merge(routes::github_annotations::router())
        .merge(routes::baseline::router())
        .merge(routes::runtime_coverage::router())
        .merge(routes::auto_fix::router())
        .merge(routes::dependencies::router())
        .with_state(state)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let db_path = std::env::var("IGNITE_DB_PATH").unwrap_or_else(|_| "ignite.db".to_string());
    let db = ignite_db_store::DbStore::open(std::path::Path::new(&db_path)).expect("failed to open db");

    let state = Arc::new(AppState { runner: state::default_runner(), db, running_runs: Mutex::new(HashMap::new()) });
    let app = build_router(state);

    let port: u16 = std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(51337);
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await.expect("failed to bind port");
    tracing::info!("Ignite (Rust) listening on http://0.0.0.0:{port}");
    axum::serve(listener, app).await.expect("server error");
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    async fn spawn_test_server() -> String {
        let db_dir = tempfile::tempdir().unwrap();
        let db = ignite_db_store::DbStore::open(&db_dir.path().join("test.db")).unwrap();
        let state = Arc::new(AppState { runner: state::default_runner(), db, running_runs: Mutex::new(HashMap::new()) });
        let app = build_router(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        // leak the tempdir so the db file survives for the life of the test process
        std::mem::forget(db_dir);
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn tools_status_returns_every_expected_key() {
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.get(format!("{base}/api/tools/status")).send().await.unwrap();
        assert_eq!(res.status(), 200);
        let body: Value = res.json().await.unwrap();
        for key in ["ort", "licensee", "gitleaks", "trivy", "trivyImage", "checkov", "hadolint", "syft", "cosign", "semgrep", "bearer", "jscpd", "gocloc", "spectral", "guarddog", "codeql", "picklescan", "oasdiff"] {
            assert!(body.get(key).is_some(), "missing key: {key}");
        }
    }

    #[tokio::test]
    async fn sarif_route_returns_404_for_unknown_job() {
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.get(format!("{base}/api/pipeline/nope/sarif")).send().await.unwrap();
        assert_eq!(res.status(), 404);
    }

    #[tokio::test]
    async fn annotations_route_returns_404_for_unknown_job() {
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.get(format!("{base}/api/pipeline/nope/annotations")).send().await.unwrap();
        assert_eq!(res.status(), 404);
    }

    #[tokio::test]
    async fn baseline_round_trip_save_get_delete() {
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();

        let res = client.post(format!("{base}/api/baseline/acme/widgets")).json(&serde_json::json!({ "issueIds": ["a", "b"] })).send().await.unwrap();
        assert_eq!(res.status(), 200);
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["savedCount"], 2);

        let res = client.get(format!("{base}/api/baseline/acme/widgets")).send().await.unwrap();
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["count"], 2);

        let res = client.delete(format!("{base}/api/baseline/acme/widgets")).send().await.unwrap();
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["removed"], 2);
    }

    #[tokio::test]
    async fn baseline_save_rejects_missing_issue_ids() {
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.post(format!("{base}/api/baseline/acme/widgets")).json(&serde_json::json!({})).send().await.unwrap();
        assert_eq!(res.status(), 400);
    }

    #[tokio::test]
    async fn runtime_coverage_round_trip() {
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();

        let res = client.post(format!("{base}/api/runtime-coverage/acme/widgets")).json(&serde_json::json!({ "src/a.js": 5, "src/b.js": 0 })).send().await.unwrap();
        assert_eq!(res.status(), 200);
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["format"], "simple");
        assert_eq!(body["filesIngested"], 2);

        let res = client.get(format!("{base}/api/runtime-coverage/acme/widgets")).send().await.unwrap();
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["files"]["src/a.js"]["hitCount"], 5);

        let res = client.delete(format!("{base}/api/runtime-coverage/acme/widgets")).send().await.unwrap();
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["removed"], 2);
    }

    #[tokio::test]
    async fn auto_fix_rejects_nonexistent_project_path() {
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.post(format!("{base}/api/pipeline/auto-fix")).json(&serde_json::json!({ "projectPath": "/no/such/directory/ignite-test" })).send().await.unwrap();
        assert_eq!(res.status(), 400);
    }

    #[tokio::test]
    async fn auto_fix_dry_run_reports_dead_code_findings() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("orphan.js"), "module.exports = 1;\n").unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"name":"x","main":"index.js"}"#).unwrap();
        std::fs::write(dir.path().join("index.js"), "console.log(1);\n").unwrap();

        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.post(format!("{base}/api/pipeline/auto-fix")).json(&serde_json::json!({ "projectPath": dir.path().to_string_lossy(), "categories": ["dead-code"] })).send().await.unwrap();
        assert_eq!(res.status(), 200);
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["dryRun"], true);
        assert!(body["actionCount"].as_u64().unwrap() >= 1);
    }

    #[tokio::test]
    async fn dependencies_check_rejects_nonexistent_project_path() {
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.post(format!("{base}/api/dependencies/check")).json(&serde_json::json!({ "projectPath": "/no/such/directory/ignite-test" })).send().await.unwrap();
        assert_eq!(res.status(), 400);
    }
}
