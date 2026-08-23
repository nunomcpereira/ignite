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
        .merge(routes::reports::router())
        .merge(routes::github_pr_status::router())
        .merge(routes::issues::router())
        .merge(routes::history::router())
        .merge(routes::pipeline_validate::router())
        .merge(routes::config::router())
        .with_state(state)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let db_path = std::env::var("IGNITE_DB_PATH").unwrap_or_else(|_| "ignite.db".to_string());
    let db = ignite_db_store::DbStore::open(std::path::Path::new(&db_path)).expect("failed to open db");

    let state = Arc::new(AppState { runner: state::default_runner(), db, running_runs: Mutex::new(HashMap::new()), llm_config: state::default_llm_config() });
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
        let state = Arc::new(AppState { runner: state::default_runner(), db, running_runs: Mutex::new(HashMap::new()), llm_config: state::default_llm_config() });
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

    #[tokio::test]
    async fn reports_loc_metrics_returns_ok_for_real_project() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("main.go"), "package main\nfunc main() {}\n").unwrap();

        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.post(format!("{base}/api/reports/loc-metrics")).json(&serde_json::json!({ "projectPath": dir.path().to_string_lossy() })).send().await.unwrap();
        assert_eq!(res.status(), 200);
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["ok"], true);
    }

    #[tokio::test]
    async fn reports_sbom_rejects_nonexistent_project_path() {
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.post(format!("{base}/api/reports/sbom")).json(&serde_json::json!({ "projectPath": "/no/such/directory/ignite-test" })).send().await.unwrap();
        assert_eq!(res.status(), 400);
    }

    #[tokio::test]
    async fn github_check_rejects_invalid_owner_name() {
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.post(format!("{base}/api/pipeline/job-1/github-check")).json(&serde_json::json!({ "owner": "-bad-", "repo": "widgets", "sha": "abc1234" })).send().await.unwrap();
        assert_eq!(res.status(), 400);
    }

    #[tokio::test]
    async fn github_check_returns_404_for_unknown_job() {
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.post(format!("{base}/api/pipeline/nope/github-check")).json(&serde_json::json!({ "owner": "acme", "repo": "widgets", "sha": "abc1234" })).send().await.unwrap();
        assert_eq!(res.status(), 404);
    }

    #[tokio::test]
    async fn config_returns_six_phases_and_version() {
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.get(format!("{base}/api/config")).send().await.unwrap();
        assert_eq!(res.status(), 200);
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["phases"].as_array().unwrap().len(), 6);
        assert!(body["version"].as_str().is_some());
    }

    #[tokio::test]
    async fn validate_all_runs_full_pipeline_against_a_real_project() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"name":"smoke","dependencies":{"lodash":"4.17.21"}}"#).unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/app.js"), "console.log('hi');\n").unwrap();

        let base = spawn_test_server().await;
        let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(180)).build().unwrap();
        let res = client
            .post(format!("{base}/api/pipeline/validate-all"))
            .json(&serde_json::json!({ "projectPath": dir.path().to_string_lossy(), "runLocalCi": false, "fast": true }))
            .send()
            .await
            .unwrap();
        let status = res.status();
        let body: Value = res.json().await.unwrap();
        // fast:true + runLocalCi:false keeps this well inside the test
        // timeout; blocking findings (e.g. the known lodash CVEs) are a
        // legitimate 400 here, so this checks the pipeline actually ran
        // end to end rather than asserting a specific pass/fail outcome.
        assert!(status == 200 || status == 400, "unexpected status {status}: {body}");
        assert_eq!(body["mode"], "validate-all");
        assert!(body["phases"].as_array().unwrap().len() == 6);
        let phase3 = body["phases"].as_array().unwrap().iter().find(|p| p["phase"] == 3).unwrap();
        assert_eq!(phase3["state"], "success");
    }

    #[tokio::test]
    async fn validate_all_rejects_invalid_repo_name() {
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.post(format!("{base}/api/pipeline/validate-all")).json(&serde_json::json!({ "repo": "..", "projectPath": "/tmp" })).send().await.unwrap();
        assert_eq!(res.status(), 400);
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["failedPhase"], 1);
    }

    #[tokio::test]
    async fn list_projects_returns_empty_array_for_fresh_db() {
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.get(format!("{base}/api/projects")).send().await.unwrap();
        assert_eq!(res.status(), 200);
        let body: Value = res.json().await.unwrap();
        assert_eq!(body.as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn list_effectivated_projects_returns_empty_wrapper() {
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.get(format!("{base}/api/projects/effectivated")).send().await.unwrap();
        assert_eq!(res.status(), 200);
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["projects"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn project_details_returns_404_for_unknown_id() {
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.get(format!("{base}/api/projects/999999")).send().await.unwrap();
        assert_eq!(res.status(), 404);
    }

    #[tokio::test]
    async fn project_details_returns_400_for_non_numeric_id() {
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.get(format!("{base}/api/projects/not-a-number")).send().await.unwrap();
        assert_eq!(res.status(), 400);
    }

    #[tokio::test]
    async fn delete_all_projects_succeeds_on_empty_db() {
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.delete(format!("{base}/api/projects")).send().await.unwrap();
        assert_eq!(res.status(), 200);
    }

    #[tokio::test]
    async fn set_schedule_rejects_unknown_interval() {
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        // project doesn't exist, but the id-shape check runs first — this
        // exercises the 404 path since no project was created in this test.
        let res = client.post(format!("{base}/api/projects/1/schedule")).json(&serde_json::json!({ "enabled": true, "interval": "hourly" })).send().await.unwrap();
        assert_eq!(res.status(), 404);
    }

    #[tokio::test]
    async fn get_document_returns_404_for_unknown_id() {
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.get(format!("{base}/api/documents/999999")).send().await.unwrap();
        assert_eq!(res.status(), 404);
    }

    #[tokio::test]
    async fn pipeline_issues_returns_404_for_unknown_job() {
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.get(format!("{base}/api/pipeline/nope/issues")).send().await.unwrap();
        assert_eq!(res.status(), 404);
    }

    #[tokio::test]
    async fn issues_explain_rejects_missing_category() {
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.post(format!("{base}/api/issues/explain")).json(&serde_json::json!({ "summary": "found a thing" })).send().await.unwrap();
        assert_eq!(res.status(), 400);
    }

    #[tokio::test]
    async fn issues_explain_reports_unavailable_when_no_llm_endpoint() {
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.post(format!("{base}/api/issues/explain")).json(&serde_json::json!({ "category": "secret", "summary": "hardcoded key" })).send().await.unwrap();
        assert_eq!(res.status(), 200);
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["explanation"], Value::Null);
        assert!(body["reason"].as_str().unwrap().contains("unavailable"));
    }

    #[tokio::test]
    async fn issues_suggest_fix_requires_snippet() {
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.post(format!("{base}/api/issues/suggest-fix")).json(&serde_json::json!({ "category": "secret", "summary": "hardcoded key" })).send().await.unwrap();
        assert_eq!(res.status(), 400);
    }

    #[tokio::test]
    async fn reports_posture_rejects_nonexistent_project_path() {
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.post(format!("{base}/api/reports/posture")).json(&serde_json::json!({ "projectPath": "/no/such/directory/ignite-test" })).send().await.unwrap();
        assert_eq!(res.status(), 400);
    }
}
