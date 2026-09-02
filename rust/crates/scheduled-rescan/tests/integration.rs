//! Full-orchestration test for `rescan_one`, against fakes on both sides
//! it talks to — never a real network/GitHub/`gh` call, matching the
//! pattern the rest of Ignite's external-tool integration suites use:
//! - GitHub: a fake `gh` binary on PATH (same style as
//!   `ignite-github-api`'s own tests) standing in for
//!   `default_branch`/`gh_clone_repo_branch`/`head_sha`.
//! - The Ignite server: a minimal axum stand-in for
//!   `POST /api/pipeline/validate-all` and
//!   `POST /api/pipeline/:jobId/github-check` — `scheduled-rescan` only
//!   ever talks to the real server over HTTP (it's a separate deployed
//!   process), so mocking that boundary is the real seam, not a
//!   simplification. `ignite-server` has no importable lib target to
//!   reuse its real router from an external crate, so this fakes the two
//!   response shapes `rescan_one` actually reads
//!   (`{jobId, issues}` / `200 OK`) rather than the full pipeline.

use axum::extract::Path as AxumPath;
use axum::routing::post;
use axum::{Json, Router};
use ignite_scheduled_rescan::{default_runner, rescan_one, RescanTarget};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

fn make_fake_gh(dir: &std::path::Path) {
    let script_path = dir.join("gh");
    let script = r#"#!/bin/sh
if [ "$1" = "--version" ]; then echo "gh version 2.0.0 fake"; exit 0; fi
if [ "$1" = "api" ] && [ "$2" = "repos/acme/widgets" ]; then echo '{"default_branch":"main"}'; exit 0; fi
if [ "$1" = "api" ] && [ "$2" = "repos/acme/widgets/commits/main" ]; then echo '{"sha":"deadbeef1234"}'; exit 0; fi
if [ "$1" = "repo" ] && [ "$2" = "clone" ]; then
  dest="$4"
  mkdir -p "$dest"
  echo '{"name":"fixture"}' > "$dest/package.json"
  exit 0
fi
echo "unexpected gh args: $@" >&2
exit 1
"#;
    std::fs::write(&script_path, script).unwrap();
    let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
    std::fs::set_permissions(&script_path, perms).unwrap();
}

#[derive(Clone, Default)]
struct FakeServerState {
    github_check_calls: Arc<Mutex<Vec<Value>>>,
    issues_to_return: Arc<Mutex<Vec<Value>>>,
    simulate_structural_failure: Arc<Mutex<bool>>,
}

async fn fake_validate_all(axum::extract::State(state): axum::extract::State<FakeServerState>) -> Json<Value> {
    if *state.simulate_structural_failure.lock().unwrap() {
        // Matches a real pipeline_validate.rs failure response: `ok: false`,
        // `issues: null` (not `[]`) — e.g. raw .env files found, a broken
        // unit test, a Phase 4 crash. Never the same thing as "issues: []".
        return Json(json!({ "ok": false, "jobId": "fake-job-1", "error": "Raw environment files detected (1). Remove them before validation.", "failedPhase": 3, "issues": Value::Null }));
    }
    let issues = state.issues_to_return.lock().unwrap().clone();
    Json(json!({ "ok": true, "jobId": "fake-job-1", "issues": issues }))
}

async fn fake_github_check(axum::extract::State(state): axum::extract::State<FakeServerState>, AxumPath(_job_id): AxumPath<String>, Json(body): Json<Value>) -> Json<Value> {
    state.github_check_calls.lock().unwrap().push(body);
    Json(json!({ "ok": true, "state": "failure" }))
}

async fn spawn_fake_server(state: FakeServerState) -> String {
    let router = Router::new().route("/api/pipeline/validate-all", post(fake_validate_all)).route("/api/pipeline/:job_id/github-check", post(fake_github_check)).with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    format!("http://{addr}")
}

static PATH_LOCK: Mutex<()> = Mutex::new(());

#[tokio::test]
async fn rescan_one_posts_github_check_when_issues_found() {
    let _guard = PATH_LOCK.lock().unwrap();
    let fake_gh_dir = tempfile::tempdir().unwrap();
    make_fake_gh(fake_gh_dir.path());
    let original_path = std::env::var("PATH").unwrap_or_default();
    std::env::set_var("PATH", format!("{}:{}", fake_gh_dir.path().display(), original_path));

    let state = FakeServerState { issues_to_return: Arc::new(Mutex::new(vec![json!({"category": "secret", "severity": "error"})])), ..Default::default() };
    let base = spawn_fake_server(state.clone()).await;

    let runner = default_runner();
    let http = reqwest::Client::new();
    let target = RescanTarget { org: "acme".to_string(), repo: "widgets".to_string() };
    let outcome = rescan_one(&runner, &http, &base, "tok", &target).await;

    std::env::set_var("PATH", &original_path);

    assert!(outcome.error.is_none(), "unexpected error: {:?}", outcome.error);
    assert_eq!(outcome.issue_count, 1);
    assert!(outcome.posted);
    let calls = state.github_check_calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0]["owner"], "acme");
    assert_eq!(calls[0]["repo"], "widgets");
    assert_eq!(calls[0]["sha"], "deadbeef1234");
}

#[tokio::test]
async fn rescan_one_is_a_noop_when_no_issues_found() {
    let _guard = PATH_LOCK.lock().unwrap();
    let fake_gh_dir = tempfile::tempdir().unwrap();
    make_fake_gh(fake_gh_dir.path());
    let original_path = std::env::var("PATH").unwrap_or_default();
    std::env::set_var("PATH", format!("{}:{}", fake_gh_dir.path().display(), original_path));

    let state = FakeServerState::default();
    let base = spawn_fake_server(state.clone()).await;

    let runner = default_runner();
    let http = reqwest::Client::new();
    let target = RescanTarget { org: "acme".to_string(), repo: "widgets".to_string() };
    let outcome = rescan_one(&runner, &http, &base, "tok", &target).await;

    std::env::set_var("PATH", &original_path);

    assert!(outcome.error.is_none());
    assert_eq!(outcome.issue_count, 0);
    assert!(!outcome.posted);
    assert!(state.github_check_calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn rescan_one_reports_error_not_silent_clean_on_structural_pipeline_failure() {
    let _guard = PATH_LOCK.lock().unwrap();
    let fake_gh_dir = tempfile::tempdir().unwrap();
    make_fake_gh(fake_gh_dir.path());
    let original_path = std::env::var("PATH").unwrap_or_default();
    std::env::set_var("PATH", format!("{}:{}", fake_gh_dir.path().display(), original_path));

    let state = FakeServerState { simulate_structural_failure: Arc::new(Mutex::new(true)), ..Default::default() };
    let base = spawn_fake_server(state.clone()).await;

    let runner = default_runner();
    let http = reqwest::Client::new();
    let target = RescanTarget { org: "acme".to_string(), repo: "widgets".to_string() };
    let outcome = rescan_one(&runner, &http, &base, "tok", &target).await;

    std::env::set_var("PATH", &original_path);

    // The critical assertion: a structural failure (ok:false, issues:null)
    // must NOT be reported as "clean, no findings" — that would silently
    // hide a real failure from an unattended scheduled job.
    assert!(outcome.error.is_some(), "structural pipeline failure was silently treated as clean");
    let err = outcome.error.unwrap();
    assert!(err.contains("phase 3"), "expected failed phase in error, got: {err}");
    assert!(err.contains("Raw environment files"), "expected server error message in error, got: {err}");
    assert_eq!(outcome.issue_count, 0);
    assert!(!outcome.posted);
    assert!(state.github_check_calls.lock().unwrap().is_empty());
}
