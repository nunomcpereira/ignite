//! Characterization of the phase sequence, lifecycle end state, coverage report
//! and override recording that validate-all and onboard each implement on their
//! own today. Written against the HTTP behavior only, so the sequencing can be
//! moved into a shared module without touching these tests.
use super::*;
use serde_json::{json, Value};

fn secret_project() -> tempfile::TempDir {
    let dir = agent_test_project();
    std::fs::write(dir.path().join("config.js"), "const aws_secret_key = 'AKIAABCDEFGHIJKLMNOP';\nconsole.log(aws_secret_key);\n").unwrap();
    dir
}

fn phase_states(body: &Value) -> Vec<(i64, String)> {
    body["phases"].as_array().unwrap().iter().map(|p| (p["phase"].as_i64().unwrap(), p["state"].as_str().unwrap().to_string())).collect()
}

fn coverage_ids(body: &Value) -> Vec<String> {
    let mut ids: Vec<String> = body["coverage"].as_array().unwrap().iter().map(|c| c["checkId"].as_str().unwrap().to_string()).collect();
    ids.sort();
    ids
}

fn lifecycle_of(state: &AppState, job_id: &str) -> (String, String) {
    let pid = state.db.get_project_id_by_job_id(job_id).unwrap_or_else(|| panic!("no project for job {job_id}"));
    let run = state.db.get_scan_run_for_legacy_project(pid).unwrap();
    (state.db.get_scan_run_lifecycle(run.id).unwrap(), state.db.get_project(pid).unwrap().status)
}

fn override_body(unresolved: &Value) -> Value {
    let ids = unresolved.as_array().unwrap();
    Value::Array(ids.iter().map(|id| json!({ "issueId": id, "justification": "Characterization run: reviewed and accepted for this fixture." })).collect())
}

fn audit_count(state: &AppState, event_type: &str) -> usize {
    state.db.list_audit_events(None, None, Some(event_type), None, None, None, None, 500).len()
}

#[tokio::test]
async fn validate_all_on_a_clean_project_runs_the_phases_in_order_and_ends_completed() {
    let (base, key, state) = spawn_test_server_with_state("seq-clean@example.com", None).await;
    let project = agent_test_project();
    let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(300)).build().unwrap();
    let res = client.post(format!("{base}/api/pipeline/validate-all")).bearer_auth(&key).json(&json!({ "projectPath": project.path().to_string_lossy(), "runLocalCi": false, "fast": true })).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();

    assert_eq!(body["ok"], true);
    assert_eq!(body["mode"], "validate-all");
    assert_eq!(body["policyDecision"]["decision"], "pass");
    assert_eq!(
        phase_states(&body),
        vec![(1, "success".to_string()), (2, "skipped".into()), (3, "success".into()), (4, "success".into()), (5, "skipped".into()), (6, "skipped".into())],
        "validate-all never reaches phase 6"
    );
    let ids = coverage_ids(&body);
    for expected in ["secrets", "governance", "semanticSast", "fileEncapsulation", "dependency-vulnerability", "codeql", "sbom", "boundaries"] {
        assert!(ids.iter().any(|i| i == expected), "coverage must name {expected}: {ids:?}");
    }
    assert_eq!(lifecycle_of(&state, body["jobId"].as_str().unwrap()), ("completed".to_string(), "success".to_string()), "a validate-all run is Completed, never Published");
    assert_eq!(audit_count(&state, "override.approved"), 0);
}

#[tokio::test]
async fn validate_all_with_a_planted_secret_is_blocked_then_passes_once_overridden_and_records_it() {
    let (base, key, state) = spawn_test_server_with_state("seq-block@example.com", None).await;
    let project = secret_project();
    let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(300)).build().unwrap();
    let request = json!({ "projectPath": project.path().to_string_lossy(), "runLocalCi": false, "fast": true });

    // 1. Blocked.
    let res = client.post(format!("{base}/api/pipeline/validate-all")).bearer_auth(&key).json(&request).send().await.unwrap();
    assert_eq!(res.status(), 400);
    let blocked: Value = res.json().await.unwrap();
    assert_eq!(blocked["ok"], false);
    assert_eq!(blocked["failedPhase"], 4);
    assert_eq!(blocked["blocked"], true);
    assert_eq!(blocked["blockReason"], "unresolved_findings");
    assert_eq!(blocked["overridable"], true);
    assert!(blocked["issues"].as_array().unwrap().iter().any(|i| i["category"] == "secret" && i["severity"] == "error"));
    assert_eq!(policy_decision(&blocked), "blocked");
    assert_eq!(
        phase_states(&blocked),
        vec![(1, "success".to_string()), (2, "skipped".into()), (3, "success".into()), (4, "failed".into()), (5, "pending".into()), (6, "pending".into())]
    );
    assert_eq!(lifecycle_of(&state, blocked["jobId"].as_str().unwrap()), ("blocked".to_string(), "failed".to_string()));
    assert_eq!(audit_count(&state, "gate.push_rejected"), 0, "validate-all never records a push rejection (only onboard does)");

    // 2. Overridden with an API key: passes, and every override is recorded.
    let unresolved = &blocked["unresolvedIssueIds"];
    let mut with_overrides = request.clone();
    with_overrides["overrides"] = override_body(unresolved);
    let res = client.post(format!("{base}/api/pipeline/validate-all")).bearer_auth(&key).json(&with_overrides).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let passed: Value = res.json().await.unwrap();
    assert_eq!(passed["ok"], true);
    assert_eq!(policy_decision(&passed), "pass");
    let n = unresolved.as_array().unwrap().len();
    let overridden = passed["issues"].as_array().unwrap().iter().filter(|i| i["status"] == "overridden").count();
    assert_eq!(overridden, n, "every unresolved blocking issue is marked overridden in the response");

    let job_id = passed["jobId"].as_str().unwrap();
    assert_eq!(lifecycle_of(&state, job_id), ("completed".to_string(), "success".to_string()));
    let pid = state.db.get_project_id_by_job_id(job_id).unwrap();
    let rows = state.db.get_project_overrides(pid);
    assert_eq!(rows.len(), n);
    for o in &rows {
        assert_eq!(o.actor_email, "seq-block@example.com");
        assert_eq!(o.origin, "api_key");
        assert_eq!(o.severity, "error");
        assert_eq!(o.phase, 4);
    }
    assert_eq!(audit_count(&state, "override.approved"), n, "one audit event per override");
    assert_eq!(audit_count(&state, "override.pending_approval"), 0);
}

fn policy_decision(body: &Value) -> String {
    body["policyDecision"]["decision"].as_str().unwrap_or("").to_string()
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn onboard_dry_run_on_a_clean_project_ends_completed_and_registers_a_snapshot() {
    let _data_guard = crate::state::IGNITE_DATA_DIR_ENV_GUARD.lock();
    let data_dir = tempfile::tempdir().unwrap();
    std::env::set_var("IGNITE_DATA_DIR", data_dir.path());
    let config = ignite_config::Config { phases: vec![json!({ "id": 4, "enabled": false })], ..Default::default() };
    let (base, key, state) = spawn_test_server_with_state_and_config("seq-onboard@example.com", None, config).await;
    let project = agent_test_project();
    let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(300)).build().unwrap();
    let res = client.post(format!("{base}/api/pipeline/onboard")).bearer_auth(&key).json(&json!({ "org": "acme", "repo": "seq-widgets", "projectPath": project.path().to_string_lossy(), "dryRun": true, "runLocalCi": false })).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();

    assert_eq!(body["ok"], true);
    assert_eq!(body["mode"], "onboard");
    assert_eq!(body["dryRun"], true);
    assert_eq!(policy_decision(&body), "pass");
    let states = phase_states(&body);
    assert_eq!(states.first(), Some(&(1, "success".to_string())));
    assert_eq!(states.iter().find(|(p, _)| *p == 3).map(|(_, s)| s.as_str()), Some("success"));
    assert_eq!(states.iter().find(|(p, _)| *p == 6).map(|(_, s)| s.as_str()), Some("skipped"), "a dry run never provisions or pushes");
    assert_eq!(lifecycle_of(&state, body["jobId"].as_str().unwrap()), ("completed".to_string(), "success".to_string()), "a dry run is Completed, never Published");
    assert_eq!(body["effectivatable"], true);
    assert!(state.db.get_pending_effectivation(body["projectId"].as_i64().unwrap()).is_some());
    assert!(body["repoUrl"].is_null() && body["prUrl"].is_null());
    std::env::remove_var("IGNITE_DATA_DIR");
}

/// Full Phase 4 runs here (about a minute on an idle machine).
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn onboard_with_a_planted_secret_is_blocked_then_passes_once_overridden_and_records_it() {
    let _data_guard = crate::state::IGNITE_DATA_DIR_ENV_GUARD.lock();
    let data_dir = tempfile::tempdir().unwrap();
    std::env::set_var("IGNITE_DATA_DIR", data_dir.path());
    let (base, key, state) = spawn_test_server_with_state("seq-onboard-block@example.com", None).await;
    let project = secret_project();
    let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(600)).build().unwrap();
    let request = json!({ "org": "acme", "repo": "seq-block", "projectPath": project.path().to_string_lossy(), "dryRun": true, "runLocalCi": false });

    // 1. Blocked, and the rejection is audited (onboard does this; validate-all doesn't).
    let res = client.post(format!("{base}/api/pipeline/onboard")).bearer_auth(&key).json(&request).send().await.unwrap();
    assert_eq!(res.status(), 400);
    let blocked: Value = res.json().await.unwrap();
    assert_eq!((blocked["failedPhase"].as_i64(), blocked["blocked"].as_bool(), blocked["blockReason"].as_str()), (Some(4), Some(true), Some("unresolved_findings")));
    assert!(blocked["issues"].as_array().unwrap().iter().any(|i| i["category"] == "secret"));
    assert_eq!(lifecycle_of(&state, blocked["jobId"].as_str().unwrap()), ("blocked".to_string(), "failed".to_string()));
    assert_eq!(audit_count(&state, "gate.push_rejected"), 1);
    assert!(state.db.get_pending_effectivation(blocked["projectId"].as_i64().unwrap()).is_none(), "a blocked run registers no snapshot");

    // 2. Overridden: passes, recorded with origin and audit events.
    let unresolved = blocked["unresolvedIssueIds"].clone();
    let mut with_overrides = request.clone();
    with_overrides["overrides"] = override_body(&unresolved);
    let res = client.post(format!("{base}/api/pipeline/onboard")).bearer_auth(&key).json(&with_overrides).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let passed: Value = res.json().await.unwrap();
    assert_eq!(passed["ok"], true);
    let n = unresolved.as_array().unwrap().len();
    let pid = passed["projectId"].as_i64().unwrap();
    let rows = state.db.get_project_overrides(pid);
    assert_eq!(rows.len(), n);
    assert!(rows.iter().all(|o| o.actor_email == "seq-onboard-block@example.com" && o.origin == "api_key" && o.phase == 4));
    assert_eq!(audit_count(&state, "override.approved"), n);
    assert_eq!(lifecycle_of(&state, passed["jobId"].as_str().unwrap()), ("completed".to_string(), "success".to_string()));
    assert_eq!(passed["effectivatable"], true);
    std::env::remove_var("IGNITE_DATA_DIR");
}
