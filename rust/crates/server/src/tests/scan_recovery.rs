//! US-18: queued and running scans survive a server restart.
use super::*;
use serde_json::{json, Value};

/// Simulates what a killed process leaves behind, then runs the startup
/// recovery the next process runs.
#[tokio::test]
async fn work_left_by_a_dead_process_is_requeued_and_finishes_without_resubmission() {
    let (_base, _key, state) = spawn_test_server_with_state("recover@example.com", None).await;
    let project = agent_test_project();
    let async_job = uuid::Uuid::new_v4().to_string();
    state.db.create_async_job(&async_job, "validate-all", None);
    let body = |repo: &str, async_id: Option<&str>| {
        let mut b = json!({ "org": "acme", "repo": repo, "projectPath": project.path().to_string_lossy(), "runLocalCi": false, "fast": true });
        if let Some(a) = async_id {
            b["_asyncJobId"] = json!(a);
        }
        json!({ "body": b }).to_string()
    };
    let insert = |id: &str, kind: &str, lane: &str, repo: &str, payload: Option<String>, seq: i64| {
        state.db.insert_scan_job(&ignite_db_store::NewScanJob { id, kind, lane, org: Some("acme"), repo: Some(repo), source: "validate-all", actor: None, payload_json: payload.as_deref(), seq });
    };
    // Was running in the dead process (an async caller is polling for it)...
    insert("running-job", "validate_all", "user", "running", Some(body("running", Some(&async_job))), 1);
    assert!(state.db.claim_scan_job("running-job", "dead-process", 600).is_some());
    // ...one was still waiting, and an upload can't run without its client.
    insert("waiting-job", "validate_all", "background", "waiting", Some(body("waiting", None)), 2);
    insert("upload-job", "upload", "user", "upload", None, 3);

    let resumed = crate::routes::scan_queue::recover_after_restart(&state);
    assert_eq!(resumed, vec![async_job.clone()], "the async caller's job is still going to be answered");
    assert_eq!(state.db.fail_unfinished_async_jobs_except(7, &resumed), 0);
    assert_eq!(state.db.get_scan_job("upload-job").unwrap().state, "failed");

    let done = |id: &str| state.db.get_scan_job(id).map(|j| j.state == "done").unwrap_or(false);
    tokio::time::timeout(std::time::Duration::from_secs(600), async {
        while !(done("running-job") && done("waiting-job")) {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("re-queued jobs never finished");

    let running = state.db.get_scan_job("running-job").unwrap();
    assert_eq!((running.restarts, running.attempt), (1, 2), "the restart is counted and the job was claimed again");
    let result = state.db.get_async_job(&async_job).unwrap();
    assert_eq!(result.state, "done");
    let value: Value = serde_json::from_str(result.result_json.as_deref().unwrap()).unwrap();
    assert_eq!(value["mode"], "validate-all", "{value}");
    assert!(value["jobId"].as_str().is_some_and(|j| j != async_job), "the re-run gets its own pipeline job id");
    assert!(state.db.list_audit_events(None, None, Some("scan.requeued_after_restart"), None, None, None, None, 10).len() >= 1);
}
