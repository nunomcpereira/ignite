//! US-14: every entry point leaves the same end-of-scan record — evidence
//! manifest, check executions, policy decision and finding history — for
//! passing and blocked runs alike.
use super::*;
use serde_json::{json, Value};

const SECRET_JS: &str = "const aws_secret_key = 'AKIAABCDEFGHIJKLMNOP';\nconsole.log(aws_secret_key);\n";

fn secret_project() -> tempfile::TempDir {
    let dir = agent_test_project();
    std::fs::write(dir.path().join("config.js"), SECRET_JS).unwrap();
    dir
}

fn client() -> reqwest::Client {
    reqwest::Client::builder().timeout(std::time::Duration::from_secs(600)).build().unwrap()
}

fn run_for_job(state: &AppState, job_id: &str) -> ignite_db_store::ScanRunRow {
    let pid = state.db.get_project_id_by_job_id(job_id).unwrap_or_else(|| panic!("no project for job {job_id}"));
    state.db.get_scan_run_for_legacy_project(pid).unwrap()
}

/// The four records US-14 requires, for one run that found a planted secret.
fn assert_full_record(state: &AppState, run: &ignite_db_store::ScanRunRow, expected_decision: &str) {
    let manifest: Value = serde_json::from_str(&state.db.get_evidence_manifest(run.id).expect("evidence manifest")).unwrap();
    assert!(manifest["sourceDigest"].as_str().unwrap().starts_with("sha256:"), "{manifest}");
    let decision = state.db.get_policy_decision(run.id).expect("policy decision");
    assert_eq!(serde_json::to_value(decision.decision).unwrap(), expected_decision);
    let findings = state.db.list_findings_for_repository(run.repository_id);
    assert!(findings.iter().any(|f| f.category == "secret" && f.first_seen_run_id == Some(run.id)), "secret finding not tracked: {findings:?}");
}

#[tokio::test]
async fn a_blocked_validate_all_run_still_records_evidence_and_finding_history() {
    let (base, key, state) = spawn_test_server_with_state("fin-validate@example.com", None).await;
    let project = secret_project();
    let res = client().post(format!("{base}/api/pipeline/validate-all")).bearer_auth(&key).json(&json!({ "org": "acme", "repo": "fin-validate", "projectPath": project.path().to_string_lossy(), "runLocalCi": false, "fast": true })).send().await.unwrap();
    assert_eq!(res.status(), 400);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["blockReason"], "unresolved_findings");
    assert_full_record(&state, &run_for_job(&state, body["jobId"].as_str().unwrap()), "blocked");
}

#[tokio::test]
async fn a_blocked_onboard_run_records_evidence_finding_history_and_a_policy_decision() {
    let (base, key, state) = spawn_test_server_with_state("fin-onboard@example.com", None).await;
    let project = secret_project();
    let res = client().post(format!("{base}/api/pipeline/onboard")).bearer_auth(&key).json(&json!({ "org": "acme", "repo": "fin-onboard", "projectPath": project.path().to_string_lossy(), "dryRun": true, "runLocalCi": false })).send().await.unwrap();
    assert_eq!(res.status(), 400);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["policyDecision"]["decision"], "blocked", "{body}");
    let job_id = body["jobId"].as_str().unwrap();
    assert_full_record(&state, &run_for_job(&state, job_id), "blocked");

    // The evidence route serves it too.
    let ev = client().get(format!("{base}/api/pipeline/{job_id}/evidence")).bearer_auth(&key).send().await.unwrap();
    assert_eq!(ev.status(), 200);
}

fn zip_bytes(files: &[(&str, &str)]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let opts: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default();
        for (name, data) in files {
            writer.start_file(*name, opts).unwrap();
            std::io::Write::write_all(&mut writer, data.as_bytes()).unwrap();
        }
        writer.finish().unwrap();
    }
    buf
}

#[tokio::test]
async fn an_interactive_upload_records_evidence_and_reports_coverage_and_policy_on_done() {
    let owner = "fin-upload@example.com";
    let (base, key, state) = spawn_test_server_with_state(owner, None).await;
    let zip = zip_bytes(&[("package.json", r#"{"name":"fixture"}"#), ("app.js", "console.log(1);\n"), ("config.js", SECRET_JS)]);
    let form = reqwest::multipart::Form::new().text("org", "acme").text("repo", "fin-upload").text("dryRun", "true").part("archive", reqwest::multipart::Part::bytes(zip).file_name("p.zip"));
    let req = client().post(format!("{base}/api/pipeline")).bearer_auth(&key).multipart(form);
    let handle = tokio::spawn(async move { req.send().await.unwrap() });

    // The planted secret always pauses the run at the review gate; decline.
    let job_id = tokio::time::timeout(std::time::Duration::from_secs(300), async {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            if let Some((id, _)) = state.running_runs.lock().iter().find(|(_, r)| r.review_active) {
                return id.clone();
            }
        }
    })
    .await
    .expect("run never reached the review gate");
    // Recorded before the gate — the scan is done even while a human decides.
    assert!(state.db.get_evidence_manifest(run_for_job(&state, &job_id).id).is_some(), "evidence must exist while awaiting review");
    let resolved = state.review_gate.resolve(
        &job_id,
        owner,
        crate::review_gate::ReviewDecisionInput { proceed: false, overrides: vec![], actor: crate::review_gate::Actor { email: owner.into(), name: "Owner".into() }, origin: "session" },
    );
    assert_eq!(resolved, crate::review_gate::ResolveOutcome::Resolved);

    let res = handle.await.unwrap();
    let text = res.text().await.unwrap();
    let done: Value = text.lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()).find(|e| e["type"] == "done").expect("done event");
    assert_eq!(done["ok"], false);
    assert!(done["coverage"].as_array().is_some_and(|c| c.iter().any(|x| x["checkId"] == "secrets")), "{done}");
    assert_eq!(done["policyDecision"]["decision"], "blocked", "{done}");
    assert_full_record(&state, &run_for_job(&state, &job_id), "blocked");
}

#[tokio::test]
async fn identical_source_dedupes_onto_one_snapshot_across_entry_points() {
    let (base, key, state) = spawn_test_server_with_state("fin-dedupe@example.com", None).await;
    let project = secret_project();
    let path = project.path().to_string_lossy().to_string();
    let a: Value = client().post(format!("{base}/api/pipeline/validate-all")).bearer_auth(&key).json(&json!({ "org": "acme", "repo": "fin-dedupe", "projectPath": path, "runLocalCi": false })).send().await.unwrap().json().await.unwrap();
    let b: Value = client().post(format!("{base}/api/pipeline/onboard")).bearer_auth(&key).json(&json!({ "org": "acme", "repo": "fin-dedupe", "projectPath": path, "dryRun": true, "runLocalCi": false })).send().await.unwrap().json().await.unwrap();
    let ra = run_for_job(&state, a["jobId"].as_str().unwrap());
    let rb = run_for_job(&state, b["jobId"].as_str().unwrap());
    assert_ne!(ra.id, rb.id);
    assert_eq!(ra.snapshot_id, rb.snapshot_id, "byte-identical source must share one snapshot");
}

/// Org scans (`retainSource`) keep only each repo's latest scanned tree:
/// Studio opens the newest run live, and the previous run's copy is gone.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn an_org_scan_keeps_only_the_repos_latest_source() {
    let _data_guard = crate::state::IGNITE_DATA_DIR_ENV_GUARD.lock();
    let data_dir = tempfile::tempdir().unwrap();
    std::env::set_var("IGNITE_DATA_DIR", data_dir.path());
    let (base, key, state) = spawn_test_server_with_state("fin-retain@example.com", None).await;
    let project = agent_test_project();
    let scan = |retain: bool| {
        let body = json!({ "org": "acme", "repo": "fin-retain", "projectPath": project.path().to_string_lossy(), "runLocalCi": false, "fast": true, "retainSource": retain });
        client().post(format!("{base}/api/pipeline/validate-all")).bearer_auth(&key).json(&body).send()
    };
    let first: Value = scan(true).await.unwrap().json().await.unwrap();
    let first_job = first["jobId"].as_str().unwrap().to_string();
    let first_pid = state.db.get_project_id_by_job_id(&first_job).unwrap();
    let first_dir = state.db.get_retained_source(first_pid).expect("first scan's source kept");
    assert!(std::path::Path::new(&first_dir).join("package.json").is_file());

    let second: Value = scan(true).await.unwrap().json().await.unwrap();
    let second_job = second["jobId"].as_str().unwrap().to_string();
    let second_pid = state.db.get_project_id_by_job_id(&second_job).unwrap();
    assert!(state.db.get_retained_source(second_pid).is_some(), "latest scan's source kept");
    assert!(state.db.get_retained_source(first_pid).is_none(), "previous scan's source dropped");
    assert!(!std::path::Path::new(&first_dir).exists(), "previous scan's copy deleted from disk");
    let rows = state.db.list_repo_latest_retained_sources("ACME", "fin-retain");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].tier, ignite_db_store::REPO_LATEST_TIER);

    let tree = client().get(format!("{base}/api/pipeline/{second_job}/studio/tree")).bearer_auth(&key).send().await.unwrap();
    assert_eq!(tree.status(), 200, "Studio opens the latest org scan live");
    let gone = client().get(format!("{base}/api/pipeline/{first_job}/studio/tree")).bearer_auth(&key).send().await.unwrap();
    assert_eq!(gone.status(), 409);

    // A scan that doesn't ask (pre-push hook, CLI) keeps nothing new.
    let plain: Value = scan(false).await.unwrap().json().await.unwrap();
    let plain_pid = state.db.get_project_id_by_job_id(plain["jobId"].as_str().unwrap()).unwrap();
    assert!(state.db.get_retained_source(plain_pid).is_none());
    assert!(state.db.get_retained_source(second_pid).is_some());
    std::env::remove_var("IGNITE_DATA_DIR");
}

/// Generated reports are stored per scan, and only a repo's latest scan
/// keeps them; uploaded documents on older scans stay.
#[tokio::test]
async fn scan_reports_are_kept_only_on_the_repos_latest_scan() {
    let (_base, _key, state) = spawn_test_server_with_state("fin-reports@example.com", None).await;
    let docs = || ignite_phase4_orchestrator::Phase4Documents {
        sbom: Some(("sbom.cyclonedx.json".to_string(), b"{}".to_vec())),
        provenance: Some(b"{}".to_vec()),
        loc_metrics: Some(b"{}".to_vec()),
        posture_report: Some(b"{}".to_vec()),
        ai_act_documents_report: None,
    };
    let names = |pid: i64| -> Vec<String> { state.db.get_project_details(pid).unwrap().documents.into_iter().map(|d| d.name).collect() };
    let older = state.db.create_project("fin-reports-1", "acme", "reports", false, "api", None).unwrap();
    state.db.add_upload_document(older, "validation-plan.pdf", Some("application/pdf"), 1, b"x");
    crate::routes::run_finalization::persist_scan_reports(&state, older, "acme", "reports", &docs());
    assert_eq!(names(older).len(), 5, "{:?}", names(older));

    let newer = state.db.create_project("fin-reports-2", "Acme", "Reports", false, "api", None).unwrap();
    crate::routes::run_finalization::persist_scan_reports(&state, newer, "Acme", "Reports", &docs());
    let mut latest = names(newer);
    latest.sort();
    assert_eq!(latest, ["loc-metrics.json", "posture-report.json", "provenance.json", "sbom.cyclonedx.json"]);
    assert_eq!(names(older), ["validation-plan.pdf"], "older scan keeps only its uploaded document");
}
