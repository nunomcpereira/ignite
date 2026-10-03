//! US-15: Phase 1–3 checks report through the coverage envelope, so a
//! skipped test suite or an accepted test failure is never mistaken for a
//! clean pass.
use super::*;
use serde_json::{json, Value};

fn coverage_entry<'a>(body: &'a Value, check_id: &str) -> &'a Value {
    body["coverage"].as_array().unwrap().iter().find(|c| c["checkId"] == check_id).unwrap_or_else(|| panic!("no {check_id} coverage: {}", body["coverage"]))
}

fn client() -> reqwest::Client {
    reqwest::Client::builder().timeout(std::time::Duration::from_secs(900)).build().unwrap()
}

#[tokio::test]
async fn a_project_with_no_test_suite_reports_unit_tests_as_not_applicable() {
    let (base, key, _state) = spawn_test_server_with_state("p3-notests@example.com", None).await;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("main.py"), "print('hi')\n").unwrap();
    let body: Value = client().post(format!("{base}/api/pipeline/validate-all")).bearer_auth(&key).json(&json!({ "projectPath": dir.path().to_string_lossy(), "runLocalCi": false, "fast": true })).send().await.unwrap().json().await.unwrap();
    assert_eq!(coverage_entry(&body, "unit-tests")["outcome"], "not_applicable", "{body}");
    assert_eq!(coverage_entry(&body, "env-files")["outcome"], "completed");
    assert_eq!(coverage_entry(&body, "codeowners")["outcome"], "completed");
    // Phase 2 is off by default; when on, a non-GxP project is not applicable.
    assert_eq!(coverage_entry(&body, "gxp-documents")["outcome"], "disabled");
    assert!(coverage_entry(&body, "license-compliance")["outcome"].is_string());
    let dep_vuln = body["coverage"].as_array().unwrap().iter().filter(|c| c["checkId"] == "dependency-vulnerability").count();
    assert_eq!(dep_vuln, 1, "dependency-vulnerability must be reported once");
}

#[tokio::test]
async fn accepted_test_failures_show_as_failed_coverage_and_strict_policy_rejects_them() {
    let mut config = ignite_config::Config::default();
    config.policy.strict = true;
    let (base, key, _state) = spawn_test_server_with_state_and_config("p3-failing@example.com", None, config).await;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("package.json"), r#"{"name":"failing","scripts":{"test":"exit 1"}}"#).unwrap();
    std::fs::write(dir.path().join("index.js"), "module.exports = 1;\n").unwrap();
    let body: Value = client()
        .post(format!("{base}/api/pipeline/validate-all"))
        .bearer_auth(&key)
        .json(&json!({ "projectPath": dir.path().to_string_lossy(), "runLocalCi": false, "fast": true, "unitTestFailuresNonBlocking": true }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let unit = coverage_entry(&body, "unit-tests");
    if unit["outcome"] == "unavailable" {
        eprintln!("skipping: Docker not running ({unit})");
        return;
    }
    assert_eq!(unit["outcome"], "failed", "{body}");
    assert!(unit["reason"].as_str().unwrap().contains("accepted as non-blocking"), "{unit}");
    assert!(body["unitTestWarning"].is_string(), "the warning string is still returned: {body}");
    assert_eq!(body["policyDecision"]["decision"], "incomplete", "{body}");
    assert!(body["policyDecision"]["missingRequiredCoverage"].as_array().unwrap().iter().any(|c| c == "unit-tests"), "{body}");
    assert_eq!(body["policyDecision"]["policyVersion"], "strict-publication-v2");
}
