//! US-16: findings keep their identity across scans — through baselines
//! when code moves above them, and through the finding-history API.
use super::*;
use serde_json::{json, Value};

const SECRET_JS: &str = "const aws_secret_key = 'AKIAABCDEFGHIJKLMNOP';\nconsole.log(aws_secret_key);\n";

fn client() -> reqwest::Client {
    reqwest::Client::builder().timeout(std::time::Duration::from_secs(600)).build().unwrap()
}

async fn validate(base: &str, key: &str, path: &std::path::Path, extra: Value) -> (u16, Value) {
    let mut body = json!({ "org": "acme", "repo": "history", "projectPath": path.to_string_lossy(), "runLocalCi": false, "fast": true });
    body.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
    let res = client().post(format!("{base}/api/pipeline/validate-all")).bearer_auth(key).json(&body).send().await.unwrap();
    (res.status().as_u16(), res.json().await.unwrap())
}

#[tokio::test]
async fn a_baselined_finding_stays_baselined_after_code_moves_above_it() {
    let (base, key, _state) = spawn_test_server_with_state("hist-baseline@example.com", None).await;
    let project = agent_test_project();
    std::fs::write(project.path().join("config.js"), SECRET_JS).unwrap();
    let (_, saved) = validate(&base, &key, project.path(), json!({ "baselineMode": "save" })).await;
    let secret_id = saved["issues"].as_array().unwrap().iter().find(|i| i["category"] == "secret").expect("secret finding")["id"].as_str().unwrap().to_string();

    // Shift the secret down three lines: its issue id changes, its code doesn't.
    std::fs::write(project.path().join("config.js"), format!("\n\n\n{SECRET_JS}")).unwrap();
    ignite_fs_utils::invalidate_walk_cache(project.path());
    let (status, gated) = validate(&base, &key, project.path(), json!({ "baselineMode": "gate" })).await;
    let moved = gated["issues"].as_array().unwrap().iter().find(|i| i["category"] == "secret").expect("secret still reported").clone();
    assert_ne!(moved["id"], secret_id, "the line shift must change the legacy id");
    assert_eq!(moved["status"], "baselined", "{moved}");
    assert_eq!(status, 200, "a baselined finding must not block the gate: {gated}");
}

#[tokio::test]
async fn finding_history_spans_three_scans() {
    let (base, key, _state) = spawn_test_server_with_state("hist-api@example.com", None).await;
    let project = agent_test_project();
    std::fs::write(project.path().join("config.js"), SECRET_JS).unwrap();
    let mut last_job = String::new();
    for _ in 0..3 {
        let (_, body) = validate(&base, &key, project.path(), json!({})).await;
        last_job = body["jobId"].as_str().unwrap().to_string();
    }
    let page: Value = client().get(format!("{base}/api/repositories/acme/history/findings?status=open&pageSize=10")).bearer_auth(&key).send().await.unwrap().json().await.unwrap();
    let secret = page["findings"].as_array().unwrap().iter().find(|f| f["category"] == "secret").expect("secret finding tracked").clone();
    assert!(page["total"].as_i64().unwrap() >= 1);
    let fp = secret["fingerprint"].as_str().unwrap();

    let obs: Value = client().get(format!("{base}/api/repositories/acme/history/findings/{fp}/observations")).bearer_auth(&key).send().await.unwrap().json().await.unwrap();
    let classes: Vec<&str> = obs["observations"].as_array().unwrap().iter().map(|o| o["classification"].as_str().unwrap()).collect();
    assert_eq!(classes, vec!["new", "existing", "existing"]);

    let secret_issue_id = secret["legacyIssueId"].as_str().unwrap();
    let hist: Value = client().get(format!("{base}/api/pipeline/{last_job}/issues/{}/history", urlencoding_encode(secret_issue_id))).bearer_auth(&key).send().await.unwrap().json().await.unwrap();
    assert_eq!(hist["fingerprint"], fp);
    assert_eq!(hist["observations"].as_array().unwrap().len(), 3);
    assert_eq!(hist["observations"][2]["jobId"], last_job.as_str());

    let bad = client().get(format!("{base}/api/repositories/acme/history/findings?status=bogus")).bearer_auth(&key).send().await.unwrap();
    assert_eq!(bad.status(), 400);
}

fn urlencoding_encode(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}
