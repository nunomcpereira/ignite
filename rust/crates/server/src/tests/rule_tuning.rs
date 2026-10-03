//! Learning from triage: verdicts, the noise report, and AI-proposed ignore
//! rules that take effect only once an admin accepts them.
use super::*;
use serde_json::{json, Value};

fn client() -> reqwest::Client {
    reqwest::Client::builder().timeout(std::time::Duration::from_secs(600)).build().unwrap()
}

fn issue(id: &str, file: &str, rule: &str) -> ignite_db_store::IssueInput {
    ignite_db_store::IssueInput { id: id.into(), phase: Some(4), category: "semantic-sast".into(), severity: "error".into(), score: Some(8), summary: "weak hash".into(), file: Some(file.into()), line: Some(3), snippet: None, cross_file: false, chain: None, cwe: Some("CWE-328".into()), owasp: None, tool: Some("semgrep".into()), references: None, duplicate_ref: None, author: None, rule: Some(rule.into()) }
}

#[tokio::test]
async fn a_verdict_is_recorded_per_finding_and_feeds_the_noise_report() {
    let (base, key, state) = spawn_test_server_with_state("triager@tuning.test", None).await;
    let pid = state.db.create_project("job-v", "acme", "w", false, "ui", None).unwrap();
    state.db.replace_project_issues(pid, &[issue("semantic-sast::src/A.java::3", "src/A.java", "java.weak-hash")], &std::collections::HashSet::new());

    let bad = client().post(format!("{base}/api/pipeline/job-v/issues/x/verdict")).bearer_auth(&key).json(&json!({ "verdict": "maybe" })).send().await.unwrap();
    assert_eq!(bad.status(), 400);
    let res: Value = client().post(format!("{base}/api/pipeline/job-v/issues/semantic-sast::src%2FA.java::3/verdict")).bearer_auth(&key).json(&json!({ "verdict": "false_positive" })).send().await.unwrap().json().await.unwrap();
    assert_eq!(res["verdict"]["verdict"], "false_positive", "{res}");

    let noise: Value = client().get(format!("{base}/api/policy/rule-noise?org=acme")).bearer_auth(&key).send().await.unwrap().json().await.unwrap();
    assert_eq!(noise["rules"][0]["rule"], "java.weak-hash");
    assert_eq!(noise["rules"][0]["falsePositives"], 1);
    let hist: Value = client().get(format!("{base}/api/pipeline/job-v/issues/semantic-sast::src%2FA.java::3/history")).bearer_auth(&key).send().await.unwrap().json().await.unwrap();
    assert_eq!(hist["verdict"]["verdict"], "false_positive");
}

#[tokio::test]
async fn an_accepted_proposal_acknowledges_matching_findings_on_the_next_scan() {
    let (base, admin_key, state) = spawn_test_server_with_state("admin@tuning.test", None).await;
    state.db.sync_configured_policy_admins_into_grants(&["admin@tuning.test".to_string()]);
    let user_key = {
        let uid = state.db.create_local_user("dev@tuning.test", None, ignite_auth::dummy_hash()).unwrap();
        let token = format!("{}{}", ignite_auth::API_KEY_PREFIX, uuid::Uuid::new_v4());
        state.db.create_api_key(uid, &ignite_auth::hash_api_key(&token), None, None, "test");
        token
    };
    let cats = vec!["secret".to_string()];
    let files = vec!["^legacy/".to_string()];
    let id = state.db.insert_rule_proposal(&ignite_db_store::NewRuleProposal { org: "acme", repo: "*", categories: &cats, file_patterns: &files, line_patterns: &[], reason: "Test fixtures with fake credentials", rationale: "Several justifications say these are fake test keys", evidence_override_ids: &[1, 2], match_count: 1 }).unwrap();

    let project = agent_test_project();
    std::fs::create_dir_all(project.path().join("legacy")).unwrap();
    std::fs::write(project.path().join("legacy/creds.js"), "const aws_secret_key = 'AKIAABCDEFGHIJKLMNOP';\nconsole.log(aws_secret_key);\n").unwrap();
    let scan = || client().post(format!("{base}/api/pipeline/validate-all")).bearer_auth(&admin_key).json(&json!({ "org": "acme", "repo": "tuned", "projectPath": project.path().to_string_lossy(), "runLocalCi": false, "fast": true })).send();

    // Proposed only: nothing changes yet.
    assert_eq!(scan().await.unwrap().status(), 400, "the fixture secret still blocks while the rule is only proposed");

    let listed: Value = client().get(format!("{base}/api/policy/rule-proposals?status=proposed")).bearer_auth(&admin_key).send().await.unwrap().json().await.unwrap();
    assert_eq!(listed["proposals"][0]["id"], id);
    assert_eq!(client().post(format!("{base}/api/policy/rule-proposals/{id}/accept")).bearer_auth(&user_key).send().await.unwrap().status(), 403, "only a policy admin decides");
    assert_eq!(client().post(format!("{base}/api/policy/rule-proposals/{id}/accept")).bearer_auth(&admin_key).send().await.unwrap().status(), 200);
    assert_eq!(client().post(format!("{base}/api/policy/rule-proposals/{id}/dismiss")).bearer_auth(&admin_key).send().await.unwrap().status(), 409, "an active rule is disabled, not dismissed");

    ignite_fs_utils::invalidate_walk_cache(project.path());
    let res = scan().await.unwrap();
    let body: Value = res.json().await.unwrap();
    let secret = body["issues"].as_array().unwrap().iter().find(|i| i["category"] == "secret").unwrap_or_else(|| panic!("secret still reported: {body}")).clone();
    assert_eq!(secret["status"], "overridden", "{secret}");
    assert_eq!(body["ok"], true, "{body}");
    let types: Vec<String> = state.db.list_audit_events(None, None, None, None, None, None, None, 100).into_iter().map(|e| e.event_type).collect();
    assert!(types.iter().any(|t| t == "policy.rule_proposal_accepted"), "{types:?}");
}

#[tokio::test]
async fn generating_proposals_needs_an_admin_and_reports_why_it_produced_nothing() {
    let (base, key, state) = spawn_test_server_with_state("gen@tuning.test", None).await;
    assert_eq!(client().post(format!("{base}/api/policy/rule-proposals/generate")).bearer_auth(&key).json(&json!({})).send().await.unwrap().status(), 403);
    state.db.sync_configured_policy_admins_into_grants(&["gen@tuning.test".to_string()]);
    assert_eq!(client().post(format!("{base}/api/policy/rule-proposals/generate")).bearer_auth(&key).json(&json!({})).send().await.unwrap().status(), 202);
    let status = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let v: Value = client().get(format!("{base}/api/policy/rule-proposals")).bearer_auth(&key).send().await.unwrap().json().await.unwrap();
            if v["generation"]["running"] == false {
                return v;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    assert!(status["generation"]["error"].as_str().unwrap().contains("Not enough override justifications"), "{status}");
}
