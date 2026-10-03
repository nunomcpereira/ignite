//! US-17: permission-grant management and opt-in enforcement.
use super::*;
use serde_json::{json, Value};

fn client() -> reqwest::Client {
    reqwest::Client::builder().timeout(std::time::Duration::from_secs(600)).build().unwrap()
}

/// A second user with an API key on the same server.
fn add_user_key(state: &AppState, email: &str) -> String {
    let user_id = state.db.create_local_user(email, None, ignite_auth::dummy_hash()).unwrap();
    let token = format!("{}{}", ignite_auth::API_KEY_PREFIX, uuid::Uuid::new_v4());
    state.db.create_api_key(user_id, &ignite_auth::hash_api_key(&token), None, None, "test");
    token
}

fn enforced_config() -> ignite_config::Config {
    let mut config = ignite_config::Config::default();
    config.security.enforce_grants = true;
    config
}

#[tokio::test]
async fn only_a_policy_admin_manages_grants_and_every_change_is_audited() {
    let (base, admin_key, state) = spawn_test_server_with_state("admin@grants.test", None).await;
    state.db.sync_configured_policy_admins_into_grants(&["admin@grants.test".to_string()]);
    let other_key = add_user_key(&state, "dev@grants.test");

    let denied = client().post(format!("{base}/api/policy/grants")).bearer_auth(&other_key).json(&json!({ "subjectEmail": "dev@grants.test", "permission": "scan" })).send().await.unwrap();
    assert_eq!(denied.status(), 403);
    assert_eq!(client().get(format!("{base}/api/policy/grants")).bearer_auth(&other_key).send().await.unwrap().status(), 403);

    let bad = client().post(format!("{base}/api/policy/grants")).bearer_auth(&admin_key).json(&json!({ "subjectEmail": "dev@grants.test", "permission": "root" })).send().await.unwrap();
    assert_eq!(bad.status(), 400);

    let created: Value = client().post(format!("{base}/api/policy/grants")).bearer_auth(&admin_key).json(&json!({ "subjectEmail": "Dev@Grants.test", "permission": "scan", "org": "acme" })).send().await.unwrap().json().await.unwrap();
    let id = created["grant"]["id"].as_i64().unwrap_or_else(|| panic!("{created}"));
    assert_eq!(created["grant"]["subjectEmail"], "dev@grants.test");
    assert!(state.db.has_permission("dev@grants.test", "scan", "acme", "anything"));

    let listed: Value = client().get(format!("{base}/api/policy/grants")).bearer_auth(&admin_key).send().await.unwrap().json().await.unwrap();
    assert!(listed["grants"].as_array().unwrap().iter().any(|g| g["id"] == id));
    assert_eq!(listed["enforced"], false);

    assert_eq!(client().delete(format!("{base}/api/policy/grants/{id}")).bearer_auth(&admin_key).send().await.unwrap().status(), 200);
    assert!(!state.db.has_permission("dev@grants.test", "scan", "acme", "anything"));
    let types: Vec<String> = state.db.list_audit_events(None, None, None, None, None, None, None, 100).into_iter().map(|e| e.event_type).collect();
    assert!(types.iter().any(|t| t == "policy.grant_created") && types.iter().any(|t| t == "policy.grant_revoked"), "{types:?}");
}

#[tokio::test]
async fn removing_an_email_from_policy_admins_keeps_its_grant() {
    let (_base, _key, state) = spawn_test_server_with_state("keep@grants.test", None).await;
    state.db.sync_configured_policy_admins_into_grants(&["keep@grants.test".to_string()]);
    state.db.sync_configured_policy_admins_into_grants(&[]);
    assert!(state.db.has_permission_at_scope("keep@grants.test", "policy_admin", None, None));
}

#[tokio::test]
async fn with_enforcement_on_scan_needs_a_grant_and_an_org_grant_is_enough() {
    let (base, key, state) = spawn_test_server_with_state_and_config("scanner@grants.test", None, enforced_config()).await;
    let project = agent_test_project();
    let req = json!({ "org": "acme", "repo": "widgets", "projectPath": project.path().to_string_lossy(), "runLocalCi": false, "fast": true });

    let res = client().post(format!("{base}/api/pipeline/validate-all")).bearer_auth(&key).json(&req).send().await.unwrap();
    assert_eq!(res.status(), 403);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["code"], "permission_denied");
    assert_eq!(body["requiredPermission"], "scan");

    state.db.grant_permission("scanner@grants.test", "scan", Some("acme"), None, None);
    let res = client().post(format!("{base}/api/pipeline/validate-all")).bearer_auth(&key).json(&req).send().await.unwrap();
    assert_ne!(res.status(), 403, "an org-wide scan grant must cover acme/widgets");

    // A real onboard also needs publish.
    let onboard = client().post(format!("{base}/api/pipeline/onboard")).bearer_auth(&key).json(&json!({ "org": "acme", "repo": "widgets", "projectPath": project.path().to_string_lossy(), "dryRun": false, "runLocalCi": false })).send().await.unwrap();
    assert_eq!(onboard.status(), 403);
    assert_eq!(onboard.json::<Value>().await.unwrap()["requiredPermission"], "publish");
}

#[tokio::test]
async fn with_enforcement_on_views_are_scoped_to_granted_repositories() {
    let (base, key, state) = spawn_test_server_with_state_and_config("viewer@grants.test", None, enforced_config()).await;
    let mine = state.db.create_project("job-mine", "acme", "mine", false, "ui", None).unwrap();
    let theirs = state.db.create_project("job-theirs", "acme", "theirs", false, "ui", None).unwrap();
    state.db.grant_permission("viewer@grants.test", "view", Some("acme"), Some("mine"), None);

    assert_eq!(client().get(format!("{base}/api/projects/{mine}")).bearer_auth(&key).send().await.unwrap().status(), 200);
    assert_eq!(client().get(format!("{base}/api/projects/{theirs}")).bearer_auth(&key).send().await.unwrap().status(), 403);
    assert_eq!(client().get(format!("{base}/api/pipeline/job-theirs/issues")).bearer_auth(&key).send().await.unwrap().status(), 403);
    let list: Value = client().get(format!("{base}/api/projects")).bearer_auth(&key).send().await.unwrap().json().await.unwrap();
    let repos: Vec<&str> = list.as_array().unwrap().iter().map(|p| p["repo"].as_str().unwrap()).collect();
    assert_eq!(repos, vec!["mine"]);
}

#[tokio::test]
async fn with_enforcement_off_nothing_changes() {
    let (base, key, state) = spawn_test_server_with_state("plain@grants.test", None).await;
    let pid = state.db.create_project("job-plain", "acme", "plain", false, "ui", None).unwrap();
    assert_eq!(client().get(format!("{base}/api/projects/{pid}")).bearer_auth(&key).send().await.unwrap().status(), 200);
    let project = agent_test_project();
    let res = client().post(format!("{base}/api/pipeline/validate-all")).bearer_auth(&key).json(&json!({ "org": "acme", "repo": "plain", "projectPath": project.path().to_string_lossy(), "runLocalCi": false, "fast": true })).send().await.unwrap();
    assert_ne!(res.status(), 403);
}
