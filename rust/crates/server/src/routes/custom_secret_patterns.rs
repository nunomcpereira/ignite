//! `/api/secret-patterns` — custom secret patterns (GHAS "custom pattern"
//! parity): operator-authored regex rules, a "playground" to test one
//! against sample text before saving it, and a retroactive sweep that
//! reuses `ignite-secrets`' gitleaks-history infra to check whether a
//! newly-added pattern would have caught anything already committed to a
//! repo's history before the pattern existed.
//!
//! `test` (the playground) is pure/local — no auth required, same
//! posture as `routes/campaigns.rs`. `sweep` clones a real repo and
//! spends a GitHub token, so it requires an authenticated caller, same
//! posture as `routes/fix_pr.rs`'s `apply`.

use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ignite_secrets::CustomSecretPattern;
use serde::Serialize;
use serde_json::{json, Value};
use std::sync::Arc;

fn err(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(json!({ "ok": false, "error": message.into() }))).into_response()
}

async fn list_patterns(State(state): State<Arc<AppState>>) -> Response {
    Json(state.db.list_custom_secret_patterns()).into_response()
}

async fn create_pattern(State(state): State<Arc<AppState>>, crate::auth::RequireAuth(_user): crate::auth::RequireAuth, Json(body): Json<Value>) -> Response {
    let Some(name) = body.get("name").and_then(|v| v.as_str()).filter(|s| !s.trim().is_empty()) else {
        return err(StatusCode::BAD_REQUEST, "Request body must include a non-empty name.");
    };
    let Some(regex) = body.get("regex").and_then(|v| v.as_str()).filter(|s| !s.trim().is_empty()) else {
        return err(StatusCode::BAD_REQUEST, "Request body must include a non-empty regex.");
    };
    // Reject an uncompilable pattern up front — the playground already
    // steers an operator away from this, but the create endpoint is the
    // actual point where a bad pattern would otherwise silently never
    // match anything once it's fed into `build_gitleaks_config_for_patterns`.
    if let Err(e) = ignite_secrets::test_pattern_against_sample(regex, "") {
        return err(StatusCode::BAD_REQUEST, e.to_string());
    }
    let created_by = body.get("createdBy").and_then(|v| v.as_str());
    let id = state.db.create_custom_secret_pattern(name, regex, created_by);
    match state.db.get_custom_secret_pattern(id) {
        Some(row) => (StatusCode::CREATED, Json(row)).into_response(),
        None => Json(json!({ "ok": true, "id": id })).into_response(),
    }
}

async fn set_pattern_enabled(State(state): State<Arc<AppState>>, crate::auth::RequireAuth(_user): crate::auth::RequireAuth, Path(id): Path<i64>, Json(body): Json<Value>) -> Response {
    let Some(enabled) = body.get("enabled").and_then(|v| v.as_bool()) else {
        return err(StatusCode::BAD_REQUEST, "Request body must include a boolean enabled field.");
    };
    let ok = state.db.set_custom_secret_pattern_enabled(id, enabled);
    Json(json!({ "ok": ok, "id": id })).into_response()
}

async fn delete_pattern(State(state): State<Arc<AppState>>, crate::auth::RequireAuth(_user): crate::auth::RequireAuth, Path(id): Path<i64>) -> Response {
    let deleted = state.db.delete_custom_secret_pattern(id);
    Json(json!({ "ok": deleted, "id": id })).into_response()
}

/// The "playground": compiles `regex` and runs it against `sample`,
/// returning every match — no persistence, no auth, pure computation.
async fn test_pattern(Json(body): Json<Value>) -> Response {
    let Some(regex) = body.get("regex").and_then(|v| v.as_str()) else {
        return err(StatusCode::BAD_REQUEST, "Request body must include a regex field.");
    };
    let sample = body.get("sample").and_then(|v| v.as_str()).unwrap_or("");
    match ignite_secrets::test_pattern_against_sample(regex, sample) {
        Ok(matches) => {
            let matches: Vec<Value> = matches.into_iter().map(|m| json!({ "start": m.start, "end": m.end, "matchedText": m.matched_text })).collect();
            Json(json!({ "ok": true, "matchCount": matches.len(), "matches": matches })).into_response()
        }
        Err(e) => err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

/// A `GitleaksRawResult` isn't `Serialize` (that crate deliberately
/// leaves report-parsing pure/plain, no JSON concern) — this is the
/// thin, route-local wire shape for a sweep finding.
#[derive(Serialize)]
struct SweepFinding {
    file: String,
    line: usize,
    kind: String,
}

/// `POST /api/secret-patterns/:id/sweep` — retroactive git-history sweep:
/// clones `org/repo`'s default branch with full history, builds a
/// throwaway gitleaks config carrying only this one pattern (plus
/// gitleaks' own built-ins, via `useDefault = true`), and runs
/// `run_gitleaks_history_scan` against it. Answers "would this pattern,
/// if it had existed from day one, have caught a secret already
/// committed and possibly since removed?" — the retroactive half of
/// GHAS custom-pattern parity; `check_secrets`/the regular scan path is
/// where an *enabled* pattern applies going forward.
async fn sweep_pattern(State(state): State<Arc<AppState>>, crate::auth::RequireAuth(_user): crate::auth::RequireAuth, Path(id): Path<i64>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    let Some(pattern) = state.db.get_custom_secret_pattern(id) else {
        return err(StatusCode::NOT_FOUND, "Unknown custom secret pattern id.");
    };
    let owner = body.get("owner").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let repo = body.get("repo").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if !ignite_github_api::is_valid_github_owner(&owner) {
        return err(StatusCode::BAD_REQUEST, format!("Invalid GitHub owner/org: \"{owner}\""));
    }
    if !ignite_github_api::is_valid_github_repo(&repo) {
        return err(StatusCode::BAD_REQUEST, format!("Invalid repository name: \"{repo}\""));
    }

    let token = crate::auth::resolve_effective_github_token(&headers, &state.db);
    if token.is_empty() {
        return err(StatusCode::UNAUTHORIZED, "No GitHub token available — connect a GitHub account or configure a server token.");
    }

    let full_name = format!("{owner}/{repo}");
    let github_api = ignite_github_api::GithubApi::new(&state.runner);
    let default_branch = match github_api.default_branch(&full_name, &token).await {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_GATEWAY, format!("Failed to resolve default branch for {full_name}: {e}")),
    };

    let staging = match tempfile::tempdir() {
        Ok(d) => d,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create staging dir: {e}")),
    };
    let clone_dir = staging.path().join("clone");
    let clone_dir_str = clone_dir.to_string_lossy().to_string();
    if let Err(e) = github_api.gh_clone_repo_branch_full_history(&full_name, &default_branch, &clone_dir_str, &token).await {
        return err(StatusCode::BAD_GATEWAY, format!("Failed to clone {full_name}@{default_branch}: {e}"));
    }

    let config_toml = ignite_secrets::build_gitleaks_config_for_patterns(std::slice::from_ref(&CustomSecretPattern { name: pattern.name.clone(), regex: pattern.regex.clone() }), None);
    let config_path = staging.path().join("gitleaks-custom-pattern.toml");
    if let Err(e) = std::fs::write(&config_path, &config_toml) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to write sweep config: {e}"));
    }

    let raw_findings = ignite_secrets::run_gitleaks_history_scan(&clone_dir, &state.runner, Some(&config_path)).await;
    let findings: Vec<SweepFinding> = raw_findings.into_iter().map(|f| SweepFinding { file: f.file, line: f.line, kind: f.kind }).collect();

    Json(json!({ "ok": true, "patternId": id, "patternName": pattern.name, "repo": full_name, "findingCount": findings.len(), "findings": findings })).into_response()
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/secret-patterns", get(list_patterns).post(create_pattern))
        .route("/api/secret-patterns/test", post(test_pattern))
        .route("/api/secret-patterns/:id", axum::routing::delete(delete_pattern))
        .route("/api/secret-patterns/:id/enabled", post(set_pattern_enabled))
        .route("/api/secret-patterns/:id/sweep", post(sweep_pattern))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn test_state() -> Arc<AppState> {
        let db_dir = tempfile::tempdir().unwrap();
        let db = ignite_db_store::DbStore::open(&db_dir.path().join("test.db")).unwrap();
        std::mem::forget(db_dir);
        Arc::new(AppState {
            runner: state::default_runner(),
            db,
            running_runs: parking_lot::Mutex::new(std::collections::HashMap::new()),
            pending_effectivations: parking_lot::Mutex::new(std::collections::HashMap::new()),
            review_gate: crate::review_gate::ReviewGate::default(),
            llm_config: state::default_llm_config(),
            config: ignite_config::Config::default(),
            package_hallucination_checker: state::default_package_hallucination_checker(),
            fix_pr_previews: parking_lot::Mutex::new(std::collections::HashMap::new()),
            audit_http: reqwest::Client::new(),
        })
    }

    async fn body_json(res: Response) -> Value {
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// A valid `Authorization: Bearer ignite_<key>` header value for a
    /// freshly created local user in `state`'s db — the mutating
    /// endpoints in this file now require `RequireAuth`.
    fn auth_header(state: &AppState) -> String {
        let user_id = state.db.create_local_user("tester@example.com", Some("Tester"), "unused-hash");
        let raw_key = ignite_auth::generate_api_key();
        state.db.create_api_key(user_id, &ignite_auth::hash_api_key(&raw_key), None, None, "test");
        format!("Bearer {raw_key}")
    }

    #[tokio::test]
    async fn test_pattern_route_reports_matches_without_persisting_anything() {
        let state = test_state();
        let app = router().with_state(state.clone());
        let req = Request::post("/api/secret-patterns/test").header("content-type", "application/json").body(Body::from(r#"{"regex":"sk_live_[a-z0-9]+","sample":"key: sk_live_abc123"}"#)).unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let json = body_json(res).await;
        assert_eq!(json["matchCount"], 1);
        assert_eq!(json["matches"][0]["matchedText"], "sk_live_abc123");
        assert!(state.db.list_custom_secret_patterns().is_empty(), "testing a pattern must never save it");
    }

    #[tokio::test]
    async fn test_pattern_route_rejects_invalid_regex() {
        let app = router().with_state(test_state());
        let req = Request::post("/api/secret-patterns/test").header("content-type", "application/json").body(Body::from(r#"{"regex":"(unclosed","sample":"x"}"#)).unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_list_and_delete_round_trip() {
        let state = test_state();
        let auth = auth_header(&state);
        let app = router().with_state(state.clone());

        let create_req = Request::post("/api/secret-patterns").header("content-type", "application/json").header("authorization", &auth).body(Body::from(r#"{"name":"Internal Token","regex":"tok_[a-z0-9]+"}"#)).unwrap();
        let create_res = app.clone().oneshot(create_req).await.unwrap();
        assert_eq!(create_res.status(), StatusCode::CREATED);
        let created = body_json(create_res).await;
        let id = created["id"].as_i64().unwrap();

        let list_res = app.clone().oneshot(Request::get("/api/secret-patterns").body(Body::empty()).unwrap()).await.unwrap();
        let list = body_json(list_res).await;
        assert_eq!(list.as_array().unwrap().len(), 1);

        let delete_res = app.oneshot(Request::delete(format!("/api/secret-patterns/{id}")).header("authorization", &auth).body(Body::empty()).unwrap()).await.unwrap();
        let deleted = body_json(delete_res).await;
        assert_eq!(deleted["ok"], true);
        assert!(state.db.list_custom_secret_patterns().is_empty());
    }

    #[tokio::test]
    async fn create_rejects_missing_name_or_regex() {
        let state = test_state();
        let auth = auth_header(&state);
        let app = router().with_state(state);
        let res = app.oneshot(Request::post("/api/secret-patterns").header("content-type", "application/json").header("authorization", &auth).body(Body::from(r#"{"regex":"x"}"#)).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_rejects_uncompilable_regex() {
        let state = test_state();
        let auth = auth_header(&state);
        let app = router().with_state(state);
        let res = app.oneshot(Request::post("/api/secret-patterns").header("content-type", "application/json").header("authorization", &auth).body(Body::from(r#"{"name":"Bad","regex":"(unclosed"}"#)).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_requires_auth() {
        let app = router().with_state(test_state());
        let res = app.oneshot(Request::post("/api/secret-patterns").header("content-type", "application/json").body(Body::from(r#"{"name":"Bad","regex":"x"}"#)).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn set_enabled_toggles_and_persists() {
        let state = test_state();
        let auth = auth_header(&state);
        let id = state.db.create_custom_secret_pattern("P", "a", None);
        let app = router().with_state(state.clone());
        let res = app.oneshot(Request::post(format!("/api/secret-patterns/{id}/enabled")).header("content-type", "application/json").header("authorization", &auth).body(Body::from(r#"{"enabled":false}"#)).unwrap()).await.unwrap();
        let json = body_json(res).await;
        assert_eq!(json["ok"], true);
        assert!(!state.db.get_custom_secret_pattern(id).unwrap().enabled);
    }

    #[tokio::test]
    async fn sweep_requires_auth() {
        let state = test_state();
        let id = state.db.create_custom_secret_pattern("P", "a", None);
        let app = router().with_state(state);
        let res = app.oneshot(Request::post(format!("/api/secret-patterns/{id}/sweep")).header("content-type", "application/json").body(Body::from(r#"{"owner":"acme","repo":"widgets"}"#)).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }
}
