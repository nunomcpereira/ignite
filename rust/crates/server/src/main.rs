//! Ignite's HTTP server — Rust port of `server.js`'s route layer.
//! Session auth, the streaming pipeline endpoints, and upload handling
//! aren't ported yet — see each `routes/*.rs` module's doc comment for
//! what it covers.
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

mod ai_justify;
mod auth;
mod phase4_config;
mod review_gate;
mod routes;
mod security;
mod state;

use state::AppState;
use std::collections::HashMap;
use std::path::Path;
use parking_lot::Mutex;
use std::sync::Arc;
use tower_http::services::ServeDir;

/// Mirrors server.js's `app.use(express.static(path.join(__dirname,
/// 'public')))`: static assets — including `public/index.html`, the
/// single-file SPA — are served for any request path that doesn't match
/// one of the API routes above. Mounted as a `fallback_service` (checked
/// only after every other route fails to match), same effective ordering
/// as Express's static-middleware-before-routes, since none of the API
/// routes ever collide with a static asset path. The security-headers and
/// `/api` rate-limit middlewares (server.js:77-104) are layered on last so
/// they wrap the fallback static service too, matching Express mounting
/// both before every route including the static one.
fn build_router(state: Arc<AppState>, public_dir: &Path) -> axum::Router {
    let rate_limiter = Arc::new(security::RateLimiter::default());
    axum::Router::new()
        .merge(auth::router())
        .merge(routes::tools_status::router())
        .merge(routes::sarif::router())
        .merge(routes::github_annotations::router())
        .merge(routes::baseline::router())
        .merge(routes::campaigns::router())
        .merge(routes::compliance::router())
        .merge(routes::daily_report::router())
        .merge(routes::findings_markdown::router())
        .merge(routes::settings::router())
        .merge(routes::audit_log::router())
        .merge(routes::custom_secret_patterns::router())
        .merge(routes::runtime_coverage::router())
        .merge(routes::auto_fix::router())
        .merge(routes::dependencies::router())
        .merge(routes::reports::router())
        .merge(routes::github_pr_status::router())
        .merge(routes::code_scanning_webhook::router())
        .merge(routes::push_protection_webhook::router())
        .merge(routes::secret_scanning_webhook::router())
        .merge(routes::repository_events_webhook::router())
        .merge(routes::override_approval::router())
        .merge(routes::issues::router())
        .merge(routes::history::router())
        .merge(routes::onboarded_repos::router())
        .merge(routes::org_repos::router())
        .merge(routes::pipeline_validate::router())
        .merge(routes::config::router())
        .merge(routes::pipeline_onboard::router())
        .merge(routes::pipeline_interactive::router())
        .merge(routes::studio::router())
        .merge(routes::studio::mutating_router().layer(axum::middleware::from_fn_with_state(state.clone(), auth::require_auth_middleware)))
        .merge(routes::effectivate::router())
        .merge(routes::project_overrides::router())
        .merge(routes::fix_pr::router())
        .with_state(state)
        .fallback_service(ServeDir::new(public_dir))
        .layer(axum::middleware::from_fn_with_state(rate_limiter, security::rate_limit_middleware))
        .layer(axum::middleware::from_fn(security::security_headers_middleware))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let db_path = std::env::var("IGNITE_DB_PATH").unwrap_or_else(|_| "ignite.db".to_string());
    let db = ignite_db_store::DbStore::open(std::path::Path::new(&db_path)).expect("failed to open db");

    // Mirrors config.js's __dirname convention (config.json,
    // ignite-posture-rules.yaml, spectral-default-ruleset.yaml all live
    // next to it) — IGNITE_CONFIG_DIR lets a packaged/deployed binary
    // point elsewhere; defaults to the process cwd otherwise.
    let config_dir = std::env::var("IGNITE_CONFIG_DIR").map(std::path::PathBuf::from).unwrap_or_else(|_| std::env::current_dir().expect("cwd"));
    let config = ignite_config::load_config(&config_dir).expect("failed to load config.json");

    // Dropping GHAS means losing GitHub's continuously-updated CodeQL query
    // packs — security.codeql's querySuites are now pinned by hand
    // (config.example.json). Non-blocking: just nudges an operator to
    // re-pin, never fails startup or gates a run.
    if ignite_config::is_codeql_review_overdue(config.security.codeql.last_reviewed_at.as_deref(), config.security.codeql.review_cadence_days, chrono::Utc::now().date_naive()) {
        tracing::warn!("CodeQL query suite review overdue, last reviewed: {}", config.security.codeql.last_reviewed_at.as_deref().unwrap_or("never"));
    }

    let state = Arc::new(AppState {
        runner: phase4_config::runner_from_config(&config),
        db,
        running_runs: Mutex::new(HashMap::new()),
        pending_effectivations: Mutex::new(HashMap::new()),
        review_gate: review_gate::ReviewGate::default(),
        llm_config: state::llm_config_from_config(&config),
        config,
        package_hallucination_checker: state::default_package_hallucination_checker(),
        fix_pr_previews: Mutex::new(HashMap::new()),
        audit_http: reqwest::Client::new(),
    });
    let config_port = state.config.port;
    let public_dir = config_dir.join("public");

    // US-08: mirror the legacy config allowlist into the real, queryable
    // grant model on every startup (idempotent) — additive only, never
    // revokes anything an operator granted/removed directly.
    state.db.sync_configured_approvers_into_grants(&state.config.security.override_approval.approver_emails);

    state.db.sweep_expired_sessions();
    state.db.abort_stale_running_projects();
    {
        let sweep_state = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            interval.tick().await; // first tick fires immediately; already swept above
            loop {
                interval.tick().await;
                sweep_state.db.sweep_expired_sessions();
            }
        });
    }
    {
        let housekeeping_state = state.clone();
        tokio::spawn(async move {
            ignite_container_image_vulnerabilities::docker_housekeeping(&housekeeping_state.runner).await;
        });
    }

    routes::daily_report::spawn_scheduler(state.clone());

    let app = build_router(state, &public_dir);

    // Mirrors server.js: `process.env.PORT || CONFIG.port`.
    let port: u16 = std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(config_port);
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await.expect("failed to bind port");
    // Always visible regardless of RUST_LOG (tracing::info! is silent
    // unless a filter enabling it is set) — an operator starting the
    // server needs to see the port immediately, not only when they
    // happen to have verbose logging configured.
    eprintln!("Ignite (Rust) listening on http://0.0.0.0:{port}");
    tracing::info!("Ignite (Rust) listening on http://0.0.0.0:{port}");
    axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await.expect("server error");
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    async fn spawn_test_server() -> String {
        spawn_test_server_with_llm_config(state::default_llm_config()).await.0
    }

    /// Binds a TCP listener on an OS-assigned port and immediately drops
    /// it, handing back a port that was free at that instant — used to
    /// point a test's `llm.scan_url` somewhere guaranteed to have nothing
    /// listening, instead of a hardcoded port that can collide with a real
    /// local LLM server a developer happens to be running (the actual
    /// `llm.url` default, `http://localhost:8050`, is indistinguishable
    /// from a real one from inside the test).
    fn unused_local_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    }

    async fn spawn_test_server_with_llm_config(llm_config: ignite_llm_client::LlmClientConfig) -> (String, String) {
        let db_dir = tempfile::tempdir().unwrap();
        let db = ignite_db_store::DbStore::open(&db_dir.path().join("test.db")).unwrap();
        let user_id = db.create_local_user("llm-test@example.com", None, ignite_auth::dummy_hash()).unwrap();
        let token = format!("{}{}", ignite_auth::API_KEY_PREFIX, uuid::Uuid::new_v4());
        db.create_api_key(user_id, &ignite_auth::hash_api_key(&token), None, None, "test");
        let state = Arc::new(AppState {
            runner: state::default_runner(),
            db,
            running_runs: Mutex::new(HashMap::new()),
            pending_effectivations: Mutex::new(HashMap::new()),
            review_gate: review_gate::ReviewGate::default(),
            llm_config,
            config: ignite_config::Config::default(),
            package_hallucination_checker: state::default_package_hallucination_checker(),
        fix_pr_previews: Mutex::new(HashMap::new()),
        audit_http: reqwest::Client::new(),
        });
        let public_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../public");
        let app = build_router(state, &public_dir);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await.unwrap();
        });
        // leak the tempdir so the db file survives for the life of the test process
        std::mem::forget(db_dir);
        (format!("http://{addr}"), token)
    }

    /// Like `spawn_test_server`, but also mints a real API key against a
    /// real local user so tests hitting a `RequireAuth`-gated route (e.g.
    /// `/github-check`) can authenticate as a headless caller instead of
    /// carrying a session cookie around.
    async fn spawn_test_server_with_api_key() -> (String, String) {
        let db_dir = tempfile::tempdir().unwrap();
        let db = ignite_db_store::DbStore::open(&db_dir.path().join("test.db")).unwrap();
        let user_id = db.create_local_user("apikey-test@example.com", None, ignite_auth::dummy_hash()).unwrap();
        let token = format!("{}{}", ignite_auth::API_KEY_PREFIX, uuid::Uuid::new_v4());
        db.create_api_key(user_id, &ignite_auth::hash_api_key(&token), None, None, "test");
        let state = Arc::new(AppState {
            runner: state::default_runner(),
            db,
            running_runs: Mutex::new(HashMap::new()),
            pending_effectivations: Mutex::new(HashMap::new()),
            review_gate: review_gate::ReviewGate::default(),
            llm_config: state::default_llm_config(),
            config: ignite_config::Config::default(),
            package_hallucination_checker: state::default_package_hallucination_checker(),
        fix_pr_previews: Mutex::new(HashMap::new()),
        audit_http: reqwest::Client::new(),
        });
        let public_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../public");
        let app = build_router(state, &public_dir);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await.unwrap();
        });
        std::mem::forget(db_dir);
        (format!("http://{addr}"), token)
    }

    #[tokio::test]
    async fn root_serves_spa_index_html() {
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.get(&base).send().await.unwrap();
        assert_eq!(res.status(), 200);
        let content_type = res.headers().get("content-type").unwrap().to_str().unwrap().to_string();
        assert!(content_type.contains("text/html"), "unexpected content-type: {content_type}");
        let body = res.text().await.unwrap();
        assert!(body.contains("<html"), "expected real index.html content, got: {}", &body[..body.len().min(200)]);
    }

    #[tokio::test]
    async fn unknown_path_falls_through_to_404() {
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.get(format!("{base}/definitely-not-a-real-asset.xyz")).send().await.unwrap();
        assert_eq!(res.status(), 404);
    }

    #[tokio::test]
    async fn tools_status_returns_every_expected_key() {
        let (base, token) = spawn_test_server_with_api_key().await;
        let client = reqwest::Client::new();
        let res = client.get(format!("{base}/api/tools/status")).header("authorization", format!("Bearer {token}")).send().await.unwrap();
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
        let (base, token) = spawn_test_server_with_api_key().await;
        let client = reqwest::Client::new();
        let auth = format!("Bearer {token}");

        let res = client.post(format!("{base}/api/baseline/acme/widgets")).header("authorization", &auth).json(&serde_json::json!({ "issueIds": ["a", "b"] })).send().await.unwrap();
        assert_eq!(res.status(), 200);
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["savedCount"], 2);

        let res = client.get(format!("{base}/api/baseline/acme/widgets")).header("authorization", &auth).send().await.unwrap();
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["count"], 2);

        let res = client.delete(format!("{base}/api/baseline/acme/widgets")).header("authorization", &auth).send().await.unwrap();
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["removed"], 2);
    }

    #[tokio::test]
    async fn baseline_save_rejects_missing_issue_ids() {
        let (base, token) = spawn_test_server_with_api_key().await;
        let client = reqwest::Client::new();
        let res = client.post(format!("{base}/api/baseline/acme/widgets")).header("authorization", format!("Bearer {token}")).json(&serde_json::json!({})).send().await.unwrap();
        assert_eq!(res.status(), 400);
    }

    #[tokio::test]
    async fn runtime_coverage_round_trip() {
        let (base, token) = spawn_test_server_with_api_key().await;
        let client = reqwest::Client::new();
        let auth = format!("Bearer {token}");

        let res = client.post(format!("{base}/api/runtime-coverage/acme/widgets")).header("authorization", &auth).json(&serde_json::json!({ "src/a.js": 5, "src/b.js": 0 })).send().await.unwrap();
        assert_eq!(res.status(), 200);
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["format"], "simple");
        assert_eq!(body["filesIngested"], 2);

        let res = client.get(format!("{base}/api/runtime-coverage/acme/widgets")).header("authorization", &auth).send().await.unwrap();
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["files"]["src/a.js"]["hitCount"], 5);

        let res = client.delete(format!("{base}/api/runtime-coverage/acme/widgets")).header("authorization", &auth).send().await.unwrap();
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["removed"], 2);
    }

    #[tokio::test]
    async fn auto_fix_rejects_nonexistent_project_path() {
        let (base, token) = spawn_test_server_with_api_key().await;
        let client = reqwest::Client::new();
        let res = client.post(format!("{base}/api/pipeline/auto-fix")).header("authorization", format!("Bearer {token}")).json(&serde_json::json!({ "projectPath": "/no/such/directory/ignite-test" })).send().await.unwrap();
        assert_eq!(res.status(), 400);
    }

    #[tokio::test]
    async fn auto_fix_dry_run_reports_dead_code_findings() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("orphan.js"), "module.exports = 1;\n").unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"name":"x","main":"index.js"}"#).unwrap();
        std::fs::write(dir.path().join("index.js"), "console.log(1);\n").unwrap();

        let (base, token) = spawn_test_server_with_api_key().await;
        let client = reqwest::Client::new();
        let res = client.post(format!("{base}/api/pipeline/auto-fix")).header("authorization", format!("Bearer {token}")).json(&serde_json::json!({ "projectPath": dir.path().to_string_lossy(), "categories": ["dead-code"] })).send().await.unwrap();
        assert_eq!(res.status(), 200);
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["dryRun"], true);
        assert!(body["actionCount"].as_u64().unwrap() >= 1);
    }

    #[tokio::test]
    async fn dependencies_check_rejects_nonexistent_project_path() {
        let (base, token) = spawn_test_server_with_api_key().await;
        let client = reqwest::Client::new();
        let res = client.post(format!("{base}/api/dependencies/check")).header("authorization", format!("Bearer {token}")).json(&serde_json::json!({ "projectPath": "/no/such/directory/ignite-test" })).send().await.unwrap();
        assert_eq!(res.status(), 400);
    }

    #[tokio::test]
    async fn reports_loc_metrics_returns_ok_for_real_project() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("main.go"), "package main\nfunc main() {}\n").unwrap();

        let (base, token) = spawn_test_server_with_api_key().await;
        let client = reqwest::Client::new();
        let res = client.post(format!("{base}/api/reports/loc-metrics")).header("authorization", format!("Bearer {token}")).json(&serde_json::json!({ "projectPath": dir.path().to_string_lossy() })).send().await.unwrap();
        assert_eq!(res.status(), 200);
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["ok"], true);
    }

    #[tokio::test]
    async fn reports_sbom_rejects_nonexistent_project_path() {
        let (base, token) = spawn_test_server_with_api_key().await;
        let client = reqwest::Client::new();
        let res = client.post(format!("{base}/api/reports/sbom")).bearer_auth(token).json(&serde_json::json!({ "projectPath": "/no/such/directory/ignite-test" })).send().await.unwrap();
        assert_eq!(res.status(), 400);
    }

    #[tokio::test]
    async fn github_check_rejects_invalid_owner_name() {
        let (base, token) = spawn_test_server_with_api_key().await;
        let client = reqwest::Client::new();
        let res = client.post(format!("{base}/api/pipeline/job-1/github-check")).bearer_auth(token).json(&serde_json::json!({ "owner": "-bad-", "repo": "widgets", "sha": "abc1234" })).send().await.unwrap();
        assert_eq!(res.status(), 400);
    }

    #[tokio::test]
    async fn github_check_returns_404_for_unknown_job() {
        let (base, token) = spawn_test_server_with_api_key().await;
        let client = reqwest::Client::new();
        let res = client.post(format!("{base}/api/pipeline/nope/github-check")).bearer_auth(token).json(&serde_json::json!({ "owner": "acme", "repo": "widgets", "sha": "abc1234" })).send().await.unwrap();
        assert_eq!(res.status(), 404);
    }

    #[tokio::test]
    async fn github_check_rejects_unauthenticated_caller() {
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.post(format!("{base}/api/pipeline/job-1/github-check")).json(&serde_json::json!({ "owner": "acme", "repo": "widgets", "sha": "abc1234" })).send().await.unwrap();
        assert_eq!(res.status(), 401);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn onboard_rejects_missing_gh_token_when_not_dry_run() {
        // See `state::GH_TOKEN_ENV_GUARD`: this depends on the ambient
        // absence of GH_TOKEN/GITHUB_TOKEN, shared with the tests in
        // `routes/effectivate.rs` that set/unset those vars.
        let _guard = crate::state::GH_TOKEN_ENV_GUARD.lock();
        std::env::remove_var("GH_TOKEN");
        std::env::remove_var("GITHUB_TOKEN");
        let dir = tempfile::tempdir().unwrap();
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        // dryRun is omitted (defaults false) — must fail fast before
        // touching the filesystem or making any GitHub API call.
        let res = client.post(format!("{base}/api/pipeline/onboard")).json(&serde_json::json!({ "org": "acme", "repo": "widgets", "projectPath": dir.path().to_string_lossy() })).send().await.unwrap();
        assert_eq!(res.status(), 401);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn onboard_dry_run_completes_without_shipping() {
        // A dry run now keeps its validated snapshot under
        // `IGNITE_DATA_DIR` — point that at a tempdir, not the real ~/.ignite.
        let _data_guard = crate::state::IGNITE_DATA_DIR_ENV_GUARD.lock();
        let data_dir = tempfile::tempdir().unwrap();
        std::env::set_var("IGNITE_DATA_DIR", data_dir.path());
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"name":"smoke"}"#).unwrap();
        std::fs::write(dir.path().join("app.js"), "console.log(1);\n").unwrap();

        let base = spawn_test_server().await;
        let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(180)).build().unwrap();
        let res = client
            .post(format!("{base}/api/pipeline/onboard"))
            .json(&serde_json::json!({ "org": "acme", "repo": "widgets", "projectPath": dir.path().to_string_lossy(), "dryRun": true, "runLocalCi": false }))
            .send()
            .await
            .unwrap();
        let status = res.status();
        let body: Value = res.json().await.unwrap();
        assert!(status == 200 || status == 400, "unexpected status {status}: {body}");
        assert_eq!(body["mode"], "onboard");
        assert_eq!(body["dryRun"], true);
        assert_eq!(body["repoUrl"], Value::Null);
        let phase6 = body["phases"].as_array().unwrap().iter().find(|p| p["phase"] == 6).unwrap();
        if status == 200 {
            // Every check passed (or was overridden) — dry run reaches
            // phase 6 and explicitly marks it "skipped" (never provisions/
            // pushes).
            assert_eq!(phase6["state"], "skipped");
        } else {
            // A blocking Phase 4 finding (e.g. an unreviewed CodeQL
            // query-suite pin — see `security.codeql.lastReviewedAt`,
            // always "overdue" for a fresh/default config) stops the run
            // before phase 6 ever runs, so it's still at its initial
            // "pending" state, not "skipped".
            assert_eq!(phase6["state"], "pending");
        }
    }

    #[tokio::test]
    async fn onboard_rejects_invalid_org_name() {
        let base = spawn_test_server().await;
        let client = reqwest::Client::new();
        let res = client.post(format!("{base}/api/pipeline/onboard")).json(&serde_json::json!({ "org": "-bad-", "repo": "widgets", "dryRun": true })).send().await.unwrap();
        assert_eq!(res.status(), 400);
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["failedPhase"], 1);
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

        let (base, token) = spawn_test_server_with_api_key().await;
        let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(180)).build().unwrap();
        let res = client
            .post(format!("{base}/api/pipeline/validate-all"))
            .bearer_auth(token)
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
        let (base, token) = spawn_test_server_with_api_key().await;
        let client = reqwest::Client::new();
        let res = client.post(format!("{base}/api/pipeline/validate-all")).bearer_auth(token).json(&serde_json::json!({ "repo": "..", "projectPath": "/tmp" })).send().await.unwrap();
        assert_eq!(res.status(), 400);
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["failedPhase"], 1);
    }

    #[tokio::test]
    async fn list_projects_returns_empty_array_for_fresh_db() {
        let (base, token) = spawn_test_server_with_api_key().await;
        let client = reqwest::Client::new();
        let res = client.get(format!("{base}/api/projects")).bearer_auth(token).send().await.unwrap();
        assert_eq!(res.status(), 200);
        let body: Value = res.json().await.unwrap();
        assert_eq!(body.as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn list_effectivated_projects_returns_empty_wrapper() {
        let (base, token) = spawn_test_server_with_api_key().await;
        let client = reqwest::Client::new();
        let res = client.get(format!("{base}/api/projects/effectivated")).bearer_auth(token).send().await.unwrap();
        assert_eq!(res.status(), 200);
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["projects"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn project_details_returns_404_for_unknown_id() {
        let (base, token) = spawn_test_server_with_api_key().await;
        let client = reqwest::Client::new();
        let res = client.get(format!("{base}/api/projects/999999")).bearer_auth(token).send().await.unwrap();
        assert_eq!(res.status(), 404);
    }

    #[tokio::test]
    async fn project_details_returns_400_for_non_numeric_id() {
        let (base, token) = spawn_test_server_with_api_key().await;
        let client = reqwest::Client::new();
        let res = client.get(format!("{base}/api/projects/not-a-number")).bearer_auth(token).send().await.unwrap();
        assert_eq!(res.status(), 400);
    }

    #[tokio::test]
    async fn delete_all_projects_succeeds_on_empty_db() {
        let (base, token) = spawn_test_server_with_api_key().await;
        let client = reqwest::Client::new();
        let res = client.delete(format!("{base}/api/projects")).bearer_auth(token).send().await.unwrap();
        assert_eq!(res.status(), 200);
    }

    #[tokio::test]
    async fn set_schedule_rejects_unknown_interval() {
        let (base, token) = spawn_test_server_with_api_key().await;
        let client = reqwest::Client::new();
        // project doesn't exist, but the id-shape check runs first — this
        // exercises the 404 path since no project was created in this test.
        let res = client.post(format!("{base}/api/projects/1/schedule")).bearer_auth(token).json(&serde_json::json!({ "enabled": true, "interval": "hourly" })).send().await.unwrap();
        assert_eq!(res.status(), 404);
    }

    #[tokio::test]
    async fn get_document_returns_404_for_unknown_id() {
        let (base, token) = spawn_test_server_with_api_key().await;
        let client = reqwest::Client::new();
        let res = client.get(format!("{base}/api/documents/999999")).bearer_auth(token).send().await.unwrap();
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
        let (base, token) = spawn_test_server_with_api_key().await;
        let client = reqwest::Client::new();
        let res = client.post(format!("{base}/api/issues/explain")).bearer_auth(token).json(&serde_json::json!({ "summary": "found a thing" })).send().await.unwrap();
        assert_eq!(res.status(), 400);
    }

    #[tokio::test]
    async fn issues_explain_reports_unavailable_when_no_llm_endpoint() {
        // An ephemeral, guaranteed-free port rather than the `local`
        // provider's default `http://localhost:8050` — a developer running
        // a real local LLM server on that exact default port would
        // otherwise make this test observe a genuine response instead of
        // "unavailable".
        let mut llm_config = state::default_llm_config();
        llm_config.scan_url = format!("http://127.0.0.1:{}", unused_local_port());
        let (base, token) = spawn_test_server_with_llm_config(llm_config).await;
        let client = reqwest::Client::new();
        let res = client.post(format!("{base}/api/issues/explain")).bearer_auth(token).json(&serde_json::json!({ "category": "secret", "summary": "hardcoded key" })).send().await.unwrap();
        assert_eq!(res.status(), 200);
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["explanation"], Value::Null);
        assert!(body["reason"].as_str().unwrap().contains("unavailable"));
    }

    #[tokio::test]
    async fn issues_suggest_fix_requires_snippet() {
        let (base, token) = spawn_test_server_with_api_key().await;
        let client = reqwest::Client::new();
        let res = client.post(format!("{base}/api/issues/suggest-fix")).bearer_auth(token).json(&serde_json::json!({ "category": "secret", "summary": "hardcoded key" })).send().await.unwrap();
        assert_eq!(res.status(), 400);
    }

    #[tokio::test]
    async fn reports_posture_rejects_nonexistent_project_path() {
        let (base, token) = spawn_test_server_with_api_key().await;
        let client = reqwest::Client::new();
        let res = client.post(format!("{base}/api/reports/posture")).bearer_auth(token).json(&serde_json::json!({ "projectPath": "/no/such/directory/ignite-test" })).send().await.unwrap();
        assert_eq!(res.status(), 400);
    }

    /// Like `spawn_test_server_with_api_key`, but hands back the shared
    /// `AppState` (to assert on DB rows) and the key's owner email, and can
    /// bind a GitHub token to the key.
    async fn spawn_test_server_with_state(owner_email: &str, key_github_token: Option<&str>) -> (String, String, Arc<AppState>) {
        let db_dir = tempfile::tempdir().unwrap();
        let db = ignite_db_store::DbStore::open(&db_dir.path().join("test.db")).unwrap();
        let user_id = db.create_local_user(owner_email, None, ignite_auth::dummy_hash()).unwrap();
        let token = format!("{}{}", ignite_auth::API_KEY_PREFIX, uuid::Uuid::new_v4());
        let key_id = db.create_api_key(user_id, &ignite_auth::hash_api_key(&token), None, None, "test");
        if let Some(gh) = key_github_token {
            db.set_api_key_github_token(key_id, Some(gh));
        }
        let state = Arc::new(AppState {
            runner: state::default_runner(),
            db,
            running_runs: Mutex::new(HashMap::new()),
            pending_effectivations: Mutex::new(HashMap::new()),
            review_gate: review_gate::ReviewGate::default(),
            llm_config: state::default_llm_config(),
            config: ignite_config::Config::default(),
            package_hallucination_checker: state::default_package_hallucination_checker(),
            fix_pr_previews: Mutex::new(HashMap::new()),
            audit_http: reqwest::Client::new(),
        });
        let public_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../public");
        let app = build_router(state.clone(), &public_dir);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await.unwrap();
        });
        std::mem::forget(db_dir);
        (format!("http://{addr}"), token, state)
    }

    fn agent_test_project() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"name":"smoke"}"#).unwrap();
        std::fs::write(dir.path().join("app.js"), "console.log(1);\n").unwrap();
        dir
    }

    /// The agent's happy path — `onboard_project(dryRun)` then
    /// `effectivate_project` — used to be impossible: the dry run returned no
    /// `projectId` and registered nothing to effectivate. Covers both ways a
    /// dry run can end (this environment may or may not produce blocking
    /// findings, e.g. an unreviewed CodeQL pin).
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn agent_dry_run_reports_policy_and_registers_a_snapshot_that_survives_a_restart() {
        let _data_guard = crate::state::IGNITE_DATA_DIR_ENV_GUARD.lock();
        let data_dir = tempfile::tempdir().unwrap();
        std::env::set_var("IGNITE_DATA_DIR", data_dir.path());
        let project = agent_test_project();

        let (base, key, state) = spawn_test_server_with_state("agent@example.com", Some("ghp_bound_to_key")).await;
        let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(300)).build().unwrap();
        let res = client
            .post(format!("{base}/api/pipeline/onboard"))
            .bearer_auth(&key)
            .json(&serde_json::json!({ "org": "acme", "repo": "widgets", "projectPath": project.path().to_string_lossy(), "dryRun": true, "runLocalCi": false }))
            .send()
            .await
            .unwrap();
        let status = res.status();
        let body: Value = res.json().await.unwrap();
        let project_id = body["projectId"].as_i64().unwrap_or_else(|| panic!("onboard must return projectId ({status}): {body}"));
        assert!(body["coverage"].is_array(), "coverage must be reported on every onboard response: {body}");
        assert!(body.get("policyDecision").is_some(), "policyDecision key must always be present: {body}");

        if status == 200 {
            assert_eq!(body["effectivatable"], true, "a passing dry run must be effectivatable: {body}");
            assert_eq!(body["policyDecision"]["decision"], "pass");
            let row = state.db.get_pending_effectivation(project_id).expect("a durable pending-effectivation row");
            assert!(std::path::Path::new(&row.source_dir).join("app.js").is_file(), "the kept snapshot must hold the validated tree");
            assert!(row.source_dir.starts_with(&*data_dir.path().to_string_lossy()), "kept under the data dir, not the OS temp dir");

            // Simulate a restart (in-memory map lost) and a vanished snapshot
            // dir: effectivate must still *find* the run (410 snapshot_gone),
            // not report it as never having existed (404).
            state.pending_effectivations.lock().clear();
            std::fs::remove_dir_all(&row.source_dir).unwrap();
            let eff = client.post(format!("{base}/api/projects/{project_id}/effectivate")).bearer_auth(&key).json(&serde_json::json!({})).send().await.unwrap();
            assert_eq!(eff.status(), 410, "the durable row must be found after a restart");
            let eff_body: Value = eff.json().await.unwrap();
            assert_eq!(eff_body["code"], "snapshot_gone");
        } else {
            assert_eq!(status, 400, "unexpected status: {body}");
            assert_eq!(body["blocked"], true, "a refused run must carry the machine-readable envelope: {body}");
            assert_eq!(body["ok"], false);
            let reason = body["blockReason"].as_str().unwrap();
            assert!(["unresolved_findings", "pending_approval", "incomplete_coverage", "policy_blocked"].contains(&reason), "unexpected blockReason {reason}");
            assert!(body["nextAction"].is_string() && body["overridable"].is_boolean());
            if reason == "unresolved_findings" {
                assert_eq!(body["overridable"], true);
                assert!(!body["unresolvedIssueIds"].as_array().unwrap().is_empty());
            }
            assert!(state.db.get_pending_effectivation(project_id).is_none(), "a blocked run must not register a snapshot");
        }
        std::env::remove_var("IGNITE_DATA_DIR");
    }

    /// The three publishing routes resolve "who is this override from"
    /// differently on purpose (validate-all may take a body actor when
    /// unauthenticated; onboard never does). For an *authenticated* agent
    /// they must all agree: the key's owner, never a body-supplied actor.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn an_agents_overrides_are_attributed_to_its_key_owner_on_every_route() {
        let _data_guard = crate::state::IGNITE_DATA_DIR_ENV_GUARD.lock();
        let data_dir = tempfile::tempdir().unwrap();
        std::env::set_var("IGNITE_DATA_DIR", data_dir.path());
        let project = agent_test_project();
        let (base, key, state) = spawn_test_server_with_state("owner@example.com", None).await;
        let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(300)).build().unwrap();
        let path = project.path().to_string_lossy().to_string();

        let routes: [(&str, Value); 2] = [
            ("/api/pipeline/onboard", serde_json::json!({ "org": "acme", "repo": "widgets", "projectPath": path, "dryRun": true, "runLocalCi": false })),
            ("/api/pipeline/validate-all", serde_json::json!({ "projectPath": path, "runLocalCi": false, "fast": true })),
        ];
        let mut exercised = 0;
        for (route, base_body) in routes {
            let first: Value = client.post(format!("{base}{route}")).bearer_auth(&key).json(&base_body).send().await.unwrap().json().await.unwrap();
            let Some(issues) = first["issues"].as_array().filter(|i| !i.is_empty()) else {
                eprintln!("skipping {route}: no findings in this environment, so there is nothing to override");
                continue;
            };
            let overrides: Vec<Value> = issues.iter().map(|i| serde_json::json!({ "issueId": i["id"], "justification": "Reviewed by the agent's owner: accepted risk for this test fixture." })).collect();
            let mut body = base_body.clone();
            body["overrides"] = Value::Array(overrides);
            body["actor"] = serde_json::json!({ "email": "mallory@example.com", "name": "Mallory" });
            let second: Value = client.post(format!("{base}{route}")).bearer_auth(&key).json(&body).send().await.unwrap().json().await.unwrap();
            let job_id = second["jobId"].as_str().unwrap_or_else(|| panic!("{route} returned no jobId: {second}"));
            let project_id = state.db.get_project_id_by_job_id(job_id).unwrap();
            let recorded = state.db.get_project_overrides(project_id);
            assert!(!recorded.is_empty(), "{route}: the overrides must have been recorded");
            for o in recorded {
                assert_eq!(o.actor_email, "owner@example.com", "{route}: attributed to the key owner, never the body actor");
            }
            exercised += 1;
        }
        eprintln!("override-attribution checked on {exercised}/2 routes");
        std::env::remove_var("IGNITE_DATA_DIR");
    }
}
