//! GitHub sign-in (`auth.js`'s `mode === 'github'`) and GitHub *account
//! connection* (`/api/auth/github/connect`, independent of sign-in mode —
//! holds a push token for Phase 6 provisioning). Talks to
//! `github.com/login/oauth/*` and `api.github.com` exactly like the Node
//! original; in tests, a local mock server stands in for both endpoints
//! so the real OAuth code→token→user-fetch contract is exercised without
//! needing a live GitHub OAuth app.

use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use once_cell::sync::Lazy;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::{issue_session_response, resolve_user, RequireAuth};
use crate::state::AppState;

struct PendingGithubState {
    user_id: Option<i64>,
    is_login: bool,
    created_at: Instant,
}

static PENDING: Lazy<Mutex<HashMap<String, PendingGithubState>>> = Lazy::new(|| Mutex::new(HashMap::new()));
const PENDING_TTL: Duration = Duration::from_secs(10 * 60);

fn prune_pending(map: &mut HashMap<String, PendingGithubState>) {
    let now = Instant::now();
    map.retain(|_, v| now.duration_since(v.created_at) <= PENDING_TTL);
}

/// Overridable in tests so the OAuth token-exchange/user-fetch calls hit a
/// local mock server instead of the real `github.com`/`api.github.com`.
struct GithubEndpoints {
    authorize_base: String,
    token_url: String,
    api_base: String,
}

fn endpoints() -> GithubEndpoints {
    if let Ok(base) = std::env::var("IGNITE_GITHUB_OAUTH_MOCK_BASE") {
        GithubEndpoints { authorize_base: format!("{base}/login/oauth/authorize"), token_url: format!("{base}/login/oauth/access_token"), api_base: base }
    } else {
        GithubEndpoints {
            authorize_base: "https://github.com/login/oauth/authorize".into(),
            token_url: "https://github.com/login/oauth/access_token".into(),
            api_base: "https://api.github.com".into(),
        }
    }
}

async fn github_status(State(state): State<Arc<AppState>>, headers: axum::http::HeaderMap) -> Response {
    match resolve_user(&headers, &state.db) {
        None => Json(json!({ "connected": false })).into_response(),
        Some(user) => {
            let conn = state.db.get_github_connection(user.id);
            Json(json!({ "connected": conn.is_some(), "login": conn.map(|c| c.github_login) })).into_response()
        }
    }
}

fn start_github_oauth(state: &Arc<AppState>, user_id: Option<i64>, is_login: bool) -> Response {
    let oauth = &state.config.github.oauth;
    if oauth.client_id.is_empty() || oauth.redirect_uri.is_empty() {
        return (axum::http::StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": "GitHub OAuth is not configured: set github.oauth.clientId, clientSecret, and redirectUri." }))).into_response();
    }
    let state_token = ignite_auth::generate_session_id();
    {
        let mut pending = PENDING.lock().unwrap();
        prune_pending(&mut pending);
        pending.insert(state_token.clone(), PendingGithubState { user_id, is_login, created_at: Instant::now() });
    }
    let base_scope = if oauth.scope.is_empty() { "repo" } else { &oauth.scope };
    let scope = if is_login { format!("{base_scope} user:email") } else { base_scope.to_string() };
    let ep = endpoints();
    let url = format!(
        "{}?client_id={}&redirect_uri={}&scope={}&state={}",
        ep.authorize_base,
        urlencoding::encode(&oauth.client_id),
        urlencoding::encode(&oauth.redirect_uri),
        urlencoding::encode(&scope),
        urlencoding::encode(&state_token),
    );
    Redirect::to(&url).into_response()
}

async fn github_login(State(state): State<Arc<AppState>>) -> Response {
    if state.config.auth.mode != "github" {
        return (axum::http::StatusCode::NOT_FOUND, "Not found").into_response();
    }
    start_github_oauth(&state, None, true)
}

async fn github_connect(State(state): State<Arc<AppState>>, RequireAuth(user): RequireAuth) -> Response {
    start_github_oauth(&state, Some(user.id), false)
}

#[derive(Deserialize)]
struct CallbackQuery {
    #[serde(default)]
    code: String,
    #[serde(default)]
    state: String,
}

#[derive(Deserialize, Default)]
struct TokenResponse {
    access_token: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
    scope: Option<String>,
}

#[derive(Deserialize, Default)]
struct GhUser {
    login: Option<String>,
    id: Option<i64>,
    name: Option<String>,
    email: Option<String>,
}

#[derive(Deserialize)]
struct GhEmail {
    email: String,
    primary: bool,
    verified: bool,
}

fn error_page(status: axum::http::StatusCode, message: &str) -> Response {
    (status, format!("GitHub authentication failed: {}", ignite_auth::escape_html(message))).into_response()
}

async fn github_callback(State(state): State<Arc<AppState>>, headers: axum::http::HeaderMap, Query(q): Query<CallbackQuery>) -> Response {
    let pending = {
        let mut pending = PENDING.lock().unwrap();
        prune_pending(&mut pending);
        match pending.remove(&q.state) {
            Some(p) => p,
            None => return error_page(axum::http::StatusCode::UNAUTHORIZED, "Unknown or expired GitHub OAuth state."),
        }
    };

    if !pending.is_login {
        let current = resolve_user(&headers, &state.db);
        match (&current, pending.user_id) {
            (Some(u), Some(pending_uid)) if u.id == pending_uid => {}
            _ => return error_page(axum::http::StatusCode::UNAUTHORIZED, "GitHub connection must be completed in the same session that started it."),
        }
    }

    let oauth = &state.config.github.oauth;
    let ep = endpoints();
    let client = reqwest::Client::new();
    let token_res = match client
        .post(&ep.token_url)
        .header("Accept", "application/json")
        .json(&json!({
            "client_id": oauth.client_id,
            "client_secret": oauth.client_secret,
            "code": q.code,
            "redirect_uri": oauth.redirect_uri,
        }))
        .send()
        .await
    {
        Ok(r) => r,
        Err(err) => return error_page(axum::http::StatusCode::UNAUTHORIZED, &err.to_string()),
    };
    let token_data: TokenResponse = match token_res.json().await {
        Ok(t) => t,
        Err(err) => return error_page(axum::http::StatusCode::UNAUTHORIZED, &format!("invalid token response: {err}")),
    };
    let access_token = match token_data.access_token {
        Some(t) if !t.is_empty() => t,
        _ => {
            let msg = token_data.error_description.or(token_data.error).unwrap_or_else(|| "GitHub did not return an access token.".into());
            return error_page(axum::http::StatusCode::UNAUTHORIZED, &msg);
        }
    };

    let user_res = match client.get(format!("{}/user", ep.api_base)).bearer_auth(&access_token).header("User-Agent", "ignite-onboarding-gatekeeper").send().await {
        Ok(r) => r,
        Err(err) => return error_page(axum::http::StatusCode::UNAUTHORIZED, &err.to_string()),
    };
    let gh_user: GhUser = match user_res.json().await {
        Ok(u) => u,
        Err(err) => return error_page(axum::http::StatusCode::UNAUTHORIZED, &format!("invalid user response: {err}")),
    };
    let login = match gh_user.login {
        Some(l) if !l.is_empty() => l,
        _ => return error_page(axum::http::StatusCode::UNAUTHORIZED, "Could not read the GitHub account login."),
    };

    if pending.is_login {
        let email = match gh_user.email {
            Some(e) if !e.is_empty() => e,
            _ => {
                let emails_res = client.get(format!("{}/user/emails", ep.api_base)).bearer_auth(&access_token).header("User-Agent", "ignite-onboarding-gatekeeper").send().await;
                let emails: Vec<GhEmail> = match emails_res {
                    Ok(r) => r.json().await.unwrap_or_default(),
                    Err(_) => Vec::new(),
                };
                emails
                    .iter()
                    .find(|e| e.primary && e.verified)
                    .or_else(|| emails.iter().find(|e| e.verified))
                    .map(|e| e.email.clone())
                    .unwrap_or_else(|| format!("{login}@users.noreply.github.com"))
            }
        };
        let name = gh_user.name.filter(|n| !n.is_empty()).unwrap_or_else(|| login.clone());
        let external_id = gh_user.id.map(|i| i.to_string()).unwrap_or_default();
        let user = state.db.upsert_github_user(&email, Some(&name), &external_id);
        state.db.upsert_github_connection(user.id, &login, &access_token, token_data.scope.as_deref());
        issue_session_response(&state.db, user.id, json!({ "user": { "id": user.id, "email": user.email, "name": user.name } }), axum::http::StatusCode::OK)
    } else {
        state.db.upsert_github_connection(pending.user_id.unwrap(), &login, &access_token, token_data.scope.as_deref());
        Json(json!({ "ok": true, "login": login })).into_response()
    }
}

async fn github_disconnect(State(state): State<Arc<AppState>>, RequireAuth(user): RequireAuth) -> Response {
    state.db.delete_github_connection(user.id);
    Json(json!({ "ok": true })).into_response()
}

pub fn github_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/auth/github/status", get(github_status))
        .route("/api/auth/github/login", get(github_login))
        .route("/api/auth/github/connect", get(github_connect))
        .route("/api/auth/github/callback", get(github_callback))
        .route("/api/auth/github/disconnect", post(github_disconnect))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::review_gate::ReviewGate;
    use axum::body::Body;
    use axum::http::Request;
    use std::collections::HashMap as Map;
    use std::sync::Mutex as StdMutex;
    use tower::ServiceExt;

    fn test_state(config: ignite_config::Config) -> Arc<AppState> {
        let db_dir = tempfile::tempdir().unwrap();
        let db = ignite_db_store::DbStore::open(&db_dir.path().join("test.db")).unwrap();
        Box::leak(Box::new(db_dir));
        Arc::new(AppState {
            runner: crate::state::default_runner(),
            db,
            running_runs: StdMutex::new(Map::new()),
            pending_effectivations: StdMutex::new(Map::new()),
            review_gate: ReviewGate::default(),
            llm_config: crate::state::default_llm_config(),
            config,
            package_hallucination_checker: crate::state::default_package_hallucination_checker(),
        })
    }

    /// Local mock of `github.com/login/oauth/access_token` +
    /// `api.github.com/user`(`/emails`) — real HTTP/JSON over the actual
    /// GitHub OAuth/REST contract, just not the live service.
    async fn spawn_mock_github() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = axum::Router::new()
            .route("/login/oauth/access_token", post(|| async { Json(json!({ "access_token": "gh-token-123", "token_type": "bearer", "scope": "repo" })) }))
            .route("/user", get(|| async { Json(json!({ "login": "octocat", "id": 42, "name": "The Octocat", "email": "octocat@example.com" })) }))
            .route("/user/emails", get(|| async { Json(json!([{ "email": "octocat@example.com", "primary": true, "verified": true }])) }));
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    fn github_configured_state(mode: &str) -> Arc<AppState> {
        let mut config = ignite_config::Config::default();
        config.auth.mode = mode.into();
        config.github.oauth.client_id = "client-123".into();
        config.github.oauth.client_secret = "secret-123".into();
        config.github.oauth.redirect_uri = "http://localhost/callback".into();
        test_state(config)
    }

    #[tokio::test]
    async fn full_github_login_round_trip_against_a_local_mock() {
        let mock_base = spawn_mock_github().await;
        std::env::set_var("IGNITE_GITHUB_OAUTH_MOCK_BASE", &mock_base);

        let state = github_configured_state("github");
        let app = github_router().with_state(state.clone());

        let login_res = app.clone().oneshot(Request::get("/api/auth/github/login").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(login_res.status(), axum::http::StatusCode::SEE_OTHER);
        let location = login_res.headers().get(axum::http::header::LOCATION).unwrap().to_str().unwrap().to_string();
        let redirect_url = url::Url::parse(&location).unwrap();
        let state_token = redirect_url.query_pairs().find(|(k, _)| k == "state").unwrap().1.to_string();

        let callback_res = app.oneshot(Request::get(format!("/api/auth/github/callback?code=abc&state={state_token}")).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(callback_res.status(), axum::http::StatusCode::OK, "callback did not succeed");
        let cookie = callback_res.headers().get(axum::http::header::SET_COOKIE).unwrap().to_str().unwrap().to_string();
        assert!(cookie.contains(ignite_auth::SESSION_COOKIE));

        let user = state.db.get_user_by_email("octocat@example.com").unwrap();
        assert_eq!(user.provider, "github");
        let conn = state.db.get_github_connection(user.id).unwrap();
        assert_eq!(conn.access_token, "gh-token-123");

        std::env::remove_var("IGNITE_GITHUB_OAUTH_MOCK_BASE");
    }

    #[tokio::test]
    async fn login_404s_when_mode_is_not_github() {
        let state = github_configured_state("standalone");
        let app = github_router().with_state(state);
        let res = app.oneshot(Request::get("/api/auth/github/login").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn status_reports_disconnected_with_no_session() {
        let state = github_configured_state("standalone");
        let app = github_router().with_state(state);
        let res = app.oneshot(Request::get("/api/auth/github/status").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), axum::http::StatusCode::OK);
        let bytes = axum::body::to_bytes(res.into_body(), 1024 * 1024).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["connected"], false);
    }

    #[tokio::test]
    async fn connect_requires_auth() {
        let state = github_configured_state("standalone");
        let app = github_router().with_state(state);
        let res = app.oneshot(Request::get("/api/auth/github/connect").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn callback_rejects_unknown_state() {
        let state = github_configured_state("standalone");
        let app = github_router().with_state(state);
        let res = app.oneshot(Request::get("/api/auth/github/callback?code=x&state=unknown").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), axum::http::StatusCode::UNAUTHORIZED);
    }
}
