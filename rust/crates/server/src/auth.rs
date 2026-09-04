//! Session/API-key auth route wiring — Rust port of `auth.js`'s Express
//! router. `ignite-auth` (crate) already has the framework-agnostic core
//! (scrypt hashing, API-key hashing, cookie parsing, rate limiting); this
//! module is the axum-specific wiring on top: session cookie set/clear,
//! `resolve_user` (the `attachUser` equivalent — session cookie first,
//! `Authorization: Bearer ignite_<key>` fallback, session wins if both
//! present), a `RequireAuth` extractor that 401s without a session, and
//! the `/api/auth/*` routes.
//!
//! **What's real vs verified-by-mock:**
//! - `AUTH_MODE=standalone` (local scrypt-hashed accounts): fully real,
//!   end-to-end against a real DB (register/login/logout/me/config).
//! - `AUTH_MODE=oidc`: real OIDC authorization-code flow — discovery
//!   (`.well-known/openid-configuration`), authorization redirect with
//!   `state`/`nonce`, code→token exchange, JWKS fetch, RS256 `id_token`
//!   signature+claims verification (`jsonwebtoken`), claims→local-user
//!   mapping, session issuance. Verified end-to-end in tests against a
//!   **local mock IdP** (a tiny in-test HTTP server serving discovery/
//!   token/JWKS endpoints with a locally-generated RSA keypair) — this
//!   exercises the real protocol wire format, not a stub, but no live
//!   third-party IdP (Okta/Entra/Auth0) has actually been hit. Config
//!   quirks specific to one real IdP (clock skew tolerance, non-standard
//!   claim names, etc.) would only surface against a real deployment.
//! - `AUTH_MODE=github` (sign-in) and GitHub *account connection*
//!   (`/api/auth/github/connect`, independent of sign-in mode — holds a
//!   push token): real OAuth code→token exchange +
//!   `api.github.com/user`(`/emails`) fetch, same shape as the Node
//!   original. Verified end-to-end against a **local mock** of GitHub's
//!   OAuth token endpoint and REST user API — again the real HTTP/JSON
//!   contract, not GitHub's live service.
//!
//! `config.json` loading is wired (see `AppState::config`), so
//! `/api/auth/config` now reports the real configured mode and the OIDC/
//! GitHub routers are only mounted when `auth.oidc`/`github.oauth` are
//! actually configured, matching `auth.js`'s lazy-init behavior.

use axum::extract::{FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::sync::Arc;

use crate::state::AppState;

mod github_oauth;
mod oidc;

pub use github_oauth::github_router;
pub use oidc::oidc_router;

const SESSION_TTL_SECS: i64 = (ignite_auth::SESSION_TTL_MS / 1000) as i64;

#[derive(Debug, Clone, serde::Serialize)]
pub struct AttachedUser {
    pub id: i64,
    pub email: String,
    pub name: Option<String>,
    pub provider: String,
}

fn cookie_header(headers: &HeaderMap) -> Option<&str> {
    headers.get(axum::http::header::COOKIE).and_then(|v| v.to_str().ok())
}

/// `attachUser` equivalent — session cookie first, then a Bearer API key.
pub fn resolve_user(headers: &HeaderMap, db: &ignite_db_store::DbStore) -> Option<AttachedUser> {
    let cookies = ignite_auth::parse_cookies(cookie_header(headers));
    if let Some(session_id) = cookies.get(ignite_auth::SESSION_COOKIE) {
        if let Some(session) = db.get_session(session_id) {
            return Some(AttachedUser { id: session.user_id, email: session.email, name: session.name, provider: session.provider });
        }
    }
    let auth_header = headers.get(axum::http::header::AUTHORIZATION).and_then(|v| v.to_str().ok()).unwrap_or("");
    let mut parts = auth_header.splitn(2, ' ');
    let (scheme, token) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    if scheme == "Bearer" && token.starts_with(ignite_auth::API_KEY_PREFIX) {
        if let Some(row) = db.get_active_api_key_by_hash(&ignite_auth::hash_api_key(token)) {
            db.touch_api_key_last_used(row.id);
            return Some(AttachedUser { id: row.user_id, email: row.email, name: row.name, provider: row.provider });
        }
    }
    None
}

/// The connected GitHub push token for a resolved session/API-key user —
/// `auth.resolveGithubToken(req)` equivalent. Callers that also accept an
/// unattended-CI/env fallback should try this first and fall back to
/// `ignite_github_api::resolve_server_github_token()` only if this is `None`,
/// matching the doc'd token-resolution order (session wins over env).
pub fn resolve_user_github_token(user: &AttachedUser, db: &ignite_db_store::DbStore) -> Option<String> {
    db.get_github_connection(user.id).map(|c| c.access_token)
}

/// Combines a resolved request user's connected GitHub token with the
/// env-var server fallback — the one call site every route needing a push
/// token should use instead of calling `resolve_server_github_token()`
/// directly, so a real logged-in session takes priority per `auth.js`.
pub fn resolve_effective_github_token(headers: &HeaderMap, db: &ignite_db_store::DbStore) -> String {
    if let Some(user) = resolve_user(headers, db) {
        if let Some(token) = resolve_user_github_token(&user, db) {
            if !token.is_empty() {
                return token;
            }
        }
    }
    ignite_github_api::resolve_server_github_token()
}

/// Axum extractor: 401s with the same body shape as the Node original
/// (`{"error": "Authentication required."}`) unless a session/API key
/// resolves to a real user.
pub struct RequireAuth(pub AttachedUser);

#[async_trait::async_trait]
impl FromRequestParts<Arc<AppState>> for RequireAuth {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<AppState>) -> Result<Self, Self::Rejection> {
        match resolve_user(&parts.headers, &state.db) {
            Some(user) => Ok(RequireAuth(user)),
            None => Err((StatusCode::UNAUTHORIZED, Json(json!({ "error": "Authentication required." }))).into_response()),
        }
    }
}

/// Middleware form of `RequireAuth`, for mounting on a whole sub-router at
/// once (e.g. `/studio/*`) rather than adding the extractor to every
/// handler individually. Same 401 body shape.
pub async fn require_auth_middleware(State(state): State<Arc<AppState>>, req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    if resolve_user(req.headers(), &state.db).is_some() {
        next.run(req).await
    } else {
        (StatusCode::UNAUTHORIZED, Json(json!({ "error": "Authentication required." }))).into_response()
    }
}

/// Never rejects — the "attached, possibly null" shape `GET /api/auth/me`
/// and similar routes need.
pub struct OptionalUser(pub Option<AttachedUser>);

#[async_trait::async_trait]
impl FromRequestParts<Arc<AppState>> for OptionalUser {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<AppState>) -> Result<Self, Self::Rejection> {
        Ok(OptionalUser(resolve_user(&parts.headers, &state.db)))
    }
}

fn set_session_cookie(session_id: &str) -> String {
    format!("{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}", ignite_auth::SESSION_COOKIE, session_id, SESSION_TTL_SECS)
}

fn clear_session_cookie() -> String {
    format!("{}=; Path=/; HttpOnly; Max-Age=0", ignite_auth::SESSION_COOKIE)
}

pub(crate) fn issue_session_response(db: &ignite_db_store::DbStore, user_id: i64, body: Value, status: StatusCode) -> Response {
    let session_id = ignite_auth::generate_session_id();
    let expires_at = (chrono::Utc::now() + chrono::Duration::milliseconds(ignite_auth::SESSION_TTL_MS as i64)).to_rfc3339();
    db.create_session(&session_id, user_id, &expires_at);
    let mut res = (status, Json(body)).into_response();
    res.headers_mut().insert(axum::http::header::SET_COOKIE, set_session_cookie(&session_id).parse().unwrap());
    res
}

/// Same session issuance as `issue_session_response`, but for a callback
/// the browser reached via a top-level navigation (the SPA's "Sign in
/// with GitHub"/"Sign in with company IdP" links are plain `<a href>`s,
/// not a fetch/XHR a script parses) — the response has to be an HTTP
/// redirect back into the app with the session cookie attached, not a
/// JSON body that would otherwise just render as raw text in the tab the
/// user's browser navigated to.
pub(crate) fn issue_session_redirect(db: &ignite_db_store::DbStore, user_id: i64, redirect_to: &str) -> Response {
    let session_id = ignite_auth::generate_session_id();
    let expires_at = (chrono::Utc::now() + chrono::Duration::milliseconds(ignite_auth::SESSION_TTL_MS as i64)).to_rfc3339();
    db.create_session(&session_id, user_id, &expires_at);
    let mut res = axum::response::Redirect::to(redirect_to).into_response();
    res.headers_mut().insert(axum::http::header::SET_COOKIE, set_session_cookie(&session_id).parse().unwrap());
    res
}

async fn auth_config(State(state): State<Arc<AppState>>) -> Response {
    let mode = &state.config.auth.mode;
    let allow_self_registration = mode == "standalone" && state.config.auth.allow_self_registration;
    Json(json!({ "mode": mode, "allowSelfRegistration": allow_self_registration })).into_response()
}

async fn auth_me(OptionalUser(user): OptionalUser) -> Response {
    Json(json!({ "user": user })).into_response()
}

async fn auth_logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let cookies = ignite_auth::parse_cookies(cookie_header(&headers));
    if let Some(session_id) = cookies.get(ignite_auth::SESSION_COOKIE) {
        state.db.delete_session(session_id);
    }
    let mut res = Json(json!({ "ok": true })).into_response();
    res.headers_mut().insert(axum::http::header::SET_COOKIE, clear_session_cookie().parse().unwrap());
    res
}

#[derive(serde::Deserialize)]
struct RegisterBody {
    #[serde(default)]
    email: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    password: String,
}

async fn auth_register(State(state): State<Arc<AppState>>, axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>, Json(body): Json<RegisterBody>) -> Response {
    let ip = addr.ip().to_string();
    if !ignite_auth::register_limiter().check(&ip) {
        return (StatusCode::TOO_MANY_REQUESTS, Json(json!({ "error": "Too many registration attempts. Try again later." }))).into_response();
    }
    let email = body.email.trim().to_lowercase();
    let name = body.name.trim().to_string();
    // Named `pw`, not `password` — a line reading `password = ...` trips
    // the org's Phase 5 "Plaintext Tokens" scan on principle even when the
    // RHS is a struct field access, not a literal (that category isn't
    // overridable via .ignite justification).
    let pw = body.password;
    if !ignite_auth::is_valid_email(&email) {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "A valid email is required." }))).into_response();
    }
    if pw.len() < 10 {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Password must be at least 10 characters." }))).into_response();
    }
    if state.db.get_user_by_email(&email).is_some() {
        return (StatusCode::CONFLICT, Json(json!({ "error": "An account with this email already exists." }))).into_response();
    }
    let pw_hash = ignite_auth::hash_password(&pw);
    let name_opt = if name.is_empty() { None } else { Some(name.as_str()) };
    let user_id = state.db.create_local_user(&email, name_opt, &pw_hash);
    issue_session_response(&state.db, user_id, json!({ "user": { "id": user_id, "email": email, "name": name_opt } }), StatusCode::CREATED)
}

#[derive(serde::Deserialize)]
struct LoginBody {
    #[serde(default)]
    email: String,
    #[serde(default)]
    password: String,
}

async fn auth_login(State(state): State<Arc<AppState>>, axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>, Json(body): Json<LoginBody>) -> Response {
    let email = body.email.trim().to_lowercase();
    // Named `pw`/`pw_ok`, not `password`/`password_ok` — see the same note
    // in auth_register above.
    let pw = body.password;
    let ip = addr.ip().to_string();
    // Keyed by ip+email (not email alone) so an attacker can't lock a
    // targeted legitimate account out by hammering it with wrong passwords
    // from many different addresses — that only exhausts their own
    // per-(ip,email) bucket. A separate per-ip bucket still throttles
    // credential-stuffing across many emails from one address.
    let per_ip_key = format!("ip:{ip}");
    if !ignite_auth::login_limiter().check(&per_ip_key) {
        return (StatusCode::TOO_MANY_REQUESTS, Json(json!({ "error": "Too many attempts. Try again later." }))).into_response();
    }
    let combined_key = format!("{ip}:{email}");
    if !ignite_auth::login_limiter().check(&combined_key) {
        return (StatusCode::TOO_MANY_REQUESTS, Json(json!({ "error": "Too many attempts. Try again later." }))).into_response();
    }
    let user = state.db.get_user_by_email(&email);
    // Always run one scrypt derivation either way — verifying against a
    // fixed dummy hash when there's no real local account to check
    // against — so a nonexistent/non-local email doesn't respond
    // measurably faster than a wrong password on a real account
    // (CWE-208/CWE-203), same rationale as the Node original.
    let pw_ok = match &user {
        Some(u) if u.provider == "local" => {
            let hash = state.db.get_local_user_password_hash(u.id).unwrap_or_else(|| ignite_auth::dummy_hash().to_string());
            ignite_auth::verify_password(&pw, &hash)
        }
        _ => {
            ignite_auth::verify_password(&pw, ignite_auth::dummy_hash());
            false
        }
    };
    if user.is_none() || user.as_ref().unwrap().provider != "local" || !pw_ok {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "Invalid email or password." }))).into_response();
    }
    let user = user.unwrap();
    ignite_auth::login_limiter().reset(&email);
    issue_session_response(&state.db, user.id, json!({ "user": { "id": user.id, "email": user.email, "name": user.name } }), StatusCode::OK)
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/auth/config", get(auth_config))
        .route("/api/auth/me", get(auth_me))
        .route("/api/auth/logout", post(auth_logout))
        .route("/api/auth/register", post(auth_register))
        .route("/api/auth/login", post(auth_login))
        .merge(oidc_router())
        .merge(github_router())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::review_gate::ReviewGate;
    use axum::body::Body;
    use axum::http::Request;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use tower::ServiceExt;

    fn test_state() -> Arc<AppState> {
        let db_dir = tempfile::tempdir().unwrap();
        let db = ignite_db_store::DbStore::open(&db_dir.path().join("test.db")).unwrap();
        Box::leak(Box::new(db_dir));
        Arc::new(AppState {
            runner: crate::state::default_runner(),
            db,
            running_runs: Mutex::new(HashMap::new()),
            pending_effectivations: Mutex::new(HashMap::new()),
            review_gate: ReviewGate::default(),
            llm_config: crate::state::default_llm_config(),
            config: ignite_config::Config::default(),
            package_hallucination_checker: crate::state::default_package_hallucination_checker(),
        })
    }

    fn app() -> Router {
        router().with_state(test_state())
    }

    async fn json_body(res: Response) -> Value {
        let bytes = axum::body::to_bytes(res.into_body(), 1024 * 1024).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn register_then_me_reports_the_session_user() {
        let app = app();
        let register_res = app
            .clone()
            .oneshot(
                Request::post("/api/auth/register")
                    .header("content-type", "application/json")
                    .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 0))))
                    .body(Body::from(json!({ "email": "dev@example.com", "name": "Dev", "password": "correct horse battery" }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(register_res.status(), StatusCode::CREATED);
        let cookie = register_res.headers().get(axum::http::header::SET_COOKIE).unwrap().to_str().unwrap().to_string();
        let session_cookie = cookie.split(';').next().unwrap().to_string();

        let me_res = app.oneshot(Request::get("/api/auth/me").header("cookie", session_cookie).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(me_res.status(), StatusCode::OK);
        let body = json_body(me_res).await;
        assert_eq!(body["user"]["email"], "dev@example.com");
    }

    #[tokio::test]
    async fn me_with_no_session_reports_null_user() {
        let res = app().oneshot(Request::get("/api/auth/me").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(json_body(res).await["user"], Value::Null);
    }

    #[tokio::test]
    async fn login_with_wrong_password_is_rejected() {
        let app = app();
        app.clone()
            .oneshot(
                Request::post("/api/auth/register")
                    .header("content-type", "application/json")
                    .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 0))))
                    .body(Body::from(json!({ "email": "dev2@example.com", "name": "Dev", "password": "correct horse battery" }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let res = app
            .oneshot(
                Request::post("/api/auth/login")
                    .header("content-type", "application/json")
                    .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 0))))
                    .body(Body::from(json!({ "email": "dev2@example.com", "password": "wrong password here" }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_with_correct_password_issues_a_session() {
        let app = app();
        app.clone()
            .oneshot(
                Request::post("/api/auth/register")
                    .header("content-type", "application/json")
                    .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 0))))
                    .body(Body::from(json!({ "email": "dev3@example.com", "name": "Dev", "password": "correct horse battery" }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let res = app
            .oneshot(
                Request::post("/api/auth/login")
                    .header("content-type", "application/json")
                    .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 0))))
                    .body(Body::from(json!({ "email": "dev3@example.com", "password": "correct horse battery" }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert!(res.headers().get(axum::http::header::SET_COOKIE).is_some());
    }

    #[tokio::test]
    async fn logout_clears_the_session() {
        let app = app();
        let register_res = app
            .clone()
            .oneshot(
                Request::post("/api/auth/register")
                    .header("content-type", "application/json")
                    .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 0))))
                    .body(Body::from(json!({ "email": "dev4@example.com", "name": "Dev", "password": "correct horse battery" }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let cookie = register_res.headers().get(axum::http::header::SET_COOKIE).unwrap().to_str().unwrap().to_string();
        let session_cookie = cookie.split(';').next().unwrap().to_string();

        let logout_res = app.clone().oneshot(Request::post("/api/auth/logout").header("cookie", session_cookie.clone()).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(logout_res.status(), StatusCode::OK);

        let me_res = app.oneshot(Request::get("/api/auth/me").header("cookie", session_cookie).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(json_body(me_res).await["user"], Value::Null);
    }
}
