//! `auth.js`'s `mode === 'oidc'` branch — real authorization-code flow
//! (discovery, redirect, code→token exchange, JWKS fetch, RS256 `id_token`
//! verification) against whatever `auth.oidc` in config.json points at.
//! Only mounted/active when `state.config.auth.mode == "oidc"` and the
//! required `auth.oidc` fields (issuer/clientId/redirectUri) are set —
//! otherwise these handlers 404/503 the same way an unmounted Express
//! route or a lazy-init failure would in the Node original.

use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::{Json, Router};
use once_cell::sync::Lazy;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::issue_session_redirect;
use crate::state::AppState;

struct PendingOidcState {
    nonce: String,
    created_at: Instant,
}

static PENDING: Lazy<Mutex<HashMap<String, PendingOidcState>>> = Lazy::new(|| Mutex::new(HashMap::new()));

const PENDING_TTL: Duration = Duration::from_secs(10 * 60);

fn prune_pending(map: &mut HashMap<String, PendingOidcState>) {
    let now = Instant::now();
    map.retain(|_, v| now.duration_since(v.created_at) <= PENDING_TTL);
}

fn random_token() -> String {
    ignite_auth::generate_session_id()
}

#[derive(Deserialize)]
struct Discovery {
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

async fn discover(issuer: &str) -> Result<Discovery, String> {
    let url = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));
    let res = reqwest::get(&url).await.map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        return Err(format!("discovery endpoint returned {}", res.status()));
    }
    res.json::<Discovery>().await.map_err(|e| e.to_string())
}

#[derive(Deserialize)]
struct Jwk {
    kid: String,
    n: String,
    e: String,
}

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
}

async fn oidc_login(State(state): State<Arc<AppState>>) -> Response {
    if state.config.auth.mode != "oidc" {
        return (axum::http::StatusCode::NOT_FOUND, "Not found").into_response();
    }
    let oidc = &state.config.auth.oidc;
    if oidc.issuer.is_empty() || oidc.client_id.is_empty() || oidc.redirect_uri.is_empty() {
        return (axum::http::StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": "OIDC login unavailable: OIDC is not configured: set auth.oidc.issuer, clientId, and redirectUri." }))).into_response();
    }
    let discovery = match discover(&oidc.issuer).await {
        Ok(d) => d,
        Err(err) => return (axum::http::StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": format!("OIDC login unavailable: {err}") }))).into_response(),
    };
    let state_token = random_token();
    let nonce = random_token();
    {
        let mut pending = PENDING.lock().unwrap();
        prune_pending(&mut pending);
        pending.insert(state_token.clone(), PendingOidcState { nonce: nonce.clone(), created_at: Instant::now() });
    }
    let scope = if oidc.scope.is_empty() { "openid email profile" } else { &oidc.scope };
    let url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}",
        discovery.authorization_endpoint,
        urlencoding::encode(&oidc.client_id),
        urlencoding::encode(&oidc.redirect_uri),
        urlencoding::encode(scope),
        urlencoding::encode(&state_token),
        urlencoding::encode(&nonce),
    );
    Redirect::to(&url).into_response()
}

#[derive(Deserialize)]
struct CallbackQuery {
    #[serde(default)]
    code: String,
    #[serde(default)]
    state: String,
}

fn error_page(status: axum::http::StatusCode, message: &str) -> Response {
    (status, format!("OIDC login failed: {}", ignite_auth::escape_html(message))).into_response()
}

async fn oidc_callback(State(state): State<Arc<AppState>>, Query(q): Query<CallbackQuery>) -> Response {
    if state.config.auth.mode != "oidc" {
        return (axum::http::StatusCode::NOT_FOUND, "Not found").into_response();
    }
    let oidc = &state.config.auth.oidc;

    let pending_nonce = {
        let mut pending = PENDING.lock().unwrap();
        prune_pending(&mut pending);
        match pending.remove(&q.state) {
            Some(p) => p.nonce,
            None => return error_page(axum::http::StatusCode::UNAUTHORIZED, "Unknown or expired OIDC state."),
        }
    };

    let discovery = match discover(&oidc.issuer).await {
        Ok(d) => d,
        Err(err) => return error_page(axum::http::StatusCode::UNAUTHORIZED, &err),
    };

    let client = reqwest::Client::new();
    let mut form = HashMap::new();
    form.insert("grant_type", "authorization_code");
    form.insert("code", q.code.as_str());
    form.insert("redirect_uri", oidc.redirect_uri.as_str());
    form.insert("client_id", oidc.client_id.as_str());
    form.insert("client_secret", oidc.client_secret.as_str());
    let token_res = match client.post(&discovery.token_endpoint).form(&form).send().await {
        Ok(r) => r,
        Err(err) => return error_page(axum::http::StatusCode::UNAUTHORIZED, &err.to_string()),
    };
    if !token_res.status().is_success() {
        return error_page(axum::http::StatusCode::UNAUTHORIZED, &format!("token endpoint returned {}", token_res.status()));
    }
    let token_body: TokenResponse = match token_res.json().await {
        Ok(t) => t,
        Err(err) => return error_page(axum::http::StatusCode::UNAUTHORIZED, &format!("invalid token response: {err}")),
    };

    let header = match jsonwebtoken::decode_header(&token_body.id_token) {
        Ok(h) => h,
        Err(err) => return error_page(axum::http::StatusCode::UNAUTHORIZED, &format!("invalid id_token header: {err}")),
    };
    let kid = match header.kid {
        Some(k) => k,
        None => return error_page(axum::http::StatusCode::UNAUTHORIZED, "id_token is missing a key id."),
    };

    let jwks: Jwks = match reqwest::get(&discovery.jwks_uri).await {
        Ok(r) => match r.json().await {
            Ok(j) => j,
            Err(err) => return error_page(axum::http::StatusCode::UNAUTHORIZED, &format!("invalid JWKS response: {err}")),
        },
        Err(err) => return error_page(axum::http::StatusCode::UNAUTHORIZED, &err.to_string()),
    };
    let jwk = match jwks.keys.iter().find(|k| k.kid == kid) {
        Some(k) => k,
        None => return error_page(axum::http::StatusCode::UNAUTHORIZED, "No matching signing key found for id_token."),
    };

    let decoding_key = match jsonwebtoken::DecodingKey::from_rsa_components(&jwk.n, &jwk.e) {
        Ok(k) => k,
        Err(err) => return error_page(axum::http::StatusCode::UNAUTHORIZED, &format!("invalid signing key: {err}")),
    };
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&[&oidc.client_id]);
    validation.set_issuer(&[&oidc.issuer]);
    let token_data = match jsonwebtoken::decode::<Value>(&token_body.id_token, &decoding_key, &validation) {
        Ok(t) => t,
        Err(err) => return error_page(axum::http::StatusCode::UNAUTHORIZED, &format!("id_token verification failed: {err}")),
    };
    let claims = token_data.claims;

    if claims.get("nonce").and_then(|v| v.as_str()) != Some(pending_nonce.as_str()) {
        return error_page(axum::http::StatusCode::UNAUTHORIZED, "id_token nonce mismatch.");
    }
    let email = match claims.get("email").and_then(|v| v.as_str()) {
        Some(e) if !e.is_empty() => e.to_string(),
        _ => return error_page(axum::http::StatusCode::UNAUTHORIZED, "IdP did not return an email claim."),
    };
    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    let name = claims.get("name").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| email.clone());

    let user = state.db.upsert_oidc_user(&email, Some(&name), &sub);
    issue_session_redirect(&state.db, user.id, "/")
}

pub fn oidc_router() -> Router<Arc<AppState>> {
    Router::new().route("/api/auth/oidc/login", get(oidc_login)).route("/api/auth/oidc/callback", get(oidc_callback))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::review_gate::ReviewGate;
    use axum::body::Body;
    use axum::http::Request;
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use parking_lot::Mutex;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPrivateKey;
    use std::collections::HashMap as Map;
    use tower::ServiceExt;

    fn test_state(config: ignite_config::Config) -> Arc<AppState> {
        let db_dir = tempfile::tempdir().unwrap();
        let db = ignite_db_store::DbStore::open(&db_dir.path().join("test.db")).unwrap();
        Box::leak(Box::new(db_dir));
        Arc::new(AppState {
            runner: crate::state::default_runner(),
            db,
            running_runs: Mutex::new(Map::new()),
            pending_effectivations: Mutex::new(Map::new()),
            review_gate: ReviewGate::default(),
            llm_config: crate::state::default_llm_config(),
            config,
            package_hallucination_checker: crate::state::default_package_hallucination_checker(),
            fix_pr_previews: Mutex::new(HashMap::new()),
        })
    }

    fn base64url(bytes: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Spins up a tiny local mock IdP (discovery + token + jwks endpoints)
    /// serving real HTTP/JSON in the real OIDC wire shapes, backed by a
    /// freshly generated RSA keypair — this is the "local mock IdP" the
    /// module doc comment refers to, not a live third-party provider.
    async fn spawn_mock_idp(key: &RsaPrivateKey) -> String {
        let n = base64url(&key.n().to_bytes_be());
        let e = base64url(&key.e().to_bytes_be());
        let jwks = json!({ "keys": [{ "kty": "RSA", "kid": "test-key", "n": n, "e": e }] });
        let key_der = key.to_pkcs1_der().unwrap().as_bytes().to_vec();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let issuer = format!("http://{addr}");
        let issuer_for_disco = issuer.clone();
        let issuer_for_token = issuer.clone();

        let app = axum::Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move || {
                    let issuer = issuer_for_disco.clone();
                    async move {
                        Json(json!({
                            "issuer": issuer,
                            "authorization_endpoint": format!("{issuer}/authorize"),
                            "token_endpoint": format!("{issuer}/token"),
                            "jwks_uri": format!("{issuer}/jwks"),
                        }))
                    }
                }),
            )
            .route("/jwks", get(move || { let jwks = jwks.clone(); async move { Json(jwks) } }))
            .route(
                "/token",
                axum::routing::post(move |axum::Form(_): axum::Form<Map<String, String>>| {
                    let issuer = issuer_for_token.clone();
                    let key_der = key_der.clone();
                    async move {
                        let encoding_key = EncodingKey::from_rsa_der(&key_der);
                        let mut header = Header::new(Algorithm::RS256);
                        header.kid = Some("test-key".into());
                        let now = chrono::Utc::now().timestamp();
                        let claims = json!({
                            "iss": issuer,
                            "aud": "test-client",
                            "sub": "user-123",
                            "email": "oidc-user@example.com",
                            "name": "OIDC User",
                            "nonce": "__NONCE__",
                            "iat": now,
                            "exp": now + 300,
                        });
                        let id_token = jsonwebtoken::encode(&header, &claims, &encoding_key).unwrap();
                        Json(json!({ "id_token": id_token, "access_token": "at-123", "token_type": "Bearer" }))
                    }
                }),
            );

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        issuer
    }

    #[tokio::test]
    async fn full_oidc_login_callback_round_trip_against_a_local_mock_idp() {
        let key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let issuer = spawn_mock_idp(&key).await;

        let mut config = ignite_config::Config::default();
        config.auth.mode = "oidc".into();
        config.auth.oidc.issuer = issuer.clone();
        config.auth.oidc.client_id = "test-client".into();
        config.auth.oidc.client_secret = "test-secret".into();
        config.auth.oidc.redirect_uri = format!("{issuer}/callback");

        let state = test_state(config);
        let app = oidc_router().with_state(state.clone());

        // Drive /login for real to capture the actual state/nonce this
        // server generated (the mock IdP's /token handler embeds a fixed
        // nonce placeholder — real state extraction below matches it via
        // the redirect Location, then we hand-craft the callback like a
        // browser completing the redirect would).
        let login_res = app.clone().oneshot(Request::get("/api/auth/oidc/login").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(login_res.status(), axum::http::StatusCode::SEE_OTHER);
        let location = login_res.headers().get(axum::http::header::LOCATION).unwrap().to_str().unwrap().to_string();
        let redirect_url = url::Url::parse(&location).unwrap();
        let state_token = redirect_url.query_pairs().find(|(k, _)| k == "state").unwrap().1.to_string();

        // The mock /token handler above signs a token with a hardcoded
        // "__NONCE__" claim — swap the pending entry's expected nonce to
        // match so verification succeeds, since the real nonce is only
        // known inside this process's PENDING map.
        {
            let mut pending = PENDING.lock().unwrap();
            let entry = pending.get_mut(&state_token).unwrap();
            entry.nonce = "__NONCE__".to_string();
        }

        let callback_res = app.oneshot(Request::get(format!("/api/auth/oidc/callback?code=abc&state={state_token}")).body(Body::empty()).unwrap()).await.unwrap();
        // Same reasoning as the GitHub login callback test: "Sign in with
        // company IdP" is a plain <a href>, so the callback has to
        // redirect the browser back into the app, not hand back JSON.
        assert_eq!(callback_res.status(), axum::http::StatusCode::SEE_OTHER, "callback did not redirect back into the app");
        assert_eq!(callback_res.headers().get(axum::http::header::LOCATION).unwrap().to_str().unwrap(), "/");
        let cookie = callback_res.headers().get(axum::http::header::SET_COOKIE).unwrap().to_str().unwrap().to_string();
        assert!(cookie.contains(ignite_auth::SESSION_COOKIE));

        let user = state.db.get_user_by_email("oidc-user@example.com").unwrap();
        assert_eq!(user.provider, "oidc");
    }

    #[tokio::test]
    async fn login_404s_when_mode_is_not_oidc() {
        let state = test_state(ignite_config::Config::default());
        let app = oidc_router().with_state(state);
        let res = app.oneshot(Request::get("/api/auth/oidc/login").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn callback_rejects_unknown_state() {
        let mut config = ignite_config::Config::default();
        config.auth.mode = "oidc".into();
        let state = test_state(config);
        let app = oidc_router().with_state(state);
        let res = app.oneshot(Request::get("/api/auth/oidc/callback?code=x&state=unknown").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), axum::http::StatusCode::UNAUTHORIZED);
    }
}
