//! End-to-end GitHub App token exchange against a local stand-in for the
//! GitHub API: JWT signed with the App key, installation lookup, token mint,
//! caching, and the "not installed" fallback.
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use ignite_github_api::GithubAppAuth;
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

struct Fake {
    public_pem: String,
    mints: AtomicUsize,
}

fn verify(state: &Fake, headers: &HeaderMap) -> bool {
    let Some(token) = headers.get("authorization").and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")) else { return false };
    let key = jsonwebtoken::DecodingKey::from_rsa_pem(state.public_pem.as_bytes()).unwrap();
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_required_spec_claims(&["exp", "iat", "iss"]);
    validation.set_issuer(&["4242"]);
    jsonwebtoken::decode::<Value>(token, &key, &validation).is_ok()
}

async fn org_installation(State(s): State<Arc<Fake>>, headers: HeaderMap, Path(org): Path<String>) -> (StatusCode, Json<Value>) {
    if !verify(&s, &headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "message": "bad jwt" })));
    }
    if org.eq_ignore_ascii_case("acme") { (StatusCode::OK, Json(json!({ "id": 77 }))) } else { (StatusCode::NOT_FOUND, Json(json!({ "message": "Not Found" }))) }
}

async fn user_installation() -> (StatusCode, Json<Value>) {
    (StatusCode::NOT_FOUND, Json(json!({ "message": "Not Found" })))
}

async fn mint(State(s): State<Arc<Fake>>, headers: HeaderMap, Path(id): Path<u64>) -> (StatusCode, Json<Value>) {
    if !verify(&s, &headers) || id != 77 {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "message": "bad jwt" })));
    }
    let n = s.mints.fetch_add(1, Ordering::SeqCst);
    (StatusCode::CREATED, Json(json!({ "token": format!("ghs_test{n}"), "expires_at": "2999-01-01T00:00:00Z" })))
}

#[tokio::test(flavor = "multi_thread")]
async fn mints_caches_and_falls_back_when_not_installed() {
    let private = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
    let private_pem = private.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF).unwrap();
    let public_pem = rsa::RsaPublicKey::from(&private).to_pkcs1_pem(rsa::pkcs1::LineEnding::LF).unwrap();
    let fake = Arc::new(Fake { public_pem, mints: AtomicUsize::new(0) });
    let app = Router::new()
        .route("/orgs/:org/installation", get(org_installation))
        .route("/users/:user/installation", get(user_installation))
        .route("/app/installations/:id/access_tokens", post(mint))
        .with_state(fake.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let auth = GithubAppAuth::new("4242", private_pem.as_bytes()).unwrap().with_api_base(&base);
    assert_eq!(auth.installation_token("ACME").await.unwrap().as_deref(), Some("ghs_test0"));
    assert_eq!(auth.installation_token("acme").await.unwrap().as_deref(), Some("ghs_test0"), "cached, not re-minted");
    assert_eq!(fake.mints.load(Ordering::SeqCst), 1);
    assert_eq!(auth.installation_token("other-org").await.unwrap(), None, "not installed there");

    auth.clear_cache();
    assert_eq!(auth.installation_token("acme").await.unwrap().as_deref(), Some("ghs_test1"));
}
