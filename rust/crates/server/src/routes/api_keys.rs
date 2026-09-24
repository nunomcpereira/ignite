//! `/api/auth/api-keys` — self-service API keys, so a signed-in person can
//! mint a key for the VS Code extension/CLI/CI from the UI instead of an
//! operator running the `create-api-key` binary on the server host.
//!
//! Every route requires a **browser session**, not an API key: a leaked key
//! must not be able to mint fresh, independently-revocable keys for itself.
//! A key minted here is always for the session's own user, carries the same
//! optional scopes model as `create-api-key --scopes`, and is shown exactly
//! once (only its hash is stored).

use crate::auth::{resolve_auth_method, resolve_user, AttachedUser, AuthMethod};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::sync::Arc;

const MAX_LABEL_LEN: usize = 80;
/// Keys minted here are always short-lived: one of these lifetimes (days),
/// defaulting to [`DEFAULT_EXPIRY_DAYS`]. Revoking ends one sooner.
/// (`create-api-key` on the server host can still mint a non-expiring key
/// for CI, deliberately — that's an operator's call, not self-service.)
const ALLOWED_EXPIRY_DAYS: &[i64] = &[1, 7, 30, 90];
const DEFAULT_EXPIRY_DAYS: i64 = 30;

fn require_session_user(headers: &HeaderMap, state: &AppState) -> Result<AttachedUser, Response> {
    if resolve_auth_method(headers, &state.db) != AuthMethod::Session {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Sign in with your Ignite account to manage API keys — an API key can't create or revoke keys.", "code": "session_required" })),
        )
            .into_response());
    }
    resolve_user(headers, &state.db).ok_or_else(|| (StatusCode::UNAUTHORIZED, Json(json!({ "error": "Authentication required." }))).into_response())
}

async fn list_keys(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let user = match require_session_user(&headers, &state) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let keys: Vec<Value> = state
        .db
        .list_api_keys_for_user(user.id)
        .into_iter()
        .map(|k| {
            json!({
                "id": k.id,
                "label": k.label,
                "createdAt": k.created_at,
                "createdVia": k.created_via,
                "lastUsedAt": k.last_used_at,
                "revokedAt": k.revoked_at,
                "expiresAt": k.expires_at,
                "expired": k.expired,
                "active": k.revoked_at.is_none() && !k.expired,
            })
        })
        .collect();
    Json(json!({ "keys": keys })).into_response()
}

async fn create_key(State(state): State<Arc<AppState>>, headers: HeaderMap, body: Option<Json<Value>>) -> Response {
    let user = match require_session_user(&headers, &state) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let body = body.map(|Json(v)| v).unwrap_or(Value::Null);
    let label: Option<String> = body
        .get("label")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().chars().filter(|c| !c.is_control()).take(MAX_LABEL_LEN).collect::<String>())
        .filter(|s| !s.is_empty());
    let scopes = match body.get("scopes") {
        None | Some(Value::Null) => None,
        Some(Value::String(raw)) => match ignite_db_store::parse_api_key_scopes(raw) {
            Ok(s) => Some(s),
            Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))).into_response(),
        },
        Some(Value::Array(items)) => {
            let joined = items.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(",");
            match ignite_db_store::parse_api_key_scopes(&joined) {
                Ok(s) => Some(s),
                Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))).into_response(),
            }
        }
        Some(_) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": "scopes must be a comma-separated string or an array of strings." }))).into_response(),
    };
    let expiry_days = match body.get("expiresInDays") {
        None | Some(Value::Null) => DEFAULT_EXPIRY_DAYS,
        Some(v) => match v.as_i64().filter(|d| ALLOWED_EXPIRY_DAYS.contains(d)) {
            Some(d) => d,
            None => return (StatusCode::BAD_REQUEST, Json(json!({ "error": format!("expiresInDays must be one of {ALLOWED_EXPIRY_DAYS:?}.") }))).into_response(),
        },
    };
    // Which client asked (extension/web UI) — informational only, from a fixed set.
    let created_via = match body.get("client").and_then(|v| v.as_str()) {
        Some("vscode") => "vscode",
        _ => "ui",
    };

    let raw_key = ignite_auth::generate_api_key();
    let hash = ignite_auth::hash_api_key(&raw_key);
    let id = state.db.create_api_key(user.id, &hash, label.as_deref(), Some(&user.email), created_via);
    if let Some(scopes) = scopes.as_deref() {
        state.db.set_api_key_scopes(id, Some(scopes));
    }
    state.db.set_api_key_expiry_days(id, expiry_days);
    let expires_at = state.db.list_api_keys_for_user(user.id).into_iter().find(|k| k.id == id).and_then(|k| k.expires_at);
    state.emit_audit_event(
        ignite_audit_log::AuditEvent::new("api_key.created", "warning", format!("API key created for {} via {created_via}", user.email))
            .actor(user.email.clone())
            .metadata(json!({ "apiKeyId": id, "label": label, "scopes": scopes, "createdVia": created_via, "expiresInDays": expiry_days })),
    );
    (
        StatusCode::CREATED,
        Json(json!({ "id": id, "key": raw_key, "label": label, "scopes": scopes, "expiresAt": expires_at, "expiresInDays": expiry_days, "user": { "email": user.email, "name": user.name } })),
    )
        .into_response()
}

async fn revoke_key(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<i64>) -> Response {
    let user = match require_session_user(&headers, &state) {
        Ok(u) => u,
        Err(r) => return r,
    };
    if !state.db.revoke_api_key(id, user.id) {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": "No active API key with that id for your account." }))).into_response();
    }
    state.emit_audit_event(
        ignite_audit_log::AuditEvent::new("api_key.revoked", "info", format!("API key {id} revoked by {}", user.email))
            .actor(user.email.clone())
            .metadata(json!({ "apiKeyId": id })),
    );
    Json(json!({ "ok": true, "id": id })).into_response()
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/auth/api-keys", get(list_keys).post(create_key))
        .route("/api/auth/api-keys/:id", delete(revoke_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn app() -> Router {
        let db_dir = tempfile::tempdir().unwrap();
        let db = ignite_db_store::DbStore::open(&db_dir.path().join("test.db")).unwrap();
        Box::leak(Box::new(db_dir));
        let state = Arc::new(crate::state::test_state(db, ignite_config::Config::default()));
        router().merge(crate::auth::router()).with_state(state)
    }

    async fn json_body(res: Response) -> Value {
        let bytes = axum::body::to_bytes(res.into_body(), 1024 * 1024).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn session_cookie(app: &Router, email: &str) -> String {
        let res = app
            .clone()
            .oneshot(
                Request::post("/api/auth/register")
                    .header("content-type", "application/json")
                    .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 0))))
                    .body(Body::from(json!({ "email": email, "name": "Dev", "password": "correct horse battery" }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
        res.headers().get(axum::http::header::SET_COOKIE).unwrap().to_str().unwrap().split(';').next().unwrap().to_string()
    }

    async fn create(app: &Router, auth: (&str, &str), body: Value) -> Response {
        app.clone()
            .oneshot(
                Request::post("/api/auth/api-keys")
                    .header("content-type", "application/json")
                    .header(auth.0, auth.1)
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_session_can_mint_a_key_that_then_authenticates() {
        let app = app();
        let cookie = session_cookie(&app, "keys@example.com").await;
        let res = create(&app, ("cookie", &cookie), json!({ "label": "vscode", "client": "vscode" })).await;
        assert_eq!(res.status(), StatusCode::CREATED);
        let body = json_body(res).await;
        let key = body["key"].as_str().unwrap().to_string();
        assert!(key.starts_with("ignite_"));

        let me = app
            .clone()
            .oneshot(Request::get("/api/auth/me").header("authorization", format!("Bearer {key}")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(json_body(me).await["user"]["email"], "keys@example.com");

        let list = app.clone().oneshot(Request::get("/api/auth/api-keys").header("cookie", &cookie).body(Body::empty()).unwrap()).await.unwrap();
        let list = json_body(list).await;
        assert_eq!(list["keys"][0]["label"], "vscode");
        assert_eq!(list["keys"][0]["createdVia"], "vscode");
        assert!(list["keys"][0].get("key").is_none(), "the raw key must never be listed again");
    }

    #[tokio::test]
    async fn an_api_key_cannot_mint_or_list_keys() {
        let app = app();
        let cookie = session_cookie(&app, "nokeys@example.com").await;
        let key = json_body(create(&app, ("cookie", &cookie), json!({})).await).await["key"].as_str().unwrap().to_string();

        let res = create(&app, ("authorization", &format!("Bearer {key}")), json!({})).await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(json_body(res).await["code"], "session_required");

        let res = app.oneshot(Request::get("/api/auth/api-keys").header("authorization", format!("Bearer {key}")).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn keys_are_short_lived_by_default_and_only_accept_allowed_lifetimes() {
        let app = app();
        let cookie = session_cookie(&app, "expiry@example.com").await;
        let body = json_body(create(&app, ("cookie", &cookie), json!({})).await).await;
        assert_eq!(body["expiresInDays"], 30);
        assert!(body["expiresAt"].as_str().is_some_and(|s| !s.is_empty()));

        let week = json_body(create(&app, ("cookie", &cookie), json!({ "expiresInDays": 7 })).await).await;
        assert_eq!(week["expiresInDays"], 7);

        for bad in [json!(0), json!(365), json!("30")] {
            let res = create(&app, ("cookie", &cookie), json!({ "expiresInDays": bad })).await;
            assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{bad} should be rejected");
        }

        let list = app.clone().oneshot(Request::get("/api/auth/api-keys").header("cookie", &cookie).body(Body::empty()).unwrap()).await.unwrap();
        let list = json_body(list).await;
        assert!(list["keys"].as_array().unwrap().iter().all(|k| k["expiresAt"].is_string() && k["active"] == true));
    }

    #[tokio::test]
    async fn an_expired_key_stops_authenticating_and_is_listed_as_expired() {
        let db_dir = tempfile::tempdir().unwrap();
        let db = ignite_db_store::DbStore::open(&db_dir.path().join("test.db")).unwrap();
        let state = Arc::new(crate::state::test_state(db, ignite_config::Config::default()));
        let app = router().merge(crate::auth::router()).with_state(state.clone());
        let cookie = session_cookie(&app, "expired@example.com").await;
        let body = json_body(create(&app, ("cookie", &cookie), json!({ "expiresInDays": 1 })).await).await;
        let (id, key) = (body["id"].as_i64().unwrap(), body["key"].as_str().unwrap().to_string());

        // Push it into the past, as if a day had gone by.
        state.db.set_api_key_expiry_days(id, -1);

        let me = app.clone().oneshot(Request::get("/api/auth/me").header("authorization", format!("Bearer {key}")).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(json_body(me).await["user"], Value::Null);
        let list = json_body(app.oneshot(Request::get("/api/auth/api-keys").header("cookie", &cookie).body(Body::empty()).unwrap()).await.unwrap()).await;
        assert_eq!(list["keys"][0]["expired"], true);
        assert_eq!(list["keys"][0]["active"], false);
    }

    #[tokio::test]
    async fn unknown_scopes_are_rejected() {
        let app = app();
        let cookie = session_cookie(&app, "scopes@example.com").await;
        let res = create(&app, ("cookie", &cookie), json!({ "scopes": "scan,publsh" })).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_revoked_key_stops_authenticating_and_others_cannot_revoke_it() {
        let app = app();
        let owner = session_cookie(&app, "owner@example.com").await;
        let other = session_cookie(&app, "other@example.com").await;
        let body = json_body(create(&app, ("cookie", &owner), json!({})).await).await;
        let (id, key) = (body["id"].as_i64().unwrap(), body["key"].as_str().unwrap().to_string());

        let res = app.clone().oneshot(Request::delete(format!("/api/auth/api-keys/{id}")).header("cookie", &other).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        let res = app.clone().oneshot(Request::delete(format!("/api/auth/api-keys/{id}")).header("cookie", &owner).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let me = app.oneshot(Request::get("/api/auth/me").header("authorization", format!("Bearer {key}")).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(json_body(me).await["user"], Value::Null);
    }
}
