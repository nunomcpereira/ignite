//! `GET /api/audit-log` / `GET /api/audit-log/verify` — read access to the
//! local, tamper-evident audit trail (`db_store::audit_events`) built for
//! GxP/21 CFR Part 11-style onboarding cases: an auditor needs to see
//! Ignite's own governance history (scan outcomes, overrides, gate
//! decisions, webhook-driven dismissals, API key mints) without depending
//! on whether an external SIEM sink happens to be configured — see
//! `crates/db-store/src/audit_events.rs`'s doc comment for the durability/
//! hash-chaining rationale.
//!
//! `GET /api/audit-log` supports `org`, `repo`, `eventType`, `severity`,
//! `from`/`to` (`YYYY-MM-DD`, inclusive, matched against the stored UTC
//! timestamp) and cursor pagination (`cursor` = the last-seen row `id`
//! from a previous page, `limit` capped at 500). `GET
//! /api/audit-log/verify` recomputes and checks every row's hash chain,
//! surfacing the first tampered/missing row's id if the chain is broken —
//! this is the actual auditor-facing proof the local trail hasn't been
//! edited since it was written.

use crate::state::AppState;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

fn err(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(json!({ "ok": false, "error": message.into() }))).into_response()
}

#[derive(Deserialize)]
struct AuditLogQuery {
    org: Option<String>,
    repo: Option<String>,
    #[serde(rename = "eventType")]
    event_type: Option<String>,
    severity: Option<String>,
    from: Option<String>,
    to: Option<String>,
    cursor: Option<i64>,
    limit: Option<i64>,
}

fn non_empty(v: Option<String>) -> Option<String> {
    v.filter(|s| !s.trim().is_empty())
}

async fn list(State(state): State<Arc<AppState>>, crate::auth::RequireAuth(_user): crate::auth::RequireAuth, Query(query): Query<AuditLogQuery>) -> Response {
    let from_bound = match non_empty(query.from) {
        Some(d) => match chrono::NaiveDate::parse_from_str(&d, "%Y-%m-%d") {
            Ok(d) => Some(format!("{} 00:00:00", d.format("%Y-%m-%d"))),
            Err(_) => return err(StatusCode::BAD_REQUEST, format!("Invalid \"from\" date \"{d}\" — expected YYYY-MM-DD.")),
        },
        None => None,
    };
    let to_bound = match non_empty(query.to) {
        Some(d) => match chrono::NaiveDate::parse_from_str(&d, "%Y-%m-%d") {
            Ok(d) => Some(format!("{} 23:59:59", d.format("%Y-%m-%d"))),
            Err(_) => return err(StatusCode::BAD_REQUEST, format!("Invalid \"to\" date \"{d}\" — expected YYYY-MM-DD.")),
        },
        None => None,
    };
    let limit = query.limit.unwrap_or(100).clamp(1, 500);

    let org = non_empty(query.org);
    let repo = non_empty(query.repo);
    let event_type = non_empty(query.event_type);
    let severity = non_empty(query.severity);

    let events = state.db.list_audit_events(org.as_deref(), repo.as_deref(), event_type.as_deref(), severity.as_deref(), from_bound.as_deref(), to_bound.as_deref(), query.cursor, limit);
    let next_cursor = if events.len() as i64 == limit { events.last().map(|e| e.id) } else { None };

    let items: Vec<Value> = events
        .into_iter()
        .map(|e| {
            json!({
                "id": e.id,
                "eventType": e.event_type,
                "severity": e.severity,
                "summary": e.summary,
                "actor": e.actor,
                "org": e.org,
                "repo": e.repo,
                "metadata": e.metadata_json.as_deref().and_then(|m| serde_json::from_str::<Value>(m).ok()),
                "createdAt": e.created_at,
                "prevHash": e.prev_hash,
                "hash": e.hash,
            })
        })
        .collect();

    Json(json!({ "ok": true, "items": items, "nextCursor": next_cursor })).into_response()
}

async fn verify(State(state): State<Arc<AppState>>, crate::auth::RequireAuth(_user): crate::auth::RequireAuth) -> Response {
    match state.db.verify_audit_chain() {
        Ok(()) => Json(json!({ "ok": true, "intact": true })).into_response(),
        Err(broken_id) => Json(json!({ "ok": true, "intact": false, "firstBrokenId": broken_id })).into_response(),
    }
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/audit-log", get(list)).route("/api/audit-log/verify", get(verify))
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
    /// freshly created local user in `state`'s db — both endpoints in
    /// this file now require `RequireAuth`.
    fn auth_header(state: &AppState) -> String {
        let user_id = state.db.create_local_user("tester@example.com", Some("Tester"), "unused-hash").unwrap();
        let raw_key = ignite_auth::generate_api_key();
        state.db.create_api_key(user_id, &ignite_auth::hash_api_key(&raw_key), None, None, "test");
        format!("Bearer {raw_key}")
    }

    #[tokio::test]
    async fn verify_reports_intact_on_an_empty_trail() {
        let state = test_state();
        let auth = auth_header(&state);
        let app = router().with_state(state);
        let res = app.oneshot(Request::get("/api/audit-log/verify").header("authorization", &auth).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let json = body_json(res).await;
        assert_eq!(json["intact"], true);
    }

    #[tokio::test]
    async fn list_returns_recorded_events_filtered_by_org() {
        let state = test_state();
        let auth = auth_header(&state);
        state.db.record_audit_event("gate.push_rejected", "critical", "blocked push", None, Some("acme"), Some("widgets"), None).unwrap();
        state.db.record_audit_event("scan.completed", "info", "clean scan", None, Some("other"), Some("thing"), None).unwrap();

        let app = router().with_state(state);
        let res = app.oneshot(Request::get("/api/audit-log?org=acme").header("authorization", &auth).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let json = body_json(res).await;
        let items = json["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["summary"], "blocked push");
        assert!(items[0]["hash"].as_str().unwrap().len() == 64);
    }

    #[tokio::test]
    async fn list_rejects_malformed_date() {
        let state = test_state();
        let auth = auth_header(&state);
        let app = router().with_state(state);
        let res = app.oneshot(Request::get("/api/audit-log?from=not-a-date").header("authorization", &auth).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn list_requires_auth() {
        let app = router().with_state(test_state());
        let res = app.oneshot(Request::get("/api/audit-log").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }
}
