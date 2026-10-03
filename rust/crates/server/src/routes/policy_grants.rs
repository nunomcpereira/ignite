//! US-17: `/api/policy/grants` — list, create and revoke the org/repo-scoped
//! permission grants (`ignite_db_store::permissions`). A caller administers
//! a scope through a `policy_admin` grant covering it: a global admin
//! manages every grant, an org-wide admin manages grants inside that org, a
//! repo admin only that repo's. The first admin comes from
//! `security.policyAdmins`. Every change is audit-logged.

use crate::auth::RequireAuth;
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get};
use axum::{Json, Router};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Value};
use std::sync::Arc;

static NAME_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9._-]{1,100}$").expect("static regex"));

fn err(status: StatusCode, message: impl Into<String>, code: &str) -> Response {
    (status, Json(json!({ "ok": false, "error": message.into(), "code": code }))).into_response()
}

fn deny_restricted_key(state: &AppState, headers: &HeaderMap) -> Option<Response> {
    crate::auth::api_key_is_scope_restricted(headers, &state.db).then(|| err(StatusCode::FORBIDDEN, "A scope-restricted API key can't manage permission grants.", "scope_denied"))
}

fn administers(state: &AppState, email: &str, org: Option<&str>, repo: Option<&str>) -> bool {
    state.db.has_permission_at_scope(email, "policy_admin", org, repo)
}

async fn list_grants(State(state): State<Arc<AppState>>, RequireAuth(user): RequireAuth, headers: HeaderMap) -> Response {
    if let Some(r) = deny_restricted_key(&state, &headers) {
        return r;
    }
    let grants: Vec<_> = state.db.list_permission_grants().into_iter().filter(|g| administers(&state, &user.email, g.org.as_deref(), g.repo.as_deref())).collect();
    let is_admin = !grants.is_empty() || state.db.list_permission_grants_for_subject(&user.email).iter().any(|g| g.permission == "policy_admin");
    if !is_admin {
        return err(StatusCode::FORBIDDEN, "Only a policy admin can view permission grants.", "permission_denied");
    }
    Json(json!({ "ok": true, "grants": grants, "permissions": crate::auth::GRANT_PERMISSIONS, "enforced": state.config.security.enforce_grants })).into_response()
}

async fn create_grant(State(state): State<Arc<AppState>>, RequireAuth(user): RequireAuth, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if let Some(r) = deny_restricted_key(&state, &headers) {
        return r;
    }
    let field = |k: &str| body.get(k).and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
    let Some(subject) = field("subjectEmail").map(|e| e.to_ascii_lowercase()) else { return err(StatusCode::BAD_REQUEST, "subjectEmail is required.", "invalid_request") };
    if !ignite_auth::is_valid_email(&subject) {
        return err(StatusCode::BAD_REQUEST, "subjectEmail is not a valid email address.", "invalid_request");
    }
    let Some(permission) = field("permission") else { return err(StatusCode::BAD_REQUEST, "permission is required.", "invalid_request") };
    if !crate::auth::GRANT_PERMISSIONS.contains(&permission.as_str()) {
        return err(StatusCode::BAD_REQUEST, format!("permission must be one of {}.", crate::auth::GRANT_PERMISSIONS.join(", ")), "invalid_request");
    }
    let (org, repo) = (field("org"), field("repo"));
    if repo.is_some() && org.is_none() {
        return err(StatusCode::BAD_REQUEST, "A repository grant needs its org too.", "invalid_request");
    }
    if org.iter().chain(repo.iter()).any(|n| !NAME_RE.is_match(n)) {
        return err(StatusCode::BAD_REQUEST, "org/repo may only contain letters, digits, '.', '_' and '-'.", "invalid_request");
    }
    if !administers(&state, &user.email, org.as_deref(), repo.as_deref()) {
        return err(StatusCode::FORBIDDEN, "You don't administer grants at this scope.", "permission_denied");
    }
    state.db.grant_permission(&subject, &permission, org.as_deref(), repo.as_deref(), Some(&user.email));
    let Some(grant) = state.db.find_permission_grant(&subject, &permission, org.as_deref(), repo.as_deref()).and_then(|id| state.db.get_permission_grant(id)) else {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "The grant could not be saved.", "internal_error");
    };
    state.emit_audit_event(
        ignite_audit_log::AuditEvent::new("policy.grant_created", "warning", format!("{} granted \"{permission}\" to {subject} on {}", user.email, scope_label(org.as_deref(), repo.as_deref())))
            .actor(user.email.clone())
            .metadata(json!({ "grantId": grant.id, "subjectEmail": subject, "permission": permission, "org": org, "repo": repo })),
    );
    (StatusCode::CREATED, Json(json!({ "ok": true, "grant": grant }))).into_response()
}

async fn revoke_grant(State(state): State<Arc<AppState>>, RequireAuth(user): RequireAuth, headers: HeaderMap, Path(id): Path<i64>) -> Response {
    if let Some(r) = deny_restricted_key(&state, &headers) {
        return r;
    }
    let Some(grant) = state.db.get_permission_grant(id) else { return err(StatusCode::NOT_FOUND, "Grant not found.", "not_found") };
    if !administers(&state, &user.email, grant.org.as_deref(), grant.repo.as_deref()) {
        return err(StatusCode::FORBIDDEN, "You don't administer grants at this scope.", "permission_denied");
    }
    state.db.revoke_permission_grant(id);
    state.emit_audit_event(
        ignite_audit_log::AuditEvent::new("policy.grant_revoked", "warning", format!("{} revoked \"{}\" from {} on {}", user.email, grant.permission, grant.subject_email, scope_label(grant.org.as_deref(), grant.repo.as_deref())))
            .actor(user.email.clone())
            .metadata(json!({ "grantId": grant.id, "subjectEmail": grant.subject_email, "permission": grant.permission, "org": grant.org, "repo": grant.repo })),
    );
    Json(json!({ "ok": true, "revoked": grant.id })).into_response()
}

fn scope_label(org: Option<&str>, repo: Option<&str>) -> String {
    match (org, repo) {
        (Some(o), Some(r)) => format!("{o}/{r}"),
        (Some(o), None) => format!("{o}/*"),
        _ => "every repository".to_string(),
    }
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/policy/grants", get(list_grants).post(create_grant)).route("/api/policy/grants/:id", delete(revoke_grant))
}
