//! Dual-custody approval for critical-severity overrides
//! (`security.overrideApproval`, see that config struct's own doc
//! comment and `routes/effectivate.rs`/`routes/pipeline_interactive/run.rs`,
//! which are what actually put a row into the `pending` state this module
//! resolves).
//!
//! There's no database-backed role/permission system in Ignite (see
//! CLAUDE.md's own gap analysis) — "sufficient role" here means "a real
//! authenticated session or API key whose email appears in
//! `security.overrideApproval.approverEmails`", checked by
//! [`require_approver`] below. This is deliberately a config-driven
//! allowlist, not a new `users.role` column: adding real RBAC is a much
//! bigger schema/UI change than this feature needs to be useful.
//!
//! All three routes 404 when `security.overrideApproval.enabled` is
//! `false` — same "unconfigured means the endpoint doesn't exist" posture
//! every other opt-in feature in this codebase uses.

use crate::auth::RequireAuth;
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;
use std::sync::Arc;

fn err(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(json!({ "error": message.into() }))).into_response()
}

fn is_configured_approver(state: &AppState, email: &str) -> bool {
    state.config.security.override_approval.approver_emails.iter().any(|e| e.eq_ignore_ascii_case(email))
}

/// `Ok(())` when `security.overrideApproval` is on and `user` is on the
/// configured approver list; otherwise the `(status, message)` the route
/// handler should turn into a response immediately. A plain tuple rather
/// than a built `Response` here keeps the `Err` variant small — building
/// the actual response is cheap and left to each call site via `err(...)`.
fn require_approver(state: &AppState, user: &crate::auth::AttachedUser) -> Result<(), (StatusCode, &'static str)> {
    if !state.config.security.override_approval.enabled {
        return Err((StatusCode::NOT_FOUND, "Override approval is not enabled."));
    }
    if !is_configured_approver(state, &user.email) {
        return Err((StatusCode::FORBIDDEN, "Your account is not on the configured override-approver list."));
    }
    Ok(())
}

async fn list_pending(Path(project_id): Path<i64>, State(state): State<Arc<AppState>>, RequireAuth(user): RequireAuth) -> Response {
    if let Err((status, message)) = require_approver(&state, &user) {
        return err(status, message);
    }
    let pending = state.db.list_pending_overrides(project_id);
    Json(json!({ "ok": true, "pending": pending })).into_response()
}

async fn approve(Path((project_id, override_id)): Path<(i64, i64)>, State(state): State<Arc<AppState>>, RequireAuth(user): RequireAuth) -> Response {
    if let Err((status, message)) = require_approver(&state, &user) {
        return err(status, message);
    }
    match state.db.approve_override(project_id, override_id, &user.email) {
        Ok((project_id, issue_id)) => {
            state.db.set_issue_status(project_id, &issue_id, "overridden");
            state.emit_audit_event(ignite_audit_log::AuditEvent::new("override.approved_by_reviewer", "info", format!("critical override for issue {issue_id} approved")).actor(user.email.clone()).metadata(json!({ "issueId": issue_id, "overrideId": override_id, "projectId": project_id })));
            Json(json!({ "ok": true, "issueId": issue_id })).into_response()
        }
        Err(e) => err(status_for_override_error(&e), e),
    }
}

async fn reject(Path((project_id, override_id)): Path<(i64, i64)>, State(state): State<Arc<AppState>>, RequireAuth(user): RequireAuth) -> Response {
    if let Err((status, message)) = require_approver(&state, &user) {
        return err(status, message);
    }
    match state.db.reject_override(project_id, override_id, &user.email) {
        Ok((project_id, issue_id)) => {
            state.emit_audit_event(ignite_audit_log::AuditEvent::new("override.rejected_by_reviewer", "warning", format!("critical override for issue {issue_id} rejected")).actor(user.email.clone()).metadata(json!({ "issueId": issue_id, "overrideId": override_id, "projectId": project_id })));
            Json(json!({ "ok": true, "issueId": issue_id })).into_response()
        }
        Err(e) => err(status_for_override_error(&e), e),
    }
}

/// "Not found" (unknown id, or an id that belongs to a different
/// project) is a 404; every other `approve_override`/`reject_override`
/// failure (already decided, self-approval) is a 409 — the request was
/// understood and reached a real row, it's just not actionable right now.
fn status_for_override_error(message: &str) -> StatusCode {
    if message.contains("not found") {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::CONFLICT
    }
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/projects/:projectId/overrides/pending", get(list_pending))
        .route("/api/projects/:projectId/overrides/:overrideId/approve", post(approve))
        .route("/api/projects/:projectId/overrides/:overrideId/reject", post(reject))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state_with_config(config: ignite_config::Config) -> Arc<AppState> {
        let db_dir = tempfile::tempdir().unwrap();
        let db = ignite_db_store::DbStore::open(&db_dir.path().join("test.db")).unwrap();
        std::mem::forget(db_dir);
        Arc::new(AppState {
            runner: crate::state::default_runner(),
            db,
            running_runs: parking_lot::Mutex::new(std::collections::HashMap::new()),
            pending_effectivations: parking_lot::Mutex::new(std::collections::HashMap::new()),
            review_gate: crate::review_gate::ReviewGate::default(),
            llm_config: crate::state::default_llm_config(),
            config,
            package_hallucination_checker: crate::state::default_package_hallucination_checker(),
            fix_pr_previews: parking_lot::Mutex::new(std::collections::HashMap::new()),
            audit_http: reqwest::Client::new(),
        })
    }

    fn user(email: &str) -> crate::auth::AttachedUser {
        crate::auth::AttachedUser { id: 1, email: email.to_string(), name: None, provider: "local".to_string() }
    }

    #[test]
    fn require_approver_404s_when_feature_disabled() {
        let mut config = ignite_config::Config::default();
        config.security.override_approval.enabled = false;
        config.security.override_approval.approver_emails = vec!["admin@acme.example".to_string()];
        let state = state_with_config(config);
        let (status, _) = require_approver(&state, &user("admin@acme.example")).unwrap_err();
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn require_approver_403s_for_a_user_not_on_the_allowlist() {
        let mut config = ignite_config::Config::default();
        config.security.override_approval.enabled = true;
        config.security.override_approval.approver_emails = vec!["admin@acme.example".to_string()];
        let state = state_with_config(config);
        let (status, _) = require_approver(&state, &user("someone-else@acme.example")).unwrap_err();
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn require_approver_ok_for_an_allowlisted_email_case_insensitively() {
        let mut config = ignite_config::Config::default();
        config.security.override_approval.enabled = true;
        config.security.override_approval.approver_emails = vec!["Admin@Acme.example".to_string()];
        let state = state_with_config(config);
        assert!(require_approver(&state, &user("admin@acme.example")).is_ok());
    }

    #[tokio::test]
    async fn approve_flips_issue_status_and_rejects_wrong_project() {
        let mut config = ignite_config::Config::default();
        config.security.override_approval.enabled = true;
        config.security.override_approval.approver_emails = vec!["approver@acme.example".to_string()];
        let state = state_with_config(config);
        let project_id = state.db.create_project("job-1", "acme", "widgets", false, "ui", None);
        state.db.replace_project_issues(
            project_id,
            &[ignite_db_store::IssueInput { id: "secret::a.js::1".into(), phase: Some(4), category: "secret".into(), severity: "error".into(), score: Some(10), summary: "hardcoded key".into(), file: Some("a.js".into()), line: Some(1), snippet: None, cross_file: false, chain: None, cwe: None, owasp: None, tool: None, references: None, duplicate_ref: None }],
            &std::collections::HashSet::new(),
        );
        let override_id = state.db.add_pending_override(ignite_db_store::AddOverrideArgs { project_id, job_id: "job-1", phase: 4, issue_id: "secret::a.js::1", category: "secret", severity: "error", summary: "hardcoded key", file: Some("a.js"), line: Some(1), justification: "under review", actor_email: "submitter@acme.example", actor_name: None, email_sent: false });

        let resp = approve(Path((project_id, override_id)), State(state.clone()), RequireAuth(user("approver@acme.example"))).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let issues = state.db.get_project_issues(project_id);
        assert_eq!(issues[0].status, "overridden");

        let other_project = state.db.create_project("job-2", "acme", "gadgets", false, "ui", None);
        let resp2 = approve(Path((other_project, override_id)), State(state.clone()), RequireAuth(user("approver@acme.example"))).await;
        assert_eq!(resp2.status(), StatusCode::NOT_FOUND);
    }
}
