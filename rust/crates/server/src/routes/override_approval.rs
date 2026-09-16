//! Dual-custody approval for critical-severity overrides
//! (`security.overrideApproval`, see that config struct's own doc
//! comment and `routes/effectivate.rs`/`routes/pipeline_interactive/run.rs`,
//! which are what actually put a row into the `pending` state this module
//! resolves).
//!
//! US-08: "sufficient role" here means "a real authenticated session or
//! API key whose email either appears in
//! `security.overrideApproval.approverEmails` (the original, still-
//! supported global allowlist — kept for backward compatibility; startup
//! also mirrors it into an equivalent global `review`
//! [`ignite_db_store::DbStore::grant_permission`], see `main.rs`) or
//! holds an explicit `review` permission grant scoped globally, to the
//! project's org, or to the project's exact org/repo", checked by
//! [`require_approver`] below. The grant model
//! (`ignite_db_store::permissions`) is deliberately narrow — no
//! `users.role` column, no team/group concept, just per-(subject, org?,
//! repo?) grants — but it's real and queryable, unlike a config-only
//! allowlist, and lets an org scope a reviewer to just the repositories
//! they actually own instead of every project in the deployment.
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

/// `Ok(())` when `security.overrideApproval` is on and `user` is
/// authorized to review overrides for `project_id` — either via the
/// legacy global config allowlist or an explicit `review` permission
/// grant scoped globally, to the project's org, or to its exact org/repo;
/// otherwise the `(status, message)` the route handler should turn into a
/// response immediately. A plain tuple rather than a built `Response`
/// here keeps the `Err` variant small — building the actual response is
/// cheap and left to each call site via `err(...)`.
fn require_approver(state: &AppState, user: &crate::auth::AttachedUser, project_id: i64) -> Result<(), (StatusCode, &'static str)> {
    if !state.config.security.override_approval.enabled {
        return Err((StatusCode::NOT_FOUND, "Override approval is not enabled."));
    }
    if is_configured_approver(state, &user.email) {
        return Ok(());
    }
    let (org, repo) = state.db.get_project(project_id).map(|p| (p.org, p.repo)).unwrap_or_default();
    if state.db.has_permission(&user.email, "review", &org, &repo) {
        return Ok(());
    }
    Err((StatusCode::FORBIDDEN, "Your account is not authorized to review overrides for this project."))
}

async fn list_pending(Path(project_id): Path<i64>, State(state): State<Arc<AppState>>, RequireAuth(user): RequireAuth) -> Response {
    if let Err((status, message)) = require_approver(&state, &user, project_id) {
        return err(status, message);
    }
    let pending = state.db.list_pending_overrides(project_id);
    Json(json!({ "ok": true, "pending": pending })).into_response()
}

async fn approve(Path((project_id, override_id)): Path<(i64, i64)>, State(state): State<Arc<AppState>>, RequireAuth(user): RequireAuth) -> Response {
    if let Err((status, message)) = require_approver(&state, &user, project_id) {
        return err(status, message);
    }
    match state.db.approve_override(project_id, override_id, &user.email) {
        Ok((project_id, issue_id)) => {
            state.db.set_issue_status(project_id, &issue_id, "overridden");
            let mut event = ignite_audit_log::AuditEvent::new("override.approved_by_reviewer", "info", format!("critical override for issue {issue_id} approved")).actor(user.email.clone()).metadata(json!({ "issueId": issue_id, "overrideId": override_id, "projectId": project_id }));
            if let Some(project) = state.db.get_project(project_id) {
                event = event.repo(&project.org, &project.repo);
            }
            state.emit_audit_event(event);
            Json(json!({ "ok": true, "issueId": issue_id })).into_response()
        }
        Err(e) => err(status_for_override_error(&e), e),
    }
}

async fn reject(Path((project_id, override_id)): Path<(i64, i64)>, State(state): State<Arc<AppState>>, RequireAuth(user): RequireAuth) -> Response {
    if let Err((status, message)) = require_approver(&state, &user, project_id) {
        return err(status, message);
    }
    match state.db.reject_override(project_id, override_id, &user.email) {
        Ok((project_id, issue_id)) => {
            let mut event = ignite_audit_log::AuditEvent::new("override.rejected_by_reviewer", "warning", format!("critical override for issue {issue_id} rejected")).actor(user.email.clone()).metadata(json!({ "issueId": issue_id, "overrideId": override_id, "projectId": project_id }));
            if let Some(project) = state.db.get_project(project_id) {
                event = event.repo(&project.org, &project.repo);
            }
            state.emit_audit_event(event);
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

    /// Returns the `TempDir` guard alongside the state — the caller must
    /// keep it alive for as long as `state` is in use (its `Drop` deletes
    /// the backing directory the SQLite file lives in).
    fn state_with_config(config: ignite_config::Config) -> (Arc<AppState>, tempfile::TempDir) {
        let db_dir = tempfile::tempdir().unwrap();
        let db = ignite_db_store::DbStore::open(&db_dir.path().join("test.db")).unwrap();
        let state = Arc::new(AppState {
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
        });
        (state, db_dir)
    }

    fn user(email: &str) -> crate::auth::AttachedUser {
        crate::auth::AttachedUser { id: 1, email: email.to_string(), name: None, provider: "local".to_string() }
    }

    #[test]
    fn require_approver_404s_when_feature_disabled() {
        let mut config = ignite_config::Config::default();
        config.security.override_approval.enabled = false;
        config.security.override_approval.approver_emails = vec!["admin@acme.example".to_string()];
        let (state, _db_dir) = state_with_config(config);
        let (status, _) = require_approver(&state, &user("admin@acme.example"), 1).unwrap_err();
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn require_approver_403s_for_a_user_not_on_the_allowlist() {
        let mut config = ignite_config::Config::default();
        config.security.override_approval.enabled = true;
        config.security.override_approval.approver_emails = vec!["admin@acme.example".to_string()];
        let (state, _db_dir) = state_with_config(config);
        let (status, _) = require_approver(&state, &user("someone-else@acme.example"), 1).unwrap_err();
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn require_approver_ok_for_an_allowlisted_email_case_insensitively() {
        let mut config = ignite_config::Config::default();
        config.security.override_approval.enabled = true;
        config.security.override_approval.approver_emails = vec!["Admin@Acme.example".to_string()];
        let (state, _db_dir) = state_with_config(config);
        assert!(require_approver(&state, &user("admin@acme.example"), 1).is_ok());
    }

    #[test]
    fn require_approver_ok_for_a_repo_scoped_grant_holder() {
        let mut config = ignite_config::Config::default();
        config.security.override_approval.enabled = true;
        let (state, _db_dir) = state_with_config(config);
        let project_id = state.db.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        state.db.grant_permission("reviewer@acme.example", "review", Some("acme"), Some("widgets"), None);
        assert!(require_approver(&state, &user("reviewer@acme.example"), project_id).is_ok());

        let other_project = state.db.create_project("job-2", "acme", "gadgets", false, "ui", None).unwrap();
        let (status, _) = require_approver(&state, &user("reviewer@acme.example"), other_project).unwrap_err();
        assert_eq!(status, StatusCode::FORBIDDEN, "a repo-scoped grant must not authorize a sibling repository");
    }

    #[tokio::test]
    async fn approve_flips_issue_status_and_rejects_wrong_project() {
        let mut config = ignite_config::Config::default();
        config.security.override_approval.enabled = true;
        config.security.override_approval.approver_emails = vec!["approver@acme.example".to_string()];
        let (state, _db_dir) = state_with_config(config);
        let project_id = state.db.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
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

        let other_project = state.db.create_project("job-2", "acme", "gadgets", false, "ui", None).unwrap();
        let resp2 = approve(Path((other_project, override_id)), State(state.clone()), RequireAuth(user("approver@acme.example"))).await;
        assert_eq!(resp2.status(), StatusCode::NOT_FOUND);
    }
}
