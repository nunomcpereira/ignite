//! `POST /api/pipeline/:jobId/overrides` and `POST /api/projects/:projectId/overrides`
//! — justify (override) one or more already-persisted issues *outside* a
//! live run: the "Flagged issues" popup's own justify action
//! (`issuesViewModal` in `public/index.html`), for a project that never
//! pauses at an interactive review gate at all (`validate-all`, `onboard`,
//! `scheduled-rescan`, org-repo scans) or whose review gate has already
//! closed. Reuses the same `validate_overrides`/dual-custody/`add_override`
//! machinery `routes/effectivate.rs` already uses for a live run's own
//! override submission — this is that same justification action, just
//! triggered from a read-only findings view instead of the review gate.
//!
//! Requires a real authenticated session (`RequireAuth`), same posture as
//! `effectivate.rs`: an override recorded here is a real audit-log entry
//! attributing a security decision to a person, and — unlike
//! `review-decision`'s narrow unauthenticated-simulation carve-out — a
//! historical/org-scan project has no "this run itself started
//! unauthenticated" context to fall back on.

use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use ignite_db_store::IssueRow;
use ignite_override_engine::{is_critical_score, partition_for_dual_custody, validate_overrides, Issue, Severity, SubmittedOverride};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::Arc;

fn issue_row_to_issue(r: &IssueRow) -> Issue {
    Issue {
        id: r.id.clone(),
        category: r.category.clone(),
        severity: if r.severity == "error" { Severity::Error } else { Severity::Warning },
        score: i32::try_from(r.score.unwrap_or(0)).unwrap_or(i32::MAX),
        summary: r.summary.clone(),
        file: r.file.clone(),
        line: r.line,
        snippet: r.snippet.clone(),
        cross_file: r.cross_file,
        chain: r.chain.clone(),
        duplicate_ref: None,
        cwe: r.cwe.clone(),
        owasp: r.owasp.clone(),
        tool: r.tool.clone(),
        references: r.references.as_ref().and_then(|v| serde_json::from_value(v.clone()).ok()).unwrap_or_default(),
    }
}

fn issues_json(rows: &[IssueRow]) -> Vec<Value> {
    rows.iter()
        .map(|r| {
            serde_json::to_value(r).unwrap_or_else(|e| {
                tracing::warn!(issue_id = %r.id, error = %e, "failed to serialize issue row, dropping to null");
                Value::Null
            })
        })
        .collect()
}

async fn add_overrides(project_id: i64, job_id: String, state: Arc<AppState>, user: crate::auth::AttachedUser, origin: &'static str, body: Value) -> Response {
    let Some(project) = state.db.get_project(project_id) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": "Unknown project." }))).into_response();
    };

    let issue_rows = state.db.get_project_issues(project_id);
    let still_open: Vec<Issue> = issue_rows.iter().filter(|r| r.status != "overridden").map(issue_row_to_issue).collect();
    let requested: Vec<SubmittedOverride> = body
        .get("overrides")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .map(|o| SubmittedOverride {
                    issue_id: o.get("issueId").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    justification: o.get("justification").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    code: o.get("code").and_then(|v| v.as_str()).map(|s| s.to_string()),
                })
                .collect()
        })
        .unwrap_or_default();
    if requested.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "No overrides submitted." }))).into_response();
    }

    let result = validate_overrides(&still_open, &requested);
    let applied: Vec<(&Issue, String)> = result.applied.iter().map(|(i, j)| (*i, j.clone())).collect();
    if applied.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "None of the submitted overrides matched a still-open issue on this project.", "issues": issues_json(&issue_rows) }))).into_response();
    }

    let actor_email = user.email.clone();
    let actor_name = user.name.clone().unwrap_or_else(|| user.email.clone());

    let (auto_apply, needs_approval): (Vec<_>, Vec<_>) = if state.config.security.override_approval.enabled {
        let already_approved: HashSet<String> = applied.iter().filter(|(i, _)| state.db.has_approved_override(project_id, &i.id)).map(|(i, _)| i.id.clone()).collect();
        partition_for_dual_custody(applied.clone(), |i| is_critical_score(i.score), &already_approved)
    } else {
        (applied.clone(), Vec::new())
    };

    for (issue, justification) in &needs_approval {
        if state.db.has_pending_override(project_id, &issue.id) {
            continue;
        }
        state.db.add_pending_override_with_origin(ignite_db_store::AddOverrideArgs {
            project_id,
            job_id: &job_id,
            phase: 4,
            issue_id: &issue.id,
            category: &issue.category,
            severity: match issue.severity {
                Severity::Error => "error",
                Severity::Warning => "warning",
            },
            summary: &issue.summary,
            file: issue.file.as_deref(),
            line: issue.line,
            justification,
            actor_email: &actor_email,
            actor_name: Some(&actor_name),
            email_sent: false,
        }, origin);
        state.emit_audit_event(
            ignite_audit_log::AuditEvent::new("override.pending_approval", "warning", format!("critical override for {}: {} awaiting a second reviewer's approval", issue.category, issue.summary))
                .actor(actor_email.clone())
                .repo(&project.org, &project.repo)
                .metadata(json!({ "issueId": issue.id, "category": issue.category, "justification": justification, "origin": origin })),
        );
    }

    if !auto_apply.is_empty() {
        let overrides: Vec<ignite_notifications::AppliedOverride> = auto_apply
            .iter()
            .map(|(issue, justification)| ignite_notifications::AppliedOverride {
                issue: ignite_notifications::IssueLike {
                    severity: match issue.severity {
                        Severity::Error => "error",
                        Severity::Warning => "warning",
                    },
                    category: &issue.category,
                    file: issue.file.as_deref(),
                    line: issue.line,
                    summary: &issue.summary,
                },
                justification: justification.as_str(),
            })
            .collect();
        let phase_meta = super::phase_meta::resolve_phase_meta(&state.config);
        let titles = ignite_notifications::phase_titles_map(&phase_meta.iter().map(|p| (p.id, p.title.clone())).collect::<Vec<_>>());
        let details = ignite_notifications::OverrideEmailDetails {
            job_id: &job_id,
            org: &project.org,
            repo: &project.repo,
            phase: 4,
            actor: ignite_notifications::Actor { name: Some(&actor_name), email: &actor_email },
            applied: &overrides,
        };
        let email_sent = ignite_notifications::send_override_notification(&state.config.notifications, &titles, &details).await.map(|r| r.sent).unwrap_or(false);

        for (issue, justification) in &auto_apply {
            state.db.add_override_with_origin(ignite_db_store::AddOverrideArgs {
                project_id,
                job_id: &job_id,
                phase: 4,
                issue_id: &issue.id,
                category: &issue.category,
                severity: match issue.severity {
                    Severity::Error => "error",
                    Severity::Warning => "warning",
                },
                summary: &issue.summary,
                file: issue.file.as_deref(),
                line: issue.line,
                justification,
                actor_email: &actor_email,
                actor_name: Some(&actor_name),
                email_sent,
            }, origin);
            state.db.set_issue_status(project_id, &issue.id, "overridden");
            state.emit_audit_event(
                ignite_audit_log::AuditEvent::new("override.approved", "info", format!("override approved for {}: {}", issue.category, issue.summary))
                    .actor(actor_email.clone())
                    .repo(&project.org, &project.repo)
                    .metadata(json!({ "issueId": issue.id, "category": issue.category, "justification": justification, "origin": origin })),
            );
        }
    }

    let updated_rows = state.db.get_project_issues(project_id);
    Json(json!({
        "ok": true,
        "appliedCount": auto_apply.len(),
        "pendingApprovalCount": needs_approval.len(),
        "pendingApproval": !needs_approval.is_empty(),
        "issues": issues_json(&updated_rows),
    }))
    .into_response()
}

async fn add_overrides_by_project(Path(project_id): Path<i64>, State(state): State<Arc<AppState>>, crate::auth::RequireAuth(user): crate::auth::RequireAuth, headers: axum::http::HeaderMap, Json(body): Json<Value>) -> Response {
    if let Err((status, denied)) = crate::auth::require_scope(&headers, &state.db, crate::auth::Scope::Override) {
        return (status, Json(denied)).into_response();
    }
    let origin = crate::auth::resolve_auth_method(&headers, &state.db).origin();
    add_overrides(project_id, format!("override-{project_id}"), state, user, origin, body).await
}

async fn add_overrides_by_job(Path(job_id): Path<String>, State(state): State<Arc<AppState>>, crate::auth::RequireAuth(user): crate::auth::RequireAuth, headers: axum::http::HeaderMap, Json(body): Json<Value>) -> Response {
    if let Err((status, denied)) = crate::auth::require_scope(&headers, &state.db, crate::auth::Scope::Override) {
        return (status, Json(denied)).into_response();
    }
    let origin = crate::auth::resolve_auth_method(&headers, &state.db).origin();
    let Some(project_id) = state.db.get_project_id_by_job_id(&job_id) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": "Unknown job id." }))).into_response();
    };
    add_overrides(project_id, job_id, state, user, origin, body).await
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/projects/:projectId/overrides", post(add_overrides_by_project))
        .route("/api/pipeline/:jobId/overrides", post(add_overrides_by_job))
}

#[cfg(test)]
mod characterization {
    //! Pins how an override submission behaves end to end today (validation,
    //! dual-custody, persistence, issue status, audit trail, origin). The same
    //! sequence is hand-copied in the validate-all, onboard, interactive and
    //! effectivate paths; consolidating them must keep every assertion here true.
    use super::*;
    use crate::state;
    use ignite_db_store::IssueInput;
    use parking_lot::Mutex;
    use std::collections::HashMap;

    struct Fixture {
        state: Arc<AppState>,
        base: String,
        key: String,
        project_id: i64,
        _dir: tempfile::TempDir,
    }

    fn issue(id: &str, category: &str, severity: &str, score: i64) -> IssueInput {
        IssueInput { id: id.into(), phase: Some(4), category: category.into(), severity: severity.into(), score: Some(score), summary: format!("summary of {id}"), file: Some("app.js".into()), line: Some(1), snippet: None, cross_file: false, chain: None, cwe: None, owasp: None, tool: Some("built-in".into()), references: None, duplicate_ref: None }
    }

    async fn fixture(dual_custody: bool) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let db = ignite_db_store::DbStore::open(&dir.path().join("test.db")).unwrap();
        let mut config = ignite_config::Config::default();
        config.security.override_approval.enabled = dual_custody;
        let user_id = db.create_local_user("owner@example.com", Some("Owner"), "unused-hash").unwrap();
        let key = ignite_auth::generate_api_key();
        db.create_api_key(user_id, &ignite_auth::hash_api_key(&key), None, None, "test");
        let project_id = db.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        db.replace_project_issues(
            project_id,
            &[
                issue("secret::app.js::1", "secret", "error", 10),       // critical
                issue("quality::app.js::1", "quality", "warning", 3),    // non-critical warning
                issue("security::app.js::1", "security", "error", 5),    // non-critical error
            ],
            &HashSet::new(),
        );
        let state = Arc::new(AppState {
            runner: state::default_runner(),
            db,
            running_runs: Mutex::new(HashMap::new()),
            pending_effectivations: Mutex::new(HashMap::new()),
            review_gate: crate::review_gate::ReviewGate::default(),
            llm_config: state::default_llm_config(),
            config,
            package_hallucination_checker: state::default_package_hallucination_checker(),
            fix_pr_previews: Mutex::new(HashMap::new()),
            audit_http: reqwest::Client::new(),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().merge(router()).with_state(state.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Fixture { state, base: format!("http://{addr}"), key, project_id, _dir: dir }
    }

    async fn submit(f: &Fixture, path: &str, ids: &[&str]) -> (u16, Value) {
        let overrides: Vec<Value> = ids.iter().map(|id| json!({ "issueId": id, "justification": "reviewed and accepted for this fixture" })).collect();
        let res = reqwest::Client::new().post(format!("{}{}", f.base, path)).bearer_auth(&f.key).json(&json!({ "overrides": overrides })).send().await.unwrap();
        (res.status().as_u16(), res.json().await.unwrap_or(Value::Null))
    }

    fn status_of(body: &Value, id: &str) -> String {
        body["issues"].as_array().unwrap().iter().find(|i| i["id"] == id).unwrap_or_else(|| panic!("{id} missing from {body}"))["status"].as_str().unwrap_or("").to_string()
    }

    fn audit(f: &Fixture, event_type: &str) -> Vec<ignite_db_store::AuditEventRow> {
        f.state.db.list_audit_events(Some("acme"), Some("widgets"), Some(event_type), None, None, None, None, 100)
    }

    #[tokio::test]
    async fn non_critical_overrides_apply_at_once_and_record_actor_origin_severity_and_an_audit_event() {
        let f = fixture(false).await;
        let path = format!("/api/projects/{}/overrides", f.project_id);
        let (status, body) = submit(&f, &path, &["quality::app.js::1", "security::app.js::1"]).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["ok"], true);
        assert_eq!(body["appliedCount"], 2);
        assert_eq!(body["pendingApprovalCount"], 0);
        assert_eq!(body["pendingApproval"], false);
        assert_eq!(status_of(&body, "quality::app.js::1"), "overridden");
        assert_eq!(status_of(&body, "security::app.js::1"), "overridden");
        assert_ne!(status_of(&body, "secret::app.js::1"), "overridden", "an issue not named stays open");

        let rows: HashMap<String, ignite_db_store::OverrideRow> = f.state.db.get_project_overrides(f.project_id).into_iter().map(|o| (o.issue_id.clone(), o)).collect();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows["quality::app.js::1"].severity, "warning", "the issue's severity is stored, not a constant");
        assert_eq!(rows["security::app.js::1"].severity, "error");
        for o in rows.values() {
            assert_eq!(o.actor_email, "owner@example.com");
            assert_eq!(o.actor_name.as_deref(), Some("Owner"));
            assert_eq!(o.origin, "api_key");
            assert_eq!(o.justification, "reviewed and accepted for this fixture");
            assert_eq!(o.phase, 4);
        }
        let events = audit(&f, "override.approved");
        assert_eq!(events.len(), 2, "one audit event per applied override");
        for e in events {
            assert_eq!(e.actor.as_deref(), Some("owner@example.com"));
            let meta: Value = serde_json::from_str(e.metadata_json.as_deref().unwrap()).unwrap();
            assert_eq!(meta["origin"], "api_key");
            assert!(meta["issueId"].as_str().unwrap().ends_with("app.js::1"));
            assert_eq!(meta["justification"], "reviewed and accepted for this fixture");
        }
    }

    #[tokio::test]
    async fn a_browser_session_is_recorded_as_session_origin() {
        let f = fixture(false).await;
        let user_id = f.state.db.get_user_by_email("owner@example.com").unwrap().id;
        f.state.db.create_session("sid-characterization", user_id, "2999-01-01 00:00:00");
        let overrides = vec![json!({ "issueId": "quality::app.js::1", "justification": "reviewed and accepted for this fixture" })];
        let res = reqwest::Client::new()
            .post(format!("{}/api/projects/{}/overrides", f.base, f.project_id))
            .header("cookie", format!("{}=sid-characterization", ignite_auth::SESSION_COOKIE))
            .json(&json!({ "overrides": overrides }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        assert_eq!(f.state.db.get_project_overrides(f.project_id)[0].origin, "session");
    }

    #[tokio::test]
    async fn a_critical_override_waits_for_a_second_reviewer_when_dual_custody_is_on() {
        let f = fixture(true).await;
        let path = format!("/api/projects/{}/overrides", f.project_id);
        let (status, body) = submit(&f, &path, &["secret::app.js::1"]).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["appliedCount"], 0);
        assert_eq!(body["pendingApprovalCount"], 1);
        assert_eq!(body["pendingApproval"], true);
        assert_ne!(status_of(&body, "secret::app.js::1"), "overridden", "a pending override must leave the issue open and blocking");
        assert!(f.state.db.get_project_overrides(f.project_id).is_empty());
        let pending = f.state.db.list_pending_overrides(f.project_id);
        assert_eq!(pending.len(), 1);
        assert_eq!((pending[0].issue_id.as_str(), pending[0].origin.as_str(), pending[0].actor_email.as_str()), ("secret::app.js::1", "api_key", "owner@example.com"));
        assert_eq!(audit(&f, "override.pending_approval").len(), 1);
        assert!(audit(&f, "override.approved").is_empty());

        // Sending it again must not stack a second pending row.
        let (_, again) = submit(&f, &path, &["secret::app.js::1"]).await;
        assert_eq!(again["pendingApprovalCount"], 1);
        assert_eq!(f.state.db.list_pending_overrides(f.project_id).len(), 1, "a pending override is not duplicated");
        assert_eq!(audit(&f, "override.pending_approval").len(), 1, "and it is not audited twice");
    }

    #[tokio::test]
    async fn without_dual_custody_a_critical_override_applies_immediately() {
        let f = fixture(false).await;
        let (status, body) = submit(&f, &format!("/api/projects/{}/overrides", f.project_id), &["secret::app.js::1"]).await;
        assert_eq!(status, 200);
        assert_eq!((body["appliedCount"].as_i64(), body["pendingApprovalCount"].as_i64()), (Some(1), Some(0)));
        assert_eq!(status_of(&body, "secret::app.js::1"), "overridden");
    }

    #[tokio::test]
    async fn one_request_can_apply_the_non_critical_and_hold_the_critical() {
        let f = fixture(true).await;
        let (_, body) = submit(&f, &format!("/api/projects/{}/overrides", f.project_id), &["secret::app.js::1", "security::app.js::1"]).await;
        assert_eq!((body["appliedCount"].as_i64(), body["pendingApprovalCount"].as_i64()), (Some(1), Some(1)));
        assert_eq!(status_of(&body, "security::app.js::1"), "overridden");
        assert_ne!(status_of(&body, "secret::app.js::1"), "overridden");
    }

    #[tokio::test]
    async fn the_same_submission_by_job_id_behaves_identically() {
        let f = fixture(false).await;
        let (status, body) = submit(&f, "/api/pipeline/job-1/overrides", &["quality::app.js::1"]).await;
        assert_eq!(status, 200);
        assert_eq!(body["appliedCount"], 1);
        let (status, body) = submit(&f, "/api/pipeline/no-such-job/overrides", &["quality::app.js::1"]).await;
        assert_eq!(status, 404);
        assert_eq!(body["error"], "Unknown job id.");
    }

    #[tokio::test]
    async fn bad_submissions_are_rejected_with_specific_errors_and_change_nothing() {
        let f = fixture(false).await;
        let path = format!("/api/projects/{}/overrides", f.project_id);

        let res = reqwest::Client::new().post(format!("{}{}", f.base, path)).bearer_auth(&f.key).json(&json!({ "overrides": [] })).send().await.unwrap();
        assert_eq!(res.status(), 400);
        assert_eq!(res.json::<Value>().await.unwrap()["error"], "No overrides submitted.");

        let (status, body) = submit(&f, &path, &["nothing::matches::1"]).await;
        assert_eq!(status, 400);
        assert_eq!(body["error"], "None of the submitted overrides matched a still-open issue on this project.");
        assert_eq!(body["issues"].as_array().unwrap().len(), 3, "the current issue list is returned to help the caller");

        let (status, body) = submit(&f, "/api/projects/9999/overrides", &["quality::app.js::1"]).await;
        assert_eq!((status, body["error"].as_str()), (404, Some("Unknown project.")));

        let res = reqwest::Client::new().post(format!("{}{}", f.base, path)).json(&json!({ "overrides": [{ "issueId": "quality::app.js::1", "justification": "x" }] })).send().await.unwrap();
        assert_eq!(res.status(), 401, "no credentials, no override");

        assert!(f.state.db.get_project_overrides(f.project_id).is_empty(), "none of the above may write anything");
        assert!(audit(&f, "override.approved").is_empty());
    }

    #[tokio::test]
    async fn an_already_overridden_issue_cannot_be_overridden_again() {
        let f = fixture(false).await;
        let path = format!("/api/projects/{}/overrides", f.project_id);
        assert_eq!(submit(&f, &path, &["quality::app.js::1"]).await.0, 200);
        let (status, body) = submit(&f, &path, &["quality::app.js::1"]).await;
        assert_eq!(status, 400, "{body}");
        assert_eq!(f.state.db.get_project_overrides(f.project_id).len(), 1);
    }
}
