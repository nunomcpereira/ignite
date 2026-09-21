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
    let origin = crate::auth::resolve_auth_method(&headers, &state.db).origin();
    add_overrides(project_id, format!("override-{project_id}"), state, user, origin, body).await
}

async fn add_overrides_by_job(Path(job_id): Path<String>, State(state): State<Arc<AppState>>, crate::auth::RequireAuth(user): crate::auth::RequireAuth, headers: axum::http::HeaderMap, Json(body): Json<Value>) -> Response {
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
