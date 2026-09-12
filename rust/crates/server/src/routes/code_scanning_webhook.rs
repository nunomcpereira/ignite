//! POST /api/webhooks/github/code-scanning — inbound half of GHAS-parity
//! alert-dismissal sync. `github_pr_status.rs`'s `sync_dismissals` already
//! pushes Ignite override -> GitHub dismiss; this is the missing reverse
//! direction: a human dismissing (or reopening) a code-scanning alert
//! directly in GitHub's UI previously never reached Ignite's own
//! `ignite.db`, so the next `validate-all`/gate check kept treating the
//! finding as an unapproved open issue.
//!
//! Not wrapped in `RequireAuth` — the caller is GitHub's webhook
//! delivery system, which has no Ignite session or API key. Authenticity
//! instead comes from verifying GitHub's `X-Hub-Signature-256` header
//! (HMAC-SHA256 over the raw request body) against
//! `security.codeScanning.inboundWebhookSecret`
//! (`CODE_SCANNING_INBOUND_WEBHOOK_SECRET`) — the same shared secret
//! configured when the webhook is registered on the repo/org in GitHub's
//! settings (Settings → Webhooks → code_scanning_alert events, or the
//! equivalent GitHub App webhook subscription). When no secret is
//! configured the endpoint always 404s, so an unconfigured deployment
//! never exposes an unauthenticated write path.
//!
//! Mapping a webhook's `alert` back to an Ignite issue id mirrors
//! `github_pr_status.rs::find_matching_open_alert_number` in reverse:
//! same three-field match (`ignite_sarif::rule_id_for(issue)` vs.
//! `alert.rule.id`, plus `alert.most_recent_instance.location`'s
//! `path`/`start_line` vs. `issue.file`/`issue.line`) — GitHub's alert
//! payload doesn't echo back SARIF's `partialFingerprints` either.

use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use ignite_db_store::{IssueRow, GITHUB_DISMISSAL_ACTOR_EMAIL};
use ignite_github_api::verify_webhook_signature;
use serde_json::{json, Value};
use std::sync::Arc;

/// The Ignite `IssueRow` from `issues` that a webhook's `alert` object
/// refers to — `None` when the alert has no file/line (never true for a
/// real code-scanning alert, but mirrored from `find_matching_open_alert_number`
/// for symmetry) or no issue in this project matches on rule id + location.
fn find_matching_issue<'a>(issues: &'a [IssueRow], alert: &Value) -> Option<&'a IssueRow> {
    let rule_id = alert.get("rule").and_then(|r| r.get("id")).and_then(|v| v.as_str())?;
    let location = alert.get("most_recent_instance").and_then(|i| i.get("location"));
    let path = location.and_then(|l| l.get("path")).and_then(|v| v.as_str())?;
    let start_line = location.and_then(|l| l.get("start_line")).and_then(|v| v.as_i64())?;
    issues.iter().find(|issue| {
        issue.file.as_deref() == Some(path) && issue.line == Some(start_line) && ignite_sarif::rule_id_for(issue) == rule_id
    })
}

fn err(status: StatusCode, message: impl Into<String>) -> Response {
    (status, axum::Json(json!({ "error": message.into() }))).into_response()
}

async fn code_scanning_webhook(State(state): State<Arc<AppState>>, headers: HeaderMap, body: Bytes) -> Response {
    let Some(secret) = state.config.security.code_scanning.inbound_webhook_secret.as_deref().filter(|s| !s.is_empty()) else {
        return err(StatusCode::NOT_FOUND, "Inbound code-scanning webhook is not configured.".to_string());
    };
    let Some(signature) = headers.get("x-hub-signature-256").and_then(|v| v.to_str().ok()) else {
        return err(StatusCode::UNAUTHORIZED, "Missing X-Hub-Signature-256 header.".to_string());
    };
    if !verify_webhook_signature(secret, &body, signature) {
        return err(StatusCode::UNAUTHORIZED, "Signature verification failed.".to_string());
    }

    let payload: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("Invalid JSON body: {e}")),
    };

    let action = payload.get("action").and_then(|v| v.as_str()).unwrap_or("");
    if action != "dismissed" && action != "reopened" {
        // Every other `code_scanning_alert` action (created, fixed,
        // appeared_in_branch, ...) is a no-op for Ignite's own issue
        // state — acknowledge with 200 so GitHub doesn't retry delivery.
        return axum::Json(json!({ "ok": true, "ignored": action })).into_response();
    }

    let org = payload.get("repository").and_then(|r| r.get("owner")).and_then(|o| o.get("login")).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let repo = payload.get("repository").and_then(|r| r.get("name")).and_then(|v| v.as_str()).unwrap_or("").to_string();
    if !ignite_github_api::is_valid_github_owner(&org) || !ignite_github_api::is_valid_github_repo(&repo) {
        return err(StatusCode::BAD_REQUEST, "Invalid or missing repository owner/name in payload.".to_string());
    }

    let Some(alert) = payload.get("alert") else {
        return err(StatusCode::BAD_REQUEST, "Missing alert object in payload.".to_string());
    };

    let Some((project_id, job_id)) = state.db.get_latest_project_for_org_repo(&org, &repo) else {
        // Not an onboarded repo (or never scanned) — nothing to sync.
        return axum::Json(json!({ "ok": true, "ignored": "unknown_repo" })).into_response();
    };

    let issues = state.db.get_project_issues(project_id);
    let Some(issue) = find_matching_issue(&issues, alert) else {
        return axum::Json(json!({ "ok": true, "ignored": "no_matching_issue" })).into_response();
    };
    let issue_id = issue.id.clone();

    if action == "dismissed" {
        let reason = alert.get("dismissed_reason").and_then(|v| v.as_str()).unwrap_or("(no reason given)");
        let comment = alert.get("dismissed_comment").and_then(|v| v.as_str());
        let dismissed_by = alert.get("dismissed_by").and_then(|d| d.get("login")).and_then(|v| v.as_str());
        let justification = match comment {
            Some(c) if !c.is_empty() => format!("Dismissed on GitHub ({reason}): {c}"),
            _ => format!("Dismissed on GitHub: {reason}"),
        };
        state.db.add_override(ignite_db_store::AddOverrideArgs {
            project_id,
            job_id: &job_id,
            phase: issue.phase.unwrap_or(4),
            issue_id: &issue_id,
            category: &issue.category,
            severity: &issue.severity,
            summary: &issue.summary,
            file: issue.file.as_deref(),
            line: issue.line,
            justification: &justification,
            actor_email: GITHUB_DISMISSAL_ACTOR_EMAIL,
            actor_name: dismissed_by,
            email_sent: false,
        });
        state.db.set_issue_status(project_id, &issue_id, "overridden");
        state.emit_audit_event(
            ignite_audit_log::AuditEvent::new("code_scanning_alert.dismissed_on_github", "info", format!("alert for {}: {} dismissed on GitHub ({reason})", issue.category, issue.summary))
                .repo(&org, &repo)
                .metadata(json!({ "issueId": issue_id, "reason": reason })),
        );
    } else {
        let removed = state.db.delete_github_dismissal_overrides(&org, &repo, &issue_id);
        if removed > 0 && !state.db.issue_has_override(project_id, &issue_id) {
            state.db.set_issue_status(project_id, &issue_id, "open");
        }
        state.emit_audit_event(
            ignite_audit_log::AuditEvent::new("code_scanning_alert.reopened_on_github", "warning", format!("alert for {}: {} reopened on GitHub", issue.category, issue.summary))
                .repo(&org, &repo)
                .metadata(json!({ "issueId": issue_id })),
        );
    }

    axum::Json(json!({ "ok": true, "action": action, "issueId": issue_id })).into_response()
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/webhooks/github/code-scanning", post(code_scanning_webhook))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issue(category: &str, file: &str, line: i64) -> IssueRow {
        IssueRow { id: format!("{category}::{file}::{line}"), phase: Some(4), category: category.to_string(), severity: "error".to_string(), score: Some(8), summary: "test finding".to_string(), file: Some(file.to_string()), line: Some(line), snippet: None, cross_file: false, chain: None, cwe: None, owasp: None, tool: None, references: None, duplicate_ref: None, status: "open".to_string(), created_at: String::new(), justification: None, actor_email: None, actor_name: None }
    }

    fn alert(rule_id: &str, path: &str, start_line: i64) -> Value {
        json!({ "rule": { "id": rule_id }, "most_recent_instance": { "location": { "path": path, "start_line": start_line } } })
    }

    #[test]
    fn find_matching_issue_matches_by_rule_file_and_line() {
        let issues = vec![issue("codeql-sast", "a.js", 3), issue("secret", "a.js", 3)];
        let found = find_matching_issue(&issues, &alert("secret", "a.js", 3));
        assert_eq!(found.unwrap().category, "secret");
    }

    #[test]
    fn find_matching_issue_requires_exact_file_and_line() {
        let issues = vec![issue("secret", "a.js", 3)];
        assert!(find_matching_issue(&issues, &alert("secret", "b.js", 3)).is_none());
        assert!(find_matching_issue(&issues, &alert("secret", "a.js", 4)).is_none());
    }

    #[test]
    fn find_matching_issue_none_when_alert_missing_fields() {
        let issues = vec![issue("secret", "a.js", 3)];
        assert!(find_matching_issue(&issues, &json!({})).is_none());
    }
}
