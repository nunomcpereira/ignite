//! POST /api/webhooks/github/secret-scanning — inbound sync for GitHub's
//! `secret_scanning_alert` webhook events that neither of Ignite's other
//! two webhooks cover: `code_scanning_webhook.rs` only ever receives
//! `code_scanning_alert` deliveries, and `push_protection_webhook.rs`
//! filters `secret_scanning_alert` down to just the `push_protection_bypassed:
//! true` case. Every other action on that same event type — `created`,
//! `resolved`, `reopened`, `validated`, `publicly_leaked` — previously
//! reached nothing in Ignite.
//!
//! `resolved`/`reopened` mirror `code_scanning_webhook.rs`'s own
//! dismissed/reopened sync: a human resolving a secret alert on GitHub's
//! side should flip Ignite's own issue status, and reopening should undo
//! exactly that override (never a human-justified one on the same issue —
//! same `GITHUB_DISMISSAL_ACTOR_EMAIL`-scoped delete `delete_github_dismissal_overrides`
//! already uses). `created`, `validated`, and `publicly_leaked` have no
//! Ignite issue-state equivalent (Ignite's own secret finding already
//! exists from its own scan) — they're audit-log-only signals,
//! `publicly_leaked` always logged at `critical` since it means a live
//! secret is now public.
//!
//! Matching an alert back to an Ignite issue is harder here than for
//! `code_scanning_alert`: the webhook payload's `alert` object carries no
//! file/line (unlike `most_recent_instance.location` on a code-scanning
//! alert) — only `GET .../secret-scanning/alerts/{number}/locations` has
//! that, so `resolved`/`reopened` make one best-effort GitHub API call
//! before matching on `category == "secret"` + file/line. No server
//! GitHub token configured, or the API call failing/returning no
//! locations, degrades to "no matching issue" rather than failing the
//! webhook.
//!
//! Same auth posture as the other two: no `RequireAuth` (GitHub's webhook
//! delivery has no Ignite session/API key), `X-Hub-Signature-256`
//! HMAC-SHA256 against `security.secretScanning.inboundWebhookSecret`
//! (`SECRET_SCANNING_INBOUND_WEBHOOK_SECRET`) is the only gate, and an
//! unset secret always 404s.

use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use ignite_db_store::{IssueRow, GITHUB_DISMISSAL_ACTOR_EMAIL};
use ignite_github_api::verify_webhook_signature;
use ignite_tool_runner::ToolRunner;
use serde_json::{json, Value};
use std::sync::Arc;

fn err(status: StatusCode, message: impl Into<String>) -> Response {
    (status, axum::Json(json!({ "error": message.into() }))).into_response()
}

/// First reported location for `alert_number` (`path`/`start_line`), via
/// GitHub's Secret Scanning Locations API — the one piece of information
/// the `secret_scanning_alert` webhook payload itself never carries.
/// `None` on a missing/empty token, a request failure, or an alert with no
/// recorded locations — all soft, the caller degrades to "no matching
/// issue" rather than failing the webhook over it.
async fn fetch_first_location(runner: &ToolRunner, full_name: &str, alert_number: u64, token: &str) -> Option<(String, i64)> {
    if token.is_empty() {
        return None;
    }
    let api = ignite_github_api::GithubApi::new(runner);
    let locations = api.gh_api_get(&format!("/repos/{full_name}/secret-scanning/alerts/{alert_number}/locations"), token).await.ok()??;
    let first = locations.as_array()?.first()?;
    let details = first.get("details")?;
    let path = details.get("path").and_then(|v| v.as_str())?.to_string();
    let start_line = details.get("start_line").and_then(|v| v.as_i64())?;
    Some((path, start_line))
}

fn find_matching_secret_issue<'a>(issues: &'a [IssueRow], path: &str, start_line: i64) -> Option<&'a IssueRow> {
    issues.iter().find(|issue| issue.category == "secret" && issue.file.as_deref() == Some(path) && issue.line == Some(start_line))
}

async fn secret_scanning_webhook(State(state): State<Arc<AppState>>, headers: HeaderMap, body: Bytes) -> Response {
    let Some(secret) = state.config.security.secret_scanning.inbound_webhook_secret.as_deref().filter(|s| !s.is_empty()) else {
        return err(StatusCode::NOT_FOUND, "Inbound secret-scanning webhook is not configured.".to_string());
    };
    let Some(signature) = headers.get("x-hub-signature-256").and_then(|v| v.to_str().ok()) else {
        return err(StatusCode::UNAUTHORIZED, "Missing X-Hub-Signature-256 header.".to_string());
    };
    if !verify_webhook_signature(secret, &body, signature) {
        return err(StatusCode::UNAUTHORIZED, "Signature verification failed.".to_string());
    }
    let delivery_id = headers.get("x-github-delivery").and_then(|v| v.to_str().ok()).unwrap_or("");
    if !state.db.record_webhook_delivery_once(delivery_id) {
        return axum::Json(json!({ "ok": true, "ignored": "duplicate_delivery" })).into_response();
    }

    let payload: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("Invalid JSON body: {e}")),
    };

    let action = payload.get("action").and_then(|v| v.as_str()).unwrap_or("");
    if !["resolved", "reopened", "created", "validated", "publicly_leaked"].contains(&action) {
        // `emails_leaked` isn't a real event but a handful of other
        // documented actions (none currently) would land here too —
        // acknowledge with 200 so GitHub doesn't retry delivery.
        return axum::Json(json!({ "ok": true, "ignored": action })).into_response();
    }

    let org = payload.get("repository").and_then(|r| r.get("owner")).and_then(|o| o.get("login")).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let repo = payload.get("repository").and_then(|r| r.get("name")).and_then(|v| v.as_str()).unwrap_or("").to_string();
    if !ignite_github_api::is_valid_github_owner(&org) || !ignite_github_api::is_valid_github_repo(&repo) {
        return err(StatusCode::BAD_REQUEST, "Invalid or missing repository owner/name in payload.".to_string());
    }
    let full_name = format!("{org}/{repo}");

    let Some(alert) = payload.get("alert") else {
        return err(StatusCode::BAD_REQUEST, "Missing alert object in payload.".to_string());
    };
    let secret_type = alert.get("secret_type_display_name").or_else(|| alert.get("secret_type")).and_then(|v| v.as_str()).unwrap_or("secret");
    let alert_url = alert.get("html_url").and_then(|v| v.as_str());

    // `created`/`validated`/`publicly_leaked` have no Ignite issue-state
    // equivalent — audit-only, regardless of whether this repo has ever
    // been onboarded/scanned by Ignite, since they're org-level compliance
    // signals rather than a change to a specific Ignite-tracked finding.
    if action == "created" || action == "validated" || action == "publicly_leaked" {
        let (event_type, severity, message) = match action {
            "publicly_leaked" => ("secret_scanning_alert.publicly_leaked", "critical", format!("{secret_type} publicly leaked in {full_name}")),
            "validated" => {
                let validity = alert.get("validity").and_then(|v| v.as_str()).unwrap_or("unknown");
                let sev = if validity == "active" { "warning" } else { "info" };
                ("secret_scanning_alert.validated", sev, format!("{secret_type} in {full_name} validated as {validity}"))
            }
            _ => ("secret_scanning_alert.created", "warning", format!("New {secret_type} alert in {full_name}")),
        };
        state.emit_audit_event(ignite_audit_log::AuditEvent::new(event_type, severity, message).repo(&org, &repo).metadata(json!({ "alertNumber": alert.get("number"), "secretType": secret_type, "alertUrl": alert_url })));
        return axum::Json(json!({ "ok": true, "action": action })).into_response();
    }

    let Some((project_id, job_id)) = state.db.get_latest_project_for_org_repo(&org, &repo) else {
        // Not an onboarded repo (or never scanned) — nothing to sync.
        return axum::Json(json!({ "ok": true, "ignored": "unknown_repo" })).into_response();
    };
    let Some(alert_number) = alert.get("number").and_then(|v| v.as_u64()) else {
        return err(StatusCode::BAD_REQUEST, "Missing alert.number in payload.".to_string());
    };
    let token = ignite_github_api::resolve_server_github_token();
    let Some((path, start_line)) = fetch_first_location(&state.runner, &full_name, alert_number, &token).await else {
        return axum::Json(json!({ "ok": true, "ignored": "no_location_data" })).into_response();
    };

    let issues = state.db.get_project_issues(project_id);
    let Some(issue) = find_matching_secret_issue(&issues, &path, start_line) else {
        return axum::Json(json!({ "ok": true, "ignored": "no_matching_issue" })).into_response();
    };
    let issue_id = issue.id.clone();

    if action == "resolved" {
        let resolution = alert.get("resolution").and_then(|v| v.as_str()).unwrap_or("(no reason given)");
        let comment = alert.get("resolution_comment").and_then(|v| v.as_str());
        let resolved_by = alert.get("resolved_by").and_then(|d| d.get("login")).and_then(|v| v.as_str());
        let justification = match comment {
            Some(c) if !c.is_empty() => format!("Resolved on GitHub ({resolution}): {c}"),
            _ => format!("Resolved on GitHub: {resolution}"),
        };
        let override_args = ignite_db_store::AddOverrideArgs {
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
            actor_name: resolved_by,
            email_sent: false,
        };
        // Dual-custody: same enforcement as code_scanning_webhook.rs's
        // dismissal handler — a critical-severity finding resolved via a
        // GitHub secret-scanning alert dismissal is still a human override
        // decision, and must not bypass the second-reviewer approval every
        // other override entry point enforces just because it arrived
        // through this webhook instead of Ignite's own UI/API.
        // Saturating cast, not `as i32` — see code_scanning_webhook.rs's
        // identical guard for why a truncating cast here is unsafe.
        let score_i32 = i32::try_from(issue.score.unwrap_or(0)).unwrap_or(i32::MAX);
        let is_critical = state.config.security.override_approval.enabled && ignite_override_engine::is_critical_score(score_i32);
        if is_critical {
            state.db.add_pending_override(override_args);
            state.emit_audit_event(
                ignite_audit_log::AuditEvent::new("secret_scanning_alert.resolved_on_github", "info", format!("{secret_type} finding {}: resolved on GitHub ({resolution}) — critical, held pending a second reviewer's approval", issue.summary))
                    .repo(&org, &repo)
                    .metadata(json!({ "issueId": issue_id, "resolution": resolution, "pendingApproval": true })),
            );
        } else {
            state.db.add_override(override_args);
            state.db.set_issue_status(project_id, &issue_id, "overridden");
            state.emit_audit_event(
                ignite_audit_log::AuditEvent::new("secret_scanning_alert.resolved_on_github", "info", format!("{secret_type} finding {}: resolved on GitHub ({resolution})", issue.summary))
                    .repo(&org, &repo)
                    .metadata(json!({ "issueId": issue_id, "resolution": resolution })),
            );
        }
    } else {
        let removed = state.db.delete_github_dismissal_overrides(&org, &repo, &issue_id);
        if removed > 0 && !state.db.issue_has_override(project_id, &issue_id) {
            state.db.set_issue_status(project_id, &issue_id, "open");
        }
        state.emit_audit_event(
            ignite_audit_log::AuditEvent::new("secret_scanning_alert.reopened_on_github", "warning", format!("{secret_type} finding {}: reopened on GitHub", issue.summary))
                .repo(&org, &repo)
                .metadata(json!({ "issueId": issue_id })),
        );
    }

    axum::Json(json!({ "ok": true, "action": action, "issueId": issue_id })).into_response()
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/webhooks/github/secret-scanning", post(secret_scanning_webhook))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issue(category: &str, file: &str, line: i64) -> IssueRow {
        IssueRow { id: format!("{category}::{file}::{line}"), phase: Some(4), category: category.to_string(), severity: "error".to_string(), score: Some(8), summary: "test finding".to_string(), file: Some(file.to_string()), line: Some(line), snippet: None, cross_file: false, chain: None, cwe: None, owasp: None, tool: None, references: None, duplicate_ref: None, status: "open".to_string(), created_at: String::new(), justification: None, actor_email: None, actor_name: None }
    }

    #[test]
    fn find_matching_secret_issue_requires_category_file_and_line() {
        let issues = vec![issue("codeql-sast", "a.py", 3), issue("secret", "a.py", 3), issue("secret", "b.py", 3)];
        let found = find_matching_secret_issue(&issues, "a.py", 3);
        assert_eq!(found.unwrap().category, "secret");
        assert!(find_matching_secret_issue(&issues, "a.py", 4).is_none());
        assert!(find_matching_secret_issue(&issues, "c.py", 3).is_none());
    }

    #[tokio::test]
    async fn fetch_first_location_none_on_empty_token() {
        let runner = ToolRunner::new(std::collections::HashMap::new());
        assert!(fetch_first_location(&runner, "acme/widgets", 1, "").await.is_none());
    }

    #[tokio::test]
    async fn webhook_404s_when_secret_not_configured() {
        let db_dir = tempfile::tempdir().unwrap();
        let db = ignite_db_store::DbStore::open(&db_dir.path().join("test.db")).unwrap();
        std::mem::forget(db_dir);
        let state = Arc::new(AppState {
            runner: crate::state::default_runner(),
            db,
            running_runs: parking_lot::Mutex::new(std::collections::HashMap::new()),
            pending_effectivations: parking_lot::Mutex::new(std::collections::HashMap::new()),
            review_gate: crate::review_gate::ReviewGate::default(),
            llm_config: crate::state::default_llm_config(),
            config: ignite_config::Config::default(),
            package_hallucination_checker: crate::state::default_package_hallucination_checker(),
            fix_pr_previews: parking_lot::Mutex::new(std::collections::HashMap::new()),
            audit_http: reqwest::Client::new(),
        });
        let res = secret_scanning_webhook(State(state), HeaderMap::new(), Bytes::new()).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }
}
