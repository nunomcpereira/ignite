//! POST /api/webhooks/github/push-protection — inbound sync for GitHub's
//! own secret **push-protection** bypass. GitHub's pre-receive check can
//! block a commit containing a recognized secret pattern, but a developer
//! is still allowed to push anyway after giving a justification ("used in
//! tests", "false positive", ...). GitHub can notify the org of that via
//! a `secret_scanning_alert` webhook delivery carrying
//! `push_protection_bypassed: true` — previously nothing in Ignite ever
//! saw that event, so a knowingly-pushed live secret could sail straight
//! past without anyone noticing beyond whoever happens to browse GitHub's
//! own Security tab.
//!
//! Same auth posture as `code_scanning_webhook.rs`: not wrapped in
//! `RequireAuth` (the caller is GitHub's webhook delivery system, which
//! has no Ignite session/API key) — authenticity instead comes from
//! verifying `X-Hub-Signature-256` against
//! `security.pushProtection.inboundWebhookSecret`
//! (`PUSH_PROTECTION_INBOUND_WEBHOOK_SECRET`). `None` (the default) makes
//! the endpoint always 404, so an unconfigured deployment never exposes
//! an unauthenticated write path. Register the webhook on the repo/org in
//! GitHub's settings (Settings → Webhooks → `secret_scanning_alert`
//! events) with the same secret.
//!
//! Every delivery whose `alert.push_protection_bypassed` isn't `true` is
//! acknowledged and ignored (200, so GitHub doesn't retry) — a bypass is
//! the one `secret_scanning_alert` outcome this endpoint exists for; a
//! plain alert with no bypass is already covered by the *code-scanning*
//! webhook/outbound-SARIF path for secret-category findings.
//!
//! Remediation is two-tier: a "critical"-severity audit-log event always
//! fires (so a SIEM/security-team sink sees it regardless of any other
//! config), and — only when `security.pushProtection.autoFileIssue` is
//! explicitly turned on — a real GitHub issue gets filed via
//! `gh_create_issue` summarizing who bypassed what and why, so it lands
//! somewhere a human is already looking (GitHub Issues) instead of only
//! a log line. Both are best-effort/non-fatal, matching every other push
//! in this codebase — a failure to file the issue never fails the
//! webhook response GitHub is waiting on.

use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use ignite_github_api::verify_webhook_signature;
use serde_json::{json, Value};
use std::sync::Arc;

/// The bypass-relevant fields pulled out of a `secret_scanning_alert`
/// webhook's `alert` object — split out from the handler so the
/// extraction itself (which fields, which fallbacks) is unit-testable
/// without a real HTTP request.
struct BypassInfo {
    secret_type: String,
    bypassed_by: Option<String>,
    bypassed_at: Option<String>,
    reason: Option<String>,
    comment: Option<String>,
    alert_url: Option<String>,
}

fn extract_bypass_info(alert: &Value) -> Option<BypassInfo> {
    if alert.get("push_protection_bypassed").and_then(|v| v.as_bool()) != Some(true) {
        return None;
    }
    Some(BypassInfo {
        secret_type: alert.get("secret_type_display_name").or_else(|| alert.get("secret_type")).and_then(|v| v.as_str()).unwrap_or("secret").to_string(),
        bypassed_by: alert.get("push_protection_bypassed_by").and_then(|b| b.get("login")).and_then(|v| v.as_str()).map(str::to_string),
        bypassed_at: alert.get("push_protection_bypassed_at").and_then(|v| v.as_str()).map(str::to_string),
        reason: alert.get("resolution").and_then(|v| v.as_str()).map(str::to_string),
        comment: alert.get("resolution_comment").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(str::to_string),
        alert_url: alert.get("html_url").and_then(|v| v.as_str()).map(str::to_string),
    })
}

fn issue_body_for(info: &BypassInfo, org: &str, repo: &str) -> String {
    let mut body = format!("A GitHub secret push-protection block was **bypassed** on `{org}/{repo}`.\n\n- **Secret type:** {}\n", info.secret_type);
    if let Some(by) = &info.bypassed_by {
        body.push_str(&format!("- **Bypassed by:** @{by}\n"));
    }
    if let Some(at) = &info.bypassed_at {
        body.push_str(&format!("- **Bypassed at:** {at}\n"));
    }
    if let Some(reason) = &info.reason {
        body.push_str(&format!("- **Stated reason:** {reason}\n"));
    }
    if let Some(comment) = &info.comment {
        body.push_str(&format!("- **Comment:** {comment}\n"));
    }
    if let Some(url) = &info.alert_url {
        body.push_str(&format!("\n[View alert on GitHub]({url})\n"));
    }
    body.push_str("\n_Filed automatically by Ignite (`security.pushProtection.autoFileIssue`) — please confirm this bypass was legitimate and rotate the credential if not._");
    body
}

fn err(status: StatusCode, message: impl Into<String>) -> Response {
    (status, axum::Json(json!({ "error": message.into() }))).into_response()
}

async fn push_protection_webhook(State(state): State<Arc<AppState>>, headers: HeaderMap, body: Bytes) -> Response {
    let Some(secret) = state.config.security.push_protection.inbound_webhook_secret.as_deref().filter(|s| !s.is_empty()) else {
        return err(StatusCode::NOT_FOUND, "Inbound push-protection webhook is not configured.".to_string());
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

    let org = payload.get("repository").and_then(|r| r.get("owner")).and_then(|o| o.get("login")).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let repo = payload.get("repository").and_then(|r| r.get("name")).and_then(|v| v.as_str()).unwrap_or("").to_string();
    if !ignite_github_api::is_valid_github_owner(&org) || !ignite_github_api::is_valid_github_repo(&repo) {
        return err(StatusCode::BAD_REQUEST, "Invalid or missing repository owner/name in payload.".to_string());
    }

    let Some(alert) = payload.get("alert") else {
        return err(StatusCode::BAD_REQUEST, "Missing alert object in payload.".to_string());
    };
    let Some(info) = extract_bypass_info(alert) else {
        // Every `secret_scanning_alert` delivery that isn't a bypass
        // (created, resolved, reopened, ...) is a no-op here — those
        // findings are already the outbound code-scanning/SARIF path's
        // concern, not this endpoint's.
        return axum::Json(json!({ "ok": true, "ignored": "not_a_bypass" })).into_response();
    };

    state.emit_audit_event(
        ignite_audit_log::AuditEvent::new("push_protection.bypassed", "critical", format!("Push-protection bypassed on {org}/{repo}: {}", info.secret_type))
            .repo(&org, &repo)
            .metadata(json!({ "secretType": info.secret_type, "bypassedBy": info.bypassed_by, "reason": info.reason, "comment": info.comment, "alertUrl": info.alert_url })),
    );

    let mut issue_filed = false;
    if state.config.security.push_protection.auto_file_issue {
        let token = ignite_github_api::resolve_server_github_token();
        if token.is_empty() {
            tracing::warn!("push-protection bypass on {org}/{repo}: autoFileIssue is on but no GH_TOKEN/GITHUB_TOKEN is configured — skipping issue creation.");
        } else {
            let api = ignite_github_api::GithubApi::new(&state.runner);
            let title = format!("Push-protection bypass: {} in {org}/{repo}", info.secret_type);
            let body = issue_body_for(&info, &org, &repo);
            match api.gh_create_issue(&format!("{org}/{repo}"), &title, &body, &token).await {
                Ok(()) => issue_filed = true,
                Err(e) => tracing::warn!("Failed to file push-protection bypass issue for {org}/{repo}: {e}"),
            }
        }
    }

    axum::Json(json!({ "ok": true, "bypassed": true, "issueFiled": issue_filed })).into_response()
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/webhooks/github/push-protection", post(push_protection_webhook))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_bypass_info_none_when_not_bypassed() {
        assert!(extract_bypass_info(&json!({ "push_protection_bypassed": false })).is_none());
        assert!(extract_bypass_info(&json!({})).is_none());
    }

    #[test]
    fn extract_bypass_info_pulls_every_field_when_present() {
        let alert = json!({
            "push_protection_bypassed": true,
            "secret_type_display_name": "AWS Access Key",
            "push_protection_bypassed_by": { "login": "octocat" },
            "push_protection_bypassed_at": "2026-01-01T00:00:00Z",
            "resolution": "used_in_tests",
            "resolution_comment": "fixture value, not real",
            "html_url": "https://github.com/acme/widgets/security/secret-scanning/1",
        });
        let info = extract_bypass_info(&alert).unwrap();
        assert_eq!(info.secret_type, "AWS Access Key");
        assert_eq!(info.bypassed_by.as_deref(), Some("octocat"));
        assert_eq!(info.bypassed_at.as_deref(), Some("2026-01-01T00:00:00Z"));
        assert_eq!(info.reason.as_deref(), Some("used_in_tests"));
        assert_eq!(info.comment.as_deref(), Some("fixture value, not real"));
        assert_eq!(info.alert_url.as_deref(), Some("https://github.com/acme/widgets/security/secret-scanning/1"));
    }

    #[test]
    fn extract_bypass_info_falls_back_to_secret_type_when_no_display_name() {
        let alert = json!({ "push_protection_bypassed": true, "secret_type": "generic_api_key" });
        let info = extract_bypass_info(&alert).unwrap();
        assert_eq!(info.secret_type, "generic_api_key");
    }

    #[test]
    fn extract_bypass_info_treats_empty_comment_as_absent() {
        let alert = json!({ "push_protection_bypassed": true, "resolution_comment": "" });
        let info = extract_bypass_info(&alert).unwrap();
        assert!(info.comment.is_none());
    }

    #[test]
    fn issue_body_for_includes_every_present_field_and_the_automation_note() {
        let info = BypassInfo { secret_type: "AWS Access Key".to_string(), bypassed_by: Some("octocat".to_string()), bypassed_at: Some("2026-01-01T00:00:00Z".to_string()), reason: Some("used_in_tests".to_string()), comment: Some("fixture".to_string()), alert_url: Some("https://example.com/alert/1".to_string()) };
        let body = issue_body_for(&info, "acme", "widgets");
        assert!(body.contains("acme/widgets"));
        assert!(body.contains("AWS Access Key"));
        assert!(body.contains("@octocat"));
        assert!(body.contains("used_in_tests"));
        assert!(body.contains("fixture"));
        assert!(body.contains("https://example.com/alert/1"));
        assert!(body.contains("Filed automatically by Ignite"));
    }

    #[tokio::test]
    async fn push_protection_webhook_404s_when_unconfigured() {
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
        let res = push_protection_webhook(State(state), HeaderMap::new(), Bytes::new()).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }
}
