//! POST /api/webhooks/github/repository-events — zero-touch repo
//! onboarding, GHAS-parity for "Security Configurations" auto-applying to
//! any new repo an org creates. Previously a repo only ever got a
//! `projects` table row (and any branch protection) once a human manually
//! uploaded/scanned it or ran `enforce-gate-branch-protection`/
//! `scheduled-rescan` against it by name — a newly-created repo sat
//! completely unprotected and unknown to Ignite until someone remembered
//! it existed.
//!
//! Listens for GitHub's `repository` webhook event, actions `created` and
//! `transferred` (a repo transferred into the org is just as new to
//! *this* org's Ignite deployment as one created fresh in it — every
//! other action, e.g. `deleted`/`archived`/`renamed`, is a no-op here).
//! On a match:
//! 1. Always: a minimal `projects` row is inserted so the repo shows up
//!    in Onboarded Repos immediately, even before any real scan has run
//!    (`status` stays `NULL` until one does — the same shape a
//!    freshly-`create_project`'d row already has ahead of
//!    `finish_project`).
//! 2. `security.repositoryEvents.applyOrgRuleset` (off by default):
//!    applies/updates the org's `ignite-gate` Repository Ruleset via
//!    `ignite_enforce_gate_branch_protection::{plan_for_org,apply_org_plan}`
//!    — the exact same logic the standalone CLI's `--org` mode uses,
//!    reused as a library call instead of shelling out to the binary.
//!    Since an org ruleset already applies to every repo the moment it
//!    exists, this is normally a no-op confirming the existing ruleset
//!    still covers the new repo — genuinely useful only for an org that
//!    hasn't run the CLI at all yet.
//! 3. `security.repositoryEvents.triggerBaselineScan` (off by default):
//!    spawns a background task running `ignite_scheduled_rescan::rescan_one`
//!    against the new repo — the same shallow-clone + `validate-all` +
//!    `github-check` sequence a scheduled rescan already runs for
//!    *existing* onboarded repos, just aimed at a repo that's never been
//!    scanned before. Fire-and-forget (`tokio::spawn`, matching
//!    `AppState::emit_audit_event`'s own posture) since a real scan can
//!    take minutes — the webhook response itself never waits on it.
//!
//! Every step past the initial enrollment is independently opt-in and
//! best-effort/non-fatal: a ruleset-apply or scan failure is logged and
//! audited but never turns into a 5xx for GitHub's webhook delivery.
//!
//! Same auth posture as the other three inbound webhooks: no
//! `RequireAuth` (GitHub's webhook delivery has no Ignite session/API
//! key), `X-Hub-Signature-256` HMAC-SHA256 against
//! `security.repositoryEvents.inboundWebhookSecret`
//! (`REPOSITORY_EVENTS_INBOUND_WEBHOOK_SECRET`) is the only gate, and an
//! unset secret always 404s.

use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use ignite_github_api::verify_webhook_signature;
use ignite_scheduled_rescan::{rescan_one, AutoFixMode, RescanTarget};
use serde_json::{json, Value};
use std::sync::Arc;

fn err(status: StatusCode, message: impl Into<String>) -> Response {
    (status, axum::Json(json!({ "error": message.into() }))).into_response()
}

async fn repository_events_webhook(State(state): State<Arc<AppState>>, headers: HeaderMap, body: Bytes) -> Response {
    let Some(secret) = state.config.security.repository_events.inbound_webhook_secret.as_deref().filter(|s| !s.is_empty()) else {
        return err(StatusCode::NOT_FOUND, "Inbound repository-events webhook is not configured.".to_string());
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
    if action != "created" && action != "transferred" {
        // `deleted`/`archived`/`renamed`/`publicized`/... are all no-ops
        // for onboarding — acknowledge with 200 so GitHub doesn't retry.
        return axum::Json(json!({ "ok": true, "ignored": action })).into_response();
    }

    let org = payload.get("repository").and_then(|r| r.get("owner")).and_then(|o| o.get("login")).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let repo = payload.get("repository").and_then(|r| r.get("name")).and_then(|v| v.as_str()).unwrap_or("").to_string();
    if !ignite_github_api::is_valid_github_owner(&org) || !ignite_github_api::is_valid_github_repo(&repo) {
        return err(StatusCode::BAD_REQUEST, "Invalid or missing repository owner/name in payload.".to_string());
    }
    let repo_url = payload.get("repository").and_then(|r| r.get("html_url")).and_then(|v| v.as_str()).map(str::to_string);

    // 1. Always: enroll a minimal project row, even before any real scan
    // has run — `status` stays NULL, same as a fresh `create_project` row
    // ahead of `finish_project`, which every existing reader (Onboarded
    // Repos, `get_latest_project_for_org_repo`) already tolerates.
    let job_id = format!("repo-event-{}", uuid::Uuid::new_v4());
    let project_id = match state.db.create_project(&job_id, &org, &repo, false, "repository-event", None) {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("repository-events webhook: failed to enroll {org}/{repo}: {e}");
            return err(StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to enroll {org}/{repo}: {e}"));
        }
    };
    // This row is never a real scan run — `finish_project` is never
    // called on it, so without this it permanently sits at the
    // `create_project` default of `status = 'running'`, forever
    // indistinguishable from an actually-in-progress (or crashed) scan in
    // every dashboard/monitor that reads project status.
    state.db.set_project_status(project_id, "enrolled");
    state.emit_audit_event(ignite_audit_log::AuditEvent::new("repository.enrolled", "info", format!("{org}/{repo}: auto-enrolled on GitHub \"{action}\" event")).repo(&org, &repo).metadata(json!({ "projectId": project_id, "action": action, "repoUrl": repo_url })));

    // 2. Optional: apply/update the org's ignite-gate Repository Ruleset —
    // reuses the standalone CLI's own library functions rather than
    // shelling out to the binary.
    if state.config.security.repository_events.apply_org_ruleset {
        match ignite_enforce_gate_branch_protection::plan_for_org(&state.runner, &org).await {
            Ok(plan) => match ignite_enforce_gate_branch_protection::apply_org_plan(&state.runner, &plan).await {
                Ok(()) => {
                    state.emit_audit_event(ignite_audit_log::AuditEvent::new("repository.org_ruleset_applied", "info", format!("applied ignite-gate org ruleset for {org} (triggered by {org}/{repo} {action})")).repo(&org, &repo));
                }
                Err(e) => tracing::warn!("repository-events webhook: failed to apply org ruleset for {org}: {e}"),
            },
            Err(e) => tracing::warn!("repository-events webhook: failed to plan org ruleset for {org}: {e}"),
        }
    }

    // 3. Optional: kick off a real baseline scan in the background — a
    // full clone + validate-all can take minutes (per
    // `IGNITE_SCHEDULED_RESCAN_TIMEOUT_SECS`'s own sizing), so this never
    // blocks the webhook response.
    if state.config.security.repository_events.trigger_baseline_scan {
        let runner = state.runner.clone();
        let org = org.clone();
        let repo = repo.clone();
        // Same `PORT`-env-overrides-`config.json` precedence `main.rs`
        // actually binds with — `state.config.port` alone is wrong in any
        // deployment (containerized or otherwise) that sets `PORT` to bind
        // a different port than the static config value.
        let port: u16 = std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(state.config.port);
        // `IGNITE_BASE_URL` is the same env var every other in-process
        // caller of this server already reads to reach itself (the CLI,
        // mcp-server) — a deployment terminating TLS itself or sitting
        // behind an HTTPS-only reverse proxy sets it to the real external
        // scheme/host, since a hardcoded `http://127.0.0.1:{port}` can't
        // possibly be reachable at all if the server isn't actually
        // listening on plain HTTP on that loopback address.
        let server_base = std::env::var("IGNITE_BASE_URL").unwrap_or_else(|_| format!("http://127.0.0.1:{port}"));
        tokio::spawn(async move {
            let http = reqwest::Client::new();
            let gh_token = ignite_github_api::resolve_server_github_token();
            let target = RescanTarget { org: org.clone(), repo: repo.clone() };
            let outcome = rescan_one(&runner, &http, &server_base, &gh_token, &target, AutoFixMode::Off).await;
            if let Some(e) = &outcome.error {
                tracing::warn!("repository-events webhook: baseline scan failed for {org}/{repo}: {e}");
                return;
            }
            tracing::info!("repository-events webhook: baseline scan for {org}/{repo} completed ({} issue(s), posted={})", outcome.issue_count, outcome.posted);
        });
    }

    axum::Json(json!({ "ok": true, "action": action, "projectId": project_id })).into_response()
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/webhooks/github/repository-events", post(repository_events_webhook))
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let res = repository_events_webhook(State(state), HeaderMap::new(), Bytes::new()).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }
}
