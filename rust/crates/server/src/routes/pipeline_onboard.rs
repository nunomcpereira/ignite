//! POST /api/pipeline/onboard — faithful port of routes/pipeline-onboard.js:
//! full onboarding pipeline from a local filesystem path — phases 1-5
//! exactly as validate-all, and, if everything passes, phase 6
//! provisioning + push (skipped when `dryRun: true`, which gives
//! validate-all's behavior from this same request shape).
//!
//! Same known gaps as pipeline_validate.rs (per-task Phase 4 timings, GxP
//! document persistence). Push-token
//! resolution now prefers a connected session
//! (`crate::auth::resolve_effective_github_token`) over the
//! `resolve_server_github_token()` env fallback, matching `auth.js`.

use crate::routes::phase_meta::{phase_enabled, phase_title, resolve_phase_meta, PhaseMeta};
use crate::state::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use futures::FutureExt;
use ignite_override_engine::{Issue, Severity, SubmittedOverride};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

static GITHUB_NAME_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$").unwrap());
static REPO_NAME_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9._-]{1,100}$").unwrap());

struct PhaseRecord {
    state: String,
    logs: Vec<String>,
}

struct PipelineState {
    record: HashMap<i64, PhaseRecord>,
    events: Vec<Value>,
    project_id: Option<i64>,
}

#[derive(Clone)]
struct Logger {
    state: Arc<AppState>,
    meta: Vec<PhaseMeta>,
    inner: Arc<Mutex<PipelineState>>,
    job_id: String,
}

impl Logger {
    fn persist(&self, phase: i64) {
        let inner = self.inner.lock().unwrap();
        let Some(project_id) = inner.project_id else { return };
        if let Some(rec) = inner.record.get(&phase) {
            self.state.db.upsert_step(project_id, phase, &phase_title(&self.meta, phase), &rec.state, &rec.logs.join("\n"));
        }
    }

    fn log(&self, phase: i64, message: &str) {
        {
            let mut inner = self.inner.lock().unwrap();
            inner.record.entry(phase).or_insert_with(|| PhaseRecord { state: "pending".to_string(), logs: vec![] }).logs.push(message.to_string());
            inner.events.push(json!({ "type": "log", "phase": phase, "message": message }));
        }
        tracing::info!(job_id = %self.job_id, phase, "{message}");
        self.persist(phase);
    }

    fn status(&self, phase: i64, state: &str, extra: Option<Value>) {
        tracing::info!(job_id = %self.job_id, phase, state, "phase status");
        {
            let mut inner = self.inner.lock().unwrap();
            inner.record.entry(phase).or_insert_with(|| PhaseRecord { state: "pending".to_string(), logs: vec![] }).state = state.to_string();
            let mut ev = json!({ "type": "status", "phase": phase, "state": state });
            if let Some(extra) = extra {
                if let (Some(ev_obj), Some(extra_obj)) = (ev.as_object_mut(), extra.as_object()) {
                    for (k, v) in extra_obj {
                        ev_obj.insert(k.clone(), v.clone());
                    }
                }
            }
            inner.events.push(ev);
        }
        self.persist(phase);
    }

    fn set_project_id(&self, id: i64) {
        self.inner.lock().unwrap().project_id = Some(id);
    }

    fn phase_summary(&self) -> Vec<Value> {
        let inner = self.inner.lock().unwrap();
        self.meta
            .iter()
            .map(|p| {
                let (state, logs) = inner.record.get(&p.id).map(|r| (r.state.clone(), r.logs.clone())).unwrap_or(("pending".to_string(), vec![]));
                json!({ "phase": p.id, "title": p.title, "state": state, "logs": logs })
            })
            .collect()
    }

    fn events(&self) -> Vec<Value> {
        self.inner.lock().unwrap().events.clone()
    }
}

/// A resolved session/API-key identity is the *only* source of audit-trail
/// attribution here — there used to be a fallback to the request body's
/// own `actor.email` for "a genuinely unauthenticated deployment", but
/// that's exactly what let any caller attribute an override to an
/// arbitrary email (including bypassing dual-custody's
/// self-approval check, which compares against `actor_email`). Submitting
/// an override always requires a real authenticated caller now.
fn resolve_actor(headers: &axum::http::HeaderMap, db: &ignite_db_store::DbStore) -> Option<ignite_pipeline_core::Actor> {
    let user = crate::auth::resolve_user(headers, db);
    // `allow_unauth_body_actor: false` — onboarding always allows a real
    // provisioning + push to follow, so attribution must come from a
    // verified session; there is no body to consult anyway. See
    // `ignite_pipeline_core::resolve_actor`'s own doc comment.
    ignite_pipeline_core::resolve_actor(user.as_ref().map(|u| u.email.as_str()), user.as_ref().and_then(|u| u.name.as_deref()), None, None, false)
}

struct PipelineError {
    phase: i64,
    message: String,
    issues: Option<Vec<Issue>>,
    /// Set when the run stopped because publication is *blocked* (as opposed
    /// to a crash): the machine-readable reason + details an agent acts on.
    block: Option<(super::blocked::BlockReason, Value)>,
}

impl PipelineError {
    fn new(phase: i64, message: impl Into<String>) -> Self {
        PipelineError { phase, message: message.into(), issues: None, block: None }
    }

    fn blocked(mut self, reason: super::blocked::BlockReason, details: Value) -> Self {
        self.block = Some((reason, details));
        self
    }
}

// `panic_message` moved to `ignite_pipeline_core` (candidate 2 of the
// architecture review): this file and `pipeline_validate.rs` each carried a
// byte-identical copy.
use ignite_pipeline_core::panic_message;

pub(crate) fn issue_to_input(i: &Issue) -> ignite_db_store::IssueInput {
    ignite_db_store::IssueInput { id: i.id.clone(), phase: Some(4), category: i.category.clone(), severity: format!("{:?}", i.severity).to_lowercase(), score: Some(i.score as i64), summary: i.summary.clone(), file: i.file.clone(), line: i.line, snippet: i.snippet.clone(), cross_file: i.cross_file, chain: i.chain.clone(), cwe: i.cwe.clone(), owasp: i.owasp.clone(), tool: i.tool.clone(), references: if i.references.is_empty() { None } else { Some(serde_json::to_value(&i.references).unwrap()) }, duplicate_ref: i.duplicate_ref.clone() }
}

// `default_phase4_config` (this file used to define its own thin wrapper,
// hardcoding `fast: false`) is gone — candidate 2 of the architecture
// review. `crate::phase4_config::from_config` is the one real
// implementation (already deep, already tested); every call site now calls
// it directly with an explicit `fast` argument instead of going through two
// near-identical route-level wrappers. Onboarding (unlike validate-all/the
// pre-push hook) never runs in lightning mode, so its call sites — here and
// in `pipeline_interactive/run.rs`, which used to import this wrapper —
// pass `false` explicitly.

/// The API-key scopes an onboard request needs: it always scans, overrides
/// need `override`, and a real (non-dry) run publishes.
fn onboard_scopes(body: &Value, dry_run: bool) -> Vec<crate::auth::Scope> {
    let mut needed = vec![crate::auth::Scope::Scan];
    if crate::auth::body_submits_overrides(body) {
        needed.push(crate::auth::Scope::Override);
    }
    if !dry_run {
        needed.push(crate::auth::Scope::Publish);
    }
    needed
}

async fn run_onboard(state: Arc<AppState>, headers: axum::http::HeaderMap, body: Value) -> Result<Value, (StatusCode, Value)> {
    let org = body.get("org").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let repo = body.get("repo").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let phase_meta = resolve_phase_meta(&state.config);
    let is_gxp = phase_enabled(&phase_meta, 2) && body.get("gxp").and_then(|v| v.as_bool()).unwrap_or(false);
    let run_local_ci = body.get("runLocalCi").and_then(|v| v.as_bool()).unwrap_or(true);
    let dry_run = body.get("dryRun").and_then(|v| v.as_bool()).unwrap_or(false);
    let warning_decision = body.get("warningDecision").and_then(|v| v.as_str()).unwrap_or("continue").to_lowercase();
    let raw_project_path = body.get("projectPath").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let raw_project_path = if raw_project_path.is_empty() { std::env::current_dir().unwrap_or_default().to_string_lossy().into_owned() } else { raw_project_path };
    let gxp_links = body.get("gxpLinks").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let requested_overrides: Vec<SubmittedOverride> = body
        .get("overrides")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().map(|o| SubmittedOverride { 
            issue_id: o.get("issueId").and_then(|v| v.as_str()).unwrap_or("").to_string(), 
            justification: o.get("justification").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            code: o.get("code").and_then(|v| v.as_str()).map(|s| s.to_string()),
        }).collect())
        .unwrap_or_default();

    // An API key limited to fewer scopes can't run, override or publish beyond them.
    crate::auth::require_scopes(&headers, &state.db, &onboard_scopes(&body, dry_run))?;

    // Provisioning (Phase 6) must run as the actual caller's own GitHub
    // account — fail fast rather than burning phases 1-5 first.
    let gh_token = if dry_run { String::new() } else { crate::auth::resolve_effective_github_token(&headers, &state.db) };
    if !dry_run && gh_token.is_empty() {
        return Err((StatusCode::UNAUTHORIZED, crate::auth::github_token_missing_body("onboard for real")));
    }

    // How this caller authenticated, recorded on every override it submits.
    let origin = crate::auth::resolve_auth_method(&headers, &state.db).origin();

    let project_path = match ignite_tool_runner::sanitize_absolute_project_path(&raw_project_path) {
        Ok(p) => p,
        Err(e) => return Err((StatusCode::BAD_REQUEST, json!({ "error": e.to_string() }))),
    };

    // Scoped idempotency, same contract as validate-all (US-04): a caller
    // that re-sends the identical request under the same `idempotencyKey`
    // (an agent retrying after a dropped connection, say) gets a reference to
    // the run that key already started instead of a second scan and — worse,
    // for a real onboard — a second provision and push. The same key with a
    // different body is a 409. Only consulted for well-formed org/repo names,
    // so garbage names never create a repository row here.
    let idempotency_key = body.get("idempotencyKey").and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
    if let Some(key) = idempotency_key.as_deref() {
        if GITHUB_NAME_RE.is_match(&org) && REPO_NAME_RE.is_match(&repo) && repo != "." && repo != ".." {
            let repository_id = state.db.resolve_repository(&org, &repo, None);
            if let Some(existing) = state.db.find_scan_run_by_idempotency(repository_id, key) {
                if existing.payload_hash != super::pipeline_validate::idempotency_payload_hash(&body) {
                    return Err((
                        StatusCode::CONFLICT,
                        json!({
                            "ok": false,
                            "error": "idempotencyKey was already used with a different request payload. Use a new key for a new attempt (for example after adding overrides).",
                            "conflict": true,
                            "jobId": existing.legacy_job_id,
                        }),
                    ));
                }
                if let Some(pid) = existing.legacy_project_id {
                    if let Some(details) = state.db.get_project_details(pid) {
                        return Ok(json!({
                            "ok": details.project.status != "failed",
                            "mode": "onboard",
                            "idempotent": true,
                            "dryRun": dry_run,
                            "jobId": existing.legacy_job_id,
                            "projectId": pid,
                            // The original run may still be going; poll GET /api/pipeline/:jobId/status.
                            "inProgress": details.project.status == "running",
                            "repoUrl": details.project.repo_url,
                            "prUrl": details.project.pr_url,
                            "effectivatable": state.db.get_pending_effectivation(pid).is_some(),
                            "project": details.project,
                            "phases": details.steps,
                        }));
                    }
                }
            }
        }
    }

    let job_id = super::async_jobs::injected_job_id(&body).unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    tracing::info!(job_id = %job_id, org = %org, repo = %repo, project_path = %project_path.display(), "starting onboard pipeline run");
    let staging_dir = std::env::temp_dir().join("gatekeeper-staging").join(format!("{job_id}-onboard"));
    let source_backup_dir = std::path::PathBuf::from(format!("{}-source-backup", staging_dir.to_string_lossy()));
    let publish_dir = std::path::PathBuf::from(format!("{}-publish", staging_dir.to_string_lossy()));
    let workflow_dir = std::path::PathBuf::from(format!("{}-workflows", staging_dir.to_string_lossy()));

    let logger = Logger { state: state.clone(), meta: phase_meta.clone(), inner: Arc::new(Mutex::new(PipelineState { record: HashMap::new(), events: vec![], project_id: None })), job_id: job_id.clone() };
    let mut project_root: Option<std::path::PathBuf> = None;
    let mut project_id: i64 = 0;
    let mut run_id: Option<i64> = None;
    let mut repo_url: Option<String> = None;
    let mut pr_url: Option<String> = None;
    // Declared outside the pipeline block so a *failed* run can still report
    // the coverage it collected and the policy decision it reached.
    let mut coverage: Vec<ignite_policy::CheckCoverage> = Vec::new();
    let mut policy_out: Option<ignite_policy::PolicyDecision> = None;
    // Set on a dry run whose validated snapshot is now registered for
    // `POST /api/projects/:id/effectivate`.
    let mut effectivatable = false;

    // See pipeline_validate.rs's identical comment: without catch_unwind
    // here, a panic anywhere inside this block would skip the staging-dir/
    // walk-cache cleanup below entirely, leaking both for the rest of the
    // process's lifetime and violating this codebase's own "always removed
    // regardless of success or failure" hardening invariant.
    let result: Result<(), PipelineError> = match std::panic::AssertUnwindSafe(async {
        logger.status(1, "running", None);
        if !GITHUB_NAME_RE.is_match(&org) {
            return Err(PipelineError::new(1, format!("Invalid GitHub organization name: \"{org}\"")));
        }
        if !REPO_NAME_RE.is_match(&repo) || repo == "." || repo == ".." {
            return Err(PipelineError::new(1, format!("Invalid repository name: \"{repo}\"")));
        }
        logger.log(1, &format!("Onboarding job {job_id}"));
        logger.log(1, &format!("Source project path: {}", project_path.display()));
        logger.log(1, &format!("Target: {org}/{repo} (private)"));
        logger.log(1, &format!("GxP-regulated process: {}", if is_gxp { "YES" } else { "no" }));
        if dry_run {
            logger.log(1, "Simulation mode (dryRun) — phase 6 provisioning/push will be skipped.");
        }
        let source = if body.get("_client_is_mcp").and_then(|v| v.as_bool()).unwrap_or(false) { "mcp" } else { "api" };
        project_id = state.db.create_project(&job_id, &org, &repo, is_gxp, source, Some(&project_path.to_string_lossy())).map_err(|e| PipelineError::new(1, format!("Failed to create project record: {e}")))?;
        run_id = state.db.get_scan_run_for_legacy_project(project_id).map(|r| r.id);
        if let Some(rid) = run_id {
            state.db.transition_scan_run_or_warn(rid, ignite_run_lifecycle::RunLifecycleState::Scanning);
            if let Some(key) = idempotency_key.as_deref() {
                state.db.set_scan_run_idempotency(rid, key, &super::pipeline_validate::idempotency_payload_hash(&body));
            }
        }
        logger.set_project_id(project_id);
        logger.status(1, "success", None);

        if !is_gxp {
            logger.log(2, "Process declared non-GxP — no validation documents required.");
            logger.status(2, "skipped", None);
        } else {
            logger.status(2, "running", None);
            let mut valid_links = Vec::new();
            for l in &gxp_links {
                let url = l.get("url").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
                let parsed = url::Url::parse(&url).ok();
                let is_http = parsed.as_ref().map(|p| p.scheme() == "http" || p.scheme() == "https").unwrap_or(false);
                if !is_http {
                    return Err(PipelineError::new(2, format!("Invalid GxP document link: \"{url}\" (must be http/https).")));
                }
                let name = l.get("name").and_then(|v| v.as_str()).filter(|s| !s.trim().is_empty()).map(str::to_string).unwrap_or_else(|| parsed.as_ref().map(|p| format!("{}{}", p.host_str().unwrap_or(""), p.path())).unwrap_or_default());
                valid_links.push((name, url));
            }
            if valid_links.is_empty() {
                return Err(PipelineError::new(2, "GxP process declared but no gxpLinks provided in API payload."));
            }
            for (name, url) in &valid_links {
                state.db.add_link_document(project_id, name, url);
            }
            logger.log(2, &format!("Received {} GxP document link(s) for validation context.", valid_links.len()));
            logger.status(2, "success", None);
        }

        logger.status(3, "running", None);
        ignite_staging::stage_existing_project(&project_path.to_string_lossy(), &staging_dir).map_err(|e| PipelineError::new(3, e.to_string()))?;
        let root = ignite_staging::resolve_project_root(&staging_dir).map_err(|e| PipelineError::new(3, e.to_string()))?;
        project_root = Some(root.clone());

        ignite_staging::clone_directory_without_symlinks(&root, &source_backup_dir).map_err(|e| PipelineError::new(3, e.to_string()))?;
        logger.log(3, "Created immutable source snapshot for final publish phase.");

        let client = ignite_deps_dev_client::DepsDevClient::new();
        let npm_http = reqwest::Client::new();
        let l3a = logger.clone();
        let license_issues = ignite_pipeline_core::run_license_and_dependency_scan(&root, &state.runner, &client, &npm_http, &state.db, Some(project_id), move |m| l3a.log(3, m)).await;

        {
            let l3b = logger.clone();
            ignite_pipeline_core::run_env_and_codeowners_checks(&root, "Remove them before onboarding.", move |m| l3b.log(3, m)).map_err(|e| PipelineError::new(3, e.to_string()))?;
        }
        {
            let l3c = logger.clone();
            ignite_unit_test_runner::run_project_unit_tests(&root, &state.runner, move |m| l3c.log(3, m)).await.map_err(|e| PipelineError::new(3, e.to_string()))?;
        }
        logger.status(3, "success", None);

        logger.status(4, "running", None);
        let mut issues: Vec<Issue> = license_issues.clone();
        coverage.push(ignite_policy::CheckCoverage::completed("dependency-vulnerability", "deps.dev", false));
        if !phase_enabled(&phase_meta, 4) {
            logger.log(4, "Skipped — disabled by config (phases: [{ id: 4, enabled: false }]).");
            coverage.push(ignite_policy::CheckCoverage::disabled("phase4"));
        } else {
            let config = crate::phase4_config::from_config(&state.config, &org, &repo, Some(project_id), false, Some(project_path.clone()));
            let output = ignite_phase4_orchestrator::run_phase4_checks(&root, &state.runner, &state.db, &config, &state.package_hallucination_checker, &|m: &str| logger.log(4, m))
                .await
                .map_err(|e| PipelineError::new(4, e.to_string()))?;
            coverage.extend(output.coverage);
            issues = output.issues;
            issues.extend(license_issues);
        }
        let issue_inputs: Vec<ignite_db_store::IssueInput> = issues.iter().map(issue_to_input).collect();
        state.db.replace_project_issues(project_id, &issue_inputs, &HashSet::new());

        let error_issues: Vec<&Issue> = issues.iter().filter(|i| i.severity == Severity::Error).collect();
        let issues_requiring_override: Vec<&Issue> = if warning_decision == "continue" { error_issues } else { issues.iter().collect() };
        let mut applied_override_ids: HashSet<String> = HashSet::new();

        if !issues_requiring_override.is_empty() {
            let owned: Vec<Issue> = issues_requiring_override.iter().map(|i| (*i).clone()).collect();
            let plan = ignite_pipeline_core::plan_overrides(&state.db, &owned, &requested_overrides, &ignite_pipeline_core::PlanOverridesRequest { project_id, dual_custody_enabled: state.config.security.override_approval.enabled });
            if !plan.applied.is_empty() || !plan.needs_approval.is_empty() {
                let Some(actor) = resolve_actor(&headers, &state.db) else {
                    return Err(PipelineError::new(4, "Overrides were submitted but no authenticated user or actor {email,name} was provided — cannot attribute the audit record."));
                };

                // Dual-custody: a critical-severity override submitted
                // during onboarding must not resolve its issue until a
                // *different* reviewer approves it — same
                // `security.overrideApproval` gate every other override
                // submission site applies (`plan_overrides` already
                // computed the partition above).
                logger.log(4, &format!("⚠ {} flagged issue(s) overridden by {}:", plan.applied.len(), actor.email));
                let override_email_sent = if !plan.applied.is_empty() {
                    let notif_applied: Vec<ignite_notifications::AppliedOverride> = plan.applied.iter().map(|(issue, justification)| {
                        ignite_notifications::AppliedOverride {
                            issue: ignite_notifications::IssueLike {
                                severity: match issue.severity { Severity::Error => "error", Severity::Warning => "warning" },
                                category: &issue.category,
                                file: issue.file.as_deref(),
                                line: issue.line,
                                summary: &issue.summary,
                            },
                            justification,
                        }
                    }).collect();
                    let notif_titles = ignite_notifications::phase_titles_map(&logger.meta.iter().map(|p| (p.id, p.title.clone())).collect::<Vec<_>>());
                    match ignite_notifications::send_override_notification(
                        &state.config.notifications,
                        &notif_titles,
                        &ignite_notifications::OverrideEmailDetails {
                            job_id: &job_id,
                            org: &org,
                            repo: &repo,
                            phase: 4,
                            actor: ignite_notifications::Actor { name: Some(&actor.name), email: &actor.email },
                            applied: &notif_applied,
                        },
                    ).await {
                        Ok(r) if r.sent => {
                            logger.log(4, &format!("📧 Override notification emailed to {}.", r.to.as_deref().unwrap_or("?")));
                            true
                        }
                        Ok(_) => false,
                        Err(e) => {
                            tracing::warn!("Could not send override notification email: {e}");
                            false
                        }
                    }
                } else {
                    false
                };
                for (issue, justification) in &plan.applied {
                    logger.log(4, &format!("    ⚠ [override] [{:?}] {}:{} — {} — \"{justification}\"", issue.severity, issue.file.as_deref().unwrap_or(""), issue.line.unwrap_or(0), issue.summary));
                    applied_override_ids.insert(issue.id.clone());
                }
                let persist_req = ignite_pipeline_core::PersistOverridesRequest { project_id, job_id: &job_id, phase: 4, actor_email: &actor.email, actor_name: &actor.name, origin, email_sent: override_email_sent };
                ignite_pipeline_core::persist_applied_overrides(&state.db, &plan.applied, &persist_req);
                for (issue, justification) in &plan.applied {
                    state.emit_audit_event(
                        ignite_audit_log::AuditEvent::new("override.approved", "info", format!("override approved for {}: {}", issue.category, issue.summary))
                            .actor(actor.email.clone())
                            .repo(&org, &repo)
                            .metadata(json!({ "issueId": issue.id, "category": issue.category, "justification": justification, "origin": origin })),
                    );
                }
                state.db.replace_project_issues(project_id, &issue_inputs, &applied_override_ids);

                if !plan.needs_approval.is_empty() {
                    ignite_pipeline_core::persist_pending_overrides(&state.db, &plan.newly_pending, &ignite_pipeline_core::PersistOverridesRequest { project_id, job_id: &job_id, phase: 4, actor_email: &actor.email, actor_name: &actor.name, origin, email_sent: false });
                    for (issue, justification) in &plan.newly_pending {
                        state.emit_audit_event(
                            ignite_audit_log::AuditEvent::new("override.pending_approval", "warning", format!("critical override for {}: {} awaiting a second reviewer's approval", issue.category, issue.summary))
                                .actor(actor.email.clone())
                                .repo(&org, &repo)
                                .metadata(json!({ "issueId": issue.id, "category": issue.category, "justification": justification, "origin": origin })),
                        );
                    }
                    return Err(PipelineError::new(4, format!("{} critical finding(s) require a second reviewer's approval before this can ship. Ask another reviewer to approve them, then re-run.", plan.needs_approval.len())).blocked(
                        super::blocked::BlockReason::PendingApproval,
                        json!({
                            "pendingOverrides": state.db.list_pending_overrides(project_id).into_iter().map(|o| json!({
                                "overrideId": o.id,
                                "issueId": o.issue_id,
                                "submittedBy": o.actor_email,
                                "approveEndpoint": format!("/api/projects/{project_id}/overrides/{}/approve", o.id),
                            })).collect::<Vec<_>>(),
                            "approverMustDifferFrom": actor.email,
                        }),
                    ));
                }
            }
            if !plan.ok {
                logger.log(4, &format!("✗ {} blocking finding(s) were not overridden:", plan.unresolved_errors.len()));
                for issue in &plan.unresolved_errors {
                    let loc = issue.file.as_deref().map(|f| format!("{f}{}", issue.line.map(|l| format!(":{l}")).unwrap_or_default())).unwrap_or_else(|| "Phase 4".to_string());
                    logger.log(4, &format!("    ✗ [{}] {loc} — {}", issue.category, issue.summary));
                }
                state.emit_audit_event(
                    ignite_audit_log::AuditEvent::new("gate.push_rejected", "critical", format!("push rejected for {org}/{repo}: {} unresolved blocking finding(s)", plan.unresolved_errors.len()))
                        .repo(&org, &repo)
                        .metadata(json!({ "unresolvedCount": plan.unresolved_errors.len() })),
                );
                let mut e = PipelineError::new(4, format!("Phase 4 has {} unresolved blocking finding(s). Submit an override with a justification for each, or fix them.", plan.unresolved_errors.len()))
                    .blocked(super::blocked::BlockReason::UnresolvedFindings, json!({ "unresolvedIssueIds": plan.unresolved_errors.iter().map(|i| i.id.clone()).collect::<Vec<_>>() }));
                e.issues = Some(plan.unresolved_errors.into_iter().cloned().collect());
                return Err(e);
            }
        }
        logger.status(4, "success", None);
        // Onboard has no interactive review gate — a blocking finding is
        // either resolved synchronously via a body-supplied override
        // above (an early `return Err` otherwise) or there were none to
        // begin with, so reaching here always means "approved", the same
        // way `pipeline_interactive/run.rs`'s no-findings-needed-review
        // case reaches it directly from `Scanning`.
        if let Some(rid) = run_id {
            state.db.transition_scan_run_or_warn(rid, ignite_run_lifecycle::RunLifecycleState::Approved);
        }

        logger.status(5, "running", None);
        if !phase_enabled(&phase_meta, 5) {
            logger.log(5, "Skipped — disabled by config (phases: [{ id: 5, enabled: false }]).");
            logger.log(5, "⚠ The org governance workflows will still gate the repo on GitHub after push.");
            logger.status(5, "skipped", None);
            coverage.push(ignite_policy::CheckCoverage::disabled("governance-ci"));
        } else if !run_local_ci {
            logger.log(5, "Local CI execution disabled by request (runLocalCi=false).");
            logger.status(5, "skipped", None);
            coverage.push(ignite_policy::CheckCoverage::disabled_with_reason("governance-ci", "local CI disabled by request"));
        } else {
            let l5 = logger.clone();
            let gov = &state.config.governance;
            match ignite_pipeline_core::run_governance_ci_phase(&root, &workflow_dir, &state.runner, &state.db, &gov.repo, &gov.workflow, &gov.event, gov.timeout_minutes, move |m| l5.log(5, m)).await {
                Ok(ignite_pipeline_core::GovernanceCiOutcome::Skipped(reason)) => {
                    logger.log(5, &format!("⚠ Local CI skipped: {reason}"));
                    logger.log(5, "⚠ The org governance workflows will still gate the repo on GitHub after push.");
                    logger.status(5, "success", None);
                    coverage.push(ignite_policy::CheckCoverage::unavailable("governance-ci", reason));
                }
                Ok(ignite_pipeline_core::GovernanceCiOutcome::Passed) => {
                    logger.log(5, "✓ All org governance jobs passed locally.");
                    logger.status(5, "success", None);
                    coverage.push(ignite_policy::CheckCoverage::completed("governance-ci", "act", false));
                }
                Err(e) => {
                    coverage.push(ignite_policy::CheckCoverage::failed("governance-ci", e.clone()));
                    return Err(PipelineError::new(5, e));
                }
            }
        }

        // Onboarding has already resolved every blocking finding before it
        // reaches this point. Coverage can still make the decision
        // incomplete under the explicitly configured strict profile; in
        // that case stop before Phase 6 rather than publishing an
        // insufficiently assessed snapshot.
        let policy_decision = crate::routes::policy_finalization::finalize(state.as_ref(), run_id, &coverage, false, false);
        policy_out = Some(policy_decision.clone());
        if !policy_decision.permits_publication() {
            let mut e = PipelineError::new(5, format!("Policy decision '{:?}' prevents publication: {}", policy_decision.decision, policy_decision.reasons.join("; ")));
            if let Some(reason) = super::blocked::reason_for_policy_decision(&policy_decision) {
                e = e.blocked(reason, super::blocked::policy_details(&policy_decision));
            }
            return Err(e);
        }

        if dry_run {
            logger.log(6, "Simulation mode (dryRun) — all checks passed; skipping repository provisioning and push.");
            logger.status(6, "skipped", None);
            // Before `finish_project` — see `pipeline_validate.rs`'s
            // identical comment on why the ordering matters.
            if let Some(rid) = run_id {
                state.db.transition_scan_run_or_warn(rid, ignite_run_lifecycle::RunLifecycleState::Completed);
            }
            state.db.finish_project("success", None, None, None, project_id);

            // Keep the exact validated snapshot so `effectivate_project` can
            // publish it later without re-running phases 1-5 — the MCP tool
            // is documented to follow `onboard_project(dryRun: true)`, which
            // previously registered nothing (the backup was deleted below and
            // no project id was returned). Copied out of the OS temp dir
            // into the data dir so it survives temp cleanup and a restart.
            for expired in state.db.take_expired_pending_effectivations() {
                let _ = std::fs::remove_dir_all(&expired.source_dir);
            }
            let durable_dir = super::pipeline_interactive::ignite_data_dir().join("pending-effectivations").join(project_id.to_string());
            let copied = durable_dir.parent().map(std::fs::create_dir_all).transpose().is_ok() && {
                let _ = std::fs::remove_dir_all(&durable_dir);
                ignite_staging::clone_directory_without_symlinks(&source_backup_dir, &durable_dir).is_ok()
            };
            if copied {
                state.pending_effectivations.lock().insert(project_id, crate::state::PendingEffectivation { org: org.clone(), repo: repo.clone(), source_backup_dir: durable_dir.clone(), created_at: std::time::Instant::now() });
                state.db.set_snapshot_lease(project_id, "pending_effectivation", 24);
                state.db.save_pending_effectivation(project_id, &org, &repo, &durable_dir.to_string_lossy(), 24);
                effectivatable = true;
                logger.log(6, "Validated snapshot kept for 24h — call effectivate to publish exactly this tree without re-running the checks.");
            } else {
                logger.log(6, "⚠ Could not keep the validated snapshot for effectivation; re-run without dryRun to publish.");
            }
        } else {
            logger.status(6, "running", None);
            if !source_backup_dir.is_dir() {
                return Err(PipelineError::new(6, "Immutable source snapshot is missing before phase 6."));
            }
            if let Some(rid) = run_id {
                state.db.transition_scan_run_or_warn(rid, ignite_run_lifecycle::RunLifecycleState::Publishing);
            }
            let _ = std::fs::remove_dir_all(&publish_dir);
            ignite_staging::clone_directory_without_symlinks(&source_backup_dir, &publish_dir).map_err(|e| PipelineError::new(6, e.to_string()))?;
            logger.log(6, "Prepared clean publish workspace from immutable source snapshot.");

            let l6 = logger.clone();
            ignite_shipping::archive_phase6_payload(&publish_dir, Some(project_id), &state.runner, &state.db, move |m| l6.log(6, m)).await;

            let ship_config = ignite_shipping::ShippingConfig::default();
            let l6b = logger.clone();
            let ship_result = ignite_shipping::ship_to_github(&publish_dir, &org, &repo, &gh_token, &state.runner, &gh_api_for_ship(&state), &ship_config, move |m| l6b.log(6, m)).await.map_err(|e| PipelineError::new(6, e.to_string()))?;
            logger.log(6, &format!("✓ Repository live at {}", ship_result.repo_url));
            logger.status(6, "success", Some(json!({ "repoUrl": ship_result.repo_url, "prUrl": ship_result.pr_url })));
            repo_url = Some(ship_result.repo_url);
            pr_url = ship_result.pr_url;

            if let Some(rid) = run_id {
                state.db.transition_scan_run_or_warn(rid, ignite_run_lifecycle::RunLifecycleState::Published);
            }
            state.db.finish_project("success", None, repo_url.as_deref(), pr_url.as_deref(), project_id);
        }

        Ok(())
    })
    .catch_unwind()
    .await
    {
        Ok(r) => r,
        Err(panic) => Err(PipelineError::new(0, format!("internal error: {}", panic_message(&*panic)))),
    };

    let phases = logger.phase_summary();
    let events = logger.events();

    ignite_fs_utils::invalidate_walk_cache(&staging_dir);
    if let Some(root) = &project_root {
        ignite_fs_utils::invalidate_walk_cache(root);
    }
    let _ = std::fs::remove_dir_all(&staging_dir);
    let _ = std::fs::remove_dir_all(&source_backup_dir);
    let _ = std::fs::remove_dir_all(&publish_dir);
    let _ = std::fs::remove_dir_all(&workflow_dir);

    // The `Ok(())` (success) cases already set their precise terminal
    // state (`Completed`/`Published`) inline above, before their
    // respective `finish_project` calls — only the failure case still
    // needs to be classified here.
    if let (Some(rid), Err(e)) = (run_id, &result) {
        let target = if e.issues.is_some() { ignite_run_lifecycle::RunLifecycleState::Blocked } else { ignite_run_lifecycle::RunLifecycleState::Failed };
        state.db.transition_scan_run_or_warn(rid, target);
    }

    match result {
        Ok(()) => Ok(json!({
            "ok": true,
            "mode": "onboard",
            "dryRun": dry_run,
            "jobId": job_id,
            "projectId": project_id,
            "projectPath": project_path,
            "repoUrl": repo_url,
            "prUrl": pr_url,
            // Present on every pipeline entry point since US-02; onboard used
            // to omit both, leaving an agent unable to see what was assessed.
            "coverage": coverage,
            "policyDecision": policy_out,
            // `true` only when a dry run's snapshot is registered, i.e. the
            // `effectivate_project` call the agent would make next can work.
            "effectivatable": effectivatable,
            "phases": phases,
            "events": events,
        })),
        Err(e) => {
            logger.log(e.phase, &format!("✗ {}", e.message));
            logger.status(e.phase, "failed", Some(json!({ "error": e.message })));
            state.db.finish_project("failed", Some(&e.message), None, None, project_id);

            // Best-effort failure notification — never blocks pipeline
            // response or cleanup.
            {
                let record_snapshot: Vec<(i64, String, Vec<String>)> = {
                    let inner = logger.inner.lock().unwrap();
                    inner.record.iter().map(|(k, v)| (*k, v.state.clone(), v.logs.clone())).collect()
                };
                let notif_record = ignite_notifications::phase_tuples_to_state(&record_snapshot);
                let notif_titles = ignite_notifications::phase_titles_map(&logger.meta.iter().map(|p| (p.id, p.title.clone())).collect::<Vec<_>>());
                match ignite_notifications::send_failure_notification(
                    &state.config.notifications,
                    &notif_titles,
                    &ignite_notifications::FailureEmailDetails {
                        job_id: &job_id,
                        org: &org,
                        repo: &repo,
                        error: &e.message,
                        failed_phase: e.phase,
                        record: &notif_record,
                        insight: None,
                    },
                ).await {
                    Ok(r) if r.sent => {
                        logger.log(e.phase, &format!("📧 Failure report emailed to {}.", r.to.as_deref().unwrap_or("?")));
                    }
                    Ok(_) => {}
                    Err(mail_err) => {
                        tracing::warn!("Could not send failure email: {mail_err}");
                    }
                }
            }

            let phases = logger.phase_summary();
            let events = logger.events();
            let body = json!({
                "ok": false,
                "mode": "onboard",
                "dryRun": dry_run,
                "jobId": job_id,
                "projectId": (project_id != 0).then_some(project_id),
                "projectPath": project_path,
                "error": e.message,
                "failedPhase": e.phase,
                "issues": e.issues.map(|list| list.iter().map(|i| serde_json::to_value(i).unwrap()).collect::<Vec<_>>()),
                // Coverage collected up to the failure point; not final when
                // the run stopped before Phase 5.
                "coverage": coverage,
                "policyDecision": policy_out,
                "phases": phases,
                "events": events,
            });
            let body = match e.block {
                Some((reason, details)) => super::blocked::with_block_info(body, reason, details),
                None => body,
            };
            Err((StatusCode::BAD_REQUEST, body))
        }
    }
}

// GithubApi<'_> borrows the ToolRunner it's constructed from, so it can't
// be built once up front and stored on Logger/state alongside the other
// already-borrowed uses of state.runner in the same async fn — built
// fresh at the one call site that needs it instead.
fn gh_api_for_ship(state: &AppState) -> ignite_github_api::GithubApi<'_> {
    ignite_github_api::GithubApi::new(&state.runner)
}

async fn onboard(State(state): State<Arc<AppState>>, crate::auth::OptionalUser(user): crate::auth::OptionalUser, headers: axum::http::HeaderMap, Json(mut body): Json<Value>) -> Response {
    super::async_jobs::strip_client_job_id(&mut body);
    if super::async_jobs::wants_async(&body) {
        // Scopes are checked here too so a rejected key gets its 403 now,
        // not through a poll; everything else is reported through the result.
        let dry_run = body.get("dryRun").and_then(|v| v.as_bool()).unwrap_or(false);
        if let Err((status, denied)) = crate::auth::require_scopes(&headers, &state.db, &onboard_scopes(&body, dry_run)) {
            return (status, Json(denied)).into_response();
        }
        return super::async_jobs::start(state, "onboard", user.map(|u| u.id), headers, body, |state, headers, body| async move {
            match run_onboard(state, headers, body).await {
                Ok(v) => (200, v),
                Err((status, v)) => (status.as_u16(), v),
            }
        });
    }
    match run_onboard(state, headers, body).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err((status, v)) => (status, Json(v)).into_response(),
    }
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/pipeline/onboard", post(onboard))
}
