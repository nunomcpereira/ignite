//! POST /api/pipeline/validate-all — faithful port of
//! routes/pipeline-validate.js: a synchronous JSON pipeline run,
//! phases 1-5 only (always skips shipping), for agent/CI callers that
//! want pass/fail without a real push.
//!
//! Known gaps vs. the JS original:
//! per-Phase-4-task timing breakdown (`__taskTimings`) isn't tracked,
//! only top-level stage timings; GxP (Phase 2) document links are
//! accepted/validated but not persisted as real documents (no
//! addUploadDocument wiring yet).

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
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

static GITHUB_NAME_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$").unwrap());
static REPO_NAME_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9._-]{1,100}$").unwrap());

use crate::routes::phase_meta::{phase_enabled, phase_title, resolve_phase_meta, PhaseMeta};

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
        let mut inner = self.inner.lock().unwrap();
        inner.project_id = Some(id);
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

/// A resolved session/API-key identity always wins over the request
/// body's own `actor` field — trusting the body outright would let any
/// caller attribute an override to an arbitrary email, spoofing the audit
/// trail. The body-supplied actor is only ever used as a fallback for a
/// genuinely unauthenticated deployment (headless CI with no session and
/// no API key configured), matching this endpoint's documented "agent/CI
/// callers" use case.
fn resolve_actor(headers: &axum::http::HeaderMap, db: &ignite_db_store::DbStore, body: &Value) -> Option<(String, String)> {
    let session_user = crate::auth::resolve_user(headers, db);
    let body_email = body.get("actor").and_then(|a| a.get("email")).and_then(|v| v.as_str());
    let body_name = body.get("actor").and_then(|a| a.get("name")).and_then(|v| v.as_str());
    // `allow_unauth_body_actor: true` — this endpoint's documented
    // agent/CI use case: a genuinely unauthenticated deployment with no
    // session may still self-declare an actor. See
    // `ignite_pipeline_core::resolve_actor`'s own doc comment for why
    // `pipeline_onboard.rs` deliberately passes `false` here instead.
    ignite_pipeline_core::resolve_actor(session_user.as_ref().map(|u| u.email.as_str()), session_user.as_ref().and_then(|u| u.name.as_deref()), body_email, body_name, true).map(|a| (a.email, a.name))
}

struct StageTiming {
    name: &'static str,
    ms: u128,
}

async fn time_stage<T, F: std::future::Future<Output = T>>(timings: &Mutex<Vec<StageTiming>>, name: &'static str, fut: F) -> T {
    let t0 = Instant::now();
    let r = fut.await;
    timings.lock().unwrap().push(StageTiming { name, ms: t0.elapsed().as_millis() });
    r
}

struct PipelineError {
    phase: i64,
    message: String,
    issues: Option<Vec<Issue>>,
}

impl PipelineError {
    fn new(phase: i64, message: impl Into<String>) -> Self {
        PipelineError { phase, message: message.into(), issues: None }
    }
}

// `panic_message` moved to `ignite_pipeline_core` (candidate 2 of the
// architecture review): this file and `pipeline_onboard.rs` each carried a
// byte-identical copy.
use ignite_pipeline_core::panic_message;

#[cfg(test)]
mod panic_message_tests {
    use super::panic_message;

    /// Regression test for the actual bug: proves the exact
    /// catch_unwind-then-cleanup pattern used around `run_validate_all`'s
    /// inner async block actually prevents a panic from skipping cleanup —
    /// the staging directory and its `WALK_CACHE` entry must both be gone
    /// even though the "scan" panicked partway through.
    #[tokio::test]
    async fn catch_unwind_pattern_still_cleans_up_after_a_panic() {
        use futures::FutureExt;

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("f.txt"), "x").unwrap();
        let staging_dir = dir.path().to_path_buf();
        // Populate the real WALK_CACHE the same way a real scan would.
        ignite_fs_utils::walk_files(&staging_dir).unwrap();

        let result: Result<(), String> = match std::panic::AssertUnwindSafe(async {
            panic!("simulated scan panic");
            #[allow(unreachable_code)]
            Ok(())
        })
        .catch_unwind()
        .await
        {
            Ok(r) => r,
            Err(panic) => Err(panic_message(&*panic)),
        };

        ignite_fs_utils::invalidate_walk_cache(&staging_dir);
        let _ = std::fs::remove_dir_all(&staging_dir);

        assert_eq!(result, Err("simulated scan panic".to_string()));
        assert!(!staging_dir.exists(), "staging dir must be removed even though the scan panicked");

        // Recreate the same path with different content: if the cache
        // entry hadn't actually been evicted, this would still return the
        // stale pre-panic [f.txt] list instead of re-walking.
        std::fs::create_dir_all(&staging_dir).unwrap();
        std::fs::write(staging_dir.join("g.txt"), "y").unwrap();
        let files = ignite_fs_utils::walk_files(&staging_dir).unwrap();
        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("g.txt"), "cache must not have served the stale pre-panic file list");
    }
}

#[allow(clippy::result_large_err)]
async fn run_validate_all(state: Arc<AppState>, headers: axum::http::HeaderMap, body: Value) -> Result<Value, (Value, Value)> {
    let org = body.get("org").and_then(|v| v.as_str()).unwrap_or("local-validation").trim().to_string();
    let org = if org.is_empty() { "local-validation".to_string() } else { org };
    let repo = body.get("repo").and_then(|v| v.as_str()).unwrap_or("local-project").trim().to_string();
    let repo = if repo.is_empty() { "local-project".to_string() } else { repo };
    // How this caller authenticated, recorded on every override it submits.
    let origin = crate::auth::resolve_auth_method(&headers, &state.db).origin();
    let phase_meta = resolve_phase_meta(&state.config);
    let is_gxp = phase_enabled(&phase_meta, 2) && body.get("gxp").and_then(|v| v.as_bool()).unwrap_or(false);
    let run_local_ci = body.get("runLocalCi").and_then(|v| v.as_bool()).unwrap_or(true);
    let fast = body.get("fast").and_then(|v| v.as_bool()).unwrap_or(false);
    // Unattended sweeps (`scheduled-rescan`'s `rescan_one`, so the GitHub Org
    // view / auto-rescan too) scan repos whose own test suite Ignite has no
    // way to make runnable (missing deps, broken packaging, no Docker). A
    // failing project test run must not hide every Phase 4 security result
    // for such a repo, so it is downgraded to a logged warning
    // (`unitTestWarning` in the response). Off by default: the pre-push
    // hook/CLI/interactive paths keep it a hard Phase 3 failure.
    let unit_test_failures_non_blocking = body.get("unitTestFailuresNonBlocking").and_then(|v| v.as_bool()).unwrap_or(false);
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
    let changed_files: Option<std::collections::HashSet<String>> = body.get("changedFiles").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.trim().to_string())).filter(|s| !s.is_empty()).collect());
    let baseline_mode = body.get("baselineMode").and_then(|v| v.as_str()).filter(|m| *m == "gate" || *m == "save").map(str::to_string);
    let baseline_issue_ids = if baseline_mode.as_deref() == Some("gate") { Some(state.db.get_baseline_issue_ids(&org, &repo).unwrap_or_default()) } else { None };

    let project_path = match ignite_tool_runner::sanitize_absolute_project_path(&raw_project_path) {
        Ok(p) => p,
        Err(e) => return Err((json!({ "ok": false, "error": e.to_string() }), json!({}))),
    };

    // US-04: scoped idempotency — a caller (a CI retry after a dropped
    // connection, a pre-push hook re-invoked by a flaky shell) that
    // re-sends the exact same request with the same `idempotencyKey`
    // gets back a reference to the run that key already started, instead
    // of a second full pipeline execution; the same key with a genuinely
    // different payload is a conflict, not a replay. Scoped per
    // repository (not globally) so two different repos can't collide on
    // a caller-chosen key.
    if let Some(key) = body.get("idempotencyKey").and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty()) {
        let repository_id = state.db.resolve_repository(&org, &repo, None);
        let payload_hash = idempotency_payload_hash(&body);
        if let Some(existing) = state.db.find_scan_run_by_idempotency(repository_id, key) {
            if existing.payload_hash != payload_hash {
                return Err((
                    json!({ "ok": false, "error": "idempotencyKey was already used with a different request payload.", "conflict": true, "jobId": existing.legacy_job_id }),
                    json!({}),
                ));
            }
            if let Some(pid) = existing.legacy_project_id {
                if let Some(details) = state.db.get_project_details(pid) {
                    return Ok(json!({
                        "ok": details.project.status != "failed",
                        "mode": "validate-all",
                        "idempotent": true,
                        "jobId": existing.legacy_job_id,
                        "projectId": pid,
                        "project": details.project,
                        "phases": details.steps,
                        "issues": state.db.get_project_issues(pid),
                    }));
                }
            }
        }
    }

    let timings: Mutex<Vec<StageTiming>> = Mutex::new(Vec::new());
    let job_id = super::async_jobs::injected_job_id(&body).unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    tracing::info!(job_id = %job_id, org = %org, repo = %repo, project_path = %project_path.display(), "starting validate-all pipeline run");
    let staging_dir = std::env::temp_dir().join("gatekeeper-staging").join(format!("{job_id}-api-validation"));
    let workflow_dir_str = format!("{}-workflows", staging_dir.to_string_lossy());
    let workflow_dir = std::path::PathBuf::from(&workflow_dir_str);

    let logger = Logger { state: state.clone(), meta: phase_meta.clone(), inner: Arc::new(Mutex::new(PipelineState { record: HashMap::new(), events: vec![], project_id: None })), job_id: job_id.clone() };

    let mut project_root: Option<std::path::PathBuf> = None;
    let mut issues: Vec<Issue> = vec![];
    let mut unit_test_warning: Option<String> = None;
    let mut phase4_task_timings: Vec<(&'static str, u64)> = vec![];
    let mut phase4_coverage: Vec<ignite_policy::CheckCoverage> = vec![];
    let mut overridden_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut project_id: i64 = 0;
    let mut run_id: Option<i64> = None;

    // The staging directory / walk-cache cleanup below (`invalidate_walk_cache`
    // + `remove_dir_all`) previously ran as plain code after this block's
    // `.await` — meaning it only ever ran on a normal `Ok`/`Err` return, not
    // if anything inside the block panicked (a `.unwrap()`/`.expect()` deep
    // in any Phase 3/4 check, for instance). A panic would unwind straight
    // past the cleanup, leaking the staging directory on disk and its
    // `WALK_CACHE` entry in memory for the rest of the process's lifetime —
    // silently violating this codebase's own stated hardening invariant
    // ("Staging directories... are always removed regardless of success or
    // failure"). `catch_unwind` turns a panic into an `Err` here so the
    // existing cleanup code (unchanged below) still always runs.
    let result: Result<(), PipelineError> = match std::panic::AssertUnwindSafe(async {
        // Phase 1
        logger.status(1, "running", None);
        if !REPO_NAME_RE.is_match(&repo) || repo == "." || repo == ".." {
            return Err(PipelineError::new(1, format!("Invalid repository name: \"{repo}\"")));
        }
        if !GITHUB_NAME_RE.is_match(&org) && org != "local-validation" {
            return Err(PipelineError::new(1, format!("Invalid organization name: \"{org}\"")));
        }
        logger.log(1, &format!("Validation job {job_id}"));
        logger.log(1, &format!("Source project path: {}", project_path.display()));
        logger.log(1, &format!("Target metadata: {org}/{repo}"));
        logger.log(1, &format!("GxP-regulated process: {}", if is_gxp { "YES" } else { "no" }));
        let source = if body.get("_client_is_mcp").and_then(|v| v.as_bool()).unwrap_or(false) { "mcp" } else { "api" };
        project_id = state.db.create_project(&job_id, &org, &repo, is_gxp, source, Some(&project_path.to_string_lossy())).map_err(|e| PipelineError::new(1, format!("Failed to create project record: {e}")))?;
        run_id = state.db.get_scan_run_for_legacy_project(project_id).map(|r| r.id);
        if let Some(rid) = run_id {
            state.db.transition_scan_run_or_warn(rid, ignite_run_lifecycle::RunLifecycleState::Scanning);
            if let Some(key) = body.get("idempotencyKey").and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty()) {
                state.db.set_scan_run_idempotency(rid, key, &idempotency_payload_hash(&body));
            }
        }
        logger.set_project_id(project_id);
        logger.status(1, "success", None);

        // Phase 2
        if !is_gxp {
            logger.log(2, "Process declared non-GxP — no validation documents required.");
            logger.status(2, "skipped", None);
        } else {
            logger.status(2, "running", None);
            let mut valid_links = 0;
            for l in &gxp_links {
                let url = l.get("url").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
                let parsed = url::Url::parse(&url).ok();
                let is_http = parsed.as_ref().map(|p| p.scheme() == "http" || p.scheme() == "https").unwrap_or(false);
                if !is_http {
                    return Err(PipelineError::new(2, format!("Invalid GxP document link: \"{url}\" (must be http/https).")));
                }
                valid_links += 1;
            }
            if valid_links == 0 {
                return Err(PipelineError::new(2, "GxP process declared but no gxpLinks provided in API payload."));
            }
            logger.log(2, &format!("Received {valid_links} GxP document link(s) for validation context."));
            logger.status(2, "success", None);
        }

        // Phase 3
        logger.status(3, "running", None);
        let stage_result = time_stage(&timings, "stageExistingProject", async { ignite_staging::stage_existing_project(&project_path.to_string_lossy(), &staging_dir) }).await.map_err(|e| PipelineError::new(3, e.to_string()))?;
        let _ = stage_result;
        let root = ignite_staging::resolve_project_root(&staging_dir).map_err(|e| PipelineError::new(3, e.to_string()))?;
        project_root = Some(root.clone());
        // Justifications committed in the scanned repo itself. A caller
        // with a local checkout (CLI/pre-push/VS Code) already sends these
        // as `overrides`, but a server-side scan of a fresh clone (org scan,
        // scheduled rescan) has nobody to send them — without this, every
        // such scan re-flags findings the repo has long since justified.
        let file_overrides = repo_file_overrides(&project_path, &root, &requested_overrides);
        if !file_overrides.is_empty() {
            logger.log(3, &format!("Using {} justification(s) from the repository's {REPO_ACK_FILE}.", file_overrides.len()));
        }

        {
            let l3 = logger.clone();
            time_stage(&timings, "envAndCodeownersChecks", async { ignite_pipeline_core::run_env_and_codeowners_checks(&root, "Remove them before validation.", move |m| l3.log(3, m)) }).await.map_err(|e| PipelineError::new(3, e.to_string()))?;
        }
        {
            let l3 = logger.clone();
            match time_stage(&timings, "runProjectUnitTests", async { ignite_unit_test_runner::run_project_unit_tests(&root, &state.runner, move |m| l3.log(3, m)).await }).await {
                Ok(_) => {}
                Err(e) if unit_test_failures_non_blocking => {
                    let msg = e.to_string();
                    logger.log(3, &format!("⚠ Project unit tests failed — continuing (non-blocking for this scan): {msg}"));
                    unit_test_warning = Some(msg);
                }
                Err(e) => return Err(PipelineError::new(3, e.to_string())),
            }
        }
        logger.status(3, "success", None);

        // Phase 4
        logger.status(4, "running", None);
        let client = ignite_deps_dev_client::DepsDevClient::new();
        let npm_http = reqwest::Client::new();
        if !phase_enabled(&phase_meta, 4) {
            logger.log(4, "Skipped — disabled by config (phases: [{ id: 4, enabled: false }]).");
            logger.log(3, "Check 3 — dependency & license compliance scan (manifests + LICENSE files)...");
            let l3a = logger.clone();
            issues.extend(ignite_pipeline_core::run_license_and_dependency_scan(&root, &state.runner, &client, &npm_http, &state.db, Some(project_id), move |m| l3a.log(3, m)).await);
            phase4_coverage.push(ignite_policy::CheckCoverage::completed("dependency-vulnerability", "deps.dev", false));
        } else {
            logger.log(3, "Check 3 — dependency & license compliance scan (manifests + LICENSE files)...");
            let l3a = logger.clone();
            let l4 = logger.clone();
            let root_a = root.clone();
            let root_b = root.clone();
            let state_a = state.clone();
            let state_b = state.clone();
            let config = crate::phase4_config::from_config(&state.config, &org, &repo, Some(project_id), fast, Some(project_path.clone()));
            let (license_result, phase4_result) = tokio::join!(
                time_stage(&timings, "licenseAndDependencyScan", async move { ignite_pipeline_core::run_license_and_dependency_scan(&root_a, &state_a.runner, &client, &npm_http, &state_a.db, Some(project_id), move |m| l3a.log(3, m)).await }),
                time_stage(&timings, "phase4Total", async move { ignite_phase4_orchestrator::run_phase4_checks(&root_b, &state_b.runner, &state_b.db, &config, &state_b.package_hallucination_checker, &|m: &str| l4.log(4, m)).await })
            );
            match phase4_result {
                Ok(output) => {
                    issues.extend(output.issues);
                    phase4_task_timings.extend(output.task_timings);
                    phase4_coverage.extend(output.coverage);
                }
                Err(e) => return Err(PipelineError::new(4, e.to_string())),
            }
            issues.extend(license_result);
            phase4_coverage.push(ignite_policy::CheckCoverage::completed("dependency-vulnerability", "deps.dev", false));
        }

        let gated_issues: Vec<&Issue> = match baseline_mode.as_deref() {
            Some("gate") => {
                let ids = baseline_issue_ids.as_ref().unwrap();
                issues.iter().filter(|i| !ids.contains(&i.id)).collect()
            }
            _ => issues.iter().collect(),
        };
        let error_issues: Vec<&Issue> = gated_issues.iter().filter(|i| i.severity == Severity::Error).copied().collect();
        let issues_requiring_override: Vec<&Issue> = if warning_decision == "continue" { error_issues } else { gated_issues };

        if !issues_requiring_override.is_empty() {
            let owned: Vec<Issue> = issues_requiring_override.iter().map(|i| (*i).clone()).collect();
            // Dual-custody: a critical-severity override submitted here must
            // not resolve its issue until a *different* reviewer approves it —
            // same `security.overrideApproval` gate `routes/effectivate.rs`/
            // `pipeline_interactive/run.rs` apply, kept in sync here since
            // this is the other place a human submits a brand-new override.
            let all_requested: Vec<SubmittedOverride> = requested_overrides.iter().chain(file_overrides.iter()).cloned().collect();
            let plan = ignite_pipeline_core::plan_overrides(&state.db, &owned, &all_requested, &ignite_pipeline_core::PlanOverridesRequest { project_id, dual_custody_enabled: state.config.security.override_approval.enabled });
            // Overrides that came only from the repo file are recorded under
            // the file's own identity, never attributed to whoever triggered
            // the scan; the rest keep the existing caller-attributed flow.
            let from_file: std::collections::HashSet<&str> = file_overrides.iter().map(|o| o.issue_id.as_str()).collect();
            let is_file = |(issue, _): &(&Issue, String)| from_file.contains(issue.id.as_str());
            let file_applied: Vec<(&Issue, String)> = plan.applied.iter().filter(|o| is_file(o)).cloned().collect();
            let file_needs_approval = plan.needs_approval.iter().filter(|o| is_file(o)).count();
            let file_newly_pending: Vec<(&Issue, String)> = plan.newly_pending.iter().filter(|o| is_file(o)).cloned().collect();
            let plan = ignite_pipeline_core::OverridesPlan {
                ok: plan.ok,
                unresolved_errors: plan.unresolved_errors,
                applied: plan.applied.into_iter().filter(|o| !is_file(o)).collect(),
                needs_approval: plan.needs_approval.into_iter().filter(|o| !is_file(o)).collect(),
                newly_pending: plan.newly_pending.into_iter().filter(|o| !is_file(o)).collect(),
            };
            for (issue, _) in &file_applied {
                overridden_ids.insert(issue.id.clone());
            }
            if !file_applied.is_empty() || !file_newly_pending.is_empty() {
                let file_req = ignite_pipeline_core::PersistOverridesRequest { project_id, job_id: &job_id, phase: 4, actor_email: REPO_ACK_ACTOR_EMAIL, actor_name: REPO_ACK_ACTOR_NAME, origin: "repo_file", email_sent: false };
                ignite_pipeline_core::persist_applied_overrides(&state.db, &file_applied, &file_req);
                ignite_pipeline_core::persist_pending_overrides(&state.db, &file_newly_pending, &file_req);
                if !file_applied.is_empty() {
                    logger.log(4, &format!("⚠ {} flagged issue(s) justified in the repository's {REPO_ACK_FILE}:", file_applied.len()));
                }
                for (issue, justification) in &file_applied {
                    logger.log(4, &format!("    ⚠ [override] [{:?}] {}:{} — {} — \"{justification}\"", issue.severity, issue.file.as_deref().unwrap_or(""), issue.line.unwrap_or(0), issue.summary));
                    state.emit_audit_event(
                        ignite_audit_log::AuditEvent::new("override.approved", "info", format!("override from {REPO_ACK_FILE} for {}: {}", issue.category, issue.summary))
                            .actor(REPO_ACK_ACTOR_EMAIL)
                            .repo(&org, &repo)
                            .metadata(json!({ "issueId": issue.id, "category": issue.category, "justification": justification, "origin": "repo_file" })),
                    );
                }
            }
            if file_needs_approval > 0 {
                return Err(PipelineError::new(4, format!("{file_needs_approval} critical finding(s) justified in {REPO_ACK_FILE} require a second reviewer's approval before this can ship. Ask another reviewer to approve them, then re-run.")));
            }
            for (issue, _) in &plan.applied {
                overridden_ids.insert(issue.id.clone());
            }
            if !plan.applied.is_empty() || !plan.needs_approval.is_empty() {
                let Some((email, name)) = resolve_actor(&headers, &state.db, &body) else {
                    return Err(PipelineError::new(4, "Overrides were submitted but no authenticated user or actor {email,name} was provided — cannot attribute the audit record."));
                };

                logger.log(4, &format!("⚠ {} flagged issue(s) overridden by {email}:", plan.applied.len()));
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
                            actor: ignite_notifications::Actor { name: Some(&name), email: &email },
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
                }
                let persist_req = ignite_pipeline_core::PersistOverridesRequest { project_id, job_id: &job_id, phase: 4, actor_email: &email, actor_name: &name, origin, email_sent: override_email_sent };
                ignite_pipeline_core::persist_applied_overrides(&state.db, &plan.applied, &persist_req);
                for (issue, justification) in &plan.applied {
                    state.emit_audit_event(
                        ignite_audit_log::AuditEvent::new("override.approved", "info", format!("override approved for {}: {}", issue.category, issue.summary))
                            .actor(email.clone())
                            .repo(&org, &repo)
                            .metadata(json!({ "issueId": issue.id, "category": issue.category, "justification": justification, "origin": origin })),
                    );
                }

                if !plan.needs_approval.is_empty() {
                    ignite_pipeline_core::persist_pending_overrides(&state.db, &plan.newly_pending, &ignite_pipeline_core::PersistOverridesRequest { project_id, job_id: &job_id, phase: 4, actor_email: &email, actor_name: &name, origin, email_sent: false });
                    for (issue, justification) in &plan.newly_pending {
                        state.emit_audit_event(
                            ignite_audit_log::AuditEvent::new("override.pending_approval", "warning", format!("critical override for {}: {} awaiting a second reviewer's approval", issue.category, issue.summary))
                                .actor(email.clone())
                                .repo(&org, &repo)
                                .metadata(json!({ "issueId": issue.id, "category": issue.category, "justification": justification, "origin": origin })),
                        );
                    }
                    return Err(PipelineError::new(4, format!("{} critical finding(s) require a second reviewer's approval before this can ship. Ask another reviewer to approve them, then re-run.", plan.needs_approval.len())));
                }
            }
            if !plan.ok {
                logger.log(4, &format!("✗ {} blocking finding(s) were not overridden:", plan.unresolved_errors.len()));
                for issue in &plan.unresolved_errors {
                    let loc = issue.file.as_deref().map(|f| format!("{f}{}", issue.line.map(|l| format!(":{l}")).unwrap_or_default())).unwrap_or_else(|| "Phase 4".to_string());
                    logger.log(4, &format!("    ✗ [{}] {loc} — {}", issue.category, issue.summary));
                }
                let mut e = PipelineError::new(4, format!("Phase 4 has {} unresolved blocking finding(s). Submit an override with a justification for each, or fix them.", plan.unresolved_errors.len()));
                // Every error-severity issue the scan found, not just the
                // still-unresolved ones - a caller (e.g. the pre-push hook)
                // that regenerates a review file from this response needs
                // to know a successfully-overridden finding is still
                // reported by the scan, or it will drop that entry as if
                // the finding had been fixed in source and never resubmit
                // its justification on the next run, even though the
                // underlying finding is unchanged.
                e.issues = Some(owned);
                return Err(e);
            }
        }
        logger.status(4, "success", None);

        // Phase 5
        logger.status(5, "running", None);
        if !phase_enabled(&phase_meta, 5) {
            logger.log(5, "Skipped — disabled by config (phases: [{ id: 5, enabled: false }]).");
            logger.status(5, "skipped", None);
            phase4_coverage.push(ignite_policy::CheckCoverage::disabled("governance-ci"));
        } else if !run_local_ci {
            logger.log(5, "Local CI execution disabled by request (runLocalCi=false).");
            logger.status(5, "skipped", None);
            phase4_coverage.push(ignite_policy::CheckCoverage::disabled_with_reason("governance-ci", "local CI disabled by request"));
        } else {
            let root = project_root.clone().unwrap();
            let l5 = logger.clone();
            let gov = &state.config.governance;
            let gov_result = time_stage(&timings, "governanceCi", async {
                ignite_pipeline_core::run_governance_ci_phase(&root, &workflow_dir, &state.runner, &state.db, &gov.repo, &gov.workflow, &gov.event, gov.timeout_minutes, move |m| l5.log(5, m)).await
            })
            .await;
            match gov_result {
                Ok(ignite_pipeline_core::GovernanceCiOutcome::Skipped(reason)) => {
                    logger.log(5, &format!("⚠ Local CI skipped: {reason}"));
                    // Matches `pipeline_onboard.rs`/`pipeline_interactive/run.rs`'s
                    // treatment of "act tooling unavailable" as a
                    // non-blocking success (the org governance workflows
                    // still gate the repo on GitHub after push) — this
                    // route previously reported "skipped" here instead,
                    // the one behavioral divergence US-03's shared
                    // extraction surfaced across the three entry points.
                    logger.status(5, "success", None);
                    phase4_coverage.push(ignite_policy::CheckCoverage::unavailable("governance-ci", reason));
                }
                Ok(ignite_pipeline_core::GovernanceCiOutcome::Passed) => {
                    logger.log(5, "✓ All org governance jobs passed locally.");
                    logger.status(5, "success", None);
                    phase4_coverage.push(ignite_policy::CheckCoverage::completed("governance-ci", "act", false));
                }
                Err(e) => {
                    phase4_coverage.push(ignite_policy::CheckCoverage::failed("governance-ci", e.clone()));
                    return Err(PipelineError::new(5, e));
                }
            }
        }

        logger.log(6, "Shipping phase skipped in validate-all mode.");
        logger.status(6, "skipped", None);

        // US-05: the versioned evidence manifest — computed once the
        // source is fully staged and Phase 4 has finished (so
        // `phase4_coverage` reflects what actually ran this scan), while
        // the staging directory this run scanned still exists on disk
        // (cleanup, below, removes it once this closure returns).
        // `finalize_scan_run_snapshot` re-points this run's
        // `source_snapshots` row at the *real* content-addressed digest,
        // replacing the synthetic `unknown:project:<id>` placeholder
        // `create_project` had to use at Phase 1 (nothing was staged yet)
        // — two scans of byte-and-mode-identical source now share one
        // snapshot row, same as US-01 always intended.
        if let Some(rid) = run_id {
            match ignite_provenance::digest_project_tree(&root) {
                Ok(tree) => {
                    let repository_id = state.db.resolve_repository(&org, &repo, None);
                    let commit_sha = state
                        .runner
                        .run_tool("git", &["rev-parse".to_string(), "HEAD".to_string()], &root.to_string_lossy(), ignite_tool_runner::RunToolOptions::default())
                        .await
                        .ok()
                        .map(|o| o.stdout.trim().to_string())
                        .filter(|s| !s.is_empty());
                    let source_digest = format!("sha256:{}", tree.sha256);
                    state.db.finalize_scan_run_snapshot(rid, repository_id, &source_digest, commit_sha.as_deref());

                    let policy_version = if state.config.policy.strict { ignite_policy::PolicyVersion::strict_publication() } else { ignite_policy::PolicyVersion::legacy_compatible() };
                    let manifest = ignite_evidence::build_evidence_manifest(
                        source_digest,
                        tree.file_count,
                        commit_sha,
                        policy_version.id.clone(),
                        ignite_evidence::config_digest(&state.config),
                        phase4_coverage.clone(),
                        vec![],
                        ignite_evidence::now_iso8601(),
                    );
                    if let Ok(manifest_json) = serde_json::to_string(&manifest) {
                        state.db.save_evidence_manifest(rid, &manifest_json);
                    }
                }
                Err(e) => tracing::warn!("evidence: failed to compute snapshot digest for run {rid}: {e}"),
            }
        }

        // US-07: sync this run's issues against the repository's tracked
        // findings — fingerprint-keyed (line-drift-tolerant), not the raw
        // `category::file::line` id. Only a check whose coverage this run
        // says `Completed` gets to prove a prior finding for its tool is
        // gone; everything else (failed/disabled/unavailable/not-run) never
        // resolves a finding by omission. Wired into this one entry point
        // first, matching this backlog's established per-story precedent
        // (see CLAUDE.md's US-07 note).
        if let Some(rid) = run_id {
            let repository_id = state.db.resolve_repository(&org, &repo, None);
            let completed_tools: std::collections::HashSet<String> = phase4_coverage.iter().filter(|c| c.outcome == ignite_policy::CheckOutcome::Completed).filter_map(|c| c.engine.as_deref()).map(|e| e.to_ascii_lowercase()).collect();
            let observations: Vec<ignite_db_store::FindingObservationInput> = issues
                .iter()
                .map(|issue| {
                    let discriminator = ignite_override_engine::discriminator_from_issue_id(&issue.id);
                    let fingerprint = ignite_override_engine::stable_fingerprint(&issue.category, issue.file.as_deref(), issue.snippet.as_ref(), issue.line, discriminator.as_deref());
                    ignite_db_store::FindingObservationInput {
                        legacy_issue_id: issue.id.clone(),
                        category: issue.category.clone(),
                        fingerprint,
                        file: issue.file.clone(),
                        line: issue.line,
                        severity: match issue.severity {
                            Severity::Error => "error".to_string(),
                            Severity::Warning => "warning".to_string(),
                        },
                        tool: issue.tool.clone(),
                    }
                })
                .collect();
            state.db.record_finding_observations(repository_id, rid, &completed_tools, &observations);
        }

        // Set *before* `finish_project` — its own internal lifecycle sync
        // is a naive `"success" -> "published"` fallback that doesn't
        // know validate-all never publishes anything; a precise state set
        // first is never overwritten (terminal states reject any further
        // transition, `sync_scan_run_lifecycle`'s included).
        if let Some(rid) = run_id {
            state.db.transition_scan_run_or_warn(rid, ignite_run_lifecycle::RunLifecycleState::Completed);
        }
        // Persist to the `issues` table validate-all had never written to
        // before — a real gap this endpoint's own doc comment didn't flag,
        // found by chasing why a rescan_one-triggered run (the Onboarded
        // Repos/GitHub Org "Scan now" buttons, `scheduled-rescan`) always
        // came back with real findings in its HTTP response yet nothing
        // browsable in "View findings"/Ignite Studio afterward: this
        // endpoint already writes to the newer fingerprint-tracking
        // tables via `record_finding_observations` above, but every UI
        // read path (job_issues, Studio's historical reconstruction,
        // Onboarded Repos' findings count) still reads the older `issues`
        // table, which only `pipeline_onboard.rs`/`pipeline_interactive`
        // ever populated. Reuses `pipeline_onboard`'s own `issue_to_input`
        // mapping rather than a second copy.
        let issue_inputs: Vec<ignite_db_store::IssueInput> = issues.iter().map(crate::routes::pipeline_onboard::issue_to_input).collect();
        state.db.replace_project_issues(project_id, &issue_inputs, &overridden_ids);
        state.db.finish_project("success", None, None, None, project_id);
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
    let mut stage_timings: Vec<Value> = timings.into_inner().unwrap().into_iter().map(|t| json!({ "name": t.name, "ms": t.ms })).collect();
    stage_timings.extend(phase4_task_timings.into_iter().map(|(name, ms)| json!({ "name": format!("phase4:{name}"), "ms": ms })));

    ignite_fs_utils::invalidate_walk_cache(&staging_dir);
    if let Some(root) = &project_root {
        ignite_fs_utils::invalidate_walk_cache(root);
    }
    let _ = std::fs::remove_dir_all(&staging_dir);
    let _ = std::fs::remove_dir_all(&workflow_dir);

    // The `Ok(())` (success) case already set its precise terminal state
    // (`Completed`) inline above, before `finish_project` ran — only the
    // failure case still needs to be classified here, since its
    // `finish_project("failed", ...)` call happens below, in this same
    // match.
    if let (Some(rid), Err(e)) = (run_id, &result) {
        // `e.issues.is_some()` is only ever set on the one failure path
        // that means "blocking findings were never resolved" (see
        // `e.issues = Some(owned)` above) — every other failure (bad
        // input, a tool crash, a missing snapshot) is a genuine error,
        // not a declined/unresolved review outcome.
        let target = if e.issues.is_some() { ignite_run_lifecycle::RunLifecycleState::Blocked } else { ignite_run_lifecycle::RunLifecycleState::Failed };
        state.db.transition_scan_run_or_warn(rid, target);
    }

    match result {
        Ok(()) => {
            let tagged: Vec<Value> = issues
                .iter()
                .map(|i| {
                    let mut v = serde_json::to_value(i).unwrap();
                    if overridden_ids.contains(&i.id) {
                        v["status"] = json!("overridden");
                    } else if baseline_issue_ids.as_ref().map(|ids| ids.contains(&i.id)).unwrap_or(false) {
                        v["status"] = json!("baselined");
                    }
                    v
                })
                .collect();
            let total_issue_count = tagged.len();
            let filtered = filter_tagged_by_changed_files(&tagged, changed_files.as_ref());

            // US-02: report coverage/policy decision alongside findings —
            // `evaluate_policy` is the same pure function every entry point
            // (browser streaming, this headless path, CLI, MCP-via-HTTP)
            // shares, so a clean `issues` list can never be mistaken for a
            // complete assessment. `legacy_compatible()` preserves this
            // existing endpoint's current gate behavior unchanged (no check
            // is individually required) while still surfacing what did/
            // didn't run; a deployment opts into `strict_publication()` via
            // `policy.version` in `config.json` (`ignite_config`).
            let blocking_unresolved = issues.iter().any(|i| i.severity == ignite_override_engine::Severity::Error && !overridden_ids.contains(&i.id));
            let policy_decision = crate::routes::policy_finalization::finalize(state.as_ref(), run_id, &phase4_coverage, blocking_unresolved, false);

            if baseline_mode.as_deref() == Some("save") {
                let ids: Vec<String> = issues.iter().map(|i| i.id.clone()).collect();
                if let Err(e) = state.db.save_baseline(&org, &repo, &ids) {
                    tracing::error!("save_baseline failed for {org}/{repo}: {e}");
                }
            }

            let mut response = json!({
                "ok": true,
                "mode": "validate-all",
                "jobId": job_id,
                "projectPath": project_path,
                "issues": filtered,
                "phases": phases,
                "__stageTimings": stage_timings,
                "events": events,
                "coverage": phase4_coverage,
                "policyDecision": policy_decision,
            });
            let obj = response.as_object_mut().unwrap();
            if fast {
                obj.insert("fastMode".to_string(), json!(true));
            }
            if let Some(w) = &unit_test_warning {
                obj.insert("unitTestWarning".to_string(), json!(w));
            }
            if changed_files.is_some() {
                obj.insert("totalIssueCount".to_string(), json!(total_issue_count));
                obj.insert("filteredByChangedFiles".to_string(), json!(true));
            }
            if baseline_mode.as_deref() == Some("save") {
                obj.insert("baselineSaved".to_string(), json!(issues.len()));
            }
            if let Some(ids) = &baseline_issue_ids {
                obj.insert("baselineIssueCount".to_string(), json!(ids.len()));
            }
            Ok(response)
        }
        Err(e) => {
            logger.log(e.phase, &format!("✗ {}", e.message));
            logger.status(e.phase, "failed", Some(json!({ "error": e.message })));
            // Same gap as the success path above, but the one that's
            // actually hit far more often in practice: "N unresolved
            // blocking finding(s)" is this exact error branch
            // (`e.issues` is `Some` precisely then), so a scan that
            // *fails the gate* — the normal outcome for a repo scanned
            // for the first time with no overrides yet — is exactly the
            // case someone most wants to open in Studio afterward, and
            // was exactly the case silently missing every persisted issue.
            if let Some(failure_issue_list) = &e.issues {
                let issue_inputs: Vec<ignite_db_store::IssueInput> = failure_issue_list.iter().map(crate::routes::pipeline_onboard::issue_to_input).collect();
                state.db.replace_project_issues(project_id, &issue_inputs, &overridden_ids);
            }
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
            let failure_issues: Option<Vec<Value>> = e.issues.as_ref().map(|list| {
                list.iter()
                    .map(|i| {
                        let mut v = serde_json::to_value(i).unwrap();
                        if overridden_ids.contains(&i.id) {
                            v.as_object_mut().unwrap().insert("status".to_string(), json!("overridden"));
                        }
                        v
                    })
                    .collect()
            });
            // US-02: coverage/policy decision survive onto a failed run's
            // response too — a blocked/incomplete run is exactly the case
            // where knowing what did/didn't run matters most.
            let blocking_unresolved = e.issues.as_ref().map(|list| list.iter().any(|i| i.severity == ignite_override_engine::Severity::Error && !overridden_ids.contains(&i.id))).unwrap_or(true);
            let policy_decision = crate::routes::policy_finalization::finalize(state.as_ref(), run_id, &phase4_coverage, blocking_unresolved, false);
            let mut response = json!({
                "ok": false,
                "mode": "validate-all",
                "jobId": job_id,
                "projectPath": project_path,
                "error": e.message,
                "failedPhase": e.phase,
                "phases": phases,
                "__stageTimings": stage_timings,
                "events": events,
                "coverage": phase4_coverage,
                "policyDecision": policy_decision,
            });
            let obj = response.as_object_mut().unwrap();
            if let Some(fi) = &failure_issues {
                let total = fi.len();
                let filtered = filter_tagged_by_changed_files(fi, changed_files.as_ref());
                obj.insert("issues".to_string(), json!(filtered));
                if changed_files.is_some() {
                    obj.insert("totalIssueCount".to_string(), json!(total));
                    obj.insert("filteredByChangedFiles".to_string(), json!(true));
                }
            } else {
                obj.insert("issues".to_string(), Value::Null);
            }
            // Machine-readable "what do I do next" — only for a run that
            // stopped on findings (`e.issues` set); a crash carries no issue
            // list and is not a block, so it gets no envelope.
            let response = match &e.issues {
                Some(list) if blocking_unresolved => {
                    let unresolved: Vec<String> = list.iter().filter(|i| i.severity == ignite_override_engine::Severity::Error && !overridden_ids.contains(&i.id)).map(|i| i.id.clone()).collect();
                    crate::routes::blocked::with_block_info(response, crate::routes::blocked::BlockReason::UnresolvedFindings, json!({ "unresolvedIssueIds": unresolved }))
                }
                Some(_) => match crate::routes::blocked::reason_for_policy_decision(&policy_decision) {
                    Some(reason) => crate::routes::blocked::with_block_info(response, reason, crate::routes::blocked::policy_details(&policy_decision)),
                    None => response,
                },
                None => response,
            };
            Err((response, json!({})))
        }
    }
}

/// Deterministic digest of the whole request body — `serde_json::Value`
/// serializes object keys in sorted order (this workspace never enables
/// `preserve_order`), so two requests with identical content hash
/// identically regardless of the order fields were sent in over the wire.
pub(crate) fn idempotency_payload_hash(body: &Value) -> String {
    use sha2::{Digest, Sha256};
    // `async` and the injected job id change how a request is *delivered*, not
    // what it asks for, so a retry may flip between sync and async.
    let mut body = body.clone();
    if let Some(obj) = body.as_object_mut() {
        obj.remove("async");
        obj.remove(super::async_jobs::ASYNC_JOB_ID_KEY);
    }
    let canonical = serde_json::to_string(&body).unwrap_or_default();
    format!("sha256:{:x}", Sha256::digest(canonical.as_bytes()))
}

/// Where a repository keeps its committed justifications — the same file
/// the pre-push hook, `ignite check` and the VS Code extension maintain.
const REPO_ACK_FILE: &str = ".ignite/acknowledgments.md";
/// Actor recorded on overrides that came from [`REPO_ACK_FILE`] rather than
/// from the request itself.
const REPO_ACK_ACTOR_EMAIL: &str = "repo-acknowledgments@ignite.internal";
const REPO_ACK_ACTOR_NAME: &str = "Repository .ignite/acknowledgments.md";

/// Justified entries from the scanned repo's own [`REPO_ACK_FILE`] (checked
/// at the path the caller gave, then at the resolved project root), minus
/// any issue the request already sent an override for — an explicit
/// request always wins over the file. Missing/unreadable file = none.
fn repo_file_overrides(project_path: &std::path::Path, root: &std::path::Path, requested: &[SubmittedOverride]) -> Vec<SubmittedOverride> {
    let text = [project_path, root]
        .iter()
        .find_map(|dir| std::fs::read_to_string(dir.join(REPO_ACK_FILE)).ok())
        .unwrap_or_default()
        .replace("\r\n", "\n");
    let already: std::collections::HashSet<&str> = requested.iter().map(|o| o.issue_id.as_str()).collect();
    // One entry per finding, latest justification wins (same rule every writer applies).
    ignite_acknowledgments::dedupe_latest(ignite_acknowledgments::parse_blocks(&text))
        .into_iter()
        .filter(|e| !e.justification.is_empty() && !already.contains(e.id.as_str()))
        .map(|e| SubmittedOverride { issue_id: e.id, justification: e.justification, code: e.code })
        .collect()
}

fn filter_tagged_by_changed_files(tagged: &[Value], changed_files: Option<&std::collections::HashSet<String>>) -> Vec<Value> {
    match changed_files {
        None => tagged.to_vec(),
        Some(set) => tagged.iter().filter(|i| i.get("file").and_then(|f| f.as_str()).map(|f| set.contains(f)).unwrap_or(false)).cloned().collect(),
    }
}

// `default_phase4_config` (this file's own thin wrapper, threading `fast`
// through) is gone — candidate 2 of the architecture review, see the
// removal note in `pipeline_onboard.rs`.

async fn validate_all(State(state): State<Arc<AppState>>, crate::auth::OptionalUser(user): crate::auth::OptionalUser, headers: axum::http::HeaderMap, Json(mut body): Json<Value>) -> Response {
    super::async_jobs::strip_client_job_id(&mut body);
    if user.is_none() && !state.config.security.allow_unauthenticated_validate_all {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "Authentication required." }))).into_response();
    }
    let mut needed = vec![crate::auth::Scope::Scan];
    if crate::auth::body_submits_overrides(&body) {
        needed.push(crate::auth::Scope::Override);
    }
    if let Err((status, denied)) = crate::auth::require_scopes(&headers, &state.db, &needed) {
        return (status, Json(denied)).into_response();
    }
    if super::async_jobs::wants_async(&body) {
        return super::async_jobs::start(state, "validate-all", user.map(|u| u.id), headers, body, |state, headers, body| async move {
            match run_validate_all(state, headers, body).await {
                Ok(v) => (200, v),
                Err((v, _)) => (error_status(&v).as_u16(), v),
            }
        });
    }
    match run_validate_all(state, headers, body).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err((v, _)) => (error_status(&v), Json(v)).into_response(),
    }
}

/// `run_validate_all`'s error type carries only a body, so every failure used
/// to be a 400. An idempotency-key conflict (`conflict: true`) is a 409, as it
/// is on `onboard`; every other failure stays 400.
fn error_status(body: &Value) -> StatusCode {
    if body.get("conflict").and_then(|v| v.as_bool()).unwrap_or(false) {
        StatusCode::CONFLICT
    } else {
        StatusCode::BAD_REQUEST
    }
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/pipeline/validate-all", post(validate_all))
}

#[cfg(test)]
mod phase_gating_tests {
    use crate::state::AppState;
    use axum::Router;
    use serde_json::{json, Value};
    
    
    use std::sync::Arc;

    fn build_state(config: ignite_config::Config) -> (Arc<AppState>, tempfile::TempDir) {
        let db_dir = tempfile::tempdir().unwrap();
        let db = ignite_db_store::DbStore::open(&db_dir.path().join("test.db")).unwrap();
        let app_state = Arc::new(crate::state::test_state(db, config));
        (app_state, db_dir)
    }

    async fn spawn_test_server(state: Arc<AppState>) -> String {
        let router = Router::new().merge(super::router()).with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        format!("http://{addr}")
    }

    fn secret_fixture_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"name":"phase-gating-fixture"}"#).unwrap();
        // Matches secrets crate's SECRET_RE — a real, blocking phase-4-only
        // finding (never produced by the always-on license/vuln checks
        // pipeline_validate.rs still runs when phase 4 is disabled).
        let fixture_js = String::from("const api_key =")
            + " \"sk_live_abcdefghij1234567890\";\n";
        std::fs::write(dir.path().join("config.js"), fixture_js).unwrap();
        dir
    }

    #[tokio::test]
    async fn phase_4_disabled_via_config_skips_secrets_scan_but_still_runs() {
        let dir = secret_fixture_dir();
        let cfg = ignite_config::Config { phases: vec![json!({ "id": 4, "enabled": false })], ..Default::default() };
        let (state, _db_dir) = build_state(cfg);
        let user_id = state.db.create_local_user("tester@example.com", None, "unused-hash").unwrap();
        let token = format!("{}{}", ignite_auth::API_KEY_PREFIX, uuid::Uuid::new_v4());
        state.db.create_api_key(user_id, &ignite_auth::hash_api_key(&token), None, None, "test");
        let base = spawn_test_server(state).await;
        let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(60)).build().unwrap();
        let res = client
            .post(format!("{base}/api/pipeline/validate-all"))
            .bearer_auth(token)
            .json(&json!({ "projectPath": dir.path().to_string_lossy(), "fast": true, "runLocalCi": false }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        let body: Value = res.json().await.unwrap();

        let phase4_log = body["phases"].as_array().unwrap().iter().find(|p| p["phase"] == 4).unwrap()["logs"].as_array().unwrap().iter().map(|l| l.as_str().unwrap_or("")).collect::<Vec<_>>().join("\n");
        assert!(phase4_log.contains("Skipped — disabled by config"), "expected skip log, got: {phase4_log}");

        let issues = body["issues"].as_array().cloned().unwrap_or_default();
        assert!(!issues.iter().any(|i| i["category"] == "secret"), "secrets check should not have run when phase 4 is disabled: {issues:?}");
    }

    #[tokio::test]
    async fn phase_4_enabled_by_default_runs_secrets_scan() {
        let dir = secret_fixture_dir();
        let cfg = ignite_config::Config::default();
        let (state, _db_dir) = build_state(cfg);
        let user_id = state.db.create_local_user("tester@example.com", None, "unused-hash").unwrap();
        let token = format!("{}{}", ignite_auth::API_KEY_PREFIX, uuid::Uuid::new_v4());
        state.db.create_api_key(user_id, &ignite_auth::hash_api_key(&token), None, None, "test");
        let base = spawn_test_server(state).await;
        let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(60)).build().unwrap();
        let res = client
            .post(format!("{base}/api/pipeline/validate-all"))
            .bearer_auth(token)
            .json(&json!({ "projectPath": dir.path().to_string_lossy(), "fast": true, "runLocalCi": false }))
            .send()
            .await
            .unwrap();
        let status = res.status();
        let body: Value = res.json().await.unwrap();
        assert!(status == 200 || status == 400, "unexpected status {status}: {body}");

        let issues = body["issues"].as_array().cloned().unwrap_or_default();
        assert!(issues.iter().any(|i| i["category"] == "secret"), "expected a secrets finding with phase 4 enabled: {issues:?}");

        // US-02: coverage/policyDecision ride along with every validate-all
        // response (pass or fail — an unresolved secret finding here makes
        // this a 400/blocked response, not a 200), not just the findings
        // list.
        let coverage = body["coverage"].as_array().cloned().unwrap_or_default();
        assert!(coverage.iter().any(|c| c["checkId"] == "secrets" && c["outcome"] == "completed"), "expected a completed 'secrets' coverage entry: {coverage:?}");
        assert_eq!(body["policyDecision"]["policyVersion"], "legacy-compatible-v1", "default config pins the legacy-compatible policy");
    }

    #[tokio::test]
    async fn validate_all_rejects_an_unauthenticated_caller_by_default() {
        let dir = secret_fixture_dir();
        let (state, _db_dir) = build_state(ignite_config::Config::default());
        let base = spawn_test_server(state).await;
        let client = reqwest::Client::new();
        let res = client.post(format!("{base}/api/pipeline/validate-all")).json(&json!({ "projectPath": dir.path().to_string_lossy(), "fast": true, "runLocalCi": false })).send().await.unwrap();
        assert_eq!(res.status(), 401);
    }

    #[tokio::test]
    async fn validate_all_allows_an_unauthenticated_caller_when_explicitly_configured() {
        let dir = secret_fixture_dir();
        let cfg = ignite_config::Config { security: ignite_config::SecurityConfig { allow_unauthenticated_validate_all: true, ..Default::default() }, ..Default::default() };
        let (state, _db_dir) = build_state(cfg);
        let base = spawn_test_server(state).await;
        let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(60)).build().unwrap();
        let res = client.post(format!("{base}/api/pipeline/validate-all")).json(&json!({ "projectPath": dir.path().to_string_lossy(), "fast": true, "runLocalCi": false })).send().await.unwrap();
        assert_ne!(res.status(), 401, "unauthenticated validate-all must not be rejected once explicitly allowed");
    }

    // US-04: a clean validate-all run reaches the "completed" (not
    // "published" — this endpoint never ships) lifecycle state.
    #[tokio::test]
    async fn a_clean_run_reaches_the_completed_lifecycle_state() {
        let dir = clean_fixture_dir();
        let cfg = ignite_config::Config { phases: vec![json!({ "id": 4, "enabled": false })], security: ignite_config::SecurityConfig { allow_unauthenticated_validate_all: true, ..Default::default() }, ..Default::default() };
        let (state, _db_dir) = build_state(cfg);
        let base = spawn_test_server(state.clone()).await;
        let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(60)).build().unwrap();
        let body: Value = client
            .post(format!("{base}/api/pipeline/validate-all"))
            .json(&json!({ "projectPath": dir.path().to_string_lossy(), "fast": true, "runLocalCi": false }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(body["ok"], true);
        let project_id = state.db.get_project_id_by_job_id(body["jobId"].as_str().unwrap()).unwrap();
        let run = state.db.get_scan_run_for_legacy_project(project_id).unwrap();
        assert_eq!(run.lifecycle_state, "completed");
    }

    fn clean_fixture_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"name":"idempotency-fixture"}"#).unwrap();
        dir
    }

    // US-04: scoped idempotency keys.
    #[tokio::test]
    async fn same_idempotency_key_and_payload_replays_the_existing_run() {
        let dir = clean_fixture_dir();
        let cfg = ignite_config::Config { phases: vec![json!({ "id": 4, "enabled": false })], security: ignite_config::SecurityConfig { allow_unauthenticated_validate_all: true, ..Default::default() }, ..Default::default() };
        let (state, _db_dir) = build_state(cfg);
        let base = spawn_test_server(state).await;
        let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(60)).build().unwrap();
        let payload = json!({ "projectPath": dir.path().to_string_lossy(), "fast": true, "runLocalCi": false, "idempotencyKey": "retry-1" });

        let first: Value = client.post(format!("{base}/api/pipeline/validate-all")).json(&payload).send().await.unwrap().json().await.unwrap();
        assert_eq!(first["ok"], true);
        let first_job_id = first["jobId"].as_str().unwrap().to_string();

        let second: Value = client.post(format!("{base}/api/pipeline/validate-all")).json(&payload).send().await.unwrap().json().await.unwrap();
        assert_eq!(second["idempotent"], true);
        assert_eq!(second["jobId"].as_str(), Some(first_job_id.as_str()), "a retry with the same key+payload must reference the original run, not start a new one");
    }

    #[tokio::test]
    async fn same_idempotency_key_with_a_different_payload_conflicts() {
        let dir = clean_fixture_dir();
        let cfg = ignite_config::Config { phases: vec![json!({ "id": 4, "enabled": false })], security: ignite_config::SecurityConfig { allow_unauthenticated_validate_all: true, ..Default::default() }, ..Default::default() };
        let (state, _db_dir) = build_state(cfg);
        let base = spawn_test_server(state).await;
        let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(60)).build().unwrap();

        let first = client
            .post(format!("{base}/api/pipeline/validate-all"))
            .json(&json!({ "projectPath": dir.path().to_string_lossy(), "fast": true, "runLocalCi": false, "idempotencyKey": "retry-2" }))
            .send()
            .await
            .unwrap();
        assert_eq!(first.status(), 200);

        let second = client
            .post(format!("{base}/api/pipeline/validate-all"))
            .json(&json!({ "projectPath": dir.path().to_string_lossy(), "fast": true, "runLocalCi": false, "idempotencyKey": "retry-2", "warningDecision": "block" }))
            .send()
            .await
            .unwrap();
        assert_eq!(second.status(), 409, "an idempotency conflict is a 409, matching onboard");
        let body: Value = second.json().await.unwrap();
        assert_eq!(body["conflict"], true);
    }

    #[test]
    fn only_a_conflict_body_is_a_409_every_other_failure_stays_a_400() {
        use axum::http::StatusCode;
        assert_eq!(super::error_status(&json!({ "ok": false, "conflict": true })), StatusCode::CONFLICT);
        assert_eq!(super::error_status(&json!({ "ok": false, "error": "Phase 4 has 1 unresolved blocking finding(s)." })), StatusCode::BAD_REQUEST);
        assert_eq!(super::error_status(&json!({ "conflict": false })), StatusCode::BAD_REQUEST);
        assert_eq!(super::error_status(&json!({})), StatusCode::BAD_REQUEST);
    }
}

#[cfg(test)]
mod repo_ack_file_tests {
    use super::{repo_file_overrides, REPO_ACK_FILE};
    use ignite_override_engine::SubmittedOverride;

    fn ack_file(dir: &std::path::Path, body: &str) {
        std::fs::create_dir_all(dir.join(".ignite")).unwrap();
        std::fs::write(dir.join(REPO_ACK_FILE), body).unwrap();
    }

    #[test]
    fn reads_the_latest_justification_per_finding() {
        let dir = tempfile::tempdir().unwrap();
        ack_file(
            dir.path(),
            "# header\nID: secret::Preparation Steps/LELEQUIPMENT.txt::12\n# [ERROR] secret - Hardcoded credential\nAcknowledge: older\n\nID: secret::Preparation Steps/LELEQUIPMENT.txt::12\nAcknowledge: false positive, CPI security material\r\n\nID: secret::b.txt::1\nAcknowledge: \n",
        );
        let got = repo_file_overrides(dir.path(), dir.path(), &[]);
        assert_eq!(got.len(), 1, "one entry per finding, blank ones skipped");
        assert_eq!(got[0].issue_id, "secret::Preparation Steps/LELEQUIPMENT.txt::12");
        assert_eq!(got[0].justification, "false positive, CPI security material");
    }

    #[test]
    fn never_shadows_an_override_sent_in_the_request() {
        let dir = tempfile::tempdir().unwrap();
        ack_file(dir.path(), "ID: secret::a.txt::1\nAcknowledge: from file\n\nID: secret::b.txt::2\nAcknowledge: also from file\n");
        let requested = vec![SubmittedOverride { issue_id: "secret::a.txt::1".into(), justification: "from request".into(), code: None }];
        let got = repo_file_overrides(dir.path(), dir.path(), &requested);
        assert_eq!(got.iter().map(|o| o.issue_id.as_str()).collect::<Vec<_>>(), vec!["secret::b.txt::2"]);
    }

    #[test]
    fn is_empty_without_a_file() {
        let dir = tempfile::tempdir().unwrap();
        assert!(repo_file_overrides(dir.path(), dir.path(), &[]).is_empty());
    }
}
