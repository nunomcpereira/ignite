//! POST /api/pipeline/validate-all — faithful port of
//! routes/pipeline-validate.js: a synchronous JSON pipeline run,
//! phases 1-5 only (always skips shipping), for agent/CI callers that
//! want pass/fail without a real push.
//!
//! Known gaps vs. the JS original: phase title/enabled config.json
//! overrides aren't wired (uses the hardcoded DEFAULT_PHASE_META);
//! per-Phase-4-task timing breakdown (`__taskTimings`) isn't tracked,
//! only top-level stage timings; GxP (Phase 2) document links are
//! accepted/validated but not persisted as real documents (no
//! addUploadDocument wiring yet); overrides never trigger an email
//! notification (no SMTP transport wired yet — see ignite-notifications'
//! doc comment).

use crate::state::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use ignite_override_engine::{validate_overrides, Issue, Severity, SubmittedOverride};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

static GITHUB_NAME_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$").unwrap());
static REPO_NAME_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9._-]{1,100}$").unwrap());

const PHASE_META: &[(i64, &str, bool)] = &[
    (1, "Input & Metadata Configuration", true),
    (2, "GxP Validation Documents", false),
    (3, "Extraction, Structure Audit & Unit Tests", true),
    (4, "Security & AI Compliance Scan", true),
    (5, "Org Governance CI — GitHub Actions", true),
    (6, "Provisioning & Shipping", true),
];

fn phase_title(phase: i64) -> &'static str {
    PHASE_META.iter().find(|(id, _, _)| *id == phase).map(|(_, t, _)| *t).unwrap_or("Unknown")
}

fn phase_enabled(phase: i64) -> bool {
    PHASE_META.iter().find(|(id, _, _)| *id == phase).map(|(_, _, e)| *e).unwrap_or(true)
}

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
    inner: Arc<Mutex<PipelineState>>,
}

impl Logger {
    fn persist(&self, phase: i64) {
        let inner = self.inner.lock().unwrap();
        let Some(project_id) = inner.project_id else { return };
        if let Some(rec) = inner.record.get(&phase) {
            self.state.db.upsert_step(project_id, phase, phase_title(phase), &rec.state, &rec.logs.join("\n"));
        }
    }

    fn log(&self, phase: i64, message: &str) {
        {
            let mut inner = self.inner.lock().unwrap();
            inner.record.entry(phase).or_insert_with(|| PhaseRecord { state: "pending".to_string(), logs: vec![] }).logs.push(message.to_string());
            inner.events.push(json!({ "type": "log", "phase": phase, "message": message }));
        }
        self.persist(phase);
    }

    fn status(&self, phase: i64, state: &str, extra: Option<Value>) {
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
        PHASE_META
            .iter()
            .map(|(id, title, _)| {
                let (state, logs) = inner.record.get(id).map(|r| (r.state.clone(), r.logs.clone())).unwrap_or(("pending".to_string(), vec![]));
                json!({ "phase": id, "title": title, "state": state, "logs": logs })
            })
            .collect()
    }

    fn events(&self) -> Vec<Value> {
        self.inner.lock().unwrap().events.clone()
    }
}

fn resolve_actor(body: &Value) -> Option<(String, String)> {
    let email = body.get("actor").and_then(|a| a.get("email")).and_then(|v| v.as_str()).unwrap_or("").trim().to_lowercase();
    let name = body.get("actor").and_then(|a| a.get("name")).and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if !ignite_auth::is_valid_email(&email) {
        return None;
    }
    let name = if name.is_empty() { email.clone() } else { name };
    Some((email, name))
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

async fn run_validate_all(state: Arc<AppState>, body: Value) -> Result<Value, (Value, Value)> {
    let org = body.get("org").and_then(|v| v.as_str()).unwrap_or("local-validation").trim().to_string();
    let org = if org.is_empty() { "local-validation".to_string() } else { org };
    let repo = body.get("repo").and_then(|v| v.as_str()).unwrap_or("local-project").trim().to_string();
    let repo = if repo.is_empty() { "local-project".to_string() } else { repo };
    let is_gxp = phase_enabled(2) && body.get("gxp").and_then(|v| v.as_bool()).unwrap_or(false);
    let run_local_ci = body.get("runLocalCi").and_then(|v| v.as_bool()).unwrap_or(true);
    let fast = body.get("fast").and_then(|v| v.as_bool()).unwrap_or(false);
    let warning_decision = body.get("warningDecision").and_then(|v| v.as_str()).unwrap_or("continue").to_lowercase();
    let raw_project_path = body.get("projectPath").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let raw_project_path = if raw_project_path.is_empty() { std::env::current_dir().unwrap_or_default().to_string_lossy().into_owned() } else { raw_project_path };
    let gxp_links = body.get("gxpLinks").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let requested_overrides: Vec<SubmittedOverride> = body
        .get("overrides")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().map(|o| SubmittedOverride { issue_id: o.get("issueId").and_then(|v| v.as_str()).unwrap_or("").to_string(), justification: o.get("justification").and_then(|v| v.as_str()).unwrap_or("").to_string() }).collect())
        .unwrap_or_default();
    let changed_files: Option<std::collections::HashSet<String>> = body.get("changedFiles").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.trim().to_string())).filter(|s| !s.is_empty()).collect());
    let baseline_mode = body.get("baselineMode").and_then(|v| v.as_str()).filter(|m| *m == "gate" || *m == "save").map(str::to_string);
    let baseline_issue_ids = if baseline_mode.as_deref() == Some("gate") { Some(state.db.get_baseline_issue_ids(&org, &repo)) } else { None };

    let project_path = match ignite_tool_runner::sanitize_absolute_project_path(&raw_project_path) {
        Ok(p) => p,
        Err(e) => return Err((json!({ "ok": false, "error": e.to_string() }), json!({}))),
    };

    let timings: Mutex<Vec<StageTiming>> = Mutex::new(Vec::new());
    let job_id = uuid::Uuid::new_v4().to_string();
    let staging_dir = std::env::temp_dir().join("gatekeeper-staging").join(format!("{job_id}-api-validation"));
    let workflow_dir_str = format!("{}-workflows", staging_dir.to_string_lossy());
    let workflow_dir = std::path::PathBuf::from(&workflow_dir_str);

    let logger = Logger { state: state.clone(), inner: Arc::new(Mutex::new(PipelineState { record: HashMap::new(), events: vec![], project_id: None })) };

    let mut project_root: Option<std::path::PathBuf> = None;
    let mut issues: Vec<Issue> = vec![];
    let mut overridden_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut project_id: i64 = 0;

    let result: Result<(), PipelineError> = async {
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
        project_id = state.db.create_project(&job_id, &org, &repo, is_gxp, source, Some(&project_path.to_string_lossy()));
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

        logger.log(3, "Check 1 — scanning for raw environment files (.env*)...");
        let env_check = time_stage(&timings, "checkEnvFiles", async { ignite_staging::check_env_files(&root) }).await.map_err(|e| PipelineError::new(3, e.to_string()))?;
        if !env_check.ignored.is_empty() {
            logger.log(3, &format!("ℹ {} .env file(s) found but already excluded by this project's .gitignore — not blocking: {}", env_check.ignored.len(), env_check.ignored.join(", ")));
        }
        if !env_check.blocking.is_empty() {
            logger.log(3, &format!("✗ {} forbidden environment file(s) found:", env_check.blocking.len()));
            for f in &env_check.blocking {
                logger.log(3, &format!("    ✗ {f}"));
            }
            return Err(PipelineError::new(3, format!("Raw environment files detected ({}). Remove them before validation.", env_check.blocking.len())));
        }
        logger.log(3, "✓ Check 1 passed — no raw environment files present.");
        logger.log(3, "Check 2 — checking for a CODEOWNERS file...");
        let codeowners = time_stage(&timings, "checkCodeowners", async { ignite_staging::check_codeowners(&root) }).await;
        if codeowners.found {
            logger.log(3, &format!("✓ CODEOWNERS found at {} ({} contact email(s)).", codeowners.path.as_deref().unwrap_or(""), codeowners.emails.len()));
        } else {
            logger.log(3, "ℹ No CODEOWNERS file found (advisory — checked root, .github/, docs/).");
        }
        {
            let l3 = logger.clone();
            time_stage(&timings, "runProjectUnitTests", async { ignite_unit_test_runner::run_project_unit_tests(&root, &state.runner, move |m| l3.log(3, m)).await }).await.map_err(|e| PipelineError::new(3, e.to_string()))?;
        }
        logger.status(3, "success", None);

        // Phase 4
        logger.status(4, "running", None);
        let client = ignite_deps_dev_client::DepsDevClient::new();
        let npm_http = reqwest::Client::new();
        if !phase_enabled(4) {
            logger.log(4, "Skipped — disabled by config (phases: [{ id: 4, enabled: false }]).");
            logger.log(3, "Check 3 — dependency & license compliance scan (manifests + LICENSE files)...");
            let l3a = logger.clone();
            let l3b = logger.clone();
            issues.extend(ignite_dependency_license_scan::run_license_compliance_check(&root, &state.runner, &client, &npm_http, move |m| l3a.log(3, m)).await);
            issues.extend(ignite_dependency_license_scan::run_dependency_vulnerability_check(&root, &client, move |m| l3b.log(3, m)).await);
        } else {
            logger.log(3, "Check 3 — dependency & license compliance scan (manifests + LICENSE files)...");
            let l3a = logger.clone();
            let l3b = logger.clone();
            let root_a = root.clone();
            let root_b = root.clone();
            let state_a = state.clone();
            let state_b = state.clone();
            let config = default_phase4_config(&org, &repo, Some(project_id), fast);
            let (license_issues, phase4_result) = tokio::join!(
                time_stage(&timings, "licenseAndDependencyScan", async move {
                    let mut v = ignite_dependency_license_scan::run_license_compliance_check(&root_a, &state_a.runner, &client, &npm_http, move |m| l3a.log(3, m)).await;
                    v.extend(ignite_dependency_license_scan::run_dependency_vulnerability_check(&root_a, &client, move |m| l3b.log(3, m)).await);
                    v
                }),
                time_stage(&timings, "phase4Total", async move { ignite_phase4_orchestrator::run_phase4_checks(&root_b, &state_b.runner, &state_b.db, &config).await })
            );
            match phase4_result {
                Ok(output) => issues.extend(output.issues),
                Err(e) => return Err(PipelineError::new(4, e.to_string())),
            }
            issues.extend(license_issues);
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
            let result = validate_overrides(&owned, &requested_overrides);
            for (issue, _) in &result.applied {
                overridden_ids.insert(issue.id.clone());
            }
            if !result.applied.is_empty() {
                let Some((email, _name)) = resolve_actor(&body) else {
                    return Err(PipelineError::new(4, "Overrides were submitted but no authenticated user or actor {email,name} was provided — cannot attribute the audit record."));
                };
                logger.log(4, &format!("⚠ {} flagged issue(s) overridden by {email}:", result.applied.len()));
                for (issue, justification) in &result.applied {
                    logger.log(4, &format!("    ⚠ [override] [{:?}] {}:{} — {} — \"{justification}\"", issue.severity, issue.file.as_deref().unwrap_or(""), issue.line.unwrap_or(0), issue.summary));
                }
            }
            if !result.ok {
                logger.log(4, &format!("✗ {} blocking finding(s) were not overridden:", result.unresolved_errors.len()));
                for issue in &result.unresolved_errors {
                    let loc = issue.file.as_deref().map(|f| format!("{f}{}", issue.line.map(|l| format!(":{l}")).unwrap_or_default())).unwrap_or_else(|| "Phase 4".to_string());
                    logger.log(4, &format!("    ✗ [{}] {loc} — {}", issue.category, issue.summary));
                }
                let mut e = PipelineError::new(4, format!("Phase 4 has {} unresolved blocking finding(s). Submit an override with a justification for each, or fix them.", result.unresolved_errors.len()));
                e.issues = Some(result.unresolved_errors.into_iter().cloned().collect());
                return Err(e);
            }
        }
        logger.status(4, "success", None);

        // Phase 5
        logger.status(5, "running", None);
        if !phase_enabled(5) {
            logger.log(5, "Skipped — disabled by config (phases: [{ id: 5, enabled: false }]).");
            logger.status(5, "skipped", None);
        } else if !run_local_ci {
            logger.log(5, "Local CI execution disabled by request (runLocalCi=false).");
            logger.status(5, "skipped", None);
        } else {
            let tooling = ignite_governance_ci::act_tooling(&state.runner).await;
            if !tooling.ok {
                logger.log(5, &format!("⚠ Local CI skipped: {}", tooling.reason.unwrap_or_default()));
                logger.status(5, "skipped", None);
            } else {
                let gh_api = ignite_github_api::GithubApi::new(&state.runner);
                let gh_token = ignite_github_api::resolve_server_github_token();
                let root = project_root.clone().unwrap();
                let l5 = logger.clone();
                let wf_result = time_stage(&timings, "fetchGovernanceWorkflow", async {
                    ignite_governance_ci::fetch_governance_workflow(&workflow_dir, &gh_api, &state.db, "nunomcpereira/ai-guardrails-orchestrator", "ai-guardrails-orchestrator.yml", &gh_token, move |m| l5.log(5, m)).await
                })
                .await;
                match wf_result {
                    Ok(wf_file) => {
                        logger.log(5, "Executing org governance workflows locally with act (event: push).");
                        let l5b = logger.clone();
                        let run_result = time_stage(&timings, "runActionsLocally", async { ignite_governance_ci::run_actions_locally(&root, &wf_file, &state.runner, &gh_api, &ignite_governance_ci::RunActionsConfig { act_event: "push".to_string(), act_timeout_min: 20 }, move |m| l5b.log(5, m)).await }).await;
                        match run_result {
                            Ok(_) => {
                                logger.log(5, "✓ All org governance jobs passed locally.");
                                logger.status(5, "success", None);
                            }
                            Err(e) => return Err(PipelineError::new(5, e.to_string())),
                        }
                    }
                    Err(e) => return Err(PipelineError::new(5, e.to_string())),
                }
            }
        }

        logger.log(6, "Shipping phase skipped in validate-all mode.");
        logger.status(6, "skipped", None);

        state.db.finish_project("success", None, None, None, project_id);
        Ok(())
    }
    .await;

    let phases = logger.phase_summary();
    let events = logger.events();
    let stage_timings: Vec<Value> = timings.into_inner().unwrap().into_iter().map(|t| json!({ "name": t.name, "ms": t.ms })).collect();

    ignite_fs_utils::invalidate_walk_cache(&staging_dir);
    if let Some(root) = &project_root {
        ignite_fs_utils::invalidate_walk_cache(root);
    }
    let _ = std::fs::remove_dir_all(&staging_dir);
    let _ = std::fs::remove_dir_all(&workflow_dir);

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

            if baseline_mode.as_deref() == Some("save") {
                let ids: Vec<String> = issues.iter().map(|i| i.id.clone()).collect();
                state.db.save_baseline(&org, &repo, &ids);
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
            });
            let obj = response.as_object_mut().unwrap();
            if fast {
                obj.insert("fastMode".to_string(), json!(true));
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
            state.db.finish_project("failed", Some(&e.message), None, None, project_id);

            let phases = logger.phase_summary();
            let events = logger.events();
            let failure_issues: Option<Vec<Value>> = e.issues.as_ref().map(|list| list.iter().map(|i| serde_json::to_value(i).unwrap()).collect());
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
            Err((response, json!({})))
        }
    }
}

fn filter_tagged_by_changed_files(tagged: &[Value], changed_files: Option<&std::collections::HashSet<String>>) -> Vec<Value> {
    match changed_files {
        None => tagged.to_vec(),
        Some(set) => tagged.iter().filter(|i| i.get("file").and_then(|f| f.as_str()).map(|f| set.contains(f)).unwrap_or(false)).cloned().collect(),
    }
}

#[allow(clippy::too_many_arguments)]
fn default_phase4_config(org: &str, repo: &str, project_id: Option<i64>, fast: bool) -> ignite_phase4_orchestrator::Phase4Config {
    ignite_phase4_orchestrator::Phase4Config {
        fast,
        org: org.to_string(),
        repo: repo.to_string(),
        project_id,
        secrets: ignite_secrets::SecretsConfig::default(),
        llm: None,
        iac: ignite_iac_security::IacSecurityConfig::default(),
        container_image_vulnerabilities: ignite_container_image_vulnerabilities::ContainerImageVulnerabilitiesConfig::default(),
        sbom_enabled: true,
        image_provenance: ignite_image_provenance::ImageProvenanceConfig::default(),
        semantic_sast: ignite_semantic_sast::SemanticSastConfig::default(),
        pii_data_flow: ignite_pii_dataflow::PiiDataFlowConfig::default(),
        code_duplication: ignite_code_duplication::CodeDuplicationConfig::default(),
        file_encapsulation: ignite_file_encapsulation::FileEncapsulationConfig { enabled: true, max_lines: 1000 },
        loc_metrics_enabled: true,
        api_schema: ignite_api_schema::ApiSchemaConfig::default(),
        api_schema_drift: ignite_api_schema_drift::ApiSchemaDriftConfig::default(),
        malicious_dependencies: ignite_malicious_dependencies::MaliciousDependenciesConfig::default(),
        model_artifact_security: ignite_model_artifact_security::ModelArtifactSecurityConfig::default(),
        package_hallucination_enabled: true,
        feature_posture: ignite_feature_posture::FeaturePostureConfig { enabled: true, ruleset: String::new(), max_scan_file_bytes: 1_000_000 },
        eu_ai_act_documents_enabled: true,
        eu_ai_act_report_as_findings: false,
        dead_code: ignite_dead_code::DeadCodeConfig { enabled: true },
        complexity_health: ignite_complexity_health::ComplexityHealthConfig::default(),
        css_dead_code: ignite_css_dead_code::CssDeadCodeConfig { enabled: true },
        boundaries: ignite_boundaries::BoundariesConfig { enabled: false, preset: None, zones: vec![] },
        igniteignore_enabled: true,
        codeql: ignite_codeql_cross_file::CodeqlConfig::default(),
    }
}

async fn validate_all(State(state): State<Arc<AppState>>, Json(body): Json<Value>) -> Response {
    match run_validate_all(state, body).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err((v, _)) => (StatusCode::BAD_REQUEST, Json(v)).into_response(),
    }
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/pipeline/validate-all", post(validate_all))
}
