//! POST /api/pipeline/onboard — faithful port of routes/pipeline-onboard.js:
//! full onboarding pipeline from a local filesystem path — phases 1-5
//! exactly as validate-all, and, if everything passes, phase 6
//! provisioning + push (skipped when `dryRun: true`, which gives
//! validate-all's behavior from this same request shape).
//!
//! Same known gaps as pipeline_validate.rs (config.json phase overrides,
//! per-task Phase 4 timings, GxP document persistence, override email
//! notifications), plus: `auth.resolveGithubToken(req)`'s connected-
//! session lookup isn't available (no session middleware) — falls back
//! straight to `resolve_server_github_token()`.

use crate::routes::phase_meta::{phase_enabled, phase_title, PHASE_META};
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
        self.inner.lock().unwrap().project_id = Some(id);
    }

    fn phase_summary(&self) -> Vec<Value> {
        let inner = self.inner.lock().unwrap();
        PHASE_META
            .iter()
            .map(|(id, title, _, _)| {
                let (state, logs) = inner.record.get(id).map(|r| (r.state.clone(), r.logs.clone())).unwrap_or(("pending".to_string(), vec![]));
                json!({ "phase": id, "title": title, "state": state, "logs": logs })
            })
            .collect()
    }

    fn events(&self) -> Vec<Value> {
        self.inner.lock().unwrap().events.clone()
    }
}

fn resolve_actor(body: &Value) -> Option<String> {
    let email = body.get("actor").and_then(|a| a.get("email")).and_then(|v| v.as_str()).unwrap_or("").trim().to_lowercase();
    if !ignite_auth::is_valid_email(&email) {
        return None;
    }
    Some(email)
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

fn issue_to_input(i: &Issue) -> ignite_db_store::IssueInput {
    ignite_db_store::IssueInput { id: i.id.clone(), phase: Some(4), category: i.category.clone(), severity: format!("{:?}", i.severity).to_lowercase(), score: Some(i.score as i64), summary: i.summary.clone(), file: i.file.clone(), line: i.line, snippet: i.snippet.clone(), cross_file: i.cross_file, chain: i.chain.clone(), cwe: i.cwe.clone() }
}

#[allow(clippy::too_many_arguments)]
fn default_phase4_config(org: &str, repo: &str, project_id: Option<i64>) -> ignite_phase4_orchestrator::Phase4Config {
    ignite_phase4_orchestrator::Phase4Config {
        fast: false,
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

async fn run_onboard(state: Arc<AppState>, body: Value) -> Result<Value, (StatusCode, Value)> {
    let org = body.get("org").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let repo = body.get("repo").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let is_gxp = phase_enabled(2) && body.get("gxp").and_then(|v| v.as_bool()).unwrap_or(false);
    let run_local_ci = body.get("runLocalCi").and_then(|v| v.as_bool()).unwrap_or(true);
    let dry_run = body.get("dryRun").and_then(|v| v.as_bool()).unwrap_or(false);
    let warning_decision = body.get("warningDecision").and_then(|v| v.as_str()).unwrap_or("continue").to_lowercase();
    let raw_project_path = body.get("projectPath").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let raw_project_path = if raw_project_path.is_empty() { std::env::current_dir().unwrap_or_default().to_string_lossy().into_owned() } else { raw_project_path };
    let gxp_links = body.get("gxpLinks").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let requested_overrides: Vec<SubmittedOverride> = body
        .get("overrides")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().map(|o| SubmittedOverride { issue_id: o.get("issueId").and_then(|v| v.as_str()).unwrap_or("").to_string(), justification: o.get("justification").and_then(|v| v.as_str()).unwrap_or("").to_string() }).collect())
        .unwrap_or_default();

    // Provisioning (Phase 6) must run as the actual caller's own GitHub
    // account — fail fast rather than burning phases 1-5 first.
    let gh_token = if dry_run { String::new() } else { ignite_github_api::resolve_server_github_token() };
    if !dry_run && gh_token.is_empty() {
        return Err((StatusCode::UNAUTHORIZED, json!({ "error": "Log in and connect your GitHub account before onboarding for real, or pass dryRun: true." })));
    }

    let project_path = match ignite_tool_runner::sanitize_absolute_project_path(&raw_project_path) {
        Ok(p) => p,
        Err(e) => return Err((StatusCode::BAD_REQUEST, json!({ "error": e.to_string() }))),
    };

    let job_id = uuid::Uuid::new_v4().to_string();
    let staging_dir = std::env::temp_dir().join("gatekeeper-staging").join(format!("{job_id}-onboard"));
    let source_backup_dir = std::path::PathBuf::from(format!("{}-source-backup", staging_dir.to_string_lossy()));
    let publish_dir = std::path::PathBuf::from(format!("{}-publish", staging_dir.to_string_lossy()));
    let workflow_dir = std::path::PathBuf::from(format!("{}-workflows", staging_dir.to_string_lossy()));

    let logger = Logger { state: state.clone(), inner: Arc::new(Mutex::new(PipelineState { record: HashMap::new(), events: vec![], project_id: None })) };
    let mut project_root: Option<std::path::PathBuf> = None;
    let mut project_id: i64 = 0;
    let mut repo_url: Option<String> = None;
    let mut pr_url: Option<String> = None;

    let result: Result<(), PipelineError> = async {
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
        project_id = state.db.create_project(&job_id, &org, &repo, is_gxp, source, Some(&project_path.to_string_lossy()));
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
        let l3b = logger.clone();
        let mut license_issues = ignite_dependency_license_scan::run_license_compliance_check(&root, &state.runner, &client, &npm_http, move |m| l3a.log(3, m)).await;
        license_issues.extend(ignite_dependency_license_scan::run_dependency_vulnerability_check(&root, &client, move |m| l3b.log(3, m)).await);

        logger.log(3, "Check 1 — scanning for raw environment files (.env*)...");
        let env_check = ignite_staging::check_env_files(&root).map_err(|e| PipelineError::new(3, e.to_string()))?;
        if !env_check.ignored.is_empty() {
            logger.log(3, &format!("ℹ {} .env file(s) found but already excluded by this project's .gitignore — not blocking: {}", env_check.ignored.len(), env_check.ignored.join(", ")));
        }
        if !env_check.blocking.is_empty() {
            logger.log(3, &format!("✗ {} forbidden environment file(s) found:", env_check.blocking.len()));
            for f in &env_check.blocking {
                logger.log(3, &format!("    ✗ {f}"));
            }
            return Err(PipelineError::new(3, format!("Raw environment files detected ({}). Remove them before onboarding.", env_check.blocking.len())));
        }
        logger.log(3, "✓ Check 1 passed — no raw environment files present.");
        logger.log(3, "Check 2 — checking for a CODEOWNERS file...");
        let codeowners = ignite_staging::check_codeowners(&root);
        if codeowners.found {
            logger.log(3, &format!("✓ CODEOWNERS found at {} ({} contact email(s)).", codeowners.path.as_deref().unwrap_or(""), codeowners.emails.len()));
        } else {
            logger.log(3, "ℹ No CODEOWNERS file found (advisory — checked root, .github/, docs/).");
        }
        {
            let l3c = logger.clone();
            ignite_unit_test_runner::run_project_unit_tests(&root, &state.runner, move |m| l3c.log(3, m)).await.map_err(|e| PipelineError::new(3, e.to_string()))?;
        }
        logger.status(3, "success", None);

        logger.status(4, "running", None);
        let mut issues: Vec<Issue> = license_issues.clone();
        if !phase_enabled(4) {
            logger.log(4, "Skipped — disabled by config (phases: [{ id: 4, enabled: false }]).");
        } else {
            let config = default_phase4_config(&org, &repo, Some(project_id));
            let output = ignite_phase4_orchestrator::run_phase4_checks(&root, &state.runner, &state.db, &config).await.map_err(|e| PipelineError::new(4, e.to_string()))?;
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
            let result = validate_overrides(&owned, &requested_overrides);
            if !result.applied.is_empty() {
                let Some(email) = resolve_actor(&body) else {
                    return Err(PipelineError::new(4, "Overrides were submitted but no authenticated user or actor {email,name} was provided — cannot attribute the audit record."));
                };
                logger.log(4, &format!("⚠ {} flagged issue(s) overridden by {email}:", result.applied.len()));
                for (issue, justification) in &result.applied {
                    logger.log(4, &format!("    ⚠ [override] [{:?}] {}:{} — {} — \"{justification}\"", issue.severity, issue.file.as_deref().unwrap_or(""), issue.line.unwrap_or(0), issue.summary));
                    applied_override_ids.insert(issue.id.clone());
                }
                state.db.replace_project_issues(project_id, &issue_inputs, &applied_override_ids);
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

        logger.status(5, "running", None);
        if !phase_enabled(5) {
            logger.log(5, "Skipped — disabled by config (phases: [{ id: 5, enabled: false }]).");
            logger.log(5, "⚠ The org governance workflows will still gate the repo on GitHub after push.");
            logger.status(5, "skipped", None);
        } else if !run_local_ci {
            logger.log(5, "Local CI execution disabled by request (runLocalCi=false).");
            logger.status(5, "skipped", None);
        } else {
            let tooling = ignite_governance_ci::act_tooling(&state.runner).await;
            if !tooling.ok {
                logger.log(5, &format!("⚠ Local CI skipped: {}", tooling.reason.unwrap_or_default()));
                logger.log(5, "⚠ The org governance workflows will still gate the repo on GitHub after push.");
                logger.status(5, "success", None);
            } else {
                let gh_api = ignite_github_api::GithubApi::new(&state.runner);
                let server_token = ignite_github_api::resolve_server_github_token();
                let l5 = logger.clone();
                let wf_file = ignite_governance_ci::fetch_governance_workflow(&workflow_dir, &gh_api, &state.db, "nunomcpereira/ai-guardrails-orchestrator", "ai-guardrails-orchestrator.yml", &server_token, move |m| l5.log(5, m)).await.map_err(|e| PipelineError::new(5, e.to_string()))?;
                logger.log(5, "Executing org governance workflows locally with act (event: push).");
                let l5b = logger.clone();
                ignite_governance_ci::run_actions_locally(&root, &wf_file, &state.runner, &gh_api, &ignite_governance_ci::RunActionsConfig { act_event: "push".to_string(), act_timeout_min: 20 }, move |m| l5b.log(5, m)).await.map_err(|e| PipelineError::new(5, e.to_string()))?;
                logger.log(5, "✓ All org governance jobs passed locally.");
                logger.status(5, "success", None);
            }
        }

        if dry_run {
            logger.log(6, "Simulation mode (dryRun) — all checks passed; skipping repository provisioning and push.");
            logger.status(6, "skipped", None);
            state.db.finish_project("success", None, None, None, project_id);
        } else {
            logger.status(6, "running", None);
            if !source_backup_dir.is_dir() {
                return Err(PipelineError::new(6, "Immutable source snapshot is missing before phase 6."));
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

            state.db.finish_project("success", None, repo_url.as_deref(), pr_url.as_deref(), project_id);
        }

        Ok(())
    }
    .await;

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

    match result {
        Ok(()) => Ok(json!({
            "ok": true,
            "mode": "onboard",
            "dryRun": dry_run,
            "jobId": job_id,
            "projectPath": project_path,
            "repoUrl": repo_url,
            "prUrl": pr_url,
            "phases": phases,
            "events": events,
        })),
        Err(e) => {
            logger.log(e.phase, &format!("✗ {}", e.message));
            logger.status(e.phase, "failed", Some(json!({ "error": e.message })));
            state.db.finish_project("failed", Some(&e.message), None, None, project_id);
            let phases = logger.phase_summary();
            let events = logger.events();
            Err((
                StatusCode::BAD_REQUEST,
                json!({
                    "ok": false,
                    "mode": "onboard",
                    "dryRun": dry_run,
                    "jobId": job_id,
                    "projectPath": project_path,
                    "error": e.message,
                    "failedPhase": e.phase,
                    "issues": e.issues.map(|list| list.iter().map(|i| serde_json::to_value(i).unwrap()).collect::<Vec<_>>()),
                    "phases": phases,
                    "events": events,
                }),
            ))
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

async fn onboard(State(state): State<Arc<AppState>>, Json(body): Json<Value>) -> Response {
    match run_onboard(state, body).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err((status, v)) => (status, Json(v)).into_response(),
    }
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/pipeline/onboard", post(onboard))
}
