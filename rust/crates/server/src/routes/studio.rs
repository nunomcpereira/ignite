//! `/api/pipeline/:jobId/studio/*` — faithful (partial) port of
//! routes/studio.js: file-tree/editor + on-demand report views for a run
//! paused at the review gate ('live' window) or kept alive afterward via
//! `pending_effectivations`/`retained_sources` ('kept' window).
//!
//! Known gaps vs. the Node original:
//! - `/studio/rescan` skips the local LLM deep-scan check, same as every
//!   other already-ported route in this crate — `Phase4Config::llm` has
//!   no wiring to a real config.json/env-driven local LLM endpoint yet
//!   (see MIGRATION_STATUS.md's "config.json loading" gap), so this
//!   route doesn't invent one either.
//! - `/studio/rescan`'s per-file scan cache (`file_scan_cache`) isn't
//!   reused here — each rescan call does a full, uncached sweep. Slower
//!   than Node's cache-hit-heavy rescan, never incorrect.
//! - Stale-issue purge on rescan is precise for the fixed-category
//!   checks (secret / ai-governance / iac-security / license-compliance
//!   / dependency-vulnerability): a finding that no longer reproduces in
//!   one of those categories is removed. `Issue` doesn't carry its
//!   originating phase (an existing simplification shared with
//!   `pipeline_onboard.rs`/`pipeline_interactive.rs`), so this route
//!   never touches issues outside that fixed category set.

use crate::routes::pipeline_interactive::ignite_data_dir;
use crate::routes::pipeline_onboard::issue_to_input;
use crate::state::AppState;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use ignite_db_store::{IssueInput, IssueRow};
use ignite_override_engine::{CheckResult, CodeqlFinding as OeCodeqlFinding, CodeqlResult, Phase4Inputs, RawFinding};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tokio_stream::StreamExt as _;

const STUDIO_MAX_FILE_BYTES: u64 = 500_000;
const EFFECTIVATION_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// The four fixed categories `/studio/rescan` recomputes and purges stale
/// entries for — see the module doc for why this list, not `phase`, is
/// the truth here.
const RESCAN_PURGE_CATEGORIES: &[&str] = &["secret", "ai-governance", "iac-security", "license-compliance", "dependency-vulnerability"];

struct StudioContext {
    project_id: Option<i64>,
    root: PathBuf,
    backup_root: PathBuf,
    org: String,
    repo: String,
}

fn issue_row_to_input(r: &IssueRow) -> IssueInput {
    IssueInput { id: r.id.clone(), phase: r.phase, category: r.category.clone(), severity: r.severity.clone(), score: r.score, summary: r.summary.clone(), file: r.file.clone(), line: r.line, snippet: r.snippet.clone(), cross_file: r.cross_file, chain: r.chain.clone(), cwe: r.cwe.clone() }
}

fn get_issues(state: &AppState, job_id: &str, ctx: &StudioContext) -> Vec<IssueRow> {
    if let Some(live) = state.running_runs.lock().unwrap().get(job_id) {
        if live.review_active && live.project_root.is_some() {
            return live.all_issues.clone();
        }
    }
    match ctx.project_id {
        Some(pid) => state.db.get_project_issues(pid),
        None => vec![],
    }
}

/// Persists a fresh batch of issues, purging any previous issue whose
/// category is in `purge_categories` (or shares an id with something
/// fresh) and keeping everything else untouched. Returns `(resolved_ids,
/// new_ids)`. Shared by `/studio/rescan` (the fixed multi-category purge
/// set) and `/studio/codeql` (just `codeql-sast`, mirroring Node's
/// `replaceCodeql`).
fn replace_issue_batch(state: &AppState, job_id: &str, ctx: &StudioContext, fresh: Vec<ignite_override_engine::Issue>, purge_categories: &[&str]) -> (Vec<String>, Vec<String>) {
    let Some(project_id) = ctx.project_id else { return (vec![], vec![]) };
    let previous = get_issues(state, job_id, ctx);
    let overridden_ids: HashSet<String> = previous.iter().filter(|r| r.status == "overridden").map(|r| r.id.clone()).collect();
    let fresh_ids: HashSet<String> = fresh.iter().map(|i| i.id.clone()).collect();

    let previous_purged_ids: HashSet<String> = previous.iter().filter(|r| purge_categories.contains(&r.category.as_str()) || fresh_ids.contains(&r.id)).map(|r| r.id.clone()).collect();
    let resolved_ids: Vec<String> = previous_purged_ids.difference(&fresh_ids).cloned().collect();
    let previous_ids: HashSet<String> = previous.iter().map(|r| r.id.clone()).collect();
    let new_ids: Vec<String> = fresh_ids.difference(&previous_ids).cloned().collect();

    let kept: Vec<IssueInput> = previous.iter().filter(|r| !purge_categories.contains(&r.category.as_str()) && !fresh_ids.contains(&r.id)).map(issue_row_to_input).collect();
    let mut inputs = kept;
    inputs.extend(fresh.iter().map(issue_to_input));

    state.db.replace_project_issues(project_id, &inputs, &overridden_ids);
    let rows = state.db.get_project_issues(project_id);
    if let Some(live) = state.running_runs.lock().unwrap().get_mut(job_id) {
        if live.review_active {
            live.all_issues = rows;
        }
    }
    (resolved_ids, new_ids)
}

/// Where a project's CodeQL database(s) live once `/studio/codeql` has
/// built one, keyed by project id so `/studio/codeql/query` can find the
/// same database later without rebuilding it. Faithful port of
/// `codeqlDbDirFor` — outside the repo working tree (`IGNITE_DATA_DIR`,
/// `~/.ignite` by default), same reasoning as retained sources.
fn codeql_db_dir_for(project_id: Option<i64>) -> Option<PathBuf> {
    project_id.map(|id| ignite_data_dir().join("codeql-dbs").join(id.to_string()))
}

fn resolve_studio_context(state: &AppState, job_id: &str) -> Result<StudioContext, Response> {
    if let Some(live) = state.running_runs.lock().unwrap().get(job_id) {
        if live.review_active {
            if let (Some(root), Some(backup)) = (&live.project_root, &live.source_backup_dir) {
                return Ok(StudioContext { project_id: live.project_id, root: root.clone(), backup_root: backup.clone(), org: live.org.clone(), repo: live.repo.clone() });
            }
        }
    }

    if let Some(project_id) = state.db.get_project_id_by_job_id(job_id) {
        let mut pending = state.pending_effectivations.lock().unwrap();
        if let Some(entry) = pending.get(&project_id) {
            if entry.created_at.elapsed() >= EFFECTIVATION_TTL {
                pending.remove(&project_id);
            }
        }
        let kept = pending.get(&project_id);
        let source = kept.map(|k| k.source_backup_dir.clone()).or_else(|| state.db.get_retained_source(project_id).map(PathBuf::from));
        if let Some(source) = source {
            let (org, repo) = if let Some(k) = kept { (k.org.clone(), k.repo.clone()) } else if let Some(p) = state.db.get_project(project_id) { (p.org, p.repo) } else { (String::new(), String::new()) };
            return Ok(StudioContext { project_id: Some(project_id), root: source.clone(), backup_root: source, org, repo });
        }
    }

    Err((StatusCode::CONFLICT, Json(json!({ "error": "This run's source is no longer available (already shipped for real, expired, or unknown job)." }))).into_response())
}

async fn tree(State(state): State<Arc<AppState>>, Path(job_id): Path<String>) -> Response {
    let ctx = match resolve_studio_context(&state, &job_id) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let files = match ignite_fs_utils::walk_files(&ctx.root) {
        Ok(files) => files,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))).into_response(),
    };
    let entries: Vec<Value> = files
        .iter()
        .filter_map(|f| {
            let size = std::fs::metadata(f).ok()?.len();
            let rel = f.strip_prefix(&ctx.root).unwrap_or(f).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
            Some(json!({ "path": rel, "size": size }))
        })
        .collect();
    Json(json!({ "ok": true, "files": entries })).into_response()
}

#[derive(serde::Deserialize)]
struct FileQuery {
    path: Option<String>,
}

async fn get_file(State(state): State<Arc<AppState>>, Path(job_id): Path<String>, Query(q): Query<FileQuery>) -> Response {
    let ctx = match resolve_studio_context(&state, &job_id) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let target = match ignite_staging::resolve_within_root(&ctx.root, &q.path.unwrap_or_default()) {
        Ok(p) => p,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))).into_response(),
    };
    let buffer = match std::fs::read(&target) {
        Ok(b) => b,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))).into_response(),
    };
    if ignite_fs_utils::looks_binary(&buffer) {
        return (StatusCode::UNSUPPORTED_MEDIA_TYPE, Json(json!({ "error": "Binary file — cannot display in Studio." }))).into_response();
    }
    if buffer.len() as u64 > STUDIO_MAX_FILE_BYTES {
        return (StatusCode::PAYLOAD_TOO_LARGE, Json(json!({ "error": "File too large to display in Studio." }))).into_response();
    }
    match String::from_utf8(buffer) {
        Ok(content) => Json(json!({ "ok": true, "content": content })).into_response(),
        Err(_) => (StatusCode::BAD_REQUEST, Json(json!({ "error": "File is not valid UTF-8." }))).into_response(),
    }
}

#[derive(serde::Deserialize)]
struct PutFileBody {
    path: Option<String>,
    content: Option<String>,
}

async fn put_file(State(state): State<Arc<AppState>>, Path(job_id): Path<String>, Json(body): Json<PutFileBody>) -> Response {
    let ctx = match resolve_studio_context(&state, &job_id) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let Some(content) = body.content else {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "content (string) is required." }))).into_response();
    };
    let rel_path = body.path.unwrap_or_default();
    let live_target = match ignite_staging::resolve_within_root(&ctx.root, &rel_path) {
        Ok(p) => p,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))).into_response(),
    };
    if let Some(parent) = live_target.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(&live_target, &content) {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))).into_response();
    }
    if ctx.backup_root != ctx.root {
        match ignite_staging::resolve_within_root(&ctx.backup_root, &rel_path) {
            Ok(backup_target) => {
                if let Some(parent) = backup_target.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if let Err(e) = std::fs::write(&backup_target, &content) {
                    return (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))).into_response();
                }
            }
            Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))).into_response(),
        }
    }
    Json(json!({ "ok": true })).into_response()
}

async fn rescan(State(state): State<Arc<AppState>>, Path(job_id): Path<String>) -> Response {
    let ctx = match resolve_studio_context(&state, &job_id) {
        Ok(c) => c,
        Err(r) => return r,
    };

    let secrets_result = match ignite_secrets::check_secrets(&ctx.root, &ignite_secrets::SecretsConfig::default(), &std::collections::HashMap::new()) {
        Ok((r, _)) => r,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))).into_response(),
    };
    let governance_result = match ignite_ai_governance::check_ai_governance(&ctx.root, &std::collections::HashMap::new()) {
        Ok((r, _)) => r,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))).into_response(),
    };
    let iac_result = match ignite_iac_security::check_iac_security(&ctx.root, &state.runner, &ignite_iac_security::IacSecurityConfig::default()).await {
        Ok(r) => r,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))).into_response(),
    };

    let secrets_check = CheckResult { findings: secrets_result.findings.iter().map(|f| RawFinding { file: Some(f.file.clone()), line: Some(f.line as i64), kind: Some(f.kind.clone()), tool: Some(f.tool.to_string()), ..Default::default() }).collect(), engine: Some("built-in".to_string()) };
    let governance_check = CheckResult { findings: governance_result.findings.iter().map(|f| RawFinding { file: Some(f.file.clone()), line: Some(f.line as i64), raw_snippet_text: Some(f.snippet.clone()), ..Default::default() }).collect(), engine: Some("built-in".to_string()) };
    let iac_check = CheckResult { findings: iac_result.findings.iter().map(|f| RawFinding { file: Some(f.file.clone()), line: Some(f.line as i64), kind: Some(f.kind.clone()), tool: Some(f.tool.to_string()), severity: Some(f.severity.clone()), message: Some(f.message.clone()), ..Default::default() }).collect(), engine: Some(iac_result.engine.clone()) };

    let mut fresh_issues = ignite_override_engine::collect_phase4_issues(&Phase4Inputs { secrets: secrets_check, governance: governance_check, iac: Some(iac_check), ..Default::default() });

    let http_client = reqwest::Client::new();
    let client = ignite_deps_dev_client::DepsDevClient::new();
    fresh_issues.extend(ignite_dependency_license_scan::run_license_compliance_check(&ctx.root, &state.runner, &client, &http_client, |_| {}).await);
    fresh_issues.extend(ignite_dependency_license_scan::run_dependency_vulnerability_check(&ctx.root, &client, |_| {}).await);

    let (resolved_ids, new_ids) = replace_issue_batch(&state, &job_id, &ctx, fresh_issues, RESCAN_PURGE_CATEGORIES);
    let issues = get_issues(&state, &job_id, &ctx);
    Json(json!({ "ok": true, "issues": issues, "resolvedIds": resolved_ids, "newIds": new_ids })).into_response()
}

/// On-demand CodeQL run against the currently staged tree — streaming
/// NDJSON, unlike `/studio/rescan`, because a CodeQL database build is a
/// real per-language build+analyze that can take tens of seconds to
/// minutes. Faithful port of the Node `/studio/codeql` route.
async fn codeql_run(State(state): State<Arc<AppState>>, Path(job_id): Path<String>) -> Response {
    let ctx = match resolve_studio_context(&state, &job_id) {
        Ok(c) => c,
        Err(r) => return r,
    };

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let send = {
        let tx = tx.clone();
        move |event: Value| {
            let _ = tx.send(format!("{}\n", event));
        }
    };
    let log = {
        let tx = tx.clone();
        move |message: &str| {
            let _ = tx.send(format!("{}\n", json!({ "type": "log", "message": message })));
        }
    };

    tokio::spawn(async move {
        let keep_db_dir = codeql_db_dir_for(ctx.project_id);
        let codeql_config = crate::phase4_config::from_config(&state.config, &ctx.org, &ctx.repo, ctx.project_id, false).codeql;
        let codeql_result = ignite_codeql_cross_file::check_codeql_cross_file_with_log(
            &ctx.root,
            &state.runner,
            &codeql_config,
            ignite_codeql_cross_file::CodeqlContext { org: Some(&ctx.org), repo: Some(&ctx.repo), store: Some(&state.db), keep_db_dir: keep_db_dir.as_deref() },
            |line| log(line),
        )
        .await;

        let codeql_result = match codeql_result {
            Ok(r) => r,
            Err(e) => {
                log(&format!("✗ {e}"));
                send(json!({ "type": "done", "ok": false, "error": e.to_string() }));
                return;
            }
        };

        if codeql_result.engine != "codeql" {
            log("✓ CodeQL skipped — disabled or not installed (security.codeql.enabled).");
        } else if codeql_result.findings.is_empty() {
            log(&format!("✓ No CodeQL findings across {} language(s) scanned.", codeql_result.languages.len()));
        } else {
            let cross_file_count = codeql_result.findings.iter().filter(|f| f.cross_file).count();
            log(&format!("✗ {} CodeQL finding(s) ({cross_file_count} genuinely cross-file).", codeql_result.findings.len()));
        }

        let oe_result = CodeqlResult {
            findings: codeql_result
                .findings
                .iter()
                .map(|f| OeCodeqlFinding {
                    file: Some(f.file.clone()),
                    line: Some(f.line as i64),
                    kind: Some(f.kind.clone()),
                    severity: Some(f.severity.clone()),
                    message: Some(f.message.clone()),
                    snippet: f.snippet.as_ref().and_then(|s| serde_json::to_value(s).ok()),
                    cross_file: f.cross_file,
                    chain: f.chain.as_ref().and_then(|c| serde_json::to_value(c).ok()),
                    cwe: f.cwe.clone(),
                })
                .collect(),
        };
        let fresh_issues = ignite_override_engine::collect_codeql_issues(&oe_result);

        let (resolved_ids, new_ids) = replace_issue_batch(&state, &job_id, &ctx, fresh_issues, &["codeql-sast"]);
        let issues = get_issues(&state, &job_id, &ctx);
        send(json!({ "type": "done", "ok": true, "issues": issues, "resolvedIds": resolved_ids, "newIds": new_ids, "languages": codeql_result.languages }));
    });

    let stream = UnboundedReceiverStream::new(rx).map(Ok::<String, std::io::Error>);
    let body = Body::from_stream(stream);
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-ndjson")
        .header(header::CACHE_CONTROL, "no-cache")
        .header("X-Accel-Buffering", "no")
        .body(body)
        .unwrap()
}

#[derive(serde::Deserialize)]
struct CodeqlQueryBody {
    #[serde(default)]
    language: String,
    #[serde(default)]
    query: String,
}

/// Ad-hoc CodeQL query — runs a user-supplied `.ql` query against
/// whichever database `/studio/codeql` already built for this
/// project/language, rather than the fixed security-extended suite.
/// Faithful port of the Node `/studio/codeql/query` route. Purely
/// exploratory — results aren't persisted as issues or cached.
async fn codeql_query(State(state): State<Arc<AppState>>, Path(job_id): Path<String>, Json(body): Json<CodeqlQueryBody>) -> Response {
    let ctx = match resolve_studio_context(&state, &job_id) {
        Ok(c) => c,
        Err(r) => return r,
    };

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let send = {
        let tx = tx.clone();
        move |event: Value| {
            let _ = tx.send(format!("{}\n", event));
        }
    };
    let log = {
        let tx = tx.clone();
        move |message: &str| {
            let _ = tx.send(format!("{}\n", json!({ "type": "log", "message": message })));
        }
    };

    let language = body.language.trim().to_string();
    let query_text = body.query;

    tokio::spawn(async move {
        let result = async {
            if language.is_empty() {
                return Err("language is required.".to_string());
            }
            if query_text.trim().is_empty() {
                return Err("query is required.".to_string());
            }
            if query_text.len() > 20_000 {
                return Err("Query is too large (max 20,000 characters).".to_string());
            }
            let Some(db_root) = codeql_db_dir_for(ctx.project_id) else {
                return Err("No CodeQL database available for this project.".to_string());
            };
            let db_dir = db_root.join(&language).join("db");
            let timeout_ms = crate::phase4_config::from_config(&state.config, &ctx.org, &ctx.repo, ctx.project_id, false).codeql.timeout_ms;
            ignite_codeql_cross_file::run_custom_codeql_query(&ctx.root, &db_dir, &language, &query_text, &state.runner, timeout_ms, |line| log(line)).await
        }
        .await;

        match result {
            Ok(r) => {
                log(&format!("✓ {} row(s) returned.", r.rows.len()));
                send(json!({ "type": "done", "ok": true, "columns": r.columns, "rows": r.rows }));
            }
            Err(e) => {
                log(&format!("✗ {e}"));
                send(json!({ "type": "done", "ok": false, "error": e }));
            }
        }
    });

    let stream = UnboundedReceiverStream::new(rx).map(Ok::<String, std::io::Error>);
    let body = Body::from_stream(stream);
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-ndjson")
        .header(header::CACHE_CONTROL, "no-cache")
        .header("X-Accel-Buffering", "no")
        .body(body)
        .unwrap()
}

async fn dependencies(State(state): State<Arc<AppState>>, Path(job_id): Path<String>) -> Response {
    let ctx = match resolve_studio_context(&state, &job_id) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let client = ignite_deps_dev_client::DepsDevClient::new();
    let npm_http = reqwest::Client::new();
    match ignite_dependency_license_scan::scan_dependency_licenses(&ctx.root, &state.runner, &client, &npm_http, |_| {}).await {
        Ok(scan) => Json(json!({ "ok": true, "engine": scan.engine, "projectLicense": scan.project_license.map(|p| json!({ "spdxId": p.spdx_id, "confidence": p.confidence, "tier": p.tier, "reason": p.reason })), "manifests": scan.manifests })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))).into_response(),
    }
}

async fn sbom(State(state): State<Arc<AppState>>, Path(job_id): Path<String>) -> Response {
    let ctx = match resolve_studio_context(&state, &job_id) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let manifests = ignite_package_hallucination::default_manifests();
    // routes/studio.js's equivalent spreads the check result's own fields
    // (`{ engine, sbom }`/`{ engine, metrics }`/`{ engine, posture }`) into
    // the top-level JSON object (`res.json({ ok: true, ...result })`), not
    // nested under a same-named key — the frontend's render* functions read
    // `data.engine`/`data.sbom` directly. Nesting here (as this route
    // previously did) doubled up the key (`data.sbom.sbom`) and left every
    // field the frontend actually reads undefined.
    match ignite_sbom::generate_sbom(&ctx.root, &state.runner, state.config.sbom.syft.enabled, &manifests, 1000).await {
        Ok(result) => Json(json!({ "ok": true, "engine": result.engine, "sbom": result.sbom })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))).into_response(),
    }
}

async fn loc_metrics(State(state): State<Arc<AppState>>, Path(job_id): Path<String>) -> Response {
    let ctx = match resolve_studio_context(&state, &job_id) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let result = ignite_loc_metrics::generate_loc_metrics(&ctx.root, &state.runner, state.config.metrics.gocloc.enabled).await;
    Json(json!({ "ok": true, "engine": result.engine, "metrics": result.metrics })).into_response()
}

async fn posture(State(state): State<Arc<AppState>>, Path(job_id): Path<String>) -> Response {
    let ctx = match resolve_studio_context(&state, &job_id) {
        Ok(c) => c,
        Err(r) => return r,
    };
    // Reuses the real config-resolved ruleset path (absolute path to
    // ignite-posture-rules.yaml next to config.json — see
    // ignite_config::load_config), not a hardcoded empty string: an empty
    // `--config` still runs semgrep "successfully" with zero rules loaded,
    // silently producing an all-MISSING report instead of a real posture
    // read — wrong, not just unavailable.
    let config = ignite_feature_posture::FeaturePostureConfig { enabled: state.config.compliance.posture.enabled, ruleset: state.config.compliance.posture.ruleset.clone(), max_scan_file_bytes: 1_000_000 };
    match ignite_feature_posture::check_feature_posture(&ctx.root, &state.runner, &config).await {
        Ok(result) => Json(json!({ "ok": true, "engine": result.engine, "posture": result.posture })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))).into_response(),
    }
}

async fn provenance(State(state): State<Arc<AppState>>, Path(job_id): Path<String>) -> Response {
    let ctx = match resolve_studio_context(&state, &job_id) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match ignite_provenance::generate_provenance(&ctx.root, &state.runner, "0.1.0", ignite_provenance::ProvenanceParams { org: Some(&ctx.org), repo: Some(&ctx.repo), job_id: Some(&job_id) }).await {
        Ok(prov) => Json(json!({ "ok": true, "provenance": prov })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))).into_response(),
    }
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/pipeline/:job_id/studio/tree", get(tree))
        .route("/api/pipeline/:job_id/studio/file", get(get_file).put(put_file))
        .route("/api/pipeline/:job_id/studio/rescan", axum::routing::post(rescan))
        .route("/api/pipeline/:job_id/studio/codeql", axum::routing::post(codeql_run))
        .route("/api/pipeline/:job_id/studio/codeql/query", axum::routing::post(codeql_query))
        .route("/api/pipeline/:job_id/studio/dependencies", get(dependencies))
        .route("/api/pipeline/:job_id/studio/sbom", get(sbom))
        .route("/api/pipeline/:job_id/studio/loc-metrics", get(loc_metrics))
        .route("/api/pipeline/:job_id/studio/posture", get(posture))
        .route("/api/pipeline/:job_id/studio/provenance", get(provenance))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::review_gate::ReviewGate;
    use crate::state::{self, LiveRun};
    use std::collections::HashMap;
    use std::sync::Mutex;

    async fn spawn_test_server_with_live_run(root: PathBuf, backup: PathBuf) -> (String, Arc<AppState>, String) {
        let db_dir = tempfile::tempdir().unwrap();
        let db = ignite_db_store::DbStore::open(&db_dir.path().join("test.db")).unwrap();
        let job_id = "studio-test-job".to_string();
        let project_id = db.create_project(&job_id, "acme", "widgets", false, "api", None);

        let app_state = Arc::new(AppState {
            runner: state::default_runner(),
            db,
            running_runs: Mutex::new(HashMap::new()),
            pending_effectivations: Mutex::new(HashMap::new()),
            review_gate: ReviewGate::default(),
            llm_config: state::default_llm_config(),
            config: ignite_config::Config::default(),
            package_hallucination_checker: state::default_package_hallucination_checker(),
        });
        app_state.running_runs.lock().unwrap().insert(
            job_id.clone(),
            LiveRun { org: "acme".to_string(), repo: "widgets".to_string(), project_id: Some(project_id), all_issues: vec![], project_root: Some(root), source_backup_dir: Some(backup), review_active: true },
        );

        let router = axum::Router::new().merge(router()).with_state(app_state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        std::mem::forget(db_dir);
        (format!("http://{addr}"), app_state, job_id)
    }

    #[tokio::test]
    async fn tree_and_file_roundtrip_on_live_run() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.js"), b"console.log('hi');\n").unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        std::fs::write(backup_dir.path().join("app.js"), b"console.log('hi');\n").unwrap();

        let (base, _state, job_id) = spawn_test_server_with_live_run(dir.path().to_path_buf(), backup_dir.path().to_path_buf()).await;
        let client = reqwest::Client::new();

        let tree: Value = client.get(format!("{base}/api/pipeline/{job_id}/studio/tree")).send().await.unwrap().json().await.unwrap();
        assert_eq!(tree["ok"], true);
        assert!(tree["files"].as_array().unwrap().iter().any(|f| f["path"] == "app.js"));

        let file: Value = client.get(format!("{base}/api/pipeline/{job_id}/studio/file?path=app.js")).send().await.unwrap().json().await.unwrap();
        assert_eq!(file["ok"], true);
        assert!(file["content"].as_str().unwrap().contains("console.log"));

        let put_res = client.put(format!("{base}/api/pipeline/{job_id}/studio/file")).json(&json!({ "path": "app.js", "content": "console.log('edited');\n" })).send().await.unwrap();
        assert_eq!(put_res.status(), 200);
        assert_eq!(std::fs::read_to_string(dir.path().join("app.js")).unwrap(), "console.log('edited');\n");
        assert_eq!(std::fs::read_to_string(backup_dir.path().join("app.js")).unwrap(), "console.log('edited');\n", "edit must land in the immutable backup too, since phase 6 publishes from there");

        std::mem::forget(dir);
        std::mem::forget(backup_dir);
    }

    #[tokio::test]
    async fn file_path_traversal_is_blocked() {
        let dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let (base, _state, job_id) = spawn_test_server_with_live_run(dir.path().to_path_buf(), backup_dir.path().to_path_buf()).await;
        let client = reqwest::Client::new();
        let res = client.get(format!("{base}/api/pipeline/{job_id}/studio/file?path=../../../../etc/passwd")).send().await.unwrap();
        assert_eq!(res.status(), 400);
        std::mem::forget(dir);
        std::mem::forget(backup_dir);
    }

    #[tokio::test]
    async fn unknown_job_returns_409() {
        let dir = tempfile::tempdir().unwrap();
        let (base, _state, _job_id) = spawn_test_server_with_live_run(dir.path().to_path_buf(), dir.path().to_path_buf()).await;
        let client = reqwest::Client::new();
        let res = client.get(format!("{base}/api/pipeline/no-such-job/studio/tree")).send().await.unwrap();
        assert_eq!(res.status(), 409);
        std::mem::forget(dir);
    }

    #[tokio::test]
    async fn rescan_detects_secret_and_is_idempotent_on_second_pass() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.js"), format!("const password = '{}';\n", "hunter2-very-secret-value")).unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        std::fs::write(backup_dir.path().join("app.js"), format!("const password = '{}';\n", "hunter2-very-secret-value")).unwrap();

        let (base, state, job_id) = spawn_test_server_with_live_run(dir.path().to_path_buf(), backup_dir.path().to_path_buf()).await;
        let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(60)).build().unwrap();

        let first: Value = client.post(format!("{base}/api/pipeline/{job_id}/studio/rescan")).send().await.unwrap().json().await.unwrap();
        assert_eq!(first["ok"], true);
        let issues = first["issues"].as_array().unwrap();
        assert!(issues.iter().any(|i| i["category"] == "secret"), "expected a secret finding, got {issues:?}");
        assert!(!first["newIds"].as_array().unwrap().is_empty());

        // Fix the file, rescan again: the secret finding must be purged.
        std::fs::write(dir.path().join("app.js"), b"console.log('clean');\n").unwrap();
        std::fs::write(backup_dir.path().join("app.js"), b"console.log('clean');\n").unwrap();
        let second: Value = client.post(format!("{base}/api/pipeline/{job_id}/studio/rescan")).send().await.unwrap().json().await.unwrap();
        assert_eq!(second["ok"], true);
        assert!(second["issues"].as_array().unwrap().iter().all(|i| i["category"] != "secret"));
        assert!(!second["resolvedIds"].as_array().unwrap().is_empty());

        let _ = &state; // keep state alive for the duration of the requests above
        std::mem::forget(dir);
        std::mem::forget(backup_dir);
    }

    #[tokio::test]
    async fn loc_metrics_and_posture_endpoints_respond_ok() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.js"), b"console.log('hi');\n").unwrap();
        let (base, _state, job_id) = spawn_test_server_with_live_run(dir.path().to_path_buf(), dir.path().to_path_buf()).await;
        let client = reqwest::Client::new();

        // Regression test for a real shape bug: these three responses must
        // spread the check result's own fields at the top level (`engine`,
        // `sbom`/`metrics`/`posture` as siblings of `ok`), matching
        // routes/studio.js's `res.json({ ok: true, ...result })`. Nesting
        // under a same-named key instead (`data.sbom.sbom`) leaves every
        // field the frontend's renderStudio* functions actually read
        // (`data.engine`, `data.sbom`, etc.) undefined — this is exactly
        // what caused a "Cannot read properties of undefined" crash and
        // blank SBOM/LOC/Posture panels in the real browser UI.
        let sbom: Value = client.get(format!("{base}/api/pipeline/{job_id}/studio/sbom")).send().await.unwrap().json().await.unwrap();
        assert_eq!(sbom["ok"], true);
        assert!(sbom.get("engine").is_some(), "engine must be a top-level sibling of ok, not nested under sbom: {sbom}");
        assert!(sbom.get("sbom").is_some(), "sbom field missing: {sbom}");
        assert!(sbom["sbom"].get("sbom").is_none(), "sbom must not be double-nested (data.sbom.sbom): {sbom}");

        let loc: Value = client.get(format!("{base}/api/pipeline/{job_id}/studio/loc-metrics")).send().await.unwrap().json().await.unwrap();
        assert_eq!(loc["ok"], true);
        assert!(loc.get("engine").is_some(), "engine must be top-level, not nested under metrics: {loc}");
        assert!(loc["metrics"].get("metrics").is_none(), "metrics must not be double-nested: {loc}");

        let posture: Value = client.get(format!("{base}/api/pipeline/{job_id}/studio/posture")).send().await.unwrap().json().await.unwrap();
        assert_eq!(posture["ok"], true);
        assert!(posture.get("engine").is_some(), "engine must be top-level, not nested under posture: {posture}");
        assert!(posture["posture"].get("posture").is_none(), "posture must not be double-nested: {posture}");

        let prov: Value = client.get(format!("{base}/api/pipeline/{job_id}/studio/provenance")).send().await.unwrap().json().await.unwrap();
        assert_eq!(prov["ok"], true);

        std::mem::forget(dir);
    }

    async fn read_ndjson(res: reqwest::Response) -> Vec<Value> {
        let text = res.text().await.unwrap();
        text.lines().filter(|l| !l.is_empty()).map(|l| serde_json::from_str(l).unwrap()).collect()
    }

    /// No built-database case: `/studio/codeql/query` must fail fast with
    /// a clear message and never shell out to `codeql` at all — this
    /// doesn't need the real binary installed.
    #[tokio::test]
    async fn codeql_query_without_a_built_database_reports_a_clear_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.js"), b"console.log('hi');\n").unwrap();
        let (base, _state, job_id) = spawn_test_server_with_live_run(dir.path().to_path_buf(), dir.path().to_path_buf()).await;
        let client = reqwest::Client::new();

        let res = client
            .post(format!("{base}/api/pipeline/{job_id}/studio/codeql/query"))
            .json(&json!({ "language": "javascript", "query": "select 1" }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        let events = read_ndjson(res).await;
        let done = events.iter().find(|e| e["type"] == "done").expect("expected a done event");
        assert_eq!(done["ok"], false);
        assert!(done["error"].as_str().unwrap().contains("No CodeQL database"), "unexpected error: {done:?}");

        std::mem::forget(dir);
    }

    #[tokio::test]
    async fn codeql_query_rejects_missing_language_and_query() {
        let dir = tempfile::tempdir().unwrap();
        let (base, _state, job_id) = spawn_test_server_with_live_run(dir.path().to_path_buf(), dir.path().to_path_buf()).await;
        let client = reqwest::Client::new();

        let res = client.post(format!("{base}/api/pipeline/{job_id}/studio/codeql/query")).json(&json!({})).send().await.unwrap();
        let events = read_ndjson(res).await;
        let done = events.iter().find(|e| e["type"] == "done").unwrap();
        assert_eq!(done["ok"], false);
        assert!(done["error"].as_str().unwrap().contains("language is required"));

        std::mem::forget(dir);
    }

    /// Real end-to-end: "Run CodeQL" builds+persists a database, then an
    /// ad-hoc query against that same persisted database finds our one
    /// function. Skips (not fails) if the `codeql` CLI isn't on PATH in
    /// this environment.
    #[tokio::test]
    async fn codeql_run_persists_database_and_query_can_reuse_it() {
        let mut check = std::process::Command::new("codeql");
        check.arg("version");
        if check.output().map(|o| !o.status.success()).unwrap_or(true) {
            eprintln!("skipping: codeql not installed on PATH");
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.js"), b"function add(a, b) { return a + b; }\nmodule.exports = add;\n").unwrap();
        let (base, state, job_id) = spawn_test_server_with_live_run(dir.path().to_path_buf(), dir.path().to_path_buf()).await;
        let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(300)).build().unwrap();

        let res = client.post(format!("{base}/api/pipeline/{job_id}/studio/codeql")).send().await.unwrap();
        assert_eq!(res.status(), 200);
        let events = read_ndjson(res).await;
        let done = events.iter().find(|e| e["type"] == "done").expect("expected a done event");
        assert_eq!(done["ok"], true, "codeql run failed: {done:?}");
        assert_eq!(done["languages"].as_array().unwrap(), &vec![json!("javascript")]);

        let project_id = state.running_runs.lock().unwrap().get(&job_id).unwrap().project_id.unwrap();
        let db_dir = codeql_db_dir_for(Some(project_id)).unwrap().join("javascript").join("db");
        assert!(db_dir.exists(), "expected the CodeQL database to be persisted at {db_dir:?}");

        let query_res = client
            .post(format!("{base}/api/pipeline/{job_id}/studio/codeql/query"))
            .json(&json!({ "language": "javascript", "query": "import javascript\nfrom Function f\nselect f, f.getName()\n" }))
            .send()
            .await
            .unwrap();
        let query_events = read_ndjson(query_res).await;
        let query_done = query_events.iter().find(|e| e["type"] == "done").expect("expected a done event");
        assert_eq!(query_done["ok"], true, "ad-hoc query failed: {query_done:?}");
        assert!(!query_done["rows"].as_array().unwrap().is_empty(), "expected at least one row for the `add` function");

        let _ = std::fs::remove_dir_all(codeql_db_dir_for(Some(project_id)).unwrap());
        std::mem::forget(dir);
    }
}
