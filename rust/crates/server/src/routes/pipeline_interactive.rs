//! POST /api/pipeline — faithful port of routes/pipeline-interactive.js:
//! the browser UI's interactive pipeline. Multipart ZIP/folder upload,
//! streaming newline-delimited JSON progress over the whole response
//! body, issues accumulated across every phase and shown together at one
//! review gate (`crate::review_gate`) right before phase 6
//! provisioning/push, and `dryRun` support.
//!
//! Known gaps vs. server.js's version (same category of gap as
//! pipeline_onboard.rs already has): push-token resolution now prefers a
//! connected session (`crate::auth::resolve_effective_github_token`,
//! resolved once from the request headers before the run is spawned)
//! over the `resolve_server_github_token()` env fallback; no
//! failure-insight (local LLM) generation, no failure-email
//! notification, no config.json phase-enable
//! overrides (hardcoded like the sibling routes), and a Phase 5 CI
//! failure is recorded as one generic issue rather than resolved to
//! per-line issues (`resolveGovernanceCiLocation`/
//! `filterGovernanceCiFailureLines` aren't ported). `POST
//! /api/pipeline/:jobId/review-decision` (routes/review-gate.js) is also
//! mounted here — thin enough not to need the full route file split out.
//! The "Effectivate" half of routes/review-gate.js lives in
//! `crate::routes::effectivate`.

use crate::review_gate::{Actor, ReviewDecisionInput};
use crate::routes::pipeline_onboard::{default_phase4_config, issue_to_input};
use crate::state::{AppState, LiveRun, PendingEffectivation};
use axum::body::Body;
use axum::extract::{Multipart, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use ignite_override_engine::{score_for_issue, validate_overrides, Issue, Severity, SubmittedOverride};
use ignite_staging::UploadFile;
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tokio_stream::StreamExt as _;

static GITHUB_NAME_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$").unwrap());
static REPO_NAME_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9._-]{1,100}$").unwrap());

/// A run is retained for later "Effectivate" (or just Studio browsing) up
/// to this many most-recently-completed jobs that made it through Phase 3
/// staging — mirrors server.js's `listEvictableRetainedSources(5)`.
const RETAINED_PROJECTS_KEEP: i64 = 5;

pub(crate) fn ignite_data_dir() -> PathBuf {
    std::env::var("IGNITE_DATA_DIR").map(PathBuf::from).unwrap_or_else(|_| dirs_home().join(".ignite"))
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("."))
}

fn write_temp_upload(bytes: &[u8]) -> std::io::Result<PathBuf> {
    let path = std::env::temp_dir().join(format!("ignite-upload-{}", uuid::Uuid::new_v4()));
    std::fs::write(&path, bytes)?;
    Ok(path)
}

/// Matches server.js's multer config exactly (server.js:161-164:
/// `{ fileSize: MAX_ZIP_BYTES, files: 100000 }`) — `fileSize` bounds each
/// individual file *part*, `files` bounds the file-part *count*. Neither is
/// a whole-request-body cap: a folder upload with many small files can
/// total well over 1GB as long as no single file exceeds it, same as Node.
/// Enforced by streaming each file field via `.chunk()` instead of
/// `.bytes()` (which would buffer past the limit before we could reject),
/// with the whole-body `DefaultBodyLimit` disabled on this route (see
/// `router()` below) so it can't impose its own, different cap underneath
/// this one.
const MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_FILES: usize = 100_000;

async fn read_field_bytes_limited(field: &mut axum::extract::multipart::Field<'_>) -> Result<Vec<u8>, (StatusCode, Value)> {
    read_field_bytes_limited_to(field, MAX_FILE_BYTES).await
}

/// `max_bytes`-parameterized core so tests can exercise real rejection
/// behavior at a small scale instead of needing an actual 1GB upload.
async fn read_field_bytes_limited_to(field: &mut axum::extract::multipart::Field<'_>, max_bytes: u64) -> Result<Vec<u8>, (StatusCode, Value)> {
    let mut buf = Vec::new();
    while let Some(chunk) = field.chunk().await.map_err(|e| (StatusCode::BAD_REQUEST, json!({ "error": e.to_string() })))? {
        if buf.len() as u64 + chunk.len() as u64 > max_bytes {
            return Err((StatusCode::PAYLOAD_TOO_LARGE, json!({ "error": format!("File too large (max {max_bytes} bytes per file).") })));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

struct ParsedUpload {
    org: String,
    repo: String,
    gxp_requested: bool,
    dry_run: bool,
    gxp_links: Vec<Value>,
    archive: Option<(PathBuf, String, u64)>,
    dir_files: Vec<UploadFile>,
    dir_file_count_and_bytes: (usize, u64),
    gxp_doc_files: Vec<(String, Option<String>, Vec<u8>)>,
    temp_paths_to_clean: Vec<PathBuf>,
}

async fn parse_multipart(mut multipart: Multipart) -> Result<ParsedUpload, (StatusCode, Value)> {
    let bad = |e: String| (StatusCode::BAD_REQUEST, json!({ "error": e }));

    let mut org = String::new();
    let mut repo = String::new();
    let mut gxp_requested = false;
    let mut dry_run = false;
    let mut gxp_links_raw = String::from("[]");
    let mut rel_paths_raw = String::from("[]");
    let mut archive: Option<(PathBuf, String, u64)> = None;
    let mut dir_files: Vec<UploadFile> = Vec::new();
    let mut dir_file_names: Vec<String> = Vec::new();
    let mut gxp_doc_files: Vec<(String, Option<String>, Vec<u8>)> = Vec::new();
    let mut temp_paths_to_clean: Vec<PathBuf> = Vec::new();
    // Mirrors multer's `files: 100000` — only file-bearing fields
    // (archive/files/gxpDocs) count toward this, not text fields like
    // org/repo/dryRun, matching multer's own "max number of file fields"
    // semantics.
    let mut file_field_count: usize = 0;

    while let Some(mut field) = multipart.next_field().await.map_err(|e| bad(e.to_string()))? {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "org" => org = field.text().await.unwrap_or_default().trim().to_string(),
            "repo" => repo = field.text().await.unwrap_or_default().trim().to_string(),
            "gxp" => gxp_requested = field.text().await.unwrap_or_default() == "true",
            "dryRun" => dry_run = field.text().await.unwrap_or_default() == "true",
            "gxpLinks" => gxp_links_raw = field.text().await.unwrap_or_else(|_| "[]".to_string()),
            "paths" => rel_paths_raw = field.text().await.unwrap_or_else(|_| "[]".to_string()),
            "archive" => {
                file_field_count += 1;
                if file_field_count > MAX_FILES {
                    return Err((StatusCode::PAYLOAD_TOO_LARGE, json!({ "error": format!("Too many files (max {MAX_FILES}).") })));
                }
                let fname = field.file_name().unwrap_or("archive.zip").to_string();
                let bytes = read_field_bytes_limited(&mut field).await?;
                let size = bytes.len() as u64;
                let path = write_temp_upload(&bytes).map_err(|e| bad(e.to_string()))?;
                temp_paths_to_clean.push(path.clone());
                archive = Some((path, fname, size));
            }
            "files" => {
                file_field_count += 1;
                if file_field_count > MAX_FILES {
                    return Err((StatusCode::PAYLOAD_TOO_LARGE, json!({ "error": format!("Too many files (max {MAX_FILES}).") })));
                }
                let fname = field.file_name().unwrap_or("").to_string();
                let bytes = read_field_bytes_limited(&mut field).await?;
                let size = bytes.len() as u64;
                let path = write_temp_upload(&bytes).map_err(|e| bad(e.to_string()))?;
                temp_paths_to_clean.push(path.clone());
                dir_file_names.push(fname);
                dir_files.push(UploadFile { temp_path: path, rel_path: String::new(), size });
            }
            "gxpDocs" => {
                file_field_count += 1;
                if file_field_count > MAX_FILES {
                    return Err((StatusCode::PAYLOAD_TOO_LARGE, json!({ "error": format!("Too many files (max {MAX_FILES}).") })));
                }
                let fname = field.file_name().unwrap_or("document").to_string();
                let mime = field.content_type().map(|c| c.to_string());
                let bytes = read_field_bytes_limited(&mut field).await?;
                gxp_doc_files.push((fname, mime, bytes));
            }
            _ => {
                let _ = field.bytes().await;
            }
        }
    }

    let rel_paths: Vec<String> = serde_json::from_str(&rel_paths_raw).unwrap_or_default();
    for (i, uf) in dir_files.iter_mut().enumerate() {
        uf.rel_path = rel_paths.get(i).cloned().unwrap_or_else(|| dir_file_names[i].clone());
    }
    let gxp_links: Vec<Value> = serde_json::from_str(&gxp_links_raw).unwrap_or_default();
    let dir_file_count_and_bytes = (dir_files.len(), dir_files.iter().map(|f| f.size).sum());

    Ok(ParsedUpload { org, repo, gxp_requested, dry_run, gxp_links, archive, dir_files, dir_file_count_and_bytes, gxp_doc_files, temp_paths_to_clean })
}

struct PhaseRecord {
    state: String,
    logs: Vec<String>,
}

struct EventLog {
    state: Arc<AppState>,
    meta: Vec<super::phase_meta::PhaseMeta>,
    tx: tokio::sync::mpsc::UnboundedSender<String>,
    record: Mutex<HashMap<i64, PhaseRecord>>,
    project_id: Mutex<Option<i64>>,
}

impl EventLog {
    fn send(&self, ev: Value) {
        let _ = self.tx.send(format!("{}\n", ev));
    }

    fn set_project_id(&self, id: i64) {
        *self.project_id.lock().unwrap() = Some(id);
    }

    fn project_id(&self) -> Option<i64> {
        *self.project_id.lock().unwrap()
    }

    fn persist(&self, phase: i64) {
        let Some(project_id) = self.project_id() else { return };
        let record = self.record.lock().unwrap();
        if let Some(rec) = record.get(&phase) {
            self.state.db.upsert_step(project_id, phase, &super::phase_meta::phase_title(&self.meta, phase), &rec.state, &rec.logs.join("\n"));
        }
    }

    fn log(&self, phase: i64, message: &str) {
        {
            let mut record = self.record.lock().unwrap();
            record.entry(phase).or_insert_with(|| PhaseRecord { state: "pending".to_string(), logs: vec![] }).logs.push(message.to_string());
        }
        self.send(json!({ "type": "log", "phase": phase, "message": message }));
        self.persist(phase);
    }

    fn status(&self, phase: i64, state: &str, extra: Option<Value>) {
        {
            let mut record = self.record.lock().unwrap();
            record.entry(phase).or_insert_with(|| PhaseRecord { state: "pending".to_string(), logs: vec![] }).state = state.to_string();
        }
        let mut ev = json!({ "type": "status", "phase": phase, "state": state });
        if let Some(extra) = extra {
            if let (Some(ev_obj), Some(extra_obj)) = (ev.as_object_mut(), extra.as_object()) {
                for (k, v) in extra_obj {
                    ev_obj.insert(k.clone(), v.clone());
                }
            }
        }
        self.send(ev);
        self.persist(phase);
    }

    fn all_phase_records(&self) -> HashMap<i64, (String, Vec<String>)> {
        self.record.lock().unwrap().iter().map(|(k, v)| (*k, (v.state.clone(), v.logs.clone()))).collect()
    }
}

fn new_issue(id: String, phase: i64, category: &str, severity: Severity, summary: String, file: Option<String>, line: Option<i64>) -> Issue {
    let _ = phase;
    Issue { id, category: category.to_string(), severity, score: score_for_issue(category, severity), summary, file, line, snippet: None, cross_file: false, chain: None, duplicate_ref: None, cwe: None, owasp: None }
}

fn resolve_actor_from_body(actor_value: &Value) -> Option<Actor> {
    let actor = actor_value;
    let email = actor.get("email").and_then(|v| v.as_str()).unwrap_or("").trim().to_lowercase();
    if !ignite_auth::is_valid_email(&email) {
        return None;
    }
    let name = actor.get("name").and_then(|v| v.as_str()).filter(|n| !n.trim().is_empty()).unwrap_or(&email).to_string();
    Some(Actor { email, name })
}

/// Refreshes `AppState::running_runs`' cached issue snapshot for this job
/// from the DB, so a concurrent read (sarif.rs/github_annotations.rs via
/// `job_issues::lookup_job_issues`) sees the same shape whether the run
/// is still live or already finished. No-op until `project_id` is known.
fn persist_issues_snapshot(state: &AppState, job_id: &str, project_id: Option<i64>, issues: &[Issue], overridden_ids: &std::collections::HashSet<String>) {
    let Some(project_id) = project_id else { return };
    let inputs: Vec<ignite_db_store::IssueInput> = issues.iter().map(issue_to_input).collect();
    state.db.replace_project_issues(project_id, &inputs, overridden_ids);
    let rows = state.db.get_project_issues(project_id);
    if let Some(live) = state.running_runs.lock().unwrap().get_mut(job_id) {
        live.all_issues = rows;
    }
}

async fn run_interactive_pipeline(state: Arc<AppState>, upload: ParsedUpload, log: Arc<EventLog>, job_id: String, session_gh_token: String) {
    let org = upload.org.clone();
    let repo = upload.repo.clone();
    let is_gxp = super::phase_meta::phase_enabled(&log.meta, 2) && upload.gxp_requested;
    let dry_run = upload.dry_run;

    log.send(json!({ "type": "job", "jobId": job_id }));

    let staging_dir = std::env::temp_dir().join("gatekeeper-staging").join(&job_id);
    let source_backup_dir = PathBuf::from(format!("{}-source-backup", staging_dir.to_string_lossy()));
    let publish_dir = PathBuf::from(format!("{}-publish", staging_dir.to_string_lossy()));
    let workflow_dir = PathBuf::from(format!("{}-workflows", staging_dir.to_string_lossy()));

    let mut all_issues: Vec<Issue> = Vec::new();
    let mut project_id: Option<i64> = None;
    let mut phase1_ok = false;
    let mut project_root_ready = false;
    let mut project_root: Option<PathBuf> = None;
    let mut snapshot_ready = false;
    let mut shipped_for_real = false;
    let mut keep_source_backup_dir = false;
    let mut gh_token = String::new();

    state.running_runs.lock().unwrap().insert(
        job_id.clone(),
        LiveRun { org: org.clone(), repo: repo.clone(), project_id: None, all_issues: vec![], project_root: None, source_backup_dir: None, review_active: false },
    );

    macro_rules! persist {
        () => {
            persist_issues_snapshot(&state, &job_id, project_id, &all_issues, &std::collections::HashSet::new())
        };
    }

    let outcome: Result<(), (i64, String)> = 'run: {
        // ---------------- Phase 1: input validation ----------------
        log.status(1, "running", None);
        match (|| -> Result<(), String> {
            if upload.archive.is_none() && upload.dir_files.is_empty() {
                return Err("No ZIP archive or folder upload received.".to_string());
            }
            if !GITHUB_NAME_RE.is_match(&org) {
                return Err(format!("Invalid GitHub organization name: \"{org}\""));
            }
            if !REPO_NAME_RE.is_match(&repo) || repo == "." || repo == ".." {
                return Err(format!("Invalid repository name: \"{repo}\""));
            }
            if !dry_run {
                gh_token = session_gh_token.clone();
                if gh_token.is_empty() {
                    return Err("Log in and connect your GitHub account before running for real, or check \"Simulation mode\".".to_string());
                }
            }
            Ok(())
        })() {
            Ok(()) => {
                log.log(1, &format!("Job {job_id}"));
                if let Some((_, fname, size)) = &upload.archive {
                    log.log(1, &format!("Archive: {fname} ({:.1} KB)", *size as f64 / 1024.0));
                } else {
                    let (count, bytes) = upload.dir_file_count_and_bytes;
                    log.log(1, &format!("Folder upload: {count} files ({:.1} MB)", bytes as f64 / 1_048_576.0));
                }
                log.log(1, &format!("Target: {org}/{repo} (private)"));
                log.log(1, &format!("GxP-regulated process: {}", if is_gxp { "YES — validation documents are mandatory" } else { "no" }));
                if dry_run {
                    log.log(1, "Simulation mode (dryRun) — phase 6 provisioning/push will be skipped.");
                }
                let scan_location = if let Some((_, fname, _)) = &upload.archive { format!("Archive: {fname}") } else { format!("Folder upload: {} file(s)", upload.dir_file_count_and_bytes.0) };
                let pid = state.db.create_project(&job_id, &org, &repo, is_gxp, "ui", Some(&scan_location));
                project_id = Some(pid);
                log.set_project_id(pid);
                if let Some(live) = state.running_runs.lock().unwrap().get_mut(&job_id) {
                    live.project_id = Some(pid);
                }
                log.status(1, "success", None);
                phase1_ok = true;
            }
            Err(msg) => {
                log.log(1, &format!("✗ {msg}"));
                log.status(1, "failed", Some(json!({ "error": msg })));
                all_issues.push(new_issue("phase1::input-validation".to_string(), 1, "input-validation", Severity::Error, msg, None, None));
                persist!();
            }
        }

        // ---------------- Phase 2: GxP validation documents ----------------
        if !phase1_ok {
            log.log(2, "Skipped — blocked by Phase 1 failure (no project record to attach documents to).");
            log.status(2, "skipped", None);
        } else if !is_gxp {
            log.log(2, "Process declared non-GxP — no validation documents required.");
            log.status(2, "skipped", None);
        } else {
            log.status(2, "running", None);
            match (|| -> Result<Vec<(String, String)>, String> {
                let mut valid_links = Vec::new();
                for l in &upload.gxp_links {
                    let url = l.get("url").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
                    let parsed = url::Url::parse(&url).ok();
                    let is_http = parsed.as_ref().map(|p| p.scheme() == "http" || p.scheme() == "https").unwrap_or(false);
                    if !is_http {
                        return Err(format!("Invalid GxP document link: \"{url}\" (must be http/https)."));
                    }
                    let name = l.get("name").and_then(|v| v.as_str()).filter(|n| !n.trim().is_empty()).map(str::to_string).unwrap_or_else(|| parsed.as_ref().map(|p| format!("{}{}", p.host_str().unwrap_or(""), p.path())).unwrap_or_default());
                    valid_links.push((name, url));
                }
                if upload.gxp_doc_files.is_empty() && valid_links.is_empty() {
                    return Err("GxP process declared but no validation documents provided. Attach at least one document (upload or link).".to_string());
                }
                Ok(valid_links)
            })() {
                Ok(valid_links) => {
                    log.log(2, &format!("Collecting {} uploaded document(s) and {} link(s)...", upload.gxp_doc_files.len(), valid_links.len()));
                    for (name, mime, data) in &upload.gxp_doc_files {
                        state.db.add_upload_document(project_id.unwrap(), name, mime.as_deref(), data.len() as i64, data);
                        log.log(2, &format!("✓ Archived upload: {name} ({:.1} KB)", data.len() as f64 / 1024.0));
                    }
                    for (name, url) in &valid_links {
                        state.db.add_link_document(project_id.unwrap(), name, url);
                        log.log(2, &format!("✓ Archived link: {name} → {url}"));
                    }
                    log.log(2, &format!("✓ {} GxP validation document(s) saved to the database.", upload.gxp_doc_files.len() + valid_links.len()));
                    log.status(2, "success", None);
                }
                Err(msg) => {
                    log.log(2, &format!("✗ {msg}"));
                    log.status(2, "failed", Some(json!({ "error": msg })));
                    all_issues.push(new_issue("phase2::gxp-documents".to_string(), 2, "gxp-documents", Severity::Error, msg, None, None));
                    persist!();
                }
            }
        }

        // ---------------- Phase 3: extraction + structure audit ----------------
        log.status(3, "running", None);
        let phase3_result: Result<(), String> = async {
            std::fs::create_dir_all(&staging_dir).map_err(|e| e.to_string())?;
            log.log(3, &format!("Staging directory: {}", staging_dir.display()));

            if let Some((path, fname, size)) = &upload.archive {
                let staged = ignite_staging::extract_zip(path, &staging_dir).map_err(|e| e.to_string())?;
                log.log(3, &format!("Extracted {} files ({:.1} KB).", staged.file_count, staged.total_bytes as f64 / 1024.0));
                let _ = (fname, size);
            } else {
                let staged = ignite_staging::stage_directory_upload(&upload.dir_files, &staging_dir).map_err(|e| e.to_string())?;
                log.log(3, &format!("Staged {} files ({:.1} KB) from folder upload.", staged.file_count, staged.total_bytes as f64 / 1024.0));
            }

            let root = ignite_staging::resolve_project_root(&staging_dir).map_err(|e| e.to_string())?;
            if root != staging_dir {
                log.log(3, &format!("Detected single top-level folder — project root: {}/", root.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()));
            }
            project_root = Some(root.clone());

            ignite_staging::clone_directory_without_symlinks(&root, &source_backup_dir).map_err(|e| e.to_string())?;
            log.log(3, "Created immutable source snapshot for final publish phase.");
            snapshot_ready = true;
            project_root_ready = true;
            if let Some(live) = state.running_runs.lock().unwrap().get_mut(&job_id) {
                live.project_root = Some(root.clone());
                live.source_backup_dir = Some(source_backup_dir.clone());
            }

            let client = ignite_deps_dev_client::DepsDevClient::new();
            let npm_http = reqwest::Client::new();
            let log_a = log.clone();
            let log_b = log.clone();
            let mut license_issues = ignite_dependency_license_scan::run_license_compliance_check(&root, &state.runner, &client, &npm_http, move |m| log_a.log(3, m)).await;
            license_issues.extend(ignite_dependency_license_scan::run_dependency_vulnerability_check(&root, &client, move |m| log_b.log(3, m)).await);
            if !license_issues.is_empty() {
                all_issues.extend(license_issues);
                persist!();
            }

            log.log(3, "Check 1 — scanning for raw environment files (.env*)...");
            let env_check = ignite_staging::check_env_files(&root).map_err(|e| e.to_string())?;
            if !env_check.ignored.is_empty() {
                log.log(3, &format!("ℹ {} .env file(s) found but already excluded by this project's .gitignore — not blocking: {}", env_check.ignored.len(), env_check.ignored.join(", ")));
            }
            if !env_check.blocking.is_empty() {
                log.log(3, &format!("✗ {} forbidden environment file(s) found:", env_check.blocking.len()));
                for f in &env_check.blocking {
                    log.log(3, &format!("    ✗ {f}"));
                }
                return Err(format!("Raw environment files detected ({}). Remove them and re-upload.", env_check.blocking.len()));
            }
            log.log(3, "✓ Check 1 passed — no raw environment files present.");
            log.log(3, "Check 2 — checking for a CODEOWNERS file...");
            let codeowners = ignite_staging::check_codeowners(&root);
            if codeowners.found {
                log.log(3, &format!("✓ CODEOWNERS found at {} ({} contact email(s)).", codeowners.path.as_deref().unwrap_or(""), codeowners.emails.len()));
            } else {
                log.log(3, "ℹ No CODEOWNERS file found (advisory — checked root, .github/, docs/).");
            }
            let log_c = log.clone();
            ignite_unit_test_runner::run_project_unit_tests(&root, &state.runner, move |m| log_c.log(3, m)).await.map_err(|e| e.to_string())?;
            Ok(())
        }
        .await;

        match phase3_result {
            Ok(()) => log.status(3, "success", None),
            Err(msg) => {
                log.log(3, &format!("✗ {msg}"));
                log.status(3, "failed", Some(json!({ "error": msg })));
                all_issues.push(new_issue("phase3::structure-audit".to_string(), 3, "structure-audit", Severity::Error, msg, None, None));
                persist!();
            }
        }

        // ---------------- Phase 4: security + AI compliance ----------------
        if !project_root_ready {
            log.log(4, "Skipped — blocked by Phase 3 failure (no staged project root to scan).");
            log.status(4, "skipped", None);
        } else if !super::phase_meta::phase_enabled(&log.meta, 4) {
            log.log(4, "Skipped — disabled by config (phases: [{ id: 4, enabled: false }]).");
            log.status(4, "skipped", None);
        } else {
            log.status(4, "running", None);
            let root = project_root.clone().unwrap();
            let config = default_phase4_config(state.as_ref(), &org, &repo, project_id);
            match ignite_phase4_orchestrator::run_phase4_checks(&root, &state.runner, &state.db, &config, &state.package_hallucination_checker).await {
                Ok(output) => {
                    let issue_count = output.issues.len();
                    let blocking_count = output.issues.iter().filter(|i| i.severity == Severity::Error).count();
                    all_issues.extend(output.issues);
                    if issue_count > 0 {
                        log.log(4, &format!("⚠ {issue_count} flagged issue(s) ({blocking_count} blocking) — will be presented for final review before push."));
                    }
                    persist!();
                    log.status(4, "success", Some(json!({ "issueCount": issue_count, "blockingCount": blocking_count })));
                }
                Err(e) => {
                    let msg = e.to_string();
                    log.log(4, &format!("✗ {msg}"));
                    log.status(4, "failed", Some(json!({ "error": msg })));
                    all_issues.push(new_issue("phase4::security-scan".to_string(), 4, "security-scan", Severity::Error, msg, None, None));
                    persist!();
                }
            }
        }

        // ---------------- Phase 5: local GitHub Actions run (act) ----------------
        if !project_root_ready {
            log.log(5, "Skipped — blocked by Phase 3 failure (no staged project root to run CI against).");
            log.status(5, "skipped", None);
        } else if !super::phase_meta::phase_enabled(&log.meta, 5) {
            log.log(5, "Skipped — disabled by config (phases: [{ id: 5, enabled: false }]).");
            log.log(5, "⚠ The org governance workflows will still gate the repo on GitHub after push.");
            log.status(5, "skipped", None);
        } else {
            log.status(5, "running", None);
            let root = project_root.clone().unwrap();
            let tooling = ignite_governance_ci::act_tooling(&state.runner).await;
            if !tooling.ok {
                log.log(5, &format!("⚠ Local CI skipped: {}", tooling.reason.unwrap_or_default()));
                log.log(5, "⚠ The org governance workflows will still gate the repo on GitHub after push.");
                log.status(5, "success", None);
            } else {
                let gh_api = ignite_github_api::GithubApi::new(&state.runner);
                let server_token = ignite_github_api::resolve_server_github_token();
                let log_5 = log.clone();
                let result: Result<(), String> = async {
                    let wf_file = ignite_governance_ci::fetch_governance_workflow(&workflow_dir, &gh_api, &state.db, &state.config.governance.repo, &state.config.governance.workflow, &server_token, {
                        let l = log_5.clone();
                        move |m| l.log(5, m)
                    })
                    .await
                    .map_err(|e| e.to_string())?;
                    log_5.log(5, &format!("Executing org governance workflows locally with act (event: {}).", state.config.governance.event));
                    ignite_governance_ci::run_actions_locally(&root, &wf_file, &state.runner, &gh_api, &ignite_governance_ci::RunActionsConfig { act_event: state.config.governance.event.clone(), act_timeout_min: state.config.governance.timeout_minutes as u64 }, {
                        let l = log_5.clone();
                        move |m| l.log(5, m)
                    })
                    .await
                    .map_err(|e| e.to_string())?;
                    Ok(())
                }
                .await;
                match result {
                    Ok(()) => {
                        log.log(5, "✓ All org governance jobs passed locally.");
                        log.status(5, "success", None);
                    }
                    Err(msg) => {
                        log.log(5, &format!("✗ {msg}"));
                        log.status(5, "failed", Some(json!({ "error": msg })));
                        all_issues.push(new_issue("phase5::governance-ci".to_string(), 5, "governance-ci", Severity::Error, msg, None, None));
                        persist!();
                    }
                }
            }
        }

        // ---------------- Final review gate ----------------
        log.status(6, "running", None);
        if !all_issues.is_empty() {
            let error_count = all_issues.iter().filter(|i| i.severity == Severity::Error).count();
            log.log(6, &format!("⚠ {} issue(s) accumulated across the run ({error_count} blocking) — waiting for final review before provisioning/push.", all_issues.len()));

            let rx = state.review_gate.wait(&job_id);
            if let Some(live) = state.running_runs.lock().unwrap().get_mut(&job_id) {
                live.review_active = true;
            }
            log.send(json!({ "type": "review_required", "phase": 6, "jobId": job_id, "issues": all_issues.iter().map(|i| serde_json::to_value(i).unwrap()).collect::<Vec<_>>() }));

            let decision = match rx.await {
                Ok(d) => d,
                Err(_) => break 'run Err((6, "Pipeline interrupted: review gate closed without a decision.".to_string())),
            };
            if let Some(live) = state.running_runs.lock().unwrap().get_mut(&job_id) {
                live.review_active = false;
            }

            let result = validate_overrides(&all_issues, &decision.overrides);
            let applied_ids: std::collections::HashSet<String> = result.applied.iter().map(|(i, _)| i.id.clone()).collect();
            let ok = result.ok;
            let unresolved_count = result.unresolved_errors.len();
            let unresolved_lines: Vec<String> = result
                .unresolved_errors
                .iter()
                .map(|issue| {
                    let loc = issue.file.as_deref().map(|f| format!("{f}{}", issue.line.map(|l| format!(":{l}")).unwrap_or_default())).unwrap_or_else(|| "unknown location".to_string());
                    format!("    ✗ [{}] {loc} — {}", issue.category, issue.summary)
                })
                .collect();
            let applied_count = result.applied.len();

            if applied_count > 0 {
                log.log(6, &format!("⚠ {applied_count} flagged issue(s) overridden by {}:", decision.actor.email));
                for (issue, justification) in &result.applied {
                    let loc = issue.file.as_deref().map(|f| format!("{f}{}", issue.line.map(|l| format!(":{l}")).unwrap_or_default())).unwrap_or_else(|| "unknown location".to_string());
                    log.log(6, &format!("    ⚠ [override] [{:?}] {loc} — {} — \"{justification}\"", issue.severity, issue.summary));
                    if let Some(pid) = project_id {
                        // No per-issue phase is tracked on `Issue` itself (same
                        // simplification pipeline_onboard.rs's `issue_to_input`
                        // already makes) — every override is recorded against
                        // phase 4, the phase most findings actually originate
                        // from.
                        state.db.add_override(ignite_db_store::AddOverrideArgs {
                            project_id: pid,
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
                            actor_email: &decision.actor.email,
                            actor_name: Some(&decision.actor.name),
                            email_sent: false,
                        });
                    }
                }
            }

            persist_issues_snapshot(&state, &job_id, project_id, &all_issues, &applied_ids);

            if !decision.proceed {
                break 'run Err((6, "Pipeline interrupted by user after reviewing all flagged issues.".to_string()));
            }
            if !ok {
                log.log(6, &format!("✗ {unresolved_count} blocking finding(s) were not overridden:"));
                for line in &unresolved_lines {
                    log.log(6, line);
                }
                break 'run Err((6, format!("{unresolved_count} unresolved blocking finding(s) remain across the run. Override each with a justification, or fix them and re-run.")));
            }
            log.log(6, "✓ User chose to continue after reviewing all flagged issues.");
        }

        // ---------------- Phase 6: provisioning + shipping ----------------
        if dry_run {
            log.log(
                6,
                if !all_issues.is_empty() {
                    "Simulation mode (dryRun) — all flagged issues were fixed or overridden; skipping repository provisioning and push."
                } else {
                    "Simulation mode (dryRun) — all checks passed; skipping repository provisioning and push."
                },
            );
            log.log(6, "The validated snapshot is kept so this run can be effectivated (provisioned + pushed for real) later, still gated on any unresolved blocking findings.");
            log.status(6, "skipped", None);
            if let Some(pid) = project_id {
                state.db.finish_project("success", None, None, None, pid);
            }
            log.send(json!({ "type": "done", "ok": true, "dryRun": dry_run, "repoUrl": Value::Null, "prUrl": Value::Null, "effectivatable": snapshot_ready && !shipped_for_real, "projectId": project_id }));
            break 'run Ok(());
        }

        let backup_ok = source_backup_dir.is_dir();
        if !backup_ok {
            break 'run Err((6, "Immutable source snapshot is missing before phase 6 — an earlier phase failed to produce a publishable project.".to_string()));
        }
        let _ = std::fs::remove_dir_all(&publish_dir);
        if let Err(e) = ignite_staging::clone_directory_without_symlinks(&source_backup_dir, &publish_dir) {
            break 'run Err((6, e.to_string()));
        }
        log.log(6, "Prepared clean publish workspace from immutable source snapshot.");

        let log_6 = log.clone();
        ignite_shipping::archive_phase6_payload(&publish_dir, project_id, &state.runner, &state.db, move |m| log_6.log(6, m)).await;

        let ship_config = ignite_shipping::ShippingConfig::default();
        let gh_api = ignite_github_api::GithubApi::new(&state.runner);
        let log_6b = log.clone();
        match ignite_shipping::ship_to_github(&publish_dir, &org, &repo, &gh_token, &state.runner, &gh_api, &ship_config, move |m| log_6b.log(6, m)).await {
            Ok(ship_result) => {
                log.log(6, &format!("✓ Repository live at {}", ship_result.repo_url));
                log.status(6, "success", Some(json!({ "repoUrl": ship_result.repo_url, "prUrl": ship_result.pr_url })));
                shipped_for_real = true;
                if let Some(pid) = project_id {
                    state.db.finish_project("success", None, Some(&ship_result.repo_url), ship_result.pr_url.as_deref(), pid);
                }
                log.send(json!({ "type": "done", "ok": true, "dryRun": dry_run, "repoUrl": ship_result.repo_url, "prUrl": ship_result.pr_url, "effectivatable": snapshot_ready && !shipped_for_real, "projectId": project_id }));
                Ok(())
            }
            Err(e) => Err((6, e.to_string())),
        }
    };

    if let Err((phase, message)) = outcome {
        log.log(phase, &format!("✗ {message}"));
        log.status(phase, "failed", Some(json!({ "error": message })));
        if let Some(pid) = project_id {
            state.db.finish_project("failed", Some(&message), None, None, pid);
        }
        log.send(json!({ "type": "done", "ok": false, "error": message, "phase": phase, "effectivatable": snapshot_ready && !shipped_for_real, "projectId": project_id }));
    }

    // ---------------- Cleanup (always runs, success or failure) ----------------
    state.running_runs.lock().unwrap().remove(&job_id);
    if snapshot_ready && !shipped_for_real {
        if let Some(pid) = project_id {
            let mut pending = state.pending_effectivations.lock().unwrap();
            let cutoff = Instant::now().checked_sub(std::time::Duration::from_secs(24 * 3600));
            pending.retain(|_, v| cutoff.map(|c| v.created_at > c).unwrap_or(true));
            pending.insert(pid, PendingEffectivation { org: org.clone(), repo: repo.clone(), source_backup_dir: source_backup_dir.clone(), created_at: Instant::now() });
            keep_source_backup_dir = true;
        }
    }

    if let Some(pid) = project_id {
        for (phase, (state_str, logs)) in log.all_phase_records() {
            state.db.upsert_step(pid, phase, &super::phase_meta::phase_title(&log.meta, phase), &state_str, &logs.join("\n"));
        }
    }

    if snapshot_ready {
        if let Some(pid) = project_id {
            let retained_root = ignite_data_dir().join("retained-projects");
            let retained_dir = retained_root.join(pid.to_string());
            if std::fs::create_dir_all(&retained_root).is_ok() {
                let _ = std::fs::remove_dir_all(&retained_dir);
                if ignite_staging::clone_directory_without_symlinks(&source_backup_dir, &retained_dir).is_ok() {
                    state.db.retain_project_source(pid, &retained_dir.to_string_lossy());
                    for evicted in state.db.list_evictable_retained_sources(RETAINED_PROJECTS_KEEP) {
                        let _ = std::fs::remove_dir_all(&evicted.dir_path);
                        let _ = std::fs::remove_dir_all(ignite_data_dir().join("codeql-dbs").join(evicted.project_id.to_string()));
                        state.db.delete_retained_source(evicted.project_id);
                    }
                }
            }
        }
    }

    ignite_fs_utils::invalidate_walk_cache(&staging_dir);
    if let Some(root) = &project_root {
        ignite_fs_utils::invalidate_walk_cache(root);
    }
    let _ = std::fs::remove_dir_all(&staging_dir);
    if !keep_source_backup_dir {
        let _ = std::fs::remove_dir_all(&source_backup_dir);
    }
    let _ = std::fs::remove_dir_all(&publish_dir);
    let _ = std::fs::remove_dir_all(&workflow_dir);
    for p in &upload.temp_paths_to_clean {
        let _ = std::fs::remove_file(p);
    }
}

async fn pipeline(State(state): State<Arc<AppState>>, headers: axum::http::HeaderMap, multipart: Multipart) -> Response {
    let upload = match parse_multipart(multipart).await {
        Ok(u) => u,
        Err((status, body)) => return (status, axum::Json(body)).into_response(),
    };

    let session_gh_token = crate::auth::resolve_effective_github_token(&headers, &state.db);
    let job_id = uuid::Uuid::new_v4().to_string();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let log = Arc::new(EventLog { state: state.clone(), meta: super::phase_meta::resolve_phase_meta(&state.config), tx, record: Mutex::new(HashMap::new()), project_id: Mutex::new(None) });

    let job_id_task = job_id.clone();
    tokio::spawn(async move {
        run_interactive_pipeline(state, upload, log, job_id_task, session_gh_token).await;
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

/// `POST /api/pipeline/:jobId/review-decision` — resolves a run paused at
/// the review gate. Thin enough to live here rather than waiting on the
/// full routes/review_gate.js port (studio.js's file-browsing endpoints,
/// which share that file, are the parts still not ported).
async fn review_decision(axum::extract::Path(job_id): axum::extract::Path<String>, State(state): State<Arc<AppState>>, axum::Json(body): axum::Json<Value>) -> Response {
    let proceed = body.get("proceed").and_then(|v| v.as_bool()).unwrap_or(false);
    let overrides: Vec<SubmittedOverride> = body
        .get("overrides")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().map(|o| SubmittedOverride { issue_id: o.get("issueId").and_then(|v| v.as_str()).unwrap_or("").to_string(), justification: o.get("justification").and_then(|v| v.as_str()).unwrap_or("").to_string() }).collect())
        .unwrap_or_default();
    let actor_value = body.get("actor").cloned().unwrap_or(Value::Null);
    let actor = match resolve_actor_from_body(&actor_value) {
        Some(a) => a,
        None => return (StatusCode::UNAUTHORIZED, axum::Json(json!({ "error": "An actor {email, name} is required to attribute this decision." }))).into_response(),
    };
    let resolved = state.review_gate.resolve(&job_id, ReviewDecisionInput { proceed, overrides, actor });
    if !resolved {
        return (StatusCode::NOT_FOUND, axum::Json(json!({ "error": "No run is currently paused for review under this job id." }))).into_response();
    }
    (StatusCode::OK, axum::Json(json!({ "ok": true }))).into_response()
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        // Axum's `Multipart` extractor otherwise enforces its own default
        // 2MB whole-body limit (`DefaultBodyLimit`) — disabled here because
        // `parse_multipart`/`read_field_bytes_limited` now enforce the real
        // per-file/per-field-count limits matching server.js's multer
        // config exactly (MAX_FILE_BYTES/MAX_FILES above), which a single
        // whole-body cap can't express (a folder upload with many small
        // files can legitimately total well over 1GB in Node as long as no
        // single file exceeds it). Scoped to just this route, not the
        // whole router, so JSON endpoints elsewhere keep axum's smaller
        // stock default, closer to server.js's separate
        // `express.json({ limit: '1mb' })` cap on those.
        .route("/api/pipeline", post(pipeline).layer(axum::extract::DefaultBodyLimit::disable()))
        .route("/api/pipeline/:jobId/review-decision", post(review_decision))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state;
    use reqwest::multipart::{Form, Part};

    async fn spawn_test_server() -> (String, Arc<AppState>) {
        let db_dir = tempfile::tempdir().unwrap();
        let db = ignite_db_store::DbStore::open(&db_dir.path().join("test.db")).unwrap();
        let app_state = Arc::new(AppState {
            runner: state::default_runner(),
            db,
            running_runs: Mutex::new(HashMap::new()),
            pending_effectivations: Mutex::new(HashMap::new()),
            review_gate: crate::review_gate::ReviewGate::default(),
            llm_config: state::default_llm_config(),
            config: ignite_config::Config::default(),
            package_hallucination_checker: state::default_package_hallucination_checker(),
        });
        let router = axum::Router::new().merge(router()).with_state(app_state.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        std::mem::forget(db_dir);
        (format!("http://{addr}"), app_state)
    }

    fn zip_bytes(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let cursor = std::io::Cursor::new(&mut buf);
            let mut writer = zip::ZipWriter::new(cursor);
            let opts: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default();
            for (name, data) in files {
                writer.start_file(*name, opts.clone()).unwrap();
                std::io::Write::write_all(&mut writer, data).unwrap();
            }
            writer.finish().unwrap();
        }
        buf
    }

    async fn read_ndjson(res: reqwest::Response) -> Vec<Value> {
        let text = res.text().await.unwrap();
        text.lines().filter(|l| !l.is_empty()).map(|l| serde_json::from_str(l).unwrap()).collect()
    }

    #[tokio::test]
    async fn rejects_invalid_org_name() {
        // Faithful to server.js: an invalid org name doesn't abort the
        // stream immediately — it's recorded as a phase-1 issue and the
        // run still proceeds through phases 3-6, reaching the review gate
        // (every issue from every phase is shown together, right before
        // phase 6). Here the user declines to proceed at the gate, which
        // is what actually surfaces the phase-1 problem to them.
        let (base, state) = spawn_test_server().await;
        let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(120)).build().unwrap();
        let zip = zip_bytes(&[("app.js", b"console.log(1);"), ("package.json", b"{\"name\":\"fixture\"}")]);
        let form = Form::new().text("org", "-bad-").text("repo", "widgets").text("dryRun", "true").part("archive", Part::bytes(zip).file_name("p.zip"));

        let handle = tokio::spawn(async move { client.post(format!("{base}/api/pipeline")).multipart(form).send().await.unwrap() });

        let job_id = loop {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let running = state.running_runs.lock().unwrap();
            if let Some((id, _)) = running.iter().find(|(_, r)| r.review_active) {
                break id.clone();
            }
            drop(running);
        };
        let resolved = state.review_gate.resolve(
            &job_id,
            ReviewDecisionInput { proceed: false, overrides: vec![], actor: Actor { email: "tester@example.com".into(), name: "Tester".into() } },
        );
        assert!(resolved);

        let res = handle.await.unwrap();
        assert_eq!(res.status(), 200);
        let events = read_ndjson(res).await;
        assert!(events.iter().any(|e| e["type"] == "status" && e["phase"] == 1 && e["state"] == "failed"));
        let done = events.iter().find(|e| e["type"] == "done").unwrap();
        assert_eq!(done["ok"], false);
        assert_eq!(done["phase"], 6);
        assert!(done["error"].as_str().unwrap().contains("interrupted"));
    }

    /// Real end-to-end test of `read_field_bytes_limited_to`'s streaming
    /// rejection, against a genuine `axum::extract::Multipart` `Field`
    /// (not a mock) — a tiny standalone route lets this run at a 10-byte
    /// scale instead of needing an actual 1GB upload to exercise the
    /// production `MAX_FILE_BYTES` constant. Regression coverage for the
    /// multer-parity fix: a per-file limit enforced by streaming `.chunk()`
    /// calls and rejecting mid-stream, not by buffering the whole field
    /// first (which would defeat the point of a size limit).
    #[tokio::test]
    async fn read_field_bytes_limited_to_rejects_mid_stream_and_accepts_within_limit() {
        async fn probe(mut mp: Multipart) -> String {
            let Some(mut field) = mp.next_field().await.unwrap() else { return "none".into() };
            match read_field_bytes_limited_to(&mut field, 10).await {
                Ok(bytes) => format!("ok:{}", bytes.len()),
                Err((status, _)) => format!("rejected:{}", status.as_u16()),
            }
        }
        let app = axum::Router::new().route("/probe", post(probe));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let base = format!("http://{addr}");
        let client = reqwest::Client::new();

        let over_limit = Form::new().part("f", Part::bytes(vec![0u8; 25]).file_name("big.bin"));
        let res = client.post(format!("{base}/probe")).multipart(over_limit).send().await.unwrap();
        assert_eq!(res.text().await.unwrap(), "rejected:413");

        let within_limit = Form::new().part("f", Part::bytes(vec![0u8; 5]).file_name("small.bin"));
        let res = client.post(format!("{base}/probe")).multipart(within_limit).send().await.unwrap();
        assert_eq!(res.text().await.unwrap(), "ok:5");
    }

    #[tokio::test]
    async fn accepts_upload_larger_than_axum_default_body_limit() {
        // Axum's `Multipart` extractor enforces its own default 2 MB
        // whole-body limit unless disabled per-route; server.js's multer
        // config bounds each *file* to 1 GB (MAX_ZIP_BYTES) with no
        // whole-body cap at all. Proves the `DefaultBodyLimit::disable()`
        // on this route actually takes effect by sending a real multipart
        // body over 2 MB — incompressible filler bytes, so zip deflate
        // can't shrink the wire size back under the old limit.
        let (base, state) = spawn_test_server().await;
        let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(120)).build().unwrap();
        let mut filler = vec![0u8; 3 * 1024 * 1024];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut filler);
        let zip = zip_bytes(&[("app.js", b"console.log(1);"), ("package.json", b"{\"name\":\"fixture\"}"), ("filler.bin", &filler)]);
        assert!(zip.len() > 2 * 1024 * 1024, "fixture must exceed the old 2MB default to actually exercise the override, got {} bytes", zip.len());
        let form = Form::new().text("org", "-bad-").text("repo", "widgets").text("dryRun", "true").part("archive", Part::bytes(zip).file_name("p.zip"));

        let handle = tokio::spawn(async move { client.post(format!("{base}/api/pipeline")).multipart(form).send().await.unwrap() });

        let job_id = loop {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let running = state.running_runs.lock().unwrap();
            if let Some((id, _)) = running.iter().find(|(_, r)| r.review_active) {
                break id.clone();
            }
            drop(running);
        };
        let resolved = state.review_gate.resolve(
            &job_id,
            ReviewDecisionInput { proceed: false, overrides: vec![], actor: Actor { email: "tester@example.com".into(), name: "Tester".into() } },
        );
        assert!(resolved);

        let res = handle.await.unwrap();
        // A 413/400 here would mean the body-limit override didn't take —
        // 200 with real phase-1 events means multipart parsing succeeded.
        assert_eq!(res.status(), 200);
        let events = read_ndjson(res).await;
        assert!(events.iter().any(|e| e["type"] == "status" && e["phase"] == 1));
    }

    // Ignored by default: this route has no `runLocalCi`/`fast` toggle
    // (faithful to routes/pipeline-interactive.js, which doesn't expose one
    // either — the browser UI always runs the real scan). On a machine with
    // every Phase 4/5 tool actually installed (gitleaks/act+Docker/CodeQL/
    // Bearer/...), Phase 5's real `act` run can mean a multi-minute Docker
    // image pull, and this test would otherwise turn the fast suite into a
    // multi-minute one. Same self-skip convention as the real-binary
    // integration suites (test/iac-scan.test.js etc. in the Node codebase).
    // Run explicitly with `cargo test -- --ignored` when validating this
    // path end to end.
    #[tokio::test]
    #[ignore]
    async fn dry_run_streams_job_and_review_events_then_pauses_at_gate() {
        let (base, state) = spawn_test_server().await;
        let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(120)).build().unwrap();
        // A hardcoded secret in the fixture guarantees at least one Phase 4
        // finding, so this run is guaranteed to reach the review gate. No
        // package.json/other language marker on purpose — Phase 3's real
        // unit-test-runner would otherwise detect a Node project and try
        // to `npm install` inside Docker, which hangs with no registry
        // network access in a sandboxed test environment.
        let zip = zip_bytes(&[("app.js", b"const key = 'AKIAABCDEFGHIJKLMNOP';\nconsole.log(key);\n")]);
        let form = Form::new().text("org", "acme").text("repo", "widgets").text("dryRun", "true").part("archive", Part::bytes(zip).file_name("p.zip"));

        let handle = tokio::spawn(async move { client.post(format!("{base}/api/pipeline")).multipart(form).send().await.unwrap() });

        // Poll running_runs until the job appears and is paused at review,
        // then resolve it — mirrors what routes/review_gate.js (not yet
        // ported) will eventually do over HTTP.
        let job_id = loop {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let running = state.running_runs.lock().unwrap();
            if let Some((id, _run)) = running.iter().find(|(_, r)| r.review_active) {
                break id.clone();
            }
            drop(running);
        };

        let resolved = state.review_gate.resolve(
            &job_id,
            ReviewDecisionInput { proceed: true, overrides: vec![], actor: Actor { email: "tester@example.com".into(), name: "Tester".into() } },
        );
        assert!(resolved);

        let res = handle.await.unwrap();
        assert_eq!(res.status(), 200);
        let events = read_ndjson(res).await;
        assert!(events.iter().any(|e| e["type"] == "job"));
        assert!(events.iter().any(|e| e["type"] == "review_required"));
        let done = events.iter().find(|e| e["type"] == "done").unwrap();
        assert_eq!(done["ok"], true);
        assert_eq!(done["dryRun"], true);
    }
}
