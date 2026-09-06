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
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Instant;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tokio_stream::StreamExt as _;

static GITHUB_NAME_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$").unwrap());
static REPO_NAME_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9._-]{1,100}$").unwrap());

/// A run is retained with its full source tree for later "Effectivate" (or
/// Studio browsing) for this many most-recently-completed jobs that made
/// it through Phase 3 staging.
const RETAINED_FULL_KEEP: i64 = 5;
/// Beyond `RETAINED_FULL_KEEP`, a retained project's source is pruned down
/// to only the files that have findings (see `prune_retained_source_to_findings`)
/// rather than evicted outright, up to this many most-recently-completed
/// jobs total (full + pruned combined). Anything older is evicted entirely.
const RETAINED_TOTAL_KEEP: i64 = 10;

pub(crate) fn ignite_data_dir() -> PathBuf {
    std::env::var("IGNITE_DATA_DIR").map(PathBuf::from).unwrap_or_else(|_| dirs_home().join(".ignite"))
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("."))
}

/// Deletes every file under `dir` whose path relative to `dir` isn't in
/// `flagged_rel_paths`, then removes any directory left empty by that -
/// turns a full retained-source copy into a "flagged files only" one.
/// `dir`'s own files are already rooted under `dir` (this walks a copy
/// Ignite made itself, not an external tool's differently-rooted report),
/// so a plain `strip_prefix` is enough - no path canonicalization needed.
fn prune_retained_source_to_findings(dir: &std::path::Path, flagged_rel_paths: &std::collections::HashSet<String>) {
    let Ok(files) = ignite_fs_utils::walk_files(dir) else { return };
    for f in &files {
        let rel: String = f.strip_prefix(dir).unwrap_or(f).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
        if !flagged_rel_paths.contains(&rel) {
            let _ = std::fs::remove_file(f);
        }
    }
    remove_empty_dirs(dir);
}

/// Post-order removal of any directory left empty after pruning - never
/// removes `root` itself, even if everything under it was pruned away.
fn remove_empty_dirs(root: &std::path::Path) {
    let Ok(entries) = std::fs::read_dir(root) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            remove_empty_dirs(&path);
            let _ = std::fs::remove_dir(&path); // no-op (fails silently) if not actually empty
        }
    }
}

fn write_temp_upload(bytes: &[u8]) -> std::io::Result<PathBuf> {
    let path = std::env::temp_dir().join(format!("ignite-upload-{}", uuid::Uuid::new_v4()));
    // Uploaded archives can contain confidential source (and `.env`
    // files); `std::fs::write` creates with the process umask (typically
    // 0644), leaving them readable by every local OS user on a shared box
    // for as long as the file lingers. Open with 0600 up front instead of
    // writing-then-chmod, so there's no window where the file is
    // world-readable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&path)?;
        std::io::Write::write_all(&mut f, bytes)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&path, bytes)?;
    }
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

async fn parse_multipart(multipart: Multipart) -> Result<ParsedUpload, (StatusCode, Value)> {
    let mut temp_paths_to_clean: Vec<PathBuf> = Vec::new();
    let result = parse_multipart_inner(multipart, &mut temp_paths_to_clean).await;
    // Any temp file already written to disk for this request must be
    // removed even when the parse fails partway through (payload-too-large,
    // a malformed field, the client aborting mid-upload) — otherwise every
    // rejected upload leaks its already-streamed bytes into the OS temp
    // dir forever, a straightforward disk-exhaustion DoS against repeated
    // failed uploads.
    if result.is_err() {
        for p in &temp_paths_to_clean {
            let _ = std::fs::remove_file(p);
        }
    }
    result
}

async fn parse_multipart_inner(mut multipart: Multipart, temp_paths_to_clean: &mut Vec<PathBuf>) -> Result<ParsedUpload, (StatusCode, Value)> {
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

    Ok(ParsedUpload { org, repo, gxp_requested, dry_run, gxp_links, archive, dir_files, dir_file_count_and_bytes, gxp_doc_files, temp_paths_to_clean: temp_paths_to_clean.clone() })
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
    job_id: String,
}

impl EventLog {
    fn send(&self, ev: Value) {
        let _ = self.tx.send(format!("{}\n", ev));
    }

    fn set_project_id(&self, id: i64) {
        *self.project_id.lock() = Some(id);
    }

    fn project_id(&self) -> Option<i64> {
        *self.project_id.lock()
    }

    fn persist(&self, phase: i64) {
        let Some(project_id) = self.project_id() else { return };
        let record = self.record.lock();
        if let Some(rec) = record.get(&phase) {
            self.state.db.upsert_step(project_id, phase, &super::phase_meta::phase_title(&self.meta, phase), &rec.state, &rec.logs.join("\n"));
        }
    }

    fn log(&self, phase: i64, message: &str) {
        {
            let mut record = self.record.lock();
            record.entry(phase).or_insert_with(|| PhaseRecord { state: "pending".to_string(), logs: vec![] }).logs.push(message.to_string());
        }
        tracing::info!(job_id = %self.job_id, phase, "{message}");
        self.send(json!({ "type": "log", "phase": phase, "message": message }));
        self.persist(phase);
    }

    fn status(&self, phase: i64, state: &str, extra: Option<Value>) {
        {
            let mut record = self.record.lock();
            record.entry(phase).or_insert_with(|| PhaseRecord { state: "pending".to_string(), logs: vec![] }).state = state.to_string();
        }
        tracing::info!(job_id = %self.job_id, phase, state, "phase status");
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
        self.record.lock().iter().map(|(k, v)| (*k, (v.state.clone(), v.logs.clone()))).collect()
    }
}

fn new_issue(id: String, phase: i64, category: &str, severity: Severity, summary: String, file: Option<String>, line: Option<i64>) -> Issue {
    let _ = phase;
    Issue { id, category: category.to_string(), severity, score: score_for_issue(category, severity), summary, file, line, snippet: None, cross_file: false, chain: None, duplicate_ref: None, cwe: None, owasp: None, tool: None, references: ignite_override_engine::IssueReferences::default() }
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
    if let Some(live) = state.running_runs.lock().get_mut(job_id) {
        live.all_issues = rows;
    }
}


mod handlers;
mod run;

pub use handlers::router;


#[cfg(test)]
mod tests {
    use super::*;
    use crate::state;
    use reqwest::multipart::{Form, Part};

    #[test]
    fn prune_retained_source_to_findings_keeps_only_flagged_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("flagged.js"), b"x").unwrap();
        std::fs::write(dir.path().join("clean.js"), b"y").unwrap();
        std::fs::create_dir_all(dir.path().join("nested")).unwrap();
        std::fs::write(dir.path().join("nested/also-clean.js"), b"z").unwrap();

        let flagged: std::collections::HashSet<String> = ["flagged.js".to_string()].into_iter().collect();
        prune_retained_source_to_findings(dir.path(), &flagged);

        assert!(dir.path().join("flagged.js").exists());
        assert!(!dir.path().join("clean.js").exists());
        assert!(!dir.path().join("nested").exists(), "the now-empty nested/ dir should be cleaned up too");
    }

    #[test]
    fn remove_empty_dirs_never_removes_the_root_itself() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("a/b")).unwrap();
        remove_empty_dirs(dir.path());
        assert!(dir.path().exists());
        assert!(!dir.path().join("a").exists());
    }

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
        fix_pr_previews: Mutex::new(HashMap::new()),
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
                writer.start_file(*name, opts).unwrap();
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

        // Bounded, not an unconditional `loop`: if the fixture's blocking
        // finding doesn't actually get flagged in this environment (e.g. a
        // secrets-scan fixture that needs `gitleaks` installed to match),
        // the run never pauses at the review gate and `review_active`
        // never becomes true — an unbounded loop here would then spin
        // forever instead of failing with a message that says why.
        let job_id = tokio::time::timeout(std::time::Duration::from_secs(180), async {
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                let running = state.running_runs.lock();
                if let Some((id, _)) = running.iter().find(|(_, r)| r.review_active) {
                    return id.clone();
                }
                drop(running);
            }
        })
        .await
        .expect("run never reached the review gate within 180s — the fixture's blocking finding may not be getting flagged in this environment");
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

    /// Zips a real directory tree (including a `.git` if present) into an
    /// in-memory archive, recursively — unlike `zip_bytes` (a flat list of
    /// synthetic files), this preserves whatever's actually on disk so a
    /// real `git init`+commit survives the round trip through the upload.
    fn zip_dir(root: &std::path::Path) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let cursor = std::io::Cursor::new(&mut buf);
            let mut writer = zip::ZipWriter::new(cursor);
            let opts: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default();
            for path in ignite_fs_utils::walk_files(root).unwrap() {
                // walk_files skips .git itself (it's not a project source
                // file) - add it back in by hand so the fixture keeps its
                // real commit history through the zip round trip.
                let rel = path.strip_prefix(root).unwrap().to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
                writer.start_file(&rel, opts).unwrap();
                std::io::Write::write_all(&mut writer, &std::fs::read(&path).unwrap()).unwrap();
            }
            for git_file in walkdir_git(&root.join(".git")) {
                let rel = git_file.strip_prefix(root).unwrap().to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
                writer.start_file(&rel, opts).unwrap();
                std::io::Write::write_all(&mut writer, &std::fs::read(&git_file).unwrap()).unwrap();
            }
            writer.finish().unwrap();
        }
        buf
    }

    fn walkdir_git(dir: &std::path::Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(dir) else { return out };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                out.extend(walkdir_git(&path));
            } else {
                out.push(path);
            }
        }
        out
    }

    #[tokio::test]
    async fn source_commit_sha_is_captured_from_a_real_git_repo_in_the_upload() {
        let mut check = std::process::Command::new("git");
        check.arg("--version");
        if check.output().map(|o| !o.status.success()).unwrap_or(true) {
            eprintln!("skipping: git not installed on PATH");
            return;
        }

        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("app.js"), b"console.log(1);\n").unwrap();
        std::fs::write(src.path().join("package.json"), b"{\"name\":\"fixture\"}").unwrap();
        let run = |args: &[&str]| {
            let status = std::process::Command::new("git")
                .args(args)
                .current_dir(src.path())
                .env("GIT_AUTHOR_NAME", "t").env("GIT_AUTHOR_EMAIL", "t@t").env("GIT_COMMITTER_NAME", "t").env("GIT_COMMITTER_EMAIL", "t@t")
                .status()
                .unwrap();
            assert!(status.success());
        };
        run(&["init", "-q", "-b", "main"]);
        run(&["add", "-A"]);
        run(&["commit", "-q", "-m", "init"]);
        let expected_sha = String::from_utf8(std::process::Command::new("git").args(["rev-parse", "HEAD"]).current_dir(src.path()).output().unwrap().stdout).unwrap().trim().to_string();
        ignite_fs_utils::invalidate_walk_cache(src.path());

        let (base, state) = spawn_test_server().await;
        // A real Phase 4 run against this fixture normally finishes in well
        // under a minute, but under heavy concurrent load (e.g. other
        // `cargo test` processes competing for CPU) it's been observed to
        // exceed a 120s client timeout — 240s gives real headroom without
        // masking an actual hang (that would still fail, just later).
        let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(240)).build().unwrap();
        let zip = zip_dir(src.path());
        let form = Form::new().text("org", "acme").text("repo", "widgets").text("dryRun", "true").part("archive", Part::bytes(zip).file_name("p.zip"));

        // This fixture itself is clean (no secrets/governance/etc.
        // findings), but the *default* test config's CodeQL query-suite
        // review is always "overdue" (no `lastReviewedAt` set —
        // `is_codeql_review_overdue` treats unset as never-reviewed), which
        // unconditionally adds one blocking `codeql-query-suite-stale`
        // issue to every real Phase 4 run regardless of the scanned
        // project. So this run does still reach the review gate — resolve
        // it like the sibling tests above, rather than assuming a
        // straight-through `done` with no pause.
        let base_for_run = base.clone();
        let handle = tokio::spawn(async move { client.post(format!("{base_for_run}/api/pipeline")).multipart(form).send().await.unwrap() });

        let review_wait = tokio::time::timeout(std::time::Duration::from_secs(60), async {
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                let running = state.running_runs.lock();
                if let Some((id, r)) = running.iter().find(|(_, r)| r.review_active) {
                    let open_issue_ids: Vec<String> = r.all_issues.iter().filter(|i| i.status != "overridden").map(|i| i.id.clone()).collect();
                    return (id.clone(), open_issue_ids);
                }
                drop(running);
            }
        })
        .await;
        if let Ok((job_id, open_issue_ids)) = review_wait {
            // Override every open blocking finding (e.g. the config-level
            // "codeql-query-suite-stale" check, always overdue for a
            // default test config regardless of the scanned project) so
            // this run can actually reach `done` with `ok: true` — this
            // test only cares about the source-commit-sha capture, not
            // about exercising blocking-finding handling.
            let overrides = open_issue_ids.into_iter().map(|issue_id| SubmittedOverride { issue_id, justification: "not relevant to this test".to_string(), code: None }).collect();
            let resolved = state.review_gate.resolve(
                &job_id,
                ReviewDecisionInput { proceed: true, overrides, actor: Actor { email: "tester@example.com".into(), name: "Tester".into() } },
            );
            assert!(resolved);
        }

        let res = handle.await.unwrap();
        assert_eq!(res.status(), 200);
        let events = read_ndjson(res).await;
        let done = events.iter().find(|e| e["type"] == "done").unwrap();
        assert_eq!(done["ok"], true);
        let job_id = events.iter().find_map(|e| e.get("jobId").and_then(|v| v.as_str())).unwrap();

        let project_id = state.db.get_project_id_by_job_id(job_id).unwrap();
        let project = state.db.get_project(project_id).unwrap();
        assert_eq!(project.source_commit_sha.as_deref(), Some(expected_sha.as_str()));
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

        // Bounded, not an unconditional `loop`: if the fixture's blocking
        // finding doesn't actually get flagged in this environment (e.g. a
        // secrets-scan fixture that needs `gitleaks` installed to match),
        // the run never pauses at the review gate and `review_active`
        // never becomes true — an unbounded loop here would then spin
        // forever instead of failing with a message that says why.
        let job_id = tokio::time::timeout(std::time::Duration::from_secs(180), async {
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                let running = state.running_runs.lock();
                if let Some((id, _)) = running.iter().find(|(_, r)| r.review_active) {
                    return id.clone();
                }
                drop(running);
            }
        })
        .await
        .expect("run never reached the review gate within 180s — the fixture's blocking finding may not be getting flagged in this environment");
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
        let zip = zip_bytes(&[("app.js", b"const aws_secret_key = 'AKIAABCDEFGHIJKLMNOP';\nconsole.log(aws_secret_key);\n")]);
        let form = Form::new().text("org", "acme").text("repo", "widgets").text("dryRun", "true").part("archive", Part::bytes(zip).file_name("p.zip"));

        let handle = tokio::spawn(async move { client.post(format!("{base}/api/pipeline")).multipart(form).send().await.unwrap() });

        // Poll running_runs until the job appears and is paused at review,
        // then resolve it — mirrors what routes/review_gate.js (not yet
        // ported) will eventually do over HTTP.
        // Bounded, not an unconditional `loop`: if the fixture's blocking
        // finding doesn't actually get flagged in this environment (e.g. a
        // secrets-scan fixture that needs `gitleaks` installed to match),
        // the run never pauses at the review gate and `review_active`
        // never becomes true — an unbounded loop here would then spin
        // forever instead of failing with a message that says why.
        let (job_id, open_issue_ids) = tokio::time::timeout(std::time::Duration::from_secs(180), async {
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                let running = state.running_runs.lock();
                if let Some((id, r)) = running.iter().find(|(_, r)| r.review_active) {
                    let open_issue_ids: Vec<String> = r.all_issues.iter().filter(|i| i.status != "overridden").map(|i| i.id.clone()).collect();
                    return (id.clone(), open_issue_ids);
                }
                drop(running);
            }
        })
        .await
        .expect("run never reached the review gate within 180s — the fixture's blocking finding may not be getting flagged in this environment");

        // Override every open blocking finding, not just the fixture's own
        // secret — a config-level check (e.g. "codeql-query-suite-stale",
        // always overdue for a default test config) can also be blocking
        // and is otherwise unrelated to what this test is checking.
        let overrides = open_issue_ids.into_iter().map(|issue_id| SubmittedOverride { issue_id, justification: "not relevant to this test".to_string(), code: None }).collect();
        let resolved = state.review_gate.resolve(
            &job_id,
            ReviewDecisionInput { proceed: true, overrides, actor: Actor { email: "tester@example.com".into(), name: "Tester".into() } },
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

    /// Same ignore rationale as `dry_run_streams_job_and_review_events_then_pauses_at_gate`
    /// (needs a real Phase 4 secrets scan). Proves the carry-forward wiring
    /// end to end: a repeat scan of the same org/repo must not require the
    /// human to re-justify a finding they already justified last time —
    /// `run_interactive_pipeline`'s pre-gate block should have already
    /// looked it up via `db.get_carry_forward_overrides` and applied it, so
    /// the second run's decision can proceed with zero overrides and still
    /// end up `ok`.
    #[tokio::test]
    #[ignore]
    async fn repeat_scan_of_same_repo_carries_forward_a_previously_justified_finding() {
        let (base, state) = spawn_test_server().await;
        let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(120)).build().unwrap();
        let zip = zip_bytes(&[("app.js", b"const aws_secret_key = 'AKIAABCDEFGHIJKLMNOP';\nconsole.log(aws_secret_key);\n")]);

        // --- First scan: a human justifies the secret finding by hand. ---
        let form1 = Form::new().text("org", "acme").text("repo", "widgets").text("dryRun", "true").part("archive", Part::bytes(zip.clone()).file_name("p.zip"));
        let client1 = client.clone();
        let base1 = base.clone();
        let handle1 = tokio::spawn(async move { client1.post(format!("{base1}/api/pipeline")).multipart(form1).send().await.unwrap() });
        let job1 = wait_for_review_gate(&state, std::time::Duration::from_secs(180)).await;
        let (secret_issue_id, open_issue_ids) = {
            let running = state.running_runs.lock();
            let issues = &running[&job1].all_issues;
            let secret_issue_id = issues.iter().find(|i| i.category == "secret").map(|i| i.id.clone()).expect("fixture should flag a secret finding");
            // Override every open blocking finding, not just the secret —
            // a config-level check (e.g. "codeql-query-suite-stale") can
            // also be blocking here and would otherwise need re-justifying
            // on every scan, which isn't what this test is checking.
            let open_issue_ids: Vec<String> = issues.iter().filter(|i| i.status != "overridden").map(|i| i.id.clone()).collect();
            (secret_issue_id, open_issue_ids)
        };
        let overrides1 = open_issue_ids
            .into_iter()
            .map(|issue_id| {
                let justification = if issue_id == secret_issue_id { "Test fixture literal, not a real credential.".to_string() } else { "not relevant to this test".to_string() };
                SubmittedOverride { issue_id, justification, code: None }
            })
            .collect();
        assert!(state.review_gate.resolve(&job1, ReviewDecisionInput { proceed: true, overrides: overrides1, actor: Actor { email: "human@acme.example".into(), name: "Human Reviewer".into() } }));
        let res1 = handle1.await.unwrap();
        assert_eq!(res1.status(), 200);
        let events1 = read_ndjson(res1).await;
        assert_eq!(events1.iter().find(|e| e["type"] == "done").unwrap()["ok"], true);

        // --- Second scan: same org/repo/fixture, human submits *no*
        // overrides at all — the earlier justification must already have
        // been carried forward and applied before the gate even opened.
        let form2 = Form::new().text("org", "acme").text("repo", "widgets").text("dryRun", "true").part("archive", Part::bytes(zip).file_name("p.zip"));
        let handle2 = tokio::spawn(async move { client.post(format!("{base}/api/pipeline")).multipart(form2).send().await.unwrap() });
        let job2 = wait_for_review_gate(&state, std::time::Duration::from_secs(180)).await;
        assert_ne!(job1, job2);
        assert!(state.review_gate.resolve(&job2, ReviewDecisionInput { proceed: true, overrides: vec![], actor: Actor { email: "human@acme.example".into(), name: "Human Reviewer".into() } }));
        let res2 = handle2.await.unwrap();
        assert_eq!(res2.status(), 200);
        let events2 = read_ndjson(res2).await;
        let done2 = events2.iter().find(|e| e["type"] == "done").unwrap();
        assert_eq!(done2["ok"], true, "second scan should have succeeded on the carried-forward override alone: {done2:?}");

        // The carried-forward override is a real audit-log row, attributed
        // to a distinct system actor, not silently invisible.
        let project2_id = state.db.get_project_id_by_job_id(&job2).unwrap();
        let overrides2 = state.db.get_project_overrides(project2_id);
        let carried = overrides2.iter().find(|o| o.issue_id == secret_issue_id).expect("carried-forward override should be recorded on the second scan's own project row");
        assert_eq!(carried.actor_email, "carried-forward@ignite.internal");
        assert!(carried.justification.contains("Carried forward"));
    }

    async fn wait_for_review_gate(state: &Arc<AppState>, timeout: std::time::Duration) -> String {
        tokio::time::timeout(timeout, async {
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                let running = state.running_runs.lock();
                if let Some((id, _)) = running.iter().find(|(_, r)| r.review_active) {
                    return id.clone();
                }
                drop(running);
            }
        })
        .await
        .expect("run never reached the review gate within the timeout — the fixture's blocking finding may not be getting flagged in this environment")
    }

    /// Regression test for the "Stop pipeline"/Esc/✕ path leaving a run
    /// stuck forever at the review gate when the caller's session has
    /// expired: a bare decline (`proceed: false`, no overrides — exactly
    /// what those all send) has nothing to attribute, so it must succeed
    /// fully unauthenticated (no bearer token, no `actor` in the body),
    /// driven through the real HTTP route (not `review_gate.resolve`
    /// directly, which would bypass the auth-requirement bug entirely).
    #[tokio::test]
    async fn review_decision_stop_with_no_overrides_needs_no_auth() {
        let (base, state) = spawn_test_server().await;
        let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(120)).build().unwrap();
        let zip = zip_bytes(&[("app.js", b"const aws_secret_key = 'AKIAABCDEFGHIJKLMNOP';\nconsole.log(aws_secret_key);\n")]);
        let form = Form::new().text("org", "acme").text("repo", "widgets").text("dryRun", "true").part("archive", Part::bytes(zip).file_name("p.zip"));
        let base_for_decision = base.clone();

        let handle = tokio::spawn(async move { client.post(format!("{base}/api/pipeline")).multipart(form).send().await.unwrap() });

        // Bounded, not an unconditional `loop`: if the fixture's blocking
        // finding doesn't actually get flagged in this environment (e.g. a
        // secrets-scan fixture that needs `gitleaks` installed to match),
        // the run never pauses at the review gate and `review_active`
        // never becomes true — an unbounded loop here would then spin
        // forever instead of failing with a message that says why.
        let job_id = tokio::time::timeout(std::time::Duration::from_secs(180), async {
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                let running = state.running_runs.lock();
                if let Some((id, _)) = running.iter().find(|(_, r)| r.review_active) {
                    return id.clone();
                }
                drop(running);
            }
        })
        .await
        .expect("run never reached the review gate within 180s — the fixture's blocking finding may not be getting flagged in this environment");

        // No bearer token at all — mirrors a session that expired while
        // the pipeline sat paused for review.
        let decision_res = reqwest::Client::new().post(format!("{base_for_decision}/api/pipeline/{job_id}/review-decision")).json(&json!({ "proceed": false, "overrides": [] })).send().await.unwrap();
        assert_eq!(decision_res.status(), 200, "a bare decline with no overrides must not require authentication");

        let res = handle.await.unwrap();
        assert_eq!(res.status(), 200);
        let events = read_ndjson(res).await;
        let done = events.iter().find(|e| e["type"] == "done").unwrap();
        assert_eq!(done["ok"], false, "the run must actually finish (declined), not hang forever at the review gate");
    }

    /// The counterpart guard: an unauthenticated caller with no `actor` in
    /// the body still cannot submit an actual override — only a bare
    /// decline/no-op skips the identity requirement.
    #[tokio::test]
    async fn review_decision_with_overrides_still_requires_an_actor() {
        let (base, state) = spawn_test_server().await;
        let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(120)).build().unwrap();
        let zip = zip_bytes(&[("app.js", b"const aws_secret_key = 'AKIAABCDEFGHIJKLMNOP';\nconsole.log(aws_secret_key);\n")]);
        let form = Form::new().text("org", "acme").text("repo", "widgets").text("dryRun", "true").part("archive", Part::bytes(zip).file_name("p.zip"));
        let base_for_decision = base.clone();

        let handle = tokio::spawn(async move { client.post(format!("{base}/api/pipeline")).multipart(form).send().await.unwrap() });
        let job_id = tokio::time::timeout(std::time::Duration::from_secs(180), async {
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                let running = state.running_runs.lock();
                if let Some((id, r)) = running.iter().find(|(_, r)| r.review_active) {
                    return (id.clone(), r.all_issues.iter().find(|i| i.status != "overridden").map(|i| i.id.clone()));
                }
                drop(running);
            }
        })
        .await
        .expect("run never reached the review gate within 180s");
        let (job_id, issue_id) = job_id;
        let issue_id = issue_id.expect("expected at least one open blocking finding to attempt to override");

        let decision_res = reqwest::Client::new()
            .post(format!("{base_for_decision}/api/pipeline/{job_id}/review-decision"))
            .json(&json!({ "proceed": true, "overrides": [{ "issueId": issue_id, "justification": "reviewed, safe" }] }))
            .send()
            .await
            .unwrap();
        assert_eq!(decision_res.status(), 401, "submitting an actual override with no session and no actor in the body must still be rejected");

        // Clean up: the pipeline is still paused at the review gate — stop
        // it with a bare decline so the spawned upload request resolves.
        let _ = reqwest::Client::new().post(format!("{base_for_decision}/api/pipeline/{job_id}/review-decision")).json(&json!({ "proceed": false, "overrides": [] })).send().await;
        let _ = handle.await;
    }
}
