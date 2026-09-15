//! The actual phase-by-phase driver for `POST /api/pipeline` — split
//! out of `pipeline_interactive.rs` since this one function alone was
//! ~660 lines. Shares its parent module's imports/types/consts via
//! `use super::*`.

use super::*;

pub(super) async fn run_interactive_pipeline(state: Arc<AppState>, upload: ParsedUpload, log: Arc<EventLog>, job_id: String, session_gh_token: String, owner_email: String) {
    let org = upload.org.clone();
    let repo = upload.repo.clone();
    let is_gxp = super::super::phase_meta::phase_enabled(&log.meta, 2) && upload.gxp_requested;
    let dry_run = upload.dry_run;

    log.send(json!({ "type": "job", "jobId": job_id }));

    let staging_dir = std::env::temp_dir().join("gatekeeper-staging").join(&job_id);
    let source_backup_dir = PathBuf::from(format!("{}-source-backup", staging_dir.to_string_lossy()));
    let publish_dir = PathBuf::from(format!("{}-publish", staging_dir.to_string_lossy()));
    let workflow_dir = PathBuf::from(format!("{}-workflows", staging_dir.to_string_lossy()));

    let mut all_issues: Vec<Issue> = Vec::new();
    let mut project_id: Option<i64> = None;
    // US-04: the normalized `scan_runs.id` for this run, resolved once
    // `project_id` is known — `None` for the (rare) case Phase 1 itself
    // failed before a project row (and so a scan run) ever existed, in
    // which case there's nothing to transition.
    let mut run_id: Option<i64> = None;
    let mut phase1_ok = false;
    let mut project_root_ready = false;
    let mut project_root: Option<PathBuf> = None;
    let mut snapshot_ready = false;
    let mut shipped_for_real = false;
    let mut keep_source_backup_dir = false;
    let mut gh_token = String::new();

    state.running_runs.lock().insert(
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
                match state.db.create_project(&job_id, &org, &repo, is_gxp, "ui", Some(&scan_location)) {
                    Ok(pid) => {
                        project_id = Some(pid);
                        run_id = state.db.get_scan_run_for_legacy_project(pid).map(|r| r.id);
                        if let Some(rid) = run_id {
                            if let Err(e) = state.db.transition_scan_run(rid, ignite_run_lifecycle::RunLifecycleState::Scanning) {
                                tracing::warn!("transition_scan_run({rid}, Scanning) failed: {e}");
                            }
                        }
                        log.set_project_id(pid);
                        if let Some(live) = state.running_runs.lock().get_mut(&job_id) {
                            live.project_id = Some(pid);
                        }
                        log.status(1, "success", None);
                        phase1_ok = true;
                    }
                    Err(e) => {
                        let msg = format!("Failed to create project record: {e}");
                        log.log(1, &format!("✗ {msg}"));
                        log.status(1, "failed", Some(json!({ "error": msg })));
                    }
                }
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
                    // `phase1_ok` is only ever set true in the same branch that sets
                    // `project_id = Some(pid)` above, so this is always populated here —
                    // but a hard `.unwrap()` would turn any future decoupling of the two
                    // into a panic instead of a normal phase-2 failure.
                    match project_id {
                        None => {
                            log.log(2, "✗ No project record to attach documents to (internal state error).");
                            log.status(2, "failed", Some(json!({ "error": "missing project id" })));
                            all_issues.push(new_issue("phase2::gxp-documents".to_string(), 2, "gxp-documents", Severity::Error, "No project record to attach documents to.".to_string(), None, None));
                            persist!();
                        }
                        Some(pid) => {
                            log.log(2, &format!("Collecting {} uploaded document(s) and {} link(s)...", upload.gxp_doc_files.len(), valid_links.len()));
                            for (name, mime, data) in &upload.gxp_doc_files {
                                state.db.add_upload_document(pid, name, mime.as_deref(), data.len() as i64, data);
                                log.log(2, &format!("✓ Archived upload: {name} ({:.1} KB)", data.len() as f64 / 1024.0));
                            }
                            for (name, url) in &valid_links {
                                state.db.add_link_document(pid, name, url);
                                log.log(2, &format!("✓ Archived link: {name} → {url}"));
                            }
                            log.log(2, &format!("✓ {} GxP validation document(s) saved to the database.", upload.gxp_doc_files.len() + valid_links.len()));
                            log.status(2, "success", None);
                        }
                    }
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
            log.log(3, &format!("Project root: {}", root.display()));
            project_root = Some(root.clone());

            ignite_staging::clone_directory_without_symlinks(&root, &source_backup_dir).map_err(|e| e.to_string())?;
            log.log(3, "Created immutable source snapshot for final publish phase.");
            snapshot_ready = true;
            project_root_ready = true;

            // Same `git rev-parse HEAD` call generate_provenance already makes
            // against the staged root - most uploads (raw zip/folder, no
            // .git) simply have no commit to record, which is expected and
            // not an error; recorded here too (not just in the provenance
            // document) so it's a queryable project column for retention
            // reproduction once this run's source tree ages out (see
            // RETAINED_TOTAL_KEEP below).
            if let Some(pid) = project_id {
                let source_commit_sha = state
                    .runner
                    .run_tool("git", &["rev-parse".to_string(), "HEAD".to_string()], &root.to_string_lossy(), ignite_tool_runner::RunToolOptions::default())
                    .await
                    .ok()
                    .map(|o| o.stdout.trim().to_string())
                    .filter(|s| !s.is_empty());
                if let Some(sha) = source_commit_sha {
                    state.db.set_project_commit_shas(pid, Some(&sha), None);
                }
            }
            if let Some(live) = state.running_runs.lock().get_mut(&job_id) {
                live.project_root = Some(root.clone());
                live.source_backup_dir = Some(source_backup_dir.clone());
            }

            let client = ignite_deps_dev_client::DepsDevClient::new();
            let npm_http = reqwest::Client::new();
            let log_a = log.clone();
            let license_issues = ignite_pipeline_core::run_license_and_dependency_scan(&root, &state.runner, &client, &npm_http, &state.db, project_id, move |m| log_a.log(3, m)).await;
            if !license_issues.is_empty() {
                all_issues.extend(license_issues);
                persist!();
            }

            {
                let log_b = log.clone();
                ignite_pipeline_core::run_env_and_codeowners_checks(&root, "Remove them and re-upload.", move |m| log_b.log(3, m)).map_err(|e| e.to_string())?;
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
        } else if !super::super::phase_meta::phase_enabled(&log.meta, 4) {
            log.log(4, "Skipped — disabled by config (phases: [{ id: 4, enabled: false }]).");
            log.status(4, "skipped", None);
        } else {
            log.status(4, "running", None);
            let root = project_root.clone().unwrap();
            // No original backing directory to check git status against —
            // a ZIP/folder upload's only content is what got extracted
            // into `root` itself, so that's what `.igniteignore`'s commit
            // status gets checked against too (correctly unverifiable for
            // an upload with no git history in it).
            let config = default_phase4_config(state.as_ref(), &org, &repo, project_id, None);
            match ignite_phase4_orchestrator::run_phase4_checks(&root, &state.runner, &state.db, &config, &state.package_hallucination_checker, &|m: &str| log.log(4, m)).await {
                Ok(output) => {
                    let issue_count = output.issues.len();
                    let blocking_count = output.issues.iter().filter(|i| i.severity == Severity::Error).count();
                    all_issues.extend(output.issues);
                    if issue_count > 0 {
                        log.log(4, &format!("⚠ {issue_count} flagged issue(s) ({blocking_count} blocking) — will be presented for final review before push."));
                    }
                    // `task_timings` (see phase4-orchestrator's own doc
                    // comment) is which check was the bottleneck this run —
                    // sent both live (the status event, for the
                    // in-progress/just-finished popup) and persisted (so
                    // reopening this project later, via `/api/projects/:id`,
                    // still shows it).
                    let task_timings: Vec<Value> = output.task_timings.iter().map(|(name, ms)| json!({ "name": name, "ms": ms })).collect();
                    persist!();
                    log.status(4, "success", Some(json!({ "issueCount": issue_count, "blockingCount": blocking_count, "taskTimings": task_timings })));
                    if let Some(pid) = project_id {
                        state.db.set_step_task_timings(pid, 4, &serde_json::to_string(&task_timings).unwrap());
                    }
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
        } else if !super::super::phase_meta::phase_enabled(&log.meta, 5) {
            log.log(5, "Skipped — disabled by config (phases: [{ id: 5, enabled: false }]).");
            log.log(5, "⚠ The org governance workflows will still gate the repo on GitHub after push.");
            log.status(5, "skipped", None);
        } else {
            log.status(5, "running", None);
            let root = project_root.clone().unwrap();
            let log_5 = log.clone();
            let gov = &state.config.governance;
            match ignite_pipeline_core::run_governance_ci_phase(&root, &workflow_dir, &state.runner, &state.db, &gov.repo, &gov.workflow, &gov.event, gov.timeout_minutes, move |m| log_5.log(5, m)).await {
                Ok(ignite_pipeline_core::GovernanceCiOutcome::Skipped(reason)) => {
                    log.log(5, &format!("⚠ Local CI skipped: {reason}"));
                    log.log(5, "⚠ The org governance workflows will still gate the repo on GitHub after push.");
                    log.status(5, "success", None);
                }
                Ok(ignite_pipeline_core::GovernanceCiOutcome::Passed) => {
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

        // ---------------- Final review gate ----------------
        log.status(6, "running", None);

        // Auto-resolve findings this scan doesn't need to put in front of
        // a human at all: first, exact-id matches already justified on a
        // previous scan of this same org/repo; then (if configured) any
        // remaining finding in a low-risk allowlisted category the
        // configured LLM is willing to draft a justification for. Both
        // write real override rows under a distinct system/AI actor (never
        // attributed to whoever happens to resolve the gate below) and
        // fold into `pre_overrides`/`pre_ids` so `validate_overrides`
        // treats them as already applied and Ignite Studio shows them as
        // identified-but-justified rather than open.
        let mut pre_overrides: Vec<SubmittedOverride> = Vec::new();
        let mut pre_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
        // issue_id -> (justification, actorEmail, actorName), mirrored onto
        // the `review_required` event below so the live review-gate screen
        // shows the same "✨ AI-justified"/"↻ Carried forward" badge and
        // justification text the read-only history/Studio views already get
        // from `IssueRow` — `all_issues` itself carries no override fields.
        let mut pre_meta: std::collections::HashMap<String, (String, &'static str, &'static str)> = std::collections::HashMap::new();
        if let Some(pid) = project_id {
            let carried_forward = state.db.get_carry_forward_overrides(&org, &repo, pid);
            let mut carried_count = 0;
            for issue in &all_issues {
                let Some(prior) = carried_forward.get(&issue.id) else { continue };
                let justification = format!("Carried forward from a previous scan of {org}/{repo}: {}", prior.justification);
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
                    justification: &justification,
                    actor_email: "carried-forward@ignite.internal",
                    actor_name: Some("Carried forward (previous scan)"),
                    email_sent: false,
                });
                pre_meta.insert(issue.id.clone(), (justification.clone(), "carried-forward@ignite.internal", "Carried forward (previous scan)"));
                pre_overrides.push(SubmittedOverride { issue_id: issue.id.clone(), justification, code: None });
                pre_ids.insert(issue.id.clone());
                carried_count += 1;
            }
            if carried_count > 0 {
                log.log(6, &format!("⚠ {carried_count} finding(s) already justified in a previous scan of {org}/{repo} — carried forward, no action needed."));
            }

            let remaining: Vec<Issue> = all_issues.iter().filter(|i| !pre_ids.contains(&i.id)).cloned().collect();
            let ai_suggestions = crate::ai_justify::suggest_justifications(&state.config.ai_auto_justify, &state.llm_config, &remaining, |m| log.log(6, m)).await;
            if !ai_suggestions.is_empty() {
                let mut ai_count = 0;
                for issue in &all_issues {
                    if pre_ids.contains(&issue.id) {
                        continue;
                    }
                    let Some(justification) = ai_suggestions.get(&issue.id) else { continue };
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
                        actor_email: "ai-assist@ignite.internal",
                        actor_name: Some("Ignite AI Assist"),
                        email_sent: false,
                    });
                    pre_meta.insert(issue.id.clone(), (justification.clone(), "ai-assist@ignite.internal", "Ignite AI Assist"));
                    pre_overrides.push(SubmittedOverride { issue_id: issue.id.clone(), justification: justification.clone(), code: None });
                    pre_ids.insert(issue.id.clone());
                    ai_count += 1;
                }
                if ai_count > 0 {
                    log.log(6, &format!("⚠ {ai_count} finding(s) auto-justified by the configured AI engine — review before shipping."));
                }
            }

            if !pre_ids.is_empty() {
                persist_issues_snapshot(&state, &job_id, project_id, &all_issues, &pre_ids);
            }
        }

        if !all_issues.is_empty() {
            let error_count = all_issues.iter().filter(|i| i.severity == Severity::Error).count();
            log.log(6, &format!("⚠ {} issue(s) accumulated across the run ({error_count} blocking) — waiting for final review before provisioning/push.", all_issues.len()));

            let rx = state.review_gate.wait(&job_id, &owner_email);
            if let Some(live) = state.running_runs.lock().get_mut(&job_id) {
                live.review_active = true;
            }
            let review_issues: Vec<serde_json::Value> = all_issues
                .iter()
                .map(|i| {
                    let mut v = serde_json::to_value(i).unwrap();
                    if let Some((justification, actor_email, actor_name)) = pre_meta.get(&i.id) {
                        let obj = v.as_object_mut().unwrap();
                        obj.insert("status".to_string(), json!("overridden"));
                        obj.insert("justification".to_string(), json!(justification));
                        obj.insert("actorEmail".to_string(), json!(actor_email));
                        obj.insert("actorName".to_string(), json!(actor_name));
                    }
                    v
                })
                .collect();
            log.send(json!({ "type": "review_required", "phase": 6, "jobId": job_id, "issues": review_issues }));

            // US-04: the durable counterpart to `review_gate.wait`'s
            // in-memory registration above — a server restart loses the
            // live oneshot (and so the ability to transparently resume
            // *this* task), but `pending_reviews` still lets a client
            // reconnecting with this job id (`GET .../status`) see that a
            // review was pending, for which issues, and lets an operator
            // recognize the run needs to be restarted rather than silently
            // hanging forever.
            if let Some(rid) = run_id {
                if let Some(pid) = project_id {
                    let issues_json = serde_json::to_string(&review_issues).unwrap_or_else(|_| "[]".to_string());
                    state.db.create_pending_review(rid, pid, &org, &repo, &owner_email, &issues_json);
                    // US-05: bounded lease — a run awaiting review is
                    // "active work" the retention sweeper must not evict
                    // out from under a reviewer, but the hold still has
                    // to expire eventually rather than pin the source
                    // forever if the review is simply abandoned.
                    state.db.set_snapshot_lease(pid, "awaiting_review", 72);
                }
                if let Err(e) = state.db.transition_scan_run(rid, ignite_run_lifecycle::RunLifecycleState::AwaitingReview) {
                    tracing::warn!("transition_scan_run({rid}, AwaitingReview) failed: {e}");
                }
            }

            let decision = match rx.await {
                Ok(d) => d,
                Err(_) => {
                    if let Some(rid) = run_id {
                        let _ = state.db.transition_scan_run(rid, ignite_run_lifecycle::RunLifecycleState::Failed);
                    }
                    break 'run Err((6, "Pipeline interrupted: review gate closed without a decision.".to_string()));
                }
            };
            if let Some(rid) = run_id {
                let decision_json = json!({ "proceed": decision.proceed, "actorEmail": decision.actor.email, "overrideCount": decision.overrides.len() }).to_string();
                state.db.record_review_decision(rid, &decision_json);
            }
            if let Some(live) = state.running_runs.lock().get_mut(&job_id) {
                live.review_active = false;
            }

            let mut merged_overrides = decision.overrides.clone();
            merged_overrides.extend(pre_overrides.iter().cloned());
            let result = validate_overrides(&all_issues, &merged_overrides);
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
            // Already recorded (and logged) above under their own
            // carried-forward/AI actor — don't re-attribute them to
            // whoever just resolved the gate.
            let human_applied: Vec<(&Issue, String)> = result.applied.iter().filter(|(issue, _)| !pre_ids.contains(&issue.id)).map(|(issue, j)| (*issue, j.clone())).collect();

            // Dual-custody: a critical-severity override submitted just
            // now by whoever resolved this review gate must not resolve
            // its issue until a *different* reviewer approves it — same
            // `security.overrideApproval` gate `routes/effectivate.rs`
            // applies, kept in sync here since this is the other place a
            // human submits a brand-new override.
            let (auto_applied, needs_approval): (Vec<ignite_override_engine::AppliedOverride>, Vec<ignite_override_engine::AppliedOverride>) = if state.config.security.override_approval.enabled {
                let already_approved: std::collections::HashSet<String> = match project_id {
                    Some(pid) => human_applied.iter().filter(|(i, _)| state.db.has_approved_override(pid, &i.id)).map(|(i, _)| i.id.clone()).collect(),
                    None => std::collections::HashSet::new(),
                };
                partition_for_dual_custody(human_applied, |i| is_critical_score(i.score), &already_approved)
            } else {
                (human_applied, Vec::new())
            };
            let applied_count = auto_applied.len();

            if applied_count > 0 {
                log.log(6, &format!("⚠ {applied_count} flagged issue(s) overridden by {}:", decision.actor.email));
                for (issue, justification) in &auto_applied {
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

            if !needs_approval.is_empty() {
                log.log(6, &format!("⚠ {} critical finding(s) overridden by {} require a second reviewer's approval before shipping can continue:", needs_approval.len(), decision.actor.email));
                for (issue, justification) in &needs_approval {
                    let loc = issue.file.as_deref().map(|f| format!("{f}{}", issue.line.map(|l| format!(":{l}")).unwrap_or_default())).unwrap_or_else(|| "unknown location".to_string());
                    log.log(6, &format!("    ⏳ [pending approval] [{:?}] {loc} — {} — \"{justification}\"", issue.severity, issue.summary));
                    if let Some(pid) = project_id {
                        if !state.db.has_pending_override(pid, &issue.id) {
                            state.db.add_pending_override(ignite_db_store::AddOverrideArgs {
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
            }

            // `applied_ids` must exclude the still-pending critical
            // overrides — `persist_issues_snapshot` flips exactly these
            // ids to `"overridden"`, and a pending override must leave its
            // issue `"open"` (still blocking) until approved.
            let needs_approval_ids: std::collections::HashSet<String> = needs_approval.iter().map(|(i, _)| i.id.clone()).collect();
            let applied_ids: std::collections::HashSet<String> = applied_ids.difference(&needs_approval_ids).cloned().collect();
            persist_issues_snapshot(&state, &job_id, project_id, &all_issues, &applied_ids);

            if !decision.proceed {
                if let Some(rid) = run_id {
                    let _ = state.db.transition_scan_run(rid, ignite_run_lifecycle::RunLifecycleState::Blocked);
                }
                break 'run Err((6, "Pipeline interrupted by user after reviewing all flagged issues.".to_string()));
            }
            if !needs_approval.is_empty() {
                // Stays `awaiting_review` — this is a *different* gate (a
                // second reviewer's dual-custody approval) still pending,
                // not this run reaching a terminal state.
                break 'run Err((6, format!("{} critical finding(s) require a second reviewer's approval before this can ship. Ask another reviewer to approve them, then re-run.", needs_approval.len())));
            }
            if !ok {
                log.log(6, &format!("✗ {unresolved_count} blocking finding(s) were not overridden:"));
                for line in &unresolved_lines {
                    log.log(6, line);
                }
                if let Some(rid) = run_id {
                    let _ = state.db.transition_scan_run(rid, ignite_run_lifecycle::RunLifecycleState::Blocked);
                }
                break 'run Err((6, format!("{unresolved_count} unresolved blocking finding(s) remain across the run. Override each with a justification, or fix them and re-run.")));
            }
            log.log(6, "✓ User chose to continue after reviewing all flagged issues.");
        }
        if let Some(rid) = run_id {
            // Reached phase 6 with nothing left blocking — either no
            // finding ever needed a decision (`Scanning -> Approved`
            // directly), or the review above just approved proceeding
            // (`AwaitingReview -> Approved`); a same-state call is a legal
            // no-op either way.
            if let Err(e) = state.db.transition_scan_run(rid, ignite_run_lifecycle::RunLifecycleState::Approved) {
                tracing::warn!("transition_scan_run({rid}, Approved) failed: {e}");
            }
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
            // Before `finish_project` — its own internal lifecycle sync
            // is a naive `"success" -> "published"` fallback that
            // doesn't know this was a dry run; a precise state set first
            // is never overwritten (terminal states reject any further
            // transition, `sync_scan_run_lifecycle`'s included).
            if let Some(rid) = run_id {
                let _ = state.db.transition_scan_run(rid, ignite_run_lifecycle::RunLifecycleState::Completed);
            }
            if let Some(pid) = project_id {
                state.db.finish_project("success", None, None, None, pid);
            }
            log.send(json!({ "type": "done", "ok": true, "dryRun": dry_run, "repoUrl": Value::Null, "prUrl": Value::Null, "effectivatable": snapshot_ready && !shipped_for_real, "projectId": project_id }));
            break 'run Ok(());
        }

        // A missing required snapshot must be a clear, recoverable
        // failure — never something that could be mistaken for a passing
        // decision (this run's own `all_issues`/policy outcome is
        // unrelated to whether the snapshot phase 6 needs is actually on
        // disk).
        let backup_ok = source_backup_dir.is_dir();
        if !backup_ok {
            if let Some(rid) = run_id {
                let _ = state.db.transition_scan_run(rid, ignite_run_lifecycle::RunLifecycleState::Failed);
            }
            break 'run Err((6, "Immutable source snapshot is missing before phase 6 — an earlier phase failed to produce a publishable project.".to_string()));
        }
        if let Some(rid) = run_id {
            if let Err(e) = state.db.transition_scan_run(rid, ignite_run_lifecycle::RunLifecycleState::Publishing) {
                tracing::warn!("transition_scan_run({rid}, Publishing) failed: {e}");
            }
        }
        let _ = std::fs::remove_dir_all(&publish_dir);
        if let Err(e) = ignite_staging::clone_directory_without_symlinks(&source_backup_dir, &publish_dir) {
            if let Some(rid) = run_id {
                let _ = state.db.transition_scan_run(rid, ignite_run_lifecycle::RunLifecycleState::Failed);
            }
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
                // Before `finish_project` — see the dry-run branch's
                // identical comment on why the ordering matters.
                if let Some(rid) = run_id {
                    let _ = state.db.transition_scan_run(rid, ignite_run_lifecycle::RunLifecycleState::Published);
                }
                if let Some(pid) = project_id {
                    state.db.finish_project("success", None, Some(&ship_result.repo_url), ship_result.pr_url.as_deref(), pid);
                    // publish_dir still has the just-pushed commit checked
                    // out - this is the durable "checkout this to reproduce
                    // the scanned code" reference once this run's retained
                    // source ages past RETAINED_TOTAL_KEEP.
                    let shipped_commit_sha = state
                        .runner
                        .run_tool("git", &["rev-parse".to_string(), "HEAD".to_string()], &publish_dir.to_string_lossy(), ignite_tool_runner::RunToolOptions::default())
                        .await
                        .ok()
                        .map(|o| o.stdout.trim().to_string())
                        .filter(|s| !s.is_empty());
                    if let Some(sha) = shipped_commit_sha {
                        state.db.set_project_commit_shas(pid, None, Some(&sha));
                    }
                }
                log.send(json!({ "type": "done", "ok": true, "dryRun": dry_run, "repoUrl": ship_result.repo_url, "prUrl": ship_result.pr_url, "effectivatable": snapshot_ready && !shipped_for_real, "projectId": project_id }));
                Ok(())
            }
            Err(e) => {
                // `ship_to_github` failing here doesn't tell us whether it
                // failed before or after actually creating/pushing to the
                // remote repository (see `ignite-shipping`'s own
                // reconciliation gap — US-06's scope, not this story's);
                // "failed" is at least never mistaken for "published",
                // which is what this acceptance criterion actually asks
                // for.
                if let Some(rid) = run_id {
                    let _ = state.db.transition_scan_run(rid, ignite_run_lifecycle::RunLifecycleState::Failed);
                }
                Err((6, e.to_string()))
            }
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
    state.running_runs.lock().remove(&job_id);
    if snapshot_ready && !shipped_for_real {
        if let Some(pid) = project_id {
            let mut pending = state.pending_effectivations.lock();
            let cutoff = Instant::now().checked_sub(std::time::Duration::from_secs(24 * 3600));
            pending.retain(|_, v| cutoff.map(|c| v.created_at > c).unwrap_or(true));
            pending.insert(pid, PendingEffectivation { org: org.clone(), repo: repo.clone(), source_backup_dir: source_backup_dir.clone(), created_at: Instant::now() });
            keep_source_backup_dir = true;
            // US-05: persisted counterpart to the 24h in-memory
            // `pending_effectivations` window above — the in-memory map
            // doesn't survive a restart, so without this the retention
            // sweeper (a separate process) would have no way to know this
            // project's retained source is still "active work" pending a
            // real push.
            state.db.set_snapshot_lease(pid, "pending_effectivation", 24);
        }
    }

    if let Some(pid) = project_id {
        for (phase, (state_str, logs)) in log.all_phase_records() {
            state.db.upsert_step(pid, phase, &super::super::phase_meta::phase_title(&log.meta, phase), &state_str, &logs.join("\n"));
        }
    }

    if snapshot_ready {
        if let Some(pid) = project_id {
            let retained_root = ignite_data_dir().join("retained-projects");
            let retained_dir = retained_root.join(pid.to_string());
            if std::fs::create_dir_all(&retained_root).is_ok() {
                let _ = std::fs::remove_dir_all(&retained_dir);
                if ignite_staging::clone_directory_without_symlinks(&source_backup_dir, &retained_dir).is_ok() {
                    state.db.retain_project_source(pid, &retained_dir.to_string_lossy(), "full");

                    // Re-rank every retained project by recency: anything
                    // that just aged from a top-5 "full" slot into ranks
                    // 6-10 gets pruned down to only the files that have
                    // findings (still on disk and Studio-browsable, just
                    // not the whole tree) rather than evicted outright -
                    // full eviction is reserved for rank 11+.
                    let ranked = state.db.list_retained_sources();
                    for (rank, row) in ranked.iter().enumerate() {
                        let rank = rank as i64 + 1;
                        if row.tier == "full" && rank > RETAINED_FULL_KEEP && rank <= RETAINED_TOTAL_KEEP {
                            let flagged: std::collections::HashSet<String> =
                                state.db.get_project_issues(row.project_id).into_iter().filter_map(|i| i.file).collect();
                            prune_retained_source_to_findings(std::path::Path::new(&row.dir_path), &flagged);
                            // Studio's file-tree browsing (`routes/studio.rs`)
                            // calls `walk_files` against a retained source's
                            // own directory, which — unlike the per-job
                            // staging dirs (see pipeline_validate.rs/
                            // pipeline_onboard.rs) — was never invalidated
                            // here on either prune or eviction below. A
                            // prune deletes most of the tree's files but
                            // leaves the directory at the same path, so a
                            // pre-prune WALK_CACHE entry would keep serving
                            // the stale (now-mostly-deleted) file list.
                            ignite_fs_utils::invalidate_walk_cache(std::path::Path::new(&row.dir_path));
                            state.db.set_retained_source_tier(row.project_id, "pruned");
                        }
                    }

                    for evicted in state.db.list_evictable_retained_sources(RETAINED_TOTAL_KEEP) {
                        let _ = std::fs::remove_dir_all(&evicted.dir_path);
                        let _ = std::fs::remove_dir_all(ignite_data_dir().join("codeql-dbs").join(evicted.project_id.to_string()));
                        // Same gap as the prune case above, worse here: the
                        // directory is gone for good, so a WALK_CACHE entry
                        // for it (from a prior Studio browse) would leak in
                        // process memory for the rest of the server's
                        // lifetime — one stale entry per evicted project,
                        // forever, since nothing else ever touches this key
                        // again to naturally overwrite/evict it.
                        ignite_fs_utils::invalidate_walk_cache(std::path::Path::new(&evicted.dir_path));
                        state.db.delete_retained_source(evicted.project_id);
                    }
                }
            }
        }
    }

    // Known gap, not yet closed here: `pipeline_validate.rs`/
    // `pipeline_onboard.rs` wrap their equivalent inner-async-block-then-
    // cleanup pattern in `catch_unwind` so a panic partway through the scan
    // can't skip this cleanup and leak the staging dir + its `WALK_CACHE`
    // entry. This function's body isn't structured as a single inner async
    // block awaited once (it's the `async fn` body itself, hundreds of
    // lines, with review-gate/event-log interactions threaded through) —
    // wrapping it the same way needs restructuring the whole function into
    // a nested block first, deferred rather than done as a rushed
    // undertested change to this much larger interactive-path handler.
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
