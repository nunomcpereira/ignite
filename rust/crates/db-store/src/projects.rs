//! Project/step/document CRUD — the core `projects`/`steps`/`documents` tables.
//!
//! `impl DbStore` block — one of several per-domain files this crate's
//! accessor methods are split across (see `lib.rs`'s module list).

use crate::store::DbStore;
use crate::types::*;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::json;

impl DbStore {
    // ---------------- projects / steps / documents ----------------

    /// `job_id` has a `UNIQUE NOT NULL` constraint (`schema.rs`) — a
    /// duplicate (a webhook replay, a client retransmitting a request
    /// whose response it never saw) previously panicked here via
    /// `.unwrap()` instead of being handled as the ordinary, expected
    /// possibility a unique-constrained column implies.
    pub fn create_project(
        &self,
        job_id: &str,
        org: &str,
        repo: &str,
        is_gxp: bool,
        source: &str,
        scan_location: Option<&str>,
    ) -> rusqlite::Result<i64> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO projects (job_id, org, repo, gxp, source, scan_location) VALUES (?, ?, ?, ?, ?, ?)",
            params![job_id, org, repo, is_gxp as i64, source, scan_location],
        )?;
        let project_id = conn.last_insert_rowid();
        drop(conn); // release before the repositories.rs helpers re-acquire the same lock

        // US-01: mirror every new project into the normalized
        // repository/snapshot/scan-run model live, going forward — no
        // GitHub repository id is known at upload time (only discovered
        // later, if ever, at publication), so resolution here is by
        // (org, repo) only; `resolve_repository` still merges onto a
        // github_repo_id-identified row transparently if one already
        // exists for this (org, repo) pair. Canonical content-addressed
        // snapshot hashing is US-05's scope — until then each project gets
        // its own unlabeled-as-trustworthy digest so it never collides
        // with, or is mistaken for, a real hash.
        let repository_id = self.resolve_repository(org, repo, None);
        let snapshot_id = self.create_or_reuse_snapshot(repository_id, &format!("unknown:project:{project_id}"), None, scan_location);
        self.record_scan_run(project_id, repository_id, snapshot_id, source, source == "repository-event");

        Ok(project_id)
    }

    /// Sets `status` directly with no other side effect (no audit event,
    /// no `finished_at`/`error`/`repo_url`/`pr_url` touch) — for a row
    /// that was never a real scan run in the first place (e.g. the
    /// `repository.created` webhook's zero-touch enrollment row) and so
    /// has no "scan completed" event to record. Using [`Self::finish_project`]
    /// for that case would both misrepresent a non-scan as a completed
    /// scan in the audit trail and duplicate the caller's own more
    /// specific audit event.
    pub fn set_project_status(&self, project_id: i64, status: &str) {
        let conn = self.conn.lock();
        if let Err(e) = conn.execute("UPDATE projects SET status = ? WHERE id = ?", params![status, project_id]) {
            tracing::error!("set_project_status({project_id}, {status:?}) failed: {e}");
        }
        drop(conn);
        self.sync_scan_run_lifecycle(project_id, status, status != "running");
    }

    /// Also records a `scan.completed` audit event (`audit_events.rs`) for
    /// every project regardless of outcome — the one choke point every
    /// scan path (headless `validate-all`, interactive upload, onboarding)
    /// already runs through, so a GxP deployment's local audit trail
    /// covers every scan, not just the ones that hit an override/gate/
    /// webhook event site.
    ///
    /// `project_id` can be `0`/nonexistent here: the onboarding/interactive
    /// routes validate org/repo names *before* calling `create_project`,
    /// and report that failure through this same "failed" path with
    /// whatever `project_id` local var they'd initialized to (`0`, never
    /// written to a real row) — so the org/repo/job_id lookup below is
    /// `.optional()`, and the audit event (and the row update itself) is
    /// simply skipped when there's no such project.
    pub fn finish_project(&self, status: &str, error: Option<&str>, repo_url: Option<&str>, pr_url: Option<&str>, project_id: i64) {
        let conn = self.conn.lock();
        let found: Option<(String, String, String)> =
            match conn.query_row("SELECT org, repo, job_id FROM projects WHERE id = ?", params![project_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).optional() {
                Ok(f) => f,
                Err(e) => {
                    tracing::error!("finish_project: failed to look up project {project_id}: {e}");
                    return;
                }
            };
        let Some((org, repo, job_id)) = found else { return };
        if let Err(e) = conn.execute(
            "UPDATE projects SET status = ?, error = ?, repo_url = ?, pr_url = ?, finished_at = datetime('now') WHERE id = ?",
            params![status, error, repo_url, pr_url, project_id],
        ) {
            tracing::error!("finish_project: failed to update status for {project_id}: {e}");
            return;
        }
        if let Some(url) = pr_url {
            if let Err(e) = conn.execute("INSERT INTO pull_requests (project_id, kind, url) VALUES (?, 'onboarding', ?)", params![project_id, url]) {
                tracing::error!("finish_project: failed to record pull request for {project_id}: {e}");
            }
        }
        drop(conn); // release before record_audit_event/sync_scan_run_lifecycle re-acquire the same lock
        self.sync_scan_run_lifecycle(project_id, status, true);

        let severity = if status == "failed" { "warning" } else { "info" };
        let summary = format!("scan {status} for {org}/{repo} (job {job_id})");
        // `hasLogArchive` is set unconditionally (not after checking
        // whether the gzip below actually produced anything) — a project
        // row only ever reaches `finish_project` after Phase 1 already
        // wrote at least one `steps` row, so there's always something to
        // archive; the download endpoint 404s gracefully in the
        // pathological case where it somehow isn't, rather than this
        // metadata field lying about it either way.
        let metadata = json!({ "error": error, "hasLogArchive": true }).to_string();
        match self.record_audit_event("scan.completed", severity, &summary, None, Some(&org), Some(&repo), Some(&metadata)) {
            Ok(event_id) => self.archive_project_logs(event_id, project_id),
            Err(e) => tracing::error!("record_audit_event failed for {org}/{repo}: {e}"),
        }
    }

    /// Gzips every phase's collected log text for `project_id` into one
    /// archive attached to `event_id` (the just-recorded `scan.completed`
    /// audit event) — see [`Self::save_audit_event_log`]. Best-effort:
    /// a compression/write failure is logged, never propagated, since the
    /// scan itself already completed successfully by the time this runs.
    fn archive_project_logs(&self, event_id: i64, project_id: i64) {
        use std::io::Write;
        let steps = {
            let conn = self.conn.lock();
            let Ok(mut stmt) = conn.prepare_cached("SELECT phase, title, logs FROM steps WHERE project_id = ? ORDER BY phase") else { return };
            let rows: Vec<(i64, String, String)> = match stmt.query_map(params![project_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))) {
                Ok(mapped) => mapped.filter_map(|r| r.ok()).collect(),
                Err(_) => return,
            };
            rows
        };
        if steps.is_empty() {
            return;
        }
        let mut combined = String::new();
        for (phase, title, logs) in &steps {
            combined.push_str(&format!("=== Phase {phase}: {title} ===\n{logs}\n\n"));
        }
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        if let Err(e) = encoder.write_all(combined.as_bytes()) {
            tracing::warn!("archive_project_logs({project_id}): gzip write failed: {e}");
            return;
        }
        match encoder.finish() {
            Ok(gzip_bytes) => self.save_audit_event_log(event_id, &gzip_bytes),
            Err(e) => tracing::warn!("archive_project_logs({project_id}): gzip finish failed: {e}"),
        }
    }

    /// The most recently created project row for `(org, repo)` — used by
    /// the inbound GitHub code-scanning webhook (`routes/code_scanning_webhook.rs`)
    /// to find which project's issues a dismissed/reopened alert belongs
    /// to, since the webhook payload only carries `(org, repo)`, not a
    /// job/project id.
    pub fn get_latest_project_for_org_repo(&self, org: &str, repo: &str) -> Option<(i64, String)> {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT id, job_id FROM projects WHERE org = ? AND repo = ? AND status IS NOT NULL ORDER BY id DESC LIMIT 1",
            params![org, repo],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .unwrap()
    }

    /// Records a PR Ignite opened outside the main onboarding flow — today
    /// only the interactive fix-PR feature (`routes/fix_pr.rs`'s `apply`),
    /// kind `'fix-pr'`. The onboarding PR itself is recorded automatically
    /// by `finish_project` when it's given a `pr_url`.
    pub fn record_pull_request(&self, project_id: i64, kind: &str, url: &str, branch: Option<&str>, files_changed: Option<i64>) {
        let conn = self.conn.lock();
        conn.execute("INSERT INTO pull_requests (project_id, kind, url, branch, files_changed) VALUES (?, ?, ?, ?, ?)", params![project_id, kind, url, branch, files_changed]).unwrap();
    }

    pub fn add_step(&self, project_id: i64, phase: i64, title: &str, state: &str, logs: &str) {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO steps (project_id, phase, title, state, logs) VALUES (?, ?, ?, ?, ?)",
            params![project_id, phase, title, state, logs],
        )
        .unwrap();
    }

    pub fn upsert_step(&self, project_id: i64, phase: i64, title: &str, state: &str, logs: &str) {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO steps (project_id, phase, title, state, logs)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(project_id, phase)
             DO UPDATE SET title = excluded.title, state = excluded.state, logs = excluded.logs",
            params![project_id, phase, title, state, logs],
        )
        .unwrap();
    }

    /// Attaches `phase4-orchestrator`'s per-check timing breakdown to
    /// phase 4's already-existing `steps` row (written by `upsert_step`
    /// just before this, same as every other phase's log/state) — a
    /// targeted `UPDATE` rather than a parameter added to `upsert_step`
    /// itself, since every other phase's completion site would otherwise
    /// need to pass `None` through a call chain that never cares about it.
    pub fn set_step_task_timings(&self, project_id: i64, phase: i64, task_timings_json: &str) {
        let conn = self.conn.lock();
        conn.execute("UPDATE steps SET task_timings_json = ? WHERE project_id = ? AND phase = ?", params![task_timings_json, project_id, phase]).unwrap();
    }

    pub fn add_upload_document(&self, project_id: i64, name: &str, mime: Option<&str>, size: i64, data: &[u8]) {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO documents (project_id, kind, name, url, mime, size, data) VALUES (?, 'upload', ?, NULL, ?, ?, ?)",
            params![project_id, name, mime, size, data],
        )
        .unwrap();
    }

    pub fn add_link_document(&self, project_id: i64, name: &str, url: &str) {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO documents (project_id, kind, name, url, mime, size, data) VALUES (?, 'link', ?, ?, NULL, NULL, NULL)",
            params![project_id, name, url],
        )
        .unwrap();
    }

    pub fn list_projects(&self) -> Vec<ProjectListRow> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare_cached(
                "SELECT p.id, p.job_id, p.org, p.repo, p.gxp, p.source, p.scan_location, p.status, p.error, p.repo_url, p.pr_url,
                        p.created_at, p.finished_at,
                        (SELECT COUNT(*) FROM documents d WHERE d.project_id = p.id) AS doc_count,
                        (SELECT COUNT(*) FROM issues i WHERE i.project_id = p.id) AS issue_count,
                        (SELECT 1 FROM retained_sources r WHERE r.project_id = p.id) AS retained,
                        (SELECT r.tier FROM retained_sources r WHERE r.project_id = p.id) AS retained_tier,
                        p.source_commit_sha, p.shipped_commit_sha
                 FROM projects p ORDER BY p.id DESC LIMIT 100",
            )
            .unwrap();
        stmt.query_map([], |row| {
            Ok(ProjectListRow {
                id: row.get(0)?,
                job_id: row.get(1)?,
                org: row.get(2)?,
                repo: row.get(3)?,
                gxp: row.get::<_, i64>(4)? != 0,
                source: row.get(5)?,
                scan_location: row.get(6)?,
                status: row.get(7)?,
                error: row.get(8)?,
                repo_url: row.get(9)?,
                pr_url: row.get(10)?,
                created_at: row.get(11)?,
                finished_at: row.get(12)?,
                doc_count: row.get(13)?,
                issue_count: row.get(14)?,
                retained: row.get::<_, Option<i64>>(15)?.unwrap_or(0) != 0,
                retained_tier: row.get(16)?,
                source_commit_sha: row.get(17)?,
                shipped_commit_sha: row.get(18)?,
            })
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
    }

    /// One row per distinct (org, repo) ever onboarded, keyed to its latest
    /// project run, for the web UI's "Onboarded Repos" view. Deliberately
    /// several small queries per repo (mirrors `get_project_details`'s own
    /// style) rather than one giant join — repo counts here are small
    /// (dozens, not millions) and this endpoint isn't hit on every request.
    pub fn list_onboarded_repo_summaries(&self, sla_critical_days: u32, sla_high_days: u32, sla_medium_days: u32) -> Vec<OnboardedRepoSummary> {
        let conn = self.conn.lock();

        // As in compliance.rs: a malformed/legacy row (e.g. an unexpected
        // NULL left by an old schema migration) or lock-contention hiccup
        // during prepare should degrade this public dashboard read to a
        // smaller result, not panic the whole request/worker thread.
        let Ok(mut latest_stmt) = conn.prepare_cached(
            "SELECT p.id, p.job_id, p.org, p.repo, p.status, COALESCE(p.finished_at, p.created_at) AS last_scan_at, p.repo_url
             FROM projects p
             INNER JOIN (SELECT org, repo, MAX(id) AS max_id FROM projects GROUP BY org, repo) latest
               ON p.org = latest.org AND p.repo = latest.repo AND p.id = latest.max_id
             ORDER BY last_scan_at DESC",
        ) else {
            return vec![];
        };
        struct Latest {
            id: i64,
            job_id: String,
            org: String,
            repo: String,
            status: String,
            last_scan_at: String,
            repo_url: Option<String>,
        }
        let Ok(latest_rows_iter) =
            latest_stmt.query_map([], |row| Ok(Latest { id: row.get(0)?, job_id: row.get(1)?, org: row.get(2)?, repo: row.get(3)?, status: row.get(4)?, last_scan_at: row.get(5)?, repo_url: row.get(6)? }))
        else {
            return vec![];
        };
        let latest_rows: Vec<Latest> = latest_rows_iter.filter_map(|r| r.ok()).collect();

        let (Ok(mut count_stmt), Ok(mut sla_stmt), Ok(mut acks_stmt), Ok(mut prs_stmt)) = (
            conn.prepare_cached("SELECT COUNT(*) FROM issues WHERE project_id = ?1 AND status = 'open' AND (?2 IS NULL OR category = ?2)"),
            conn.prepare_cached(&format!(
                "SELECT COUNT(*) FROM issues i
                 JOIN issue_first_seen f ON f.org = ?1 AND f.repo = ?2 AND f.issue_id = i.issue_id
                 WHERE i.project_id = ?3 AND i.status = 'open'
                   AND (julianday('now') - julianday(f.first_detected_at)) > (
                     CASE
                       WHEN COALESCE(i.score, 0) >= {} THEN ?4
                       WHEN COALESCE(i.score, 0) >= 7 THEN ?5
                       ELSE ?6
                     END
                   )",
                ignite_override_engine::CRITICAL_SCORE_THRESHOLD
            )),
            conn.prepare_cached(
                "SELECT o.id, o.phase, o.issue_id, o.category, o.severity, o.summary, o.file, o.line, o.justification,
                        o.actor_email, o.actor_name, o.email_sent, o.created_at
                 FROM overrides o INNER JOIN projects p ON o.project_id = p.id
                 WHERE p.org = ? AND p.repo = ? ORDER BY o.created_at DESC",
            ),
            conn.prepare_cached(
                "SELECT pr.kind, pr.url, pr.branch, pr.files_changed, pr.created_at
                 FROM pull_requests pr INNER JOIN projects p ON pr.project_id = p.id
                 WHERE p.org = ? AND p.repo = ? ORDER BY pr.created_at DESC LIMIT 20",
            ),
        ) else {
            return vec![];
        };

        latest_rows
            .into_iter()
            .map(|latest| {
                let findings_count: i64 = count_stmt.query_row(params![latest.id, Option::<&str>::None], |row| row.get(0)).unwrap_or(0);
                let license_problems: i64 = count_stmt.query_row(params![latest.id, Some("license-compliance")], |row| row.get(0)).unwrap_or(0);
                let sla_breaches: i64 = sla_stmt.query_row(params![latest.org, latest.repo, latest.id, sla_critical_days, sla_high_days, sla_medium_days], |row| row.get(0)).unwrap_or(0);
                let acknowledgments = acks_stmt
                    .query_map(params![latest.org, latest.repo], |row| {
                        Ok(OverrideRow {
                            id: row.get(0)?,
                            phase: row.get(1)?,
                            issue_id: row.get(2)?,
                            category: row.get(3)?,
                            severity: row.get(4)?,
                            summary: row.get(5)?,
                            file: row.get(6)?,
                            line: row.get(7)?,
                            justification: row.get(8)?,
                            actor_email: row.get(9)?,
                            actor_name: row.get(10)?,
                            email_sent: row.get::<_, i64>(11)? != 0,
                            created_at: row.get(12)?,
                        })
                    })
                    .map(|rows| rows.filter_map(|r| r.ok()).collect())
                    .unwrap_or_default();
                let recent_prs = prs_stmt
                    .query_map(params![latest.org, latest.repo], |row| Ok(PullRequestRow { kind: row.get(0)?, url: row.get(1)?, branch: row.get(2)?, files_changed: row.get(3)?, created_at: row.get(4)? }))
                    .map(|rows| rows.filter_map(|r| r.ok()).collect())
                    .unwrap_or_default();

                OnboardedRepoSummary {
                    org: latest.org,
                    repo: latest.repo,
                    repo_url: latest.repo_url,
                    latest_project_id: latest.id,
                    latest_job_id: latest.job_id,
                    status: latest.status,
                    last_scan_at: latest.last_scan_at,
                    license_problems,
                    findings_count,
                    sla_breaches,
                    acknowledgments,
                    recent_prs,
                }
            })
            .collect()
    }

    fn get_project_row(conn: &Connection, project_id: i64) -> Option<Project> {
        conn.query_row(
            "SELECT id, org, repo, gxp, source, scan_location, status, error, repo_url, pr_url, created_at, finished_at, source_commit_sha, shipped_commit_sha FROM projects WHERE id = ?",
            params![project_id],
            |row| {
                Ok(Project {
                    id: row.get(0)?,
                    org: row.get(1)?,
                    repo: row.get(2)?,
                    gxp: row.get::<_, i64>(3)? != 0,
                    source: row.get(4)?,
                    scan_location: row.get(5)?,
                    status: row.get(6)?,
                    error: row.get(7)?,
                    repo_url: row.get(8)?,
                    pr_url: row.get(9)?,
                    created_at: row.get(10)?,
                    finished_at: row.get(11)?,
                    source_commit_sha: row.get(12)?,
                    shipped_commit_sha: row.get(13)?,
                })
            },
        )
        .optional()
        .unwrap()
    }

    pub fn get_project(&self, project_id: i64) -> Option<Project> {
        let conn = self.conn.lock();
        Self::get_project_row(&conn, project_id)
    }

    pub fn get_project_details(&self, project_id: i64) -> Option<ProjectDetails> {
        let conn = self.conn.lock();
        let project = Self::get_project_row(&conn, project_id)?;

        let mut steps_stmt = conn.prepare_cached("SELECT phase, title, state, logs, task_timings_json FROM steps WHERE project_id = ? ORDER BY phase").unwrap();
        let steps = steps_stmt
            .query_map(params![project_id], |row| {
                Ok(Step { phase: row.get(0)?, title: row.get(1)?, state: row.get(2)?, logs: row.get(3)?, task_timings: row.get(4)? })
            })
            .unwrap()
            .map(|r| r.unwrap())
            .collect();

        let mut docs_stmt = conn
            .prepare_cached("SELECT id, kind, name, url, mime, size, created_at FROM documents WHERE project_id = ? ORDER BY id")
            .unwrap();
        let documents = docs_stmt
            .query_map(params![project_id], |row| {
                Ok(DocumentSummary {
                    id: row.get(0)?,
                    kind: row.get(1)?,
                    name: row.get(2)?,
                    url: row.get(3)?,
                    mime: row.get(4)?,
                    size: row.get(5)?,
                    created_at: row.get(6)?,
                })
            })
            .unwrap()
            .map(|r| r.unwrap())
            .collect();

        let overrides = Self::get_project_overrides_inner(&conn, project_id);

        Some(ProjectDetails { project, steps, documents, overrides })
    }

    pub fn project_exists(&self, project_id: i64) -> bool {
        let conn = self.conn.lock();
        conn.query_row("SELECT id FROM projects WHERE id = ?", params![project_id], |_| Ok(()))
            .optional()
            .unwrap()
            .is_some()
    }

    pub fn delete_project_by_id(&self, project_id: i64) {
        let conn = self.conn.lock();
        let project = Self::get_project_row(&conn, project_id);
        conn.execute("DELETE FROM documents WHERE project_id = ?", params![project_id]).unwrap();
        conn.execute("DELETE FROM steps WHERE project_id = ?", params![project_id]).unwrap();
        conn.execute("DELETE FROM overrides WHERE project_id = ?", params![project_id]).unwrap();
        conn.execute("DELETE FROM issues WHERE project_id = ?", params![project_id]).unwrap();
        conn.execute("DELETE FROM retained_sources WHERE project_id = ?", params![project_id]).unwrap();
        conn.execute("DELETE FROM projects WHERE id = ?", params![project_id]).unwrap();
        if let Some(p) = project {
            conn.execute("DELETE FROM file_scan_cache WHERE org = ? AND repo = ?", params![p.org, p.repo]).unwrap();
        }
    }

    /// Keeps only the newest scan of a repo: deletes every *older*
    /// headless-scan project (`source = 'api'`, i.e. what `validate-all`
    /// creates) for the same `(org, repo)` as the project with `job_id`,
    /// so org-wide sweeps that rescan hundreds of repos on a schedule don't
    /// grow the scan history without bound. Returns how many were deleted.
    ///
    /// Deliberately narrow: upload/onboard/interactive projects (they carry
    /// the shipped repo/PR provenance), still-`running` ones, and any with a
    /// retained source directory (the retention sweeper owns those) are
    /// never touched. Justifications and PR records survive: the old
    /// projects' `overrides` and `pull_requests` are re-pointed at the kept
    /// project first (carry-forward and the acknowledgments download read
    /// them by repo across projects, and `ON DELETE CASCADE` would
    /// otherwise silently drop them with the old rows). Audit events are
    /// not tied to a project row and are untouched. Cascades clean the
    /// rest (steps, documents, issues, scan_runs, evidence, ...).
    pub fn prune_superseded_scans(&self, keep_job_id: &str) -> usize {
        let mut conn = self.conn.lock();
        let Some((keep_id, org, repo)) = conn
            .query_row("SELECT id, org, repo FROM projects WHERE job_id = ?", params![keep_job_id], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)))
            .optional()
            .unwrap()
        else {
            return 0;
        };
        let Ok(tx) = conn.transaction() else { return 0 };
        let old_ids: Vec<i64> = {
            let mut stmt = tx
                .prepare(
                    "SELECT id FROM projects
                     WHERE lower(org) = lower(?1) AND lower(repo) = lower(?2) AND id < ?3
                       AND source = 'api' AND status != 'running'
                       AND id NOT IN (SELECT project_id FROM retained_sources)",
                )
                .unwrap();
            stmt.query_map(params![org, repo, keep_id], |row| row.get(0)).unwrap().filter_map(|r| r.ok()).collect()
        };
        for id in &old_ids {
            tx.execute("UPDATE overrides SET project_id = ?1 WHERE project_id = ?2", params![keep_id, id]).unwrap();
            tx.execute("UPDATE pull_requests SET project_id = ?1 WHERE project_id = ?2", params![keep_id, id]).unwrap();
            tx.execute("DELETE FROM projects WHERE id = ?", params![id]).unwrap();
        }
        let _ = tx.commit();
        old_ids.len()
    }

    pub fn delete_all_projects(&self) {
        let conn = self.conn.lock();
        conn.execute_batch(
            "DELETE FROM documents; DELETE FROM steps; DELETE FROM overrides; DELETE FROM issues; DELETE FROM retained_sources; DELETE FROM projects; DELETE FROM file_scan_cache;",
        )
        .unwrap();
    }

    pub fn get_document(&self, document_id: i64) -> Option<DocumentDownload> {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT kind, name, url, mime, data FROM documents WHERE id = ?",
            params![document_id],
            |row| {
                Ok(DocumentDownload {
                    kind: row.get(0)?,
                    name: row.get(1)?,
                    url: row.get(2)?,
                    mime: row.get(3)?,
                    data: row.get(4)?,
                })
            },
        )
        .optional()
        .unwrap()
    }

}
