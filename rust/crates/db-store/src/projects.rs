//! Project/step/document CRUD — the core `projects`/`steps`/`documents` tables.
//!
//! `impl DbStore` block — one of several per-domain files this crate's
//! accessor methods are split across (see `lib.rs`'s module list).

use crate::store::DbStore;
use crate::types::*;
use rusqlite::{params, Connection, OptionalExtension};

impl DbStore {
    // ---------------- projects / steps / documents ----------------

    pub fn create_project(
        &self,
        job_id: &str,
        org: &str,
        repo: &str,
        is_gxp: bool,
        source: &str,
        scan_location: Option<&str>,
    ) -> i64 {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO projects (job_id, org, repo, gxp, source, scan_location) VALUES (?, ?, ?, ?, ?, ?)",
            params![job_id, org, repo, is_gxp as i64, source, scan_location],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    pub fn finish_project(&self, status: &str, error: Option<&str>, repo_url: Option<&str>, pr_url: Option<&str>, project_id: i64) {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE projects SET status = ?, error = ?, repo_url = ?, pr_url = ?, finished_at = datetime('now') WHERE id = ?",
            params![status, error, repo_url, pr_url, project_id],
        )
        .unwrap();
        if let Some(url) = pr_url {
            conn.execute("INSERT INTO pull_requests (project_id, kind, url) VALUES (?, 'onboarding', ?)", params![project_id, url]).unwrap();
        }
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
    pub fn list_onboarded_repo_summaries(&self) -> Vec<OnboardedRepoSummary> {
        let conn = self.conn.lock();

        let mut latest_stmt = conn
            .prepare_cached(
                "SELECT p.id, p.job_id, p.org, p.repo, p.status, COALESCE(p.finished_at, p.created_at) AS last_scan_at, p.repo_url
                 FROM projects p
                 INNER JOIN (SELECT org, repo, MAX(id) AS max_id FROM projects GROUP BY org, repo) latest
                   ON p.org = latest.org AND p.repo = latest.repo AND p.id = latest.max_id
                 ORDER BY last_scan_at DESC",
            )
            .unwrap();
        struct Latest {
            id: i64,
            job_id: String,
            org: String,
            repo: String,
            status: String,
            last_scan_at: String,
            repo_url: Option<String>,
        }
        let latest_rows: Vec<Latest> = latest_stmt
            .query_map([], |row| Ok(Latest { id: row.get(0)?, job_id: row.get(1)?, org: row.get(2)?, repo: row.get(3)?, status: row.get(4)?, last_scan_at: row.get(5)?, repo_url: row.get(6)? }))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();

        let mut count_stmt = conn.prepare_cached("SELECT COUNT(*) FROM issues WHERE project_id = ?1 AND status = 'open' AND (?2 IS NULL OR category = ?2)").unwrap();
        let mut acks_stmt = conn
            .prepare_cached(
                "SELECT o.id, o.phase, o.issue_id, o.category, o.severity, o.summary, o.file, o.line, o.justification,
                        o.actor_email, o.actor_name, o.email_sent, o.created_at
                 FROM overrides o INNER JOIN projects p ON o.project_id = p.id
                 WHERE p.org = ? AND p.repo = ? ORDER BY o.created_at DESC",
            )
            .unwrap();
        let mut prs_stmt = conn
            .prepare_cached(
                "SELECT pr.kind, pr.url, pr.branch, pr.files_changed, pr.created_at
                 FROM pull_requests pr INNER JOIN projects p ON pr.project_id = p.id
                 WHERE p.org = ? AND p.repo = ? ORDER BY pr.created_at DESC LIMIT 20",
            )
            .unwrap();

        latest_rows
            .into_iter()
            .map(|latest| {
                let findings_count: i64 = count_stmt.query_row(params![latest.id, Option::<&str>::None], |row| row.get(0)).unwrap();
                let license_problems: i64 = count_stmt.query_row(params![latest.id, Some("license-compliance")], |row| row.get(0)).unwrap();
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
                    .unwrap()
                    .map(|r| r.unwrap())
                    .collect();
                let recent_prs = prs_stmt
                    .query_map(params![latest.org, latest.repo], |row| Ok(PullRequestRow { kind: row.get(0)?, url: row.get(1)?, branch: row.get(2)?, files_changed: row.get(3)?, created_at: row.get(4)? }))
                    .unwrap()
                    .map(|r| r.unwrap())
                    .collect();

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

        let mut steps_stmt = conn.prepare_cached("SELECT phase, title, state, logs FROM steps WHERE project_id = ? ORDER BY phase").unwrap();
        let steps = steps_stmt
            .query_map(params![project_id], |row| {
                Ok(Step { phase: row.get(0)?, title: row.get(1)?, state: row.get(2)?, logs: row.get(3)? })
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
