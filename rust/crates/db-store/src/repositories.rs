//! US-01: durable `Repository`/`SourceSnapshot`/`ScanRun` identity, kept
//! live alongside every `projects` row from here on (historical rows are
//! covered instead by `schema::BACKFILL_REPOSITORY_MODEL_SQL`, run at
//! every `DbStore::open`). `projects.rs`'s `create_project`/`finish_project`
//! call into this module so every future scan gets a normalized
//! repository/snapshot/scan-run row for free, with no change to their own
//! callers or to the `jobId`/`projectId` URLs every existing consumer
//! already relies on.

use crate::store::DbStore;
use crate::types::{RepositoryRow, ScanRunRow};
use rusqlite::{params, Connection, OptionalExtension};

impl DbStore {
    /// Resolves `(org, repo[, github_repo_id])` to one durable repository
    /// id. `github_repo_id`, when known, is the authoritative identity —
    /// a repo renamed on GitHub keeps the same row (its `org`/`repo`
    /// columns are updated in place, preserving every prior scan/issue
    /// association keyed off `repository_id`) instead of silently forking
    /// into a second repository. Without a `github_repo_id` (the common
    /// case for an uploaded ZIP that was never linked to GitHub), matching
    /// falls back to normalized `org`/`repo` equality — two different
    /// orgs with the same repo short name never collide, since the unique
    /// index is on the `(org, repo)` pair, not `repo` alone.
    pub fn resolve_repository(&self, org: &str, repo: &str, github_repo_id: Option<&str>) -> i64 {
        let conn = self.conn.lock();
        Self::resolve_repository_inner(&conn, org, repo, github_repo_id)
    }

    fn resolve_repository_inner(conn: &Connection, org: &str, repo: &str, github_repo_id: Option<&str>) -> i64 {
        if let Some(gid) = github_repo_id {
            if let Some(id) = conn.query_row("SELECT id FROM repositories WHERE github_repo_id = ?", params![gid], |r| r.get::<_, i64>(0)).optional().unwrap_or(None) {
                if let Err(e) = conn.execute("UPDATE repositories SET org = ?, repo = ? WHERE id = ?", params![org, repo, id]) {
                    // A different pre-existing repository already occupies the
                    // target (org, repo) pair (e.g. a name swap) — keep the
                    // github_repo_id-matched row's existing org/repo rather
                    // than fail resolution outright.
                    tracing::warn!("resolve_repository: rename update for repository {id} to {org}/{repo} skipped: {e}");
                }
                return id;
            }
        }
        if let Some(id) = conn.query_row("SELECT id FROM repositories WHERE org = ? AND repo = ?", params![org, repo], |r| r.get::<_, i64>(0)).optional().unwrap_or(None) {
            if let Some(gid) = github_repo_id {
                if let Err(e) = conn.execute("UPDATE repositories SET github_repo_id = ? WHERE id = ? AND github_repo_id IS NULL", params![gid, id]) {
                    tracing::warn!("resolve_repository: linking github_repo_id for repository {id} skipped: {e}");
                }
            }
            return id;
        }
        conn.execute("INSERT INTO repositories (org, repo, github_repo_id) VALUES (?, ?, ?)", params![org, repo, github_repo_id]).unwrap();
        conn.last_insert_rowid()
    }

    /// Creates (or reuses, if this exact digest was already seen for this
    /// repository) a source snapshot, returning its id.
    pub fn create_or_reuse_snapshot(&self, repository_id: i64, source_digest: &str, commit_sha: Option<&str>, storage_ref: Option<&str>) -> i64 {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO source_snapshots (repository_id, source_digest, commit_sha, storage_ref)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(repository_id, source_digest)
             DO UPDATE SET commit_sha = COALESCE(excluded.commit_sha, source_snapshots.commit_sha),
                           storage_ref = COALESCE(excluded.storage_ref, source_snapshots.storage_ref)",
            params![repository_id, source_digest, commit_sha, storage_ref],
        )
        .unwrap();
        conn.query_row("SELECT id FROM source_snapshots WHERE repository_id = ? AND source_digest = ?", params![repository_id, source_digest], |r| r.get(0)).unwrap()
    }

    /// Records a scan run tied 1:1 to a legacy `projects.id` row — the
    /// compatibility mapping this backlog requires: every existing
    /// `jobId`/`projectId` URL keeps resolving through `projects` exactly
    /// as before, while `scan_runs.legacy_project_id` lets new code walk
    /// from a project to its normalized repository/snapshot.
    pub fn record_scan_run(&self, legacy_project_id: i64, repository_id: i64, snapshot_id: i64, source_channel: &str, is_enrollment_only: bool) -> i64 {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO scan_runs (legacy_project_id, repository_id, snapshot_id, source_channel, lifecycle_state, is_enrollment_only)
             VALUES (?, ?, ?, ?, 'queued', ?)
             ON CONFLICT(legacy_project_id) DO NOTHING",
            params![legacy_project_id, repository_id, snapshot_id, source_channel, is_enrollment_only as i64],
        )
        .unwrap();
        conn.query_row("SELECT id FROM scan_runs WHERE legacy_project_id = ?", params![legacy_project_id], |r| r.get(0)).unwrap()
    }

    /// Maps a `projects.status` transition onto `scan_runs.lifecycle_state`
    /// — called from `finish_project`/`set_project_status` so the
    /// normalized run's lifecycle never drifts from the legacy row's own
    /// status. Unrecognized/custom statuses map to `completed` rather than
    /// panicking, since `projects.status` is a free-form `TEXT` column.
    pub fn sync_scan_run_lifecycle(&self, legacy_project_id: i64, project_status: &str, finished: bool) {
        let lifecycle = match project_status {
            "success" => "published",
            "failed" => "failed",
            "enrolled" => "completed",
            "running" => "scanning",
            _ => "completed",
        };
        let conn = self.conn.lock();
        if finished {
            if let Err(e) = conn.execute("UPDATE scan_runs SET lifecycle_state = ?, finished_at = datetime('now') WHERE legacy_project_id = ?", params![lifecycle, legacy_project_id]) {
                tracing::error!("sync_scan_run_lifecycle({legacy_project_id}) failed: {e}");
            }
        } else if let Err(e) = conn.execute("UPDATE scan_runs SET lifecycle_state = ? WHERE legacy_project_id = ?", params![lifecycle, legacy_project_id]) {
            tracing::error!("sync_scan_run_lifecycle({legacy_project_id}) failed: {e}");
        }
    }

    pub fn get_repository_by_org_repo(&self, org: &str, repo: &str) -> Option<RepositoryRow> {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT id, org, repo, github_repo_id, access_scope, created_at FROM repositories WHERE org = ? AND repo = ?",
            params![org, repo],
            |row| Ok(RepositoryRow { id: row.get(0)?, org: row.get(1)?, repo: row.get(2)?, github_repo_id: row.get(3)?, access_scope: row.get(4)?, created_at: row.get(5)? }),
        )
        .optional()
        .unwrap()
    }

    /// Every scan run for a repository, newest first — the durable,
    /// repository-scoped history this story exists to provide (as opposed
    /// to `list_projects`'s flat, unscoped list of every project ever
    /// run). Enrollment-only rows are included with `is_enrollment_only`
    /// set so callers can filter them out of "actual scan" views.
    pub fn list_scan_runs_for_repository(&self, repository_id: i64) -> Vec<ScanRunRow> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare_cached(
                "SELECT sr.id, sr.legacy_project_id, sr.repository_id, sr.snapshot_id, sr.initiator, sr.source_channel,
                        sr.policy_version, sr.lifecycle_state, sr.is_enrollment_only, sr.created_at, sr.finished_at,
                        p.job_id
                 FROM scan_runs sr LEFT JOIN projects p ON p.id = sr.legacy_project_id
                 WHERE sr.repository_id = ? ORDER BY sr.id DESC",
            )
            .unwrap();
        stmt.query_map(params![repository_id], |row| {
            Ok(ScanRunRow {
                id: row.get(0)?,
                legacy_project_id: row.get(1)?,
                repository_id: row.get(2)?,
                snapshot_id: row.get(3)?,
                initiator: row.get(4)?,
                source_channel: row.get(5)?,
                policy_version: row.get(6)?,
                lifecycle_state: row.get(7)?,
                is_enrollment_only: row.get::<_, i64>(8)? != 0,
                created_at: row.get(9)?,
                finished_at: row.get(10)?,
                legacy_job_id: row.get(11)?,
            })
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
    }

    /// Resolves a legacy `job_id`/`project_id` straight to its scan run —
    /// the "historical URLs still resolve" half of the compatibility
    /// mapping, from the run side rather than the project side.
    pub fn get_scan_run_for_legacy_project(&self, legacy_project_id: i64) -> Option<ScanRunRow> {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT sr.id, sr.legacy_project_id, sr.repository_id, sr.snapshot_id, sr.initiator, sr.source_channel,
                    sr.policy_version, sr.lifecycle_state, sr.is_enrollment_only, sr.created_at, sr.finished_at,
                    p.job_id
             FROM scan_runs sr LEFT JOIN projects p ON p.id = sr.legacy_project_id
             WHERE sr.legacy_project_id = ?",
            params![legacy_project_id],
            |row| {
                Ok(ScanRunRow {
                    id: row.get(0)?,
                    legacy_project_id: row.get(1)?,
                    repository_id: row.get(2)?,
                    snapshot_id: row.get(3)?,
                    initiator: row.get(4)?,
                    source_channel: row.get(5)?,
                    policy_version: row.get(6)?,
                    lifecycle_state: row.get(7)?,
                    is_enrollment_only: row.get::<_, i64>(8)? != 0,
                    created_at: row.get(9)?,
                    finished_at: row.get(10)?,
                    legacy_job_id: row.get(11)?,
                })
            },
        )
        .optional()
        .unwrap()
    }
}
