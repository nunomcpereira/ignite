//! Dependency-scan result cache and fix-PR preview job storage.
//!
//! `impl DbStore` block — one of several per-domain files this crate's
//! accessor methods are split across (see `lib.rs`'s module list).

use crate::store::DbStore;
use crate::types::*;
use rusqlite::{params, OptionalExtension};

impl DbStore {
    // ---------------- dependency scan cache ----------------

    /// Persists a dependency license scan result (the full
    /// `DependencyLicenseScan` serialized as JSON) for a project, so the
    /// Studio Dependencies tab can read it back instantly instead of
    /// re-running ORT + deps.dev from scratch.
    pub fn save_dependency_scan_cache(&self, project_id: i64, scan_json: &serde_json::Value) {
        let conn = self.conn.lock();
        let json_str = serde_json::to_string(scan_json).unwrap_or_default();
        conn.execute(
            "INSERT INTO dependency_scan_cache (project_id, scan_json) VALUES (?, ?)
             ON CONFLICT(project_id) DO UPDATE SET scan_json = excluded.scan_json, created_at = datetime('now')",
            params![project_id, json_str],
        )
        .unwrap();
    }

    /// Retrieves a cached dependency license scan result for a project.
    /// Returns `None` if no cached result exists (e.g. the scan hasn't
    /// run yet, or the project was created before caching was added).
    pub fn get_dependency_scan_cache(&self, project_id: i64) -> Option<serde_json::Value> {
        let conn = self.conn.lock();
        let result = conn.prepare_cached("SELECT scan_json FROM dependency_scan_cache WHERE project_id = ?")
            .unwrap()
            .query_row(params![project_id], |row| {
                let json_str: String = row.get(0)?;
                Ok(serde_json::from_str(&json_str).unwrap_or(serde_json::Value::Null))
            })
            .optional()
            .unwrap()
            .filter(|v| !v.is_null());
        result
    }

    /// Persists (insert-or-replace) a finished/cancelled fix-PR preview
    /// job — deliberately only ever called once the job has reached a
    /// terminal state, never mid-run: generating these candidates is one
    /// LLM call per open issue and can take real wall-clock time, so a
    /// completed result is worth surviving a server restart, but a
    /// still-running job is not resumable after one (the `tokio` task
    /// that was computing it is simply gone) — persisting a "still
    /// running" row would just leave a stale, misleading entry forever.
    /// `candidates` is stored as opaque JSON (this crate stays decoupled
    /// from `ignite-fix-pr`, like every other check crate); the caller
    /// (`routes/fix_pr.rs`) owns the typed `FixCandidate` shape.
    pub fn save_fix_pr_preview(&self, params: &crate::types::SaveFixPrPreviewParams<'_>) {
        let conn = self.conn.lock();
        let candidates_json = serde_json::to_string(params.candidates).unwrap_or_else(|_| "[]".to_string());
        conn.execute(
            "INSERT INTO fix_pr_previews (job_id, total, completed, done, cancelled, considered_count, reason, candidates_json, updated_at)
             VALUES (?, ?, ?, 1, ?, ?, ?, ?, datetime('now'))
             ON CONFLICT(job_id) DO UPDATE SET total = excluded.total, completed = excluded.completed, done = 1,
                 cancelled = excluded.cancelled, considered_count = excluded.considered_count,
                 reason = excluded.reason, candidates_json = excluded.candidates_json, updated_at = datetime('now')",
            rusqlite::params![params.job_id, params.total, params.completed, params.cancelled as i64, params.considered_count, params.reason, candidates_json],
        )
        .unwrap();
    }

    /// Retrieves a previously-finished fix-PR preview job (see
    /// [`Self::save_fix_pr_preview`]) — `None` if this job id was never
    /// saved (still running, never started, or a `job_id` from before
    /// this table existed).
    pub fn get_fix_pr_preview(&self, job_id: &str) -> Option<FixPrPreviewRow> {
        let conn = self.conn.lock();
        let result = conn
            .prepare_cached("SELECT total, completed, cancelled, considered_count, reason, candidates_json FROM fix_pr_previews WHERE job_id = ?")
            .unwrap()
            .query_row(params![job_id], |row| {
                let candidates_json: String = row.get(5)?;
                Ok(FixPrPreviewRow {
                    total: row.get(0)?,
                    completed: row.get(1)?,
                    cancelled: row.get::<_, i64>(2)? != 0,
                    considered_count: row.get(3)?,
                    reason: row.get(4)?,
                    candidates: serde_json::from_str(&candidates_json).unwrap_or(serde_json::Value::Array(vec![])),
                })
            })
            .optional()
            .unwrap();
        result
    }
}
