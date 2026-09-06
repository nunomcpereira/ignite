//! Retained-source-directory bookkeeping (Ignite Studio's post-scan 'kept' window).
//!
//! `impl DbStore` block — one of several per-domain files this crate's
//! accessor methods are split across (see `lib.rs`'s module list).

use crate::store::DbStore;
use crate::types::*;
use rusqlite::{params, OptionalExtension};

impl DbStore {
    // ---------------- retained sources ----------------

    pub fn retain_project_source(&self, project_id: i64, dir_path: &str, tier: &str) {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO retained_sources (project_id, dir_path, retained_at, tier) VALUES (?, ?, datetime('now'), ?)
             ON CONFLICT(project_id) DO UPDATE SET dir_path = excluded.dir_path, retained_at = excluded.retained_at, tier = excluded.tier",
            params![project_id, dir_path, tier],
        )
        .unwrap();
    }

    pub fn set_retained_source_tier(&self, project_id: i64, tier: &str) {
        let conn = self.conn.lock();
        conn.execute("UPDATE retained_sources SET tier = ? WHERE project_id = ?", params![tier, project_id]).unwrap();
    }

    pub fn get_retained_source(&self, project_id: i64) -> Option<String> {
        let conn = self.conn.lock();
        conn.query_row("SELECT dir_path FROM retained_sources WHERE project_id = ?", params![project_id], |row| row.get(0))
            .optional()
            .unwrap()
    }

    pub fn list_retained_sources(&self) -> Vec<RetainedSourceRow> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached("SELECT project_id, dir_path, tier FROM retained_sources ORDER BY retained_at DESC").unwrap();
        stmt.query_map([], |row| Ok(RetainedSourceRow { project_id: row.get(0)?, dir_path: row.get(1)?, tier: row.get(2)? }))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    /// Rows beyond the `keep` most recently retained — the caller fs::remove's
    /// each dir_path, then calls delete_retained_source for each project_id.
    pub fn list_evictable_retained_sources(&self, keep: i64) -> Vec<RetainedSourceRow> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare_cached("SELECT project_id, dir_path, tier FROM retained_sources ORDER BY retained_at DESC LIMIT -1 OFFSET ?")
            .unwrap();
        stmt.query_map(params![keep], |row| Ok(RetainedSourceRow { project_id: row.get(0)?, dir_path: row.get(1)?, tier: row.get(2)? }))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    pub fn delete_retained_source(&self, project_id: i64) {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM retained_sources WHERE project_id = ?", params![project_id]).unwrap();
    }

    pub fn set_project_commit_shas(&self, project_id: i64, source_commit_sha: Option<&str>, shipped_commit_sha: Option<&str>) {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE projects SET source_commit_sha = COALESCE(?, source_commit_sha), shipped_commit_sha = COALESCE(?, shipped_commit_sha) WHERE id = ?",
            params![source_commit_sha, shipped_commit_sha, project_id],
        )
        .unwrap();
    }

}
