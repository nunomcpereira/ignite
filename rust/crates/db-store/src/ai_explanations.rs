//! Cached AI-generated issue explanations, plus stale-run cleanup.
//!
//! `impl DbStore` block — one of several per-domain files this crate's
//! accessor methods are split across (see `lib.rs`'s module list).

use crate::store::DbStore;
use rusqlite::{params, OptionalExtension};

impl DbStore {
    // ---------------- cached AI explanations ----------------

    pub fn get_cached_issue_explanation(&self, hash: &str) -> Option<String> {
        let conn = self.conn.lock();
        conn.query_row("SELECT explanation FROM issue_explanations WHERE hash = ?", params![hash], |row| row.get(0))
            .optional()
            .unwrap()
    }

    pub fn cache_issue_explanation(&self, hash: &str, explanation: &str) {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO issue_explanations (hash, explanation) VALUES (?, ?)
             ON CONFLICT(hash) DO UPDATE SET explanation = excluded.explanation",
            params![hash, explanation],
        )
        .unwrap();
    }

    /// Projects/steps left in 'running' happen only when the process died
    /// mid-pipeline — nothing will ever finish them, so on every startup
    /// we sweep them into a terminal 'aborted' state instead of leaving
    /// stale spinners in the history panel forever.
    pub fn abort_stale_running_projects(&self) {
        const ABORTED_ERROR: &str = "Server restarted while onboarding was still in progress.";
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE projects SET status = 'aborted', error = COALESCE(error, ?1), finished_at = datetime('now') WHERE status = 'running'",
            params![ABORTED_ERROR],
        )
        .unwrap();
        conn.execute(
            "UPDATE steps SET state = 'failed', logs = logs || char(10) || '✗ ' || ?1
             WHERE state = 'running' AND project_id IN (SELECT id FROM projects WHERE error = ?1)",
            params![ABORTED_ERROR],
        )
        .unwrap();
    }

}
