//! Durable record of a run's "effectivatable" snapshot — the persisted
//! counterpart of `AppState::pending_effectivations`, which is process-local
//! and so lost its entries on every server restart. `impl DbStore` block, one
//! of several per-domain files (see `lib.rs`'s module list).

use crate::store::DbStore;
use rusqlite::{params, OptionalExtension};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingEffectivationRow {
    pub project_id: i64,
    pub org: String,
    pub repo: String,
    pub source_dir: String,
}

impl DbStore {
    /// Records (or replaces) the snapshot a later effectivate call may
    /// publish. `ttl_hours` may be negative (an already-expired row, for tests).
    pub fn save_pending_effectivation(&self, project_id: i64, org: &str, repo: &str, source_dir: &str, ttl_hours: i64) {
        let conn = self.conn.lock();
        if let Err(e) = conn.execute(
            "INSERT INTO pending_effectivations (project_id, org, repo, source_dir, created_at, expires_at) VALUES (?, ?, ?, ?, datetime('now'), datetime('now', ?))
             ON CONFLICT(project_id) DO UPDATE SET org = excluded.org, repo = excluded.repo, source_dir = excluded.source_dir, created_at = excluded.created_at, expires_at = excluded.expires_at",
            params![project_id, org, repo, source_dir, format!("{ttl_hours:+} hours")],
        ) {
            tracing::error!("save_pending_effectivation({project_id}) failed: {e}");
        }
    }

    /// `None` when there's no row or it has expired (compared in SQL, so the
    /// caller needs no clock of its own).
    pub fn get_pending_effectivation(&self, project_id: i64) -> Option<PendingEffectivationRow> {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT project_id, org, repo, source_dir FROM pending_effectivations WHERE project_id = ? AND expires_at > datetime('now')",
            params![project_id],
            |row| Ok(PendingEffectivationRow { project_id: row.get(0)?, org: row.get(1)?, repo: row.get(2)?, source_dir: row.get(3)? }),
        )
        .optional()
        .unwrap_or(None)
    }

    /// Deletes and returns every row whose TTL has passed, so the caller can
    /// remove the on-disk snapshot each one points at — without this a
    /// dry run nobody ever effectivates would leak its directory forever.
    pub fn take_expired_pending_effectivations(&self) -> Vec<PendingEffectivationRow> {
        let conn = self.conn.lock();
        let rows: Vec<PendingEffectivationRow> = match conn.prepare_cached("SELECT project_id, org, repo, source_dir FROM pending_effectivations WHERE expires_at <= datetime('now')") {
            Ok(mut stmt) => match stmt.query_map([], |row| Ok(PendingEffectivationRow { project_id: row.get(0)?, org: row.get(1)?, repo: row.get(2)?, source_dir: row.get(3)? })) {
                Ok(mapped) => mapped.filter_map(|r| r.ok()).collect(),
                Err(_) => vec![],
            },
            Err(_) => vec![],
        };
        if let Err(e) = conn.execute("DELETE FROM pending_effectivations WHERE expires_at <= datetime('now')", []) {
            tracing::error!("take_expired_pending_effectivations delete failed: {e}");
        }
        rows
    }

    pub fn delete_pending_effectivation(&self, project_id: i64) {
        let conn = self.conn.lock();
        if let Err(e) = conn.execute("DELETE FROM pending_effectivations WHERE project_id = ?", params![project_id]) {
            tracing::error!("delete_pending_effectivation({project_id}) failed: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_test_db() -> (DbStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = DbStore::open(&dir.path().join("test.db")).unwrap();
        (db, dir)
    }

    #[test]
    fn a_saved_pending_effectivation_reads_back_and_survives_reopening_the_db() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        {
            let db = DbStore::open(&path).unwrap();
            db.save_pending_effectivation(7, "acme", "widgets", "/data/retained/7", 24);
        }
        let reopened = DbStore::open(&path).unwrap();
        let row = reopened.get_pending_effectivation(7).expect("must survive a restart");
        assert_eq!(row, PendingEffectivationRow { project_id: 7, org: "acme".into(), repo: "widgets".into(), source_dir: "/data/retained/7".into() });
    }

    #[test]
    fn an_expired_pending_effectivation_reads_as_absent() {
        let (db, _dir) = open_test_db();
        db.save_pending_effectivation(1, "acme", "widgets", "/x", -1);
        assert!(db.get_pending_effectivation(1).is_none());
    }

    #[test]
    fn taking_expired_rows_returns_and_removes_only_the_expired_ones() {
        let (db, _dir) = open_test_db();
        db.save_pending_effectivation(1, "acme", "old", "/old", -1);
        db.save_pending_effectivation(2, "acme", "fresh", "/fresh", 24);
        let taken = db.take_expired_pending_effectivations();
        assert_eq!(taken.iter().map(|r| r.project_id).collect::<Vec<_>>(), vec![1]);
        assert!(db.take_expired_pending_effectivations().is_empty(), "already taken");
        assert!(db.get_pending_effectivation(2).is_some(), "a fresh row is untouched");
    }

    #[test]
    fn saving_again_replaces_and_delete_removes() {
        let (db, _dir) = open_test_db();
        db.save_pending_effectivation(1, "acme", "widgets", "/old", 24);
        db.save_pending_effectivation(1, "acme", "widgets", "/new", 24);
        assert_eq!(db.get_pending_effectivation(1).unwrap().source_dir, "/new");
        db.delete_pending_effectivation(1);
        assert!(db.get_pending_effectivation(1).is_none());
    }
}
