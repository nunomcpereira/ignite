//! Baseline/diff adoption mode: freeze a project's issue set as pre-existing.
//!
//! `impl DbStore` block — one of several per-domain files this crate's
//! accessor methods are split across (see `lib.rs`'s module list).

use crate::store::DbStore;
use rusqlite::params;
use std::collections::HashSet;

impl DbStore {
    // ---------------- baseline/diff adoption mode ----------------

    pub fn save_baseline(&self, org: &str, repo: &str, issue_ids: &[String]) -> usize {
        let mut conn = self.conn.lock();
        let tx = conn.transaction().unwrap();
        tx.execute("DELETE FROM issue_baselines WHERE org = ? AND repo = ?", params![org, repo]).unwrap();
        for id in issue_ids {
            tx.execute("INSERT OR IGNORE INTO issue_baselines (org, repo, issue_id) VALUES (?, ?, ?)", params![org, repo, id]).unwrap();
        }
        tx.commit().unwrap();
        issue_ids.len()
    }

    pub fn clear_baseline(&self, org: &str, repo: &str) -> usize {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM issue_baselines WHERE org = ? AND repo = ?", params![org, repo]).unwrap()
    }

    pub fn get_baseline_issue_ids(&self, org: &str, repo: &str) -> HashSet<String> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached("SELECT issue_id FROM issue_baselines WHERE org = ? AND repo = ?").unwrap();
        stmt.query_map(params![org, repo], |row| row.get(0)).unwrap().map(|r: rusqlite::Result<String>| r.unwrap()).collect()
    }

}
