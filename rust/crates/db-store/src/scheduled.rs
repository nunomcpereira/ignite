//! Scheduled re-check bookkeeping for effectivated projects.
//!
//! `impl DbStore` block — one of several per-domain files this crate's
//! accessor methods are split across (see `lib.rs`'s module list).

use crate::store::DbStore;
use crate::types::*;
use rusqlite::params;

impl DbStore {
    // ---------------- scheduled re-checks ----------------

    /// "Effectivated" = actually shipped: a successful run that pushed to
    /// a real repo_url, as opposed to a dry run or a validate-all/onboard
    /// call that only ever ran checks.
    pub fn list_effectivated_projects(&self) -> Vec<EffectivatedProject> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare_cached(
                "SELECT id, org, repo, repo_url, created_at,
                        schedule_enabled, schedule_interval, next_scheduled_run_at,
                        last_scheduled_run_at, last_scheduled_status, last_scheduled_error
                 FROM projects WHERE status = 'success' AND repo_url IS NOT NULL ORDER BY id DESC",
            )
            .unwrap();
        stmt.query_map([], |row| {
            Ok(EffectivatedProject {
                id: row.get(0)?,
                org: row.get(1)?,
                repo: row.get(2)?,
                repo_url: row.get(3)?,
                created_at: row.get(4)?,
                schedule_enabled: row.get::<_, i64>(5)? != 0,
                schedule_interval: row.get(6)?,
                next_scheduled_run_at: row.get(7)?,
                last_scheduled_run_at: row.get(8)?,
                last_scheduled_status: row.get(9)?,
                last_scheduled_error: row.get(10)?,
            })
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
    }

    pub fn set_project_schedule(&self, project_id: i64, enabled: bool, interval: Option<&str>, next_run_at_iso: Option<&str>) {
        let conn = self.conn.lock();
        let next = if enabled { next_run_at_iso } else { None };
        conn.execute(
            "UPDATE projects SET schedule_enabled = ?, schedule_interval = ?, next_scheduled_run_at = ? WHERE id = ?",
            params![enabled as i64, interval, next, project_id],
        )
        .unwrap();
    }

    pub fn get_due_scheduled_projects(&self, now_iso: &str) -> Vec<DueScheduledProject> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare_cached("SELECT id, org, repo, repo_url, schedule_interval FROM projects WHERE schedule_enabled = 1 AND repo_url IS NOT NULL AND next_scheduled_run_at <= ?")
            .unwrap();
        stmt.query_map(params![now_iso], |row| {
            Ok(DueScheduledProject { id: row.get(0)?, org: row.get(1)?, repo: row.get(2)?, repo_url: row.get(3)?, schedule_interval: row.get(4)? })
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
    }

    pub fn record_scheduled_run_result(&self, project_id: i64, status: &str, error: Option<&str>, next_run_at_iso: Option<&str>) {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE projects SET last_scheduled_run_at = datetime('now'), last_scheduled_status = ?, last_scheduled_error = ?, next_scheduled_run_at = ? WHERE id = ?",
            params![status, error, next_run_at_iso, project_id],
        )
        .unwrap();
    }

}
