//! SLA-breach queries backing `governance.sla` (see `ignite_config::SlaConfig`):
//! how many currently-open issues for a repo have sat unresolved longer
//! than their score bucket's allowed window, using `issue_first_seen`'s
//! per-(org,repo,issue_id) "first ever detected" timestamp.
//!
//! `impl DbStore` block — one of several per-domain files this crate's
//! accessor methods are split across (see `lib.rs`'s module list).

use crate::store::DbStore;
use crate::types::SlaBreachRow;
use rusqlite::params;

impl DbStore {
    // ---------------- SLA tracking ----------------

    /// Count of open issues on `project_id` past their SLA window. Bucketed
    /// by `issues.score` (0-10): >=9 is "critical", >=7 "high", else
    /// "medium" (also covers "low" — see `SlaConfig`'s own doc comment).
    pub fn count_sla_breaches(&self, org: &str, repo: &str, project_id: i64, critical_days: u32, high_days: u32, medium_days: u32) -> i64 {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT COUNT(*) FROM issues i
             JOIN issue_first_seen f ON f.org = ?1 AND f.repo = ?2 AND f.issue_id = i.issue_id
             WHERE i.project_id = ?3 AND i.status = 'open'
               AND (julianday('now') - julianday(f.first_detected_at)) > (
                 CASE
                   WHEN COALESCE(i.score, 0) >= 9 THEN ?4
                   WHEN COALESCE(i.score, 0) >= 7 THEN ?5
                   ELSE ?6
                 END
               )",
            params![org, repo, project_id, critical_days, high_days, medium_days],
            |row| row.get(0),
        )
        .unwrap()
    }

    /// Full breach detail (not just the count) for a repo's latest scan —
    /// used by `scheduled-rescan` to decide whether to fail even a
    /// clean-findings run, and by the UI to list which issues are overdue.
    pub fn list_sla_breaches(&self, org: &str, repo: &str, project_id: i64, critical_days: u32, high_days: u32, medium_days: u32) -> Vec<SlaBreachRow> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare_cached(
                "SELECT i.issue_id, i.category, i.severity, i.score, i.summary, i.file, i.line, f.first_detected_at,
                        CAST(julianday('now') - julianday(f.first_detected_at) AS INTEGER) AS days_open
                 FROM issues i
                 JOIN issue_first_seen f ON f.org = ?1 AND f.repo = ?2 AND f.issue_id = i.issue_id
                 WHERE i.project_id = ?3 AND i.status = 'open'
                   AND (julianday('now') - julianday(f.first_detected_at)) > (
                     CASE
                       WHEN COALESCE(i.score, 0) >= 9 THEN ?4
                       WHEN COALESCE(i.score, 0) >= 7 THEN ?5
                       ELSE ?6
                     END
                   )
                 ORDER BY days_open DESC",
            )
            .unwrap();
        stmt.query_map(params![org, repo, project_id, critical_days, high_days, medium_days], |row| {
            Ok(SlaBreachRow {
                issue_id: row.get(0)?,
                category: row.get(1)?,
                severity: row.get(2)?,
                score: row.get(3)?,
                summary: row.get(4)?,
                file: row.get(5)?,
                line: row.get(6)?,
                first_detected_at: row.get(7)?,
                days_open: row.get(8)?,
            })
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
    }
}
