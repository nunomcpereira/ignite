//! SLA-breach queries backing `governance.sla` (see `ignite_config::SlaConfig`):
//! how many currently-open issues for a repo have sat unresolved longer
//! than their score bucket's allowed window, using `issue_first_seen`'s
//! per-(org,repo,issue_id) "first ever detected" timestamp.
//!
//! `impl DbStore` block — one of several per-domain files this crate's
//! accessor methods are split across (see `lib.rs`'s module list).

use crate::store::DbStore;
use crate::types::SlaBreachRow;
use ignite_override_engine::CRITICAL_SCORE_THRESHOLD;
use rusqlite::params;

impl DbStore {
    // ---------------- SLA tracking ----------------

    /// Count of open issues on `project_id` past their SLA window. Bucketed
    /// by `issues.score` (0-10): `>= CRITICAL_SCORE_THRESHOLD` is
    /// "critical" (the exact same threshold `override-engine`'s
    /// `is_critical_score`/dual-custody-approval gate uses — interpolated
    /// here rather than duplicated as a literal, so the two can't drift
    /// out of sync the way three independent copies of `9` used to be
    /// able to), `>=7` "high", else "medium" (also covers "low" —
    /// see `SlaConfig`'s own doc comment).
    pub fn count_sla_breaches(&self, org: &str, repo: &str, project_id: i64, critical_days: u32, high_days: u32, medium_days: u32) -> i64 {
        let conn = self.conn.lock();
        conn.query_row(
            &format!(
                "SELECT COUNT(*) FROM issues i
             JOIN issue_first_seen f ON f.org = ?1 AND f.repo = ?2 AND f.issue_id = i.issue_id
             WHERE i.project_id = ?3 AND i.status = 'open'
               AND (julianday('now') - julianday(f.first_detected_at)) > (
                 CASE
                   WHEN COALESCE(i.score, 0) >= {CRITICAL_SCORE_THRESHOLD} THEN ?4
                   WHEN COALESCE(i.score, 0) >= 7 THEN ?5
                   ELSE ?6
                 END
               )"
            ),
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
            .prepare_cached(&format!(
                "SELECT i.issue_id, i.category, i.severity, i.score, i.summary, i.file, i.line, f.first_detected_at,
                        CAST(julianday('now') - julianday(f.first_detected_at) AS INTEGER) AS days_open
                 FROM issues i
                 JOIN issue_first_seen f ON f.org = ?1 AND f.repo = ?2 AND f.issue_id = i.issue_id
                 WHERE i.project_id = ?3 AND i.status = 'open'
                   AND (julianday('now') - julianday(f.first_detected_at)) > (
                     CASE
                       WHEN COALESCE(i.score, 0) >= {CRITICAL_SCORE_THRESHOLD} THEN ?4
                       WHEN COALESCE(i.score, 0) >= 7 THEN ?5
                       ELSE ?6
                     END
                   )
                 ORDER BY days_open DESC"
            ))
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

#[cfg(test)]
mod tests {
    use crate::store::DbStore;
    use crate::types::IssueInput;
    use rusqlite::params;
    use std::collections::HashSet;

    fn open_test_db() -> (tempfile::TempDir, DbStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = DbStore::open(&dir.path().join("test.db")).unwrap();
        (dir, store)
    }

    fn backdate_first_seen(store: &DbStore, org: &str, repo: &str, issue_id: &str, days_ago: i64) {
        let conn = store.conn.lock();
        conn.execute(
            "UPDATE issue_first_seen SET first_detected_at = datetime('now', ?1) WHERE org = ?2 AND repo = ?3 AND issue_id = ?4",
            params![format!("-{days_ago} days"), org, repo, issue_id],
        )
        .unwrap();
    }

    fn issue(id: &str, score: i64) -> IssueInput {
        IssueInput {
            id: id.to_string(),
            phase: Some(4),
            category: "secret".to_string(),
            severity: "error".to_string(),
            score: Some(score),
            summary: "test finding".to_string(),
            file: Some("app.js".to_string()),
            line: Some(1),
            snippet: None,
            cross_file: false,
            chain: None,
            cwe: None,
            owasp: None,
            tool: None,
            references: None,
            duplicate_ref: None,
        }
    }

    /// A score of exactly `CRITICAL_SCORE_THRESHOLD` (9) must use the
    /// *critical* window (shortest), not the "high" window — verifies the
    /// SQL literal built via `format!` with the real constant actually
    /// lands as `>= 9`, not `> 9` (which would misclassify a score of
    /// exactly 9 as "high" and use the wrong, longer window).
    #[test]
    fn score_exactly_at_critical_threshold_uses_the_critical_window_not_high() {
        let (_dir, store) = open_test_db();
        let project_id = store.create_project("job-sla", "acme", "widgets", false, "ui", None).unwrap();
        store.replace_project_issues(project_id, &[issue("secret::app.js::1", ignite_override_engine::CRITICAL_SCORE_THRESHOLD as i64)], &HashSet::new());
        // 10 days old: past the critical window (critical_days=7) but
        // within the high window (high_days=30) — only breaches if this
        // score-9 issue is correctly bucketed as "critical", not "high".
        backdate_first_seen(&store, "acme", "widgets", "secret::app.js::1", 10);

        let breaches = store.count_sla_breaches("acme", "widgets", project_id, 7, 30, 90);
        assert_eq!(breaches, 1, "a score of exactly CRITICAL_SCORE_THRESHOLD must breach on the critical (shortest) window");

        let rows = store.list_sla_breaches("acme", "widgets", project_id, 7, 30, 90);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].issue_id, "secret::app.js::1");
    }

    #[test]
    fn score_just_below_critical_threshold_uses_the_high_window() {
        let (_dir, store) = open_test_db();
        let project_id = store.create_project("job-sla-2", "acme", "widgets", false, "ui", None).unwrap();
        store.replace_project_issues(project_id, &[issue("secret::app.js::2", (ignite_override_engine::CRITICAL_SCORE_THRESHOLD - 1) as i64)], &HashSet::new());
        // Same 10-day age as above, but score 8 (< threshold): must NOT
        // breach yet since 10 days hasn't crossed the high window (30).
        backdate_first_seen(&store, "acme", "widgets", "secret::app.js::2", 10);

        let breaches = store.count_sla_breaches("acme", "widgets", project_id, 7, 30, 90);
        assert_eq!(breaches, 0, "a score just below the critical threshold must use the longer high-tier window");
    }
}
