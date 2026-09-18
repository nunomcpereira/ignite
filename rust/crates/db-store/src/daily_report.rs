//! Read model behind the org-level daily findings digest
//! (`routes/daily_report.rs`): every repo's most recent scan plus the
//! findings on it that nobody has justified yet.
//!
//! `impl DbStore` block — one of several per-domain files this crate's
//! accessor methods are split across (see `lib.rs`'s module list).

use crate::store::DbStore;
use crate::types::IssueRow;

/// One repo's latest scan for the daily report. `unjustified` is that
/// scan's `status = 'open'` issues — anything an approved override (or a
/// carried-forward/AI-assist justification) already covers is
/// `status = 'overridden'` and excluded. Sorted highest score first.
#[derive(Debug, Clone)]
pub struct RepoDailyReport {
    pub org: String,
    pub repo: String,
    pub project_id: i64,
    pub status: String,
    pub last_scan_at: String,
    pub unjustified: Vec<IssueRow>,
}

impl DbStore {
    // ---------------- daily report ----------------

    /// Latest scan per `(org, repo)` (same "highest project id wins"
    /// rule as `list_onboarded_repo_summaries`), each with its unjustified
    /// findings, ordered by org then repo. `org` narrows to one org when
    /// given. Enrollment-only rows (a `repository.created` webhook that
    /// never got scanned) are included with an empty finding list rather
    /// than dropped — "all repos" means a repo nobody has scanned yet is
    /// worth a line in the report too.
    pub fn list_latest_scan_unjustified_findings(&self, org: Option<&str>) -> Vec<RepoDailyReport> {
        struct Latest {
            id: i64,
            org: String,
            repo: String,
            status: String,
            last_scan_at: String,
        }
        // Collected in its own scope so the connection lock is released
        // before `get_project_issues` takes it again below.
        let latest: Vec<Latest> = {
            let conn = self.conn.lock();
            let Ok(mut stmt) = conn.prepare_cached(
                "SELECT p.id, p.org, p.repo, p.status, COALESCE(p.finished_at, p.created_at)
                 FROM projects p
                 INNER JOIN (SELECT org, repo, MAX(id) AS max_id FROM projects GROUP BY org, repo) latest
                   ON p.org = latest.org AND p.repo = latest.repo AND p.id = latest.max_id
                 WHERE (?1 IS NULL OR p.org = ?1)
                 ORDER BY p.org, p.repo",
            ) else {
                return vec![];
            };
            let Ok(rows) = stmt.query_map(rusqlite::params![org], |row| Ok(Latest { id: row.get(0)?, org: row.get(1)?, repo: row.get(2)?, status: row.get(3)?, last_scan_at: row.get(4)? })) else {
                return vec![];
            };
            rows.filter_map(|r| r.ok()).collect()
        };
        latest
            .into_iter()
            .map(|l| {
                let mut unjustified: Vec<IssueRow> = self.get_project_issues(l.id).into_iter().filter(|i| i.status == "open").collect();
                unjustified.sort_by(|a, b| b.score.unwrap_or(0).cmp(&a.score.unwrap_or(0)).then_with(|| a.file.cmp(&b.file)).then_with(|| a.line.cmp(&b.line)));
                RepoDailyReport { org: l.org, repo: l.repo, project_id: l.id, status: l.status, last_scan_at: l.last_scan_at, unjustified }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::IssueInput;
    use std::collections::HashSet;

    fn issue(id: &str, score: i64) -> IssueInput {
        IssueInput { id: id.into(), phase: Some(4), category: "secret".into(), severity: "error".into(), score: Some(score), summary: format!("finding {id}"), file: Some("a.rs".into()), line: Some(1), snippet: None, cross_file: false, chain: None, cwe: None, owasp: None, tool: None, references: None, duplicate_ref: None }
    }

    fn open_db() -> (tempfile::TempDir, DbStore) {
        let dir = tempfile::tempdir().unwrap();
        let db = DbStore::open(&dir.path().join("test.db")).unwrap();
        (dir, db)
    }

    #[test]
    fn only_latest_scan_and_only_open_findings_are_reported() {
        let (_dir, db) = open_db();
        let old = db.create_project("job-old", "acme", "widgets", false, "ui", None).unwrap();
        db.replace_project_issues(old, &[issue("stale::a.rs::1", 9)], &HashSet::new());
        let new = db.create_project("job-new", "acme", "widgets", false, "ui", None).unwrap();
        let justified: HashSet<String> = ["b::a.rs::1".to_string()].into();
        db.replace_project_issues(new, &[issue("low::a.rs::1", 3), issue("b::a.rs::1", 8), issue("high::a.rs::1", 9)], &justified);

        let reports = db.list_latest_scan_unjustified_findings(None);
        assert_eq!(reports.len(), 1);
        let ids: Vec<&str> = reports[0].unjustified.iter().map(|i| i.id.as_str()).collect();
        assert_eq!(ids, vec!["high::a.rs::1", "low::a.rs::1"], "justified + older-scan findings excluded, highest score first");
    }

    #[test]
    fn org_filter_and_clean_repos_are_handled() {
        let (_dir, db) = open_db();
        db.create_project("job-a", "acme", "clean", false, "ui", None).unwrap();
        db.create_project("job-b", "other", "widgets", false, "ui", None).unwrap();

        let acme = db.list_latest_scan_unjustified_findings(Some("acme"));
        assert_eq!(acme.len(), 1);
        assert_eq!(acme[0].repo, "clean");
        assert!(acme[0].unjustified.is_empty(), "a repo with no findings is still listed");
        assert_eq!(db.list_latest_scan_unjustified_findings(None).len(), 2);
    }
}
