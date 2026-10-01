//! `org_report_runs` — the last send attempt of each org's scheduled
//! findings email (schedules themselves live in config.json's `orgReports`).
//! Org keys are lowercased.

use crate::store::DbStore;
use rusqlite::{params, OptionalExtension};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgReportRun {
    /// UTC `YYYY-MM-DD HH:MM:SS`.
    pub last_run_at: String,
    pub last_recipients: Option<String>,
    /// `"github_admins"`, `"fallback"`, `"fixed"` or `"none"`.
    pub last_recipient_source: Option<String>,
    pub last_error: Option<String>,
}

impl DbStore {
    pub fn get_org_report_run(&self, org: &str) -> Option<OrgReportRun> {
        let conn = self.conn.lock();
        conn.query_row("SELECT last_run_at, last_recipients, last_recipient_source, last_error FROM org_report_runs WHERE org = ?", params![org.to_ascii_lowercase()], |row| {
            Ok(OrgReportRun { last_run_at: row.get(0)?, last_recipients: row.get(1)?, last_recipient_source: row.get(2)?, last_error: row.get(3)? })
        })
        .optional()
        .unwrap()
    }

    /// Records one send attempt. `run_at` is UTC `YYYY-MM-DD HH:MM:SS`.
    pub fn record_org_report_run(&self, org: &str, run_at: &str, recipients: Option<&str>, source: Option<&str>, error: Option<&str>) {
        self.conn
            .lock()
            .execute(
                "INSERT INTO org_report_runs (org, last_run_at, last_recipients, last_recipient_source, last_error) VALUES (?, ?, ?, ?, ?)
                 ON CONFLICT(org) DO UPDATE SET last_run_at = excluded.last_run_at, last_recipients = excluded.last_recipients, last_recipient_source = excluded.last_recipient_source, last_error = excluded.last_error",
                params![org.to_ascii_lowercase(), run_at, recipients, source, error],
            )
            .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use crate::store::DbStore;

    #[test]
    fn last_run_is_replaced_and_matched_case_insensitively() {
        let dir = tempfile::tempdir().unwrap();
        let db = DbStore::open(&dir.path().join("t.db")).unwrap();
        assert!(db.get_org_report_run("Acme").is_none());
        db.record_org_report_run("Acme", "2026-10-01 09:00:00", Some("b@x.com"), Some("github_admins"), None);
        db.record_org_report_run("acme", "2026-10-02 09:00:00", None, Some("none"), Some("no recipients"));
        let r = db.get_org_report_run("ACME").unwrap();
        assert_eq!((r.last_run_at.as_str(), r.last_recipients, r.last_error.as_deref()), ("2026-10-02 09:00:00", None, Some("no recipients")));
    }
}
