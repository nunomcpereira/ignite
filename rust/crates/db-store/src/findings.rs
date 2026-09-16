//! US-07: track findings reliably across scans — separates the stable
//! `findings` identity (one row per distinct fingerprint, forever) from
//! the per-run `finding_observations` evidence, and classifies every
//! incoming finding as `new`/`existing`/`reopened`, plus marks an absent
//! previously-open finding `resolved` *only* when this run's check for
//! its producing tool actually completed — a failed/disabled/unavailable
//! check must never be read as proof the finding is gone.
//!
//! Deliberately keyed on `ignite_override_engine::stable_fingerprint`
//! (content-hashed, line-drift-tolerant), not the classic
//! `category::file::line` id — the latter is preserved verbatim as
//! `legacy_issue_id` on each row for override/SARIF/GitHub-alert
//! compatibility, but never used as this table's own identity.

use crate::store::DbStore;
use crate::types::{FindingObservationInput, FindingRow, FindingSyncSummary};
use rusqlite::{params, OptionalExtension};
use std::collections::{HashMap, HashSet};

fn finding_row_from(row: &rusqlite::Row) -> rusqlite::Result<FindingRow> {
    Ok(FindingRow {
        id: row.get(0)?,
        repository_id: row.get(1)?,
        category: row.get(2)?,
        fingerprint: row.get(3)?,
        legacy_issue_id: row.get(4)?,
        tool: row.get(5)?,
        status: row.get(6)?,
        first_seen_run_id: row.get(7)?,
        first_seen_at: row.get(8)?,
        last_seen_run_id: row.get(9)?,
        last_seen_at: row.get(10)?,
    })
}

const FINDING_COLUMNS: &str = "id, repository_id, category, fingerprint, legacy_issue_id, tool, status, first_seen_run_id, first_seen_at, last_seen_run_id, last_seen_at";

impl DbStore {
    /// Syncs one run's finding list against the repository's known
    /// findings. `completed_tools` is the set of `Issue.tool` values
    /// (lowercased) whose producing check actually reached
    /// `CheckOutcome::Completed` this run — an existing open finding
    /// whose own `tool` isn't in that set is left untouched when absent
    /// from `findings` (acceptance criterion: "Failed or unavailable
    /// scanners never mark prior findings fixed"); a finding with no
    /// recorded tool at all is treated the same conservative way, since
    /// there's no coverage signal to trust either way.
    pub fn record_finding_observations(&self, repository_id: i64, run_id: i64, completed_tools: &HashSet<String>, findings: &[FindingObservationInput]) -> FindingSyncSummary {
        let mut conn = self.conn.lock();
        let tx = match conn.transaction() {
            Ok(tx) => tx,
            Err(e) => {
                tracing::error!("record_finding_observations({repository_id}, {run_id}) failed to open transaction: {e}");
                return FindingSyncSummary::default();
            }
        };
        let mut summary = FindingSyncSummary::default();
        let mut seen_finding_ids: HashSet<i64> = HashSet::new();

        for input in findings {
            let existing: Option<FindingRow> = tx
                .query_row(&format!("SELECT {FINDING_COLUMNS} FROM findings WHERE repository_id = ? AND fingerprint = ?"), params![repository_id, input.fingerprint], finding_row_from)
                .optional()
                .unwrap_or(None);

            let (finding_id, classification) = match existing {
                None => {
                    if let Err(e) = tx.execute(
                        "INSERT INTO findings (repository_id, category, fingerprint, legacy_issue_id, tool, status, first_seen_run_id, last_seen_run_id) VALUES (?, ?, ?, ?, ?, 'open', ?, ?)",
                        params![repository_id, input.category, input.fingerprint, input.legacy_issue_id, input.tool, run_id, run_id],
                    ) {
                        tracing::error!("record_finding_observations: failed to insert finding: {e}");
                        continue;
                    }
                    (tx.last_insert_rowid(), "new")
                }
                Some(row) => {
                    let classification = if row.status == "resolved" { "reopened" } else { "existing" };
                    let new_status = if row.status == "resolved" { "reopened" } else { row.status.as_str() };
                    if let Err(e) = tx.execute(
                        "UPDATE findings SET status = ?, tool = ?, legacy_issue_id = ?, last_seen_run_id = ?, last_seen_at = datetime('now') WHERE id = ?",
                        params![new_status, input.tool, input.legacy_issue_id, run_id, row.id],
                    ) {
                        tracing::error!("record_finding_observations: failed to update finding {}: {e}", row.id);
                    }
                    (row.id, classification)
                }
            };

            seen_finding_ids.insert(finding_id);
            match classification {
                "new" => summary.new_count += 1,
                "reopened" => summary.reopened_count += 1,
                _ => summary.existing_count += 1,
            }
            if let Err(e) = tx.execute(
                "INSERT INTO finding_observations (finding_id, run_id, classification, file, line, severity) VALUES (?, ?, ?, ?, ?, ?)",
                params![finding_id, run_id, classification, input.file, input.line, input.severity],
            ) {
                tracing::error!("record_finding_observations: failed to insert observation for finding {finding_id}: {e}");
            }
        }

        // Anything still `open`/`reopened` for this repository that wasn't
        // in this run's list is a candidate for resolution — but only when
        // this run's check for its own tool actually completed. No tool
        // recorded, or that tool's check didn't complete this run: leave
        // it exactly as it was, silently (not even an observation row —
        // nothing was actually learned about it this run).
        let candidates: Vec<FindingRow> = match tx.prepare(&format!("SELECT {FINDING_COLUMNS} FROM findings WHERE repository_id = ? AND status IN ('open', 'reopened')")) {
            Ok(mut stmt) => stmt.query_map(params![repository_id], finding_row_from).map(|rows| rows.filter_map(|r| r.ok()).collect()).unwrap_or_default(),
            Err(e) => {
                tracing::error!("record_finding_observations: failed to prepare resolution query: {e}");
                vec![]
            }
        };

        for row in candidates {
            if seen_finding_ids.contains(&row.id) {
                continue;
            }
            let Some(tool) = row.tool.as_deref() else { continue };
            if !completed_tools.contains(&tool.to_ascii_lowercase()) {
                continue;
            }
            if let Err(e) = tx.execute("UPDATE findings SET status = 'resolved', last_seen_run_id = ?, last_seen_at = datetime('now') WHERE id = ?", params![run_id, row.id]) {
                tracing::error!("record_finding_observations: failed to resolve finding {}: {e}", row.id);
                continue;
            }
            if let Err(e) = tx.execute("INSERT INTO finding_observations (finding_id, run_id, classification) VALUES (?, ?, 'resolved')", params![row.id, run_id]) {
                tracing::error!("record_finding_observations: failed to insert resolution observation for finding {}: {e}", row.id);
            }
            summary.resolved_count += 1;
        }

        if let Err(e) = tx.commit() {
            tracing::error!("record_finding_observations({repository_id}, {run_id}) failed to commit: {e}");
            return FindingSyncSummary::default();
        }
        summary
    }

    pub fn list_findings_for_repository(&self, repository_id: i64) -> Vec<FindingRow> {
        let conn = self.conn.lock();
        let Ok(mut stmt) = conn.prepare(&format!("SELECT {FINDING_COLUMNS} FROM findings WHERE repository_id = ? ORDER BY id")) else { return vec![] };
        stmt.query_map(params![repository_id], finding_row_from).map(|rows| rows.filter_map(|r| r.ok()).collect()).unwrap_or_default()
    }

    /// Every category currently completed for findings not yet resolved,
    /// primarily a test/debugging aid — real callers use
    /// [`Self::list_findings_for_repository`] plus their own status filter.
    pub fn count_findings_by_status(&self, repository_id: i64) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for row in self.list_findings_for_repository(repository_id) {
            *counts.entry(row.status).or_insert(0) += 1;
        }
        counts
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

    fn input(legacy_id: &str, category: &str, fingerprint: &str, tool: &str) -> FindingObservationInput {
        FindingObservationInput { legacy_issue_id: legacy_id.to_string(), category: category.to_string(), fingerprint: fingerprint.to_string(), file: Some("src/app.js".to_string()), line: Some(10), severity: "error".to_string(), tool: Some(tool.to_string()) }
    }

    fn repo_and_run(db: &DbStore) -> (i64, i64) {
        let project_id = db.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        let repository_id = db.resolve_repository("acme", "widgets", None);
        let run_id = db.get_scan_run_for_legacy_project(project_id).unwrap().id;
        (repository_id, run_id)
    }

    #[test]
    fn a_brand_new_finding_is_classified_new() {
        let (db, _dir) = open_test_db();
        let (repository_id, run_id) = repo_and_run(&db);
        let summary = db.record_finding_observations(repository_id, run_id, &HashSet::new(), &[input("secret::app.js::1", "secret", "fp-1", "gitleaks")]);
        assert_eq!(summary.new_count, 1);
        assert_eq!(summary, FindingSyncSummary { new_count: 1, ..Default::default() });
    }

    #[test]
    fn blank_line_drift_keeps_the_same_fingerprint_and_reads_as_existing_not_new() {
        // Simulates the acceptance criterion directly: the fingerprint is
        // computed by the caller (here hardcoded, matching what
        // `stable_fingerprint` would produce for identical snippet text
        // even though the line number shifted) — this module's own job is
        // just to classify same-fingerprint inputs as `existing`.
        let (db, _dir) = open_test_db();
        let (repository_id, run_id_1) = repo_and_run(&db);
        db.record_finding_observations(repository_id, run_id_1, &HashSet::new(), &[input("secret::app.js::10", "secret", "fp-stable", "gitleaks")]);

        let project_id_2 = db.create_project("job-2", "acme", "widgets", false, "ui", None).unwrap();
        let run_id_2 = db.get_scan_run_for_legacy_project(project_id_2).unwrap().id;
        // Same fingerprint, but the line moved from 10 to 14 (blank lines
        // inserted above) — legacy id reflects the new line, fingerprint
        // does not change.
        let summary = db.record_finding_observations(repository_id, run_id_2, &HashSet::new(), &[input("secret::app.js::14", "secret", "fp-stable", "gitleaks")]);
        assert_eq!(summary.existing_count, 1);
        assert_eq!(summary.new_count, 0, "line drift alone must not read as a brand-new finding");

        let findings = db.list_findings_for_repository(repository_id);
        assert_eq!(findings.len(), 1, "one fingerprint must mean one finding row regardless of line movement");
        assert_eq!(findings[0].legacy_issue_id, "secret::app.js::14", "the legacy id still tracks the current line for display/override purposes");
    }

    #[test]
    fn different_rules_on_the_same_line_stay_distinct_findings() {
        let (db, _dir) = open_test_db();
        let (repository_id, run_id) = repo_and_run(&db);
        db.record_finding_observations(repository_id, run_id, &HashSet::new(), &[input("sast::app.js::5", "semantic-sast", "fp-rule-a", "semgrep"), input("sast::app.js::5", "semantic-sast", "fp-rule-b", "semgrep")]);
        let findings = db.list_findings_for_repository(repository_id);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn a_finding_absent_with_no_completed_check_for_its_tool_stays_open() {
        let (db, _dir) = open_test_db();
        let (repository_id, run_id_1) = repo_and_run(&db);
        db.record_finding_observations(repository_id, run_id_1, &HashSet::new(), &[input("secret::app.js::1", "secret", "fp-1", "gitleaks")]);

        let project_id_2 = db.create_project("job-2", "acme", "widgets", false, "ui", None).unwrap();
        let run_id_2 = db.get_scan_run_for_legacy_project(project_id_2).unwrap().id;
        // gitleaks is NOT in completed_tools this run (e.g. it failed/was unavailable) — absence must not resolve it.
        let summary = db.record_finding_observations(repository_id, run_id_2, &HashSet::new(), &[]);
        assert_eq!(summary.resolved_count, 0);
        let findings = db.list_findings_for_repository(repository_id);
        assert_eq!(findings[0].status, "open");
    }

    #[test]
    fn a_finding_absent_with_a_completed_check_for_its_tool_resolves() {
        let (db, _dir) = open_test_db();
        let (repository_id, run_id_1) = repo_and_run(&db);
        db.record_finding_observations(repository_id, run_id_1, &HashSet::new(), &[input("secret::app.js::1", "secret", "fp-1", "gitleaks")]);

        let project_id_2 = db.create_project("job-2", "acme", "widgets", false, "ui", None).unwrap();
        let run_id_2 = db.get_scan_run_for_legacy_project(project_id_2).unwrap().id;
        let completed: HashSet<String> = ["gitleaks".to_string()].into_iter().collect();
        let summary = db.record_finding_observations(repository_id, run_id_2, &completed, &[]);
        assert_eq!(summary.resolved_count, 1);
        let findings = db.list_findings_for_repository(repository_id);
        assert_eq!(findings[0].status, "resolved");
    }

    #[test]
    fn reintroducing_a_resolved_finding_reopens_it() {
        let (db, _dir) = open_test_db();
        let (repository_id, run_id_1) = repo_and_run(&db);
        db.record_finding_observations(repository_id, run_id_1, &HashSet::new(), &[input("secret::app.js::1", "secret", "fp-1", "gitleaks")]);

        let project_id_2 = db.create_project("job-2", "acme", "widgets", false, "ui", None).unwrap();
        let run_id_2 = db.get_scan_run_for_legacy_project(project_id_2).unwrap().id;
        let completed: HashSet<String> = ["gitleaks".to_string()].into_iter().collect();
        db.record_finding_observations(repository_id, run_id_2, &completed, &[]);
        assert_eq!(db.list_findings_for_repository(repository_id)[0].status, "resolved");

        let project_id_3 = db.create_project("job-3", "acme", "widgets", false, "ui", None).unwrap();
        let run_id_3 = db.get_scan_run_for_legacy_project(project_id_3).unwrap().id;
        let summary = db.record_finding_observations(repository_id, run_id_3, &completed, &[input("secret::app.js::1", "secret", "fp-1", "gitleaks")]);
        assert_eq!(summary.reopened_count, 1);
        assert_eq!(db.list_findings_for_repository(repository_id)[0].status, "reopened");
    }
}
