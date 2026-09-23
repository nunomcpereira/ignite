//! US-04: persisted run-lifecycle transitions, the durable pending-review
//! record, and scoped idempotency-key lookup — the enforcement layer atop
//! `ignite-run-lifecycle`'s pure state machine. `impl DbStore` block, one
//! of several per-domain files (see `lib.rs`'s module list).

use crate::store::DbStore;
use crate::types::{IdempotentRunMatch, PendingReviewRow};
use ignite_run_lifecycle::RunLifecycleState;
use rusqlite::{params, OptionalExtension};

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum LifecycleTransitionError {
    #[error("scan run {0} not found")]
    RunNotFound(i64),
    #[error("illegal transition for run {run_id}: {from} -> {to}")]
    Illegal { run_id: i64, from: String, to: String },
}

impl DbStore {
    /// Transitions `run_id` to `to`, enforcing `ignite_run_lifecycle`'s
    /// legal-transition table and recording the transition in
    /// `scan_run_transitions` — the durable history a restart (or an
    /// auditor) can read back, replacing "whatever the last writer
    /// happened to set the column to" as the source of truth.
    pub fn transition_scan_run(&self, run_id: i64, to: RunLifecycleState) -> Result<(), LifecycleTransitionError> {
        let conn = self.conn.lock();
        let current: Option<String> = conn.query_row("SELECT lifecycle_state FROM scan_runs WHERE id = ?", params![run_id], |r| r.get(0)).optional().unwrap_or(None);
        let Some(current) = current else { return Err(LifecycleTransitionError::RunNotFound(run_id)) };
        // A legacy/unrecognized value (shouldn't happen going forward, but
        // a pre-US-04 row backfilled by `BACKFILL_REPOSITORY_MODEL_SQL`
        // could in principle carry one) never blocks progress — treat it
        // as "unknown, allow the transition" rather than refusing to ever
        // move a historical row forward again.
        let from = match RunLifecycleState::parse(&current) {
            Some(s) => s,
            None => {
                Self::write_transition(&conn, run_id, &current, to);
                return Ok(());
            }
        };
        if !ignite_run_lifecycle::is_legal_transition(from, to) {
            return Err(LifecycleTransitionError::Illegal { run_id, from: from.as_str().to_string(), to: to.as_str().to_string() });
        }
        Self::write_transition(&conn, run_id, from.as_str(), to);
        Ok(())
    }

    fn write_transition(conn: &rusqlite::Connection, run_id: i64, from: &str, to: RunLifecycleState) {
        let finished = to.is_terminal();
        let result = if finished {
            conn.execute("UPDATE scan_runs SET lifecycle_state = ?, finished_at = datetime('now') WHERE id = ?", params![to.as_str(), run_id])
        } else {
            conn.execute("UPDATE scan_runs SET lifecycle_state = ? WHERE id = ?", params![to.as_str(), run_id])
        };
        if let Err(e) = result {
            tracing::error!("transition_scan_run({run_id}) failed to write {to:?}: {e}");
            return;
        }
        if let Err(e) = conn.execute("INSERT INTO scan_run_transitions (run_id, from_state, to_state) VALUES (?, ?, ?)", params![run_id, from, to.as_str()]) {
            tracing::error!("transition_scan_run({run_id}) failed to record transition history: {e}");
        }
    }

    pub fn get_scan_run_lifecycle(&self, run_id: i64) -> Option<String> {
        let conn = self.conn.lock();
        conn.query_row("SELECT lifecycle_state FROM scan_runs WHERE id = ?", params![run_id], |r| r.get(0)).optional().unwrap_or(None)
    }

    // ---------------- pending reviews ----------------

    /// Persists the durable counterpart to `ReviewGate::wait`'s in-memory
    /// registration — called from the same call site, right before
    /// `review_required` is emitted, so a server restart still leaves a
    /// queryable record of what was pending and why.
    pub fn create_pending_review(&self, run_id: i64, project_id: i64, org: &str, repo: &str, owner_email: &str, issues_json: &str) {
        let conn = self.conn.lock();
        if let Err(e) = conn.execute(
            "INSERT INTO pending_reviews (run_id, project_id, org, repo, owner_email, issues_json) VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(run_id) DO UPDATE SET project_id = excluded.project_id, org = excluded.org, repo = excluded.repo,
                                                owner_email = excluded.owner_email, issues_json = excluded.issues_json,
                                                created_at = datetime('now'), resolved_at = NULL, decision_json = NULL",
            params![run_id, project_id, org, repo, owner_email, issues_json],
        ) {
            tracing::error!("create_pending_review({run_id}) failed: {e}");
        }
    }

    /// Persists the durable counterpart to `ReviewGate::resolve` —
    /// records what was decided (even though the in-memory oneshot, if
    /// still live, is what actually unblocks the running task).
    pub fn record_review_decision(&self, run_id: i64, decision_json: &str) {
        let conn = self.conn.lock();
        if let Err(e) = conn.execute("UPDATE pending_reviews SET resolved_at = datetime('now'), decision_json = ? WHERE run_id = ?", params![decision_json, run_id]) {
            tracing::error!("record_review_decision({run_id}) failed: {e}");
        }
    }

    pub fn get_pending_review(&self, run_id: i64) -> Option<PendingReviewRow> {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT run_id, project_id, org, repo, owner_email, issues_json, created_at, resolved_at, decision_json FROM pending_reviews WHERE run_id = ?",
            params![run_id],
            Self::map_pending_review_row,
        )
        .optional()
        .unwrap_or(None)
    }

    /// Looked up by `project_id` (what every existing route/handler
    /// already has on hand) rather than requiring the caller to first
    /// resolve `run_id` itself.
    pub fn get_pending_review_by_project(&self, project_id: i64) -> Option<PendingReviewRow> {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT run_id, project_id, org, repo, owner_email, issues_json, created_at, resolved_at, decision_json FROM pending_reviews WHERE project_id = ? ORDER BY created_at DESC LIMIT 1",
            params![project_id],
            Self::map_pending_review_row,
        )
        .optional()
        .unwrap_or(None)
    }

    fn map_pending_review_row(row: &rusqlite::Row) -> rusqlite::Result<PendingReviewRow> {
        Ok(PendingReviewRow {
            run_id: row.get(0)?,
            project_id: row.get(1)?,
            org: row.get(2)?,
            repo: row.get(3)?,
            owner_email: row.get(4)?,
            issues_json: row.get(5)?,
            created_at: row.get(6)?,
            resolved_at: row.get(7)?,
            decision_json: row.get(8)?,
        })
    }

    // ---------------- idempotency keys ----------------

    /// Looks up a prior run with this exact `(repository_id, key)` pair,
    /// regardless of payload — the caller compares `payload_hash` itself
    /// to decide "same request, return the existing run" vs. "conflicting
    /// payload, reject" (see `pipeline_validate.rs`).
    pub fn find_scan_run_by_idempotency(&self, repository_id: i64, key: &str) -> Option<IdempotentRunMatch> {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT id, legacy_project_id, idempotency_payload_hash FROM scan_runs WHERE repository_id = ? AND idempotency_key = ?",
            params![repository_id, key],
            |row| {
                let run_id: i64 = row.get(0)?;
                let legacy_project_id: Option<i64> = row.get(1)?;
                let payload_hash: String = row.get(2)?;
                Ok((run_id, legacy_project_id, payload_hash))
            },
        )
        .optional()
        .unwrap_or(None)
        .map(|(run_id, legacy_project_id, payload_hash)| {
            let legacy_job_id = legacy_project_id.and_then(|pid| conn_job_id(&conn, pid));
            IdempotentRunMatch { run_id, legacy_project_id, legacy_job_id, payload_hash }
        })
    }

    pub fn set_scan_run_idempotency(&self, run_id: i64, key: &str, payload_hash: &str) {
        let conn = self.conn.lock();
        if let Err(e) = conn.execute("UPDATE scan_runs SET idempotency_key = ?, idempotency_payload_hash = ? WHERE id = ?", params![key, payload_hash, run_id]) {
            tracing::error!("set_scan_run_idempotency({run_id}) failed: {e}");
        }
    }
}

fn conn_job_id(conn: &rusqlite::Connection, project_id: i64) -> Option<String> {
    conn.query_row("SELECT job_id FROM projects WHERE id = ?", params![project_id], |r| r.get(0)).optional().unwrap_or(None)
}

#[cfg(test)]
mod tests {
    use crate::store::DbStore;
    use ignite_run_lifecycle::RunLifecycleState::*;

    fn open_test_db() -> (DbStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = DbStore::open(&dir.path().join("test.db")).unwrap();
        (db, dir)
    }

    fn run_id_for(db: &DbStore, job_id: &str, org: &str, repo: &str) -> i64 {
        let project_id = db.create_project(job_id, org, repo, false, "ui", None).unwrap();
        db.get_scan_run_for_legacy_project(project_id).unwrap().id
    }

    #[test]
    fn a_new_run_starts_queued_and_can_advance_to_scanning() {
        let (db, _dir) = open_test_db();
        let run_id = run_id_for(&db, "job-1", "acme", "widgets");
        assert_eq!(db.get_scan_run_lifecycle(run_id).as_deref(), Some("queued"));
        db.transition_scan_run(run_id, Scanning).unwrap();
        assert_eq!(db.get_scan_run_lifecycle(run_id).as_deref(), Some("scanning"));
    }

    #[test]
    fn an_illegal_transition_is_rejected_and_leaves_state_unchanged() {
        let (db, _dir) = open_test_db();
        let run_id = run_id_for(&db, "job-1", "acme", "widgets");
        let err = db.transition_scan_run(run_id, Publishing).unwrap_err();
        assert!(matches!(err, super::LifecycleTransitionError::Illegal { .. }));
        assert_eq!(db.get_scan_run_lifecycle(run_id).as_deref(), Some("queued"));
    }

    #[test]
    fn a_terminal_state_cannot_transition_again() {
        let (db, _dir) = open_test_db();
        let run_id = run_id_for(&db, "job-1", "acme", "widgets");
        db.transition_scan_run(run_id, Scanning).unwrap();
        db.transition_scan_run(run_id, Completed).unwrap();
        assert!(db.transition_scan_run(run_id, Failed).is_err());
    }

    #[test]
    fn transitioning_an_unknown_run_id_is_reported_not_panicked() {
        let (db, _dir) = open_test_db();
        assert_eq!(db.transition_scan_run(999_999, Scanning), Err(super::LifecycleTransitionError::RunNotFound(999_999)));
    }

    #[test]
    fn pending_review_round_trips_and_records_a_decision() {
        let (db, _dir) = open_test_db();
        let project_id = db.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        let run_id = db.get_scan_run_for_legacy_project(project_id).unwrap().id;

        assert!(db.get_pending_review(run_id).is_none());
        db.create_pending_review(run_id, project_id, "acme", "widgets", "owner@example.com", "[{\"id\":\"x\"}]");
        let review = db.get_pending_review(run_id).unwrap();
        assert_eq!(review.owner_email, "owner@example.com");
        assert!(review.resolved_at.is_none());

        db.record_review_decision(run_id, "{\"proceed\":true}");
        let review = db.get_pending_review(run_id).unwrap();
        assert!(review.resolved_at.is_some());
        assert_eq!(review.decision_json.as_deref(), Some("{\"proceed\":true}"));

        let by_project = db.get_pending_review_by_project(project_id).unwrap();
        assert_eq!(by_project.run_id, run_id);
    }

    #[test]
    fn idempotency_key_lookup_returns_the_existing_run() {
        let (db, _dir) = open_test_db();
        let project_id = db.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        let run_id = db.get_scan_run_for_legacy_project(project_id).unwrap().id;
        let repository_id = db.get_repository_by_org_repo("acme", "widgets").unwrap().id;

        assert!(db.find_scan_run_by_idempotency(repository_id, "key-1").is_none());
        db.set_scan_run_idempotency(run_id, "key-1", "hash-abc");
        let found = db.find_scan_run_by_idempotency(repository_id, "key-1").unwrap();
        assert_eq!(found.run_id, run_id);
        assert_eq!(found.payload_hash, "hash-abc");
        assert_eq!(found.legacy_job_id.as_deref(), Some("job-1"));
    }

    // ---- characterization: the ordering rules callers depend on today.

    #[test]
    fn finish_project_never_overwrites_a_precise_terminal_state() {
        // Regression pin: finish_project maps status "success" to "published"
        // when nothing more precise exists. Callers transition to the precise
        // terminal state *first*, so that fallback must never clobber it.
        let (db, _dir) = open_test_db();
        for (repo, terminal) in [("completed-repo", Completed), ("blocked-repo", Blocked), ("failed-repo", Failed)] {
            let pid = db.create_project(&format!("job-{repo}"), "acme", repo, false, "ui", None).unwrap();
            let run = db.get_scan_run_for_legacy_project(pid).unwrap().id;
            db.transition_scan_run(run, Scanning).unwrap();
            db.transition_scan_run(run, terminal).unwrap();
            db.finish_project("success", None, None, None, pid);
            assert_eq!(db.get_scan_run_lifecycle(run).as_deref(), Some(terminal.as_str()), "{repo}");
        }
    }

    #[test]
    fn without_a_precise_state_finish_project_falls_back_to_a_status_mapping() {
        // The naive mapping the precise transitions exist to bypass.
        let (db, _dir) = open_test_db();
        let ok = db.create_project("job-ok", "acme", "ok-repo", false, "ui", None).unwrap();
        db.finish_project("success", None, None, None, ok);
        assert_eq!(db.get_scan_run_lifecycle(db.get_scan_run_for_legacy_project(ok).unwrap().id).as_deref(), Some("published"));

        let bad = db.create_project("job-bad", "acme", "bad-repo", false, "ui", None).unwrap();
        db.finish_project("failed", Some("boom"), None, None, bad);
        assert_eq!(db.get_scan_run_lifecycle(db.get_scan_run_for_legacy_project(bad).unwrap().id).as_deref(), Some("failed"));
    }

    #[test]
    fn every_accepted_transition_is_recorded_in_order_and_a_rejected_one_is_not() {
        let (db, _dir) = open_test_db();
        let run = run_id_for(&db, "job-history", "acme", "history-repo");
        for to in [Scanning, AwaitingReview, Approved, Publishing, Published] {
            db.transition_scan_run(run, to).unwrap();
        }
        assert!(db.transition_scan_run(run, Scanning).is_err(), "a terminal run cannot move again");
        let conn = db.conn.lock();
        let mut stmt = conn.prepare("SELECT from_state, to_state FROM scan_run_transitions WHERE run_id = ? ORDER BY id").unwrap();
        let rows: Vec<(String, String)> = stmt.query_map([run], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().filter_map(|r| r.ok()).collect();
        let expected: Vec<(String, String)> = [("queued", "scanning"), ("scanning", "awaiting_review"), ("awaiting_review", "approved"), ("approved", "publishing"), ("publishing", "published")]
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect();
        assert_eq!(rows, expected);
    }

    #[test]
    fn a_dry_run_style_finish_leaves_completed_not_published() {
        // validate-all and dry-run onboard: Scanning -> Completed, then finish_project("success").
        let (db, _dir) = open_test_db();
        let pid = db.create_project("job-dry", "acme", "dry-repo", false, "api", None).unwrap();
        let run = db.get_scan_run_for_legacy_project(pid).unwrap().id;
        db.transition_scan_run(run, Scanning).unwrap();
        db.transition_scan_run(run, Completed).unwrap();
        db.finish_project("success", None, None, None, pid);
        assert_eq!(db.get_scan_run_lifecycle(run).as_deref(), Some("completed"));
    }
}
