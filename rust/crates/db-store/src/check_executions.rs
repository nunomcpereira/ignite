//! US-02 persistence for the coverage envelope and its resulting decision.
//!
//! This is deliberately separate from `issues`: a completed check with no
//! findings and an unavailable check both have no issue rows, but mean very
//! different things to a reviewer and to a strict policy.

use crate::store::DbStore;
use ignite_policy::{CheckCoverage, CheckOutcome, PolicyDecision, PolicyDecisionKind};
use rusqlite::params;

fn outcome_name(outcome: CheckOutcome) -> &'static str {
    match outcome {
        CheckOutcome::Completed => "completed",
        CheckOutcome::NotApplicable => "not_applicable",
        CheckOutcome::Disabled => "disabled",
        CheckOutcome::Unavailable => "unavailable",
        CheckOutcome::Failed => "failed",
        CheckOutcome::TimedOut => "timed_out",
        CheckOutcome::Cancelled => "cancelled",
    }
}

fn decision_name(decision: PolicyDecisionKind) -> &'static str {
    match decision {
        PolicyDecisionKind::Pass => "pass",
        PolicyDecisionKind::NeedsReview => "needs_review",
        PolicyDecisionKind::Blocked => "blocked",
        PolicyDecisionKind::Incomplete => "incomplete",
    }
}

impl DbStore {
    /// Replaces coverage for the current attempt. A resumed workflow will
    /// record a later attempt rather than overwriting this historical row;
    /// the initial validate-all adapter always uses attempt 1.
    pub fn replace_check_executions(&self, run_id: i64, coverage: &[CheckCoverage]) {
        let mut conn = self.conn.lock();
        let Ok(tx) = conn.transaction() else {
            tracing::error!("replace_check_executions({run_id}) could not start transaction");
            return;
        };
        if let Err(e) = tx.execute(
            "DELETE FROM check_executions WHERE run_id = ? AND attempt = 1",
            params![run_id],
        ) {
            tracing::error!(
                "replace_check_executions({run_id}) could not clear existing rows: {e}"
            );
            return;
        }
        for check in coverage {
            if let Err(e) = tx.execute(
                "INSERT INTO check_executions (run_id, check_id, attempt, outcome, engine, engine_version, is_fallback, scope, reason, from_cache, duration_ms) VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![run_id, check.check_id, outcome_name(check.outcome), check.engine, check.engine_version, check.is_fallback, check.scope, check.reason, check.from_cache, check.duration_ms],
            ) {
                tracing::error!("replace_check_executions({run_id}) could not insert {}: {e}", check.check_id);
                return;
            }
        }
        if let Err(e) = tx.commit() {
            tracing::error!("replace_check_executions({run_id}) could not commit: {e}");
        }
    }

    pub fn save_policy_decision(&self, run_id: i64, decision: &PolicyDecision) {
        let reasons = serde_json::to_string(&decision.reasons).unwrap_or_else(|_| "[]".to_string());
        let missing = serde_json::to_string(&decision.missing_required_coverage)
            .unwrap_or_else(|_| "[]".to_string());
        let conn = self.conn.lock();
        if let Err(e) = conn.execute(
            "INSERT INTO policy_decisions (run_id, decision, policy_version, reasons_json, missing_checks_json) VALUES (?, ?, ?, ?, ?) ON CONFLICT(run_id) DO UPDATE SET decision = excluded.decision, policy_version = excluded.policy_version, reasons_json = excluded.reasons_json, missing_checks_json = excluded.missing_checks_json, created_at = datetime('now')",
            params![run_id, decision_name(decision.decision), decision.policy_version, reasons, missing],
        ) {
            tracing::error!("save_policy_decision({run_id}) failed: {e}");
        }
        if let Err(e) = conn.execute(
            "UPDATE scan_runs SET policy_version = ? WHERE id = ?",
            params![decision.policy_version, run_id],
        ) {
            tracing::error!("save_policy_decision({run_id}) could not pin policy version: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::store::DbStore;
    use ignite_policy::{CheckCoverage, PolicyDecision, PolicyDecisionKind};

    #[test]
    fn coverage_and_strict_incomplete_decision_are_persisted_separately_from_findings() {
        let dir = tempfile::tempdir().unwrap();
        let db = DbStore::open(&dir.path().join("test.db")).unwrap();
        let project = db
            .create_project("job-1", "acme", "widgets", false, "api", None)
            .unwrap();
        let run = db.get_scan_run_for_legacy_project(project).unwrap();
        db.replace_check_executions(
            run.id,
            &[
                CheckCoverage::completed("secrets", "built-in", false),
                CheckCoverage::unavailable("semantic-sast", "semgrep missing"),
            ],
        );
        db.save_policy_decision(
            run.id,
            &PolicyDecision {
                decision: PolicyDecisionKind::Incomplete,
                policy_version: "strict-publication-v1".to_string(),
                reasons: vec!["semantic SAST unavailable".to_string()],
                missing_required_coverage: vec!["semantic-sast".to_string()],
            },
        );

        let conn = db.conn.lock();
        let rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM check_executions WHERE run_id = ?",
                [run.id],
                |row| row.get(0),
            )
            .unwrap();
        let outcome: String = conn
            .query_row(
                "SELECT decision FROM policy_decisions WHERE run_id = ?",
                [run.id],
                |row| row.get(0),
            )
            .unwrap();
        let policy: String = conn
            .query_row(
                "SELECT policy_version FROM scan_runs WHERE id = ?",
                [run.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rows, 2);
        assert_eq!(outcome, "incomplete");
        assert_eq!(policy, "strict-publication-v1");
    }
}
