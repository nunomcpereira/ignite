//! Shared US-02 policy finalization for every pipeline transport.
//!
//! A caller supplies the coverage actually collected for a run plus its
//! finding/review signals. This module picks the profile once, evaluates it,
//! and persists the result against the normalized scan run. It deliberately
//! does not read any project-provided policy input.

use crate::state::AppState;

pub fn finalize(
    state: &AppState,
    run_id: Option<i64>,
    coverage: &[ignite_policy::CheckCoverage],
    has_blocking_findings: bool,
    needs_review: bool,
) -> ignite_policy::PolicyDecision {
    let policy = if state.config.policy.strict {
        ignite_policy::PolicyVersion::strict_publication()
    } else {
        ignite_policy::PolicyVersion::legacy_compatible()
    };
    let decision = ignite_policy::evaluate_policy(coverage, has_blocking_findings, needs_review, &policy);
    if let Some(run_id) = run_id {
        state.db.replace_check_executions(run_id, coverage);
        state.db.save_policy_decision(run_id, &decision);
    }
    decision
}

#[cfg(test)]
mod tests {
    

    #[test]
    fn strict_profile_marks_missing_required_coverage_incomplete() {
        let mut config = ignite_config::Config::default();
        config.policy.strict = true;
        let policy = if config.policy.strict {
            ignite_policy::PolicyVersion::strict_publication()
        } else {
            ignite_policy::PolicyVersion::legacy_compatible()
        };
        let decision = ignite_policy::evaluate_policy(&[], false, false, &policy);
        assert_eq!(decision.decision, ignite_policy::PolicyDecisionKind::Incomplete);
    }
}
