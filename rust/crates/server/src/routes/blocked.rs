//! One machine-readable shape for "this run can't publish yet", shared by
//! every route that can refuse a publication. Human callers read the
//! `error` string; an agent needs to tell apart *what to do next* — submit
//! overrides, wait for a second reviewer, restore a missing check, or fix
//! the source — without parsing prose. Every field here is **additive**: the
//! pre-existing keys (`needsReview`, `pendingApproval`, `incompleteCoverage`,
//! `issues`, ...) stay exactly as they were.

use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockReason {
    /// Blocking findings have no justification yet.
    UnresolvedFindings,
    /// Critical overrides were submitted but await a different approver.
    PendingApproval,
    /// A required check didn't complete (tool missing/failed/disabled).
    IncompleteCoverage,
    /// The policy evaluated to something that forbids publishing, and none of
    /// the more specific reasons above applies.
    PolicyBlocked,
}

impl BlockReason {
    fn code(self) -> &'static str {
        match self {
            BlockReason::UnresolvedFindings => "unresolved_findings",
            BlockReason::PendingApproval => "pending_approval",
            BlockReason::IncompleteCoverage => "incomplete_coverage",
            BlockReason::PolicyBlocked => "policy_blocked",
        }
    }

    /// Can the caller clear this by submitting overrides itself?
    fn overridable(self) -> bool {
        matches!(self, BlockReason::UnresolvedFindings)
    }

    fn next_action(self) -> &'static str {
        match self {
            BlockReason::UnresolvedFindings => "submit_overrides_or_fix_source",
            BlockReason::PendingApproval => "await_second_reviewer",
            BlockReason::IncompleteCoverage => "restore_missing_checks_and_rescan",
            BlockReason::PolicyBlocked => "fix_source_and_rescan",
        }
    }

    /// Whether this needs a person other than the calling agent.
    fn needs_human(self) -> bool {
        matches!(self, BlockReason::PendingApproval)
    }
}

/// Adds the `blocked` envelope to `body` (a JSON object) and returns it.
/// `details` is merged in verbatim (e.g. `missingChecks`, `pendingOverrides`).
pub fn with_block_info(mut body: Value, reason: BlockReason, details: Value) -> Value {
    let Some(obj) = body.as_object_mut() else { return body };
    obj.insert("ok".into(), json!(false));
    obj.insert("blocked".into(), json!(true));
    obj.insert("blockReason".into(), json!(reason.code()));
    obj.insert("overridable".into(), json!(reason.overridable()));
    obj.insert("nextAction".into(), json!(reason.next_action()));
    obj.insert("needsHuman".into(), json!(reason.needs_human()));
    if let Some(extra) = details.as_object() {
        for (k, v) in extra {
            obj.insert(k.clone(), v.clone());
        }
    }
    body
}

/// Picks the most specific reason a policy decision blocks publication, or
/// `None` when it permits it.
pub fn reason_for_policy_decision(decision: &ignite_policy::PolicyDecision) -> Option<BlockReason> {
    use ignite_policy::PolicyDecisionKind as K;
    match decision.decision {
        K::Pass => None,
        K::Incomplete => Some(BlockReason::IncompleteCoverage),
        K::Blocked => Some(BlockReason::UnresolvedFindings),
        K::NeedsReview => Some(BlockReason::PolicyBlocked),
    }
}

/// `missingChecks` + `policyDecision` details for a policy-driven block.
pub fn policy_details(decision: &ignite_policy::PolicyDecision) -> Value {
    json!({
        "missingChecks": decision.missing_required_coverage,
        "policyDecision": decision,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_envelope_is_additive_and_carries_a_next_action() {
        let body = with_block_info(json!({ "error": "x", "needsReview": true }), BlockReason::UnresolvedFindings, json!({ "issues": [] }));
        assert_eq!(body["needsReview"], true, "pre-existing keys are untouched");
        assert_eq!(body["blocked"], true);
        assert_eq!(body["ok"], false);
        assert_eq!(body["blockReason"], "unresolved_findings");
        assert_eq!(body["overridable"], true);
        assert_eq!(body["needsHuman"], false);
        assert_eq!(body["nextAction"], "submit_overrides_or_fix_source");
    }

    #[test]
    fn a_pending_approval_is_not_overridable_and_needs_a_human() {
        let body = with_block_info(json!({}), BlockReason::PendingApproval, json!({}));
        assert_eq!(body["overridable"], false);
        assert_eq!(body["needsHuman"], true);
        assert_eq!(body["nextAction"], "await_second_reviewer");
    }

    #[test]
    fn incomplete_coverage_is_not_overridable() {
        let body = with_block_info(json!({}), BlockReason::IncompleteCoverage, json!({ "missingChecks": ["semgrep"] }));
        assert_eq!(body["overridable"], false);
        assert_eq!(body["missingChecks"][0], "semgrep");
    }

    #[test]
    fn non_object_bodies_pass_through() {
        assert_eq!(with_block_info(json!([1]), BlockReason::PolicyBlocked, json!({})), json!([1]));
    }
}
