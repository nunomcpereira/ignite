//! US-04: the pure lifecycle-state model every entry point's persisted
//! `scan_runs.lifecycle_state` transition is checked against, so "what
//! states exist and which transitions between them are legal" lives in
//! exactly one place instead of being implied by whatever a route handler
//! happens to write to the column. No I/O, no clock, no database — see
//! `ignite-db-store`'s `lifecycle.rs` for the persisted enforcement layer
//! that calls into this.
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunLifecycleState {
    /// Accepted, not yet started (the brief window between `create_project`
    /// and the first phase actually running).
    Queued,
    /// Phases 1-5 in progress.
    Scanning,
    /// Blocking findings accumulated; a human decision (override/proceed/
    /// abort) is pending before phase 6 can run.
    AwaitingReview,
    /// A human reviewed and approved proceeding — set the instant a
    /// decision resolves `proceed: true` with every blocking finding
    /// either overridden or fixed, before phase 6 actually starts.
    Approved,
    /// Phase 6 (provisioning + push) is in progress.
    Publishing,
    /// Phase 6 completed and real GitHub state now reflects this run —
    /// terminal, and the only state that means "something was actually
    /// published".
    Published,
    /// Terminal, non-publication outcome: the run finished (validate-all,
    /// or a dry-run onboard/interactive run) with nothing to push, or
    /// nothing left over that needed pushing.
    Completed,
    /// Terminal: blocking findings were never resolved (unresolved
    /// overrides, or a human explicitly declined to proceed).
    Blocked,
    /// Terminal: an unrecoverable error (tool crash, network failure,
    /// invalid input) stopped the run before a pass/block decision could
    /// even be reached.
    Failed,
    /// Terminal: cancelled before completion, explicitly.
    Cancelled,
}

impl RunLifecycleState {
    pub fn as_str(self) -> &'static str {
        match self {
            RunLifecycleState::Queued => "queued",
            RunLifecycleState::Scanning => "scanning",
            RunLifecycleState::AwaitingReview => "awaiting_review",
            RunLifecycleState::Approved => "approved",
            RunLifecycleState::Publishing => "publishing",
            RunLifecycleState::Published => "published",
            RunLifecycleState::Completed => "completed",
            RunLifecycleState::Blocked => "blocked",
            RunLifecycleState::Failed => "failed",
            RunLifecycleState::Cancelled => "cancelled",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "queued" => RunLifecycleState::Queued,
            "scanning" => RunLifecycleState::Scanning,
            "awaiting_review" => RunLifecycleState::AwaitingReview,
            "approved" => RunLifecycleState::Approved,
            "publishing" => RunLifecycleState::Publishing,
            "published" => RunLifecycleState::Published,
            "completed" => RunLifecycleState::Completed,
            "blocked" => RunLifecycleState::Blocked,
            "failed" => RunLifecycleState::Failed,
            "cancelled" => RunLifecycleState::Cancelled,
            _ => return None,
        })
    }

    /// No legal transition leaves any of these — a run that reaches one
    /// stays there forever (barring a brand-new run).
    pub fn is_terminal(self) -> bool {
        matches!(self, RunLifecycleState::Published | RunLifecycleState::Completed | RunLifecycleState::Blocked | RunLifecycleState::Failed | RunLifecycleState::Cancelled)
    }
}

/// Whether `to` is a legal next state from `from`. A same-state transition
/// is always legal (idempotent retries — e.g. a caller re-posting the same
/// "still scanning" heartbeat) even where it's not separately listed
/// below. Terminal states have no legal outgoing transition at all,
/// `from == to` included — re-finishing an already-finished run is a
/// caller bug, not a retry, and should be rejected so it surfaces instead
/// of silently overwriting a terminal record.
pub fn is_legal_transition(from: RunLifecycleState, to: RunLifecycleState) -> bool {
    use RunLifecycleState::*;
    if from.is_terminal() {
        return false;
    }
    if from == to {
        return true;
    }
    matches!(
        (from, to),
        (Queued, Scanning) | (Queued, Cancelled) | (Queued, Failed)
            | (Scanning, AwaitingReview) | (Scanning, Completed) | (Scanning, Blocked) | (Scanning, Failed) | (Scanning, Cancelled)
            // No finding ever needed a human decision (a clean scan, or
            // every finding was already carried-forward/AI-justified) —
            // "approved" with nothing to approve is still a legitimate way
            // to reach phase 6, not a skipped step.
            | (Scanning, Approved)
            | (AwaitingReview, Approved) | (AwaitingReview, Blocked) | (AwaitingReview, Failed) | (AwaitingReview, Cancelled)
            | (Approved, Publishing) | (Approved, Completed) | (Approved, Cancelled) | (Approved, Failed)
            | (Publishing, Published) | (Publishing, Failed)
    )
}

#[derive(Debug, PartialEq, Eq)]
pub struct IllegalTransition {
    pub from: RunLifecycleState,
    pub to: RunLifecycleState,
}

/// Checked variant of [`is_legal_transition`] for a caller that wants the
/// rejected pair back for logging, instead of a bare bool.
pub fn check_transition(from: RunLifecycleState, to: RunLifecycleState) -> Result<(), IllegalTransition> {
    if is_legal_transition(from, to) {
        Ok(())
    } else {
        Err(IllegalTransition { from, to })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use RunLifecycleState::*;

    #[test]
    fn round_trips_every_state_through_as_str_and_parse() {
        for s in [Queued, Scanning, AwaitingReview, Approved, Publishing, Published, Completed, Blocked, Failed, Cancelled] {
            assert_eq!(RunLifecycleState::parse(s.as_str()), Some(s));
        }
    }

    #[test]
    fn parse_rejects_unknown_strings() {
        assert_eq!(RunLifecycleState::parse("not-a-state"), None);
    }

    #[test]
    fn terminal_states_have_no_legal_outgoing_transition() {
        for terminal in [Published, Completed, Blocked, Failed, Cancelled] {
            for to in [Queued, Scanning, AwaitingReview, Approved, Publishing, Published, Completed, Blocked, Failed, Cancelled] {
                assert!(!is_legal_transition(terminal, to), "{terminal:?} -> {to:?} should be illegal (terminal)");
            }
        }
    }

    #[test]
    fn same_state_is_always_legal_for_non_terminal_states() {
        for s in [Queued, Scanning, AwaitingReview, Approved, Publishing] {
            assert!(is_legal_transition(s, s));
        }
    }

    #[test]
    fn the_happy_path_scan_only_run_is_legal() {
        assert!(is_legal_transition(Queued, Scanning));
        assert!(is_legal_transition(Scanning, Completed));
    }

    #[test]
    fn the_happy_path_review_then_publish_run_is_legal() {
        assert!(is_legal_transition(Queued, Scanning));
        assert!(is_legal_transition(Scanning, AwaitingReview));
        assert!(is_legal_transition(AwaitingReview, Approved));
        assert!(is_legal_transition(Approved, Publishing));
        assert!(is_legal_transition(Publishing, Published));
    }

    #[test]
    fn skipping_awaiting_review_straight_to_publishing_is_illegal() {
        assert!(!is_legal_transition(Scanning, Publishing));
        assert!(!is_legal_transition(Queued, Approved));
    }

    #[test]
    fn a_declined_review_blocks_rather_than_silently_completing() {
        assert!(is_legal_transition(AwaitingReview, Blocked));
        assert!(!is_legal_transition(AwaitingReview, Completed));
    }

    #[test]
    fn check_transition_reports_the_rejected_pair() {
        let err = check_transition(Published, Scanning).unwrap_err();
        assert_eq!(err, IllegalTransition { from: Published, to: Scanning });
        assert!(check_transition(Queued, Scanning).is_ok());
    }
}
