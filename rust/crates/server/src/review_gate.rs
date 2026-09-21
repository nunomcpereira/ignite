//! Review-gate decision channel — faithful port of server.js's
//! `reviewDecisions` helper (a promise-per-job-id map). The interactive
//! pipeline route (routes/pipeline_interactive.rs) calls `wait(job_id)`
//! right before emitting `review_required` and awaits the returned
//! receiver; `POST /api/pipeline/:jobId/review-decision`
//! (routes/review_gate.rs, not yet ported) is meant to call `resolve`
//! once a human has decided. Kept as its own module, not inlined into
//! pipeline_interactive.rs, so that future route can depend on it without
//! depending on the whole interactive-route module.

use ignite_override_engine::SubmittedOverride;
use std::collections::HashMap;
use std::sync::Mutex;
use tokio::sync::oneshot;

#[derive(Debug, Clone, Default)]
pub struct Actor {
    pub email: String,
    pub name: String,
}

pub struct ReviewDecisionInput {
    pub proceed: bool,
    pub overrides: Vec<SubmittedOverride>,
    pub actor: Actor,
    /// How the deciding caller authenticated (`AuthMethod::origin`), recorded
    /// on any override this decision applies.
    pub origin: &'static str,
}

/// Outcome of [`ReviewGate::resolve`] — three distinct cases a caller
/// needs to render differently (404 vs. 403 vs. success), not just a
/// bool.
#[derive(Debug, PartialEq, Eq)]
pub enum ResolveOutcome {
    /// Delivered — a run was paused and waiting on this job id.
    Resolved,
    /// No run is currently paused under this job id.
    NotFound,
    /// A run is paused under this job id, but `caller_email` doesn't
    /// match the email that started it — anyone who can guess/observe a
    /// job id would otherwise be able to abort or force-proceed someone
    /// else's paused pipeline run (a DoS, or worse, a forced push to
    /// GitHub) with no relationship to that run at all.
    Forbidden,
}

#[derive(Default)]
pub struct ReviewGate {
    senders: Mutex<HashMap<String, (oneshot::Sender<ReviewDecisionInput>, String)>>,
}

impl ReviewGate {
    /// Registers a pending decision for `job_id`, recording `owner_email`
    /// (the authenticated caller who started this run) so a later
    /// [`Self::resolve`] can verify the same identity is the one deciding
    /// it. Returns the receiver half to await. Overwrites (and thereby
    /// drops/cancels) any prior unresolved wait for the same job id — a
    /// job id is only ever waited on once per run in practice.
    pub fn wait(&self, job_id: &str, owner_email: &str) -> oneshot::Receiver<ReviewDecisionInput> {
        let (tx, rx) = oneshot::channel();
        self.senders.lock().unwrap().insert(job_id.to_string(), (tx, owner_email.to_string()));
        rx
    }

    /// Delivers a decision to the run paused under `job_id`, first
    /// verifying `caller_email` matches the email that started it (see
    /// [`Self::wait`]).
    pub fn resolve(&self, job_id: &str, caller_email: &str, decision: ReviewDecisionInput) -> ResolveOutcome {
        let mut senders = self.senders.lock().unwrap();
        let Some((_, owner_email)) = senders.get(job_id) else { return ResolveOutcome::NotFound };
        if owner_email != caller_email {
            return ResolveOutcome::Forbidden;
        }
        let (tx, _) = senders.remove(job_id).expect("just checked above");
        if tx.send(decision).is_ok() {
            ResolveOutcome::Resolved
        } else {
            ResolveOutcome::NotFound
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolve_delivers_decision_to_matching_owner() {
        let gate = ReviewGate::default();
        let rx = gate.wait("job-1", "owner@example.com");
        let resolved = gate.resolve(
            "job-1",
            "owner@example.com",
            ReviewDecisionInput { proceed: true, overrides: vec![], actor: Actor { email: "a@example.com".into(), name: "A".into() }, origin: "session" },
        );
        assert_eq!(resolved, ResolveOutcome::Resolved);
        let decision = rx.await.unwrap();
        assert!(decision.proceed);
    }

    #[test]
    fn resolve_returns_not_found_for_unknown_job() {
        let gate = ReviewGate::default();
        assert_eq!(
            gate.resolve("nope", "a@example.com", ReviewDecisionInput { proceed: true, overrides: vec![], actor: Actor { email: "a@example.com".into(), name: "A".into() }, origin: "session" }),
            ResolveOutcome::NotFound
        );
    }

    #[tokio::test]
    async fn resolve_returns_forbidden_for_non_owner() {
        let gate = ReviewGate::default();
        let _rx = gate.wait("job-1", "owner@example.com");
        let resolved = gate.resolve(
            "job-1",
            "attacker@example.com",
            ReviewDecisionInput { proceed: true, overrides: vec![], actor: Actor { email: "attacker@example.com".into(), name: "Attacker".into() }, origin: "session" },
        );
        assert_eq!(resolved, ResolveOutcome::Forbidden);
    }
}
