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

#[derive(Debug, Clone)]
pub struct Actor {
    pub email: String,
    pub name: String,
}

pub struct ReviewDecisionInput {
    pub proceed: bool,
    pub overrides: Vec<SubmittedOverride>,
    pub actor: Actor,
}

#[derive(Default)]
pub struct ReviewGate {
    senders: Mutex<HashMap<String, oneshot::Sender<ReviewDecisionInput>>>,
}

impl ReviewGate {
    /// Registers a pending decision for `job_id` and returns the receiver
    /// half to await. Overwrites (and thereby drops/cancels) any prior
    /// unresolved wait for the same job id — a job id is only ever waited
    /// on once per run in practice.
    pub fn wait(&self, job_id: &str) -> oneshot::Receiver<ReviewDecisionInput> {
        let (tx, rx) = oneshot::channel();
        self.senders.lock().unwrap().insert(job_id.to_string(), tx);
        rx
    }

    /// Delivers a decision to the run paused under `job_id`. Returns
    /// `false` if no run is currently waiting on this job id (already
    /// resolved, or never reached the gate) — the caller should surface
    /// that as a 404, same as server.js's `if (!reviewDecisions.resolve(...))`.
    pub fn resolve(&self, job_id: &str, decision: ReviewDecisionInput) -> bool {
        match self.senders.lock().unwrap().remove(job_id) {
            Some(tx) => tx.send(decision).is_ok(),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolve_delivers_decision_to_waiter() {
        let gate = ReviewGate::default();
        let rx = gate.wait("job-1");
        let resolved = gate.resolve(
            "job-1",
            ReviewDecisionInput { proceed: true, overrides: vec![], actor: Actor { email: "a@example.com".into(), name: "A".into() } },
        );
        assert!(resolved);
        let decision = rx.await.unwrap();
        assert!(decision.proceed);
    }

    #[test]
    fn resolve_returns_false_for_unknown_job() {
        let gate = ReviewGate::default();
        assert!(!gate.resolve("nope", ReviewDecisionInput { proceed: true, overrides: vec![], actor: Actor { email: "a@example.com".into(), name: "A".into() } }));
    }
}
