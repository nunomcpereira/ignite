//! Candidate 1 of the architecture review (`architecture-review-*.html`):
//! deepens override submission into one module. `validate_overrides` and
//! `partition_for_dual_custody` (override-engine) already hold the pure
//! decision; five call sites — `routes/pipeline_validate.rs`,
//! `routes/pipeline_onboard.rs`, `routes/pipeline_interactive/run.rs`,
//! `routes/effectivate.rs`, `routes/project_overrides.rs` — each hand-wrote
//! the same sequence around it: partition, send a notification email for
//! whatever got auto-applied, persist (approved/pending rows, flip the
//! issue's status, with the email's real success/failure recorded on the
//! approved rows), and report the mapping every result needs.
//!
//! Split in two, matching the sequence every site already follows:
//! [`plan_overrides`] decides (no writes — reads `has_approved_override`/
//! `has_pending_override` only) so the caller can build and send its
//! notification email from `plan.applied` first, then [`persist_overrides`]
//! writes exactly that plan, with the real send result on the approved rows.
//!
//! Deliberately out of scope: the email itself and the audit event. Both
//! need machinery this crate doesn't have (`AppState::emit_audit_event`'s
//! SIEM dispatch, each site's own `phase_titles`/logger) and already differ
//! per site (`project_overrides.rs` is the one site that emails at all here
//! for a non-critical-only submission — every site does when `applied` is
//! non-empty; `pipeline_interactive/run.rs` doesn't currently audit).
//! `plan.newly_pending` exists precisely so a caller can drive its own
//! audit logic off "what actually changed this call" without re-deriving it.

use ignite_db_store::{AddOverrideArgs, DbStore};
use ignite_override_engine::{is_critical_score, partition_for_dual_custody, validate_overrides, AppliedOverride, Issue, SubmittedOverride};
use std::collections::HashSet;

pub struct PlanOverridesRequest {
    pub project_id: i64,
    /// `config.security.overrideApproval.enabled`.
    pub dual_custody_enabled: bool,
}

pub struct OverridesPlan<'a> {
    /// `false` when at least one still-open error-severity issue has no
    /// matching override — the caller must still block in that case.
    pub ok: bool,
    /// Blocking issues that stayed unresolved (no submitted override
    /// matched them, or none was submitted at all).
    pub unresolved_errors: Vec<&'a Issue>,
    /// To be approved and persisted by [`persist_overrides`].
    pub applied: Vec<AppliedOverride<'a>>,
    /// Every override waiting on a second reviewer, including ones a
    /// previous call already recorded — use this for a count/flag.
    pub needs_approval: Vec<AppliedOverride<'a>>,
    /// The subset of `needs_approval` not already pending — [`persist_overrides`]
    /// only ever writes these. Re-submitting an already-pending override
    /// changes nothing, so use this (not `needs_approval`) to decide what
    /// to audit/notify about.
    pub newly_pending: Vec<AppliedOverride<'a>>,
}

/// Validates `requested` against `still_open_issues` and applies dual-custody
/// partitioning when `req.dual_custody_enabled` — read-only (queries
/// `has_approved_override`/`has_pending_override`, writes nothing). Never
/// considers an issue not present in `still_open_issues` (the caller decides
/// what "still open" means — every existing call site filters out
/// `status == "overridden"` first).
pub fn plan_overrides<'a>(db: &DbStore, still_open_issues: &'a [Issue], requested: &[SubmittedOverride], req: &PlanOverridesRequest) -> OverridesPlan<'a> {
    let validation = validate_overrides(still_open_issues, requested);

    let (applied, needs_approval) = if req.dual_custody_enabled {
        let already_approved: HashSet<String> = validation.applied.iter().filter(|(issue, _)| db.has_approved_override(req.project_id, &issue.id)).map(|(issue, _)| issue.id.clone()).collect();
        partition_for_dual_custody(validation.applied.clone(), |issue| is_critical_score(issue.score), &already_approved)
    } else {
        (validation.applied.clone(), Vec::new())
    };

    let newly_pending: Vec<AppliedOverride<'a>> = needs_approval.iter().filter(|(issue, _)| !db.has_pending_override(req.project_id, &issue.id)).cloned().collect();

    OverridesPlan { ok: validation.ok, unresolved_errors: validation.unresolved_errors, applied, needs_approval, newly_pending }
}

pub struct PersistOverridesRequest<'a> {
    pub project_id: i64,
    pub job_id: &'a str,
    pub phase: i64,
    pub actor_email: &'a str,
    pub actor_name: &'a str,
    /// See `auth::AuthMethod::origin()` — 'session', 'api_key', 'system', ...
    pub origin: &'static str,
    /// Whether the notification email the caller sent for `plan.applied`
    /// actually went out — recorded on every approved row this call writes.
    /// Irrelevant (and ignored) when `plan.applied` is empty.
    pub email_sent: bool,
}

/// Writes exactly what `plan` says: an approved override flips its issue to
/// `overridden`; only `plan.newly_pending` (never a `needs_approval` entry
/// that was already pending) gets a new pending row.
pub fn persist_overrides(db: &DbStore, plan: &OverridesPlan, req: &PersistOverridesRequest) {
    for (issue, justification) in &plan.applied {
        db.add_override_with_origin(override_args(issue, justification, req, req.email_sent), req.origin);
        db.set_issue_status(req.project_id, &issue.id, "overridden");
    }
    for (issue, justification) in &plan.newly_pending {
        db.add_pending_override_with_origin(override_args(issue, justification, req, false), req.origin);
    }
}

fn override_args<'a>(issue: &'a Issue, justification: &'a str, req: &'a PersistOverridesRequest, email_sent: bool) -> AddOverrideArgs<'a> {
    AddOverrideArgs {
        project_id: req.project_id,
        job_id: req.job_id,
        phase: req.phase,
        issue_id: &issue.id,
        category: &issue.category,
        severity: severity_str(issue),
        summary: &issue.summary,
        file: issue.file.as_deref(),
        line: issue.line,
        justification,
        actor_email: req.actor_email,
        actor_name: Some(req.actor_name),
        email_sent,
    }
}

/// [`plan_overrides`] + [`persist_overrides`] in one call, for a caller that
/// never sends a notification email (so `email_sent` is always `false`).
pub fn submit_overrides<'a>(db: &DbStore, still_open_issues: &'a [Issue], requested: &[SubmittedOverride], plan_req: &PlanOverridesRequest, persist_req: &PersistOverridesRequest) -> OverridesPlan<'a> {
    let plan = plan_overrides(db, still_open_issues, requested, plan_req);
    persist_overrides(db, &plan, persist_req);
    plan
}

fn severity_str(issue: &Issue) -> &'static str {
    match issue.severity {
        ignite_override_engine::Severity::Error => "error",
        ignite_override_engine::Severity::Warning => "warning",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ignite_override_engine::Severity;

    fn issue(id: &str, category: &str, severity: Severity, score: i32) -> Issue {
        Issue { id: id.to_string(), category: category.to_string(), severity, score, summary: format!("summary of {id}"), file: Some("app.js".to_string()), line: Some(1), snippet: None, cross_file: false, chain: None, cwe: None, owasp: None, tool: Some("built-in".to_string()), references: Default::default(), duplicate_ref: None }
    }

    fn submitted(id: &str) -> SubmittedOverride {
        SubmittedOverride { issue_id: id.to_string(), justification: "reviewed and accepted".to_string(), code: None }
    }

    fn open_test_db() -> (DbStore, i64, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = DbStore::open(&dir.path().join("test.db")).unwrap();
        let project_id = db.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        (db, project_id, dir)
    }

    /// `set_issue_status` (called by `persist_overrides`) only affects a row
    /// already in `issues`, so an assertion against `db.get_project_issues`
    /// needs the issue seeded first — exactly what every real caller already
    /// does before calling into this module.
    fn seed_issue(db: &DbStore, project_id: i64, issue: &Issue) {
        db.replace_project_issues(
            project_id,
            &[ignite_db_store::IssueInput { id: issue.id.clone(), phase: Some(4), category: issue.category.clone(), severity: severity_str(issue).to_string(), score: Some(issue.score as i64), summary: issue.summary.clone(), file: issue.file.clone(), line: issue.line, snippet: None, cross_file: false, chain: None, cwe: None, owasp: None, tool: None, references: None, duplicate_ref: None }],
            &HashSet::new(),
        );
    }

    fn plan_req(project_id: i64, dual_custody_enabled: bool) -> PlanOverridesRequest {
        PlanOverridesRequest { project_id, dual_custody_enabled }
    }

    fn persist_req(project_id: i64, email_sent: bool) -> PersistOverridesRequest<'static> {
        PersistOverridesRequest { project_id, job_id: "job-1", phase: 4, actor_email: "owner@example.com", actor_name: "Owner", origin: "api_key", email_sent }
    }

    #[test]
    fn a_non_critical_override_is_applied_at_once_and_persisted_with_severity_origin_and_the_real_email_result() {
        let (db, pid, _dir) = open_test_db();
        let issues = vec![issue("secret::app.js::1", "secret", Severity::Warning, 3)];
        seed_issue(&db, pid, &issues[0]);
        let out = submit_overrides(&db, &issues, &[submitted("secret::app.js::1")], &plan_req(pid, true), &persist_req(pid, true));
        assert!(out.ok);
        assert_eq!(out.applied.len(), 1);
        assert!(out.needs_approval.is_empty());
        let rows = db.get_project_overrides(pid);
        assert_eq!((rows[0].severity.as_str(), rows[0].origin.as_str(), rows[0].actor_email.as_str(), rows[0].email_sent), ("warning", "api_key", "owner@example.com", true));
        assert_eq!(db.get_project_issues(pid).into_iter().find(|i| i.id == "secret::app.js::1").map(|i| i.status), Some("overridden".to_string()));
    }

    #[test]
    fn a_failed_send_is_recorded_as_email_sent_false() {
        let (db, pid, _dir) = open_test_db();
        let issues = vec![issue("secret::app.js::1", "secret", Severity::Warning, 3)];
        submit_overrides(&db, &issues, &[submitted("secret::app.js::1")], &plan_req(pid, true), &persist_req(pid, false));
        assert!(!db.get_project_overrides(pid)[0].email_sent);
    }

    #[test]
    fn a_critical_override_waits_when_dual_custody_is_on_and_applies_at_once_when_off() {
        let critical = issue("secret::app.js::1", "secret", Severity::Error, 10);
        let (db, pid, _dir) = open_test_db();
        let out = submit_overrides(&db, std::slice::from_ref(&critical), &[submitted("secret::app.js::1")], &plan_req(pid, true), &persist_req(pid, true));
        assert!(out.applied.is_empty());
        assert_eq!(out.needs_approval.len(), 1);
        assert_eq!(out.newly_pending.len(), 1);
        assert!(db.get_project_overrides(pid).is_empty());
        let pending = db.list_pending_overrides(pid);
        assert_eq!(pending.len(), 1);
        assert!(!pending[0].origin.is_empty());

        let (db2, pid2, _dir2) = open_test_db();
        let out2 = submit_overrides(&db2, std::slice::from_ref(&critical), &[submitted("secret::app.js::1")], &plan_req(pid2, false), &persist_req(pid2, true));
        assert_eq!(out2.applied.len(), 1);
        assert!(out2.needs_approval.is_empty());
    }

    #[test]
    fn resubmitting_a_pending_override_reports_it_but_does_not_duplicate_or_re_report_it_as_new() {
        let critical = issue("secret::app.js::1", "secret", Severity::Error, 10);
        let (db, pid, _dir) = open_test_db();
        submit_overrides(&db, std::slice::from_ref(&critical), &[submitted("secret::app.js::1")], &plan_req(pid, true), &persist_req(pid, true));
        let second = plan_overrides(&db, std::slice::from_ref(&critical), &[submitted("secret::app.js::1")], &plan_req(pid, true));
        assert_eq!(second.needs_approval.len(), 1, "still reported for the count/flag");
        assert!(second.newly_pending.is_empty(), "but not newly pending — nothing to (re-)audit");
        persist_overrides(&db, &second, &persist_req(pid, true));
        assert_eq!(db.list_pending_overrides(pid).len(), 1, "and not duplicated");
    }

    #[test]
    fn an_already_approved_critical_issue_is_auto_applied_not_held_again() {
        let critical = issue("secret::app.js::1", "secret", Severity::Error, 10);
        let (db, pid, _dir) = open_test_db();
        db.add_override(AddOverrideArgs { project_id: pid, job_id: "job-1", phase: 4, issue_id: &critical.id, category: &critical.category, severity: "error", summary: &critical.summary, file: critical.file.as_deref(), line: critical.line, justification: "already approved earlier", actor_email: "reviewer@example.com", actor_name: None, email_sent: false });
        let plan = plan_overrides(&db, std::slice::from_ref(&critical), &[submitted("secret::app.js::1")], &plan_req(pid, true));
        assert_eq!(plan.applied.len(), 1, "an issue already approved for this project doesn't need a second reviewer again");
        assert!(plan.needs_approval.is_empty());
    }

    #[test]
    fn an_unmatched_or_missing_override_leaves_the_issue_unresolved() {
        let (db, pid, _dir) = open_test_db();
        let issues = vec![issue("secret::app.js::1", "secret", Severity::Error, 10)];
        let out = plan_overrides(&db, &issues, &[], &plan_req(pid, false));
        assert!(!out.ok);
        assert_eq!(out.unresolved_errors.len(), 1);
        assert!(out.applied.is_empty());

        let out = plan_overrides(&db, &issues, &[submitted("nothing::matches::1")], &plan_req(pid, false));
        assert!(!out.ok);
        assert_eq!(out.unresolved_errors.len(), 1);
    }

    #[test]
    fn a_warning_severity_issue_never_counts_as_unresolved() {
        let (db, pid, _dir) = open_test_db();
        let issues = vec![issue("quality::app.js::1", "quality", Severity::Warning, 2)];
        let out = plan_overrides(&db, &issues, &[], &plan_req(pid, false));
        assert!(out.ok, "no submitted override, but nothing blocking either");
        assert!(out.unresolved_errors.is_empty());
    }

    #[test]
    fn one_call_can_apply_the_non_critical_half_and_hold_the_critical_half() {
        let (db, pid, _dir) = open_test_db();
        let issues = vec![issue("secret::app.js::1", "secret", Severity::Error, 10), issue("security::app.js::1", "security", Severity::Error, 5)];
        let out = plan_overrides(&db, &issues, &[submitted("secret::app.js::1"), submitted("security::app.js::1")], &plan_req(pid, true));
        assert_eq!(out.applied.len(), 1);
        assert_eq!(out.applied[0].0.id, "security::app.js::1");
        assert_eq!(out.needs_approval.len(), 1);
        assert_eq!(out.needs_approval[0].0.id, "secret::app.js::1");
    }
}
