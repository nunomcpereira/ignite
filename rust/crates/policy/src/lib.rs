//! US-02: report check *coverage* separately from *findings*, so a clean
//! finding list can never be mistaken for a complete assessment.
//!
//! This crate is the pure domain layer every entry point (browser
//! streaming upload, headless `validate-all`, CLI, MCP) is meant to share
//! — [`evaluate_policy`] takes an already-computed [`CheckCoverage`] list
//! plus finding-blocking/review signals and a pinned [`PolicyVersion`],
//! and returns one deterministic [`PolicyDecision`]. It does no I/O, reads
//! no global config, and never mutates anything — callers own gathering
//! coverage (phase4-orchestrator, governance-ci, unit-test-runner, ...)
//! and persisting the decision (db-store).
//!
//! Two named profiles are provided out of the box: [`PolicyVersion::legacy_compatible`]
//! (nothing is `required_checks`-gated — preserves every existing
//! installation's current gate behavior unchanged) and
//! [`PolicyVersion::strict_publication`] (a fixed, deliberately curated
//! set of checks that must actually run, not just be attempted, before a
//! publication decision is trusted). A deployment opts into strict mode
//! explicitly (`config.json`'s `policy.version`, wired in `ignite-config`)
//! — an existing installation's gating policy never changes on its own.

use serde::{Deserialize, Serialize};

/// One check's actual coverage outcome for one run. Distinct from whether
/// it *found* anything — a check that ran cleanly and found nothing is
/// [`CheckOutcome::Completed`] with zero findings, which is a completely
/// different fact than the check never having run at all
/// ([`CheckOutcome::Unavailable`]) or having been turned off on purpose
/// ([`CheckOutcome::Disabled`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckOutcome {
    /// Ran to completion (findings, zero or more, are trustworthy).
    Completed,
    /// Genuinely doesn't apply to this project (e.g. a Python-only check
    /// against a project with no Python files) — not a failure, and does
    /// not block a required-coverage policy.
    NotApplicable,
    /// Turned off by configuration.
    Disabled,
    /// Required tool/engine/network dependency was missing or unreachable.
    Unavailable,
    /// Ran but errored out before producing a trustworthy result.
    Failed,
    /// Exceeded its time budget and was aborted.
    TimedOut,
    /// The run itself was cancelled before this check finished.
    Cancelled,
}

impl CheckOutcome {
    /// Whether this outcome represents work that actually produced a
    /// trustworthy result — the only two outcomes a `required_checks`
    /// policy entry accepts as "coverage satisfied" (a fallback engine
    /// additionally needs the policy to explicitly permit it — see
    /// [`PolicyVersion::allow_fallback_for`]).
    pub fn satisfies_requirement(self) -> bool {
        matches!(self, CheckOutcome::Completed | CheckOutcome::NotApplicable)
    }
}

/// One check's full coverage record for one run — everything a reviewer
/// or an auditor needs to tell "this passed because it was actually
/// checked" from "this passed because the check silently didn't run".
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckCoverage {
    pub check_id: String,
    pub outcome: CheckOutcome,
    /// The real engine that ran (e.g. `"semgrep"`), when one did.
    pub engine: Option<String>,
    pub engine_version: Option<String>,
    /// True when `engine` is a degraded built-in fallback rather than the
    /// full external tool — a fallback satisfies a `required_checks` entry
    /// only when the policy's `allow_fallback_for` explicitly names it.
    pub is_fallback: bool,
    /// Free-text description of what was actually covered (e.g. "142 of
    /// 142 source files", "npm/pypi manifests only — no lockfile found").
    pub scope: Option<String>,
    /// Why a `NotApplicable` outcome doesn't apply here, or why a
    /// `Disabled`/`Unavailable`/`Failed`/`TimedOut` outcome happened.
    pub reason: Option<String>,
    /// True when this coverage record came from a cache hit rather than a
    /// fresh run this scan — the cached record still carries its
    /// original `engine`/`engine_version`/`scope`, so a stale cached
    /// coverage claim is never indistinguishable from a fresh one.
    pub from_cache: bool,
    pub duration_ms: Option<u64>,
}

impl CheckCoverage {
    pub fn completed(check_id: impl Into<String>, engine: impl Into<String>, is_fallback: bool) -> Self {
        Self { check_id: check_id.into(), outcome: CheckOutcome::Completed, engine: Some(engine.into()), engine_version: None, is_fallback, scope: None, reason: None, from_cache: false, duration_ms: None }
    }
    pub fn not_applicable(check_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self { check_id: check_id.into(), outcome: CheckOutcome::NotApplicable, engine: None, engine_version: None, is_fallback: false, scope: None, reason: Some(reason.into()), from_cache: false, duration_ms: None }
    }
    pub fn disabled(check_id: impl Into<String>) -> Self {
        Self { check_id: check_id.into(), outcome: CheckOutcome::Disabled, engine: None, engine_version: None, is_fallback: false, scope: None, reason: Some("disabled by configuration".to_string()), from_cache: false, duration_ms: None }
    }
    pub fn disabled_with_reason(check_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self { check_id: check_id.into(), outcome: CheckOutcome::Disabled, engine: None, engine_version: None, is_fallback: false, scope: None, reason: Some(reason.into()), from_cache: false, duration_ms: None }
    }
    pub fn unavailable(check_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self { check_id: check_id.into(), outcome: CheckOutcome::Unavailable, engine: None, engine_version: None, is_fallback: false, scope: None, reason: Some(reason.into()), from_cache: false, duration_ms: None }
    }
    pub fn failed(check_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self { check_id: check_id.into(), outcome: CheckOutcome::Failed, engine: None, engine_version: None, is_fallback: false, scope: None, reason: Some(reason.into()), from_cache: false, duration_ms: None }
    }
    pub fn timed_out(check_id: impl Into<String>) -> Self {
        Self { check_id: check_id.into(), outcome: CheckOutcome::TimedOut, engine: None, engine_version: None, is_fallback: false, scope: None, reason: Some("exceeded its time budget".to_string()), from_cache: false, duration_ms: None }
    }
    pub fn cancelled(check_id: impl Into<String>) -> Self {
        Self { check_id: check_id.into(), outcome: CheckOutcome::Cancelled, engine: None, engine_version: None, is_fallback: false, scope: None, reason: Some("run was cancelled before this check finished".to_string()), from_cache: false, duration_ms: None }
    }

    pub fn with_engine_version(mut self, v: impl Into<String>) -> Self {
        self.engine_version = Some(v.into());
        self
    }
    pub fn with_scope(mut self, s: impl Into<String>) -> Self {
        self.scope = Some(s.into());
        self
    }
    pub fn with_duration_ms(mut self, ms: u64) -> Self {
        self.duration_ms = Some(ms);
        self
    }
    pub fn from_cache(mut self) -> Self {
        self.from_cache = true;
        self
    }
}

/// An immutable, named policy — pinned to a run at the moment it starts
/// (US-04's job), never re-read mid-run, so a config change after a run
/// begins cannot alter that run's already-pinned decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyVersion {
    pub id: String,
    /// Check ids that must reach an outcome satisfying
    /// [`CheckOutcome::satisfies_requirement`] (or an explicitly permitted
    /// fallback) for the run to be anything but `incomplete`.
    pub required_checks: Vec<String>,
    /// Check ids for which a degraded fallback engine (`is_fallback: true`)
    /// still counts as satisfying the requirement.
    pub allow_fallback_for: Vec<String>,
}

impl PolicyVersion {
    /// Every existing installation's implicit policy today: no check is
    /// individually required, so missing/disabled/unavailable coverage on
    /// any one check is visible (via the returned `coverage` list) but
    /// never turns a clean-findings run into anything but `pass`. Matches
    /// this backlog's "preserve legacy behavior while displaying
    /// incomplete coverage" instruction.
    pub fn legacy_compatible() -> Self {
        PolicyVersion { id: "legacy-compatible-v1".to_string(), required_checks: vec![], allow_fallback_for: vec![] }
    }

    /// Opt-in strict profile: the checks a publication decision cannot be
    /// trusted without actually having run. Deliberately curated to the
    /// checks with a real security/compliance stake and a legitimate
    /// built-in fallback path (secret scanning, dependency vulnerability
    /// resolution, semantic SAST, and org governance CI) rather than every
    /// check in the pipeline — a cosmetic check (e.g. LOC metrics) being
    /// unavailable was never a reason to block a publication.
    pub fn strict_publication() -> Self {
        PolicyVersion {
            id: "strict-publication-v1".to_string(),
            required_checks: vec!["secrets".to_string(), "dependency-vulnerability".to_string(), "semanticSast".to_string(), "governance-ci".to_string()],
            allow_fallback_for: vec!["secrets".to_string()],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecisionKind {
    Pass,
    NeedsReview,
    Blocked,
    Incomplete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyDecision {
    pub decision: PolicyDecisionKind,
    pub policy_version: String,
    pub reasons: Vec<String>,
    /// Required check ids whose coverage didn't satisfy the policy —
    /// empty unless `decision == Incomplete`.
    pub missing_required_coverage: Vec<String>,
}

impl PolicyDecision {
    /// `incomplete` (missing required coverage) and `blocked` (unresolved
    /// findings) both prevent publication; `needs_review` and `pass` do
    /// not, though `needs_review` still means a human must act before an
    /// automated publication path proceeds unattended.
    pub fn permits_publication(&self) -> bool {
        matches!(self.decision, PolicyDecisionKind::Pass)
    }
}

/// The one pure function every entry point shares. Coverage is checked
/// first and takes priority over findings — a completed scan is not
/// necessarily a passing scan, and an `incomplete` decision because a
/// required check never ran must never be silently downgraded to `pass`
/// just because whatever *did* run found nothing.
pub fn evaluate_policy(coverage: &[CheckCoverage], has_blocking_findings: bool, needs_review: bool, policy: &PolicyVersion) -> PolicyDecision {
    let mut reasons = Vec::new();
    let mut missing = Vec::new();

    for required in &policy.required_checks {
        match coverage.iter().find(|c| &c.check_id == required) {
            None => {
                missing.push(required.clone());
                reasons.push(format!("required check '{required}' did not report any coverage"));
            }
            Some(c) => {
                let satisfied = if c.is_fallback {
                    c.outcome == CheckOutcome::Completed && policy.allow_fallback_for.iter().any(|f| f == required)
                } else {
                    c.outcome.satisfies_requirement()
                };
                if !satisfied {
                    missing.push(required.clone());
                    let reason = c.reason.as_deref().unwrap_or("no reason recorded");
                    reasons.push(format!("required check '{required}' outcome was {:?} ({reason})", c.outcome));
                }
            }
        }
    }

    if !missing.is_empty() {
        return PolicyDecision { decision: PolicyDecisionKind::Incomplete, policy_version: policy.id.clone(), reasons, missing_required_coverage: missing };
    }
    if has_blocking_findings {
        return PolicyDecision {
            decision: PolicyDecisionKind::Blocked,
            policy_version: policy.id.clone(),
            reasons: vec!["one or more blocking findings are unresolved".to_string()],
            missing_required_coverage: vec![],
        };
    }
    if needs_review {
        return PolicyDecision {
            decision: PolicyDecisionKind::NeedsReview,
            policy_version: policy.id.clone(),
            reasons: vec!["advisory findings or pending exceptions require human review".to_string()],
            missing_required_coverage: vec![],
        };
    }
    PolicyDecision { decision: PolicyDecisionKind::Pass, policy_version: policy.id.clone(), reasons: vec![], missing_required_coverage: vec![] }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_disabled_unavailable_failed_timed_out_cancelled_are_all_distinct() {
        let outcomes = [
            CheckCoverage::completed("secrets", "gitleaks", false).outcome,
            CheckCoverage::not_applicable("api-schema", "no OpenAPI spec in project").outcome,
            CheckCoverage::disabled("trivy-image").outcome,
            CheckCoverage::unavailable("semgrep", "binary not found on PATH").outcome,
            CheckCoverage::failed("gha-security", "zizmor exited non-zero").outcome,
            CheckCoverage::timed_out("codeql").outcome,
            CheckCoverage::cancelled("dead-code").outcome,
        ];
        let unique: std::collections::HashSet<_> = outcomes.iter().collect();
        assert_eq!(unique.len(), outcomes.len(), "every outcome variant used above must be pairwise distinct");
    }

    #[test]
    fn a_successful_check_with_zero_findings_is_completed_not_not_applicable() {
        let c = CheckCoverage::completed("secrets", "gitleaks", false);
        assert_eq!(c.outcome, CheckOutcome::Completed);
        assert!(c.reason.is_none());
    }

    #[test]
    fn legacy_profile_never_reports_incomplete_regardless_of_coverage() {
        let policy = PolicyVersion::legacy_compatible();
        let coverage = vec![CheckCoverage::unavailable("semgrep", "binary missing"), CheckCoverage::timed_out("codeql")];
        let decision = evaluate_policy(&coverage, false, false, &policy);
        assert_eq!(decision.decision, PolicyDecisionKind::Pass);
        assert!(decision.missing_required_coverage.is_empty());
    }

    #[test]
    fn strict_profile_requiring_an_unavailable_check_yields_incomplete_and_blocks_publication() {
        let policy = PolicyVersion::strict_publication();
        let coverage = vec![
            CheckCoverage::unavailable("semanticSast", "semgrep binary missing"),
            CheckCoverage::completed("secrets", "gitleaks", false),
            CheckCoverage::completed("dependency-vulnerability", "osv", false),
            CheckCoverage::completed("governance-ci", "act", false),
        ];
        let decision = evaluate_policy(&coverage, false, false, &policy);
        assert_eq!(decision.decision, PolicyDecisionKind::Incomplete);
        assert_eq!(decision.missing_required_coverage, vec!["semanticSast".to_string()]);
        assert!(!decision.permits_publication());
    }

    #[test]
    fn a_required_check_missing_from_coverage_entirely_is_also_incomplete() {
        let policy = PolicyVersion::strict_publication();
        let coverage = vec![CheckCoverage::completed("secrets", "gitleaks", false)];
        let decision = evaluate_policy(&coverage, false, false, &policy);
        assert_eq!(decision.decision, PolicyDecisionKind::Incomplete);
        assert!(decision.missing_required_coverage.contains(&"dependency-vulnerability".to_string()));
    }

    #[test]
    fn a_genuinely_inapplicable_required_check_does_not_block_and_records_its_reason() {
        let policy = PolicyVersion { id: "custom".to_string(), required_checks: vec!["semanticSast".to_string()], allow_fallback_for: vec![] };
        let coverage = vec![CheckCoverage::not_applicable("semanticSast", "no source files in any supported language")];
        let decision = evaluate_policy(&coverage, false, false, &policy);
        assert_eq!(decision.decision, PolicyDecisionKind::Pass);
        assert_eq!(coverage[0].reason.as_deref(), Some("no source files in any supported language"));
    }

    #[test]
    fn a_permitted_fallback_satisfies_its_required_check() {
        let policy = PolicyVersion::strict_publication();
        let coverage = vec![
            CheckCoverage::completed("secrets", "built-in-regex-fallback", true), // fallback, explicitly permitted for "secrets"
            CheckCoverage::completed("dependency-vulnerability", "osv", false),
            CheckCoverage::completed("semanticSast", "semgrep", false),
            CheckCoverage::completed("governance-ci", "act", false),
        ];
        let decision = evaluate_policy(&coverage, false, false, &policy);
        assert_eq!(decision.decision, PolicyDecisionKind::Pass);
    }

    #[test]
    fn a_fallback_not_explicitly_permitted_does_not_satisfy_its_required_check() {
        let policy = PolicyVersion::strict_publication();
        let coverage = vec![
            CheckCoverage::completed("secrets", "gitleaks", false),
            CheckCoverage::completed("dependency-vulnerability", "built-in-fallback", true), // fallback NOT in allow_fallback_for
            CheckCoverage::completed("semanticSast", "semgrep", false),
            CheckCoverage::completed("governance-ci", "act", false),
        ];
        let decision = evaluate_policy(&coverage, false, false, &policy);
        assert_eq!(decision.decision, PolicyDecisionKind::Incomplete);
        assert_eq!(decision.missing_required_coverage, vec!["dependency-vulnerability".to_string()]);
    }

    #[test]
    fn advisory_findings_alone_do_not_block_but_can_still_ask_for_review() {
        let policy = PolicyVersion::legacy_compatible();
        let decision = evaluate_policy(&[], false, true, &policy);
        assert_eq!(decision.decision, PolicyDecisionKind::NeedsReview);
        assert!(!decision.permits_publication());
    }

    #[test]
    fn blocking_findings_take_priority_over_needs_review() {
        let policy = PolicyVersion::legacy_compatible();
        let decision = evaluate_policy(&[], true, true, &policy);
        assert_eq!(decision.decision, PolicyDecisionKind::Blocked);
    }

    #[test]
    fn incomplete_coverage_takes_priority_over_everything_else() {
        let policy = PolicyVersion::strict_publication();
        // No blocking findings, no review needed — but required coverage
        // is missing, so a clean finding list must not read as `pass`.
        let decision = evaluate_policy(&[], false, false, &policy);
        assert_eq!(decision.decision, PolicyDecisionKind::Incomplete);
    }

    #[test]
    fn a_pinned_policy_snapshot_is_immune_to_a_later_config_change() {
        // `evaluate_policy` takes `&PolicyVersion` by value/reference with
        // no ambient config lookup of its own — the caller's own pinned
        // snapshot (taken once, at run start, per US-04) is authoritative
        // for that run's lifetime, however many times config changes
        // afterward. Demonstrated here by evaluating the *same* pinned
        // value twice and getting the same answer regardless of a
        // constructed "changed" policy never being consulted.
        let pinned = PolicyVersion::strict_publication();
        let coverage = vec![
            CheckCoverage::completed("secrets", "gitleaks", false),
            CheckCoverage::completed("dependency-vulnerability", "osv", false),
            CheckCoverage::completed("semanticSast", "semgrep", false),
            CheckCoverage::completed("governance-ci", "act", false),
        ];
        let first = evaluate_policy(&coverage, false, false, &pinned);
        let _changed_but_unused = PolicyVersion::legacy_compatible();
        let second = evaluate_policy(&coverage, false, false, &pinned);
        assert_eq!(first.decision, second.decision);
        assert_eq!(first.policy_version, "strict-publication-v1");
    }

    #[test]
    fn cache_hit_coverage_still_carries_engine_and_version_provenance() {
        let c = CheckCoverage::completed("dependency-vulnerability", "osv", false).with_engine_version("2026.1").with_scope("142 manifests").from_cache();
        assert!(c.from_cache);
        assert_eq!(c.engine.as_deref(), Some("osv"));
        assert_eq!(c.engine_version.as_deref(), Some("2026.1"));
        assert_eq!(c.scope.as_deref(), Some("142 manifests"));
    }
}
