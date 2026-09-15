//! Row/input/output types returned by `DbStore`'s methods — split out of
//! lib.rs so the accessor methods (see the per-domain modules) aren't
//! interleaved with their own return-type definitions.

use serde::Serialize;

// --- row types ------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct ProjectListRow {
    pub id: i64,
    pub job_id: String,
    pub org: String,
    pub repo: String,
    pub gxp: bool,
    pub source: String,
    pub scan_location: Option<String>,
    pub status: String,
    pub error: Option<String>,
    pub repo_url: Option<String>,
    pub pr_url: Option<String>,
    pub created_at: String,
    pub finished_at: Option<String>,
    pub doc_count: i64,
    pub issue_count: i64,
    pub retained: bool,
    pub retained_tier: Option<String>,
    pub source_commit_sha: Option<String>,
    pub shipped_commit_sha: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Project {
    pub id: i64,
    pub org: String,
    pub repo: String,
    pub gxp: bool,
    pub source: String,
    pub scan_location: Option<String>,
    pub status: String,
    pub error: Option<String>,
    pub repo_url: Option<String>,
    pub pr_url: Option<String>,
    pub created_at: String,
    pub finished_at: Option<String>,
    pub source_commit_sha: Option<String>,
    pub shipped_commit_sha: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Step {
    pub phase: i64,
    pub title: String,
    pub state: String,
    pub logs: String,
    /// Phase 4 only: `phase4-orchestrator`'s per-check timings as a JSON
    /// array of `{name, ms}`, serialized already — the client parses it,
    /// this layer doesn't need to know its shape. `None` for every other
    /// phase and for any phase-4 row written before this column existed.
    pub task_timings: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DocumentSummary {
    pub id: i64,
    pub kind: String,
    pub name: String,
    pub url: Option<String>,
    pub mime: Option<String>,
    pub size: Option<i64>,
    pub created_at: String,
}

pub struct DocumentDownload {
    pub kind: String,
    pub name: String,
    pub url: Option<String>,
    pub mime: Option<String>,
    pub data: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OverrideRow {
    pub id: i64,
    pub phase: i64,
    pub issue_id: String,
    pub category: String,
    pub severity: String,
    pub summary: String,
    pub file: Option<String>,
    pub line: Option<i64>,
    pub justification: String,
    pub actor_email: String,
    pub actor_name: Option<String>,
    pub email_sent: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectDetails {
    #[serde(flatten)]
    pub project: Project,
    pub steps: Vec<Step>,
    pub documents: Vec<DocumentSummary>,
    pub overrides: Vec<OverrideRow>,
}

/// A not-yet-approved override — dual-custody for critical-severity
/// findings (see `overrides.rs`'s `add_pending_override`). Distinct from
/// [`OverrideRow`] (which every existing reader already assumes resolves
/// its issue) so a pending row can never accidentally be treated as
/// "this issue is handled" by code that hasn't been updated to check
/// `status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PendingOverrideRow {
    pub id: i64,
    pub project_id: i64,
    pub job_id: String,
    pub issue_id: String,
    pub category: String,
    pub severity: String,
    pub summary: String,
    pub file: Option<String>,
    pub line: Option<i64>,
    pub justification: String,
    pub actor_email: String,
    pub actor_name: Option<String>,
    pub created_at: String,
}

pub struct AddOverrideArgs<'a> {
    pub project_id: i64,
    pub job_id: &'a str,
    pub phase: i64,
    pub issue_id: &'a str,
    pub category: &'a str,
    pub severity: &'a str,
    pub summary: &'a str,
    pub file: Option<&'a str>,
    pub line: Option<i64>,
    pub justification: &'a str,
    pub actor_email: &'a str,
    pub actor_name: Option<&'a str>,
    pub email_sent: bool,
}

/// Mirrors the loose JS `issue` shape (`{ id, phase, category, severity,
/// score, summary, file, line, snippet, crossFile, chain, cwe }`) passed
/// into `replaceProjectIssues`.
#[derive(Debug, Clone)]
pub struct IssueInput {
    pub id: String,
    pub phase: Option<i64>,
    pub category: String,
    pub severity: String,
    pub score: Option<i64>,
    pub summary: String,
    pub file: Option<String>,
    pub line: Option<i64>,
    pub snippet: Option<serde_json::Value>,
    pub cross_file: bool,
    pub chain: Option<serde_json::Value>,
    pub cwe: Option<String>,
    pub owasp: Option<String>,
    pub tool: Option<String>,
    /// Serialized `ignite_override_engine::IssueReferences` — kept as a
    /// loose JSON blob here (same as `snippet`/`chain`) so db-store doesn't
    /// need a dependency on override-engine's types just to round-trip them.
    pub references: Option<serde_json::Value>,
    /// A code-duplication finding's "also found at" pointer (`{file, line,
    /// endLine}`) — same loose-JSON-blob treatment as `snippet`/`chain`.
    pub duplicate_ref: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueRow {
    pub id: String,
    pub phase: Option<i64>,
    pub category: String,
    pub severity: String,
    pub score: Option<i64>,
    pub summary: String,
    pub file: Option<String>,
    pub line: Option<i64>,
    pub snippet: Option<serde_json::Value>,
    pub cross_file: bool,
    pub chain: Option<serde_json::Value>,
    pub cwe: Option<String>,
    pub owasp: Option<String>,
    pub tool: Option<String>,
    pub references: Option<serde_json::Value>,
    pub duplicate_ref: Option<serde_json::Value>,
    pub status: String,
    pub created_at: String,
    /// The most recent override's justification/actor when `status ==
    /// "overridden"`, `None` otherwise — joined in from `overrides` at read
    /// time (`get_project_issues`) rather than stored on the issue row
    /// itself, so a UI showing one issue's detail (Ignite Studio's
    /// per-issue panel, Studio's file view) can render who justified it and
    /// why without a second round-trip, and so a carried-forward/AI-drafted
    /// override (see `ai_justify`/`get_carry_forward_overrides`) reads no
    /// differently from a human one — same three fields either way.
    pub justification: Option<String>,
    pub actor_email: Option<String>,
    pub actor_name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct User {
    pub id: i64,
    pub email: String,
    pub name: Option<String>,
    pub provider: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionRow {
    pub id: String,
    pub expires_at: String,
    pub user_id: i64,
    pub email: String,
    pub name: Option<String>,
    pub provider: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiKeyIdentity {
    pub id: i64,
    pub user_id: i64,
    pub email: String,
    pub name: Option<String>,
    pub provider: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiKeySummary {
    pub id: i64,
    pub label: Option<String>,
    pub created_at: String,
    pub created_by: Option<String>,
    pub created_via: String,
    pub last_used_at: Option<String>,
    pub revoked_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CosignVerifyResult {
    pub verified: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkflowCacheEntry {
    pub commit_sha: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RetainedSourceRow {
    pub project_id: i64,
    pub dir_path: String,
    pub tier: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EffectivatedProject {
    pub id: i64,
    pub org: String,
    pub repo: String,
    pub repo_url: Option<String>,
    pub created_at: String,
    pub schedule_enabled: bool,
    pub schedule_interval: Option<String>,
    pub next_scheduled_run_at: Option<String>,
    pub last_scheduled_run_at: Option<String>,
    pub last_scheduled_status: Option<String>,
    pub last_scheduled_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DueScheduledProject {
    pub id: i64,
    pub org: String,
    pub repo: String,
    pub repo_url: Option<String>,
    pub schedule_interval: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GithubConnection {
    pub user_id: i64,
    pub github_login: String,
    pub access_token: String,
    pub scope: Option<String>,
    pub connected_at: String,
}

#[derive(Debug, Clone)]
pub struct FileScanCacheEntry {
    pub hash: String,
    pub findings: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct FileScanCacheInput {
    pub rel_path: String,
    pub hash: String,
    pub findings: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PullRequestRow {
    pub kind: String,
    pub url: String,
    pub branch: Option<String>,
    pub files_changed: Option<i64>,
    pub created_at: String,
}

/// One row per distinct (org, repo) ever onboarded — the "Onboarded Repos"
/// view's data source. `license_problems`/`findings_count` are open-issue
/// counts against the *latest* project run for that repo (a fresh snapshot,
/// not a cumulative total across every historical run); `acknowledgments`/
/// `recent_prs` are the full audit history across every run for that repo,
/// since an override or a PR stays a real historical fact regardless of
/// which run produced it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OnboardedRepoSummary {
    pub org: String,
    pub repo: String,
    pub repo_url: Option<String>,
    pub latest_project_id: i64,
    pub latest_job_id: String,
    pub status: String,
    pub last_scan_at: String,
    pub license_problems: i64,
    pub findings_count: i64,
    pub sla_breaches: i64,
    pub acknowledgments: Vec<OverrideRow>,
    pub recent_prs: Vec<PullRequestRow>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SlaBreachRow {
    pub issue_id: String,
    pub category: String,
    pub severity: String,
    pub score: Option<i64>,
    pub summary: String,
    pub file: Option<String>,
    pub line: Option<i64>,
    pub first_detected_at: String,
    pub days_open: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CampaignRow {
    pub id: i64,
    pub title: String,
    pub description: Option<String>,
    pub category: Option<String>,
    pub min_score: Option<i64>,
    pub target_date: Option<String>,
    pub created_by: Option<String>,
    pub created_at: String,
    pub closed_at: Option<String>,
    pub open_count: i64,
    pub resolved_count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CustomSecretPatternRow {
    pub id: i64,
    pub name: String,
    pub regex: String,
    pub enabled: bool,
    pub created_by: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditEventRow {
    pub id: i64,
    pub event_type: String,
    pub severity: String,
    pub summary: String,
    pub actor: Option<String>,
    pub org: Option<String>,
    pub repo: Option<String>,
    pub metadata_json: Option<String>,
    pub created_at: String,
    pub prev_hash: String,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeCoverageRow {
    pub hit_count: i64,
    pub covered_pct: Option<f64>,
}

#[derive(Debug, Clone)]
pub struct RuntimeCoverageInput {
    pub hit_count: i64,
    pub covered_pct: Option<f64>,
}



/// A saved [`DbStore::save_fix_pr_preview`] row, read back by
/// [`DbStore::get_fix_pr_preview`]. Always represents a finished job —
/// there's no "still running" state in this table (see that method's
/// doc comment) — so `done` isn't a field here, it's implied `true`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FixPrPreviewRow {
    pub total: i64,
    pub completed: i64,
    pub cancelled: bool,
    pub considered_count: i64,
    pub reason: Option<String>,
    pub candidates: serde_json::Value,
}

pub struct SaveFixPrPreviewParams<'a> {
    pub job_id: &'a str,
    pub total: i64,
    pub completed: i64,
    pub cancelled: bool,
    pub considered_count: i64,
    pub reason: Option<&'a str>,
    pub candidates: &'a serde_json::Value,
}

/// US-01: durable repository identity — see `repositories.rs`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RepositoryRow {
    pub id: i64,
    pub org: String,
    pub repo: String,
    pub github_repo_id: Option<String>,
    pub access_scope: String,
    pub created_at: String,
}

/// US-01: one scan execution, compatibility-mapped back to its legacy
/// `projects` row via `legacy_project_id`/`legacy_job_id`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanRunRow {
    pub id: i64,
    pub legacy_project_id: Option<i64>,
    pub repository_id: i64,
    pub snapshot_id: i64,
    pub initiator: Option<String>,
    pub source_channel: String,
    pub policy_version: Option<String>,
    pub lifecycle_state: String,
    pub is_enrollment_only: bool,
    pub created_at: String,
    pub finished_at: Option<String>,
    pub legacy_job_id: Option<String>,
}

/// US-04: the durable "awaiting review" record — what `review_gate.rs`'s
/// `ReviewGate::wait` used to hold only in an in-process `oneshot` map.
/// Surviving a restart means this row (and `resolved_at`/`decision_json`
/// once a decision lands) is queryable even though the original async
/// task awaiting that oneshot is gone.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingReviewRow {
    pub run_id: i64,
    pub project_id: i64,
    pub org: String,
    pub repo: String,
    pub owner_email: String,
    pub issues_json: String,
    pub created_at: String,
    pub resolved_at: Option<String>,
    pub decision_json: Option<String>,
}

/// US-04: idempotency-key lookup result — the existing run a duplicate
/// request with a matching key+payload should be pointed back at, instead
/// of starting a second one.
#[derive(Debug, Clone)]
pub struct IdempotentRunMatch {
    pub run_id: i64,
    pub legacy_project_id: Option<i64>,
    pub legacy_job_id: Option<String>,
    pub payload_hash: String,
}
