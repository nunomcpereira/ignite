//! Learning from triage (Admin / Integrations → "Rule tuning").
//!
//! - `POST /api/pipeline/:jobId/issues/:issueId/verdict` `{verdict, note?}` —
//!   a reviewer marks one finding `false_positive` or `true_positive`.
//! - `GET /api/policy/rule-noise?org=` — per engine rule: false-positive and
//!   real-issue verdicts, human overrides, repositories affected.
//! - `POST /api/policy/rule-proposals/generate` `{org?}` — asks the configured
//!   LLM to read people's free-text override justifications and propose
//!   ignore rules (background job; `GET /api/policy/rule-proposals` reports
//!   `generation`). Every proposal is validated (regexes compile, evidence
//!   ids are real overrides) and previewed against stored findings.
//! - `GET /api/policy/rule-proposals?status=`, `POST .../:id/accept|dismiss|disable`.
//!   An accepted proposal is an ignore rule Phase 4 applies next to
//!   `config.json`'s `ignoreRules` (matched findings stay visible,
//!   acknowledged with the rule's reason).
//!
//! Proposals are policy decisions: a `policy_admin` grant covering the
//! proposal's scope is required to generate, accept or dismiss them.

use crate::auth::RequireAuth;
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

const MAX_JUSTIFICATIONS: i64 = 400;
const MAX_DIGEST_CHARS: usize = 40_000;
const MAX_JUSTIFICATION_CHARS: usize = 220;
const MAX_PROPOSALS: usize = 15;
/// A proposal must cite at least this many distinct overrides.
const MIN_EVIDENCE: usize = 2;
const LLM_TIMEOUT_MS: u64 = 600_000;

const SYSTEM_PROMPT: &str = "You are an application-security lead reviewing how a team justifies (overrides) security findings. \
You get findings grouped by engine rule, each with the free-text justification a person wrote when they accepted it. \
Propose ignore rules ONLY where several justifications give the same reason and that reason generalizes to a precise, safe pattern: \
test fixtures or test-only code, generated or vendored code, examples/docs, a known safe internal wrapper, a specific false-positive pattern in one rule. \
Never propose a rule that would hide real vulnerabilities in production code, never a pattern broader than the evidence supports, and never a rule based on a single justification. \
Answer with ONLY a JSON array (no prose, no code fence) of at most 15 objects: \
{\"org\": \"<org or *>\", \"repo\": \"<repo or *>\", \"categories\": [\"<finding category>\"], \"filePatterns\": [\"<regex on the repo-relative path>\"], \"linePatterns\": [\"<regex on the flagged source line>\"], \
\"reason\": \"<short acknowledgment recorded on each matched finding>\", \"rationale\": \"<why, citing the common justification>\", \"evidenceOverrideIds\": [<ids from the data>]}. \
Each rule needs at least one filePattern or linePattern; use Rust regex syntax; anchor file patterns (e.g. ^src/test/). Return [] if nothing qualifies.";

fn err(status: StatusCode, message: impl Into<String>, code: &str) -> Response {
    (status, Json(json!({ "ok": false, "error": message.into(), "code": code }))).into_response()
}

fn one_line(s: &str, max: usize) -> String {
    let flat: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max {
        flat
    } else {
        format!("{}…", flat.chars().take(max).collect::<String>())
    }
}

// ---------------- verdicts ----------------

#[derive(Deserialize)]
struct VerdictBody {
    verdict: String,
    note: Option<String>,
}

async fn record_verdict(State(state): State<Arc<AppState>>, RequireAuth(user): RequireAuth, headers: HeaderMap, Path((job_id, issue_id)): Path<(String, String)>, Json(body): Json<VerdictBody>) -> Response {
    if let Err((status, denied)) = crate::auth::require_scope(&headers, &state.db, crate::auth::Scope::Override) {
        return (status, Json(denied)).into_response();
    }
    if body.verdict != "false_positive" && body.verdict != "true_positive" {
        return err(StatusCode::BAD_REQUEST, "verdict must be false_positive or true_positive.", "invalid_request");
    }
    let Some(project_id) = state.db.get_project_id_by_job_id(job_id.trim()) else { return err(StatusCode::NOT_FOUND, "Unknown job id.", "not_found") };
    let Some(project) = state.db.get_project(project_id) else { return err(StatusCode::NOT_FOUND, "Unknown job id.", "not_found") };
    if let Err((status, denied)) = crate::auth::require_grant(&state, &headers, "review", &project.org, &project.repo) {
        return (status, Json(denied)).into_response();
    }
    let Some(issue) = state.db.get_project_issues(project_id).into_iter().find(|i| i.id == issue_id) else {
        return err(StatusCode::NOT_FOUND, "Issue not found in this scan.", "not_found");
    };
    let fingerprint = issue.fingerprint();
    let note = body.note.as_deref().map(str::trim).filter(|n| !n.is_empty());
    state.db.upsert_finding_verdict(&ignite_db_store::NewVerdict {
        org: &project.org,
        repo: &project.repo,
        fingerprint: &fingerprint,
        issue_id: &issue.id,
        category: &issue.category,
        tool: issue.tool.as_deref(),
        rule: issue.rule.as_deref(),
        file: issue.file.as_deref(),
        verdict: &body.verdict,
        note,
        actor_email: &user.email,
    });
    state.emit_audit_event(
        ignite_audit_log::AuditEvent::new("finding.verdict_recorded", "info", format!("{} marked a {} finding as {}", user.email, issue.category, body.verdict.replace('_', " ")))
            .actor(user.email.clone())
            .repo(&project.org, &project.repo)
            .metadata(json!({ "issueId": issue.id, "fingerprint": fingerprint, "verdict": body.verdict, "tool": issue.tool, "rule": issue.rule })),
    );
    Json(json!({ "ok": true, "verdict": state.db.get_finding_verdict(&project.org, &project.repo, &fingerprint) })).into_response()
}

// ---------------- noise report ----------------

#[derive(Deserialize)]
struct OrgQuery {
    org: Option<String>,
    status: Option<String>,
}

async fn rule_noise(State(state): State<Arc<AppState>>, RequireAuth(_user): RequireAuth, Query(q): Query<OrgQuery>) -> Response {
    let org = q.org.as_deref().map(str::trim).filter(|o| !o.is_empty());
    Json(json!({ "ok": true, "rules": state.db.list_rule_noise(org, 100) })).into_response()
}

// ---------------- AI proposals ----------------

/// A proposal as the model returned it, after validation.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Candidate {
    pub org: String,
    pub repo: String,
    pub categories: Vec<String>,
    pub file_patterns: Vec<String>,
    pub line_patterns: Vec<String>,
    pub reason: String,
    pub rationale: String,
    pub evidence: Vec<i64>,
}

/// The digest the model reads: justifications grouped by engine rule.
pub(crate) fn build_digest(rows: &[ignite_db_store::JustificationRow]) -> String {
    let mut groups: BTreeMap<(String, String, String), Vec<&ignite_db_store::JustificationRow>> = BTreeMap::new();
    for r in rows {
        groups.entry((r.category.clone(), r.tool.clone().unwrap_or_else(|| "-".into()), r.rule.clone().unwrap_or_else(|| "-".into()))).or_default().push(r);
    }
    let mut ordered: Vec<_> = groups.into_iter().collect();
    ordered.sort_by(|a, b| b.1.len().cmp(&a.1.len()));
    let mut out = String::new();
    for ((category, tool, rule), items) in ordered {
        let header = format!("\n## category={category} engine={tool} rule={rule} ({} override(s))\n", items.len());
        if out.len() + header.len() > MAX_DIGEST_CHARS {
            break;
        }
        out.push_str(&header);
        for r in items {
            let line = format!("- id={} {}/{} file={} :: \"{}\"\n", r.override_id, r.org, r.repo, r.file.as_deref().unwrap_or("-"), one_line(&r.justification, MAX_JUSTIFICATION_CHARS));
            if out.len() + line.len() > MAX_DIGEST_CHARS {
                break;
            }
            out.push_str(&line);
        }
    }
    out
}

fn strings(v: &Value, key: &str) -> Vec<String> {
    v.get(key).and_then(|a| a.as_array()).map(|a| a.iter().filter_map(|s| s.as_str().map(|s| s.trim().to_string())).filter(|s| !s.is_empty()).collect()).unwrap_or_default()
}

/// Parses the model's reply and keeps only proposals that are safe to show:
/// at least one pattern, every regex compiles (and isn't a catch-all), and
/// at least [`MIN_EVIDENCE`] cited ids are real overrides from the digest.
pub(crate) fn parse_candidates(text: &str, known_ids: &HashSet<i64>) -> Vec<Candidate> {
    let (Some(start), Some(end)) = (text.find('['), text.rfind(']')) else { return vec![] };
    let Ok(Value::Array(items)) = serde_json::from_str::<Value>(&text[start..=end]) else { return vec![] };
    let catch_all = |p: &str| matches!(p, ".*" | "^.*$" | ".+" | "^" | "" | "(?s).*");
    items
        .iter()
        .filter_map(|v| {
            let file_patterns = strings(v, "filePatterns");
            let line_patterns = strings(v, "linePatterns");
            if file_patterns.is_empty() && line_patterns.is_empty() {
                return None;
            }
            if file_patterns.iter().chain(line_patterns.iter()).any(|p| catch_all(p) || regex::Regex::new(p).is_err()) {
                return None;
            }
            let evidence: Vec<i64> = v.get("evidenceOverrideIds").and_then(|a| a.as_array()).map(|a| a.iter().filter_map(|x| x.as_i64()).filter(|id| known_ids.contains(id)).collect::<HashSet<_>>().into_iter().collect()).unwrap_or_default();
            if evidence.len() < MIN_EVIDENCE {
                return None;
            }
            let field = |k: &str, d: &str| v.get(k).and_then(|s| s.as_str()).map(str::trim).filter(|s| !s.is_empty()).unwrap_or(d).to_string();
            let mut evidence = evidence;
            evidence.sort_unstable();
            Some(Candidate {
                org: field("org", "*"),
                repo: field("repo", "*"),
                categories: strings(v, "categories"),
                file_patterns,
                line_patterns,
                reason: one_line(&field("reason", "Matched an AI-proposed ignore rule"), 300),
                rationale: one_line(&field("rationale", ""), 600),
                evidence,
            })
        })
        .take(MAX_PROPOSALS)
        .collect()
}

/// Stored open findings (latest scan per repo) a candidate's file/category
/// patterns match — a preview; line patterns need the source and aren't
/// checked here.
fn preview_matches(c: &Candidate, locations: &[(String, String, Option<String>, String)]) -> i64 {
    let files: Vec<regex::Regex> = c.file_patterns.iter().filter_map(|p| regex::Regex::new(p).ok()).collect();
    locations
        .iter()
        .filter(|(org, repo, file, category)| {
            (c.org == "*" || c.org.eq_ignore_ascii_case(org))
                && (c.repo == "*" || c.repo.eq_ignore_ascii_case(repo))
                && (c.categories.is_empty() || c.categories.iter().any(|x| x == category))
                && (files.is_empty() || file.as_deref().is_some_and(|f| files.iter().any(|r| r.is_match(f))))
        })
        .count() as i64
}

#[derive(Clone)]
struct Generation {
    running: bool,
    started_at: String,
    finished_at: Option<String>,
    added: usize,
    error: Option<String>,
}

static GENERATION: Lazy<Mutex<Option<Generation>>> = Lazy::new(|| Mutex::new(None));

fn generation_json() -> Value {
    match GENERATION.lock().clone() {
        None => Value::Null,
        Some(g) => json!({ "running": g.running, "startedAt": g.started_at, "finishedAt": g.finished_at, "added": g.added, "error": g.error }),
    }
}

async fn generate(state: Arc<AppState>, org: Option<String>) -> Result<usize, String> {
    let rows = state.db.list_override_justifications(org.as_deref(), MAX_JUSTIFICATIONS);
    if rows.len() < MIN_EVIDENCE {
        return Err("Not enough override justifications yet to learn from.".to_string());
    }
    let known: HashSet<i64> = rows.iter().map(|r| r.override_id).collect();
    let http = reqwest::Client::new();
    if !ignite_llm_client::llm_available(&http, &state.llm_config).await {
        return Err(format!("No AI provider is available ({}): configure llm.provider in config.json.", ignite_llm_client::provider_label(&state.llm_config.provider)));
    }
    let user_content = format!("BEGIN OVERRIDES\n{}\nEND OVERRIDES\n", build_digest(&rows));
    let text = ignite_llm_client::llm_complete(
        &ignite_llm_client::LlmCompleteRequest { client: &http, config: &state.llm_config, system_prompt: SYSTEM_PROMPT, user_content: &user_content, temperature: 0.1, timeout_ms: LLM_TIMEOUT_MS, label: "rule-proposals" },
        |_| {},
    )
    .await
    .map_err(|e| crate::routes::issues::friendly_llm_error_message(&e))?;

    let existing: HashSet<(String, String, Vec<String>, Vec<String>, Vec<String>)> = state
        .db
        .list_rule_proposals(None)
        .into_iter()
        .filter(|p| p.status == "proposed" || p.status == "accepted")
        .map(|p| (p.org.to_ascii_lowercase(), p.repo.to_ascii_lowercase(), p.categories, p.file_patterns, p.line_patterns))
        .collect();
    let locations = state.db.list_latest_open_issue_locations(org.as_deref());
    let mut added = 0;
    for c in parse_candidates(&text, &known) {
        let key = (c.org.to_ascii_lowercase(), c.repo.to_ascii_lowercase(), c.categories.clone(), c.file_patterns.clone(), c.line_patterns.clone());
        if existing.contains(&key) {
            continue;
        }
        let matches = preview_matches(&c, &locations);
        state.db.insert_rule_proposal(&ignite_db_store::NewRuleProposal {
            org: &c.org,
            repo: &c.repo,
            categories: &c.categories,
            file_patterns: &c.file_patterns,
            line_patterns: &c.line_patterns,
            reason: &c.reason,
            rationale: &c.rationale,
            evidence_override_ids: &c.evidence,
            match_count: matches,
        });
        added += 1;
    }
    Ok(added)
}

fn require_policy_admin(state: &AppState, headers: &HeaderMap, email: &str, org: Option<&str>) -> Option<Response> {
    if crate::auth::api_key_is_scope_restricted(headers, &state.db) {
        return Some(err(StatusCode::FORBIDDEN, "A scope-restricted API key can't manage rule proposals.", "scope_denied"));
    }
    let org = org.filter(|o| *o != "*");
    (!state.db.has_permission_at_scope(email, "policy_admin", org, None)).then(|| err(StatusCode::FORBIDDEN, "Only a policy admin covering this scope can manage rule proposals.", "permission_denied"))
}

#[derive(Deserialize, Default)]
struct GenerateBody {
    org: Option<String>,
}

async fn start_generation(State(state): State<Arc<AppState>>, RequireAuth(user): RequireAuth, headers: HeaderMap, body: Option<Json<GenerateBody>>) -> Response {
    let org = body.and_then(|Json(b)| b.org).map(|o| o.trim().to_string()).filter(|o| !o.is_empty());
    if let Some(denied) = require_policy_admin(&state, &headers, &user.email, org.as_deref()) {
        return denied;
    }
    {
        let mut g = GENERATION.lock();
        if g.as_ref().is_some_and(|g| g.running) {
            drop(g);
            return (StatusCode::ACCEPTED, Json(json!({ "ok": true, "generation": generation_json() }))).into_response();
        }
        *g = Some(Generation { running: true, started_at: chrono::Utc::now().to_rfc3339(), finished_at: None, added: 0, error: None });
    }
    let st = state.clone();
    let actor = user.email.clone();
    tokio::spawn(async move {
        let outcome = generate(st.clone(), org.clone()).await;
        if let Ok(n) = &outcome {
            st.emit_audit_event(ignite_audit_log::AuditEvent::new("policy.rule_proposals_generated", "info", format!("{actor} asked the AI for ignore-rule proposals: {n} new")).actor(actor.clone()).metadata(json!({ "org": org, "added": n })));
        }
        let mut g = GENERATION.lock();
        let started_at = g.as_ref().map(|g| g.started_at.clone()).unwrap_or_default();
        *g = Some(Generation { running: false, started_at, finished_at: Some(chrono::Utc::now().to_rfc3339()), added: *outcome.as_ref().unwrap_or(&0), error: outcome.err() });
    });
    (StatusCode::ACCEPTED, Json(json!({ "ok": true, "generation": generation_json() }))).into_response()
}

async fn list_proposals(State(state): State<Arc<AppState>>, RequireAuth(_user): RequireAuth, Query(q): Query<OrgQuery>) -> Response {
    let status = q.status.as_deref().filter(|s| !s.is_empty());
    let proposals = state.db.list_rule_proposals(status);
    // The justifications each proposal cites, so a reviewer reads the
    // evidence, not just the model's summary of it.
    let rows = state.db.list_override_justifications(None, MAX_JUSTIFICATIONS * 5);
    let by_id: std::collections::HashMap<i64, &ignite_db_store::JustificationRow> = rows.iter().map(|r| (r.override_id, r)).collect();
    let items: Vec<Value> = proposals
        .iter()
        .map(|p| {
            let mut v = serde_json::to_value(p).unwrap_or(Value::Null);
            v["evidence"] = json!(p.evidence_override_ids.iter().filter_map(|id| by_id.get(id)).take(10).map(|r| json!({ "id": r.override_id, "org": r.org, "repo": r.repo, "file": r.file, "justification": r.justification })).collect::<Vec<_>>());
            v
        })
        .collect();
    Json(json!({ "ok": true, "proposals": items, "generation": generation_json() })).into_response()
}

async fn decide(state: Arc<AppState>, email: &str, headers: &HeaderMap, id: i64, to: &str) -> Response {
    let Some(p) = state.db.get_rule_proposal(id) else { return err(StatusCode::NOT_FOUND, "Proposal not found.", "not_found") };
    if let Some(denied) = require_policy_admin(&state, headers, email, Some(&p.org)) {
        return denied;
    }
    let allowed = matches!((p.status.as_str(), to), ("proposed", "accepted") | ("proposed", "dismissed") | ("accepted", "disabled") | ("disabled", "accepted") | ("dismissed", "accepted"));
    if !allowed {
        return err(StatusCode::CONFLICT, format!("A {} proposal can't become {to}.", p.status), "invalid_transition");
    }
    state.db.set_rule_proposal_status(id, to, email);
    state.emit_audit_event(
        ignite_audit_log::AuditEvent::new(format!("policy.rule_proposal_{to}"), "warning", format!("{email} {to} ignore-rule proposal #{id}: {}", p.reason))
            .actor(email.to_string())
            .metadata(json!({ "proposalId": id, "org": p.org, "repo": p.repo, "categories": p.categories, "filePatterns": p.file_patterns, "linePatterns": p.line_patterns })),
    );
    Json(json!({ "ok": true, "proposal": state.db.get_rule_proposal(id) })).into_response()
}

async fn accept(State(state): State<Arc<AppState>>, RequireAuth(user): RequireAuth, headers: HeaderMap, Path(id): Path<i64>) -> Response {
    decide(state, &user.email, &headers, id, "accepted").await
}
async fn dismiss(State(state): State<Arc<AppState>>, RequireAuth(user): RequireAuth, headers: HeaderMap, Path(id): Path<i64>) -> Response {
    decide(state, &user.email, &headers, id, "dismissed").await
}
async fn disable(State(state): State<Arc<AppState>>, RequireAuth(user): RequireAuth, headers: HeaderMap, Path(id): Path<i64>) -> Response {
    decide(state, &user.email, &headers, id, "disabled").await
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/pipeline/:job_id/issues/:issue_id/verdict", post(record_verdict))
        .route("/api/policy/rule-noise", get(rule_noise))
        .route("/api/policy/rule-proposals", get(list_proposals))
        .route("/api/policy/rule-proposals/generate", post(start_generation))
        .route("/api/policy/rule-proposals/:id/accept", post(accept))
        .route("/api/policy/rule-proposals/:id/dismiss", post(dismiss))
        .route("/api/policy/rule-proposals/:id/disable", post(disable))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: i64, rule: &str, file: &str, j: &str) -> ignite_db_store::JustificationRow {
        ignite_db_store::JustificationRow { override_id: id, org: "acme".into(), repo: "w".into(), category: "semantic-sast".into(), tool: Some("semgrep".into()), rule: Some(rule.into()), file: Some(file.into()), summary: "s".into(), justification: j.into(), created_at: String::new() }
    }

    #[test]
    fn digest_groups_by_rule_biggest_first() {
        let d = build_digest(&[row(1, "a", "x", "one"), row(2, "b", "y", "two"), row(3, "b", "z", "three")]);
        let b = d.find("rule=b (2 override(s))").unwrap();
        let a = d.find("rule=a (1 override(s))").unwrap();
        assert!(b < a);
        assert!(d.contains("id=3 acme/w file=z :: \"three\""));
    }

    #[test]
    fn only_safe_well_evidenced_proposals_survive_parsing() {
        let known: HashSet<i64> = [1, 2, 3].into_iter().collect();
        let reply = r#"Here you go:
        [
          {"org":"acme","repo":"*","categories":["semantic-sast"],"filePatterns":["^src/test/"],"reason":"test code","rationale":"3 people said test-only","evidenceOverrideIds":[1,2,3]},
          {"filePatterns":[".*"],"evidenceOverrideIds":[1,2]},
          {"filePatterns":["(unclosed"],"evidenceOverrideIds":[1,2]},
          {"filePatterns":["^docs/"],"evidenceOverrideIds":[1,99]},
          {"categories":["secret"],"evidenceOverrideIds":[1,2]}
        ]"#;
        let c = parse_candidates(reply, &known);
        assert_eq!(c.len(), 1, "catch-all, bad regex, fabricated evidence and pattern-less rules are dropped: {c:?}");
        assert_eq!(c[0].file_patterns, vec!["^src/test/".to_string()]);
        assert_eq!(c[0].evidence, vec![1, 2, 3]);
        assert!(parse_candidates("no json here", &known).is_empty());
    }

    #[test]
    fn preview_counts_stored_findings_by_scope_file_and_category() {
        let c = Candidate { org: "acme".into(), repo: "*".into(), categories: vec!["semantic-sast".into()], file_patterns: vec!["^src/test/".into()], line_patterns: vec![], reason: String::new(), rationale: String::new(), evidence: vec![] };
        let locs = vec![
            ("acme".to_string(), "w".to_string(), Some("src/test/A.java".to_string()), "semantic-sast".to_string()),
            ("acme".to_string(), "w".to_string(), Some("src/main/A.java".to_string()), "semantic-sast".to_string()),
            ("acme".to_string(), "w".to_string(), Some("src/test/B.java".to_string()), "secret".to_string()),
            ("other".to_string(), "w".to_string(), Some("src/test/A.java".to_string()), "semantic-sast".to_string()),
        ];
        assert_eq!(preview_matches(&c, &locs), 1);
    }
}
