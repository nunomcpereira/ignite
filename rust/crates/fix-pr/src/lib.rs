//! Bulk "fix all findings" PR generator — the scan-wide counterpart to
//! `routes/issues.rs`'s per-issue "Suggest AI fix" button. Two-step, no
//! server-side session state kept between them:
//!
//! 1. `generate_fix_candidates` — pure LLM step, no git involved. Reuses
//!    each issue's already-stored snippet (built at scan time by the
//!    Phase 3/4 check that raised it) and the same suggest-fix prompt/
//!    response format `routes/issues.rs` already uses, so a bulk run
//!    produces the same kind of fix a human clicking "Suggest AI fix" on
//!    that one issue would have gotten. Returns one `FixCandidate` per
//!    issue that has a usable snippet and got back a real replacement
//!    (not `REPLACEMENT: NONE`, not an LLM/parse error).
//! 2. `open_fix_pr` — takes back the exact candidate list the caller
//!    wants applied (the UI shows a diff preview and lets the user drop
//!    individual candidates before calling this), clones the repo's
//!    default branch fresh, applies every edit, and opens one PR
//!    bundling all of them. Mirrors `ignite-auto-fix-pr`'s clone/branch/
//!    commit/push/PR-open pattern, generalized from "one PR per CVE fix"
//!    to "one PR for every accepted finding fix".

use ignite_fs_utils::Snippet;
use ignite_github_api::GithubApi;
use ignite_llm_client::LlmClientConfig;
use ignite_tool_runner::{RunToolOptions, ToolRunner};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

const ISSUE_SUGGEST_FIX_PROMPT: &str = "You are a senior software engineer proposing a concrete fix for one single flagged code issue, using the exact numbered code snippet shown.\nPropose a corrected replacement for ONLY the exact line range shown in the snippet (from its first to its last numbered line) — do not rewrite the whole file, do not renumber lines, do not add lines outside that range.\nRespond in EXACTLY this plain-text format and nothing else — no JSON, no code fences, no text before or after:\nEXPLANATION: <1-3 sentences: what changed and why it fixes the issue>\nREPLACEMENT:\n<the corrected text for that exact line range, copied verbatim with no escaping, newline-separated, no line-number prefixes>\nIf you cannot safely propose a fix from the snippet alone, respond:\nEXPLANATION: <why not>\nREPLACEMENT: NONE";

/// The subset of `ignite_db_store::IssueRow` this crate needs — kept
/// decoupled from `db-store` (like every other check crate) rather than
/// depending on it directly.
#[derive(Debug, Clone)]
pub struct FixIssueInput {
    pub issue_id: String,
    pub category: String,
    pub severity: String,
    pub file: String,
    pub line: i64,
    pub summary: String,
    /// `IssueRow::snippet`, as stored at scan time — deserializes into
    /// `ignite_fs_utils::Snippet` (both use the same camelCase shape).
    pub snippet: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FixCandidate {
    pub issue_id: String,
    pub file: String,
    pub category: String,
    pub severity: String,
    pub summary: String,
    pub start_line: i64,
    pub end_line: i64,
    pub explanation: String,
    /// Verbatim original text of `start_line..=end_line`, for the UI's
    /// diff preview.
    pub original: String,
    pub replacement: String,
}

fn code_block(snippet: &Snippet) -> String {
    snippet.lines.iter().map(|l| format!("{}: {}", l.number, l.text)).collect::<Vec<_>>().join("\n")
}

fn issue_user_prompt(issue: &FixIssueInput, snippet: &Snippet) -> String {
    format!("Category: {}\nSeverity: {}\nLocation: {}:{}\nTechnical summary: {}\n\nCode:\n{}", issue.category, issue.severity, issue.file, issue.line, issue.summary, code_block(snippet))
}

static CODE_FENCE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?s)^```(?:\w+)?\s*(.*?)\s*```$").unwrap());
static SUGGEST_FIX_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?is)EXPLANATION:\s*(.*?)\n\s*REPLACEMENT:\s*(.*)$").unwrap());

fn strip_code_fence(text: &str) -> String {
    let trimmed = text.trim();
    match CODE_FENCE_RE.captures(trimmed) {
        Some(c) => c[1].to_string(),
        None => trimmed.to_string(),
    }
}

fn trim_block_lines(raw: &str) -> String {
    let normalized = raw.replace("\r\n", "\n");
    let mut lines: Vec<&str> = normalized.split('\n').collect();
    while lines.first().map(|l| l.trim().is_empty()).unwrap_or(false) {
        lines.remove(0);
    }
    while lines.last().map(|l| l.trim().is_empty()).unwrap_or(false) {
        lines.pop();
    }
    lines.join("\n")
}

/// `None` on `REPLACEMENT: NONE` or a malformed response — both mean
/// "no candidate", not an error worth surfacing per-issue.
fn parse_suggest_fix_response(text: &str) -> Option<(String, String)> {
    let trimmed = strip_code_fence(text);
    let captures = SUGGEST_FIX_RE.captures(&trimmed)?;
    let explanation = captures[1].trim().to_string();
    let replacement = trim_block_lines(&strip_code_fence(&captures[2]));
    if replacement.to_uppercase() == "NONE" || replacement.is_empty() {
        return None;
    }
    Some((explanation, replacement))
}

/// How many issues' LLM calls run at once. Each call already has its own
/// 60s timeout (`llm_complete`'s hardcoded call below); running them one
/// at a time made a scan with more than a handful of open issues take
/// minutes for no reason — the calls are independent, so there's nothing
/// to serialize for. 5 is conservative enough not to hammer a
/// locally-hosted model into the ground while still cutting wall-clock
/// time roughly 5x for an API-backed provider.
const FIX_PR_CONCURRENCY: usize = 5;

/// Generates one `FixCandidate` per issue that has a stored snippet and
/// got back a real (non-`NONE`) replacement. Issues without a snippet,
/// LLM errors, and `REPLACEMENT: NONE` responses are silently dropped —
/// `log` still records why, for the caller's job log / response
/// metadata, but a single issue failing never aborts the batch.
pub async fn generate_fix_candidates(http: &reqwest::Client, llm_config: &LlmClientConfig, issues: &[FixIssueInput], log: impl FnMut(&str)) -> Vec<FixCandidate> {
    generate_fix_candidates_with_progress(http, llm_config, issues, log, |_, _| {}).await
}

/// One issue's worth of work, run concurrently with others via
/// `buffer_unordered` below. Returns its own log lines instead of calling
/// a shared `log` closure directly — `buffer_unordered` polls multiple of
/// these at once within the same task, so nothing here can hold a `&mut`
/// borrow of state shared across them; the caller replays the lines
/// through the real `log` sequentially as each future actually completes.
async fn process_one_issue(http: &reqwest::Client, llm_config: &LlmClientConfig, issue: &FixIssueInput) -> (Vec<String>, Option<FixCandidate>) {
    let mut logs = Vec::new();
    let Some(snippet_value) = &issue.snippet else {
        logs.push(format!("[fix-pr] skip {} ({}:{}) — no stored snippet", issue.issue_id, issue.file, issue.line));
        return (logs, None);
    };
    let Ok(snippet) = serde_json::from_value::<Snippet>(snippet_value.clone()) else {
        logs.push(format!("[fix-pr] skip {} ({}:{}) — snippet did not deserialize", issue.issue_id, issue.file, issue.line));
        return (logs, None);
    };
    if snippet.lines.is_empty() {
        return (logs, None);
    }

    let user = issue_user_prompt(issue, &snippet);
    let label = format!("fix-pr {}:{}:{}", issue.category, issue.file, issue.line);
    let response = match ignite_llm_client::llm_complete(&ignite_llm_client::LlmCompleteRequest { client: http, config: llm_config, system_prompt: ISSUE_SUGGEST_FIX_PROMPT, user_content: &user, temperature: 0.2, timeout_ms: 60_000, label: &label }, |l| logs.push(l.to_string())).await {
        Ok(text) => text,
        Err(e) => {
            logs.push(format!("[fix-pr] skip {} — AI request failed: {e}", issue.issue_id));
            return (logs, None);
        }
    };
    let Some((explanation, replacement)) = parse_suggest_fix_response(&response) else {
        logs.push(format!("[fix-pr] skip {} — no safe fix proposed", issue.issue_id));
        return (logs, None);
    };

    let start_line = snippet.start_line as i64;
    let end_line = snippet.lines.last().map(|l| l.number as i64).unwrap_or(start_line);
    let original = snippet.lines.iter().map(|l| l.text.clone()).collect::<Vec<_>>().join("\n");
    let candidate = FixCandidate { issue_id: issue.issue_id.clone(), file: issue.file.clone(), category: issue.category.clone(), severity: issue.severity.clone(), summary: issue.summary.clone(), start_line, end_line, explanation, original, replacement };
    (logs, Some(candidate))
}

/// Same as [`generate_fix_candidates`], but calls `on_progress(completed,
/// total)` after every issue is processed (skipped, failed, or turned
/// into a candidate) — the seam a caller running this as a background
/// job uses to report real per-issue progress instead of a fake timer.
/// Runs up to [`FIX_PR_CONCURRENCY`] issues' LLM calls at once — each
/// issue is independent, so there's no reason to wait for one before
/// starting the next.
pub async fn generate_fix_candidates_with_progress(http: &reqwest::Client, llm_config: &LlmClientConfig, issues: &[FixIssueInput], mut log: impl FnMut(&str), mut on_progress: impl FnMut(usize, usize)) -> Vec<FixCandidate> {
    use futures::stream::StreamExt;

    let total = issues.len();
    let mut candidates = Vec::new();
    let mut completed = 0usize;

    // Collected into a `Vec` up front rather than a lazy `.map(...)` over
    // the iterator — `stream::iter` over a `Map` whose closure returns a
    // borrowed-lifetime future hits a known rustc HRTB limitation
    // ("implementation of `FnOnce` is not general enough") once the
    // resulting stream gets driven inside a `tokio::spawn`'d future;
    // eagerly building the futures first sidesteps it.
    let pending: Vec<_> = issues.iter().map(|issue| process_one_issue(http, llm_config, issue)).collect();
    let mut in_flight = futures::stream::iter(pending).buffer_unordered(FIX_PR_CONCURRENCY.max(1));

    while let Some((issue_logs, candidate)) = in_flight.next().await {
        completed += 1;
        for line in issue_logs {
            log(&line);
        }
        if let Some(candidate) = candidate {
            candidates.push(candidate);
        }
        on_progress(completed, total);
    }
    candidates
}

/// Replaces `start_line..=end_line` (1-indexed, inclusive) of `content`
/// with `replacement`. `None` if the range doesn't fit the current
/// content (file changed since the candidate was generated).
fn apply_candidate_to_content(content: &str, start_line: i64, end_line: i64, replacement: &str) -> Option<String> {
    if start_line < 1 || end_line < start_line {
        return None;
    }
    let normalized = content.replace("\r\n", "\n");
    let mut lines: Vec<&str> = normalized.split('\n').collect();
    let start_idx = (start_line - 1) as usize;
    let end_idx = (end_line - 1) as usize;
    if end_idx >= lines.len() {
        return None;
    }
    let replacement_lines: Vec<&str> = replacement.split('\n').collect();
    lines.splice(start_idx..=end_idx, replacement_lines);
    Some(lines.join("\n"))
}

/// Writes every candidate's edit into `root`, one file read/write per
/// distinct file touched. Within a file, edits are applied bottom-to-top
/// (highest `start_line` first) so an earlier edit's line-count change
/// never shifts a not-yet-applied edit's line numbers out from under it.
/// Returns the relative paths actually changed, for the caller's `git
/// add`. A candidate whose range no longer matches the on-disk file
/// (edited since the candidate was generated) is skipped, not fatal.
pub fn apply_candidates_to_files(root: &Path, candidates: &[FixCandidate]) -> std::io::Result<Vec<String>> {
    let mut by_file: HashMap<&str, Vec<&FixCandidate>> = HashMap::new();
    for c in candidates {
        by_file.entry(c.file.as_str()).or_default().push(c);
    }

    let mut touched = Vec::new();
    for (file, mut file_candidates) in by_file {
        file_candidates.sort_by_key(|c| std::cmp::Reverse(c.start_line));
        // `file` is a client-supplied path (round-tripped from
        // /fix-pr/preview, but the /apply request body is trusted only up
        // to this point) — confine it to the cloned repo root the same way
        // the staging/upload path does, rather than an unconfined
        // `root.join(file)` that a `../../etc/passwd` or absolute path
        // would happily escape with.
        let path = match ignite_staging::resolve_within_root(root, file) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let mut content = std::fs::read_to_string(&path)?;
        let mut any_applied = false;
        for c in file_candidates {
            if let Some(next) = apply_candidate_to_content(&content, c.start_line, c.end_line, &c.replacement) {
                content = next;
                any_applied = true;
            }
        }
        if any_applied {
            std::fs::write(&path, content)?;
            touched.push(file.to_string());
        }
    }
    touched.sort();
    Ok(touched)
}

/// Deterministic per-job branch name — one bulk fix PR per job, matching
/// how a job already represents "one scan's worth of findings" elsewhere
/// (issue ids, job history). Re-running against the same job while its
/// branch is still open reports `already_open` rather than creating a
/// second PR for the same findings.
pub fn branch_name_for_job(job_id: &str) -> String {
    let slug: String = job_id.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '-' }).collect();
    format!("ignite/fix-issues/{slug}")
}

#[derive(Debug)]
pub struct FixPrOutcome {
    pub branch: String,
    pub files_changed: Vec<String>,
    pub already_open: bool,
    pub pr_url: Option<String>,
    pub error: Option<String>,
}

/// Clones `full_name`@`base_branch` fresh into a temp dir, applies every
/// candidate, and opens one PR for all of them. `already_open` (branch
/// already exists on `origin`) short-circuits before cloning — same
/// idempotency check `ignite-auto-fix-pr` uses.
pub async fn generate_fix_diff(runner: &ToolRunner, github_api: &GithubApi<'_>, full_name: &str, base_branch: &str, candidates: &[FixCandidate], token: &str) -> Result<String, String> {
    if candidates.is_empty() {
        return Err("no candidates to apply".to_string());
    }

    let staging = tempfile::tempdir().map_err(|e| format!("failed to create staging dir: {e}"))?;
    let clone_dir = staging.path().join("clone");
    let clone_dir_str = clone_dir.to_string_lossy().to_string();

    github_api.gh_clone_repo_branch(full_name, base_branch, &clone_dir_str, token)
        .await
        .map_err(|e| format!("failed to clone {full_name}@{base_branch}: {e}"))?;

    let files_changed = apply_candidates_to_files(&clone_dir, candidates)
        .map_err(|e| format!("failed to apply fixes: {e}"))?;

    if files_changed.is_empty() {
        return Err("none of the candidates' line ranges matched the current file contents".to_string());
    }

    let diff_out = runner.run_tool("git", &["diff".to_string()], &clone_dir_str, RunToolOptions::default())
        .await
        .map_err(|e| format!("git diff: {e}"))?;

    Ok(diff_out.stdout)
}

pub async fn open_fix_pr(runner: &ToolRunner, github_api: &GithubApi<'_>, full_name: &str, base_branch: &str, job_id: &str, candidates: &[FixCandidate], token: &str) -> FixPrOutcome {
    let branch = branch_name_for_job(job_id);
    if candidates.is_empty() {
        return FixPrOutcome { branch, files_changed: vec![], already_open: false, pr_url: None, error: Some("no candidates to apply".to_string()) };
    }

    let staging = match tempfile::tempdir() {
        Ok(d) => d,
        Err(e) => return FixPrOutcome { branch, files_changed: vec![], already_open: false, pr_url: None, error: Some(format!("failed to create staging dir: {e}")) },
    };
    let clone_dir = staging.path().join("clone");
    let clone_dir_str = clone_dir.to_string_lossy().to_string();

    if let Err(e) = github_api.gh_clone_repo_branch(full_name, base_branch, &clone_dir_str, token).await {
        return FixPrOutcome { branch, files_changed: vec![], already_open: false, pr_url: None, error: Some(format!("failed to clone {full_name}@{base_branch}: {e}")) };
    }

    match runner.run_tool("git", &["ls-remote".to_string(), "--heads".to_string(), "origin".to_string(), branch.clone()], &clone_dir_str, RunToolOptions::default()).await {
        Ok(out) if !out.stdout.trim().is_empty() => return FixPrOutcome { branch, files_changed: vec![], already_open: true, pr_url: None, error: None },
        _ => {}
    }

    let files_changed = match apply_candidates_to_files(&clone_dir, candidates) {
        Ok(f) => f,
        Err(e) => return FixPrOutcome { branch, files_changed: vec![], already_open: false, pr_url: None, error: Some(format!("failed to apply fixes: {e}")) },
    };
    if files_changed.is_empty() {
        return FixPrOutcome { branch, files_changed, already_open: false, pr_url: None, error: Some("none of the candidates' line ranges matched the current file contents".to_string()) };
    }

    if let Err(e) = runner.run_tool("git", &["checkout".to_string(), "-B".to_string(), branch.clone(), base_branch.to_string()], &clone_dir_str, RunToolOptions::default()).await {
        return FixPrOutcome { branch, files_changed, already_open: false, pr_url: None, error: Some(format!("git checkout -B: {e}")) };
    }

    let mut add_args = vec!["add".to_string()];
    add_args.extend(files_changed.iter().cloned());
    if let Err(e) = runner.run_tool("git", &add_args, &clone_dir_str, RunToolOptions::default()).await {
        return FixPrOutcome { branch, files_changed, already_open: false, pr_url: None, error: Some(format!("git add: {e}")) };
    }

    let commit_message = format!("fix: apply {} AI-suggested fix(es) from Ignite scan {job_id}", candidates.len());
    let commit_args = vec!["-c".to_string(), "user.email=ignite-bot@localhost".to_string(), "-c".to_string(), "user.name=Ignite Auto-Fix".to_string(), "commit".to_string(), "-m".to_string(), commit_message];
    if let Err(e) = runner.run_tool("git", &commit_args, &clone_dir_str, RunToolOptions::default()).await {
        return FixPrOutcome { branch, files_changed, already_open: false, pr_url: None, error: Some(format!("git commit: {e}")) };
    }

    let push_result = runner.run_tool("git", &["-c".to_string(), format!("http.extraheader=AUTHORIZATION: bearer {token}"), "push".to_string(), "origin".to_string(), format!("HEAD:refs/heads/{branch}")], &clone_dir_str, RunToolOptions::default()).await;
    if let Err(e) = push_result {
        return FixPrOutcome { branch, files_changed, already_open: false, pr_url: None, error: Some(format!("git push: {e}")) };
    }

    let pr_title = format!("Ignite: fix {} finding(s)", candidates.len());
    let pr_body = pr_body_for(candidates, job_id);
    match github_api.gh_create_pr(full_name, base_branch, &branch, &pr_title, &pr_body, token).await {
        Ok(pr) => FixPrOutcome { branch, files_changed, already_open: false, pr_url: Some(pr.url), error: None },
        Err(e) => FixPrOutcome { branch, files_changed, already_open: false, pr_url: None, error: Some(format!("branch pushed but PR creation failed: {e}")) },
    }
}

fn pr_body_for(candidates: &[FixCandidate], job_id: &str) -> String {
    let mut body = format!("Applies {} AI-suggested fix(es) from Ignite scan `{job_id}`.\n\n", candidates.len());
    for c in candidates {
        body.push_str(&format!("- **{}** `{}:{}-{}` — {}\n", c.category, c.file, c.start_line, c.end_line, c.explanation));
    }
    body.push_str("\nGenerated by Ignite's bulk fix-PR feature. Review each change before merging — AI-suggested fixes are not a substitute for human review.");
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(file: &str, start_line: i64, end_line: i64, replacement: &str) -> FixCandidate {
        FixCandidate { issue_id: "i1".to_string(), file: file.to_string(), category: "secret".to_string(), severity: "error".to_string(), summary: "s".to_string(), start_line, end_line, explanation: "e".to_string(), original: "o".to_string(), replacement: replacement.to_string() }
    }

    #[test]
    fn apply_candidate_to_content_replaces_exact_range() {
        let content = "a\nb\nc\nd\n";
        let out = apply_candidate_to_content(content, 2, 3, "B\nC").unwrap();
        assert_eq!(out, "a\nB\nC\nd\n");
    }

    #[test]
    fn apply_candidate_to_content_none_when_range_out_of_bounds() {
        assert!(apply_candidate_to_content("a\nb\n", 5, 6, "x").is_none());
        assert!(apply_candidate_to_content("a\nb\n", 0, 1, "x").is_none());
    }

    #[test]
    fn apply_candidates_to_files_applies_bottom_to_top_within_a_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("f.txt"), "1\n2\n3\n4\n5\n").unwrap();
        let candidates = vec![candidate("f.txt", 1, 1, "ONE"), candidate("f.txt", 4, 5, "FOUR\nFIVE")];
        let touched = apply_candidates_to_files(dir.path(), &candidates).unwrap();
        assert_eq!(touched, vec!["f.txt".to_string()]);
        let result = std::fs::read_to_string(dir.path().join("f.txt")).unwrap();
        assert_eq!(result, "ONE\n2\n3\nFOUR\nFIVE\n");
    }

    #[test]
    fn apply_candidates_to_files_skips_stale_range() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("f.txt"), "1\n2\n").unwrap();
        let candidates = vec![candidate("f.txt", 10, 11, "X")];
        let touched = apply_candidates_to_files(dir.path(), &candidates).unwrap();
        assert!(touched.is_empty());
    }

    #[test]
    fn branch_name_for_job_is_deterministic_and_slugified() {
        let branch = branch_name_for_job("job/abc 123");
        assert_eq!(branch, "ignite/fix-issues/job-abc-123");
        assert_eq!(branch, branch_name_for_job("job/abc 123"));
    }

    #[test]
    fn parse_suggest_fix_response_extracts_explanation_and_replacement() {
        let text = "EXPLANATION: use bound params\nREPLACEMENT:\ncursor.execute(q, (x,))";
        let (explanation, replacement) = parse_suggest_fix_response(text).unwrap();
        assert_eq!(explanation, "use bound params");
        assert_eq!(replacement, "cursor.execute(q, (x,))");
    }

    #[test]
    fn parse_suggest_fix_response_none_for_replacement_none() {
        assert!(parse_suggest_fix_response("EXPLANATION: can't tell\nREPLACEMENT: NONE").is_none());
    }

    #[test]
    fn parse_suggest_fix_response_none_for_malformed_text() {
        assert!(parse_suggest_fix_response("not the expected format at all").is_none());
    }

    #[tokio::test]
    async fn generate_fix_candidates_skips_issues_without_a_snippet() {
        let http = reqwest::Client::new();
        let llm_config = LlmClientConfig { provider: ignite_llm_client::Provider::Local, openai_api_key: String::new(), openai_base_url: String::new(), openai_model: String::new(), anthropic_api_key: String::new(), anthropic_base_url: String::new(), anthropic_model: String::new(), azure_foundry_api_key: String::new(), azure_foundry_endpoint: String::new(), azure_foundry_deployment: String::new(), azure_foundry_api_version: String::new(), scan_url: "http://127.0.0.1:9999".to_string(), scan_model: "test".to_string() };
        let issues = vec![FixIssueInput { issue_id: "i1".to_string(), category: "secret".to_string(), severity: "error".to_string(), file: "a.py".to_string(), line: 1, summary: "s".to_string(), snippet: None }];
        let candidates = generate_fix_candidates(&http, &llm_config, &issues, |_| {}).await;
        assert!(candidates.is_empty());
    }
}
