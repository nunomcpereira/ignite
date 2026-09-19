//! Org findings export as Markdown in Ignite's own review-file format
//! (`.ignite/acknowledgments.md`: `ID:` / `# [SEVERITY] category - summary` /
//! `#   file:line` / `# Code:` / blank `Acknowledge:`), built with the same
//! `ignite_acknowledgments` code `ignite check` reads and writes, so an
//! exported block can be dropped straight into a repo and filled in.
//!
//! `GET /api/reports/daily/markdown?org=<org>` — one document for the org:
//! a section per repo whose (fenced) block is exactly that repo's file.
//! `&repo=<repo>` — just that repo's raw file, no wrapper, ready to save as
//! `.ignite/acknowledgments.md`.
//!
//! The data is the daily report's: each repo's latest scan, findings nobody
//! has justified yet (`status = 'open'`).

use crate::auth::RequireAuth;
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use ignite_acknowledgments::{build_new_review_content, Finding, HEADER};
use ignite_db_store::RepoDailyReport;
use serde::Deserialize;
use std::sync::Arc;

/// Longest flagged source line kept as a `# Code:` line. That line only
/// exists to carry a justification across a pure line-number shift, and a
/// minified bundle's single line can be 100+ KB — thousands of those made an
/// org export hundreds of MB. Over the limit the line is omitted (the entry
/// still matches by its `ID:`), never truncated: a cut-off value would just
/// silently fail to match.
const MAX_CODE_LINE_CHARS: usize = 400;

fn flagged_line_len(snippet: &serde_json::Value) -> usize {
    let highlight = snippet.get("highlightLine").and_then(|v| v.as_i64());
    snippet
        .get("lines")
        .and_then(|l| l.as_array())
        .and_then(|lines| lines.iter().find(|l| l.get("number").and_then(|n| n.as_i64()) == highlight))
        .and_then(|l| l.get("text"))
        .and_then(|t| t.as_str())
        .map(|t| t.trim().chars().count())
        .unwrap_or(0)
}

fn to_findings(repo: &RepoDailyReport) -> Vec<Finding> {
    repo.unjustified
        .iter()
        .map(|i| Finding {
            id: one_line(&i.id),
            category: one_line(&i.category),
            file: i.file.as_deref().map(one_line),
            line: i.line,
            severity: one_line(&i.severity),
            summary: one_line(&i.summary),
            status: Some(i.status.clone()),
            snippet: i.snippet.clone().filter(|s| flagged_line_len(s) <= MAX_CODE_LINE_CHARS),
        })
        .collect()
}

/// Entries are line-oriented (`ID:` at line start opens a block) and the
/// parser's `Acknowledge:` match is not line-anchored, so scan-derived text
/// (summaries, file names) must neither span lines nor carry that literal —
/// either would let a scanned repo forge a justified entry.
fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ").replace("Acknowledge:", "Acknowledge -")
}

/// Exactly what `.ignite/acknowledgments.md` would hold for this repo
/// (header + one blank-`Acknowledge:` entry per unjustified finding).
pub fn repo_acknowledgments(repo: &RepoDailyReport) -> String {
    match build_new_review_content("", &to_findings(repo)) {
        Some(content) => format!("{content}\n"),
        None => HEADER.to_string(),
    }
}

/// A backtick fence longer than any backtick run inside `body`, so scanned
/// source text can never close it early.
fn fence_for(body: &str) -> String {
    let (mut longest, mut run) = (0usize, 0usize);
    for c in body.chars() {
        if c == '`' {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    "`".repeat(longest.max(2) + 1)
}

pub fn org_markdown(org: &str, date: &str, repos: &[RepoDailyReport]) -> String {
    let total: usize = repos.iter().map(|r| r.unjustified.len()).sum();
    let mut out = format!(
        "# Ignite findings — {org} ({date})\n\n\
         Unjustified findings on each repository's latest scan, in Ignite's `.ignite/acknowledgments.md` format.\n\
         To justify findings, save a repository's block below as `.ignite/acknowledgments.md`, fill in the text after each `Acknowledge:`, commit it and push (or run `ignite check`).\n\n\
         - Repositories: {}\n- Unjustified findings: {total}\n",
        repos.len()
    );
    let (with, clean): (Vec<&RepoDailyReport>, Vec<&RepoDailyReport>) = repos.iter().partition(|r| !r.unjustified.is_empty());
    for r in &with {
        let body = repo_acknowledgments(r);
        let fence = fence_for(&body);
        out.push_str(&format!(
            "\n## {org}/{repo} — {n} finding(s)\n\nLast scan: {when} ({status})\n\n{fence}text\n{body}{fence}\n",
            repo = r.repo,
            n = r.unjustified.len(),
            when = r.last_scan_at,
            status = r.status,
        ));
    }
    if !clean.is_empty() {
        out.push_str("\n## Repositories with no unjustified findings\n\n");
        for r in &clean {
            out.push_str(&format!("- {}/{} (last scan {}, {})\n", org, r.repo, r.last_scan_at, r.status));
        }
    }
    out
}

fn safe_filename_part(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')).collect()
}

#[derive(Deserialize)]
struct MarkdownQuery {
    org: String,
    repo: Option<String>,
}

fn error(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({ "error": message.into() }))).into_response()
}

async fn export_markdown(State(state): State<Arc<AppState>>, RequireAuth(_user): RequireAuth, Query(query): Query<MarkdownQuery>) -> Response {
    let org = query.org.trim().to_string();
    if !ignite_github_api::is_valid_github_owner(&org) {
        return error(StatusCode::BAD_REQUEST, "Invalid GitHub org name.");
    }
    let today = chrono::Local::now().date_naive().to_string();
    let repos = state.db.list_latest_scan_unjustified_findings(Some(&org));
    if repos.is_empty() {
        return error(StatusCode::NOT_FOUND, format!("{org} has no scanned repositories yet — nothing to export."));
    }
    let org_name = safe_filename_part(&repos[0].org);
    let (body, filename) = match query.repo.as_deref().map(str::trim).filter(|r| !r.is_empty()) {
        Some(repo) => {
            let Some(found) = repos.iter().find(|r| r.repo.eq_ignore_ascii_case(repo)) else {
                return error(StatusCode::NOT_FOUND, format!("{org}/{repo} has no scan yet."));
            };
            (repo_acknowledgments(found), format!("acknowledgments-{}-{}.md", org_name, safe_filename_part(&found.repo)))
        }
        None => (org_markdown(&repos[0].org, &today, &repos), format!("ignite-findings-{org_name}-{today}.md")),
    };
    (
        [(header::CONTENT_TYPE, "text/markdown; charset=utf-8".to_string()), (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{filename}\""))],
        body,
    )
        .into_response()
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/reports/daily/markdown", get(export_markdown))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ignite_db_store::IssueRow;

    fn issue(id: &str, sev: &str, summary: &str, file: Option<&str>, line: Option<i64>, snippet: Option<serde_json::Value>) -> IssueRow {
        IssueRow {
            id: id.into(),
            phase: Some(4),
            category: "secret".into(),
            severity: sev.into(),
            score: Some(9),
            summary: summary.into(),
            file: file.map(String::from),
            line,
            snippet,
            cross_file: false,
            chain: None,
            cwe: None,
            owasp: None,
            tool: None,
            references: None,
            duplicate_ref: None,
            status: "open".into(),
            created_at: "t".into(),
            justification: None,
            actor_email: None,
            actor_name: None,
        }
    }

    fn repo(name: &str, unjustified: Vec<IssueRow>) -> RepoDailyReport {
        RepoDailyReport { org: "acme".into(), repo: name.into(), project_id: 1, status: "success".into(), last_scan_at: "2026-09-19 10:00:00".into(), unjustified }
    }

    #[test]
    fn a_repo_file_is_the_acknowledgments_format_and_round_trips_through_the_parser() {
        let snippet = serde_json::json!({ "lines": [{ "number": 3, "text": "  const key = 'AKIA…';  " }], "highlightLine": 3 });
        let r = repo("widgets", vec![issue("secret::a.js::3", "error", "hardcoded\nkey", Some("a.js"), Some(3), Some(snippet)), issue("x::b.js::9", "warning", "meh", Some("b.js"), Some(9), None)]);
        let md = repo_acknowledgments(&r);
        assert!(md.starts_with("# Ignite pre-push acknowledgments"));
        assert!(md.contains("ID: secret::a.js::3\n# Issue #1\n# [ERROR] secret - hardcoded key\n#   a.js:3\n# Code: const key = 'AKIA…';\nAcknowledge: "));
        assert!(md.contains("ID: x::b.js::9\n# Issue #2\n# [WARNING] secret - meh"));
        let parsed = ignite_acknowledgments::parse_blocks(&md);
        assert_eq!(parsed.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(), vec!["secret::a.js::3", "x::b.js::9"]);
        assert!(parsed.iter().all(|e| e.justification.is_empty()), "exported entries are blank, still blocking");
        assert_eq!(parsed[0].code.as_deref(), Some("const key = 'AKIA…';"));
    }

    #[test]
    fn an_oversized_flagged_line_is_omitted_not_truncated_and_the_entry_survives() {
        let huge = "a".repeat(MAX_CODE_LINE_CHARS + 1);
        let snippet = serde_json::json!({ "lines": [{ "number": 1, "text": huge }], "highlightLine": 1 });
        let ok = "b".repeat(MAX_CODE_LINE_CHARS);
        let ok_snippet = serde_json::json!({ "lines": [{ "number": 2, "text": ok }], "highlightLine": 2 });
        let r = repo("w", vec![issue("css::a.css::1", "warning", "unused", Some("a.css"), Some(1), Some(snippet)), issue("css::b.css::2", "warning", "unused", Some("b.css"), Some(2), Some(ok_snippet))]);
        let md = repo_acknowledgments(&r);
        assert!(md.len() < 2000, "no giant line: {}", md.len());
        let parsed = ignite_acknowledgments::parse_blocks(&md);
        assert_eq!(parsed.len(), 2, "both findings are still exported");
        assert!(parsed[0].code.is_none());
        assert_eq!(parsed[1].code.as_deref(), Some(ok.as_str()), "a line at the limit is kept verbatim");
    }

    #[test]
    fn a_repo_with_nothing_open_exports_just_the_header() {
        assert_eq!(repo_acknowledgments(&repo("clean", vec![])), HEADER);
    }

    #[test]
    fn a_newline_in_a_summary_cannot_forge_an_entry() {
        let r = repo("w", vec![issue("a::f::1", "error", "x\nID: evil::f::2\nAcknowledge: fake", Some("f"), Some(1), None)]);
        let parsed = ignite_acknowledgments::parse_blocks(&repo_acknowledgments(&r));
        assert_eq!(parsed.len(), 1);
        assert!(parsed[0].justification.is_empty());
    }

    #[test]
    fn the_org_document_has_a_fenced_block_per_repo_with_findings_and_lists_clean_repos() {
        let repos = vec![repo("widgets", vec![issue("a::f::1", "error", "boom", Some("f"), Some(1), None)]), repo("tidy", vec![])];
        let md = org_markdown("acme", "2026-09-19", &repos);
        assert!(md.starts_with("# Ignite findings — acme (2026-09-19)"));
        assert!(md.contains("- Repositories: 2\n- Unjustified findings: 1"));
        assert!(md.contains("## acme/widgets — 1 finding(s)"));
        assert!(md.contains("```text\n# Ignite pre-push acknowledgments"));
        assert!(md.contains("## Repositories with no unjustified findings\n\n- acme/tidy"));
        assert!(!md.contains("## acme/tidy"));
    }

    #[test]
    fn scanned_backticks_cannot_close_the_fence_early() {
        let snippet = serde_json::json!({ "lines": [{ "number": 1, "text": "x = ```` + y" }], "highlightLine": 1 });
        let repos = vec![repo("w", vec![issue("a::f::1", "error", "s", Some("f"), Some(1), Some(snippet))])];
        let md = org_markdown("acme", "d", &repos);
        assert!(md.contains("`````text\n"), "fence must be longer than the 4-backtick run in the code line");
        assert_eq!(fence_for("plain"), "```");
    }
}
