//! POST /api/pipeline/:jobId/github-check — faithful port of
//! routes/github-pr-status.js. `auth.resolveGithubToken(req)` (a
//! connected-session token) isn't available yet — no session/auth
//! middleware exists — so this falls back straight to
//! `resolve_server_github_token()` (GH_TOKEN/GITHUB_TOKEN env).

use crate::routes::job_issues::lookup_job_issues;
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use ignite_db_store::IssueRow;
use ignite_github_api::GithubApi;
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

static GITHUB_NAME_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$").unwrap());
static REPO_NAME_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9._-]{1,100}$").unwrap());
static SHA_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^[0-9a-f]{7,40}$").unwrap());
const MAX_LISTED_ISSUES: usize = 15;

struct Summary {
    state: &'static str,
    description: String,
    body: String,
}

fn build_summary(issues: &[IssueRow], job_id: &str) -> Summary {
    let open: Vec<&IssueRow> = issues.iter().filter(|i| i.status != "overridden" && i.status != "baselined").collect();
    let errors: Vec<&&IssueRow> = open.iter().filter(|i| i.severity == "error").collect();
    let warnings: Vec<&&IssueRow> = open.iter().filter(|i| i.severity == "warning").collect();
    let overridden: Vec<&IssueRow> = issues.iter().filter(|i| i.status == "overridden").collect();

    let state = if !errors.is_empty() { "failure" } else { "success" };
    let description = if !errors.is_empty() {
        format!("{} blocking finding(s), {} warning(s)", errors.len(), warnings.len())
    } else {
        format!("Passed — {} warning(s), {} overridden", warnings.len(), overridden.len())
    };

    let mut lines = vec![
        format!("### {}", if !errors.is_empty() { "\u{274c} Ignite gate failed" } else { "\u{2705} Ignite gate passed" }),
        String::new(),
        format!("**{}** blocking · **{}** warning · **{}** overridden", errors.len(), warnings.len(), overridden.len()),
        String::new(),
    ];
    let to_list: Vec<&&IssueRow> = if !errors.is_empty() { errors } else { warnings };
    if !to_list.is_empty() {
        let suffix = if to_list.len() > MAX_LISTED_ISSUES { format!(" (showing first {MAX_LISTED_ISSUES})") } else { String::new() };
        lines.push(format!("<details{}><summary>{} finding(s){suffix}</summary>", if state == "failure" { " open" } else { "" }, to_list.len()));
        lines.push(String::new());
        for issue in to_list.iter().take(MAX_LISTED_ISSUES) {
            let loc = match &issue.file {
                Some(f) => format!("`{f}{}`", issue.line.map(|l| format!(":{l}")).unwrap_or_default()),
                None => "(project-wide)".to_string(),
            };
            lines.push(format!("- **[{}]** {loc} — {}", issue.category, issue.summary));
        }
        lines.push(String::new());
        lines.push("</details>".to_string());
    }
    lines.push(String::new());
    lines.push(format!("_Job `{job_id}` — via [Ignite](https://github.com/nunomcpereira/ignite)._"));

    Summary { state, description: description.chars().take(140).collect(), body: lines.join("\n") }
}

fn err(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(json!({ "error": message.into() }))).into_response()
}

async fn github_check(State(state): State<Arc<AppState>>, Path(job_id): Path<String>, Json(body): Json<Value>) -> Response {
    let job_id = job_id.trim();
    let owner = body.get("owner").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let repo = body.get("repo").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let sha = body.get("sha").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let pr_number = body.get("prNumber").and_then(|v| v.as_i64());

    if !GITHUB_NAME_RE.is_match(&owner) {
        return err(StatusCode::BAD_REQUEST, format!("Invalid GitHub owner/org: \"{owner}\""));
    }
    if !REPO_NAME_RE.is_match(&repo) {
        return err(StatusCode::BAD_REQUEST, format!("Invalid repository name: \"{repo}\""));
    }
    if !SHA_RE.is_match(&sha) {
        return err(StatusCode::BAD_REQUEST, "sha must be a 7-40 character hex commit SHA.".to_string());
    }
    if let Some(pr) = pr_number {
        if pr <= 0 {
            return err(StatusCode::BAD_REQUEST, "prNumber must be a positive integer when provided.".to_string());
        }
    }

    let Some(issues) = lookup_job_issues(&state, job_id) else {
        return err(StatusCode::NOT_FOUND, "Unknown job id.".to_string());
    };

    let gh_token = ignite_github_api::resolve_server_github_token();
    if gh_token.is_empty() {
        return err(StatusCode::UNAUTHORIZED, "No GitHub token available — connect a GitHub account, or set GH_TOKEN/GITHUB_TOKEN on the Ignite server.".to_string());
    }

    let full_name = format!("{owner}/{repo}");
    let summary = build_summary(&issues, job_id);

    let api = GithubApi::new(&state.runner);
    let fields: HashMap<String, Value> = HashMap::from([("state".to_string(), json!(summary.state)), ("description".to_string(), json!(summary.description)), ("context".to_string(), json!("ignite/gate"))]);
    if let Err(e) = api.gh_api_write("POST", &format!("repos/{full_name}/statuses/{sha}"), &fields, &gh_token).await {
        return err(StatusCode::BAD_GATEWAY, format!("Failed to post to GitHub: {e}"));
    }

    let mut commented = false;
    if let Some(pr) = pr_number {
        if let Err(e) = api.gh_comment_on_pr(&full_name, pr as u64, &summary.body, &gh_token).await {
            return err(StatusCode::BAD_GATEWAY, format!("Failed to post to GitHub: {e}"));
        }
        commented = true;
    }

    Json(json!({ "ok": true, "state": summary.state, "description": summary.description, "commented": commented })).into_response()
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/pipeline/:job_id/github-check", post(github_check))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issue(category: &str, severity: &str, status: &str, file: Option<&str>, line: Option<i64>) -> IssueRow {
        IssueRow { id: format!("{category}::x"), phase: Some(4), category: category.to_string(), severity: severity.to_string(), score: Some(5), summary: "test finding".to_string(), file: file.map(str::to_string), line, snippet: None, cross_file: false, chain: None, cwe: None, status: status.to_string(), created_at: String::new() }
    }

    #[test]
    fn build_summary_reports_failure_when_blocking_issues_open() {
        let issues = vec![issue("secret", "error", "open", Some("a.js"), Some(3))];
        let summary = build_summary(&issues, "job-1");
        assert_eq!(summary.state, "failure");
        assert!(summary.body.contains("Ignite gate failed"));
        assert!(summary.body.contains("a.js:3"));
    }

    #[test]
    fn build_summary_reports_success_when_no_blocking_issues() {
        let issues = vec![issue("secret", "warning", "open", None, None)];
        let summary = build_summary(&issues, "job-1");
        assert_eq!(summary.state, "success");
        assert!(summary.body.contains("Ignite gate passed"));
        assert!(summary.body.contains("(project-wide)"));
    }

    #[test]
    fn build_summary_excludes_overridden_and_baselined_from_open_counts() {
        let issues = vec![issue("secret", "error", "overridden", None, None), issue("license", "error", "baselined", None, None)];
        let summary = build_summary(&issues, "job-1");
        assert_eq!(summary.state, "success");
        assert!(summary.body.contains("1** overridden"));
    }

    #[test]
    fn build_summary_caps_description_at_140_chars() {
        let issues: Vec<IssueRow> = (0..50).map(|i| issue("secret", "error", "open", Some(&format!("file{i}.js")), Some(1))).collect();
        let summary = build_summary(&issues, "job-1");
        assert!(summary.description.chars().count() <= 140);
    }
}
