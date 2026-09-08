//! POST /api/pipeline/:jobId/github-check — faithful port of
//! routes/github-pr-status.js. Token resolution mirrors the push path:
//! `crate::auth::resolve_effective_github_token` (connected session first),
//! falling back to `resolve_server_github_token()` (GH_TOKEN/GITHUB_TOKEN
//! env) for unattended CI callers with no session.

use crate::auth::RequireAuth;
use crate::routes::job_issues::{lookup_job_issues, lookup_job_owner_repo};
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

static SHA_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^[0-9a-f]{7,40}$").unwrap());
const MAX_LISTED_ISSUES: usize = 15;

/// The `number` of the first alert in `alerts` (a
/// `GET .../code-scanning/alerts` response array) that represents
/// `issue` — matched by `rule.id` (the same `rule_id_for` mapping
/// `ignite_sarif::build_sarif` used to generate the SARIF this alert was
/// created from) plus the alert's most recent instance's file/line,
/// since GitHub's alerts API doesn't echo back the `partialFingerprints`
/// a SARIF upload carried. `None` when `issue` has no file/line (a
/// project-wide finding never has a code-scanning location to match), or
/// no open alert matches.
fn find_matching_open_alert_number(alerts: &[Value], issue: &IssueRow) -> Option<u64> {
    let (file, line) = (issue.file.as_deref()?, issue.line?);
    let rule_id = ignite_sarif::rule_id_for(issue);
    alerts.iter().find_map(|a| {
        let is_open = a.get("state").and_then(|v| v.as_str()) == Some("open");
        let rule_matches = a.get("rule").and_then(|r| r.get("id")).and_then(|v| v.as_str()) == Some(rule_id.as_str());
        let location = a.get("most_recent_instance").and_then(|i| i.get("location"));
        let file_matches = location.and_then(|l| l.get("path")).and_then(|v| v.as_str()) == Some(file);
        let line_matches = location.and_then(|l| l.get("start_line")).and_then(|v| v.as_i64()) == Some(line);
        (is_open && rule_matches && file_matches && line_matches).then(|| a.get("number").and_then(|v| v.as_u64())).flatten()
    })
}

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

async fn github_check(State(state): State<Arc<AppState>>, RequireAuth(_user): RequireAuth, Path(job_id): Path<String>, headers: axum::http::HeaderMap, Json(body): Json<Value>) -> Response {
    let job_id = job_id.trim();
    let owner = body.get("owner").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let repo = body.get("repo").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let sha = body.get("sha").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let pr_number = body.get("prNumber").and_then(|v| v.as_i64());
    let git_ref = body.get("ref").and_then(|v| v.as_str()).map(|s| s.trim().to_string());

    if !ignite_github_api::is_valid_github_owner(&owner) {
        return err(StatusCode::BAD_REQUEST, format!("Invalid GitHub owner/org: \"{owner}\""));
    }
    if !ignite_github_api::is_valid_github_repo(&repo) {
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
    match lookup_job_owner_repo(&state, job_id) {
        Some((job_org, job_repo)) if job_org.eq_ignore_ascii_case(&owner) && job_repo.eq_ignore_ascii_case(&repo) => {}
        _ => return err(StatusCode::FORBIDDEN, "Job id does not belong to the given owner/repo.".to_string()),
    }

    let gh_token = crate::auth::resolve_effective_github_token(&headers, &state.db);
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

    // Best-effort pushes to GitHub's own Security/Insights UI, so results
    // are visible the same way GHAS's own Code Scanning + Dependency graph
    // would show them — deliberately non-fatal: a failure here shouldn't
    // fail the gate status the caller already got posted above.
    let resolved_ref = match git_ref.filter(|r| !r.is_empty()) {
        Some(r) => r,
        None => match api.default_branch(&full_name, &gh_token).await {
            Ok(branch) => format!("refs/heads/{branch}"),
            Err(_) => format!("refs/heads/{sha}"),
        },
    };

    if state.config.security.code_scanning.enabled {
        let sarif_doc = serde_json::to_value(ignite_sarif::build_sarif(&issues)).unwrap_or(Value::Null);
        if let Err(e) = api.gh_upload_sarif(&full_name, &sha, &resolved_ref, &sarif_doc, &gh_token).await {
            tracing::warn!("SARIF upload to GitHub Code Scanning failed for {full_name}@{sha}: {e}");
        }

        // GHAS-parity alert-dismissal sync: an issue Ignite already has a
        // human-justified override for shouldn't keep sitting as an open
        // alert in GitHub's own Code Scanning tab. Runs after the SARIF
        // upload above (the alert the upload just created/refreshed is
        // what this looks up) — best-effort/non-fatal, same as every
        // other push in this handler.
        if state.config.security.code_scanning.sync_dismissals {
            let overridden: Vec<&IssueRow> = issues.iter().filter(|i| i.status == "overridden").collect();
            if !overridden.is_empty() {
                match api.gh_list_code_scanning_alerts(&full_name, &resolved_ref, &gh_token).await {
                    Ok(alerts) => {
                        for issue in overridden {
                            let Some(alert_number) = find_matching_open_alert_number(&alerts, issue) else { continue };
                            let comment = issue.justification.as_deref().unwrap_or("Justified and overridden in Ignite.");
                            if let Err(e) = api.gh_dismiss_code_scanning_alert(&full_name, alert_number, "won't fix", comment, &gh_token).await {
                                tracing::warn!("Failed to dismiss code-scanning alert #{alert_number} for {full_name} (issue {}): {e}", issue.id);
                            }
                        }
                    }
                    Err(e) => tracing::warn!("Failed to list code-scanning alerts for {full_name}@{resolved_ref}: {e}"),
                }
            }
        }
    }

    let project_id = state.db.get_project_id_by_job_id(job_id);

    if state.config.security.dependency_graph.enabled {
        if let Some(project_id) = project_id {
            if let Some(scan_json) = state.db.get_dependency_scan_cache(project_id) {
                let snapshot = ignite_dependency_license_scan::build_dependency_graph_snapshot(&scan_json, &sha, &resolved_ref, job_id);
                if let Err(e) = api.gh_submit_dependency_snapshot(&full_name, &snapshot, &gh_token).await {
                    tracing::warn!("Dependency graph snapshot submission failed for {full_name}@{sha}: {e}");
                }
            }
        }
    }

    // GHAS-parity "PR Dependency Review" sticky comment — diffs this
    // project's current dependency scan against its previous one (see
    // `ignite_dependency_license_scan::diff_dependency_scans`'s doc for
    // what "previous" means here) and posts/updates a single comment on
    // the PR, same as `dependency-graph`/`code-scanning` above: only
    // meaningful with a PR to comment on, and best-effort/non-fatal.
    if state.config.security.dependency_review.enabled {
        if let (Some(pr), Some(project_id)) = (pr_number, project_id) {
            if let (Some(head_scan), Some(base_scan)) = (state.db.get_dependency_scan_cache(project_id), state.db.get_previous_dependency_scan_cache(project_id)) {
                let changes = ignite_dependency_license_scan::diff_dependency_scans(&base_scan, &head_scan);
                if let Some(body) = ignite_dependency_license_scan::render_dependency_diff_comment(&changes) {
                    if let Err(e) = api.gh_upsert_pr_sticky_comment(&full_name, pr as u64, ignite_dependency_license_scan::DEPENDENCY_REVIEW_MARKER, &body, &gh_token).await {
                        tracing::warn!("Dependency review comment failed for {full_name}#{pr}: {e}");
                    }
                }
            }
        }
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
        IssueRow { id: format!("{category}::x"), phase: Some(4), category: category.to_string(), severity: severity.to_string(), score: Some(5), summary: "test finding".to_string(), file: file.map(str::to_string), line, snippet: None, cross_file: false, chain: None, cwe: None, owasp: None, tool: None, references: None, duplicate_ref: None, status: status.to_string(), created_at: String::new(), justification: None, actor_email: None, actor_name: None }
    }

    fn alert(number: u64, rule_id: &str, state: &str, path: &str, start_line: i64) -> Value {
        json!({ "number": number, "state": state, "rule": { "id": rule_id }, "most_recent_instance": { "location": { "path": path, "start_line": start_line } } })
    }

    #[test]
    fn find_matching_open_alert_number_matches_by_rule_file_and_line() {
        let issue = issue("secret", "error", "overridden", Some("a.js"), Some(3));
        let alerts = vec![alert(1, "codeql-sast", "open", "a.js", 3), alert(2, "secret", "open", "a.js", 3)];
        assert_eq!(find_matching_open_alert_number(&alerts, &issue), Some(2));
    }

    #[test]
    fn find_matching_open_alert_number_ignores_already_dismissed_alerts() {
        let issue = issue("secret", "error", "overridden", Some("a.js"), Some(3));
        let alerts = vec![alert(1, "secret", "dismissed", "a.js", 3)];
        assert!(find_matching_open_alert_number(&alerts, &issue).is_none());
    }

    #[test]
    fn find_matching_open_alert_number_requires_exact_file_and_line() {
        let issue = issue("secret", "error", "overridden", Some("a.js"), Some(3));
        let alerts = vec![alert(1, "secret", "open", "b.js", 3), alert(2, "secret", "open", "a.js", 4)];
        assert!(find_matching_open_alert_number(&alerts, &issue).is_none());
    }

    #[test]
    fn find_matching_open_alert_number_none_for_project_wide_issue() {
        let issue = issue("secret", "error", "overridden", None, None);
        let alerts = vec![alert(1, "secret", "open", "a.js", 3)];
        assert!(find_matching_open_alert_number(&alerts, &issue).is_none());
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
