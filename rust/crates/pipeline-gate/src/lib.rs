//! Shared pre-flight gate for every path that proposes a PR on Ignite's
//! own behalf (`auto-fix-pr`'s dependency-bump PRs, the interactive
//! fix-pr apply flow, PR-suggestion comments): before anything gets
//! pushed or posted, call the real `POST /api/pipeline/validate-all`
//! against the edited local checkout — the same call the CLI/pre-push
//! hook/`scheduled-rescan` already make — and refuse to treat the result
//! as clean unless it actually is. It is not acceptable for Ignite to
//! propose a fix that its own gate would still reject.
//!
//! "Blocking" mirrors `routes/github_pr_status.rs`'s `build_summary`
//! exactly: `severity == "error"` and not already `overridden`/
//! `baselined`. A network failure or a structural pipeline error
//! (`ok: false`) is never treated as clean — if the gate can't be
//! verified, the PR doesn't go out.

use reqwest::Client;
use serde_json::{json, Value};

#[derive(Debug, Clone, Default)]
pub struct GateResult {
    /// True only when the pipeline ran to completion (`ok: true`) *and*
    /// no unresolved blocking issue came back.
    pub clean: bool,
    pub blocking_issues: Vec<Value>,
    pub job_id: Option<String>,
    /// Set on a request/parse failure or a structural pipeline failure
    /// (`ok: false`) — distinct from "ran fine but found issues".
    pub error: Option<String>,
}

/// Matches `github_pr_status.rs::build_summary`'s definition of a
/// blocking finding.
pub fn is_blocking(issue: &Value) -> bool {
    let severity = issue.get("severity").and_then(|v| v.as_str()).unwrap_or("");
    let status = issue.get("status").and_then(|v| v.as_str()).unwrap_or("");
    severity == "error" && status != "overridden" && status != "baselined"
}

/// Runs `validate-all` against `project_path` (a local checkout — may
/// already have uncommitted edits on disk, that's the point) and reports
/// whether it's clean per [`is_blocking`].
pub async fn scan_checkout(http: &Client, server_base: &str, org: &str, repo: &str, project_path: &str) -> GateResult {
    let mut req = http.post(format!("{server_base}/api/pipeline/validate-all")).json(&json!({ "org": org, "repo": repo, "projectPath": project_path, "runLocalCi": false }));
    // `validate-all` itself doesn't require auth today, but a deployment
    // that fronts the Ignite server with `IGNITE_API_KEY`-gated auth
    // (or adds one in the future) would otherwise permanently block every
    // automated PR proposal that goes through this gate — every headless
    // caller here already runs with the server's own env configured, so
    // reading the same var costs nothing when it's unset.
    if let Ok(key) = std::env::var("IGNITE_API_KEY") {
        req = req.header("Authorization", format!("Bearer {key}"));
    }
    let res = req.send().await;

    let body: Value = match res {
        Ok(r) => match r.json().await {
            Ok(v) => v,
            Err(e) => return GateResult { clean: false, error: Some(format!("failed to parse validate-all response: {e}")), ..Default::default() },
        },
        Err(e) => return GateResult { clean: false, error: Some(format!("validate-all request failed: {e}")), ..Default::default() },
    };

    let job_id = body.get("jobId").and_then(|v| v.as_str()).map(str::to_string);
    let ok = body.get("ok").and_then(|v| v.as_bool()).unwrap_or(true);
    let issues = body.get("issues").and_then(|v| v.as_array()).cloned().unwrap_or_default();

    if !ok {
        let error = body.get("error").and_then(|v| v.as_str()).unwrap_or("validate-all reported ok:false with no error message").to_string();
        return GateResult { clean: false, blocking_issues: vec![], job_id, error: Some(error) };
    }

    let blocking: Vec<Value> = issues.into_iter().filter(is_blocking).collect();
    GateResult { clean: blocking.is_empty(), blocking_issues: blocking, job_id, error: None }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issue(severity: &str, status: Option<&str>) -> Value {
        let mut v = json!({ "severity": severity });
        if let Some(s) = status {
            v["status"] = json!(s);
        }
        v
    }

    #[test]
    fn is_blocking_true_for_open_error() {
        assert!(is_blocking(&issue("error", None)));
    }

    #[test]
    fn is_blocking_false_for_overridden_or_baselined_error() {
        assert!(!is_blocking(&issue("error", Some("overridden"))));
        assert!(!is_blocking(&issue("error", Some("baselined"))));
    }

    #[test]
    fn is_blocking_false_for_warning() {
        assert!(!is_blocking(&issue("warning", None)));
    }

    #[tokio::test]
    async fn scan_checkout_reports_unclean_on_request_failure() {
        let http = Client::new();
        // Nothing listening on this port — a connection failure must
        // fail closed (never silently "clean").
        let result = scan_checkout(&http, "http://127.0.0.1:1", "acme", "widgets", "/tmp/nonexistent").await;
        assert!(!result.clean);
        assert!(result.error.is_some());
    }
}
