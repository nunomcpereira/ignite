//! Faithful port of `lib/github-api.js` — GitHub API access without
//! requiring the `gh` CLI binary. `gh` is still the default when
//! installed (via `ToolRunner`, which resolves it directly off `PATH` as
//! a fixed command); every plain GitHub API call here is a soft
//! dependency the same way trivy/semgrep are for their checks — probed
//! once per `GithubApi` instance, transparently replaced with a direct
//! HTTPS call carrying the same token when the binary isn't installed.

use ignite_tool_runner::{RunToolOptions, ToolRunner};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::OnceCell;

#[derive(Debug, thiserror::Error)]
pub enum GithubApiError {
    #[error(transparent)]
    Tool(#[from] ignite_tool_runner::ToolError),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("GitHub API {method} {path} failed: HTTP {status} {detail}")]
    ApiFailed { method: String, path: String, status: u16, detail: String },
    #[error("GitHub GraphQL error: {0}")]
    GraphQl(String),
    #[error("No GitHub token available (gh not installed, and GH_TOKEN/GITHUB_TOKEN not set) — cannot clone.")]
    NoToken,
    #[error("{0} check(s) failed: {1}")]
    ChecksFailed(usize, String),
    #[error("Timed out waiting for required checks.")]
    ChecksTimedOut,
}

static PR_URL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"https://github\.com/\S+/pull/\d+").unwrap());
static PR_NUMBER_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"/pull/(\d+)").unwrap());

/// GitHub's own username/org naming rule: alphanumeric, single hyphens,
/// cannot begin/end with a hyphen, max 39 chars. Shared single source of
/// truth for every call site that validates an owner before shelling out
/// to `gh`/`git` (routes/github_pr_status.rs, scripts that take an
/// `org/repo` argument) — previously duplicated ad hoc per call site.
static GITHUB_OWNER_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$").unwrap());
/// GitHub's repository naming rule: alphanumeric plus `.`/`_`/`-`, 1-100 chars.
static GITHUB_REPO_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9._-]{1,100}$").unwrap());

pub fn is_valid_github_owner(owner: &str) -> bool {
    GITHUB_OWNER_RE.is_match(owner)
}

pub fn is_valid_github_repo(repo: &str) -> bool {
    GITHUB_REPO_RE.is_match(repo)
}

/// Parses an `org/repo` string, validating both halves against GitHub's
/// real naming rules. Returns `Err` with a human-readable reason on the
/// first invalid part.
pub fn parse_org_repo(spec: &str) -> Result<(String, String), String> {
    let Some((owner, repo)) = spec.split_once('/') else {
        return Err(format!("Expected \"org/repo\", got \"{spec}\""));
    };
    if !is_valid_github_owner(owner) {
        return Err(format!("Invalid GitHub owner/org: \"{owner}\""));
    }
    if !is_valid_github_repo(repo) {
        return Err(format!("Invalid repository name: \"{repo}\""));
    }
    Ok((owner.to_string(), repo.to_string()))
}

pub fn resolve_server_github_token() -> String {
    std::env::var("GH_TOKEN").or_else(|_| std::env::var("GITHUB_TOKEN")).unwrap_or_default()
}

pub struct PrResult {
    pub url: String,
    pub number: Option<u64>,
    pub node_id: Option<String>,
}

pub struct GithubApi<'a> {
    runner: &'a ToolRunner,
    http: reqwest::Client,
    gh_cli_available: OnceCell<bool>,
}

impl<'a> GithubApi<'a> {
    pub fn new(runner: &'a ToolRunner) -> Self {
        GithubApi { runner, http: reqwest::Client::new(), gh_cli_available: OnceCell::new() }
    }

    pub async fn is_gh_cli_available(&self) -> bool {
        *self.gh_cli_available.get_or_init(|| async { self.runner.run_tool("gh", &["--version".to_string()], &std::env::temp_dir().to_string_lossy(), RunToolOptions::default()).await.is_ok() }).await
    }

    pub async fn github_api_request(&self, token: &str, method: &str, api_path: &str, body: Option<&Value>, accept: Option<&str>) -> Result<Option<Value>, GithubApiError> {
        let url = format!("https://api.github.com{api_path}");
        let accept_header = accept.unwrap_or("application/vnd.github+json");
        let mut req = self
            .http
            .request(reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET), &url)
            .timeout(Duration::from_secs(15))
            .header("Accept", accept_header)
            .header("X-GitHub-Api-Version", "2022-11-28");
        if !token.is_empty() {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        if let Some(b) = body {
            req = req.header("Content-Type", "application/json").json(b);
        }
        let res = req.send().await?;
        let status = res.status();
        let text = res.text().await?;
        if !status.is_success() {
            return Err(GithubApiError::ApiFailed { method: method.to_string(), path: api_path.to_string(), status: status.as_u16(), detail: text.chars().take(300).collect() });
        }
        if text.is_empty() {
            return Ok(None);
        }
        if accept == Some("application/vnd.github.raw") {
            return Ok(Some(Value::String(text)));
        }
        Ok(Some(serde_json::from_str(&text)?))
    }

    pub async fn github_graphql_request(&self, token: &str, query: &str, variables: &Value) -> Result<Value, GithubApiError> {
        let body = serde_json::json!({ "query": query, "variables": variables });
        let data = self.github_api_request(token, "POST", "/graphql", Some(&body), None).await?.unwrap_or(Value::Null);
        if let Some(errors) = data.get("errors") {
            if !errors.is_null() {
                return Err(GithubApiError::GraphQl(errors.to_string()));
            }
        }
        Ok(data.get("data").cloned().unwrap_or(Value::Null))
    }

    pub async fn gh_api_write(&self, method: &str, api_path: &str, fields: &HashMap<String, Value>, token: &str) -> Result<Option<Value>, GithubApiError> {
        if self.is_gh_cli_available().await {
            let mut args = vec!["api".to_string(), "-X".to_string(), method.to_string(), api_path.to_string()];
            for (k, v) in fields {
                let flag = if v.is_boolean() || v.is_number() { "-F" } else { "-f" };
                let val = match v {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                args.push(flag.to_string());
                args.push(format!("{k}={val}"));
            }
            let env = HashMap::from([("GH_TOKEN".to_string(), token.to_string())]);
            let out = self.runner.run_tool("gh", &args, &std::env::temp_dir().to_string_lossy(), RunToolOptions { env, ..Default::default() }).await?;
            return Ok(if out.stdout.is_empty() { None } else { Some(serde_json::from_str(&out.stdout)?) });
        }
        self.github_api_request(token, method, &format!("/{api_path}"), Some(&Value::Object(fields.iter().map(|(k, v)| (k.clone(), v.clone())).collect())), None).await
    }

    pub async fn gh_api_get(&self, api_path: &str, token: &str) -> Result<Option<Value>, GithubApiError> {
        if self.is_gh_cli_available().await {
            let env = HashMap::from([("GH_TOKEN".to_string(), token.to_string())]);
            let out = self.runner.run_tool("gh", &["api".to_string(), api_path.to_string()], &std::env::temp_dir().to_string_lossy(), RunToolOptions { env, ..Default::default() }).await?;
            return Ok(if out.stdout.is_empty() { None } else { Some(serde_json::from_str(&out.stdout)?) });
        }
        self.github_api_request(token, "GET", &format!("/{api_path}"), None, None).await
    }

    pub async fn gh_fetch_file_raw(&self, repo_full_name: &str, file_path: &str, token: &str) -> Result<Option<String>, GithubApiError> {
        if self.is_gh_cli_available().await {
            let out = self
                .runner
                .run_tool("gh", &["api".to_string(), format!("repos/{repo_full_name}/contents/{file_path}"), "-H".to_string(), "Accept: application/vnd.github.raw".to_string()], &std::env::temp_dir().to_string_lossy(), RunToolOptions::default())
                .await?;
            return Ok(Some(out.stdout));
        }
        let v = self.github_api_request(token, "GET", &format!("/repos/{repo_full_name}/contents/{file_path}"), None, Some("application/vnd.github.raw")).await?;
        Ok(v.and_then(|v| v.as_str().map(str::to_string)))
    }

    pub async fn gh_list_commits(&self, repo_full_name: &str, file_path: &str, token: &str) -> Result<Value, GithubApiError> {
        if self.is_gh_cli_available().await {
            let out = self.runner.run_tool("gh", &["api".to_string(), format!("repos/{repo_full_name}/commits?path={file_path}&per_page=1")], &std::env::temp_dir().to_string_lossy(), RunToolOptions::default()).await?;
            return Ok(serde_json::from_str(&out.stdout)?);
        }
        Ok(self.github_api_request(token, "GET", &format!("/repos/{repo_full_name}/commits?path={file_path}&per_page=1"), None, None).await?.unwrap_or(Value::Null))
    }

    pub async fn gh_create_pr(&self, full_name: &str, base: &str, head: &str, title: &str, body: &str, token: &str) -> Result<PrResult, GithubApiError> {
        if self.is_gh_cli_available().await {
            let env = HashMap::from([("GH_TOKEN".to_string(), token.to_string())]);
            let out = self
                .runner
                .run_tool("gh", &["pr".to_string(), "create".to_string(), "--repo".to_string(), full_name.to_string(), "--base".to_string(), base.to_string(), "--head".to_string(), head.to_string(), "--title".to_string(), title.to_string(), "--body".to_string(), body.to_string()], &std::env::temp_dir().to_string_lossy(), RunToolOptions { env, ..Default::default() })
                .await?;
            let url = PR_URL_RE.find(&out.stdout).map(|m| m.as_str().to_string()).unwrap_or(out.stdout.clone());
            let number = PR_NUMBER_RE.captures(&url).and_then(|c| c[1].parse::<u64>().ok());
            return Ok(PrResult { url, number, node_id: None });
        }
        let body_json = serde_json::json!({ "title": title, "body": body, "base": base, "head": head });
        let pr = self.github_api_request(token, "POST", &format!("/repos/{full_name}/pulls"), Some(&body_json), None).await?.unwrap_or(Value::Null);
        Ok(PrResult { url: pr["html_url"].as_str().unwrap_or_default().to_string(), number: pr["number"].as_u64(), node_id: pr["node_id"].as_str().map(str::to_string) })
    }

    pub async fn gh_arm_auto_merge(&self, full_name: &str, pr_url: &str, pr_number: u64, pr_node_id: Option<&str>, token: &str) -> Result<(), GithubApiError> {
        if self.is_gh_cli_available().await {
            let env = HashMap::from([("GH_TOKEN".to_string(), token.to_string())]);
            self.runner.run_tool("gh", &["pr".to_string(), "merge".to_string(), pr_url.to_string(), "--auto".to_string(), "--squash".to_string()], &std::env::temp_dir().to_string_lossy(), RunToolOptions { env, ..Default::default() }).await?;
            return Ok(());
        }
        let node_id = match pr_node_id {
            Some(id) => id.to_string(),
            None => {
                let pr = self.github_api_request(token, "GET", &format!("/repos/{full_name}/pulls/{pr_number}"), None, None).await?.unwrap_or(Value::Null);
                pr["node_id"].as_str().unwrap_or_default().to_string()
            }
        };
        self.github_graphql_request(
            token,
            "mutation($id: ID!) { enablePullRequestAutoMerge(input: { pullRequestId: $id, mergeMethod: SQUASH }) { clientMutationId } }",
            &serde_json::json!({ "id": node_id }),
        )
        .await?;
        Ok(())
    }

    pub async fn gh_watch_pr_checks(&self, full_name: &str, pr_url: &str, pr_number: u64, token: &str, mut log: impl FnMut(&str) + Send, timeout_ms: u64) -> Result<(), GithubApiError> {
        if self.is_gh_cli_available().await {
            let env = HashMap::from([("GH_TOKEN".to_string(), token.to_string())]);
            self.runner
                .run_tool_streaming("gh", &["pr".to_string(), "checks".to_string(), pr_url.to_string(), "--watch".to_string(), "--interval".to_string(), "15".to_string()], &std::env::temp_dir().to_string_lossy(), |line| log(&line.chars().take(300).collect::<String>()), &env, timeout_ms)
                .await?;
            return Ok(());
        }
        let pr = self.github_api_request(token, "GET", &format!("/repos/{full_name}/pulls/{pr_number}"), None, None).await?.unwrap_or(Value::Null);
        let sha = pr["head"]["sha"].as_str().unwrap_or_default().to_string();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
        while tokio::time::Instant::now() < deadline {
            let resp = self.github_api_request(token, "GET", &format!("/repos/{full_name}/commits/{sha}/check-runs"), None, None).await?.unwrap_or(Value::Null);
            let runs = resp["check_runs"].as_array().cloned().unwrap_or_default();
            if !runs.is_empty() {
                let pending: Vec<&Value> = runs.iter().filter(|r| r["status"].as_str() != Some("completed")).collect();
                if pending.is_empty() {
                    let failed: Vec<&Value> = runs.iter().filter(|r| !matches!(r["conclusion"].as_str(), Some("success") | Some("neutral") | Some("skipped"))).collect();
                    if !failed.is_empty() {
                        let names = failed.iter().map(|r| r["name"].as_str().unwrap_or("?").to_string()).collect::<Vec<_>>().join(", ");
                        return Err(GithubApiError::ChecksFailed(failed.len(), names));
                    }
                    log("✓ All checks completed successfully.");
                    return Ok(());
                }
                let names = pending.iter().map(|r| r["name"].as_str().unwrap_or("?").to_string()).collect::<Vec<_>>().join(", ");
                log(&format!("Waiting on {} check(s): {names}...", pending.len()));
            } else {
                log("No check-runs reported yet...");
            }
            tokio::time::sleep(Duration::from_secs(15)).await;
        }
        Err(GithubApiError::ChecksTimedOut)
    }

    pub async fn gh_create_issue(&self, full_name: &str, title: &str, body: &str, token: &str) -> Result<(), GithubApiError> {
        if self.is_gh_cli_available().await {
            self.runner.run_tool("gh", &["issue".to_string(), "create".to_string(), "--repo".to_string(), full_name.to_string(), "--title".to_string(), title.to_string(), "--body".to_string(), body.to_string()], &std::env::temp_dir().to_string_lossy(), RunToolOptions::default()).await?;
            return Ok(());
        }
        self.github_api_request(token, "POST", &format!("/repos/{full_name}/issues"), Some(&serde_json::json!({ "title": title, "body": body })), None).await?;
        Ok(())
    }

    /// A multi-line markdown body can't go through `run_tool`'s CLI-arg
    /// sanitizer (rejects `\n` in any argument), so the `gh` path writes
    /// it to a temp file and uses `--body-file` instead of `--body`. PR
    /// comments are just issue comments under GitHub's REST model, hence
    /// the `/issues/{number}/comments` path for the fallback.
    pub async fn gh_comment_on_pr(&self, full_name: &str, pr_number: u64, body: &str, token: &str) -> Result<(), GithubApiError> {
        if self.is_gh_cli_available().await {
            let tmp_dir = tempfile::Builder::new().prefix("ignite-pr-comment-").tempdir()?;
            let tmp_file = tmp_dir.path().join("body.md");
            std::fs::write(&tmp_file, body)?;
            let env = HashMap::from([("GH_TOKEN".to_string(), token.to_string())]);
            let result = self
                .runner
                .run_tool("gh", &["pr".to_string(), "comment".to_string(), pr_number.to_string(), "--repo".to_string(), full_name.to_string(), "--body-file".to_string(), tmp_file.to_string_lossy().into_owned()], &std::env::temp_dir().to_string_lossy(), RunToolOptions { env, ..Default::default() })
                .await;
            drop(tmp_dir); // removes the temp dir + file regardless of outcome
            result?;
            return Ok(());
        }
        self.github_api_request(token, "POST", &format!("/repos/{full_name}/issues/{pr_number}/comments"), Some(&serde_json::json!({ "body": body })), None).await?;
        Ok(())
    }

    /// The repo's current default branch, per `GET repos/{full_name}`.
    /// Prefers the `gh` CLI (same dual-path convention as `gh_api_write`),
    /// falling back to a token-only REST call. Read-only — safe to call
    /// even from a dry-run.
    pub async fn default_branch(&self, full_name: &str, token: &str) -> Result<String, GithubApiError> {
        let value = if self.is_gh_cli_available().await {
            let out = self.runner.run_tool("gh", &["api".to_string(), format!("repos/{full_name}")], &std::env::temp_dir().to_string_lossy(), RunToolOptions::default()).await?;
            serde_json::from_str::<Value>(&out.stdout)?
        } else {
            self.github_api_request(token, "GET", &format!("/repos/{full_name}"), None, None).await?.unwrap_or(Value::Null)
        };
        value
            .get("default_branch")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| GithubApiError::ApiFailed { method: "GET".to_string(), path: format!("repos/{full_name}"), status: 0, detail: "response had no default_branch field".to_string() })
    }

    /// The current HEAD commit SHA of `branch` on `full_name`, per
    /// `GET repos/{full_name}/commits/{branch}`. Same gh-CLI-first /
    /// token-fallback shape as `default_branch` — used to get the exact
    /// commit a fresh clone landed on without depending on that clone's
    /// own `.git` history (works the same for a shallow clone).
    pub async fn head_sha(&self, full_name: &str, branch: &str, token: &str) -> Result<String, GithubApiError> {
        let value = if self.is_gh_cli_available().await {
            let out = self.runner.run_tool("gh", &["api".to_string(), format!("repos/{full_name}/commits/{branch}")], &std::env::temp_dir().to_string_lossy(), RunToolOptions::default()).await?;
            serde_json::from_str::<Value>(&out.stdout)?
        } else {
            self.github_api_request(token, "GET", &format!("/repos/{full_name}/commits/{branch}"), None, None).await?.unwrap_or(Value::Null)
        };
        value
            .get("sha")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| GithubApiError::ApiFailed { method: "GET".to_string(), path: format!("repos/{full_name}/commits/{branch}"), status: 0, detail: "response had no sha field".to_string() })
    }

    /// Shallow-clones `full_name` at `branch` (typically the repo's current
    /// default branch, from `default_branch`) into `dest_dir`. Same
    /// gh-CLI-first / token-fallback shape as `gh_clone_repo`, but takes an
    /// explicit branch instead of hardcoding `main`.
    pub async fn gh_clone_repo_branch(&self, full_name: &str, branch: &str, dest_dir: &str, token: &str) -> Result<(), GithubApiError> {
        if self.is_gh_cli_available().await {
            self.runner.run_tool("gh", &["repo".to_string(), "clone".to_string(), full_name.to_string(), dest_dir.to_string(), "--".to_string(), "--depth".to_string(), "1".to_string(), "--branch".to_string(), branch.to_string()], &std::env::temp_dir().to_string_lossy(), RunToolOptions::default()).await?;
            return Ok(());
        }
        if token.is_empty() {
            return Err(GithubApiError::NoToken);
        }
        self.runner
            .run_tool("git", &["-c".to_string(), format!("http.extraheader=AUTHORIZATION: bearer {token}"), "clone".to_string(), "--depth".to_string(), "1".to_string(), "--branch".to_string(), branch.to_string(), format!("https://github.com/{full_name}.git"), dest_dir.to_string()], &std::env::temp_dir().to_string_lossy(), RunToolOptions::default())
            .await?;
        Ok(())
    }

    pub async fn gh_clone_repo(&self, full_name: &str, dest_dir: &str, token: &str) -> Result<(), GithubApiError> {
        if self.is_gh_cli_available().await {
            self.runner.run_tool("gh", &["repo".to_string(), "clone".to_string(), full_name.to_string(), dest_dir.to_string(), "--".to_string(), "--depth".to_string(), "1".to_string(), "--branch".to_string(), "main".to_string()], &std::env::temp_dir().to_string_lossy(), RunToolOptions::default()).await?;
            return Ok(());
        }
        if token.is_empty() {
            return Err(GithubApiError::NoToken);
        }
        // http.extraheader is a one-off override for this invocation only —
        // unlike embedding the token in the remote URL, it's never written
        // to the cloned repo's own .git/config.
        self.runner
            .run_tool("git", &["-c".to_string(), format!("http.extraheader=AUTHORIZATION: bearer {token}"), "clone".to_string(), "--depth".to_string(), "1".to_string(), "--branch".to_string(), "main".to_string(), format!("https://github.com/{full_name}.git"), dest_dir.to_string()], &std::env::temp_dir().to_string_lossy(), RunToolOptions::default())
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Serializes tests that mutate the process-global PATH env var.
    static PATH_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn parse_org_repo_accepts_valid_spec() {
        assert_eq!(parse_org_repo("my-org/my-repo.name_1"), Ok(("my-org".to_string(), "my-repo.name_1".to_string())));
    }

    #[test]
    fn parse_org_repo_rejects_missing_slash() {
        assert!(parse_org_repo("no-slash-here").is_err());
    }

    #[test]
    fn parse_org_repo_rejects_invalid_owner() {
        assert!(parse_org_repo("-bad-owner/repo").unwrap_err().contains("Invalid GitHub owner/org"));
    }

    #[test]
    fn parse_org_repo_rejects_invalid_repo() {
        assert!(parse_org_repo("org/bad repo name").unwrap_err().contains("Invalid repository name"));
    }

    #[test]
    fn owner_validator_rejects_too_long() {
        assert!(!is_valid_github_owner(&"a".repeat(40)));
        assert!(is_valid_github_owner(&"a".repeat(39)));
    }

    fn make_fake_gh(dir: &std::path::Path, call_log_path: &std::path::Path) {
        let script_path = dir.join("gh");
        let script = format!(
            r#"#!/bin/sh
if [ "$1" = "--version" ]; then echo "gh version 2.0.0 fake"; exit 0; fi
if [ "$1" = "pr" ] && [ "$2" = "comment" ]; then
  args="$@"
  body_file=""
  prev=""
  for a in "$@"; do
    if [ "$prev" = "--body-file" ]; then body_file="$a"; fi
    prev="$a"
  done
  body_contents=""
  if [ -n "$body_file" ]; then body_contents=$(cat "$body_file"); fi
  printf '{{"args": "%s", "bodyFile": "%s"}}' "$args" "$body_file" > "{}"
  exit 0
fi
exit 1
"#,
            call_log_path.display()
        );
        std::fs::write(&script_path, script).unwrap();
        let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        std::fs::set_permissions(&script_path, perms).unwrap();
    }

    fn make_fake_gh_repo_lookup(dir: &std::path::Path) {
        let script_path = dir.join("gh");
        let script = r#"#!/bin/sh
if [ "$1" = "--version" ]; then echo "gh version 2.0.0 fake"; exit 0; fi
if [ "$1" = "api" ] && [ "$2" = "repos/acme/widgets" ]; then echo '{"default_branch":"main"}'; exit 0; fi
if [ "$1" = "api" ] && [ "$2" = "repos/acme/widgets/commits/main" ]; then echo '{"sha":"deadbeef1234567890"}'; exit 0; fi
echo "unexpected args: $@" >&2
exit 1
"#;
        std::fs::write(&script_path, script).unwrap();
        let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        std::fs::set_permissions(&script_path, perms).unwrap();
    }

    #[tokio::test]
    async fn default_branch_resolves_via_gh_cli() {
        let _guard = PATH_LOCK.lock().unwrap();
        let fake_gh_dir = tempfile::tempdir().unwrap();
        make_fake_gh_repo_lookup(fake_gh_dir.path());
        let original_path = std::env::var("PATH").unwrap_or_default();
        std::env::set_var("PATH", format!("{}:{}", fake_gh_dir.path().display(), original_path));

        let runner = ToolRunner::new(HashMap::new());
        let api = GithubApi::new(&runner);
        let branch = api.default_branch("acme/widgets", "tok").await.unwrap();

        std::env::set_var("PATH", &original_path);
        assert_eq!(branch, "main");
    }

    #[tokio::test]
    async fn head_sha_resolves_via_gh_cli() {
        let _guard = PATH_LOCK.lock().unwrap();
        let fake_gh_dir = tempfile::tempdir().unwrap();
        make_fake_gh_repo_lookup(fake_gh_dir.path());
        let original_path = std::env::var("PATH").unwrap_or_default();
        std::env::set_var("PATH", format!("{}:{}", fake_gh_dir.path().display(), original_path));

        let runner = ToolRunner::new(HashMap::new());
        let api = GithubApi::new(&runner);
        let sha = api.head_sha("acme/widgets", "main", "tok").await.unwrap();

        std::env::set_var("PATH", &original_path);
        assert_eq!(sha, "deadbeef1234567890");
    }

    #[tokio::test]
    async fn gh_comment_on_pr_writes_multiline_body_to_body_file_not_body() {
        let _guard = PATH_LOCK.lock().unwrap();
        let fake_gh_dir = tempfile::tempdir().unwrap();
        let call_log = tempfile::NamedTempFile::new().unwrap();
        make_fake_gh(fake_gh_dir.path(), call_log.path());

        let original_path = std::env::var("PATH").unwrap_or_default();
        std::env::set_var("PATH", format!("{}:{}", fake_gh_dir.path().display(), original_path));

        let runner = ToolRunner::new(HashMap::new());
        let api = GithubApi::new(&runner);
        let multiline_body = "### Ignite gate failed\n\n- one\n- two\n";
        api.gh_comment_on_pr("acme/widgets", 7, multiline_body, "tok").await.unwrap();

        std::env::set_var("PATH", &original_path);

        let call: Value = serde_json::from_str(&std::fs::read_to_string(call_log.path()).unwrap()).unwrap();
        let args = call["args"].as_str().unwrap();
        assert!(args.starts_with("pr comment 7 --repo acme/widgets"));
        assert!(args.contains("--body-file"));
        assert!(!args.contains(" --body ") && !args.ends_with(" --body"));
        let body_file = call["bodyFile"].as_str().unwrap();
        assert!(!body_file.is_empty());
        // temp dir/file must be gone after the call
        assert!(!std::path::Path::new(body_file).exists());
    }
}
