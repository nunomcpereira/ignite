//! Faithful port of `lib/github-api.js` — GitHub API access without
//! requiring the `gh` CLI binary. `gh` is still the default when
//! installed (via `ToolRunner`, which resolves it directly off `PATH` as
//! a fixed command); every plain GitHub API call here is a soft
//! dependency the same way trivy/semgrep are for their checks — probed
//! once per `GithubApi` instance, transparently replaced with a direct
//! HTTPS call carrying the same token when the binary isn't installed.
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

use base64::Engine;
use flate2::write::GzEncoder;
use flate2::Compression;
use ignite_tool_runner::{RunToolOptions, ToolRunner};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;
use std::io::Write;
use std::time::Duration;
use tokio::sync::OnceCell;

mod webhook_auth;
pub use webhook_auth::{record_delivery_once, verify_webhook_signature};

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
static GITHUB_OWNER_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9](?:-?[A-Za-z0-9]){0,38}$").unwrap());
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

/// The env override to pass a `gh` CLI invocation so it authenticates as
/// `token` instead of silently falling back to the CLI's own ambient
/// `gh auth login` identity — every gh-CLI call site that carries an
/// explicit per-request token (a connected user's session token, a
/// resolved server token) must use this rather than `RunToolOptions::default()`
/// or that token is dropped. Empty when `token` is empty: `ToolRunner::build_env`
/// already inherits the process's own `GH_TOKEN`/`GITHUB_TOKEN`, and setting
/// `GH_TOKEN=""` here would shadow that inherited value and any locally
/// stored `gh auth login` credentials with an empty one, breaking the
/// existing "no explicit token — fall back to gh's own auth" case.
fn gh_token_env(token: &str) -> HashMap<String, String> {
    if token.is_empty() {
        HashMap::new()
    } else {
        HashMap::from([("GH_TOKEN".to_string(), token.to_string())])
    }
}

/// Sets `http.extraheader` for a raw `git` invocation via the
/// `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_n`/`GIT_CONFIG_VALUE_n` environment
/// variables (supported since Git 2.31) instead of a `-c` command-line
/// argument — the token never appears in `git`'s own argv, so it isn't
/// visible to other users on the host via `/proc/<pid>/cmdline` or `ps
/// aux` the way an inline `-c http.extraheader=...bearer {token}` would be.
pub fn git_extraheader_token_env(token: &str) -> HashMap<String, String> {
    HashMap::from([
        ("GIT_CONFIG_COUNT".to_string(), "1".to_string()),
        ("GIT_CONFIG_KEY_0".to_string(), "http.extraheader".to_string()),
        ("GIT_CONFIG_VALUE_0".to_string(), format!("AUTHORIZATION: bearer {token}")),
    ])
}

/// The `id` of the first comment in `comments` (as returned by
/// `GET .../issues/{n}/comments`) whose `body` contains `marker`, if any
/// — pulled out of `gh_upsert_pr_sticky_comment` so the "which comment is
/// ours" matching logic is unit-testable without a real GitHub API call.
fn find_marker_comment_id(comments: &[Value], marker: &str) -> Option<u64> {
    comments.iter().find_map(|c| {
        let has_marker = c.get("body").and_then(|b| b.as_str()).is_some_and(|b| b.contains(marker));
        has_marker.then(|| c.get("id").and_then(|v| v.as_u64())).flatten()
    })
}

/// `true` if any comment in `comments` (as returned by
/// `gh_list_pr_review_comments`) carries `marker` in its body — the same
/// "find my own prior post" check `find_marker_comment_id` does for issue
/// comments, but boolean rather than an id: the Review Comments API has no
/// PATCH-based upsert Ignite already uses elsewhere (`gh_upsert_pr_sticky_comment`),
/// so a caller that finds a match skips posting again rather than editing
/// an existing suggestion in place.
pub fn find_review_comment_marker(comments: &[Value], marker: &str) -> bool {
    comments.iter().any(|c| c.get("body").and_then(|b| b.as_str()).is_some_and(|b| b.contains(marker)))
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
        let url = format!("https://api.github.com/{}", api_path.trim_start_matches('/'));
        let accept_header = accept.unwrap_or("application/vnd.github+json");
        let mut req = self
            .http
            .request(reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET), &url)
            .timeout(Duration::from_secs(15))
            .header("Accept", accept_header)
            .header("User-Agent", "ignite")
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
        // `gh api -f`/`-F` only carry scalar values — an object/array field
        // stringified via `other.to_string()` below would go over as opaque
        // JSON text (e.g. a literal `{"a":1}` string) instead of a
        // structured field, with no error raised. Route those calls
        // through the raw REST fallback instead, which serializes the
        // whole body correctly.
        let has_non_scalar = fields.values().any(|v| v.is_object() || v.is_array());
        // A non-scalar payload used to always fall through to the raw
        // REST fallback below, which requires an explicit `token` —
        // `resolve_server_github_token()` returns "" for an operator who
        // only ever ran `gh auth login` (no `GH_TOKEN`/`GITHUB_TOKEN` env
        // var set), so every non-scalar write failed with 401 even though
        // the `gh` CLI itself was fully authenticated. `gh api --input
        // <file>` runs through the CLI's own stored session instead of
        // needing a token passed in at all.
        if has_non_scalar && self.is_gh_cli_available().await {
            let mut tmp = tempfile::NamedTempFile::new()?;
            std::io::Write::write_all(&mut tmp, &serde_json::to_vec(&Value::Object(fields.iter().map(|(k, v)| (k.clone(), v.clone())).collect()))?)?;
            let args = vec!["api".to_string(), "-X".to_string(), method.to_string(), api_path.to_string(), "--input".to_string(), tmp.path().to_string_lossy().into_owned()];
            let env = gh_token_env(token);
            let out = self.runner.run_tool("gh", &args, &std::env::temp_dir().to_string_lossy(), RunToolOptions { env, ..Default::default() }).await?;
            return Ok(if out.stdout.is_empty() { None } else { Some(serde_json::from_str(&out.stdout)?) });
        }
        if !has_non_scalar && self.is_gh_cli_available().await {
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
            let env = gh_token_env(token);
            let out = self.runner.run_tool("gh", &args, &std::env::temp_dir().to_string_lossy(), RunToolOptions { env, ..Default::default() }).await?;
            return Ok(if out.stdout.is_empty() { None } else { Some(serde_json::from_str(&out.stdout)?) });
        }
        self.github_api_request(token, method, &format!("/{api_path}"), Some(&Value::Object(fields.iter().map(|(k, v)| (k.clone(), v.clone())).collect())), None).await
    }

    pub async fn gh_api_get(&self, api_path: &str, token: &str) -> Result<Option<Value>, GithubApiError> {
        if self.is_gh_cli_available().await {
            let env = gh_token_env(token);
            let out = self.runner.run_tool("gh", &["api".to_string(), api_path.to_string()], &std::env::temp_dir().to_string_lossy(), RunToolOptions { env, ..Default::default() }).await?;
            return Ok(if out.stdout.is_empty() { None } else { Some(serde_json::from_str(&out.stdout)?) });
        }
        self.github_api_request(token, "GET", &format!("/{api_path}"), None, None).await
    }

    pub async fn gh_fetch_file_raw(&self, repo_full_name: &str, file_path: &str, token: &str) -> Result<Option<String>, GithubApiError> {
        if self.is_gh_cli_available().await {
            let env = gh_token_env(token);
            let out = self
                .runner
                .run_tool("gh", &["api".to_string(), format!("repos/{repo_full_name}/contents/{file_path}"), "-H".to_string(), "Accept: application/vnd.github.raw".to_string()], &std::env::temp_dir().to_string_lossy(), RunToolOptions { env, ..Default::default() })
                .await?;
            return Ok(Some(out.stdout));
        }
        let v = self.github_api_request(token, "GET", &format!("/repos/{repo_full_name}/contents/{file_path}"), None, Some("application/vnd.github.raw")).await?;
        Ok(v.and_then(|v| v.as_str().map(str::to_string)))
    }

    pub async fn gh_list_commits(&self, repo_full_name: &str, file_path: &str, token: &str) -> Result<Value, GithubApiError> {
        if self.is_gh_cli_available().await {
            let env = gh_token_env(token);
            let out = self.runner.run_tool("gh", &["api".to_string(), format!("repos/{repo_full_name}/commits?path={file_path}&per_page=1")], &std::env::temp_dir().to_string_lossy(), RunToolOptions { env, ..Default::default() }).await?;
            return Ok(serde_json::from_str(&out.stdout)?);
        }
        Ok(self.github_api_request(token, "GET", &format!("/repos/{repo_full_name}/commits?path={file_path}&per_page=1"), None, None).await?.unwrap_or(Value::Null))
    }

    pub async fn gh_create_pr(&self, full_name: &str, base: &str, head: &str, title: &str, body: &str, token: &str) -> Result<PrResult, GithubApiError> {
        if self.is_gh_cli_available().await {
            // `--body` is a CLI argument, and `sanitize_cli_arg` rejects
            // any argument containing a control character — including
            // `\n`/`\r`, which every multiline PR description (the common
            // case for an auto-fix/onboarding-generated body) contains.
            // `--body-file` (same fix `gh_comment_on_pr` already uses)
            // sidesteps that entirely by passing the body as file content
            // instead of an argument.
            let tmp_dir = tempfile::Builder::new().prefix("ignite-pr-body-").tempdir()?;
            let tmp_file = tmp_dir.path().join("body.md");
            std::fs::write(&tmp_file, body)?;
            let env = gh_token_env(token);
            let out = self
                .runner
                .run_tool(
                    "gh",
                    &["pr".to_string(), "create".to_string(), "--repo".to_string(), full_name.to_string(), "--base".to_string(), base.to_string(), "--head".to_string(), head.to_string(), "--title".to_string(), title.to_string(), "--body-file".to_string(), tmp_file.to_string_lossy().into_owned()],
                    &std::env::temp_dir().to_string_lossy(),
                    RunToolOptions { env, ..Default::default() },
                )
                .await;
            drop(tmp_dir);
            let out = out?;
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
            let env = gh_token_env(token);
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
            let env = gh_token_env(token);
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
            // Same `--body-file` fix as `gh_create_pr` above — `--body`
            // as a CLI argument is rejected by `sanitize_cli_arg` for any
            // multiline body.
            let tmp_dir = tempfile::Builder::new().prefix("ignite-issue-body-").tempdir()?;
            let tmp_file = tmp_dir.path().join("body.md");
            std::fs::write(&tmp_file, body)?;
            let env = gh_token_env(token);
            let result = self
                .runner
                .run_tool("gh", &["issue".to_string(), "create".to_string(), "--repo".to_string(), full_name.to_string(), "--title".to_string(), title.to_string(), "--body-file".to_string(), tmp_file.to_string_lossy().into_owned()], &std::env::temp_dir().to_string_lossy(), RunToolOptions { env, ..Default::default() })
                .await;
            drop(tmp_dir);
            result?;
            return Ok(());
        }
        self.github_api_request(token, "POST", &format!("/repos/{full_name}/issues"), Some(&serde_json::json!({ "title": title, "body": body })), None).await?;
        Ok(())
    }

    /// Pushes a dependency-graph snapshot via GitHub's Dependency
    /// Submission API (`POST repos/{full_name}/dependency-graph/snapshots`),
    /// so results show up in the repo's native Insights > Dependency graph
    /// tab the same way Dependabot's own submission would. No `gh` CLI
    /// subcommand exists for this endpoint, so it always goes through the
    /// raw REST call regardless of whether `gh` is installed.
    pub async fn gh_submit_dependency_snapshot(&self, full_name: &str, snapshot: &Value, token: &str) -> Result<(), GithubApiError> {
        self.github_api_request(token, "POST", &format!("/repos/{full_name}/dependency-graph/snapshots"), Some(snapshot), None).await?;
        Ok(())
    }

    /// Uploads a SARIF document via GitHub's Code Scanning API (`POST
    /// repos/{full_name}/code-scanning/sarifs`), so findings appear
    /// natively in the repo's Security > Code scanning alerts tab. GitHub
    /// requires the SARIF payload gzip-compressed then base64-encoded; no
    /// `gh` CLI subcommand exists for this endpoint, so it always goes
    /// through the raw REST call.
    pub async fn gh_upload_sarif(&self, full_name: &str, commit_sha: &str, git_ref: &str, sarif: &Value, token: &str) -> Result<(), GithubApiError> {
        let sarif_bytes = serde_json::to_vec(sarif)?;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&sarif_bytes)?;
        let gzipped = encoder.finish()?;
        let sarif_b64 = base64::engine::general_purpose::STANDARD.encode(gzipped);
        let body = serde_json::json!({ "commit_sha": commit_sha, "ref": git_ref, "sarif": sarif_b64 });
        self.github_api_request(token, "POST", &format!("/repos/{full_name}/code-scanning/sarifs"), Some(&body), None).await?;
        Ok(())
    }

    /// Every currently-open code-scanning alert on `full_name` for
    /// `git_ref`, per `GET repos/{full}/code-scanning/alerts?ref=...&state=open`
    /// — the read half of alert-dismissal sync (see
    /// `gh_dismiss_code_scanning_alert`). Always goes through the raw
    /// REST call (no `gh` CLI subcommand for this endpoint, same as
    /// `gh_upload_sarif`/`gh_submit_dependency_snapshot`). Capped at the
    /// first 100 open alerts (`per_page=100`, no pagination) — plenty for
    /// matching against Ignite's own just-uploaded SARIF findings, which
    /// realistically never exceeds that per scan.
    pub async fn gh_list_code_scanning_alerts(&self, full_name: &str, git_ref: &str, token: &str) -> Result<Vec<Value>, GithubApiError> {
        let alerts = self.github_api_request(token, "GET", &format!("/repos/{full_name}/code-scanning/alerts?ref={git_ref}&state=open&per_page=100"), None, None).await?;
        Ok(alerts.and_then(|v| v.as_array().cloned()).unwrap_or_default())
    }

    /// Dismisses one code-scanning alert — the write half of
    /// alert-dismissal sync: when Ignite's own override-engine already
    /// has a human-justified override for the finding an alert
    /// represents, GitHub's copy of that alert shouldn't keep showing as
    /// an open, unaddressed risk. `reason` must be one of GitHub's own
    /// enum values (`"false positive"`, `"won't fix"`, `"used in tests"`);
    /// `comment` carries Ignite's actual justification text, since
    /// Ignite's override model doesn't capture which of those three
    /// buckets a justification falls into.
    pub async fn gh_dismiss_code_scanning_alert(&self, full_name: &str, alert_number: u64, reason: &str, comment: &str, token: &str) -> Result<(), GithubApiError> {
        let body = serde_json::json!({ "state": "dismissed", "dismissed_reason": reason, "dismissed_comment": comment });
        self.github_api_request(token, "PATCH", &format!("/repos/{full_name}/code-scanning/alerts/{alert_number}"), Some(&body), None).await?;
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
            let env = gh_token_env(token);
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

    /// Posts `body` as a PR comment, editing a prior comment carrying the
    /// same `marker` in place instead of appending a new one every call —
    /// the "sticky comment" pattern GHAS's own `dependency-review-action`
    /// and similar bots use so a PR doesn't accumulate one stale comment
    /// per push. Always goes through the raw REST API (not the `gh` CLI,
    /// which has no built-in "find and edit my own comment" subcommand)
    /// for the list/patch steps; falls back to `gh_comment_on_pr` (which
    /// does prefer the CLI) to create the first comment when none exists
    /// yet. `marker` should be a value that only this bot's own comments
    /// ever contain (e.g. a hidden HTML comment) — every comment on the
    /// PR is scanned, so an accidental match would edit a human's comment.
    pub async fn gh_upsert_pr_sticky_comment(&self, full_name: &str, pr_number: u64, marker: &str, body: &str, token: &str) -> Result<(), GithubApiError> {
        let comments = self.github_api_request(token, "GET", &format!("/repos/{full_name}/issues/{pr_number}/comments?per_page=100"), None, None).await?.and_then(|v| v.as_array().cloned()).unwrap_or_default();
        let existing_id = find_marker_comment_id(&comments, marker);
        match existing_id {
            Some(id) => {
                self.github_api_request(token, "PATCH", &format!("/repos/{full_name}/issues/comments/{id}"), Some(&serde_json::json!({ "body": body })), None).await?;
                Ok(())
            }
            None => self.gh_comment_on_pr(full_name, pr_number, body, token).await,
        }
    }

    /// Every review comment currently on `pr_number` (`GET
    /// repos/{full}/pulls/{pr}/comments`) — the read half of inline PR
    /// suggestion dedup (see [`find_review_comment_marker`]). No `gh` CLI
    /// subcommand covers this endpoint (same as `gh_upload_sarif`/
    /// `gh_submit_dependency_snapshot`), so it always goes through the raw
    /// REST call. Capped at the first 100 comments (`per_page=100`, no
    /// pagination) — plenty for matching against the handful of
    /// suggestions Ignite itself ever posts on one PR.
    pub async fn gh_list_pr_review_comments(&self, full_name: &str, pr_number: u64, token: &str) -> Result<Vec<Value>, GithubApiError> {
        let comments = self.github_api_request(token, "GET", &format!("/repos/{full_name}/pulls/{pr_number}/comments?per_page=100"), None, None).await?;
        Ok(comments.and_then(|v| v.as_array().cloned()).unwrap_or_default())
    }

    /// Posts one inline PR review comment carrying a ```suggestion fenced
    /// block (GHAS Copilot-Autofix parity) — GitHub's PR Review Comments
    /// API (`POST repos/{full}/pulls/{pr}/comments`), which requires the
    /// commit the comment anchors to (`commit_id`) plus the file/line it's
    /// attached to. `side: "RIGHT"` anchors to the new (head) version of
    /// the line, the only side a suggestion can ever apply against. No
    /// `gh` CLI subcommand exists for line-anchored PR review comments, so
    /// this always goes through the raw REST call.
    #[allow(clippy::too_many_arguments)]
    pub async fn gh_create_pr_review_comment(&self, full_name: &str, pr_number: u64, commit_id: &str, path: &str, line: i64, body: &str, token: &str) -> Result<(), GithubApiError> {
        self.gh_create_pr_review_comment_range(full_name, pr_number, commit_id, path, None, line, body, token).await
    }

    /// Same as [`gh_create_pr_review_comment`], but anchors the comment
    /// across `start_line..=line` when `start_line` is `Some` — GitHub's
    /// multi-line suggestion form, needed for a fenced `suggestion` block
    /// that spans more than one line (semantic-SAST fixes, unlike the
    /// single-line dependency-version-bump case `gh_create_pr_review_comment`
    /// was originally written for).
    /// `start_side`/`side` both anchor to the head (`"RIGHT"`) version of
    /// the diff, same as the single-line case — a suggestion can only ever
    /// apply against the PR's current content.
    #[allow(clippy::too_many_arguments)]
    pub async fn gh_create_pr_review_comment_range(&self, full_name: &str, pr_number: u64, commit_id: &str, path: &str, start_line: Option<i64>, line: i64, body: &str, token: &str) -> Result<(), GithubApiError> {
        let mut payload = serde_json::json!({ "body": body, "commit_id": commit_id, "path": path, "line": line, "side": "RIGHT" });
        if let Some(start_line) = start_line {
            if start_line < line {
                payload["start_line"] = serde_json::json!(start_line);
                payload["start_side"] = serde_json::json!("RIGHT");
            }
        }
        self.github_api_request(token, "POST", &format!("/repos/{full_name}/pulls/{pr_number}/comments"), Some(&payload), None).await?;
        Ok(())
    }

    /// The repo's current default branch, per `GET repos/{full_name}`.
    /// Prefers the `gh` CLI (same dual-path convention as `gh_api_write`),
    /// falling back to a token-only REST call. Read-only — safe to call
    /// even from a dry-run.
    pub async fn default_branch(&self, full_name: &str, token: &str) -> Result<String, GithubApiError> {
        let value = if self.is_gh_cli_available().await {
            let env = gh_token_env(token);
            let out = self.runner.run_tool("gh", &["api".to_string(), format!("repos/{full_name}")], &std::env::temp_dir().to_string_lossy(), RunToolOptions { env, ..Default::default() }).await?;
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
            let env = gh_token_env(token);
            let out = self.runner.run_tool("gh", &["api".to_string(), format!("repos/{full_name}/commits/{branch}")], &std::env::temp_dir().to_string_lossy(), RunToolOptions { env, ..Default::default() }).await?;
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
            let env = gh_token_env(token);
            self.runner.run_tool("gh", &["repo".to_string(), "clone".to_string(), full_name.to_string(), dest_dir.to_string(), "--".to_string(), "--depth".to_string(), "1".to_string(), "--branch".to_string(), branch.to_string()], &std::env::temp_dir().to_string_lossy(), RunToolOptions { env, ..Default::default() }).await?;
            return Ok(());
        }
        if token.is_empty() {
            return Err(GithubApiError::NoToken);
        }
        self.runner
            .run_tool("git", &["clone".to_string(), "--depth".to_string(), "1".to_string(), "--branch".to_string(), branch.to_string(), format!("https://github.com/{full_name}.git"), dest_dir.to_string()], &std::env::temp_dir().to_string_lossy(), RunToolOptions { env: git_extraheader_token_env(token), ..Default::default() })
            .await?;
        Ok(())
    }

    /// Full (non-shallow) clone of `branch` — unlike `gh_clone_repo_branch`
    /// (`--depth 1`, sufficient for every other clone-then-scan-working-
    /// tree caller in this codebase), a full commit history is exactly
    /// what a git-history secret sweep (`run_gitleaks_history_scan`)
    /// needs to walk; a shallow clone would only ever see the one commit
    /// it fetched, defeating the whole point of a *retroactive* sweep.
    pub async fn gh_clone_repo_branch_full_history(&self, full_name: &str, branch: &str, dest_dir: &str, token: &str) -> Result<(), GithubApiError> {
        if self.is_gh_cli_available().await {
            let env = gh_token_env(token);
            self.runner.run_tool("gh", &["repo".to_string(), "clone".to_string(), full_name.to_string(), dest_dir.to_string(), "--".to_string(), "--branch".to_string(), branch.to_string()], &std::env::temp_dir().to_string_lossy(), RunToolOptions { env, ..Default::default() }).await?;
            return Ok(());
        }
        if token.is_empty() {
            return Err(GithubApiError::NoToken);
        }
        self.runner
            .run_tool("git", &["clone".to_string(), "--branch".to_string(), branch.to_string(), format!("https://github.com/{full_name}.git"), dest_dir.to_string()], &std::env::temp_dir().to_string_lossy(), RunToolOptions { env: git_extraheader_token_env(token), ..Default::default() })
            .await?;
        Ok(())
    }

    pub async fn gh_clone_repo(&self, full_name: &str, dest_dir: &str, token: &str) -> Result<(), GithubApiError> {
        if self.is_gh_cli_available().await {
            let env = gh_token_env(token);
            self.runner.run_tool("gh", &["repo".to_string(), "clone".to_string(), full_name.to_string(), dest_dir.to_string(), "--".to_string(), "--depth".to_string(), "1".to_string(), "--branch".to_string(), "main".to_string()], &std::env::temp_dir().to_string_lossy(), RunToolOptions { env, ..Default::default() }).await?;
            return Ok(());
        }
        if token.is_empty() {
            return Err(GithubApiError::NoToken);
        }
        // http.extraheader is a one-off override for this invocation only —
        // unlike embedding the token in the remote URL, it's never written
        // to the cloned repo's own .git/config.
        self.runner
            .run_tool("git", &["clone".to_string(), "--depth".to_string(), "1".to_string(), "--branch".to_string(), "main".to_string(), format!("https://github.com/{full_name}.git"), dest_dir.to_string()], &std::env::temp_dir().to_string_lossy(), RunToolOptions { env: git_extraheader_token_env(token), ..Default::default() })
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
    fn find_marker_comment_id_matches_the_first_comment_carrying_the_marker() {
        let comments = serde_json::json!([
            {"id": 1, "body": "just a human comment"},
            {"id": 2, "body": "<!-- ignite:dependency-review -->\nsomething"},
            {"id": 3, "body": "<!-- ignite:dependency-review -->\nanother, older one"},
        ]);
        let id = find_marker_comment_id(comments.as_array().unwrap(), "<!-- ignite:dependency-review -->");
        assert_eq!(id, Some(2));
    }

    #[test]
    fn find_marker_comment_id_none_when_no_comment_carries_the_marker() {
        let comments = serde_json::json!([{"id": 1, "body": "just a human comment"}]);
        assert!(find_marker_comment_id(comments.as_array().unwrap(), "<!-- ignite:dependency-review -->").is_none());
    }

    #[test]
    fn find_marker_comment_id_none_for_empty_comment_list() {
        assert!(find_marker_comment_id(&[], "<!-- ignite:dependency-review -->").is_none());
    }

    #[test]
    fn find_review_comment_marker_true_when_a_comment_carries_it() {
        let comments = serde_json::json!([
            {"id": 1, "body": "a human review comment"},
            {"id": 2, "body": "explanation\n\n```suggestion\nfix\n```\n<!-- ignite:suggestion:dep-vuln::pkg.json::10 -->"},
        ]);
        assert!(find_review_comment_marker(comments.as_array().unwrap(), "<!-- ignite:suggestion:dep-vuln::pkg.json::10 -->"));
    }

    #[test]
    fn find_review_comment_marker_false_when_no_match() {
        let comments = serde_json::json!([{"id": 1, "body": "unrelated comment"}]);
        assert!(!find_review_comment_marker(comments.as_array().unwrap(), "<!-- ignite:suggestion:x -->"));
    }

    #[test]
    fn find_review_comment_marker_false_for_empty_list() {
        assert!(!find_review_comment_marker(&[], "<!-- ignite:suggestion:x -->"));
    }

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
    #[allow(clippy::await_holding_lock)]
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
    #[allow(clippy::await_holding_lock)]
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
    #[allow(clippy::await_holding_lock)]
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
