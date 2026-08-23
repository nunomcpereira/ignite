//! Faithful port of `lib/shipping.js` — Phase 5/6: git + gh shipping.
//! Provisions (or reuses) the target GitHub repo, pushes the compliant
//! code, and — when an org ruleset requires it — opens a PR into main
//! with auto-merge armed, watching the required remote checks.

use ignite_db_store::DbStore;
use ignite_github_api::GithubApi;
use ignite_tool_runner::{sanitize_cli_arg, RunToolOptions, ToolRunner};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::json;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum ShippingError {
    #[error("No GitHub account connected for this request. Connect your own GitHub account (GET /api/auth/github/connect, or the \"Connect GitHub\" button in the UI) before provisioning a repository — Phase 6 no longer falls back to the server's own gh session.")]
    NoToken,
    #[error(transparent)]
    Tool(#[from] ignite_tool_runner::ToolError),
    #[error(transparent)]
    GithubApi(#[from] ignite_github_api::GithubApiError),
    #[error("Remote governance checks did not pass ({0}). PR left open for review: {1}")]
    ChecksFailed(String, String),
}

pub struct ShippingConfig {
    pub bootstrap_branch: String,
    pub remote_protocol: String,
}

impl Default for ShippingConfig {
    fn default() -> Self {
        ShippingConfig { bootstrap_branch: "ignite".to_string(), remote_protocol: "https".to_string() }
    }
}

pub struct ShipResult {
    pub repo_url: String,
    pub pr_url: Option<String>,
}

static VALIDATION_422_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)HTTP 422").unwrap());
static HTTP_404_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"404").unwrap());

async fn git(runner: &ToolRunner, args: &[String], cwd: &str, gh_token: &str) -> Result<ignite_tool_runner::ToolOutput, ignite_tool_runner::ToolError> {
    let env = HashMap::from([("GH_TOKEN".to_string(), gh_token.to_string())]);
    runner.run_tool("git", args, cwd, RunToolOptions { env, ..Default::default() }).await
}

fn s(strs: &[&str]) -> Vec<String> {
    strs.iter().map(|s| s.to_string()).collect()
}

async fn repo_exists_on_github(api: &GithubApi<'_>, owner: &str, name: &str, token: &str) -> bool {
    api.gh_api_get(&format!("repos/{owner}/{name}"), token).await.is_ok()
}

#[allow(clippy::too_many_arguments)]
pub async fn ship_to_github(root: &Path, org: &str, repo: &str, gh_token: &str, runner: &ToolRunner, github_api: &GithubApi<'_>, config: &ShippingConfig, mut log: impl FnMut(&str) + Send) -> Result<ShipResult, ShippingError> {
    if gh_token.is_empty() {
        return Err(ShippingError::NoToken);
    }

    let safe_org = sanitize_cli_arg(org, "Organization name")?;
    let safe_repo = sanitize_cli_arg(repo, "Repository name")?;
    let full_name = format!("{safe_org}/{safe_repo}");
    let root_str = root.to_string_lossy().into_owned();

    // Phase 4 may already have initialized and committed the repo for act.
    let already_repo = root.join(".git").exists();
    if already_repo {
        log("Reusing repository initialized during the local CI phase.");
    } else {
        log("$ git init -b main");
        git(runner, &s(&["init", "-b", "main"]), &root_str, gh_token).await?;

        log("$ git add .");
        git(runner, &s(&["add", "."]), &root_str, gh_token).await?;

        log("$ git commit -m \"chore: initial compliant code drop via onboarding gatekeeper\"");
        git(runner, &s(&["-c", "user.name=Onboarding Gatekeeper", "-c", "user.email=gatekeeper@localhost", "commit", "-m", "chore: initial compliant code drop via onboarding gatekeeper"]), &root_str, gh_token).await?;
    }

    // Org rulesets with required workflows reject direct pushes to main
    // (GH013): the required workflow must run on GitHub in a PR context.
    // Bootstrap branch: the compliant code lands here first, then PRs into
    // the repo's default branch.
    let onboard_branch = if config.bootstrap_branch.is_empty() { "ignite".to_string() } else { config.bootstrap_branch.clone() };
    let remote_protocol = config.remote_protocol.to_lowercase();
    let remote_url = if remote_protocol == "ssh" { format!("git@github.com:{full_name}.git") } else { format!("https://github.com/{full_name}.git") };
    // https: gh as credential helper for this job only, no interactive
    // prompts. ssh: no credential helper needed — auth is whatever SSH
    // key/agent is already configured for github.com.
    let git_cred: Vec<String> = if remote_protocol == "ssh" { vec![] } else { s(&["-c", "credential.helper=", "-c", "credential.helper=!gh auth git-credential", "-c", "core.askPass="]) };
    let git_id = s(&["-c", "user.name=Onboarding Gatekeeper", "-c", "user.email=gatekeeper@localhost"]);

    log(&format!("$ gh api POST orgs/{safe_org}/repos (private, auto_init)"));
    let create_fields = HashMap::from([("name".to_string(), json!(safe_repo)), ("private".to_string(), json!(true)), ("auto_init".to_string(), json!(true))]);
    if let Err(e) = github_api.gh_api_write("POST", &format!("orgs/{safe_org}/repos"), &create_fields, gh_token).await {
        let msg = e.to_string();
        if HTTP_404_RE.is_match(&msg) {
            // Personal account, not an organization.
            log(&format!("\"{safe_org}\" is not an org — creating under the authenticated user."));
            if let Err(fallback_err) = github_api.gh_api_write("POST", "user/repos", &create_fields, gh_token).await {
                let fallback_msg = fallback_err.to_string();
                if VALIDATION_422_RE.is_match(&fallback_msg) {
                    if repo_exists_on_github(github_api, &safe_org, &safe_repo, gh_token).await {
                        log(&format!("Repository {full_name} already exists — reusing it."));
                    } else {
                        return Err(fallback_err.into());
                    }
                } else {
                    return Err(fallback_err.into());
                }
            }
        } else if VALIDATION_422_RE.is_match(&msg) {
            if repo_exists_on_github(github_api, &safe_org, &safe_repo, gh_token).await {
                log(&format!("Repository {full_name} already exists — reusing it."));
            } else {
                return Err(e.into());
            }
        } else {
            return Err(e.into());
        }
    }

    let auto_merge_fields = HashMap::from([("allow_auto_merge".to_string(), json!(true))]);
    match github_api.gh_api_write("PATCH", &format!("repos/{full_name}"), &auto_merge_fields, gh_token).await {
        Ok(_) => log("Enabled auto-merge on the repository."),
        Err(_) => log("⚠ Could not enable auto-merge — the PR will need a manual merge once checks pass."),
    }

    log(&format!("$ git remote add origin \"{remote_url}\""));
    git(runner, &s(&["remote", "add", "origin", &remote_url]), &root_str, gh_token).await?;

    // Repo initialization is asynchronous — and org rulesets with required
    // workflows can block the creation of main entirely. Wait briefly.
    log("$ git fetch origin main");
    let mut main_exists = false;
    for attempt in 1..=8 {
        let mut args = git_cred.clone();
        args.extend(s(&["fetch", "origin", "main"]));
        match git(runner, &args, &root_str, gh_token).await {
            Ok(_) => {
                main_exists = true;
                break;
            }
            Err(_) => {
                log(&format!("main ref not ready yet (attempt {attempt}/8) — retrying in 3s..."));
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
        }
    }

    if main_exists {
        // Replay our commit on top of GitHub's init commit; on conflicts
        // (e.g. the project ships its own README.md) our version wins.
        log("$ git rebase -X theirs origin/main");
        let mut args = git_id.clone();
        args.extend(s(&["rebase", "-X", "theirs", "origin/main"]));
        git(runner, &args, &root_str, gh_token).await?;
    }

    log(&format!("$ git push -u origin HEAD:{onboard_branch}"));
    let mut push_args = git_cred.clone();
    push_args.extend(s(&["push", "-u", "origin"]));
    push_args.push(format!("HEAD:{onboard_branch}"));
    git(runner, &push_args, &root_str, gh_token).await?;
    let sha = git(runner, &s(&["rev-parse", "HEAD"]), &root_str, gh_token).await?.stdout;

    if !main_exists {
        // Try to create main directly from the compliant commit (works in
        // orgs/accounts without a required-workflow ruleset on main).
        log("$ gh api POST git/refs (create main from onboarding commit)");
        let ref_fields = HashMap::from([("ref".to_string(), json!("refs/heads/main")), ("sha".to_string(), json!(sha))]);
        if github_api.gh_api_write("POST", &format!("repos/{full_name}/git/refs"), &ref_fields, gh_token).await.is_ok() {
            log("✓ main created directly — no ruleset restriction on this repo.");
            let default_branch_fields = HashMap::from([("default_branch".to_string(), json!("main"))]);
            match github_api.gh_api_write("PATCH", &format!("repos/{full_name}"), &default_branch_fields, gh_token).await {
                Ok(_) => log("✓ Default branch set to main."),
                Err(_) => log("⚠ Could not set main as the default branch — adjust in repo settings."),
            }
            log("✓ Code is live on main.");
            return Ok(ShipResult { repo_url: format!("https://github.com/{full_name}"), pr_url: None });
        }
        // Deadlock: the ruleset blocks ALL creation of main (even GitHub's
        // auto-init), but the required workflow can only run on a PR whose
        // base is main. No client-side flow can satisfy it.
        let bootstrap_default_fields = HashMap::from([("default_branch".to_string(), json!(onboard_branch))]);
        let _ = github_api.gh_api_write("PATCH", &format!("repos/{full_name}"), &bootstrap_default_fields, gh_token).await;
        log("⚠ The org ruleset blocks creating \"main\" in new repos (bootstrap deadlock: the required workflow can only run on a PR, and a PR needs main to exist).");
        log(&format!("✓ Code shipped to \"{onboard_branch}\", now the repository's default branch."));
        log(&format!("⚠ Once an org admin adds a ruleset bypass so main can be bootstrapped, open a PR from \"{onboard_branch}\" into main."));
        return Ok(ShipResult { repo_url: format!("https://github.com/{full_name}/tree/{onboard_branch}"), pr_url: None });
    }

    log("$ gh pr create --base main");
    let pr = github_api
        .gh_create_pr(
            &full_name,
            "main",
            &onboard_branch,
            "chore: initial compliant code drop via onboarding gatekeeper",
            "Automated onboarding by Ignite. All local gates passed: structure audit, secret scan, AI governance, LLM deep-scan, and the org governance workflows executed locally via act.",
            gh_token,
        )
        .await?;
    log(&format!("✓ Pull request opened: {}", pr.url));

    let pr_number = pr.number.unwrap_or(0);
    match github_api.gh_arm_auto_merge(&full_name, &pr.url, pr_number, pr.node_id.as_deref(), gh_token).await {
        Ok(_) => log("✓ Auto-merge armed — the PR merges itself when the required workflow passes."),
        Err(e) => log(&format!("⚠ Auto-merge could not be armed ({e}). Merge manually once checks pass.")),
    }

    log("Waiting for the required org workflow to run on GitHub...");
    match github_api.gh_watch_pr_checks(&full_name, &pr.url, pr_number, gh_token, |l| log(l), 20 * 60_000).await {
        Ok(_) => log("✓ All remote required checks passed — auto-merge will land the PR on main."),
        Err(e) => return Err(ShippingError::ChecksFailed(e.to_string(), pr.url.clone())),
    }

    Ok(ShipResult { repo_url: format!("https://github.com/{full_name}"), pr_url: Some(pr.url) })
}

pub struct ArchivedPayload {
    pub name: String,
    pub size: i64,
}

pub async fn archive_phase6_payload(root: &Path, project_id: Option<i64>, runner: &ToolRunner, store: &DbStore, mut log: impl FnMut(&str)) -> Option<ArchivedPayload> {
    let project_id = project_id?;

    let tmp_name = format!("ignite-phase6-payload-{}.zip", uuid::Uuid::new_v4());
    let tmp_zip = std::env::temp_dir().join(&tmp_name);
    let root_str = root.to_string_lossy().into_owned();

    // Snapshot the exact tracked tree that phase 6 is attempting to push.
    let result = runner.run_tool("git", &s(&["archive", "--format=zip", "-o"]).into_iter().chain(std::iter::once(tmp_zip.to_string_lossy().into_owned())).chain(std::iter::once("HEAD".to_string())).collect::<Vec<_>>(), &root_str, RunToolOptions::default()).await;

    let outcome = match result {
        Ok(_) => match std::fs::read(&tmp_zip) {
            Ok(data) => {
                let size = data.len() as i64;
                let timestamp = chrono::Utc::now().to_rfc3339().replace(':', "-");
                let doc_name = format!("phase6-payload-{timestamp}.zip");
                store.add_upload_document(project_id, &doc_name, Some("application/zip"), size, &data);
                log(&format!("📦 Archived phase 6 push payload for inspection: {doc_name} ({:.1} KB).", size as f64 / 1024.0));
                Some(ArchivedPayload { name: doc_name, size })
            }
            Err(e) => {
                log(&format!("⚠ Could not archive phase 6 push payload: {e}"));
                None
            }
        },
        Err(e) => {
            log(&format!("⚠ Could not archive phase 6 push payload: {e}"));
            None
        }
    };

    let _ = std::fs::remove_file(&tmp_zip);
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ships_config_defaults_match_js() {
        let config = ShippingConfig::default();
        assert_eq!(config.bootstrap_branch, "ignite");
        assert_eq!(config.remote_protocol, "https");
    }

    #[test]
    fn validation_422_regex_matches_case_insensitively() {
        assert!(VALIDATION_422_RE.is_match("GitHub API POST /orgs/x/repos failed: HTTP 422 Unprocessable"));
        assert!(VALIDATION_422_RE.is_match("http 422"));
        assert!(!VALIDATION_422_RE.is_match("HTTP 404"));
    }

    #[tokio::test]
    async fn ship_to_github_rejects_empty_token() {
        let runner = ToolRunner::new(HashMap::new());
        let api = GithubApi::new(&runner);
        let config = ShippingConfig::default();
        let result = ship_to_github(Path::new("/tmp"), "acme", "widgets", "", &runner, &api, &config, |_| {}).await;
        assert!(matches!(result, Err(ShippingError::NoToken)));
    }

    #[tokio::test]
    async fn archive_phase6_payload_skips_when_no_project_id() {
        let dir = tempfile_for_test();
        let db = ignite_db_store::DbStore::open(&dir.join("test.db")).unwrap();
        let runner = ToolRunner::new(HashMap::new());
        let result = archive_phase6_payload(Path::new("/tmp"), None, &runner, &db, |_| {}).await;
        assert!(result.is_none());
    }

    fn tempfile_for_test() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ignite-shipping-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
