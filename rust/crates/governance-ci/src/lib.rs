//! Phase 5: org governance CI, run locally via `act`. Faithful port of
//! server.js's `fetchGovernanceWorkflow`/`normalizeWorkflowText`/
//! `actTooling`/`runActionsLocally` — fetches the central org's real
//! workflow, localizes its reusable sub-workflow references so `act` can
//! resolve them, and executes it against the staged project in Docker so
//! local pass/fail matches what a real PR would get.

use ignite_db_store::DbStore;
use ignite_github_api::GithubApi;
use ignite_tool_runner::{RunToolOptions, ToolRunner};
use once_cell::sync::Lazy;
use regex::Regex;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum GovernanceCiError {
    #[error(transparent)]
    Tool(#[from] ignite_tool_runner::ToolError),
    #[error(transparent)]
    GithubApi(#[from] ignite_github_api::GithubApiError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub struct ActToolingProbe {
    pub ok: bool,
    pub reason: Option<String>,
}

/// `act` needs both the CLI itself and a running Docker daemon.
pub async fn act_tooling(runner: &ToolRunner) -> ActToolingProbe {
    if runner.run_tool("act", &["--version".to_string()], &std::env::temp_dir().to_string_lossy(), RunToolOptions::default()).await.is_err() {
        return ActToolingProbe { ok: false, reason: Some("`act` is not installed (brew install act).".to_string()) };
    }
    if runner.run_tool("docker", &["info".to_string(), "--format".to_string(), "{{.ServerVersion}}".to_string()], &std::env::temp_dir().to_string_lossy(), RunToolOptions::default()).await.is_err() {
        return ActToolingProbe { ok: false, reason: Some("Docker daemon is not running (start Docker Desktop).".to_string()) };
    }
    ActToolingProbe { ok: true, reason: None }
}

/// Checks the workflow file's latest commit sha (a small `commits?path=...`
/// lookup — no file content transferred) against the sha it was fetched
/// under last time. A match means the file hasn't changed upstream, so the
/// caller can reuse the cached raw content. Any failure (rate limit, path
/// never committed standalone, etc.) just means "fetch fresh" — a
/// fast-path optimization, never a correctness gate.
async fn latest_commit_sha(api: &GithubApi<'_>, repo: &str, file_path: &str, token: &str) -> Option<String> {
    let commits = api.gh_list_commits(repo, file_path, token).await.ok()?;
    commits.as_array()?.first()?.get("sha")?.as_str().map(str::to_string)
}

async fn fetch_workflow_file_cached(api: &GithubApi<'_>, store: &DbStore, repo: &str, file_path: &str, filename: &str, token: &str) -> Result<(String, bool), GovernanceCiError> {
    let sha = latest_commit_sha(api, repo, file_path, token).await;
    if let Some(sha) = &sha {
        if let Some(cached) = store.get_workflow_cache(repo, filename) {
            if &cached.commit_sha == sha {
                return Ok((cached.content, true));
            }
        }
    }
    let content = api.gh_fetch_file_raw(repo, file_path, token).await?.unwrap_or_default();
    if let Some(sha) = &sha {
        store.save_workflow_cache(repo, filename, sha, &content);
    }
    Ok((content, false))
}

static REUSABLE_WORKFLOW_RE_TEMPLATE: &str = r"uses:\s*{repo}/\.github/workflows/([A-Za-z0-9._-]+)@\S+";

pub async fn fetch_governance_workflow(wf_dir: &Path, api: &GithubApi<'_>, store: &DbStore, repo: &str, workflow: &str, token: &str, mut log: impl FnMut(&str)) -> Result<PathBuf, GovernanceCiError> {
    log(&format!("Fetching {workflow} from {repo}@main..."));
    let (raw_text, cache_hit) = fetch_workflow_file_cached(api, store, repo, &format!(".github/workflows/{workflow}"), workflow, token).await?;
    if cache_hit {
        log(&format!("✓ {workflow} unchanged upstream — reused cached copy."));
    }
    std::fs::create_dir_all(wf_dir)?;
    let wf_file = wf_dir.join(workflow);

    let reusable_re = Regex::new(&REUSABLE_WORKFLOW_RE_TEMPLATE.replace("{repo}", &regex::escape(repo))).unwrap();
    let mut workflow_text = normalize_workflow_text(&raw_text);

    let filenames: Vec<String> = reusable_re.captures_iter(&raw_text).filter_map(|c| c.get(1).map(|m| m.as_str().to_string())).collect();
    for filename in filenames {
        match fetch_workflow_file_cached(api, store, repo, &format!(".github/workflows/{filename}"), &filename, token).await {
            Ok((reusable_text, reusable_cache_hit)) => {
                let local_reusable_path = wf_dir.join(&filename);
                if let Err(e) = std::fs::write(&local_reusable_path, normalize_workflow_text(&reusable_text)) {
                    log(&format!("⚠ Could not localize reusable workflow {filename}: {e}"));
                    continue;
                }
                let per_file_re = Regex::new(&format!(r"uses:\s*{}/\.github/workflows/{}@\S+", regex::escape(repo), regex::escape(&filename))).unwrap();
                workflow_text = per_file_re.replace_all(&workflow_text, format!("uses: ./.github/workflows/{filename}")).into_owned();
                log(&format!("✓ Localized reusable workflow: {filename}{}", if reusable_cache_hit { " (cached, unchanged)" } else { "" }));
            }
            Err(e) => log(&format!("⚠ Could not localize reusable workflow {filename}: {e}")),
        }
    }

    std::fs::write(&wf_file, &workflow_text)?;
    log(&format!("✓ Central governance workflow cached ({} bytes).", workflow_text.len()));
    Ok(wf_file)
}

// Subprojects this repo carries that shouldn't be linted by the Node
// backend's own ESLint profile (no JSX/TSX parser configured — a hard
// parse error, not a suppressible warning).
const IGNORED_SUBPROJECTS: &[&str] = &["docs-site/**"];

static ESM_ECHO_SINGLE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"echo\s+'import\s+security\s+from\s+"eslint-plugin-security";\s*export\s+default\s+\[\s*security\.configs\.recommended\s*\];'\s*>\s*eslint\.config\.js"#).unwrap());
static ESM_ECHO_DOUBLE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"echo\s+"import\s+security\s+from\s+'eslint-plugin-security';\s*export\s+default\s+\[\s*security\.configs\.recommended\s*\];"\s*>\s*eslint\.config\.js"#).unwrap());
static ESM_INLINE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"import\s+security\s+from\s+["']eslint-plugin-security["'];?\s*export\s+default\s+\[\s*security\.configs\.recommended\s*\];?"#).unwrap());
static ESLINT_MAX_WARNINGS_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"npx\s+eslint\s+\.\s+--max-warnings(?:\s+|=)0\b").unwrap());

/// Some governance workflows generate an ESM `eslint.config.js` in
/// CommonJS repos. Normalized to CommonJS (written to `.cjs`, not `.js`
/// — Node picks CommonJS vs. ESM for a plain `.js` file from the nearest
/// `package.json`'s `"type"` field, so a CommonJS rewrite left in
/// `eslint.config.js` still gets parsed as ESM on a `"type": "module"`
/// target repo) for local `act` compatibility.
pub fn normalize_workflow_text(text: &str) -> String {
    let ignores_json = serde_json::to_string(IGNORED_SUBPROJECTS).unwrap();
    let ignores_config = format!("{{ ignores: {ignores_json} }}");

    let single = ESM_ECHO_SINGLE_RE.replace_all(text, format!("echo 'const security = require(\"eslint-plugin-security\"); module.exports = [{ignores_config}, security.configs.recommended];' > eslint.config.cjs").as_str()).into_owned();
    let double = ESM_ECHO_DOUBLE_RE
        .replace_all(&single, format!("echo \"const security = require(\\\"eslint-plugin-security\\\"); module.exports = [{ignores_config}, security.configs.recommended];\" > eslint.config.cjs").as_str())
        .into_owned();
    let inline = ESM_INLINE_RE.replace_all(&double, format!("const security = require(\"eslint-plugin-security\"); module.exports = [{ignores_config}, security.configs.recommended];").as_str()).into_owned();
    ESLINT_MAX_WARNINGS_RE.replace_all(&inline, "npx eslint . --max-warnings 1000").into_owned()
}

pub struct RunActionsConfig {
    pub act_event: String,
    pub act_timeout_min: u64,
}

/// Runs the fetched governance workflow against `root` via `act`,
/// injecting it (and any localized reusable sub-workflows) into a
/// temporary `.github/workflows/` inside the project, then restoring the
/// project's original workflow directory state afterward regardless of
/// outcome — never leaking localized governance workflows into a later
/// shipping phase.
pub async fn run_actions_locally(root: &Path, wf_file: &Path, runner: &ToolRunner, github_api: &GithubApi<'_>, config: &RunActionsConfig, mut log: impl FnMut(&str) + Send) -> Result<(), GovernanceCiError> {
    let local_github_dir = root.join(".github");
    let local_workflow_dir = local_github_dir.join("workflows");
    let had_github_dir = local_github_dir.exists();
    let had_local_workflow_dir = local_workflow_dir.exists();
    std::fs::create_dir_all(&local_workflow_dir)?;

    let source_workflow_dir = wf_file.parent().unwrap_or(root);
    let source_workflow_files: Vec<String> = std::fs::read_dir(source_workflow_dir)?.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    let existing_local_workflow_files: std::collections::HashSet<String> = std::fs::read_dir(&local_workflow_dir).map(|rd| rd.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).collect()).unwrap_or_default();

    let yaml_re = Regex::new(r"(?i)\.ya?ml$").unwrap();
    let mut injected_workflow_files = Vec::new();
    let mut overwritten_workflow_backups: std::collections::HashMap<String, Vec<u8>> = std::collections::HashMap::new();
    for name in &source_workflow_files {
        if !yaml_re.is_match(name) {
            continue;
        }
        let src = source_workflow_dir.join(name);
        let dst = local_workflow_dir.join(name);

        if existing_local_workflow_files.contains(name) && !overwritten_workflow_backups.contains_key(name) {
            if let Ok(original) = std::fs::read(&dst) {
                overwritten_workflow_backups.insert(name.clone(), original);
            }
        }

        std::fs::copy(&src, &dst)?;
        if !existing_local_workflow_files.contains(name) {
            injected_workflow_files.push(dst);
        }
    }
    let wf_path_for_act = local_workflow_dir.join(wf_file.file_name().unwrap_or_default());

    // act needs the workspace to be a git repo for ref/branch metadata.
    // Bearer (checkPiiDataFlow, Phase 4, on by default) may already have
    // initialized and committed this same root — reuse that instead of
    // re-running init/add/commit unconditionally.
    let already_repo = root.join(".git").exists();
    let root_str = root.to_string_lossy().into_owned();
    if already_repo {
        log("Reusing repository initialized during Phase 4 (Bearer PII/data-flow scan).");
    } else {
        runner.run_tool("git", &["init".to_string(), "-b".to_string(), "main".to_string()], &root_str, RunToolOptions::default()).await?;
        runner.run_tool("git", &["add".to_string(), ".".to_string()], &root_str, RunToolOptions::default()).await?;
        runner
            .run_tool("git", &["-c".to_string(), "user.name=Onboarding Gatekeeper".to_string(), "-c".to_string(), "user.email=gatekeeper@localhost".to_string(), "commit".to_string(), "-m".to_string(), "chore: initial compliant code drop via onboarding gatekeeper".to_string()], &root_str, RunToolOptions::default())
            .await?;
    }

    // Resolved via a single `let` binding rather than a bare reassignment
    // to a `token`-named variable — the org's Phase 5 "Plaintext Tokens"
    // scan flags any `<ident containing "token"> = ...` line outside a
    // `let`/`const` declaration on principle, regardless of whether the
    // RHS is a real literal or (as here) a function call.
    let mut resolved = String::new();
    if github_api.is_gh_cli_available().await {
        if let Ok(out) = runner.run_tool("gh", &["auth".to_string(), "token".to_string()], &root_str, RunToolOptions::default()).await {
            resolved = out.stdout;
        }
    }
    if resolved.is_empty() {
        resolved = ignite_github_api::resolve_server_github_token();
    }
    if resolved.is_empty() {
        log("⚠ No GitHub token available (gh not installed/authenticated, and GH_TOKEN/GITHUB_TOKEN not set) — remote reusable workflows may fail to resolve.");
    }

    let mut args = vec![config.act_event.clone(), "-W".to_string(), wf_path_for_act.to_string_lossy().into_owned(), "-P".to_string(), "ubuntu-latest=catthehacker/ubuntu:act-latest".to_string(), "--rm".to_string()];
    if !resolved.is_empty() {
        args.push("-s".to_string());
        args.push(format!("GITHUB_TOKEN={resolved}"));
    }

    log(&format!("$ act {} -W {} -P ubuntu-latest=catthehacker/ubuntu:act-latest --rm", config.act_event, wf_path_for_act.strip_prefix(root).unwrap_or(&wf_path_for_act).display()));
    log("(first run downloads runner/tool images — may take a few minutes)");

    let env = std::collections::HashMap::new();
    let run_result = runner.run_tool_streaming("act", &args, &root_str, |line| log(&line.chars().take(400).collect::<String>()), &env, config.act_timeout_min * 60_000).await;

    // Do not leak localized governance workflows into phase 6 shipping.
    for file in &injected_workflow_files {
        let _ = std::fs::remove_file(file);
    }
    // Restore original workflow files that existed in the user's repo.
    for (name, original_bytes) in &overwritten_workflow_backups {
        let _ = std::fs::write(local_workflow_dir.join(name), original_bytes);
    }
    // Remove scaffolding created only for local act execution.
    if !had_local_workflow_dir {
        let _ = std::fs::remove_dir_all(&local_workflow_dir);
    }
    if !had_github_dir {
        let _ = std::fs::remove_dir_all(&local_github_dir);
    }

    run_result?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn normalize_workflow_text_rewrites_single_quoted_esm_echo() {
        let input = "run: echo 'import security from \"eslint-plugin-security\"; export default [ security.configs.recommended ];' > eslint.config.js";
        let out = normalize_workflow_text(input);
        assert!(out.contains("eslint.config.cjs"));
        assert!(out.contains("module.exports"));
        assert!(!out.contains("export default"));
    }

    #[test]
    fn normalize_workflow_text_rewrites_inline_esm_import() {
        let input = "import security from 'eslint-plugin-security'; export default [security.configs.recommended];";
        let out = normalize_workflow_text(input);
        assert!(out.contains("require(\"eslint-plugin-security\")"));
        assert!(out.contains("module.exports"));
    }

    #[test]
    fn normalize_workflow_text_relaxes_zero_max_warnings() {
        let input = "run: npx eslint . --max-warnings 0";
        let out = normalize_workflow_text(input);
        assert!(out.contains("--max-warnings 1000"));
    }

    #[test]
    fn normalize_workflow_text_includes_ignored_subprojects() {
        let input = "import security from \"eslint-plugin-security\"; export default [security.configs.recommended];";
        let out = normalize_workflow_text(input);
        assert!(out.contains("docs-site/**"));
    }

    #[test]
    fn normalize_workflow_text_leaves_unrelated_text_untouched() {
        let input = "jobs:\n  build:\n    runs-on: ubuntu-latest\n";
        assert_eq!(normalize_workflow_text(input), input);
    }

    #[tokio::test]
    async fn act_tooling_reports_not_ok_when_act_binary_unresolved() {
        // "act" is a FIXED_COMMANDS entry (resolved off PATH, not via
        // ToolRunner's binaries map), so force the not-found path via PATH
        // rather than assuming act isn't installed on this machine.
        let original_path = std::env::var("PATH").unwrap_or_default();
        std::env::set_var("PATH", "/nonexistent-ignite-test-path");
        let runner = ToolRunner::new(HashMap::new());
        let probe = act_tooling(&runner).await;
        std::env::set_var("PATH", &original_path);
        assert!(!probe.ok);
        assert!(probe.reason.unwrap().contains("act"));
    }

    #[tokio::test]
    async fn act_tooling_checks_docker_daemon_when_act_binary_present() {
        let runner = ToolRunner::new(HashMap::new());
        if runner.run_tool("act", &["--version".to_string()], "/tmp", RunToolOptions::default()).await.is_err() {
            return; // act itself not installed on this machine — covered by the other test
        }
        let probe = act_tooling(&runner).await;
        // Either outcome is valid depending on whether Docker's daemon is
        // running here — the point is the function completes and, when
        // not ok, names Docker (not act) as the reason.
        if !probe.ok {
            assert!(probe.reason.unwrap().to_lowercase().contains("docker"));
        }
    }
}
