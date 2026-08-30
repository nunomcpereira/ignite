//! Sensitive data-flow (PII/GDPR) SAST via Bearer. Faithful port of
//! `checks/pii-dataflow.js`. Bearer reports findings pre-bucketed by
//! severity ({critical:[...], high:[...], ...}) rather than a flat array;
//! results are filtered to only what Bearer itself tags PII/Personal-Data
//! relevant via `category_groups` — everything else is Semgrep's job
//! (`checkSemanticSast`) and would otherwise double up here mislabeled.

use ignite_fs_utils::{build_snippet, skip_dirs, Snippet, SnippetOptions};
use ignite_tool_runner::{RunToolOptions, ToolRunner};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use std::path::Path;

static TEST_PATH_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(^|/)(tests?|__tests__|specs?|e2e|test-support)(/|$)|[._-](test|spec)s?\.[^/.]+$").unwrap()
});
static DEV_SERVER_FILE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)(?:^|/)(?:serve-dev|serve-spa)\.mjs$").unwrap());
static FIREBASE_WEB_API_KEY_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"AIza[0-9A-Za-z_-]{20,}").unwrap());
static HARD_CODED_SECRET_TITLE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)hard-coded secret").unwrap());
static INSECURE_HTTP_TITLE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)missing secure http server configuration|usage of insecure http connection").unwrap());
static HARD_CODED_SECRET_USAGE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)usage of hard-coded secret").unwrap());
static API_KEY_MENTION_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)apiKey").unwrap());
static BEARER_FORCE_WARNING_TITLES: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)unsanitized external input in code generation").unwrap(),
        Regex::new(r"(?i)unsanitized dynamic input in file path").unwrap(),
    ]
});

pub struct PiiDataFlowConfig {
    pub enabled: bool,
}

impl Default for PiiDataFlowConfig {
    fn default() -> Self {
        PiiDataFlowConfig { enabled: true }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PiiDataFlowFinding {
    pub file: String,
    pub line: usize,
    pub kind: String,
    pub tool: &'static str,
    pub severity: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<Snippet>,
    pub cwe: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PiiDataFlowResult {
    pub findings: Vec<PiiDataFlowFinding>,
    pub engine: &'static str,
}

pub async fn bearer_tooling(runner: &ToolRunner) -> bool {
    runner
        .run_tool("bearer", &["version".to_string()], std::env::temp_dir().to_str().unwrap_or("."), RunToolOptions::default())
        .await
        .is_ok()
}

fn severity_for(bearer_severity: &str) -> &'static str {
    match bearer_severity {
        "critical" | "high" => "error",
        _ => "warning",
    }
}

fn relative(root: &Path, name: &str) -> String {
    if name.is_empty() {
        return String::new();
    }
    let resolved = if Path::new(name).is_absolute() { std::path::PathBuf::from(name) } else { root.join(name) };
    let target_components: Vec<_> = resolved.components().collect();
    let base_components: Vec<_> = root.components().collect();
    let mut common = 0;
    while common < target_components.len() && common < base_components.len() && target_components[common] == base_components[common] {
        common += 1;
    }
    let mut result = std::path::PathBuf::new();
    for _ in common..base_components.len() {
        result.push("..");
    }
    for comp in &target_components[common..] {
        result.push(comp.as_os_str());
    }
    result.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/")
}

fn line_at(content: Option<&str>, line: usize) -> String {
    let Some(content) = content else { return String::new() };
    content.split('\n').nth(line.saturating_sub(1)).unwrap_or("").to_string()
}

/// Firebase web apiKey values are public identifiers, not auth secrets.
fn is_firebase_public_api_key_finding(title: &str, source_line: &str, content: Option<&str>) -> bool {
    if !HARD_CODED_SECRET_USAGE_RE.is_match(title) {
        return false;
    }
    if API_KEY_MENTION_RE.is_match(source_line) && FIREBASE_WEB_API_KEY_RE.is_match(source_line) {
        return true;
    }
    let content = content.unwrap_or("");
    API_KEY_MENTION_RE.is_match(content) && FIREBASE_WEB_API_KEY_RE.is_match(content)
}

pub fn is_likely_test_or_fixture_path(file: &str) -> bool {
    TEST_PATH_RE.is_match(&file.replace('\\', "/"))
}

/// Bearer shells out to git for its own bookkeeping and fails outright
/// without it. Ensures a throwaway repo (best-effort — every step's
/// failure is swallowed, matching the JS original's outer try/catch) *and*
/// fills in a fake origin + remote-tracking HEAD ref only when there
/// wasn't a real one already, since overwriting a genuine origin/HEAD
/// would destroy the signal `resolve_bearer_diff_base` depends on.
pub async fn ensure_git_context_for_bearer(root: &Path, runner: &ToolRunner) {
    let result: Result<(), Box<dyn std::error::Error>> = async {
        if !root.join(".git").exists() {
            runner.run_tool("git", &["init".to_string(), "-q".to_string()], &root.to_string_lossy(), RunToolOptions::default()).await?;
            runner.run_tool("git", &["add".to_string(), "-A".to_string()], &root.to_string_lossy(), RunToolOptions::default()).await?;
            runner
                .run_tool(
                    "git",
                    &[
                        "-c".to_string(),
                        "user.email=ignite@local".to_string(),
                        "-c".to_string(),
                        "user.name=Ignite".to_string(),
                        "commit".to_string(),
                        "-q".to_string(),
                        "-m".to_string(),
                        "ignite-bearer-scan".to_string(),
                        "--no-verify".to_string(),
                        "--allow-empty".to_string(),
                    ],
                    &root.to_string_lossy(),
                    RunToolOptions::default(),
                )
                .await?;
        }

        let has_origin = runner.run_tool("git", &["remote".to_string(), "get-url".to_string(), "origin".to_string()], &root.to_string_lossy(), RunToolOptions::default()).await.is_ok();
        if !has_origin {
            let branch = runner.run_tool("git", &["symbolic-ref".to_string(), "--short".to_string(), "HEAD".to_string()], &root.to_string_lossy(), RunToolOptions::default()).await;
            let branch_name = branch.map(|o| o.stdout.trim().to_string()).unwrap_or_default();
            let branch_name = if branch_name.is_empty() { "main".to_string() } else { branch_name };
            runner
                .run_tool(
                    "git",
                    &["remote".to_string(), "add".to_string(), "origin".to_string(), "https://ignite.local/scratch.git".to_string()],
                    &root.to_string_lossy(),
                    RunToolOptions::default(),
                )
                .await?;
            runner
                .run_tool(
                    "git",
                    &["update-ref".to_string(), format!("refs/remotes/origin/{}", branch_name), format!("refs/heads/{}", branch_name)],
                    &root.to_string_lossy(),
                    RunToolOptions::default(),
                )
                .await?;
            runner
                .run_tool(
                    "git",
                    &["symbolic-ref".to_string(), "refs/remotes/origin/HEAD".to_string(), format!("refs/remotes/origin/{}", branch_name)],
                    &root.to_string_lossy(),
                    RunToolOptions::default(),
                )
                .await?;
        }
        Ok(())
    }
    .await;
    let _ = result; // best-effort, same as the JS original's outer catch
}

/// Only reach for Bearer's `--diff` mode when a distinct ancestor commit
/// exists and the working tree is clean — `--diff` hard-refuses on any
/// uncommitted change, and diffing a commit against itself (a fresh
/// single-commit repo with no real history) silently returns zero
/// findings rather than "everything".
pub async fn resolve_bearer_diff_base(root: &Path, runner: &ToolRunner) -> Option<String> {
    let status = runner.run_tool("git", &["status".to_string(), "--porcelain".to_string()], &root.to_string_lossy(), RunToolOptions::default()).await.ok()?;
    if !status.stdout.trim().is_empty() {
        return None;
    }

    let head_out = runner.run_tool("git", &["rev-parse".to_string(), "HEAD".to_string()], &root.to_string_lossy(), RunToolOptions::default()).await.ok()?;
    let head = head_out.stdout.trim().to_string();
    if head.is_empty() {
        return None;
    }

    let mut base = String::new();
    if let Ok(out) = runner.run_tool("git", &["symbolic-ref".to_string(), "--quiet".to_string(), "refs/remotes/origin/HEAD".to_string()], &root.to_string_lossy(), RunToolOptions::default()).await {
        base = out.stdout.trim().strip_prefix("refs/remotes/").unwrap_or(out.stdout.trim()).to_string();
    }
    if base.is_empty() {
        for candidate in ["origin/main", "origin/master"] {
            if runner
                .run_tool("git", &["rev-parse".to_string(), "--verify".to_string(), "--quiet".to_string(), candidate.to_string()], &root.to_string_lossy(), RunToolOptions::default())
                .await
                .is_ok()
            {
                base = candidate.to_string();
                break;
            }
        }
    }
    if base.is_empty() {
        return None;
    }

    let base_sha_out = runner.run_tool("git", &["rev-parse".to_string(), "--verify".to_string(), "--quiet".to_string(), base.clone()], &root.to_string_lossy(), RunToolOptions::default()).await.ok()?;
    let base_sha = base_sha_out.stdout.trim().to_string();
    if base_sha.is_empty() || base_sha == head {
        return None;
    }

    runner.run_tool("git", &["merge-base".to_string(), "--is-ancestor".to_string(), base.clone(), "HEAD".to_string()], &root.to_string_lossy(), RunToolOptions::default()).await.ok()?;
    Some(base)
}

pub async fn check_pii_data_flow(root: &Path, runner: &ToolRunner, config: &PiiDataFlowConfig) -> PiiDataFlowResult {
    let tooling_ok = config.enabled && bearer_tooling(runner).await;
    if !tooling_ok {
        return PiiDataFlowResult { findings: vec![], engine: "disabled" };
    }

    ensure_git_context_for_bearer(root, runner).await;
    let diff_base = resolve_bearer_diff_base(root, runner).await;

    let mut args = vec![
        "scan".to_string(),
        root.to_string_lossy().into_owned(),
        "--format".to_string(),
        "json".to_string(),
        "--quiet".to_string(),
        "--disable-version-check".to_string(),
        "--exit-code".to_string(),
        "0".to_string(),
        "--skip-path".to_string(),
        skip_dirs().iter().copied().collect::<Vec<_>>().join(","),
    ];
    if diff_base.is_some() {
        args.push("--diff".to_string());
    }

    let output = match runner.run_tool("bearer", &args, &root.to_string_lossy(), RunToolOptions::default()).await {
        Ok(o) => o,
        Err(_) => return PiiDataFlowResult { findings: vec![], engine: "disabled" },
    };

    let data: serde_json::Value = if output.stdout.trim().is_empty() {
        serde_json::json!({})
    } else {
        match serde_json::from_str(&output.stdout) {
            Ok(v) => v,
            Err(_) => return PiiDataFlowResult { findings: vec![], engine: "disabled" },
        }
    };

    let Some(obj) = data.as_object() else {
        return PiiDataFlowResult { findings: vec![], engine: "bearer" };
    };

    let mut findings = Vec::new();
    for (severity, entries) in obj {
        let Some(entries) = entries.as_array() else { continue };
        for e in entries {
            let category_groups: Vec<String> = e.get("category_groups").and_then(|c| c.as_array()).map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
            let is_pii = category_groups.iter().any(|g| g.to_lowercase().contains("pii") || g.to_lowercase().contains("personal data"));
            if !is_pii {
                continue;
            }
            let name = e.get("full_filename").and_then(|v| v.as_str()).or_else(|| e.get("filename").and_then(|v| v.as_str())).unwrap_or("");
            let rel_file = relative(root, name);
            let line = e.get("line_number").and_then(|l| l.as_i64()).unwrap_or(1).max(1) as usize;
            let content = std::fs::read_to_string(root.join(&rel_file)).ok();
            let title = e.get("title").and_then(|t| t.as_str()).unwrap_or("Sensitive data-flow finding").to_string();
            let source_line = line_at(content.as_deref(), line);
            if is_firebase_public_api_key_finding(&title, &source_line, content.as_deref()) {
                continue;
            }
            let forced_warning = BEARER_FORCE_WARNING_TITLES.iter().any(|re| re.is_match(&title))
                || (is_likely_test_or_fixture_path(&rel_file) && HARD_CODED_SECRET_TITLE_RE.is_match(&title))
                || (DEV_SERVER_FILE_RE.is_match(&rel_file) && INSECURE_HTTP_TITLE_RE.is_match(&title));
            let cwe_id = e.get("cwe_ids").and_then(|c| c.as_array()).and_then(|a| a.first()).and_then(|v| v.as_i64());
            findings.push(PiiDataFlowFinding {
                file: rel_file,
                line,
                kind: e.get("id").and_then(|i| i.as_str()).unwrap_or("pii-dataflow").to_lowercase(),
                tool: "bearer",
                severity: if forced_warning { "warning" } else { severity_for(severity) },
                message: title,
                code: content.as_deref().and_then(|c| build_snippet(c, line, SnippetOptions::default())),
                cwe: cwe_id.map(|id| format!("CWE-{}", id)),
            });
        }
    }

    PiiDataFlowResult { findings, engine: "bearer" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use tempfile::tempdir;

    fn runner_with_bearer_and_git() -> ToolRunner {
        let mut binaries = HashMap::new();
        binaries.insert("bearer", "bearer".to_string());
        ToolRunner::new(binaries)
    }

    #[test]
    fn is_likely_test_path_matches_common_conventions() {
        assert!(is_likely_test_or_fixture_path("src/foo.test.js"));
        assert!(is_likely_test_or_fixture_path("test/helpers.js"));
        assert!(is_likely_test_or_fixture_path("__tests__/x.js"));
        assert!(!is_likely_test_or_fixture_path("src/index.js"));
    }

    #[test]
    fn firebase_public_api_key_is_excluded_only_for_hard_coded_secret_title() {
        let line = r#"const apiKey = "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe";"#;
        assert!(is_firebase_public_api_key_finding("Usage of hard-coded secret", line, None));
        assert!(!is_firebase_public_api_key_finding("Some other finding", line, None));
    }

    #[test]
    fn forced_warning_titles_are_recognized() {
        assert!(BEARER_FORCE_WARNING_TITLES.iter().any(|re| re.is_match("Unsanitized dynamic input in file path")));
        assert!(BEARER_FORCE_WARNING_TITLES.iter().any(|re| re.is_match("Unsanitized external input in code generation")));
        assert!(!BEARER_FORCE_WARNING_TITLES.iter().any(|re| re.is_match("Something unrelated")));
    }

    #[tokio::test]
    async fn disabled_returns_no_findings() {
        let dir = tempdir().unwrap();
        let config = PiiDataFlowConfig { enabled: false };
        let result = check_pii_data_flow(dir.path(), &ToolRunner::new(HashMap::new()), &config).await;
        assert_eq!(result.engine, "disabled");
        assert!(result.findings.is_empty());
    }

    #[tokio::test]
    async fn real_bearer_binary_flags_a_pii_data_flow() {
        let mut check = std::process::Command::new("bearer");
        check.arg("version");
        if check.output().map(|o| !o.status.success()).unwrap_or(true) {
            eprintln!("skipping: bearer not installed on PATH");
            return;
        }
        let mut git_check = std::process::Command::new("git");
        git_check.arg("--version");
        if git_check.output().map(|o| !o.status.success()).unwrap_or(true) {
            eprintln!("skipping: git not installed on PATH");
            return;
        }

        let dir = tempdir().unwrap();
        let root = dir.path();
        // Bearer's javascript_lang_logger rule (category_groups: PII/Personal
        // Data) fires on PII-named fields flowing into console.log/logger
        // calls — confirmed against the real binary directly before writing
        // this fixture (nodemailer.sendMail wasn't a recognized sink).
        fs::write(root.join("app.js"), "function logUser(user) {\n  console.log('user ssn is ' + user.ssn);\n  console.log('user email is ' + user.email);\n}\nmodule.exports = logUser;\n").unwrap();

        let config = PiiDataFlowConfig { enabled: true };
        let result = check_pii_data_flow(root, &runner_with_bearer_and_git(), &config).await;
        assert_eq!(result.engine, "bearer");
        assert!(!result.findings.is_empty(), "expected bearer to flag PII (ssn/email) logged via console.log");
        assert!(result.findings.iter().all(|f| f.file == "app.js"));
        ignite_fs_utils::invalidate_walk_cache(root);
    }
}
