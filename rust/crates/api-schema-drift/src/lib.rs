//! API breaking-change / shadow-endpoint detection via oasdiff. Faithful
//! port of `checks/api-schema-drift.js`. Where Spectral (`ignite-api-schema`)
//! lints a spec in isolation, this diffs each discovered spec against its
//! own previous git revision — catching a removed endpoint, a field that
//! became required, a changed response type. Only meaningful with real
//! git history to diff against (a clean tree and a distinct parent
//! commit); a fresh ZIP/folder upload has nothing to compare, so this
//! simply contributes nothing rather than fabricating a baseline.

use ignite_api_schema::discover_api_schema_files;
use ignite_tool_runner::{RunToolOptions, ToolRunner};
use serde::Serialize;
use std::path::Path;

pub struct ApiSchemaDriftConfig {
    pub enabled: bool,
}

impl Default for ApiSchemaDriftConfig {
    fn default() -> Self {
        ApiSchemaDriftConfig { enabled: true }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiSchemaDriftFinding {
    pub file: String,
    pub line: Option<usize>,
    pub kind: String,
    pub tool: &'static str,
    pub severity: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiSchemaDriftResult {
    pub findings: Vec<ApiSchemaDriftFinding>,
    pub engine: &'static str,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct OasdiffToolingProbe {
    pub ok: bool,
    pub reason: Option<String>,
}

pub async fn oasdiff_tooling(runner: &ToolRunner) -> OasdiffToolingProbe {
    match runner.run_tool("oasdiff", &["--version".to_string()], std::env::temp_dir().to_str().unwrap_or("."), RunToolOptions::default()).await {
        Ok(_) => OasdiffToolingProbe { ok: true, reason: None },
        Err(_) => OasdiffToolingProbe {
            ok: false,
            reason: Some("`oasdiff` is not installed (brew install oasdiff, or see https://github.com/oasdiff/oasdiff) — API breaking-change detection is skipped.".to_string()),
        },
    }
}

/// Mirrors `resolve_bearer_diff_base` in `ignite-pii-dataflow`: only diff
/// against a real ancestor commit, on a clean working tree.
pub async fn resolve_git_diff_base(root: &Path, runner: &ToolRunner) -> Option<String> {
    let status = runner.run_tool("git", &["status".to_string(), "--porcelain".to_string()], &root.to_string_lossy(), RunToolOptions::default()).await.ok()?;
    if !status.stdout.trim().is_empty() {
        return None;
    }

    let head_out = runner.run_tool("git", &["rev-parse".to_string(), "HEAD".to_string()], &root.to_string_lossy(), RunToolOptions::default()).await.ok()?;
    let head = head_out.stdout.trim().to_string();
    if head.is_empty() {
        return None;
    }

    let parent = runner
        .run_tool("git", &["rev-parse".to_string(), "--verify".to_string(), "--quiet".to_string(), "HEAD~1".to_string()], &root.to_string_lossy(), RunToolOptions::default())
        .await
        .map(|o| o.stdout.trim().to_string())
        .unwrap_or_default();
    if parent.is_empty() || parent == head {
        return None;
    }
    Some(parent)
}

/// ERR-level findings genuinely break existing clients. WARN-level
/// ("potential breaking change, can't be confirmed programmatically")
/// stays advisory.
fn severity_for_level(level: &serde_json::Value) -> &'static str {
    let as_upper = level.as_str().map(|s| s.to_uppercase());
    if matches!(as_upper.as_deref(), Some("ERR") | Some("ERROR")) {
        return "error";
    }
    if let Some(n) = level.as_i64() {
        if n >= 2 {
            return "error";
        }
    }
    "warning"
}

/// oasdiff's `breaking --format json` output is an array of change objects
/// (id/text/level/operation/path at minimum — exact field set has shifted
/// across versions), so this reads tolerantly rather than assuming one
/// fixed schema.
fn parse_oasdiff_changes(stdout: &str) -> Vec<serde_json::Value> {
    if stdout.trim().is_empty() {
        return vec![];
    }
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(stdout) else { return vec![] };
    if let Some(arr) = parsed.as_array() {
        return arr.clone();
    }
    if let Some(arr) = parsed.get("changes").and_then(|c| c.as_array()) {
        return arr.clone();
    }
    if let Some(arr) = parsed.get("breakingChanges").and_then(|c| c.as_array()) {
        return arr.clone();
    }
    vec![]
}

pub async fn check_api_schema_drift(root: &Path, runner: &ToolRunner, config: &ApiSchemaDriftConfig) -> std::io::Result<ApiSchemaDriftResult> {
    let tooling = if config.enabled { oasdiff_tooling(runner).await } else { OasdiffToolingProbe { ok: false, reason: None } };
    if !tooling.ok {
        return Ok(ApiSchemaDriftResult { findings: vec![], engine: "disabled" });
    }

    let rel_files = discover_api_schema_files(root)?;
    if rel_files.is_empty() {
        return Ok(ApiSchemaDriftResult { findings: vec![], engine: "oasdiff" });
    }

    let Some(diff_base) = resolve_git_diff_base(root, runner).await else {
        return Ok(ApiSchemaDriftResult { findings: vec![], engine: "oasdiff" });
    };

    let tmp_dir = std::env::temp_dir().join(format!(
        "ignite-oasdiff-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
    ));
    tokio::fs::create_dir_all(&tmp_dir).await?;

    let mut findings = Vec::new();
    for rel_file in &rel_files {
        let base_content = match runner.run_tool("git", &["show".to_string(), format!("{}:{}", diff_base, rel_file)], &root.to_string_lossy(), RunToolOptions::default()).await {
            Ok(o) => o.stdout,
            Err(_) => continue, // file didn't exist at diffBase — a new spec, nothing to diff yet
        };
        let base_file_name = Path::new(rel_file).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| rel_file.clone());
        let base_file_path = tmp_dir.join(format!("base-{}", base_file_name));
        tokio::fs::write(&base_file_path, &base_content).await?;

        let output = runner
            .run_tool(
                "oasdiff",
                &["breaking".to_string(), base_file_path.to_string_lossy().into_owned(), root.join(rel_file).to_string_lossy().into_owned(), "--format".to_string(), "json".to_string()],
                &root.to_string_lossy(),
                RunToolOptions { allowed_exit_codes: vec![0, 1], ..Default::default() },
            )
            .await;
        let Ok(output) = output else { continue };

        for change in parse_oasdiff_changes(&output.stdout) {
            let text = change.get("text").and_then(|v| v.as_str()).or_else(|| change.get("comment").and_then(|v| v.as_str())).or_else(|| change.get("id").and_then(|v| v.as_str()));
            let operation = change.get("operation").and_then(|v| v.as_str());
            let op_path = change.get("path").and_then(|v| v.as_str());
            let mut parts: Vec<String> = vec![text.unwrap_or("API breaking change detected").to_string()];
            if let (Some(op), Some(p)) = (operation, op_path) {
                parts.push(format!("({} {})", op.to_uppercase(), p));
            }
            findings.push(ApiSchemaDriftFinding {
                file: rel_file.clone(),
                line: None,
                kind: change.get("id").and_then(|v| v.as_str()).unwrap_or("api-breaking-change").to_string(),
                tool: "oasdiff",
                severity: severity_for_level(change.get("level").unwrap_or(&serde_json::Value::Null)),
                message: parts.join(" "),
            });
        }
    }

    let _ = tokio::fs::remove_dir_all(&tmp_dir).await;
    Ok(ApiSchemaDriftResult { findings, engine: "oasdiff" })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use std::process::Command;
    use tempfile::tempdir;

    fn runner_with(tools: &[&'static str]) -> ToolRunner {
        let mut binaries = HashMap::new();
        for t in tools {
            binaries.insert(*t, t.to_string());
        }
        ToolRunner::new(binaries)
    }

    fn git(root: &Path, args: &[&str]) {
        let status = Command::new("git").args(args).current_dir(root).env("GIT_AUTHOR_NAME", "t").env("GIT_AUTHOR_EMAIL", "t@t").env("GIT_COMMITTER_NAME", "t").env("GIT_COMMITTER_EMAIL", "t@t").status().unwrap();
        assert!(status.success(), "git {:?} failed", args);
    }

    #[test]
    fn severity_for_level_maps_err_and_numeric_to_error() {
        assert_eq!(severity_for_level(&serde_json::json!("ERR")), "error");
        assert_eq!(severity_for_level(&serde_json::json!("err")), "error");
        assert_eq!(severity_for_level(&serde_json::json!(2)), "error");
        assert_eq!(severity_for_level(&serde_json::json!(1)), "warning");
        assert_eq!(severity_for_level(&serde_json::json!("WARN")), "warning");
    }

    #[test]
    fn parse_oasdiff_changes_handles_bare_array_and_wrapped_shapes() {
        assert_eq!(parse_oasdiff_changes("").len(), 0);
        assert_eq!(parse_oasdiff_changes("[{\"id\":\"x\"}]").len(), 1);
        assert_eq!(parse_oasdiff_changes(r#"{"changes":[{"id":"x"},{"id":"y"}]}"#).len(), 2);
        assert_eq!(parse_oasdiff_changes(r#"{"breakingChanges":[{"id":"x"}]}"#).len(), 1);
        assert_eq!(parse_oasdiff_changes("not json").len(), 0);
    }

    #[tokio::test]
    async fn disabled_returns_no_findings() {
        let dir = tempdir().unwrap();
        let config = ApiSchemaDriftConfig { enabled: false };
        let result = check_api_schema_drift(dir.path(), &ToolRunner::new(HashMap::new()), &config).await.unwrap();
        assert_eq!(result.engine, "disabled");
        assert!(result.findings.is_empty());
    }

    #[tokio::test]
    async fn no_prior_git_history_returns_no_findings() {
        let mut check = Command::new("git");
        check.arg("--version");
        if check.output().map(|o| !o.status.success()).unwrap_or(true) {
            eprintln!("skipping: git not installed on PATH");
            return;
        }

        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("openapi.yaml"), "openapi: 3.0.0\ninfo:\n  title: x\n  version: 1.0.0\npaths: {}\n").unwrap();
        git(root, &["init", "-q"]);
        git(root, &["add", "-A"]);
        git(root, &["commit", "-q", "-m", "init", "--allow-empty"]);

        // Single-commit repo: HEAD~1 doesn't exist, so there's nothing to
        // diff against yet — matching resolve_git_diff_base's "no parent"
        // short-circuit.
        let config = ApiSchemaDriftConfig { enabled: true };
        let result = check_api_schema_drift(root, &runner_with(&["oasdiff", "git"]), &config).await.unwrap();
        assert_eq!(result.engine, "oasdiff");
        assert!(result.findings.is_empty());
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[tokio::test]
    async fn real_oasdiff_binary_flags_a_removed_endpoint() {
        let mut oasdiff_check = Command::new("oasdiff");
        oasdiff_check.arg("--version");
        if oasdiff_check.output().map(|o| !o.status.success()).unwrap_or(true) {
            eprintln!("skipping: oasdiff not installed on PATH");
            return;
        }
        let mut git_check = Command::new("git");
        git_check.arg("--version");
        if git_check.output().map(|o| !o.status.success()).unwrap_or(true) {
            eprintln!("skipping: git not installed on PATH");
            return;
        }

        let dir = tempdir().unwrap();
        let root = dir.path();
        let v1 = "openapi: 3.0.0\ninfo:\n  title: x\n  version: 1.0.0\npaths:\n  /ping:\n    get:\n      responses:\n        '200':\n          description: ok\n  /users:\n    get:\n      responses:\n        '200':\n          description: ok\n";
        fs::write(root.join("openapi.yaml"), v1).unwrap();
        git(root, &["init", "-q"]);
        git(root, &["add", "-A"]);
        git(root, &["commit", "-q", "-m", "v1"]);

        // Remove the /users endpoint entirely — a real breaking change.
        let v2 = "openapi: 3.0.0\ninfo:\n  title: x\n  version: 1.0.0\npaths:\n  /ping:\n    get:\n      responses:\n        '200':\n          description: ok\n";
        fs::write(root.join("openapi.yaml"), v2).unwrap();
        git(root, &["add", "-A"]);
        git(root, &["commit", "-q", "-m", "v2 - remove /users"]);

        let config = ApiSchemaDriftConfig { enabled: true };
        let result = check_api_schema_drift(root, &runner_with(&["oasdiff", "git"]), &config).await.unwrap();
        assert_eq!(result.engine, "oasdiff");
        assert!(!result.findings.is_empty(), "expected oasdiff to flag the removed /users endpoint");
        ignite_fs_utils::invalidate_walk_cache(root);
    }
}
