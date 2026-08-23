//! Verifies a project's `.igniteignore` is actually committed to git.
//! Faithful port of `checks/igniteignore.js` — the one Phase 4 finding
//! that's `severity: "error"` (blocking) despite being a built-in,
//! no-external-tool check: an uncommitted `.igniteignore` is a silent,
//! unreviewable scan bypass.

use ignite_tool_runner::{RunToolOptions, ToolRunner};
use serde::Serialize;
use std::path::Path;

pub const IGNITEIGNORE_FILENAME: &str = ".igniteignore";

#[derive(Debug, Clone, Serialize)]
pub struct IgniteIgnoreFinding {
    pub file: &'static str,
    pub line: usize,
    pub kind: &'static str,
    pub tool: &'static str,
    pub severity: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IgniteIgnoreResult {
    pub findings: Vec<IgniteIgnoreFinding>,
    pub engine: &'static str,
}

async fn is_git_repo(runner: &ToolRunner, root: &str) -> bool {
    runner
        .run_tool("git", &["rev-parse".to_string(), "--is-inside-work-tree".to_string()], root, RunToolOptions::default())
        .await
        .is_ok()
}

async fn is_tracked_by_git(runner: &ToolRunner, root: &str, rel_file: &str) -> bool {
    runner
        .run_tool(
            "git",
            &["ls-files".to_string(), "--error-unmatch".to_string(), "--".to_string(), rel_file.to_string()],
            root,
            RunToolOptions::default(),
        )
        .await
        .is_ok()
}

pub async fn check_igniteignore_committed(root: &Path, runner: &ToolRunner, enabled: bool) -> IgniteIgnoreResult {
    if !enabled {
        return IgniteIgnoreResult { findings: vec![], engine: "disabled" };
    }

    let igniteignore_path = root.join(IGNITEIGNORE_FILENAME);
    let exists = tokio::fs::metadata(&igniteignore_path).await.map(|m| m.is_file()).unwrap_or(false);
    if !exists {
        return IgniteIgnoreResult { findings: vec![], engine: "built-in" };
    }

    let root_str = root.to_string_lossy();
    if !is_git_repo(runner, &root_str).await {
        // .igniteignore found, but this project has no git history yet — it
        // will be committed as part of onboarding, so nothing to flag.
        return IgniteIgnoreResult { findings: vec![], engine: "built-in" };
    }

    if is_tracked_by_git(runner, &root_str, IGNITEIGNORE_FILENAME).await {
        return IgniteIgnoreResult { findings: vec![], engine: "built-in" };
    }

    let content = tokio::fs::read_to_string(&igniteignore_path).await.unwrap_or_default();
    let preview = if content.is_empty() {
        None
    } else {
        Some(content.split('\n').take(10).collect::<Vec<_>>().join("\n"))
    };

    IgniteIgnoreResult {
        findings: vec![IgniteIgnoreFinding {
            file: IGNITEIGNORE_FILENAME,
            line: 1,
            kind: "igniteignore-not-committed",
            tool: "ignite-built-in",
            severity: "error",
            message: format!(
                "{IGNITEIGNORE_FILENAME} exists but is not tracked by git — it silently excludes paths from every Ignite check with no reviewable record. Commit it (or remove it if it was left over from local testing) before this can pass."
            ),
            code: preview,
        }],
        engine: "built-in",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::process::Command;
    use tempfile::tempdir;

    fn runner() -> ToolRunner {
        ToolRunner::new(HashMap::new())
    }

    fn git(root: &Path, args: &[&str]) {
        let status = Command::new("git").args(args).current_dir(root).status().unwrap();
        assert!(status.success(), "git {:?} failed", args);
    }

    #[tokio::test]
    async fn no_igniteignore_file_produces_no_findings() {
        let dir = tempdir().unwrap();
        let result = check_igniteignore_committed(dir.path(), &runner(), true).await;
        assert!(result.findings.is_empty());
    }

    #[tokio::test]
    async fn igniteignore_present_but_no_git_repo_yet_is_not_flagged() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join(".igniteignore"), "fixtures/\n").unwrap();
        let result = check_igniteignore_committed(dir.path(), &runner(), true).await;
        assert!(result.findings.is_empty());
    }

    #[tokio::test]
    async fn igniteignore_present_and_committed_is_not_flagged() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join(".igniteignore"), "fixtures/\n").unwrap();
        git(root, &["init", "-q"]);
        git(root, &["config", "user.email", "test@example.com"]);
        git(root, &["config", "user.name", "Test"]);
        git(root, &["add", "."]);
        git(root, &["commit", "-q", "-m", "initial"]);

        let result = check_igniteignore_committed(root, &runner(), true).await;
        assert!(result.findings.is_empty());
    }

    #[tokio::test]
    async fn igniteignore_present_but_uncommitted_is_flagged_blocking() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        git(root, &["init", "-q"]);
        git(root, &["config", "user.email", "test@example.com"]);
        git(root, &["config", "user.name", "Test"]);
        std::fs::write(root.join("README.md"), "hello\n").unwrap();
        git(root, &["add", "README.md"]);
        git(root, &["commit", "-q", "-m", "initial"]);
        // .igniteignore added to disk after the commit, never staged/committed.
        std::fs::write(root.join(".igniteignore"), "fixtures/\nvendor/\n").unwrap();

        let result = check_igniteignore_committed(root, &runner(), true).await;
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, "error");
        assert_eq!(result.findings[0].kind, "igniteignore-not-committed");
        assert!(result.findings[0].code.as_deref().unwrap().contains("fixtures/"));
    }

    #[tokio::test]
    async fn disabled_returns_no_findings_even_with_uncommitted_igniteignore() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        git(root, &["init", "-q"]);
        std::fs::write(root.join(".igniteignore"), "fixtures/\n").unwrap();

        let result = check_igniteignore_committed(root, &runner(), false).await;
        assert!(result.findings.is_empty());
        assert_eq!(result.engine, "disabled");
    }
}
