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

/// `content_root` is where `.igniteignore` itself is read from (the
/// scanned copy). `git_check_root` is where its commit status is verified
/// — the same directory for a ZIP/folder upload with no other backing
/// repo, but the *original* (unstaged) project directory for the CLI/
/// pre-push/onboard paths, since staging always strips `.git` out of the
/// copy it makes regardless of whether the real source has one.
pub async fn check_igniteignore_committed(content_root: &Path, git_check_root: &Path, runner: &ToolRunner, enabled: bool) -> IgniteIgnoreResult {
    if !enabled {
        return IgniteIgnoreResult { findings: vec![], engine: "disabled" };
    }

    let igniteignore_path = content_root.join(IGNITEIGNORE_FILENAME);
    let exists = tokio::fs::metadata(&igniteignore_path).await.map(|m| m.is_file()).unwrap_or(false);
    if !exists {
        return IgniteIgnoreResult { findings: vec![], engine: "built-in" };
    }

    let root_str = git_check_root.to_string_lossy();
    let content = tokio::fs::read_to_string(&igniteignore_path).await.unwrap_or_default();
    let preview = if content.is_empty() {
        None
    } else {
        Some(content.split('\n').take(10).collect::<Vec<_>>().join("\n"))
    };

    // No `.git` at the scanned root does *not* mean this is safely a
    // brand-new project whose `.igniteignore` will obviously end up
    // committed: a ZIP/folder upload of an *existing* repo's working tree
    // commonly has no `.git` directory in it at all (browser folder-upload
    // APIs typically skip dotfiles, and a plain "zip my project" export
    // usually does too) even when that repo has real git history
    // elsewhere in which `.igniteignore` was deliberately left untracked
    // specifically to keep its exclusions out of code review. Silently
    // passing that case turns "upload a ZIP instead of using the CLI/
    // pre-push hook" into a guaranteed way to skip this check every time.
    // Without real git history to check against, the commit status is
    // simply unverifiable — treat that the same as "not committed" rather
    // than assuming it's fine.
    if !is_git_repo(runner, &root_str).await {
        return IgniteIgnoreResult {
            findings: vec![IgniteIgnoreFinding {
                file: IGNITEIGNORE_FILENAME,
                line: 1,
                kind: "igniteignore-not-committed",
                tool: "ignite-built-in",
                severity: "error",
                message: format!(
                    "{IGNITEIGNORE_FILENAME} exists but this upload has no git history to verify it will actually be committed — a folder/ZIP upload can silently drop an existing repo's real git history (and any deliberately-untracked {IGNITEIGNORE_FILENAME}) along the way. Onboard via the CLI/pre-push hook against the real repo, or confirm via override that this {IGNITEIGNORE_FILENAME} is intentional and will be committed."
                ),
                code: preview.clone(),
            }],
            engine: "built-in",
        };
    }

    if is_tracked_by_git(runner, &root_str, IGNITEIGNORE_FILENAME).await {
        return IgniteIgnoreResult { findings: vec![], engine: "built-in" };
    }

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
        let result = check_igniteignore_committed(dir.path(), dir.path(), &runner(), true).await;
        assert!(result.findings.is_empty());
    }

    #[tokio::test]
    async fn igniteignore_present_but_no_git_repo_yet_is_flagged() {
        // A ZIP/folder upload with no `.git` at all can't be trusted to be
        // a genuinely brand-new project — it's equally what an existing
        // repo's working tree looks like once its `.git` is stripped out
        // (by a browser folder-upload API, or a plain zip export). Since
        // there's no git history to check `.igniteignore` against, this
        // must be flagged rather than silently assumed safe.
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join(".igniteignore"), "fixtures/\n").unwrap();
        let result = check_igniteignore_committed(dir.path(), dir.path(), &runner(), true).await;
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, "error");
        assert_eq!(result.findings[0].kind, "igniteignore-not-committed");
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

        let result = check_igniteignore_committed(root, root, &runner(), true).await;
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

        let result = check_igniteignore_committed(root, root, &runner(), true).await;
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, "error");
        assert_eq!(result.findings[0].kind, "igniteignore-not-committed");
        assert!(result.findings[0].code.as_deref().unwrap().contains("fixtures/"));
    }

    /// Regression test: the CLI/pre-push/onboard headless paths stage an
    /// existing local directory into a temp copy that never includes
    /// `.git` (staging drops it for every path, not just uploads) — so
    /// checking git status against that staged copy would flag every
    /// single real, properly-committed repo as "unverified" purely
    /// because of how staging works, nothing to do with the actual repo.
    /// Passing the real original directory as `git_check_root` must avoid
    /// that false positive.
    #[tokio::test]
    async fn staged_copy_with_committed_igniteignore_in_the_real_source_is_not_flagged() {
        let source = tempdir().unwrap();
        let root = source.path();
        std::fs::write(root.join(".igniteignore"), "fixtures/\n").unwrap();
        git(root, &["init", "-q"]);
        git(root, &["config", "user.email", "test@example.com"]);
        git(root, &["config", "user.name", "Test"]);
        git(root, &["add", "."]);
        git(root, &["commit", "-q", "-m", "initial"]);

        // The staged copy: same .igniteignore content, no .git at all —
        // exactly what `stage_existing_project` produces.
        let staged = tempdir().unwrap();
        std::fs::write(staged.path().join(".igniteignore"), "fixtures/\n").unwrap();

        let result = check_igniteignore_committed(staged.path(), root, &runner(), true).await;
        assert!(result.findings.is_empty());
    }

    #[tokio::test]
    async fn disabled_returns_no_findings_even_with_uncommitted_igniteignore() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        git(root, &["init", "-q"]);
        std::fs::write(root.join(".igniteignore"), "fixtures/\n").unwrap();

        let result = check_igniteignore_committed(root, root, &runner(), false).await;
        assert!(result.findings.is_empty());
        assert_eq!(result.engine, "disabled");
    }
}
