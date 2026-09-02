//! External-tool process execution + the sanitizers that guard it — every
//! `git`/`gh`/`trivy`/`semgrep`/etc. invocation across Ignite's checks goes
//! through here. Faithful port of `lib/tool-runner.js`.
//!
//! `ToolRunner::new(binaries)` takes each tool's resolved binary path/name
//! as a parameter rather than reading config itself — same reasoning as
//! the JS factory: no config-derived state of its own to go stale.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

/// Every command name `run_tool`/`run_tool_streaming` will accept. git/gh/
/// act/docker/licensee/ort aren't configurable (no `binaries` entry), the
/// rest resolve through `binaries`.
pub fn allowed_commands() -> &'static [&'static str] {
    &[
        "git", "gh", "act", "docker", "gitleaks", "licensee", "ort", "trivy", "checkov",
        "hadolint", "syft", "cosign", "semgrep", "bearer", "jscpd", "gocloc", "spectral",
        "guarddog", "codeql", "picklescan", "oasdiff", "zizmor",
    ]
}

const FIXED_COMMANDS: &[&str] = &["git", "gh", "act", "docker", "licensee", "ort"];
/// Commands `run_tool_streaming` actually supports (a strict subset of
/// `allowed_commands()` — the JS original only wires up git/gh/act/docker/
/// codeql for streaming; everything else only ever goes through the
/// buffered `run_tool`).
const STREAMING_COMMANDS: &[&str] = &["git", "gh", "act", "docker", "codeql"];

#[derive(Debug, thiserror::Error)]
pub enum ToolError {
    #[error("{0} cannot be empty.")]
    Empty(String),
    #[error("{0} contains illegal control characters.")]
    ControlChars(String),
    #[error("Command is not allowed: {0}")]
    CommandNotAllowed(String),
    #[error("Working directory is required.")]
    CwdRequired,
    #[error("projectPath must be an absolute path.")]
    NotAbsolute,
    #[error("Unsupported command: {0}")]
    Unsupported(String),
    #[error("`{command} {args}` failed{timeout_note}: {detail}")]
    Failed {
        command: String,
        args: String,
        timeout_note: String,
        detail: String,
    },
    #[error("`{0}` timed out after {1} minutes.")]
    TimedOut(String, f64),
    #[error("`{command}` exited with code {code}.{detail}")]
    ExitedNonZero {
        command: String,
        code: i32,
        detail: String,
        failure_lines: Vec<String>,
    },
    #[error("Invalid path in folder upload: {0:?}")]
    InvalidUploadPath(String),
    #[error("Absolute paths are not allowed in folder upload: {0}")]
    UploadAbsolutePath(String),
    #[error("Blocked path traversal entry in folder upload: {0}")]
    UploadTraversal(String),
    #[error("Invalid path segment in folder upload: {0}")]
    UploadInvalidSegment(String),
    #[error("Invalid characters in folder upload path: {0}")]
    UploadInvalidChars(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

fn has_control_chars(s: &str) -> bool {
    s.contains('\0') || s.contains('\r') || s.contains('\n')
}

pub fn sanitize_cli_arg(value: &str, label: &str) -> Result<String, ToolError> {
    if value.is_empty() {
        return Err(ToolError::Empty(label.to_string()));
    }
    if has_control_chars(value) {
        return Err(ToolError::ControlChars(label.to_string()));
    }
    Ok(value.to_string())
}

pub fn sanitize_command(cmd: &str) -> Result<String, ToolError> {
    let safe = sanitize_cli_arg(cmd, "Command")?;
    if !allowed_commands().contains(&safe.as_str()) {
        return Err(ToolError::CommandNotAllowed(safe));
    }
    Ok(safe)
}

pub fn sanitize_cli_args(args: &[String]) -> Result<Vec<String>, ToolError> {
    args.iter()
        .enumerate()
        .map(|(i, a)| sanitize_cli_arg(a, &format!("Argument #{}", i + 1)))
        .collect()
}

pub fn sanitize_cwd(cwd: &str) -> Result<String, ToolError> {
    let s = cwd.trim();
    if s.is_empty() {
        return Err(ToolError::CwdRequired);
    }
    if has_control_chars(s) {
        return Err(ToolError::ControlChars("Working directory".to_string()));
    }
    Ok(s.to_string())
}

pub fn sanitize_absolute_project_path(project_path: &str) -> Result<PathBuf, ToolError> {
    let safe = sanitize_cwd(project_path)?;
    let p = Path::new(&safe);
    if !p.is_absolute() {
        return Err(ToolError::NotAbsolute);
    }
    // path.resolve in Node also normalizes `.`/`..` segments; Rust has no
    // stdlib equivalent that doesn't require the path to exist, so this
    // resolves symlinks/`.`/`..` the same way relative_to_root's realpath
    // calls do elsewhere in this port, falling back to the raw absolute
    // path if the target doesn't exist yet (e.g. it's about to be created).
    Ok(std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf()))
}

pub fn sanitize_env(env: &HashMap<String, String>) -> HashMap<String, String> {
    let key_ok = |k: &str| {
        let mut chars = k.chars();
        matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    };
    env.iter()
        .filter(|(k, v)| key_ok(k) && !v.contains('\0'))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

const SAFE_UPLOAD_SEGMENT_CHARS_FORBIDDEN: &[char] = &['\0', '/', '\\'];

pub fn sanitize_upload_relative_path(raw_path: &str) -> Result<String, ToolError> {
    let rel = raw_path.replace('\\', "/");
    let rel = rel.trim();
    if rel.is_empty() || rel.contains('\0') {
        return Err(ToolError::InvalidUploadPath(raw_path.to_string()));
    }
    let is_windows_drive = rel.len() >= 2
        && rel.as_bytes()[0].is_ascii_alphabetic()
        && rel[1..].starts_with(":/");
    if rel.starts_with('/') || rel.starts_with("~/") || is_windows_drive {
        return Err(ToolError::UploadAbsolutePath(rel.to_string()));
    }

    let normalized = posix_normalize(rel);
    if normalized == "." || normalized.starts_with("../") || normalized.contains("/../") {
        return Err(ToolError::UploadTraversal(rel.to_string()));
    }

    for segment in normalized.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(ToolError::UploadInvalidSegment(rel.to_string()));
        }
        if segment.chars().any(|c| SAFE_UPLOAD_SEGMENT_CHARS_FORBIDDEN.contains(&c)) {
            return Err(ToolError::UploadInvalidChars(rel.to_string()));
        }
    }
    Ok(normalized)
}

/// Minimal `path.posix.normalize` equivalent: collapses `.`/`..`/repeated
/// slashes the same way Node's does for a purely lexical (non-filesystem-
/// touching) path string.
fn posix_normalize(p: &str) -> String {
    let absolute = p.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if !absolute && (out.is_empty() || out.last() == Some(&"..")) {
                    out.push("..");
                } else {
                    out.pop();
                }
            }
            s => out.push(s),
        }
    }
    let joined = out.join("/");
    if absolute {
        format!("/{joined}")
    } else if joined.is_empty() {
        ".".to_string()
    } else {
        joined
    }
}

#[derive(Debug)]
pub struct ToolOutput {
    pub stdout: String,
    pub stderr: String,
}

/// Cap on how much of a tool's stdout/stderr gets written to the log per
/// invocation — full output can run to megabytes (Semgrep/Bearer JSON
/// dumps), and this is an audit trail, not a copy of the report.
const LOG_OUTPUT_LIMIT: usize = 4000;

fn log_preview(s: &str) -> String {
    if s.len() <= LOG_OUTPUT_LIMIT {
        return s.to_string();
    }
    // Back off to the nearest char boundary so we never split inside a
    // multi-byte UTF-8 sequence.
    let mut cut = LOG_OUTPUT_LIMIT;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    format!(
        "{}... [truncated, {} more bytes]",
        &s[..cut],
        s.len() - cut
    )
}

#[derive(Default)]
pub struct RunToolOptions {
    pub env: HashMap<String, String>,
    pub allowed_exit_codes: Vec<i32>,
    pub timeout_ms: Option<u64>,
}

pub struct ToolRunner {
    binaries: HashMap<&'static str, String>,
}

impl ToolRunner {
    pub fn new(binaries: HashMap<&'static str, String>) -> Self {
        ToolRunner { binaries }
    }

    /// Resolved binary path/name registered for `tool`, if any — mainly
    /// for tests/diagnostics asserting a config-driven binary override
    /// actually reached the runner.
    pub fn binary_for(&self, tool: &str) -> Option<&str> {
        self.binaries.get(tool).map(String::as_str)
    }

    fn resolve_binary(&self, tool: &str) -> Result<String, ToolError> {
        if FIXED_COMMANDS.contains(&tool) {
            return Ok(tool.to_string());
        }
        self.binaries
            .get(tool)
            .cloned()
            .ok_or_else(|| ToolError::Unsupported(tool.to_string()))
    }

    fn build_env(&self, overrides: &HashMap<String, String>) -> HashMap<String, String> {
        let mut env: HashMap<String, String> = std::env::vars().collect();
        env.insert("GIT_TERMINAL_PROMPT".to_string(), "0".to_string());
        for (k, v) in overrides {
            env.insert(k.clone(), v.clone());
        }
        sanitize_env(&env)
    }

    pub async fn run_tool(
        &self,
        tool: &str,
        args: &[String],
        cwd: &str,
        opts: RunToolOptions,
    ) -> Result<ToolOutput, ToolError> {
        let safe_tool = sanitize_command(tool)?;
        let safe_args = sanitize_cli_args(args)?;
        let safe_cwd = sanitize_cwd(cwd)?;
        let env = self.build_env(&opts.env);
        let timeout_ms = opts.timeout_ms.filter(|&t| t > 0).unwrap_or(120_000);
        let allowed_exit_codes = if opts.allowed_exit_codes.is_empty() {
            vec![0]
        } else {
            opts.allowed_exit_codes
        };

        let binary = self.resolve_binary(&safe_tool)?;

        tracing::info!(
            tool = %safe_tool,
            binary = %binary,
            args = %safe_args.join(" "),
            cwd = %safe_cwd,
            "tool-runner: invoking"
        );

        let mut command = Command::new(&binary);
        command
            .args(&safe_args)
            .current_dir(&safe_cwd)
            .env_clear()
            .envs(&env)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let run = async {
            let output = command.output().await.map_err(|e| ToolError::Failed {
                command: binary.clone(),
                args: safe_args.join(" "),
                timeout_note: String::new(),
                detail: e.to_string(),
            })?;
            Ok::<_, ToolError>(output)
        };

        let output = match tokio::time::timeout(Duration::from_millis(timeout_ms), run).await {
            Ok(result) => result?,
            Err(_) => {
                tracing::warn!(
                    tool = %safe_tool,
                    args = %safe_args.join(" "),
                    timeout_ms,
                    "tool-runner: timed out"
                );
                return Err(ToolError::Failed {
                    command: binary,
                    args: safe_args.join(" "),
                    timeout_note: format!(" (timed out after {timeout_ms}ms)"),
                    detail: "timed out".to_string(),
                })
            }
        };

        let code = output.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        tracing::info!(
            tool = %safe_tool,
            args = %safe_args.join(" "),
            cwd = %safe_cwd,
            exit_code = code,
            stdout = %log_preview(stdout.trim()),
            stderr = %log_preview(stderr.trim()),
            "tool-runner: completed"
        );

        if code != 0 && !allowed_exit_codes.contains(&code) {
            let detail = if !stderr.trim().is_empty() {
                stderr.trim().to_string()
            } else {
                stdout.trim().to_string()
            };
            return Err(ToolError::Failed {
                command: binary,
                args: safe_args.join(" "),
                timeout_note: String::new(),
                detail,
            });
        }

        Ok(ToolOutput {
            stdout: stdout.trim().to_string(),
            stderr: stderr.trim().to_string(),
        })
    }

    pub async fn run_tool_streaming<F: FnMut(&str) + Send>(
        &self,
        tool: &str,
        args: &[String],
        cwd: &str,
        mut on_line: F,
        env_overrides: &HashMap<String, String>,
        timeout_ms: u64,
    ) -> Result<(), ToolError> {
        let safe_tool = sanitize_command(tool)?;
        if !STREAMING_COMMANDS.contains(&safe_tool.as_str()) {
            return Err(ToolError::Unsupported(safe_tool));
        }
        let safe_args = sanitize_cli_args(args)?;
        let safe_cwd = sanitize_cwd(cwd)?;
        let env = self.build_env(env_overrides);
        let binary = self.resolve_binary(&safe_tool)?;

        tracing::info!(
            tool = %safe_tool,
            binary = %binary,
            args = %safe_args.join(" "),
            cwd = %safe_cwd,
            "tool-runner: invoking (streaming)"
        );

        let mut command = Command::new(&binary);
        command
            .args(&safe_args)
            .current_dir(&safe_cwd)
            .env_clear()
            .envs(&env)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = command.spawn()?;
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");

        let mut captured_lines: Vec<String> = Vec::new();

        let run = async {
            let mut out_lines = BufReader::new(stdout).lines();
            let mut err_lines = BufReader::new(stderr).lines();
            loop {
                tokio::select! {
                    line = out_lines.next_line() => {
                        match line {
                            Ok(Some(l)) if !l.trim().is_empty() => { captured_lines.push(l.clone()); on_line(&l); }
                            Ok(Some(_)) => {}
                            Ok(None) => break,
                            Err(e) => return Err(ToolError::Io(e)),
                        }
                    }
                    line = err_lines.next_line() => {
                        match line {
                            Ok(Some(l)) if !l.trim().is_empty() => { captured_lines.push(l.clone()); on_line(&l); }
                            Ok(Some(_)) => {}
                            Ok(None) => {}
                            Err(e) => return Err(ToolError::Io(e)),
                        }
                    }
                }
            }
            // Drain whatever's left on stderr after stdout closes (mirrors
            // the JS version's per-stream independent EOF handling).
            while let Ok(Some(l)) = err_lines.next_line().await {
                if !l.trim().is_empty() {
                    captured_lines.push(l.clone());
                    on_line(&l);
                }
            }
            Ok(())
        };

        let wait_result = tokio::time::timeout(Duration::from_millis(timeout_ms), run).await;
        match wait_result {
            Err(_) => {
                let _ = child.kill().await;
                tracing::warn!(
                    tool = %safe_tool,
                    args = %safe_args.join(" "),
                    timeout_ms,
                    "tool-runner: timed out (streaming)"
                );
                return Err(ToolError::TimedOut(binary, timeout_ms as f64 / 60_000.0));
            }
            Ok(Err(e)) => return Err(e),
            Ok(Ok(())) => {}
        }

        let status = child.wait().await?;
        let code = status.code().unwrap_or(-1);
        tracing::info!(
            tool = %safe_tool,
            args = %safe_args.join(" "),
            cwd = %safe_cwd,
            exit_code = code,
            output = %log_preview(&captured_lines.join("\n")),
            "tool-runner: completed (streaming)"
        );
        if code == 0 {
            return Ok(());
        }
        let failure_lines = extract_failure_lines(&captured_lines);
        let detail = if failure_lines.is_empty() {
            String::new()
        } else {
            let tail: Vec<&str> = failure_lines
                .iter()
                .rev()
                .take(3)
                .rev()
                .map(|s| s.as_str())
                .collect();
            format!(" Cause: {}", tail.join(" | "))
        };
        Err(ToolError::ExitedNonZero {
            command: binary,
            code,
            detail,
            failure_lines,
        })
    }
}

/// A non-zero exit code alone tells you nothing about what actually broke
/// — pulls out every line that looks like a real failure (❌, "Error:",
/// "fatal:", "Failure -", ...), deduped.
pub fn extract_failure_lines(lines: &[String]) -> Vec<String> {
    let ansi_stripped = |s: &str| -> String {
        // Strip `\x1b[...letter` ANSI escape sequences.
        let mut out = String::with_capacity(s.len());
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' && chars.peek() == Some(&'[') {
                chars.next();
                for next in chars.by_ref() {
                    if next.is_ascii_alphabetic() {
                        break;
                    }
                }
                continue;
            }
            out.push(c);
        }
        out
    };
    let looks_like_failure = |l: &str| {
        let lower = l.to_lowercase();
        l.contains('❌')
            || l.contains("::error")
            || lower.contains("error:")
            || lower.contains("fatal:")
            || lower.contains("failure")
    };

    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for raw in lines {
        let l = ansi_stripped(raw).trim().to_string();
        if !l.is_empty() && looks_like_failure(&l) && seen.insert(l.clone()) {
            out.push(l);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_command_rejects_unknown_binaries() {
        assert!(sanitize_command("rm").is_err());
        assert!(sanitize_command("git").is_ok());
    }

    #[test]
    fn sanitize_cli_args_rejects_control_characters() {
        let args = vec!["safe".to_string(), "bad\narg".to_string()];
        assert!(sanitize_cli_args(&args).is_err());
    }

    #[test]
    fn sanitize_env_drops_invalid_keys_and_nul_values() {
        let mut env = HashMap::new();
        env.insert("VALID_KEY".to_string(), "value".to_string());
        env.insert("123invalid".to_string(), "value".to_string());
        env.insert("HAS_NUL".to_string(), "bad\0value".to_string());
        let sanitized = sanitize_env(&env);
        assert_eq!(sanitized.len(), 1);
        assert!(sanitized.contains_key("VALID_KEY"));
    }

    #[test]
    fn sanitize_upload_relative_path_blocks_traversal_and_absolute() {
        assert!(sanitize_upload_relative_path("../etc/passwd").is_err());
        assert!(sanitize_upload_relative_path("/etc/passwd").is_err());
        assert!(sanitize_upload_relative_path("C:/Windows").is_err());
        assert_eq!(sanitize_upload_relative_path("src/a.js").unwrap(), "src/a.js");
        assert_eq!(sanitize_upload_relative_path("src\\a.js").unwrap(), "src/a.js");
    }

    /// Cross-checked live against the real
    /// createToolRunner({}).sanitizeUploadRelativePath for these exact
    /// inputs — every case here matches the Node original's output
    /// (or error) byte-for-byte.
    #[test]
    fn sanitize_upload_relative_path_matches_node_original_case_by_case() {
        assert_eq!(sanitize_upload_relative_path("src/a.js").unwrap(), "src/a.js");
        assert_eq!(sanitize_upload_relative_path("src\\a.js").unwrap(), "src/a.js");
        assert!(sanitize_upload_relative_path("../etc/passwd").is_err());
        assert!(sanitize_upload_relative_path("/etc/passwd").is_err());
        assert!(sanitize_upload_relative_path("C:/Windows").is_err());
        assert_eq!(sanitize_upload_relative_path("./a/./b").unwrap(), "a/b");
        assert!(sanitize_upload_relative_path("a/../../b").is_err());
        assert_eq!(sanitize_upload_relative_path("a//b").unwrap(), "a/b");
        assert!(sanitize_upload_relative_path("~/x").is_err());
    }

    #[test]
    fn extract_failure_lines_dedupes_and_strips_ansi() {
        let lines = vec![
            "\u{1b}[31m❌ build failed\u{1b}[0m".to_string(),
            "❌ build failed".to_string(), // dupe after ANSI strip
            "just some normal output".to_string(),
            "fatal: not a git repository".to_string(),
        ];
        let out = extract_failure_lines(&lines);
        assert_eq!(out, vec!["❌ build failed", "fatal: not a git repository"]);
    }

    #[tokio::test]
    async fn run_tool_captures_stdout_of_a_real_command() {
        let mut binaries = HashMap::new();
        binaries.insert("gitleaks", "/nonexistent".to_string());
        let runner = ToolRunner::new(binaries);
        let out = runner
            .run_tool("git", &["--version".to_string()], "/tmp", RunToolOptions::default())
            .await
            .unwrap();
        assert!(out.stdout.starts_with("git version"));
    }

    #[tokio::test]
    async fn run_tool_rejects_disallowed_command() {
        let runner = ToolRunner::new(HashMap::new());
        let err = runner
            .run_tool("rm", &["-rf".to_string()], "/tmp", RunToolOptions::default())
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::CommandNotAllowed(_)));
    }

    #[tokio::test]
    async fn run_tool_respects_allowed_exit_codes() {
        let runner = ToolRunner::new(HashMap::new());
        // `git -C /tmp status` inside a non-repo exits non-zero; without
        // opting in via allowed_exit_codes this should surface as an error.
        let err = runner
            .run_tool(
                "git",
                &["merge-base".to_string(), "--is-ancestor".to_string(), "HEAD".to_string(), "HEAD~1".to_string()],
                "/tmp",
                RunToolOptions::default(),
            )
            .await;
        assert!(err.is_err());
    }
}
