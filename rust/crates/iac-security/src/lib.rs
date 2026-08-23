//! IaC/container misconfiguration scan (Dockerfiles, Terraform, Kubernetes
//! manifests, Helm charts) via Trivy (primary) + Checkov + Hadolint,
//! running concurrently. Faithful port of `checks/iac-security.js`.

use ignite_fs_utils::{build_snippet, is_dockerfile_name, looks_binary, walk_files, Snippet, SnippetOptions};
use ignite_tool_runner::{RunToolOptions, ToolRunner};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use std::path::Path;

static FROM_LINE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^\s*FROM\s+(\S+?)(?:\s+AS\s+\S+)?\s*$").unwrap());
static USER_LINE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^\s*USER\s+\S+").unwrap());
static TAG_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r":([^@\s]+)$").unwrap());

pub struct IacSecurityConfig {
    pub trivy_enabled: bool,
    pub checkov_enabled: bool,
    pub hadolint_enabled: bool,
}

impl Default for IacSecurityConfig {
    fn default() -> Self {
        IacSecurityConfig { trivy_enabled: true, checkov_enabled: true, hadolint_enabled: true }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct IacFinding {
    pub file: String,
    pub line: usize,
    pub kind: String,
    pub tool: &'static str,
    pub severity: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<Snippet>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IacSecurityResult {
    pub findings: Vec<IacFinding>,
    pub engine: String,
}

fn relative_no_realpath(root: &Path, name: &str) -> String {
    if name.is_empty() {
        return String::new();
    }
    let resolved = if Path::new(name).is_absolute() { std::path::PathBuf::from(name) } else { root.join(name) };
    pathdiff(&resolved, root)
}

fn pathdiff(target: &Path, base: &Path) -> String {
    let target_components: Vec<_> = target.components().collect();
    let base_components: Vec<_> = base.components().collect();
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

pub async fn trivy_tooling(runner: &ToolRunner) -> bool {
    runner.run_tool("trivy", &["--version".to_string()], std::env::temp_dir().to_str().unwrap_or("."), RunToolOptions::default()).await.is_ok()
}

pub async fn checkov_tooling(runner: &ToolRunner) -> bool {
    runner.run_tool("checkov", &["--version".to_string()], std::env::temp_dir().to_str().unwrap_or("."), RunToolOptions::default()).await.is_ok()
}

pub async fn hadolint_tooling(runner: &ToolRunner) -> bool {
    runner.run_tool("hadolint", &["--version".to_string()], std::env::temp_dir().to_str().unwrap_or("."), RunToolOptions::default()).await.is_ok()
}

/// Returns `None` (never panics) on any tool/parse failure so the caller
/// always has the built-in fallback to drop back to.
pub async fn run_trivy_iac_scan(root: &Path, runner: &ToolRunner) -> Option<Vec<IacFinding>> {
    let report_path = std::env::temp_dir().join(format!("ignite-trivy-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)));

    let run_result = runner
        .run_tool(
            "trivy",
            &[
                "config".to_string(),
                "--format".to_string(),
                "json".to_string(),
                "--output".to_string(),
                report_path.to_string_lossy().into_owned(),
                "--exit-code".to_string(),
                "0".to_string(),
                "--quiet".to_string(),
                root.to_string_lossy().into_owned(),
            ],
            &root.to_string_lossy(),
            RunToolOptions::default(),
        )
        .await;

    let result = if run_result.is_err() {
        None
    } else {
        let raw = tokio::fs::read_to_string(&report_path).await.ok();
        match raw {
            None => Some(vec![]),
            Some(raw) => {
                let data: serde_json::Value = if raw.trim().is_empty() { serde_json::json!({}) } else { serde_json::from_str(&raw).unwrap_or(serde_json::json!({})) };
                let results = data.get("Results").and_then(|r| r.as_array()).cloned().unwrap_or_default();
                let mut findings = Vec::new();
                for result in &results {
                    let target = result.get("Target").and_then(|t| t.as_str()).unwrap_or("");
                    let rel_file = relative_no_realpath(root, target);
                    let content = std::fs::read_to_string(root.join(&rel_file)).ok();
                    let misconfigs = result.get("Misconfigurations").and_then(|m| m.as_array()).cloned().unwrap_or_default();
                    for m in &misconfigs {
                        let line = m.get("CauseMetadata").and_then(|c| c.get("StartLine")).and_then(|l| l.as_i64()).unwrap_or(0).max(1) as usize;
                        findings.push(IacFinding {
                            file: rel_file.clone(),
                            line,
                            kind: m.get("ID").and_then(|v| v.as_str()).unwrap_or("misconfig").to_lowercase(),
                            tool: "trivy",
                            severity: m.get("Severity").and_then(|v| v.as_str()).unwrap_or("MEDIUM").to_lowercase(),
                            message: m.get("Title").and_then(|v| v.as_str()).or_else(|| m.get("Message").and_then(|v| v.as_str())).unwrap_or("IaC misconfiguration").to_string(),
                            code: content.as_deref().and_then(|c| build_snippet(c, line, SnippetOptions::default())),
                        });
                    }
                }
                Some(findings)
            }
        }
    };
    let _ = tokio::fs::remove_file(&report_path).await;
    result
}

fn normalize_checkov_report(data: &serde_json::Value) -> Vec<serde_json::Value> {
    if let Some(arr) = data.as_array() {
        return arr.clone();
    }
    if data.is_object() && data.get("results").is_some() {
        return vec![data.clone()];
    }
    vec![]
}

/// Never panics on any tool/parse failure — returns `None`.
pub async fn run_checkov_iac_scan(root: &Path, runner: &ToolRunner) -> Option<Vec<IacFinding>> {
    // `-d .` (not the absolute root) with cwd=root, matching the JS
    // original's documented workaround for checkov emitting filesystem-
    // rooted paths when given an absolute -d target.
    let output = runner
        .run_tool(
            "checkov",
            &["-d".to_string(), ".".to_string(), "--output".to_string(), "json".to_string(), "--compact".to_string(), "--quiet".to_string(), "--soft-fail".to_string()],
            &root.to_string_lossy(),
            RunToolOptions { allowed_exit_codes: vec![0, 1], ..Default::default() },
        )
        .await;

    let output = output.ok()?;
    if output.stdout.trim().is_empty() {
        return Some(vec![]);
    }
    let data: serde_json::Value = serde_json::from_str(&output.stdout).ok()?;
    let reports = normalize_checkov_report(&data);
    let real_root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());

    let mut findings = Vec::new();
    for report in &reports {
        let Some(failed) = report.get("results").and_then(|r| r.get("failed_checks")).and_then(|f| f.as_array()) else { continue };
        for c in failed {
            let raw_path = c.get("repo_file_path").and_then(|v| v.as_str()).or_else(|| c.get("file_path").and_then(|v| v.as_str())).unwrap_or("");
            if raw_path.is_empty() {
                continue;
            }
            let trimmed = raw_path.trim_start_matches('/');
            let rel_file = relative_no_realpath(&real_root, trimmed);
            if rel_file.is_empty() || rel_file.starts_with("..") {
                continue;
            }
            let line = c.get("file_line_range").and_then(|r| r.as_array()).and_then(|a| a.first()).and_then(|v| v.as_i64()).unwrap_or(0).max(1) as usize;
            let content = std::fs::read_to_string(root.join(&rel_file)).ok();
            findings.push(IacFinding {
                file: rel_file,
                line,
                kind: c.get("check_id").and_then(|v| v.as_str()).unwrap_or("misconfig").to_lowercase(),
                tool: "checkov",
                severity: c.get("severity").and_then(|v| v.as_str()).unwrap_or("MEDIUM").to_lowercase(),
                message: c.get("check_name").and_then(|v| v.as_str()).unwrap_or("IaC misconfiguration").to_string(),
                code: content.as_deref().and_then(|c| build_snippet(c, line, SnippetOptions::default())),
            });
        }
    }
    Some(findings)
}

fn hadolint_severity(level: &str) -> &'static str {
    match level {
        "error" => "high",
        "warning" => "medium",
        "info" => "low",
        "style" => "low",
        _ => "medium",
    }
}

/// hadolint only understands individual Dockerfiles (no directory/repo
/// mode), so this does its own file discovery and passes every match as a
/// single multi-file invocation.
pub async fn run_hadolint_iac_scan(root: &Path, runner: &ToolRunner) -> std::io::Result<Option<Vec<IacFinding>>> {
    let mut dockerfiles = Vec::new();
    for file in walk_files(root)? {
        let base = file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        if is_dockerfile_name(&base) {
            dockerfiles.push(file.strip_prefix(root).unwrap_or(&file).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/"));
        }
    }
    if dockerfiles.is_empty() {
        return Ok(Some(vec![]));
    }

    let mut args = vec!["--format".to_string(), "json".to_string()];
    args.extend(dockerfiles);
    let output = match runner.run_tool("hadolint", &args, &root.to_string_lossy(), RunToolOptions { allowed_exit_codes: vec![0, 1], ..Default::default() }).await {
        Ok(o) => o,
        Err(_) => return Ok(None),
    };

    let results: Vec<serde_json::Value> = if output.stdout.trim().is_empty() {
        vec![]
    } else {
        match serde_json::from_str(&output.stdout) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        }
    };

    let mut findings = Vec::new();
    for r in results {
        let rel_file = r.get("file").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let line = r.get("line").and_then(|l| l.as_i64()).unwrap_or(0).max(1) as usize;
        let content = std::fs::read_to_string(root.join(&rel_file)).ok();
        findings.push(IacFinding {
            file: rel_file,
            line,
            kind: r.get("code").and_then(|v| v.as_str()).unwrap_or("dockerfile-lint").to_lowercase(),
            tool: "hadolint",
            severity: hadolint_severity(r.get("level").and_then(|v| v.as_str()).unwrap_or("")).to_string(),
            message: r.get("message").and_then(|v| v.as_str()).unwrap_or("Dockerfile lint issue").to_string(),
            code: content.as_deref().and_then(|c| build_snippet(c, line, SnippetOptions::default())),
        });
    }
    Ok(Some(findings))
}

/// Deliberately narrow (two well-known Dockerfile smells) rather than an
/// attempt to replicate trivy's much larger rule set. Used only when trivy
/// is unavailable.
pub fn check_iac_security_fallback(root: &Path) -> std::io::Result<Vec<IacFinding>> {
    let mut findings = Vec::new();
    for file in walk_files(root)? {
        let base = file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        if !is_dockerfile_name(&base) {
            continue;
        }
        let Ok(buffer) = std::fs::read(&file) else { continue };
        if looks_binary(&buffer) {
            continue;
        }
        let content = String::from_utf8_lossy(&buffer).into_owned();
        let rel = file.strip_prefix(root).unwrap_or(&file).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
        let mut has_user = false;
        for (i, line) in content.split('\n').enumerate() {
            let line = line.strip_suffix('\r').unwrap_or(line);
            if let Some(m) = FROM_LINE_RE.captures(line) {
                let image = m.get(1).map(|x| x.as_str()).unwrap_or("");
                let has_digest = image.contains("@sha256:");
                let tag = TAG_RE.captures(image).and_then(|c| c.get(1)).map(|m| m.as_str());
                let is_unpinned = !has_digest && (tag.is_none() || tag == Some("latest"));
                if is_unpinned {
                    findings.push(IacFinding {
                        file: rel.clone(),
                        line: i + 1,
                        kind: "unpinned-base-image".to_string(),
                        tool: "ignite-fallback",
                        severity: "medium".to_string(),
                        message: format!(r#"Base image "{}" is not pinned to a fixed tag/digest — resolves to whatever "latest" is at build time."#, image),
                        code: build_snippet(&content, i + 1, SnippetOptions::default()),
                    });
                }
            }
            if USER_LINE_RE.is_match(line) {
                has_user = true;
            }
        }
        if !has_user {
            findings.push(IacFinding {
                file: rel,
                line: 1,
                kind: "container-runs-as-root".to_string(),
                tool: "ignite-fallback",
                severity: "medium".to_string(),
                message: "No USER instruction — the container runs as root by default.".to_string(),
                code: build_snippet(&content, 1, SnippetOptions::default()),
            });
        }
    }
    Ok(findings)
}

fn dedup_key(f: &IacFinding) -> String {
    format!("{}:{}:{}", f.file, f.line, f.kind)
}

/// Trivy (primary), Checkov, and Hadolint each scan the same static tree
/// completely independently, so all three run concurrently. Deduped on
/// file+line+rule-id (not just file+line — different scanners routinely
/// flag distinct real issues on the same line). Checkov is merged before
/// hadolint (fixed order) so `engine`'s suffix ordering is deterministic.
pub async fn check_iac_security(root: &Path, runner: &ToolRunner, config: &IacSecurityConfig) -> std::io::Result<IacSecurityResult> {
    let (trivy_ok, checkov_ok, hadolint_ok) = futures::join!(
        async { config.trivy_enabled && trivy_tooling(runner).await },
        async { config.checkov_enabled && checkov_tooling(runner).await },
        async { config.hadolint_enabled && hadolint_tooling(runner).await },
    );

    let trivy_future = async {
        if !trivy_ok {
            return (check_iac_security_fallback(root).unwrap_or_default(), "fallback".to_string());
        }
        match run_trivy_iac_scan(root, runner).await {
            Some(findings) => (findings, "trivy".to_string()),
            None => (check_iac_security_fallback(root).unwrap_or_default(), "fallback".to_string()),
        }
    };

    let checkov_future = async { if config.checkov_enabled && checkov_ok { run_checkov_iac_scan(root, runner).await } else { None } };

    let hadolint_future = async {
        if config.hadolint_enabled && hadolint_ok {
            run_hadolint_iac_scan(root, runner).await.unwrap_or(None)
        } else {
            None
        }
    };

    let ((base_findings, base_engine), checkov_findings, hadolint_findings) = futures::join!(trivy_future, checkov_future, hadolint_future);

    let mut findings = base_findings;
    let mut engine = base_engine;

    if let Some(checkov_findings) = checkov_findings {
        let seen: std::collections::HashSet<String> = findings.iter().map(dedup_key).collect();
        findings.extend(checkov_findings.into_iter().filter(|f| !seen.contains(&dedup_key(f))));
        engine = format!("{}+checkov", engine);
    }
    if let Some(hadolint_findings) = hadolint_findings {
        let seen: std::collections::HashSet<String> = findings.iter().map(dedup_key).collect();
        findings.extend(hadolint_findings.into_iter().filter(|f| !seen.contains(&dedup_key(f))));
        engine = format!("{}+hadolint", engine);
    }

    Ok(IacSecurityResult { findings, engine })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use tempfile::tempdir;

    fn runner_with(tools: &[&'static str]) -> ToolRunner {
        let mut binaries = HashMap::new();
        for t in tools {
            binaries.insert(*t, t.to_string());
        }
        ToolRunner::new(binaries)
    }

    #[test]
    fn fallback_flags_unpinned_image_and_missing_user() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("Dockerfile"), "FROM node:latest\nCOPY . .\n").unwrap();

        let findings = check_iac_security_fallback(root).unwrap();
        assert!(findings.iter().any(|f| f.kind == "unpinned-base-image"));
        assert!(findings.iter().any(|f| f.kind == "container-runs-as-root"));
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn fallback_accepts_digest_pinned_image_with_user() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("Dockerfile"), "FROM node@sha256:abcdef1234567890\nUSER app\nCOPY . .\n").unwrap();

        let findings = check_iac_security_fallback(root).unwrap();
        assert!(!findings.iter().any(|f| f.kind == "unpinned-base-image"));
        assert!(!findings.iter().any(|f| f.kind == "container-runs-as-root"));
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn normalize_checkov_report_handles_single_object_and_array() {
        let single = serde_json::json!({"results": {"failed_checks": []}});
        assert_eq!(normalize_checkov_report(&single).len(), 1);
        let array = serde_json::json!([{"results": {}}, {"results": {}}]);
        assert_eq!(normalize_checkov_report(&array).len(), 2);
        let neither = serde_json::json!({"foo": "bar"});
        assert_eq!(normalize_checkov_report(&neither).len(), 0);
    }

    #[test]
    fn hadolint_severity_mapping() {
        assert_eq!(hadolint_severity("error"), "high");
        assert_eq!(hadolint_severity("warning"), "medium");
        assert_eq!(hadolint_severity("info"), "low");
        assert_eq!(hadolint_severity("style"), "low");
        assert_eq!(hadolint_severity("unknown"), "medium");
    }

    #[tokio::test]
    async fn disabled_everything_falls_back() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("Dockerfile"), "FROM node:latest\n").unwrap();
        let config = IacSecurityConfig { trivy_enabled: false, checkov_enabled: false, hadolint_enabled: false };
        let result = check_iac_security(root, &ToolRunner::new(HashMap::new()), &config).await.unwrap();
        assert_eq!(result.engine, "fallback");
        assert!(!result.findings.is_empty());
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[tokio::test]
    async fn real_trivy_binary_end_to_end() {
        let mut check = std::process::Command::new("trivy");
        check.arg("--version");
        if check.output().map(|o| !o.status.success()).unwrap_or(true) {
            eprintln!("skipping: trivy not installed on PATH");
            return;
        }

        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("Dockerfile"), "FROM node:latest\nCOPY . .\n").unwrap();

        let config = IacSecurityConfig { trivy_enabled: true, checkov_enabled: false, hadolint_enabled: false };
        let result = check_iac_security(root, &runner_with(&["trivy"]), &config).await.unwrap();
        assert_eq!(result.engine, "trivy");
        assert!(!result.findings.is_empty(), "expected trivy to flag the unpinned latest-tag base image");
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[tokio::test]
    async fn real_hadolint_binary_end_to_end() {
        let mut check = std::process::Command::new("hadolint");
        check.arg("--version");
        if check.output().map(|o| !o.status.success()).unwrap_or(true) {
            eprintln!("skipping: hadolint not installed on PATH");
            return;
        }

        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("Dockerfile"), "FROM node:18\nADD . /app\n").unwrap();

        let config = IacSecurityConfig { trivy_enabled: false, checkov_enabled: false, hadolint_enabled: true };
        let result = check_iac_security(root, &runner_with(&["hadolint"]), &config).await.unwrap();
        assert!(result.engine.ends_with("+hadolint"), "engine was {}", result.engine);
        assert!(result.findings.iter().any(|f| f.tool == "hadolint"), "expected hadolint to flag ADD instead of COPY");
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[tokio::test]
    async fn real_checkov_binary_end_to_end() {
        let mut check = std::process::Command::new("checkov");
        check.arg("--version");
        if check.output().map(|o| !o.status.success()).unwrap_or(true) {
            eprintln!("skipping: checkov not installed on PATH");
            return;
        }

        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("Dockerfile"), "FROM node:18\nUSER root\nCOPY . .\n").unwrap();

        let config = IacSecurityConfig { trivy_enabled: false, checkov_enabled: true, hadolint_enabled: false };
        let result = check_iac_security(root, &runner_with(&["checkov"]), &config).await.unwrap();
        assert!(result.engine.ends_with("+checkov"), "engine was {}", result.engine);
        assert!(result.findings.iter().any(|f| f.tool == "checkov"), "expected checkov to flag something in the Dockerfile");
        ignite_fs_utils::invalidate_walk_cache(root);
    }
}
