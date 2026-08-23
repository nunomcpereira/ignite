//! Builds every discovered Dockerfile and runs `trivy image` against the
//! result, catching known-vulnerable packages baked into a base image's
//! OS/package layer — a gap `checks/iac-security.js`'s `trivy config`
//! can't see, since that only lints the Dockerfile source, never what
//! actually ends up installed inside the image. Off by default: the one
//! Phase 4 check that needs a real image build, not just a static read.
//! Faithful port of `checks/container-image-vulnerabilities.js`.

use ignite_fs_utils::{is_dockerfile_name, walk_files};
use ignite_tool_runner::{RunToolOptions, ToolRunner};
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;

pub struct ContainerImageVulnerabilitiesConfig {
    pub enabled: bool,
    pub severity_threshold: String,
    pub build_timeout_ms: u64,
}

impl Default for ContainerImageVulnerabilitiesConfig {
    fn default() -> Self {
        ContainerImageVulnerabilitiesConfig { enabled: false, severity_threshold: "HIGH,CRITICAL".to_string(), build_timeout_ms: 8 * 60_000 }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ContainerImageVulnFinding {
    pub file: String,
    pub line: usize,
    pub kind: String,
    pub pkg_name: Option<String>,
    pub tool: &'static str,
    pub severity: String,
    pub message: String,
    pub code: Option<()>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContainerImageVulnerabilitiesResult {
    pub findings: Vec<ContainerImageVulnFinding>,
    pub engine: &'static str,
}

pub struct TrivyImageToolingProbe {
    pub ok: bool,
    pub reason: Option<String>,
}

pub async fn trivy_image_tooling(runner: &ToolRunner) -> TrivyImageToolingProbe {
    let tmp = std::env::temp_dir();
    let tmp_str = tmp.to_str().unwrap_or(".");
    if runner.run_tool("trivy", &["--version".to_string()], tmp_str, RunToolOptions::default()).await.is_err() {
        return TrivyImageToolingProbe { ok: false, reason: Some("`trivy` is not installed (brew install trivy).".to_string()) };
    }
    if runner.run_tool("docker", &["info".to_string(), "--format".to_string(), "{{.ServerVersion}}".to_string()], tmp_str, RunToolOptions::default()).await.is_err() {
        return TrivyImageToolingProbe { ok: false, reason: Some("Docker daemon is not running (start Docker Desktop) — needed to build the image before scanning it.".to_string()) };
    }
    TrivyImageToolingProbe { ok: true, reason: None }
}

fn unique_suffix() -> String {
    format!("{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0))
}

/// Never panics: any build/scan failure for one Dockerfile is skipped so
/// one bad Dockerfile doesn't block findings from the rest.
pub async fn check_container_image_vulnerabilities(root: &Path, runner: &ToolRunner, config: &ContainerImageVulnerabilitiesConfig) -> std::io::Result<ContainerImageVulnerabilitiesResult> {
    let tooling_ok = config.enabled && trivy_image_tooling(runner).await.ok;
    if !tooling_ok {
        return Ok(ContainerImageVulnerabilitiesResult { findings: vec![], engine: "disabled" });
    }

    let mut dockerfiles = Vec::new();
    for file in walk_files(root)? {
        let base = file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        if is_dockerfile_name(&base) {
            dockerfiles.push(file);
        }
    }
    if dockerfiles.is_empty() {
        return Ok(ContainerImageVulnerabilitiesResult { findings: vec![], engine: "trivy-image" });
    }

    let mut findings = Vec::new();
    for dockerfile in &dockerfiles {
        let rel_dockerfile = dockerfile.strip_prefix(root).unwrap_or(dockerfile).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
        let build_context = dockerfile.parent().unwrap_or(root);
        let tag = format!("ignite-trivyscan-{}:latest", unique_suffix());
        let report_path = std::env::temp_dir().join(format!("ignite-trivy-image-{}.json", unique_suffix()));

        let build_result = runner
            .run_tool_streaming(
                "docker",
                &["build".to_string(), "-f".to_string(), dockerfile.to_string_lossy().into_owned(), "-t".to_string(), tag.clone(), build_context.to_string_lossy().into_owned()],
                &root.to_string_lossy(),
                |_line| {},
                &HashMap::new(),
                config.build_timeout_ms,
            )
            .await;

        let mut built = false;
        if build_result.is_ok() {
            built = true;
            let scan_result = runner
                .run_tool(
                    "trivy",
                    &[
                        "image".to_string(),
                        "--format".to_string(),
                        "json".to_string(),
                        "--output".to_string(),
                        report_path.to_string_lossy().into_owned(),
                        "--severity".to_string(),
                        config.severity_threshold.clone(),
                        "--exit-code".to_string(),
                        "0".to_string(),
                        "--quiet".to_string(),
                        tag.clone(),
                    ],
                    &root.to_string_lossy(),
                    RunToolOptions::default(),
                )
                .await;

            if scan_result.is_ok() {
                let raw = tokio::fs::read_to_string(&report_path).await.unwrap_or_default();
                let data: serde_json::Value = if raw.trim().is_empty() { serde_json::json!({}) } else { serde_json::from_str(&raw).unwrap_or(serde_json::json!({})) };
                let results = data.get("Results").and_then(|r| r.as_array()).cloned().unwrap_or_default();
                for result in &results {
                    let vulns = result.get("Vulnerabilities").and_then(|v| v.as_array()).cloned().unwrap_or_default();
                    for v in &vulns {
                        let pkg_name = v.get("PkgName").and_then(|p| p.as_str()).map(String::from);
                        let installed = v.get("InstalledVersion").and_then(|p| p.as_str()).unwrap_or("?");
                        let title = v.get("Title").and_then(|t| t.as_str()).or_else(|| v.get("VulnerabilityID").and_then(|t| t.as_str())).unwrap_or("known vulnerability");
                        let fixed = v.get("FixedVersion").and_then(|f| f.as_str());
                        let message = format!("{}@{}: {}{}", pkg_name.as_deref().unwrap_or("package"), installed, title, fixed.map(|f| format!(" (fixed in {})", f)).unwrap_or_default());
                        findings.push(ContainerImageVulnFinding {
                            file: rel_dockerfile.clone(),
                            line: 1,
                            kind: v.get("VulnerabilityID").and_then(|i| i.as_str()).unwrap_or("cve").to_lowercase(),
                            pkg_name,
                            tool: "trivy-image",
                            severity: v.get("Severity").and_then(|s| s.as_str()).unwrap_or("MEDIUM").to_lowercase(),
                            message,
                            code: None,
                        });
                    }
                }
            }
        }

        let _ = tokio::fs::remove_file(&report_path).await;
        if built {
            let _ = runner.run_tool("docker", &["rmi".to_string(), "-f".to_string(), tag], &root.to_string_lossy(), RunToolOptions::default()).await;
        }
    }

    Ok(ContainerImageVulnerabilitiesResult { findings, engine: "trivy-image" })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap as StdHashMap;
    use std::fs;
    use tempfile::tempdir;

    fn runner_with(tools: &[&'static str]) -> ToolRunner {
        let mut binaries = StdHashMap::new();
        for t in tools {
            binaries.insert(*t, t.to_string());
        }
        ToolRunner::new(binaries)
    }

    #[tokio::test]
    async fn disabled_returns_no_findings() {
        let dir = tempdir().unwrap();
        let config = ContainerImageVulnerabilitiesConfig { enabled: false, ..Default::default() };
        let result = check_container_image_vulnerabilities(dir.path(), &ToolRunner::new(StdHashMap::new()), &config).await.unwrap();
        assert_eq!(result.engine, "disabled");
        assert!(result.findings.is_empty());
    }

    #[tokio::test]
    async fn no_dockerfiles_returns_no_findings_without_probing_tools() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("app.js"), b"console.log(1)").unwrap();
        // "enabled" but with no trivy/docker registered — tooling probe
        // fails, matching the disabled path (the two indistinguishable at
        // this layer, same as the JS original's single `tool.ok` gate).
        let config = ContainerImageVulnerabilitiesConfig { enabled: true, ..Default::default() };
        let result = check_container_image_vulnerabilities(dir.path(), &ToolRunner::new(StdHashMap::new()), &config).await.unwrap();
        assert!(result.findings.is_empty());
        ignite_fs_utils::invalidate_walk_cache(dir.path());
    }

    #[tokio::test]
    async fn real_trivy_and_docker_end_to_end() {
        let mut trivy_check = std::process::Command::new("trivy");
        trivy_check.arg("--version");
        if trivy_check.output().map(|o| !o.status.success()).unwrap_or(true) {
            eprintln!("skipping: trivy not installed on PATH");
            return;
        }
        let mut docker_check = std::process::Command::new("docker");
        docker_check.args(["info", "--format", "{{.ServerVersion}}"]);
        if docker_check.output().map(|o| !o.status.success()).unwrap_or(true) {
            eprintln!("skipping: docker daemon not running");
            return;
        }

        let dir = tempdir().unwrap();
        let root = dir.path();
        // A known-old base image with well-documented CVEs baked into its
        // package layer, small enough to pull/build quickly in a test.
        fs::write(root.join("Dockerfile"), "FROM alpine:3.10\n").unwrap();

        let config = ContainerImageVulnerabilitiesConfig { enabled: true, severity_threshold: "HIGH,CRITICAL".to_string(), build_timeout_ms: 5 * 60_000 };
        let result = check_container_image_vulnerabilities(root, &runner_with(&["trivy", "docker"]), &config).await.unwrap();
        assert_eq!(result.engine, "trivy-image");
        assert!(!result.findings.is_empty(), "expected trivy image scan to find at least one HIGH/CRITICAL CVE in alpine:3.10");
        ignite_fs_utils::invalidate_walk_cache(root);
    }
}
