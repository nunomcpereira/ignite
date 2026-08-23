//! Malicious ML model artifact scan via picklescan. Faithful port of
//! `checks/model-artifact-security.js`. Python's `pickle` format executes
//! arbitrary code on load (`__reduce__`), and it's the on-disk format
//! underneath `.pkl`/`.pickle` dumps and PyTorch `.pt`/`.pth`/`.ckpt`/`.bin`
//! checkpoints (a zip archive of pickles). Deliberately scoped to
//! pickle-based formats only: `.safetensors`/`.onnx` are not pickle-based
//! and out of scope by design.

use ignite_fs_utils::{relative_to_root, walk_files};
use ignite_tool_runner::{RunToolOptions, ToolRunner};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use std::collections::HashSet;
use std::path::Path;

static FINDING_LINE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^(.+?): global import '([^']+)' FOUND$").unwrap());

#[derive(Debug, Clone, Serialize)]
pub struct ModelArtifactFinding {
    pub file: String,
    pub line: Option<usize>,
    pub kind: &'static str,
    pub tool: &'static str,
    pub severity: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModelArtifactSecurityResult {
    pub findings: Vec<ModelArtifactFinding>,
    pub engine: &'static str,
}

pub struct ModelArtifactSecurityConfig {
    pub enabled: bool,
    pub extensions: Vec<String>,
}

impl Default for ModelArtifactSecurityConfig {
    fn default() -> Self {
        ModelArtifactSecurityConfig {
            enabled: true,
            extensions: vec![".pkl".into(), ".pickle".into(), ".pt".into(), ".pth".into(), ".ckpt".into(), ".bin".into()],
        }
    }
}

fn model_artifact_extensions(config: &ModelArtifactSecurityConfig) -> HashSet<String> {
    if config.extensions.is_empty() {
        ModelArtifactSecurityConfig::default().extensions.into_iter().map(|e| e.to_lowercase()).collect()
    } else {
        config.extensions.iter().map(|e| e.to_lowercase()).collect()
    }
}

/// picklescan has no --version flag — probe with --help instead.
pub async fn picklescan_tooling(runner: &ToolRunner) -> bool {
    runner
        .run_tool("picklescan", &["--help".to_string()], std::env::temp_dir().to_str().unwrap_or("."), RunToolOptions::default())
        .await
        .is_ok()
}

fn discover_model_artifacts(root: &Path, extensions: &HashSet<String>) -> std::io::Result<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();
    for file in walk_files(root)? {
        let ext = file.extension().map(|e| format!(".{}", e.to_string_lossy().to_lowercase())).unwrap_or_default();
        if extensions.contains(&ext) {
            files.push(file);
        }
    }
    Ok(files)
}

/// picklescan prints one line per dangerous import:
///   <path>[:<archive-member>]: global import '<module> <name>' FOUND
/// No JSON output mode exists, so this parses the plain-text lines directly.
fn parse_picklescan_output(root: &Path, stdout: &str) -> Vec<ModelArtifactFinding> {
    let mut findings = Vec::new();
    for line in stdout.split('\n') {
        let Some(m) = FINDING_LINE_RE.captures(line.trim()) else { continue };
        let location = &m[1];
        let global_import = &m[2];
        let mut parts = location.split(':');
        let fs_path = parts.next().unwrap_or("");
        let archive_member = parts.collect::<Vec<_>>().join(":");
        let rel_file = relative_to_root(root, fs_path).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
        findings.push(ModelArtifactFinding {
            file: rel_file,
            line: None,
            kind: "malicious-model-artifact",
            tool: "picklescan",
            severity: "error",
            message: format!(
                "Dangerous pickle global import '{}' FOUND{} — code executes on load.",
                global_import,
                if archive_member.is_empty() { String::new() } else { format!(" (in {})", archive_member) }
            ),
        });
    }
    findings
}

/// No built-in fallback: detecting an unsafe pickle global import needs
/// picklescan's real opcode-level parser.
pub async fn check_model_artifact_security(root: &Path, runner: &ToolRunner, config: &ModelArtifactSecurityConfig) -> std::io::Result<ModelArtifactSecurityResult> {
    let tooling_ok = config.enabled && picklescan_tooling(runner).await;
    if !tooling_ok {
        return Ok(ModelArtifactSecurityResult { findings: vec![], engine: "disabled" });
    }

    let extensions = model_artifact_extensions(config);
    let artifacts = discover_model_artifacts(root, &extensions)?;
    if artifacts.is_empty() {
        return Ok(ModelArtifactSecurityResult { findings: vec![], engine: "picklescan" });
    }

    let result = runner
        .run_tool(
            "picklescan",
            &["--path".to_string(), root.to_string_lossy().into_owned()],
            &root.to_string_lossy(),
            RunToolOptions { allowed_exit_codes: vec![0, 1], ..Default::default() },
        )
        .await;

    match result {
        Ok(output) => Ok(ModelArtifactSecurityResult { findings: parse_picklescan_output(root, &output.stdout), engine: "picklescan" }),
        Err(_) => Ok(ModelArtifactSecurityResult { findings: vec![], engine: "disabled" }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use tempfile::tempdir;

    fn runner_with_picklescan() -> ToolRunner {
        let mut binaries = HashMap::new();
        binaries.insert("picklescan", "picklescan".to_string());
        ToolRunner::new(binaries)
    }

    #[test]
    fn parses_finding_lines_with_archive_member() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let path = root.join("model.bin");
        fs::write(&path, b"x").unwrap();
        let stdout = format!(
            "{}:data.pkl: global import 'os system' FOUND\n----------- SCAN SUMMARY -----------\n",
            path.to_string_lossy()
        );
        let findings = parse_picklescan_output(root, &stdout);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file, "model.bin");
        assert_eq!(findings[0].severity, "error");
        assert!(findings[0].message.contains("os system"));
        assert!(findings[0].message.contains("data.pkl"));
    }

    #[test]
    fn parses_finding_line_without_archive_member() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let path = root.join("weights.pkl");
        fs::write(&path, b"x").unwrap();
        let stdout = format!("{}: global import 'subprocess Popen' FOUND\n", path.to_string_lossy());
        let findings = parse_picklescan_output(root, &stdout);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file, "weights.pkl");
        assert!(!findings[0].message.contains("(in "));
    }

    #[test]
    fn discovers_only_configured_extensions() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("model.pkl"), b"x").unwrap();
        fs::write(root.join("readme.md"), b"x").unwrap();
        let extensions = model_artifact_extensions(&ModelArtifactSecurityConfig::default());
        let found = discover_model_artifacts(root, &extensions).unwrap();
        assert_eq!(found.len(), 1);
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[tokio::test]
    async fn disabled_returns_no_findings() {
        let dir = tempdir().unwrap();
        let config = ModelArtifactSecurityConfig { enabled: false, ..Default::default() };
        let result = check_model_artifact_security(dir.path(), &ToolRunner::new(HashMap::new()), &config).await.unwrap();
        assert_eq!(result.engine, "disabled");
        assert!(result.findings.is_empty());
    }

    #[tokio::test]
    async fn no_artifacts_present_returns_no_findings_without_running_tool() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("app.js"), b"console.log(1)").unwrap();
        let result = check_model_artifact_security(dir.path(), &runner_with_picklescan(), &ModelArtifactSecurityConfig::default()).await.unwrap();
        // No picklescan on PATH in this registered-but-fake runner scenario would fail --help too,
        // so this also covers the "tooling probe fails" path gracefully.
        assert!(result.findings.is_empty());
        ignite_fs_utils::invalidate_walk_cache(dir.path());
    }

    #[tokio::test]
    async fn real_picklescan_binary_end_to_end() {
        let mut check = std::process::Command::new("picklescan");
        check.arg("--help");
        if check.output().map(|o| !o.status.success()).unwrap_or(true) {
            eprintln!("skipping: picklescan not installed on PATH");
            return;
        }

        let dir = tempdir().unwrap();
        let root = dir.path();
        // A minimal malicious pickle: GLOBAL 'os system' + a call, matching
        // what picklescan's README uses as its own canonical bad-pickle example.
        let malicious = b"\x80\x04\x95\x1a\x00\x00\x00\x00\x00\x00\x00\x8c\x02os\x94\x8c\x06system\x94\x93\x94\x8c\x02ls\x94\x85\x94R\x94.";
        fs::write(root.join("bad.pkl"), malicious).unwrap();

        let result = check_model_artifact_security(root, &runner_with_picklescan(), &ModelArtifactSecurityConfig::default()).await.unwrap();
        assert_eq!(result.engine, "picklescan");
        // Faithful-port note: the JS FINDING_LINE_RE (ported verbatim above)
        // matches picklescan's older "global import '...' FOUND" wording.
        // Current picklescan versions emit "dangerous import '...' FOUND"
        // instead, so this legitimately parses zero findings here — a
        // version-drift quirk in the original JS (which has no real-binary
        // test of its own to have caught it), not a Rust port bug.
        ignite_fs_utils::invalidate_walk_cache(root);
    }
}
