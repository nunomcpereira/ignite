//! GitHub Actions workflow security scan via zizmor (Trail of Bits'
//! purpose-built GHA auditor: pwn-request patterns, script injection via
//! untrusted `${{ }}` expansions in `run:` steps, excessive `permissions:`,
//! and more). No JS original — this check post-dates the Node removal.
//!
//! Distinct from `ignite-guidelines`' `no-unpinned-gha-action`: that's a
//! narrow, single-pattern regex check (mutable action ref) exposed only via
//! the dev-time guidelines catalog/MCP tools, not the onboarding gate. This
//! is the actual workflow-security scanner and is wired into the Phase 4
//! gate like the other thirteen external tools — a malicious/vulnerable
//! workflow is exactly the kind of supply-chain risk a compliance
//! gatekeeper exists to catch before a repo is pushed.

use ignite_fs_utils::relative_to_root;
use ignite_tool_runner::{RunToolOptions, ToolRunner};
use serde::Serialize;
use std::path::Path;

pub struct GhaSecurityConfig {
    pub enabled: bool,
}

impl Default for GhaSecurityConfig {
    fn default() -> Self {
        GhaSecurityConfig { enabled: true }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct GhaSecurityFinding {
    pub file: String,
    pub line: usize,
    pub kind: String,
    pub tool: &'static str,
    pub severity: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct GhaSecurityResult {
    pub findings: Vec<GhaSecurityFinding>,
    pub engine: &'static str,
}

pub async fn zizmor_tooling(runner: &ToolRunner) -> bool {
    runner.run_tool("zizmor", &["--version".to_string()], std::env::temp_dir().to_str().unwrap_or("."), RunToolOptions::default()).await.is_ok()
}

fn has_workflow_files(root: &Path) -> bool {
    let dir = root.join(".github").join("workflows");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return false;
    };
    entries.filter_map(|e| e.ok()).any(|e| {
        e.file_type().map(|t| t.is_file()).unwrap_or(false) && matches!(e.path().extension().and_then(|ext| ext.to_str()), Some("yml") | Some("yaml"))
    })
}

/// Recursively hunts a JSON value for the first string field whose key is
/// in `keys` — zizmor's finding-location schema nests the workflow path a
/// few levels deep (`locations[].symbolic.key.Local.verbatim_path`,
/// confirmed against a real zizmor 1.30.0 run) and has changed shape across
/// releases before; walking rather than hardcoding the exact path is a
/// deliberate hedge against future drift, same rationale as the picklescan
/// output-format note in `model-artifact-security`.
fn find_first_str(value: &serde_json::Value, keys: &[&str]) -> Option<String> {
    match value {
        serde_json::Value::Object(map) => {
            for k in keys {
                if let Some(serde_json::Value::String(s)) = map.get(*k) {
                    if !s.is_empty() {
                        return Some(s.clone());
                    }
                }
            }
            map.values().find_map(|v| find_first_str(v, keys))
        }
        serde_json::Value::Array(arr) => arr.iter().find_map(|v| find_first_str(v, keys)),
        _ => None,
    }
}

fn find_first_num(value: &serde_json::Value, keys: &[&str]) -> Option<i64> {
    match value {
        serde_json::Value::Object(map) => {
            for k in keys {
                if let Some(n) = map.get(*k).and_then(|v| v.as_i64()) {
                    return Some(n);
                }
            }
            map.values().find_map(|v| find_first_num(v, keys))
        }
        serde_json::Value::Array(arr) => arr.iter().find_map(|v| find_first_num(v, keys)),
        _ => None,
    }
}

/// Never panics on any malformed/unexpected finding shape — a finding that
/// can't be attributed to a file is dropped rather than reported at a
/// fabricated location.
fn parse_zizmor_output(root: &Path, stdout: &str) -> Vec<GhaSecurityFinding> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return vec![];
    }
    let data: serde_json::Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(_) => return vec![],
    };
    let findings_raw = data.as_array().cloned().unwrap_or_default();

    let mut findings = Vec::new();
    for f in &findings_raw {
        let ident = f.get("ident").and_then(|v| v.as_str()).unwrap_or("gha-security-finding").to_string();
        let desc = f.get("desc").and_then(|v| v.as_str()).unwrap_or("GitHub Actions workflow security finding").to_string();
        let severity_raw = f.get("determinations").and_then(|d| d.get("severity")).and_then(|s| s.as_str()).unwrap_or("");
        let severity: &'static str = match severity_raw.to_lowercase().as_str() {
            "critical" | "high" => "error",
            _ => "warning",
        };

        let locations = f.get("locations").and_then(|l| l.as_array()).cloned().unwrap_or_default();
        let Some(first_loc) = locations.first() else { continue };
        let raw_path = find_first_str(first_loc, &["verbatim_path", "given_path", "path", "tree_path"]);
        let Some(raw_path) = raw_path.filter(|p| !p.is_empty()) else { continue };
        let rel_file = relative_to_root(root, &raw_path).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");

        // zizmor's row/column are 0-indexed (tree-sitter convention).
        let line = find_first_num(first_loc, &["row", "line"]).map(|n| (n + 1).max(1) as usize).unwrap_or(1);
        let feature = first_loc.get("concrete").and_then(|c| c.get("feature")).and_then(|v| v.as_str());
        let message = match feature {
            Some(feature) if !feature.is_empty() => format!("{desc} ({feature})"),
            _ => desc,
        };

        findings.push(GhaSecurityFinding { file: rel_file, line, kind: ident, tool: "zizmor", severity, message });
    }
    findings
}

/// No built-in fallback: reliably catching pwn-request/script-injection
/// patterns needs zizmor's real workflow-expression parser, not a regex
/// approximation — same call as `model-artifact-security`'s picklescan-only
/// design. `ignite-guidelines`' `no-unpinned-gha-action` covers a narrow
/// slice of this heuristically for dev-time use, but that's a different,
/// non-gating code path.
pub async fn check_gha_security(root: &Path, runner: &ToolRunner, config: &GhaSecurityConfig) -> GhaSecurityResult {
    if !config.enabled || !has_workflow_files(root) {
        return GhaSecurityResult { findings: vec![], engine: "disabled" };
    }
    if !zizmor_tooling(runner).await {
        return GhaSecurityResult { findings: vec![], engine: "disabled" };
    }

    let workflows_dir = root.join(".github").join("workflows");
    let output = runner
        .run_tool(
            "zizmor",
            &["--format".to_string(), "json".to_string(), "--no-progress".to_string(), workflows_dir.to_string_lossy().into_owned()],
            &root.to_string_lossy(),
            RunToolOptions { allowed_exit_codes: (0..=20).collect(), ..Default::default() },
        )
        .await;

    match output {
        Ok(output) => GhaSecurityResult { findings: parse_zizmor_output(root, &output.stdout), engine: "zizmor" },
        Err(_) => GhaSecurityResult { findings: vec![], engine: "disabled" },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use tempfile::tempdir;

    fn runner() -> ToolRunner {
        let mut binaries = HashMap::new();
        binaries.insert("zizmor", "zizmor".to_string());
        ToolRunner::new(binaries)
    }

    fn write_workflow(root: &Path) {
        fs::create_dir_all(root.join(".github/workflows")).unwrap();
        fs::write(
            root.join(".github/workflows/ci.yml"),
            "on: pull_request_target\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v3\n",
        )
        .unwrap();
    }

    #[test]
    fn parses_a_finding_with_full_location_shape() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        write_workflow(root);
        let stdout = serde_json::json!([
            {
                "ident": "unpinned-uses",
                "desc": "action is not pinned to a full-length commit SHA",
                "determinations": { "confidence": "High", "severity": "Medium", "persona": "regular" },
                "locations": [
                    {
                        "symbolic": { "key": { "Local": { "verbatim_path": ".github/workflows/ci.yml" } } },
                        "concrete": { "location": { "start_point": { "row": 5, "column": 6 } }, "feature": "actions/checkout@v3" }
                    }
                ]
            }
        ])
        .to_string();

        let findings = parse_zizmor_output(root, &stdout);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file, ".github/workflows/ci.yml");
        assert_eq!(findings[0].line, 6);
        assert_eq!(findings[0].kind, "unpinned-uses");
        assert_eq!(findings[0].severity, "warning");
        assert!(findings[0].message.contains("actions/checkout@v3"));
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn high_severity_maps_to_error() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        write_workflow(root);
        let stdout = serde_json::json!([
            {
                "ident": "dangerous-triggers",
                "desc": "use of a fundamentally insecure workflow trigger",
                "determinations": { "confidence": "High", "severity": "High", "persona": "regular" },
                "locations": [
                    { "symbolic": { "key": { "Local": { "verbatim_path": ".github/workflows/ci.yml" } } }, "concrete": { "location": { "start_point": { "row": 0, "column": 0 } } } }
                ]
            }
        ])
        .to_string();

        let findings = parse_zizmor_output(root, &stdout);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "error");
        assert_eq!(findings[0].line, 1);
    }

    #[test]
    fn empty_stdout_is_no_findings() {
        let dir = tempdir().unwrap();
        assert!(parse_zizmor_output(dir.path(), "").is_empty());
        assert!(parse_zizmor_output(dir.path(), "  \n").is_empty());
    }

    #[test]
    fn malformed_json_is_no_findings_not_a_panic() {
        let dir = tempdir().unwrap();
        assert!(parse_zizmor_output(dir.path(), "not json at all").is_empty());
    }

    #[test]
    fn a_finding_with_no_attributable_location_is_dropped() {
        let dir = tempdir().unwrap();
        let stdout = serde_json::json!([{ "ident": "x", "desc": "y", "determinations": {"severity": "Low"}, "locations": [] }]).to_string();
        assert!(parse_zizmor_output(dir.path(), &stdout).is_empty());
    }

    #[tokio::test]
    async fn disabled_returns_no_findings() {
        let dir = tempdir().unwrap();
        write_workflow(dir.path());
        let config = GhaSecurityConfig { enabled: false };
        let result = check_gha_security(dir.path(), &runner(), &config).await;
        assert_eq!(result.engine, "disabled");
        assert!(result.findings.is_empty());
        ignite_fs_utils::invalidate_walk_cache(dir.path());
    }

    #[tokio::test]
    async fn no_workflow_files_skips_without_running_tool() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("app.js"), b"console.log(1)").unwrap();
        let result = check_gha_security(dir.path(), &runner(), &GhaSecurityConfig::default()).await;
        assert_eq!(result.engine, "disabled");
        assert!(result.findings.is_empty());
        ignite_fs_utils::invalidate_walk_cache(dir.path());
    }

    #[tokio::test]
    async fn real_zizmor_binary_end_to_end() {
        let mut check = std::process::Command::new("zizmor");
        check.arg("--version");
        if check.output().map(|o| !o.status.success()).unwrap_or(true) {
            eprintln!("skipping: zizmor not installed on PATH");
            return;
        }

        let dir = tempdir().unwrap();
        let root = dir.path();
        write_workflow(root);

        let result = check_gha_security(root, &runner(), &GhaSecurityConfig::default()).await;
        assert_eq!(result.engine, "zizmor");
        assert!(!result.findings.is_empty(), "expected zizmor to flag the unpinned actions/checkout@v3 and/or pull_request_target trigger");
        ignite_fs_utils::invalidate_walk_cache(root);
    }
}

