//! Malicious-dependency heuristic scan via GuardDog. Faithful port of
//! `checks/malicious-dependencies.js`. GuardDog verifies every dependency
//! in a manifest against Semgrep-based heuristics for supply-chain-attack
//! patterns (exfiltration in install scripts, obfuscated payloads, silent
//! network calls, typosquatting) — behavioral signals a known-CVE database
//! can't catch, since a freshly-published malicious package has no
//! advisory yet. Only npm (package.json) and PyPI (requirements.txt) are
//! supported.

use ignite_db_store::DbStore;
use ignite_fs_utils::{hash_buffer, walk_files};
use ignite_tool_runner::{RunToolOptions, ToolRunner};
use serde::Serialize;
use std::path::Path;

pub struct GuarddogManifestSpec {
    pub file: &'static str,
    pub ecosystem: &'static str,
}

pub const GUARDDOG_MANIFESTS: &[GuarddogManifestSpec] =
    &[GuarddogManifestSpec { file: "package.json", ecosystem: "npm" }, GuarddogManifestSpec { file: "requirements.txt", ecosystem: "pypi" }];

pub struct MaliciousDependenciesConfig {
    pub enabled: bool,
}

impl Default for MaliciousDependenciesConfig {
    fn default() -> Self {
        MaliciousDependenciesConfig { enabled: true }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MaliciousDependencyFinding {
    pub file: String,
    pub line: Option<usize>,
    pub kind: &'static str,
    pub tool: &'static str,
    pub severity: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MaliciousDependenciesResult {
    pub findings: Vec<MaliciousDependencyFinding>,
    pub engine: &'static str,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct GuarddogVerdict {
    pub pkg_key: String,
    pub hit_rules: Vec<String>,
    pub issue_count: i64,
}

pub struct GuarddogToolingProbe {
    pub ok: bool,
    pub version: Option<String>,
    pub reason: Option<String>,
}

pub async fn guarddog_tooling(runner: &ToolRunner) -> GuarddogToolingProbe {
    match runner.run_tool("guarddog", &["--version".to_string()], std::env::temp_dir().to_str().unwrap_or("."), RunToolOptions::default()).await {
        Ok(out) => {
            let version = out.stdout.trim().to_string();
            GuarddogToolingProbe { ok: true, version: if version.is_empty() { None } else { Some(version) }, reason: None }
        }
        Err(_) => GuarddogToolingProbe { ok: false, version: None, reason: Some("`guarddog` is not installed (pip install guarddog) — malicious-dependency heuristic scanning is skipped.".to_string()) },
    }
}

/// GuardDog's own JSON report keyed by "name==version"/"name@version",
/// each entry carrying a `results` map (rule id -> truthy/falsy) and/or a
/// numeric `issues` count. Tolerant of exactly which shape a given
/// GuardDog version emits: any entry with a positive `issues` count, or
/// any truthy value in `results`, counts as a hit.
pub fn guarddog_verdicts_from_report(report: &serde_json::Value) -> Vec<GuarddogVerdict> {
    let mut verdicts = Vec::new();
    let Some(obj) = report.as_object() else { return verdicts };
    for (pkg_key, entry) in obj {
        let Some(entry) = entry.as_object() else { continue };
        let hit_rules: Vec<String> = entry
            .get("results")
            .and_then(|r| r.as_object())
            .map(|results| {
                results
                    .iter()
                    .filter(|(_, v)| !matches!(v, serde_json::Value::Bool(false) | serde_json::Value::Null))
                    .map(|(rule_id, _)| rule_id.clone())
                    .collect()
            })
            .unwrap_or_default();
        let issue_count = entry.get("issues").and_then(|i| i.as_i64()).unwrap_or(hit_rules.len() as i64);
        if issue_count <= 0 && hit_rules.is_empty() {
            continue;
        }
        verdicts.push(GuarddogVerdict { pkg_key: pkg_key.clone(), hit_rules, issue_count });
    }
    verdicts
}

pub async fn check_malicious_dependencies(root: &Path, runner: &ToolRunner, config: &MaliciousDependenciesConfig, store: Option<&DbStore>) -> std::io::Result<MaliciousDependenciesResult> {
    let tooling = if config.enabled { guarddog_tooling(runner).await } else { GuarddogToolingProbe { ok: false, version: None, reason: None } };
    if !tooling.ok {
        return Ok(MaliciousDependenciesResult { findings: vec![], engine: "disabled" });
    }

    let mut findings = Vec::new();
    for file in walk_files(root)? {
        let base = file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let Some(spec) = GUARDDOG_MANIFESTS.iter().find(|m| m.file == base) else { continue };
        let rel = file.strip_prefix(root).unwrap_or(&file).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");

        let Ok(buffer) = std::fs::read(&file) else { continue };
        let content_hash = hash_buffer(&buffer);

        let cached = tooling.version.as_deref().and_then(|v| store.and_then(|s| s.get_manifest_scan_cache("guarddog", spec.ecosystem, &content_hash, v)));

        let verdicts: Vec<GuarddogVerdict> = if let Some(cached) = cached {
            serde_json::from_value(cached).unwrap_or_default()
        } else {
            let output = match runner
                .run_tool(
                    "guarddog",
                    &[spec.ecosystem.to_string(), "verify".to_string(), file.to_string_lossy().into_owned(), "--output-format".to_string(), "json".to_string()],
                    &root.to_string_lossy(),
                    RunToolOptions { allowed_exit_codes: vec![0, 1], ..Default::default() },
                )
                .await
            {
                Ok(o) => o,
                Err(_) => continue,
            };
            let Ok(report) = serde_json::from_str::<serde_json::Value>(&output.stdout) else { continue };
            let verdicts = guarddog_verdicts_from_report(&report);
            if let (Some(version), Some(store)) = (tooling.version.as_deref(), store) {
                store.save_manifest_scan_cache("guarddog", spec.ecosystem, &content_hash, version, &serde_json::to_value(&verdicts).unwrap());
            }
            verdicts
        };

        for v in &verdicts {
            let rule_desc = if !v.hit_rules.is_empty() { v.hit_rules.join(", ") } else { format!("{} issue(s)", v.issue_count) };
            findings.push(MaliciousDependencyFinding {
                file: rel.clone(),
                line: None,
                kind: "malicious-dependency",
                tool: "guarddog",
                severity: "error",
                message: format!(r#"Dependency "{}" flagged by GuardDog ({}): {}."#, v.pkg_key, spec.ecosystem, rule_desc),
            });
        }
    }

    Ok(MaliciousDependenciesResult { findings, engine: "guarddog" })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use tempfile::tempdir;

    fn runner_with_guarddog() -> ToolRunner {
        let mut binaries = HashMap::new();
        binaries.insert("guarddog", "guarddog".to_string());
        ToolRunner::new(binaries)
    }

    #[test]
    fn verdicts_from_report_handles_results_map_shape() {
        let report = serde_json::json!({
            "lodash==4.17.21": {"results": {"npm-install-script": true, "npm-silent-process-execution": false}},
            "left-pad==1.0.0": {"results": {}},
        });
        let verdicts = guarddog_verdicts_from_report(&report);
        assert_eq!(verdicts.len(), 1);
        assert_eq!(verdicts[0].pkg_key, "lodash==4.17.21");
        assert_eq!(verdicts[0].hit_rules, vec!["npm-install-script".to_string()]);
    }

    #[test]
    fn verdicts_from_report_handles_numeric_issues_shape() {
        let report = serde_json::json!({
            "malicious-pkg==1.0.0": {"issues": 2, "results": {}},
            "clean-pkg==1.0.0": {"issues": 0},
        });
        let verdicts = guarddog_verdicts_from_report(&report);
        assert_eq!(verdicts.len(), 1);
        assert_eq!(verdicts[0].pkg_key, "malicious-pkg==1.0.0");
        assert_eq!(verdicts[0].issue_count, 2);
    }

    #[tokio::test]
    async fn disabled_returns_no_findings() {
        let dir = tempdir().unwrap();
        let config = MaliciousDependenciesConfig { enabled: false };
        let result = check_malicious_dependencies(dir.path(), &ToolRunner::new(HashMap::new()), &config, None).await.unwrap();
        assert_eq!(result.engine, "disabled");
        assert!(result.findings.is_empty());
    }

    #[test]
    fn cache_roundtrips_verdicts_through_db_store() {
        let dir = tempdir().unwrap();
        let store = DbStore::open(&dir.path().join("test.db")).unwrap();
        let verdicts = vec![GuarddogVerdict { pkg_key: "x==1.0.0".to_string(), hit_rules: vec!["npm-install-script".to_string()], issue_count: 1 }];
        store.save_manifest_scan_cache("guarddog", "npm", "abc123", "0.1.0", &serde_json::to_value(&verdicts).unwrap());
        let cached = store.get_manifest_scan_cache("guarddog", "npm", "abc123", "0.1.0").unwrap();
        let roundtripped: Vec<GuarddogVerdict> = serde_json::from_value(cached).unwrap();
        assert_eq!(roundtripped.len(), 1);
        assert_eq!(roundtripped[0].pkg_key, "x==1.0.0");
    }

    #[tokio::test]
    async fn real_guarddog_binary_end_to_end() {
        let mut check = std::process::Command::new("guarddog");
        check.arg("--version");
        if check.output().map(|o| !o.status.success()).unwrap_or(true) {
            eprintln!("skipping: guarddog not installed on PATH");
            return;
        }

        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("package.json"), r#"{"dependencies": {"left-pad": "1.3.0"}}"#).unwrap();

        let config = MaliciousDependenciesConfig { enabled: true };
        let result = check_malicious_dependencies(root, &runner_with_guarddog(), &config, None).await.unwrap();
        assert_eq!(result.engine, "guarddog");
        ignite_fs_utils::invalidate_walk_cache(root);
    }
}
