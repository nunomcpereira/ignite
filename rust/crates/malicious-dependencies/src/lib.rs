//! Malicious-dependency heuristic scan via GuardDog. Faithful port of
//! `checks/malicious-dependencies.js`. GuardDog verifies every dependency
//! in a manifest against Semgrep-based heuristics for supply-chain-attack
//! patterns (exfiltration in install scripts, obfuscated payloads, silent
//! network calls, typosquatting) — behavioral signals a known-CVE database
//! can't catch, since a freshly-published malicious package has no
//! advisory yet. Only npm (package.json) and PyPI (requirements.txt) are
//! supported.
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

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
    /// GuardDog 3's own verdict (`risk_score.label`: `no_risks_detected`,
    /// `low`, `suspicious`, `high_risk`) and score (0-10). `None` from
    /// older GuardDog releases, which only report raw rule hits.
    #[serde(default)]
    pub risk_label: Option<String>,
    #[serde(default)]
    pub risk_score: Option<f64>,
}

impl GuarddogVerdict {
    /// Finding severity for this verdict, or `None` when it isn't one.
    /// GuardDog 3 reports `capability-*` hits (what a package *can* do:
    /// network, spawn, filesystem) for nearly every real package — react,
    /// docusaurus — and scores them with threats into a risk label; that
    /// label is the verdict, not the raw hits. Without a label (GuardDog
    /// 1.x/2.x), every hit stays blocking, as before.
    pub fn severity(&self) -> Option<&'static str> {
        match self.risk_label.as_deref() {
            None => Some("error"),
            Some("high_risk") => Some("error"),
            Some("suspicious") => Some("warning"),
            Some(_) => None,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GuarddogToolingProbe {
    pub ok: bool,
    pub version: Option<String>,
    pub reason: Option<String>,
}

/// `guarddog --version` is a plain Python startup (well under a second when
/// healthy), so a probe that takes longer than this means guarddog is
/// broken in this environment, not slow — and every scan waits on it.
pub const GUARDDOG_PROBE_TIMEOUT_MS: u64 = 20_000;
/// Per-manifest cap on `guarddog <eco> verify`. It downloads and scans
/// every listed package, so without registry egress (a locked-down k8s
/// node) it hangs until killed.
pub const GUARDDOG_VERIFY_TIMEOUT_MS: u64 = 90_000;
/// Cap on the whole check across every manifest in the project.
pub const GUARDDOG_TOTAL_BUDGET_MS: u64 = 240_000;

pub async fn guarddog_tooling(runner: &ToolRunner) -> GuarddogToolingProbe {
    let opts = RunToolOptions { timeout_ms: Some(GUARDDOG_PROBE_TIMEOUT_MS), ..Default::default() };
    match runner.run_tool("guarddog", &["--version".to_string()], std::env::temp_dir().to_str().unwrap_or("."), opts).await {
        Ok(out) => {
            let version = out.stdout.trim().to_string();
            GuarddogToolingProbe { ok: true, version: if version.is_empty() { None } else { Some(version) }, reason: None }
        }
        Err(e) => GuarddogToolingProbe { ok: false, version: None, reason: Some(probe_failure_reason(&e)) },
    }
}

/// Says why the probe failed instead of always claiming "not installed":
/// a binary that is present but crashes (unwritable cache dir, broken
/// native extension) or hangs needs a different fix than a missing one.
fn probe_failure_reason(e: &ignite_tool_runner::ToolError) -> String {
    let text = e.to_string();
    let lower = text.to_lowercase();
    let what = if lower.contains("no such file") || lower.contains("not found") || matches!(e, ignite_tool_runner::ToolError::Unsupported(_)) {
        "`guarddog` is not installed (pip install guarddog)".to_string()
    } else if lower.contains("timed out") {
        format!("`guarddog --version` did not answer within {}s", GUARDDOG_PROBE_TIMEOUT_MS / 1000)
    } else {
        let tail: String = text.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or(&text).chars().take(300).collect();
        format!("`guarddog --version` failed: {tail}")
    };
    format!("{what} — malicious-dependency heuristic scanning is skipped.")
}

/// GuardDog's JSON report. GuardDog 3.x prints an array of
/// `{"dependency", "version", "result": {"issues", "results"}}` entries;
/// older releases printed an object keyed by "name==version"/"name@version"
/// whose values carry the same `issues`/`results` fields. Both are read.
/// Any entry with a positive `issues` count, or any non-empty value in
/// `results` (rule id -> message/details; null/false/empty = no hit),
/// counts as a hit.
pub fn guarddog_verdicts_from_report(report: &serde_json::Value) -> Vec<GuarddogVerdict> {
    let entries: Vec<(String, &serde_json::Map<String, serde_json::Value>)> = match report {
        serde_json::Value::Array(items) => items
            .iter()
            .filter_map(|item| {
                let item = item.as_object()?;
                let name = item.get("dependency").and_then(|d| d.as_str())?;
                let key = match item.get("version").and_then(|v| v.as_str()) {
                    Some(v) if !v.is_empty() => format!("{name}=={v}"),
                    _ => name.to_string(),
                };
                Some((key, item.get("result")?.as_object()?))
            })
            .collect(),
        serde_json::Value::Object(obj) => obj.iter().filter_map(|(k, v)| Some((k.clone(), v.as_object()?))).collect(),
        _ => Vec::new(),
    };
    let is_hit = |v: &serde_json::Value| match v {
        serde_json::Value::Null | serde_json::Value::Bool(false) => false,
        serde_json::Value::String(s) => !s.is_empty(),
        serde_json::Value::Array(a) => !a.is_empty(),
        serde_json::Value::Object(o) => !o.is_empty(),
        _ => true,
    };
    let mut verdicts = Vec::new();
    for (pkg_key, entry) in entries {
        let hit_rules: Vec<String> = entry
            .get("results")
            .and_then(|r| r.as_object())
            .map(|results| results.iter().filter(|(_, v)| is_hit(v)).map(|(rule_id, _)| rule_id.clone()).collect())
            .unwrap_or_default();
        let issue_count = entry.get("issues").and_then(|i| i.as_i64()).unwrap_or(hit_rules.len() as i64);
        if issue_count <= 0 && hit_rules.is_empty() {
            continue;
        }
        let risk = entry.get("risk_score").and_then(|r| r.as_object());
        let risk_label = risk.and_then(|r| r.get("label")).and_then(|l| l.as_str()).map(str::to_string);
        let risk_score = risk.and_then(|r| r.get("score")).and_then(|s| s.as_f64());
        verdicts.push(GuarddogVerdict { pkg_key, hit_rules, issue_count, risk_label, risk_score });
    }
    verdicts
}

pub async fn check_malicious_dependencies(root: &Path, runner: &ToolRunner, config: &MaliciousDependenciesConfig, store: Option<&DbStore>) -> std::io::Result<MaliciousDependenciesResult> {
    let tooling = if config.enabled { guarddog_tooling(runner).await } else { GuarddogToolingProbe { ok: false, version: None, reason: None } };
    if !tooling.ok {
        return Ok(MaliciousDependenciesResult { findings: vec![], engine: "disabled" });
    }

    let mut findings = Vec::new();
    let started = std::time::Instant::now();
    // Suffix bumps whenever report parsing changes, so verdicts cached by
    // an older parser (e.g. the one that read GuardDog 3's array output as
    // "no hits") are not reused.
    let cache_version = tooling.version.as_deref().map(|v| format!("{v}+parse3"));
    let (mut verified, mut timed_out) = (0usize, 0usize);
    for file in walk_files(root)? {
        let base = file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let Some(spec) = GUARDDOG_MANIFESTS.iter().find(|m| m.file == base) else { continue };
        let rel = file.strip_prefix(root).unwrap_or(&file).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");

        let Ok(buffer) = std::fs::read(&file) else { continue };
        let content_hash = hash_buffer(&buffer);

        let cached = cache_version.as_deref().and_then(|v| store.and_then(|s| s.get_manifest_scan_cache("guarddog", spec.ecosystem, &content_hash, v)));

        let verdicts: Vec<GuarddogVerdict> = if let Some(cached) = cached {
            verified += 1;
            serde_json::from_value(cached).unwrap_or_default()
        } else {
            // Out of budget, or a previous manifest already timed out (no
            // registry access): don't make the scan wait on the rest.
            let remaining_ms = GUARDDOG_TOTAL_BUDGET_MS.saturating_sub(started.elapsed().as_millis() as u64);
            if timed_out > 0 || remaining_ms < 1_000 {
                timed_out += 1;
                continue;
            }
            let output = match runner
                .run_tool(
                    "guarddog",
                    &[spec.ecosystem.to_string(), "verify".to_string(), file.to_string_lossy().into_owned(), "--output-format".to_string(), "json".to_string()],
                    &root.to_string_lossy(),
                    RunToolOptions { allowed_exit_codes: vec![0, 1], timeout_ms: Some(GUARDDOG_VERIFY_TIMEOUT_MS.min(remaining_ms)), ..Default::default() },
                )
                .await
            {
                Ok(o) => o,
                Err(e) => {
                    if e.to_string().contains("timed out") {
                        timed_out += 1;
                    }
                    continue;
                }
            };
            let Ok(report) = serde_json::from_str::<serde_json::Value>(&output.stdout) else { continue };
            let verdicts = guarddog_verdicts_from_report(&report);
            verified += 1;
            if let (Some(version), Some(store)) = (cache_version.as_deref(), store) {
                if let Ok(cached) = serde_json::to_value(&verdicts) {
                    store.save_manifest_scan_cache("guarddog", spec.ecosystem, &content_hash, version, &cached);
                }
            }
            verdicts
        };

        for v in &verdicts {
            let Some(severity) = v.severity() else { continue };
            let rule_desc = if !v.hit_rules.is_empty() { v.hit_rules.join(", ") } else { format!("{} issue(s)", v.issue_count) };
            let risk_desc = match (&v.risk_label, v.risk_score) {
                (Some(label), Some(score)) => format!(" [risk {label}, {score:.1}/10]"),
                (Some(label), None) => format!(" [risk {label}]"),
                _ => String::new(),
            };
            findings.push(MaliciousDependencyFinding {
                file: rel.clone(),
                line: None,
                kind: "malicious-dependency",
                tool: "guarddog",
                severity,
                message: format!(r#"Dependency "{}" flagged by GuardDog ({}): {}{risk_desc}."#, v.pkg_key, spec.ecosystem, rule_desc),
            });
        }
    }

    // Nothing verified and something timed out: report it as timed out
    // rather than a clean guarddog pass.
    let engine = if verified == 0 && timed_out > 0 { "timed_out" } else { "guarddog" };
    Ok(MaliciousDependenciesResult { findings, engine })
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
    fn verdicts_from_report_handles_guarddog_3_array_shape() {
        let report = serde_json::json!([
            {"dependency": "left-pad", "version": "1.3.0", "result": {"issues": 0, "errors": {}, "results": {"typosquatting": null, "npm-install-script": null}}},
            {"dependency": "evil-pkg", "version": "0.0.1", "result": {"issues": 1, "errors": {}, "results": {"npm-install-script": "postinstall runs curl | sh", "typosquatting": null}}},
        ]);
        let verdicts = guarddog_verdicts_from_report(&report);
        assert_eq!(verdicts.len(), 1);
        assert_eq!(verdicts[0].pkg_key, "evil-pkg==0.0.1");
        assert_eq!(verdicts[0].hit_rules, vec!["npm-install-script".to_string()]);
        assert_eq!(verdicts[0].issue_count, 1);
    }

    #[test]
    fn guarddog_3_risk_label_decides_severity() {
        let entry = |dep: &str, label: &str, score: f64| serde_json::json!({"dependency": dep, "version": "1.0.0", "result": {"issues": 2, "results": {"capability-network-outbound": [{"location": "a.js:1"}]}, "risk_score": {"score": score, "label": label}}});
        let report = serde_json::json!([
            entry("react", "no_risks_detected", 0.0),
            entry("@docusaurus/core", "low", 3.3),
            entry("odd-pkg", "suspicious", 5.5),
            entry("evil-pkg", "high_risk", 8.7),
        ]);
        let severities: Vec<(String, Option<&str>)> = guarddog_verdicts_from_report(&report).iter().map(|v| (v.pkg_key.clone(), v.severity())).collect();
        assert_eq!(
            severities,
            vec![
                ("react==1.0.0".to_string(), None),
                ("@docusaurus/core==1.0.0".to_string(), None),
                ("odd-pkg==1.0.0".to_string(), Some("warning")),
                ("evil-pkg==1.0.0".to_string(), Some("error")),
            ]
        );
        // Old GuardDog: no label, every hit blocks.
        let old = guarddog_verdicts_from_report(&serde_json::json!({"x==1": {"results": {"npm-install-script": true}}}));
        assert_eq!(old[0].severity(), Some("error"));
        // Verdicts cached before the label existed still deserialize.
        let cached: GuarddogVerdict = serde_json::from_value(serde_json::json!({"pkg_key": "y==1", "hit_rules": [], "issue_count": 1})).unwrap();
        assert_eq!(cached.risk_label, None);
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

    fn runner_with_script(dir: &Path, body: &str) -> ToolRunner {
        use std::os::unix::fs::PermissionsExt;
        let script = dir.join("fake-guarddog");
        fs::write(&script, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let mut binaries = HashMap::new();
        binaries.insert("guarddog", script.to_string_lossy().into_owned());
        ToolRunner::new(binaries)
    }

    #[tokio::test]
    async fn probe_reports_missing_binary_as_not_installed() {
        let mut binaries = HashMap::new();
        binaries.insert("guarddog", "/nonexistent/guarddog".to_string());
        let probe = guarddog_tooling(&ToolRunner::new(binaries)).await;
        assert!(!probe.ok);
        assert!(probe.reason.unwrap().contains("not installed"));
    }

    #[tokio::test]
    async fn probe_reports_a_crashing_binary_with_its_error() {
        let dir = tempdir().unwrap();
        let runner = runner_with_script(dir.path(), "echo 'PermissionError: cache dir is read-only' >&2; exit 1");
        let probe = guarddog_tooling(&runner).await;
        assert!(!probe.ok);
        let reason = probe.reason.unwrap();
        assert!(reason.contains("PermissionError: cache dir is read-only"), "{reason}");
        assert!(!reason.contains("not installed"), "{reason}");
    }

    #[tokio::test]
    async fn unavailable_guarddog_skips_without_running_verify() {
        let dir = tempdir().unwrap();
        let project = dir.path().join("p");
        fs::create_dir(&project).unwrap();
        fs::write(project.join("package.json"), r#"{"dependencies": {"left-pad": "1.3.0"}}"#).unwrap();
        let runner = runner_with_script(dir.path(), "exit 1");
        let result = check_malicious_dependencies(&project, &runner, &MaliciousDependenciesConfig { enabled: true }, None).await.unwrap();
        assert_eq!(result.engine, "disabled");
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
        let verdicts = vec![GuarddogVerdict { pkg_key: "x==1.0.0".to_string(), hit_rules: vec!["npm-install-script".to_string()], issue_count: 1, risk_label: None, risk_score: None }];
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
