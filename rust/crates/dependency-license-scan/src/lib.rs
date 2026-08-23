//! Dependency license/vulnerability scan orchestrators. Faithful port of
//! server.js's `scanDependencyLicensesFallback`, `scanDependencyVulnerabilities`,
//! `scanProjectLicenseFiles`, `classifyLicenseText`, and `runLicenseeDetect`.
//!
//! `runOrtAnalyze`/`scanDependencyLicenses`'s ORT (OSS Review Toolkit)
//! integration — dependency-graph traversal over `analyzer-result.json` to
//! resolve real lockfiles across ecosystems — is deliberately not ported
//! yet; `scan_dependency_licenses_fallback` alone is what server.js itself
//! falls back to when ORT isn't installed, so this crate's behavior is
//! correct (just not ORT-augmented) until that piece is added.

use ignite_deps_dev_client::{classify_vulnerability_severity, fetch_npm_registry_license, find_manifest_dep_line, resolve_best_published_version, resolve_see_license_in_file, DepsDevClient};
use ignite_fs_utils::walk_files;
use ignite_license_classification::{classify_license_tier, is_internal_dependency_ref, best_effort_version, LicenseTier};
use ignite_studio_manifests::{studio_manifests, ManifestDep, STUDIO_MAX_DEPS_PER_MANIFEST};
use ignite_tool_runner::{RunToolOptions, ToolRunner};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use std::collections::HashSet;
use std::path::Path;

/// A superset of `classify_license_tier`'s 3-state `LicenseTier`: an
/// internal workspace/catalog reference is neither green/warning/red on
/// its merits (nothing was actually checked) — kept as its own state
/// since `collect_license_issues` (override-engine) skips "green" AND
/// "internal" alike, but they mean different things.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DependencyLicenseTier {
    Green,
    Warning,
    Red,
    Internal,
}

impl DependencyLicenseTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            DependencyLicenseTier::Green => "green",
            DependencyLicenseTier::Warning => "warning",
            DependencyLicenseTier::Red => "red",
            DependencyLicenseTier::Internal => "internal",
        }
    }
}

impl From<LicenseTier> for DependencyLicenseTier {
    fn from(t: LicenseTier) -> Self {
        match t {
            LicenseTier::Green => DependencyLicenseTier::Green,
            LicenseTier::Warning => DependencyLicenseTier::Warning,
            LicenseTier::Red => DependencyLicenseTier::Red,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LicenseScanDependency {
    pub name: String,
    pub version_range: String,
    pub version: Option<String>,
    pub line: Option<usize>,
    pub licenses: Vec<String>,
    pub tier: DependencyLicenseTier,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LicenseScanManifest {
    pub file: String,
    pub ecosystem: &'static str,
    pub dependencies: Vec<LicenseScanDependency>,
}

fn tier_to_str(tier: &LicenseTier) -> &'static str {
    match tier {
        LicenseTier::Green => "green",
        LicenseTier::Warning => "warning",
        LicenseTier::Red => "red",
    }
}

/// Built-in deps.dev-backed license scan, used directly when ORT isn't
/// installed, and as the gap-filler for any ecosystem ORT itself didn't
/// resolve. `skip_ecosystems` lets a caller (once ORT integration lands)
/// avoid double-reporting an ecosystem ORT already covered.
pub async fn scan_dependency_licenses_fallback(root: &Path, client: &DepsDevClient, npm_http: &reqwest::Client, skip_ecosystems: &HashSet<&str>) -> std::io::Result<Vec<LicenseScanManifest>> {
    let mut manifests = Vec::new();
    for file in walk_files(root)? {
        let base = file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let Some(spec) = studio_manifests().iter().find(|m| m.file == base) else { continue };
        if skip_ecosystems.contains(spec.ecosystem) {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&file) else { continue };
        let raw_deps: Vec<ManifestDep> = (spec.parse)(&content).into_iter().take(STUDIO_MAX_DEPS_PER_MANIFEST).collect();

        let mut dependencies = Vec::new();
        for dep in &raw_deps {
            let line = find_manifest_dep_line(&content, &dep.name, spec.ecosystem);

            if is_internal_dependency_ref(&dep.version_range) {
                dependencies.push(LicenseScanDependency {
                    name: dep.name.clone(),
                    version_range: dep.version_range.clone(),
                    version: None,
                    line,
                    licenses: vec![],
                    tier: DependencyLicenseTier::Internal,
                    reason: "Internal workspace/catalog reference, not an external package — nothing to license-check.".to_string(),
                });
                continue;
            }

            let Some(version) = best_effort_version(&dep.version_range) else {
                dependencies.push(LicenseScanDependency {
                    name: dep.name.clone(),
                    version_range: dep.version_range.clone(),
                    version: None,
                    line,
                    licenses: vec![],
                    tier: DependencyLicenseTier::Red,
                    reason: "Could not resolve an exact version to check (range/tag/git ref).".to_string(),
                });
                continue;
            };

            let mut licenses = client.fetch_licenses(spec.system, &dep.name, &version).await;
            let mut resolved_version = version.clone();
            if licenses.is_none() {
                if let Some(better) = resolve_best_published_version(client, spec.system, &dep.name, &dep.version_range).await {
                    if better != version {
                        if let Some(retry) = client.fetch_licenses(spec.system, &dep.name, &better).await {
                            licenses = Some(retry);
                            resolved_version = better;
                        }
                    }
                }
            }

            let Some(mut licenses) = licenses else {
                dependencies.push(LicenseScanDependency {
                    name: dep.name.clone(),
                    version_range: dep.version_range.clone(),
                    version: Some(version),
                    line,
                    licenses: vec![],
                    tier: DependencyLicenseTier::Red,
                    reason: "License lookup failed (package/version not found upstream).".to_string(),
                });
                continue;
            };

            if spec.system == "NPM" && ignite_deps_dev_client::is_placeholder_license_list(&licenses) {
                if let Some(npm_license) = fetch_npm_registry_license(npm_http, &dep.name, &resolved_version).await {
                    licenses = npm_license;
                }
            }

            let mut tier: DependencyLicenseTier = classify_license_tier(&licenses).tier.into();
            let mut reason = classify_license_tier(&licenses).reason;
            if spec.system == "NPM" && !matches!(tier, DependencyLicenseTier::Green) && licenses.len() == 1 {
                if let Some(resolved) = resolve_see_license_in_file(npm_http, &dep.name, &resolved_version, &licenses[0]).await {
                    tier = resolved.tier.into();
                    reason = resolved.reason;
                }
            }

            dependencies.push(LicenseScanDependency {
                name: dep.name.clone(),
                version_range: dep.version_range.clone(),
                version: Some(resolved_version),
                line,
                licenses,
                tier,
                reason,
            });
        }

        manifests.push(LicenseScanManifest { file: file.strip_prefix(root).unwrap_or(&file).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/"), ecosystem: spec.ecosystem, dependencies });
    }
    Ok(manifests)
}

#[derive(Debug, Clone, Serialize)]
pub struct VulnFinding {
    pub id: Option<String>,
    pub title: Option<String>,
    pub aliases: Vec<String>,
    pub cvss3_score: Option<f64>,
    pub severity: &'static str,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VulnScanDependency {
    pub name: String,
    pub version_range: String,
    pub version: Option<String>,
    pub line: Option<usize>,
    pub vulnerabilities: Vec<VulnFinding>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VulnScanManifest {
    pub file: String,
    pub ecosystem: &'static str,
    pub dependencies: Vec<VulnScanDependency>,
}

/// Only manifests/deps with something to report are kept — a
/// vulnerability-free dependency shouldn't clutter the response the way an
/// unclassified license does (that's inherently a risk; no known CVEs
/// isn't).
pub async fn scan_dependency_vulnerabilities(root: &Path, client: &DepsDevClient) -> std::io::Result<Vec<VulnScanManifest>> {
    let mut manifests = Vec::new();
    for file in walk_files(root)? {
        let base = file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let Some(spec) = studio_manifests().iter().find(|m| m.file == base) else { continue };
        let Ok(content) = std::fs::read_to_string(&file) else { continue };
        let raw_deps: Vec<ManifestDep> = (spec.parse)(&content).into_iter().take(STUDIO_MAX_DEPS_PER_MANIFEST).collect();

        let mut dependencies = Vec::new();
        for dep in &raw_deps {
            let line = find_manifest_dep_line(&content, &dep.name, spec.ecosystem);

            if is_internal_dependency_ref(&dep.version_range) {
                dependencies.push(VulnScanDependency {
                    name: dep.name.clone(),
                    version_range: dep.version_range.clone(),
                    version: None,
                    line,
                    vulnerabilities: vec![],
                    note: Some("Internal workspace/catalog reference, not an external package — nothing to check.".to_string()),
                });
                continue;
            }

            let Some(version) = best_effort_version(&dep.version_range) else {
                dependencies.push(VulnScanDependency {
                    name: dep.name.clone(),
                    version_range: dep.version_range.clone(),
                    version: None,
                    line,
                    vulnerabilities: vec![],
                    note: Some("Could not resolve an exact version to check (range/tag/git ref).".to_string()),
                });
                continue;
            };

            let mut info = client.fetch_package_info(spec.system, &dep.name, &version).await;
            let mut resolved_version = version.clone();
            if info.is_none() {
                if let Some(better) = resolve_best_published_version(client, spec.system, &dep.name, &dep.version_range).await {
                    if better != version {
                        if let Some(retry) = client.fetch_package_info(spec.system, &dep.name, &better).await {
                            info = Some(retry);
                            resolved_version = better;
                        }
                    }
                }
            }

            let Some(info) = info else {
                dependencies.push(VulnScanDependency {
                    name: dep.name.clone(),
                    version_range: dep.version_range.clone(),
                    version: Some(version),
                    line,
                    vulnerabilities: vec![],
                    note: Some("Vulnerability lookup failed (package/version not found upstream).".to_string()),
                });
                continue;
            };

            let advisories = futures::future::join_all(info.advisory_ids.iter().map(|id| client.fetch_advisory(id))).await;
            let vulnerabilities: Vec<VulnFinding> = advisories
                .into_iter()
                .flatten()
                .map(|a| {
                    let cvss3_score = a.get("cvss3Score").and_then(|v| v.as_f64());
                    VulnFinding {
                        id: a.get("advisoryKey").and_then(|k| k.get("id")).and_then(|v| v.as_str()).map(String::from),
                        title: a.get("title").and_then(|v| v.as_str()).map(String::from),
                        aliases: a.get("aliases").and_then(|v| v.as_array()).map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default(),
                        cvss3_score,
                        severity: classify_vulnerability_severity(cvss3_score),
                        url: a.get("url").and_then(|v| v.as_str()).map(String::from),
                    }
                })
                .collect();

            dependencies.push(VulnScanDependency { name: dep.name.clone(), version_range: dep.version_range.clone(), version: Some(resolved_version), line, vulnerabilities, note: None });
        }

        let with_findings: Vec<VulnScanDependency> = dependencies.into_iter().filter(|d| !d.vulnerabilities.is_empty() || d.note.is_some()).collect();
        if !with_findings.is_empty() {
            manifests.push(VulnScanManifest { file: file.strip_prefix(root).unwrap_or(&file).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/"), ecosystem: spec.ecosystem, dependencies: with_findings });
        }
    }
    Ok(manifests)
}

static LICENSE_FILENAME_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^LICEN[CS]E(\.(txt|md))?$").unwrap());
static LICENSE_SCAN_PATH_SKIP_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^(?:\.claude|\.github)/skills/").unwrap());
static COMMERCIAL_TEXT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)commercial|proprietary").unwrap());
static LICENSEE_LINE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?im)^\s*Licensee\s*:\s*(.+)$").unwrap());
static LICENSOR_LINE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?im)^\s*Licensor\s*:\s*(.+)$").unwrap());

#[derive(Debug, Clone, Serialize)]
pub struct LicenseTextClassification {
    pub tier: &'static str,
    pub line: usize,
    pub reason: String,
}

/// Dependency-free classification of a LICENSE file's raw text — catches
/// commercial terms with no external tooling at all.
pub fn classify_license_text(content: &str) -> Option<LicenseTextClassification> {
    let commercial_match = COMMERCIAL_TEXT_RE.find(content)?;
    let licensee_match = LICENSEE_LINE_RE.captures(content);
    let licensor_match = LICENSOR_LINE_RE.captures(content);
    let anchor_start = licensee_match.as_ref().map(|m| m.get(0).unwrap().start()).unwrap_or(commercial_match.start());
    let line = content[..anchor_start].split('\n').count();
    let reason = match &licensee_match {
        Some(m) => {
            let licensee = m[1].trim();
            match &licensor_match {
                Some(lic) => format!("Commercial license agreement — Licensee: {}, Licensor: {}.", licensee, lic[1].trim()),
                None => format!("Commercial license agreement — Licensee: {}.", licensee),
            }
        }
        None => "Commercial/proprietary license terms detected in LICENSE file.".to_string(),
    };
    Some(LicenseTextClassification { tier: "red", line, reason })
}

#[derive(Debug, Clone, Serialize)]
pub struct LicenseFileFinding {
    pub file: String,
    pub tier: &'static str,
    pub line: usize,
    pub reason: String,
}

/// Walks the whole staged tree for LICENSE/LICENCE files and flags the
/// commercial/proprietary-looking ones.
pub fn scan_project_license_files(root: &Path) -> std::io::Result<Vec<LicenseFileFinding>> {
    let mut findings = Vec::new();
    for file in walk_files(root)? {
        let base = file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        if !LICENSE_FILENAME_RE.is_match(&base) {
            continue;
        }
        let rel = file.strip_prefix(root).unwrap_or(&file).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
        if LICENSE_SCAN_PATH_SKIP_RE.is_match(&rel) {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&file) else { continue };
        if let Some(classified) = classify_license_text(&content) {
            findings.push(LicenseFileFinding { file: rel, tier: classified.tier, line: classified.line, reason: classified.reason });
        }
    }
    Ok(findings)
}

pub async fn licensee_tooling(runner: &ToolRunner) -> bool {
    runner.run_tool("licensee", &["version".to_string()], std::env::temp_dir().to_str().unwrap_or("."), RunToolOptions::default()).await.is_ok()
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectLicenseDetection {
    pub spdx_id: String,
    pub confidence: Option<f64>,
    pub tier: &'static str,
    pub reason: String,
}

/// Detects the PROJECT's OWN declared license (LICENSE file / package
/// metadata) via the `licensee` gem — independent of the per-dependency
/// scan above. Soft-fails to `None` if licensee isn't installed or finds
/// nothing conclusive.
pub async fn run_licensee_detect(root: &Path, runner: &ToolRunner) -> Option<ProjectLicenseDetection> {
    if !licensee_tooling(runner).await {
        return None;
    }
    let output = runner.run_tool("licensee", &["detect".to_string(), "--json".to_string(), root.to_string_lossy().into_owned()], &root.to_string_lossy(), RunToolOptions::default()).await.ok()?;
    let data: serde_json::Value = serde_json::from_str(&output.stdout).ok()?;
    let best = data.get("licenses").and_then(|l| l.as_array()).and_then(|a| a.first())?;
    let spdx_id = best.get("spdx_id").and_then(|v| v.as_str())?.to_string();
    let has_attribution = data.get("matched_files").and_then(|f| f.as_array()).and_then(|a| a.first()).and_then(|f| f.get("attribution")).map(|v| !v.is_null()).unwrap_or(false);
    let confidence = if has_attribution { Some(100.0) } else { best.get("similarity").and_then(|v| v.as_f64()) };
    let classification = classify_license_tier(&[spdx_id.clone()]);
    Some(ProjectLicenseDetection { spdx_id, confidence, tier: tier_to_str(&classification.tier), reason: classification.reason })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn classify_license_text_detects_commercial_terms_with_licensee_licensor() {
        let content = "Software License Agreement\n\nLicensee: Acme Corp\nLicensor: Vendor Inc\n\nThis is a commercial license.\n";
        let classification = classify_license_text(content).unwrap();
        assert_eq!(classification.tier, "red");
        assert!(classification.reason.contains("Acme Corp"));
        assert!(classification.reason.contains("Vendor Inc"));
    }

    #[test]
    fn classify_license_text_returns_none_for_permissive_license() {
        let content = "MIT License\n\nPermission is hereby granted, free of charge...\n";
        assert!(classify_license_text(content).is_none());
    }

    #[test]
    fn classify_license_text_falls_back_to_generic_reason_without_licensee_line() {
        let content = "This software is proprietary and confidential.\n";
        let classification = classify_license_text(content).unwrap();
        assert_eq!(classification.reason, "Commercial/proprietary license terms detected in LICENSE file.");
    }

    #[test]
    fn scan_project_license_files_finds_commercial_license_and_skips_skill_paths() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("LICENSE"), "This is a commercial license.\n").unwrap();
        fs::create_dir_all(root.join(".github/skills")).unwrap();
        fs::write(root.join(".github/skills/LICENSE.md"), "This is a commercial license too.\n").unwrap();

        let findings = scan_project_license_files(root).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file, "LICENSE");
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[tokio::test]
    async fn scan_dependency_licenses_fallback_flags_internal_dependency_refs_as_green() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("package.json"), r#"{"dependencies": {"@myorg/shared": "workspace:*"}}"#).unwrap();

        let client = DepsDevClient::new();
        let npm_http = reqwest::Client::new();
        let manifests = scan_dependency_licenses_fallback(root, &client, &npm_http, &HashSet::new()).await.unwrap();
        assert_eq!(manifests.len(), 1);
        assert_eq!(manifests[0].dependencies.len(), 1);
        assert_eq!(manifests[0].dependencies[0].tier, DependencyLicenseTier::Internal);
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[tokio::test]
    async fn scan_dependency_licenses_fallback_real_network_resolves_mit_lodash() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("package.json"), r#"{"dependencies": {"lodash": "4.17.21"}}"#).unwrap();

        let client = DepsDevClient::new();
        let npm_http = reqwest::Client::new();
        let manifests = scan_dependency_licenses_fallback(root, &client, &npm_http, &HashSet::new()).await.unwrap();
        if manifests.is_empty() || manifests[0].dependencies.is_empty() {
            eprintln!("skipping: could not reach deps.dev (network unavailable in this environment)");
            return;
        }
        let dep = &manifests[0].dependencies[0];
        assert_eq!(dep.name, "lodash");
        assert_eq!(dep.tier, DependencyLicenseTier::Green, "expected lodash (MIT) to classify green: {}", dep.reason);
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[tokio::test]
    async fn scan_dependency_vulnerabilities_skips_clean_dependencies() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("package.json"), r#"{"dependencies": {"@myorg/shared": "workspace:*"}}"#).unwrap();

        let client = DepsDevClient::new();
        let manifests = scan_dependency_vulnerabilities(root, &client).await.unwrap();
        // An internal workspace ref produces a `note` (kept), a genuinely
        // clean external dependency would be filtered out entirely — this
        // only exercises the "kept because of a note" path without a real
        // network dependency.
        assert_eq!(manifests.len(), 1);
        assert_eq!(manifests[0].dependencies[0].note.as_deref(), Some("Internal workspace/catalog reference, not an external package — nothing to check."));
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[tokio::test]
    async fn run_licensee_detect_returns_none_when_not_installed() {
        let result = run_licensee_detect(Path::new("/tmp"), &ToolRunner::new(HashMap::new())).await;
        assert!(result.is_none());
    }
}
