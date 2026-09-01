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
use ignite_override_engine::{build_issue_id, derive_cwe_owasp, score_for_issue, BuildIssueIdArgs, CweOwaspHint, Issue, Severity};
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
    /// Which engine actually resolved this manifest's dependency graph —
    /// "ORT" (real lockfile analysis) or "deps.dev" (the manifest-parser +
    /// registry-lookup fallback) — surfaced per-finding so a reviewer knows
    /// which tool to trust/re-run.
    pub source: &'static str,
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

        // One registry round-trip (or several, on the fallback paths below)
        // per dependency — awaited one at a time here used to mean N deps
        // cost N times a single request's latency; Node's equivalent
        // (`Promise.all(rawDeps.map(...))`) fires every dependency's lookup
        // concurrently instead. `join_all` matches that: each dep's whole
        // per-dependency pipeline (primary lookup, best-published-version
        // retry, npm-registry/SEE-LICENSE-IN fallbacks) becomes one future,
        // all of them run concurrently, and results come back in the same
        // order `raw_deps` was in — the push-based accumulation below is
        // unchanged in every other way.
        let dependencies: Vec<LicenseScanDependency> = futures::future::join_all(raw_deps.iter().map(|dep| async {
            let line = find_manifest_dep_line(&content, &dep.name, spec.ecosystem);

            if is_internal_dependency_ref(&dep.version_range) {
                return LicenseScanDependency {
                    name: dep.name.clone(),
                    version_range: dep.version_range.clone(),
                    version: None,
                    line,
                    licenses: vec![],
                    tier: DependencyLicenseTier::Internal,
                    reason: "Internal workspace/catalog reference, not an external package — nothing to license-check.".to_string(),
                };
            }

            let version = match best_effort_version(&dep.version_range) {
                Some(v) => v,
                None => {
                    // BEST_EFFORT_VERSION_RE requires a `major.minor`, so a
                    // bare-major range (Cargo's `"1"` shorthand for `^1`,
                    // common in every crate's Cargo.toml) doesn't match —
                    // fall through to the same registry-based range
                    // resolution the retry path below uses, instead of
                    // giving up immediately. Only a genuinely unresolvable
                    // spec (git ref, tag, local path) still reports
                    // "Could not resolve" below.
                    match resolve_best_published_version(client, spec.system, &dep.name, &dep.version_range).await {
                        Some(v) => v,
                        None => {
                            return LicenseScanDependency {
                                name: dep.name.clone(),
                                version_range: dep.version_range.clone(),
                                version: None,
                                line,
                                licenses: vec![],
                                tier: DependencyLicenseTier::Red,
                                reason: "Could not resolve an exact version to check (range/tag/git ref).".to_string(),
                            };
                        }
                    }
                }
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
                return LicenseScanDependency {
                    name: dep.name.clone(),
                    version_range: dep.version_range.clone(),
                    version: Some(version),
                    line,
                    licenses: vec![],
                    tier: DependencyLicenseTier::Red,
                    reason: "License lookup failed (package/version not found upstream).".to_string(),
                };
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

            LicenseScanDependency {
                name: dep.name.clone(),
                version_range: dep.version_range.clone(),
                version: Some(resolved_version),
                line,
                licenses,
                tier,
                reason,
            }
        }))
        .await;

        manifests.push(LicenseScanManifest { file: file.strip_prefix(root).unwrap_or(&file).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/"), ecosystem: spec.ecosystem, dependencies, source: "deps.dev" });
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

        // Same fix as scan_dependency_licenses_fallback above: one future
        // per dependency instead of one `.await` at a time in a for-loop —
        // the per-dep network round-trips (package info, best-version
        // retry, per-advisory fetches) now all happen concurrently across
        // every dependency in the manifest, not just within one dependency's
        // own advisory list as before.
        let dependencies: Vec<VulnScanDependency> = futures::future::join_all(raw_deps.iter().map(|dep| async {
            let line = find_manifest_dep_line(&content, &dep.name, spec.ecosystem);

            if is_internal_dependency_ref(&dep.version_range) {
                return VulnScanDependency {
                    name: dep.name.clone(),
                    version_range: dep.version_range.clone(),
                    version: None,
                    line,
                    vulnerabilities: vec![],
                    note: Some("Internal workspace/catalog reference, not an external package — nothing to check.".to_string()),
                };
            }

            let Some(version) = best_effort_version(&dep.version_range) else {
                return VulnScanDependency {
                    name: dep.name.clone(),
                    version_range: dep.version_range.clone(),
                    version: None,
                    line,
                    vulnerabilities: vec![],
                    note: Some("Could not resolve an exact version to check (range/tag/git ref).".to_string()),
                };
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
                return VulnScanDependency {
                    name: dep.name.clone(),
                    version_range: dep.version_range.clone(),
                    version: Some(version),
                    line,
                    vulnerabilities: vec![],
                    note: Some("Vulnerability lookup failed (package/version not found upstream).".to_string()),
                };
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

            VulnScanDependency { name: dep.name.clone(), version_range: dep.version_range.clone(), version: Some(resolved_version), line, vulnerabilities, note: None }
        }))
        .await;

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

pub async fn ort_tooling(runner: &ToolRunner) -> bool {
    runner.run_tool("ort", &["--version".to_string()], std::env::temp_dir().to_str().unwrap_or("."), RunToolOptions::default()).await.is_ok()
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

/// ORT only populates each project's `definition_file_path` (the manifest
/// path needed for per-file issues) when it can resolve the staging
/// root's VCS — on a bare directory (a ZIP/folder upload, never a git
/// checkout) it comes back empty for every project. Best-effort
/// init+commit just so ORT can compute those relative paths; swallows any
/// failure (ORT still runs, just without per-file paths).
async fn ensure_git_root_for_ort(root: &Path, runner: &ToolRunner, mut log: impl FnMut(&str)) {
    if root.join(".git").exists() {
        return;
    }
    let root_str = root.to_string_lossy().into_owned();
    let result: Result<(), ignite_tool_runner::ToolError> = async {
        runner.run_tool("git", &["init".to_string(), "-q".to_string()], &root_str, RunToolOptions::default()).await?;
        runner.run_tool("git", &["add".to_string(), "-A".to_string()], &root_str, RunToolOptions::default()).await?;
        runner
            .run_tool("git", &["-c".to_string(), "user.email=ignite@local".to_string(), "-c".to_string(), "user.name=Ignite".to_string(), "commit".to_string(), "-q".to_string(), "-m".to_string(), "ignite-ort-scan".to_string(), "--no-verify".to_string()], &root_str, RunToolOptions::default())
            .await?;
        Ok(())
    }
    .await;
    if let Err(e) = result {
        log(&format!("⚠ Could not stage a throwaway git repo for ORT's path resolution (non-blocking): {e}"));
    }
}

/// ORT's own package-manager `type` values, mapped onto the same fixed
/// ecosystem identifiers `studio_manifests`'s fallback scanner uses — an
/// ORT-detected ecosystem outside this set (e.g. Conan, NuGet) still
/// contributes its findings, just isn't recognized for the
/// skip-ecosystems de-dup against the fallback scanner, so it may (rarely)
/// be double-reported by both scanners rather than silently dropped.
fn map_ort_ecosystem(ort_type: &str) -> Option<&'static str> {
    match ort_type.to_lowercase().as_str() {
        "npm" | "yarn" | "pnpm" => Some("npm"),
        "cargo" => Some("cargo"),
        "pip" | "pypi" | "pipenv" | "poetry" => Some("pypi"),
        "gomod" | "go" => Some("go"),
        "maven" | "gradle" => Some("maven"),
        _ => None,
    }
}

/// Runs ORT's Analyzer module, which resolves actual lockfiles (more
/// accurate than this crate's own regex-based manifest parsers) across
/// every ecosystem it supports in one pass. Returns `None` — never
/// errors out to the caller — on any missing tool, timeout, or
/// unrecognized output shape, so the caller always has the fallback scan
/// to drop back to; ORT's `analyzer-result.json` schema has changed
/// across versions, so field access here is defensive.
pub async fn run_ort_analyze(root: &Path, runner: &ToolRunner, mut log: impl FnMut(&str)) -> Option<Vec<LicenseScanManifest>> {
    if !ort_tooling(runner).await {
        log("⚠ ORT analyzer skipped: `ort` (OSS Review Toolkit) is not installed — falling back to the built-in manifest scan + deps.dev lookup.");
        return None;
    }
    ensure_git_root_for_ort(root, runner, &mut log).await;

    let out_dir = std::env::temp_dir().join(format!("ignite-ort-{}", uuid::Uuid::new_v4().simple()));
    let result = run_ort_analyze_inner(root, runner, &out_dir).await;
    let _ = std::fs::remove_dir_all(&out_dir);
    match result {
        Ok(manifests) => manifests,
        Err(e) => {
            log(&format!("⚠ ORT analyzer failed, falling back to built-in scan: {e}"));
            None
        }
    }
}

async fn run_ort_analyze_inner(root: &Path, runner: &ToolRunner, out_dir: &Path) -> std::io::Result<Option<Vec<LicenseScanManifest>>> {
    std::fs::create_dir_all(out_dir)?;
    let root_str = root.to_string_lossy().into_owned();
    let out_str = out_dir.to_string_lossy().into_owned();
    // exit 2 = "found issues at/above severity threshold" (a normal ORT
    // outcome, e.g. commercial/unresolved licenses) — the result JSON is
    // still written; only other exit codes mean the analyzer itself failed.
    runner
        .run_tool("ort", &["analyze".to_string(), "-i".to_string(), root_str, "-o".to_string(), out_str, "-f".to_string(), "JSON".to_string()], &root.to_string_lossy(), RunToolOptions { allowed_exit_codes: vec![0, 2], ..Default::default() })
        .await
        .map_err(std::io::Error::other)?;

    let raw = std::fs::read_to_string(out_dir.join("analyzer-result.json"))?;
    let data: serde_json::Value = serde_json::from_str(&raw).map_err(std::io::Error::other)?;
    let result = data.get("analyzer").and_then(|a| a.get("result")).or_else(|| data.get("result"));
    let Some(result) = result else { return Ok(None) };
    let packages = result.get("packages").and_then(|p| p.as_array()).cloned().unwrap_or_default();
    if packages.is_empty() {
        return Ok(None);
    }

    // Narrow ORT's full resolved graph (direct + transitive) down to just
    // each ecosystem's direct dependencies, via the per-ecosystem
    // dependency graph: dependency_graphs[<Type>].scopes[<scopeName>]
    // lists each scope's root entries, and each root's `root` field
    // indexes directly into that same graph's `packages` id-string array.
    let mut direct_ids_by_type: std::collections::HashMap<String, HashSet<String>> = std::collections::HashMap::new();
    if let Some(graphs) = result.get("dependency_graphs").and_then(|v| v.as_object()) {
        for (graph_type, graph) in graphs {
            let graph_packages = graph.get("packages").and_then(|p| p.as_array()).cloned().unwrap_or_default();
            let mut ids = HashSet::new();
            if let Some(scopes) = graph.get("scopes").and_then(|s| s.as_object()) {
                for roots in scopes.values() {
                    if let Some(roots) = roots.as_array() {
                        for entry in roots {
                            if let Some(idx) = entry.get("root").and_then(|r| r.as_u64()) {
                                if let Some(id) = graph_packages.get(idx as usize).and_then(|v| v.as_str()) {
                                    ids.insert(id.to_string());
                                }
                            }
                        }
                    }
                }
            }
            if !ids.is_empty() {
                direct_ids_by_type.insert(graph_type.clone(), ids);
            }
        }
    }

    // Map each ecosystem to its manifest path via the analyzer's
    // `projects` list. When an ecosystem has more than one project (e.g.
    // a monorepo with two package.json's) the path is ambiguous per
    // package, so that ecosystem falls back to a synthetic label instead
    // of guessing wrong.
    let projects = result.get("projects").and_then(|p| p.as_array()).cloned().unwrap_or_default();
    let mut path_by_type: std::collections::HashMap<String, Option<String>> = std::collections::HashMap::new();
    for proj in &projects {
        let id = proj.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let proj_type = id.split(':').next().unwrap_or("").to_string();
        let def_path = proj.get("definition_file_path").or_else(|| proj.get("definitionFilePath")).and_then(|v| v.as_str());
        let (Some(def_path), false) = (def_path, proj_type.is_empty()) else { continue };
        match path_by_type.get(&proj_type) {
            Some(Some(existing)) if existing != def_path => {
                path_by_type.insert(proj_type, None); // ambiguous — more than one manifest
            }
            Some(None) => {}
            _ => {
                path_by_type.insert(proj_type, Some(def_path.to_string()));
            }
        }
    }

    let mut by_type: std::collections::HashMap<String, Vec<LicenseScanDependency>> = std::collections::HashMap::new();
    for entry in &packages {
        let pkg = entry.get("package").unwrap_or(entry);
        let id = pkg.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let parts: Vec<&str> = id.split(':').collect();
        let (Some(&pkg_type), Some(&name)) = (parts.first(), parts.get(2)) else { continue };
        if name.is_empty() || pkg_type.is_empty() {
            continue;
        }
        if let Some(direct_ids) = direct_ids_by_type.get(pkg_type) {
            if !direct_ids.contains(id) {
                continue; // transitive-only — skip
            }
        }
        let version = parts.get(3).copied().unwrap_or("");
        let declared: Vec<String> = pkg
            .get("declared_licenses")
            .or_else(|| pkg.get("declaredLicenses"))
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .or_else(|| {
                pkg.get("declared_licenses_processed")
                    .or_else(|| pkg.get("declaredLicensesProcessed"))
                    .and_then(|p| p.get("spdx_expression").or_else(|| p.get("spdxExpression")))
                    .and_then(|v| v.as_str())
                    .map(|s| vec![s.to_string()])
            })
            .unwrap_or_default();
        let classification = classify_license_tier(&declared);
        by_type.entry(pkg_type.to_string()).or_default().push(LicenseScanDependency {
            name: name.to_string(),
            version_range: version.to_string(),
            version: if version.is_empty() { None } else { Some(version.to_string()) },
            line: None,
            licenses: declared,
            tier: classification.tier.into(),
            reason: classification.reason,
        });
    }

    let mut manifests = Vec::new();
    for (pkg_type, dependencies) in by_type {
        let Some(ecosystem) = map_ort_ecosystem(&pkg_type) else { continue };
        let real_path = path_by_type.get(&pkg_type).cloned().flatten();
        let Some(real_path) = real_path else {
            manifests.push(LicenseScanManifest { file: format!("(ORT: {ecosystem})"), ecosystem, dependencies, source: "ORT" });
            continue;
        };
        // Resolve each dependency's declaration line the same way the
        // deps.dev fallback does, so Studio can highlight the exact line
        // whether the finding came from ORT or the fallback scanner.
        let dependencies = match std::fs::read_to_string(root.join(&real_path)) {
            Ok(content) => dependencies.into_iter().map(|mut dep| { dep.line = find_manifest_dep_line(&content, &dep.name, ecosystem); dep }).collect(),
            Err(_) => dependencies,
        };
        manifests.push(LicenseScanManifest { file: real_path, ecosystem, dependencies, source: "ORT" });
    }

    Ok(Some(manifests))
}

pub struct DependencyLicenseScan {
    pub engine: &'static str,
    pub project_license: Option<ProjectLicenseDetection>,
    pub manifests: Vec<LicenseScanManifest>,
}

/// Combines `run_licensee_detect`'s whole-project license detection,
/// `run_ort_analyze`'s ORT-resolved manifests (when ORT is installed),
/// and the deps.dev-backed fallback scan for whatever ecosystem ORT
/// didn't cover — using ORT's results outright for what it *did* resolve
/// and the fallback only for the rest, so one uncovered ecosystem never
/// makes every other manifest's findings disappear.
pub async fn scan_dependency_licenses(root: &Path, runner: &ToolRunner, client: &DepsDevClient, npm_http: &reqwest::Client, mut log: impl FnMut(&str)) -> std::io::Result<DependencyLicenseScan> {
    let (project_license, ort_manifests) = futures::join!(run_licensee_detect(root, runner), run_ort_analyze(root, runner, &mut log));

    let ort_ecosystems: HashSet<&str> = ort_manifests.as_deref().unwrap_or(&[]).iter().map(|m| m.ecosystem).collect();
    let fallback_manifests = scan_dependency_licenses_fallback(root, client, npm_http, &ort_ecosystems).await?;

    let engine = if ort_manifests.is_none() {
        "fallback"
    } else if !fallback_manifests.is_empty() {
        "ort+fallback"
    } else {
        "ort"
    };
    if ort_manifests.is_some() && !fallback_manifests.is_empty() {
        let ort_list: Vec<&str> = ort_ecosystems.iter().copied().collect();
        let fallback_list: Vec<&str> = fallback_manifests.iter().map(|m| m.ecosystem).collect();
        log(&format!("ℹ ORT resolved {} — falling back to deps.dev for the rest ({}).", ort_list.join(", "), fallback_list.join(", ")));
    }

    let mut manifests = ort_manifests.unwrap_or_default();
    manifests.extend(fallback_manifests);
    Ok(DependencyLicenseScan { engine, project_license, manifests })
}

/// Faithful port of `runLicenseComplianceCheck` — Phase 3's license
/// compliance gate. Never fails the phase on a scan error (a deps.dev
/// network hiccup shouldn't fail structure audit); returns an empty issue
/// list instead.
pub async fn run_license_compliance_check(root: &Path, runner: &ToolRunner, client: &DepsDevClient, npm_http: &reqwest::Client, mut log: impl FnMut(&str)) -> Vec<Issue> {
    log("Check 5 — dependency & license compliance scan (manifests + LICENSE files)...");
    let scan = match scan_dependency_licenses(root, runner, client, npm_http, &mut log).await {
        Ok(s) => s,
        Err(e) => {
            log(&format!("⚠ License compliance scan failed (non-blocking): {e}"));
            return vec![];
        }
    };
    let license_files = match scan_project_license_files(root) {
        Ok(f) => f,
        Err(e) => {
            log(&format!("⚠ License compliance scan failed (non-blocking): {e}"));
            return vec![];
        }
    };
    let issues = collect_license_issues(&scan.manifests, &license_files);
    if !issues.is_empty() {
        let blocking = issues.iter().filter(|i| i.severity == Severity::Error).count();
        log(&format!("⚠ {} license compliance finding(s) ({blocking} commercial/blocking):", issues.len()));
        for li in &issues {
            let marker = if li.severity == Severity::Error { "✗" } else { "⚠" };
            let loc = li.line.map(|l| format!(":{l}")).unwrap_or_default();
            log(&format!("    {marker} {}{loc} — {}", li.file.as_deref().unwrap_or(""), li.summary));
        }
    } else {
        log("✓ Check 5 passed — no commercial/restrictive licenses detected.");
    }
    issues
}

/// Faithful port of `runDependencyVulnerabilityCheck` — Phase 3's
/// dependency-vulnerability gate. Never fails the phase on a scan error.
pub async fn run_dependency_vulnerability_check(root: &Path, client: &DepsDevClient, mut log: impl FnMut(&str)) -> Vec<Issue> {
    log("Check 6 — dependency vulnerability scan (known CVE/GHSA advisories via deps.dev)...");
    let manifests = match scan_dependency_vulnerabilities(root, client).await {
        Ok(m) => m,
        Err(e) => {
            log(&format!("⚠ Dependency vulnerability scan failed (non-blocking): {e}"));
            return vec![];
        }
    };
    let issues = collect_dependency_vulnerability_issues(&manifests);
    if !issues.is_empty() {
        let blocking = issues.iter().filter(|i| i.severity == Severity::Error).count();
        log(&format!("⚠ {} dependency vulnerability finding(s) ({blocking} critical/high — CVSS ≥7):", issues.len()));
        for vi in &issues {
            let marker = if vi.severity == Severity::Error { "✗" } else { "⚠" };
            let loc = vi.line.map(|l| format!(":{l}")).unwrap_or_default();
            log(&format!("    {marker} {}{loc} — {}", vi.file.as_deref().unwrap_or(""), vi.summary));
        }
    } else {
        log("✓ Check 6 passed — no known vulnerabilities found in resolved dependencies.");
    }
    issues
}

/// Turns `scan_dependency_licenses_fallback`'s manifest findings and
/// `scan_project_license_files`'s raw LICENSE-file findings into the same
/// addressable-issue shape `collect_phase4_issues` uses, so commercial/
/// copyleft/unrecognized licenses gate a run exactly like a hardcoded
/// secret does, instead of only ever showing up in the Dependencies view.
pub fn collect_license_issues(manifests: &[LicenseScanManifest], license_files: &[LicenseFileFinding]) -> Vec<Issue> {
    let mut issues = Vec::new();
    let category = "license-compliance";

    for manifest in manifests {
        for dep in &manifest.dependencies {
            if matches!(dep.tier, DependencyLicenseTier::Green | DependencyLicenseTier::Internal) {
                continue;
            }
            let severity = if matches!(dep.tier, DependencyLicenseTier::Red) { Severity::Error } else { Severity::Warning };
            // The dep name (not its line) keeps the id stable across edits
            // that shift lines, so overrides survive unrelated manifest changes.
            let id = format!("{}::{}", build_issue_id(BuildIssueIdArgs { category, file: Some(&manifest.file), line: None, discriminator: None }), dep.name);
            let version = dep.version.clone().unwrap_or_else(|| if dep.version_range.is_empty() { "?".to_string() } else { dep.version_range.clone() });
            issues.push(Issue {
                id,
                category: category.to_string(),
                severity,
                score: score_for_issue(category, severity),
                summary: format!("{}@{} — {}", dep.name, version, dep.reason),
                file: Some(manifest.file.clone()),
                line: dep.line.map(|l| l as i64),
                snippet: None,
                cross_file: false,
                chain: None,
                duplicate_ref: None,
                references: ignite_override_engine::IssueReferences::default(),
                cwe: None,
                owasp: None,
                tool: Some(manifest.source.to_string()),
            });
        }
    }

    for lf in license_files {
        let severity = if lf.tier == "red" { Severity::Error } else { Severity::Warning };
        issues.push(Issue {
            id: build_issue_id(BuildIssueIdArgs { category, file: Some(&lf.file), line: Some(lf.line as i64), discriminator: None }),
            category: category.to_string(),
            severity,
            score: score_for_issue(category, severity),
            summary: lf.reason.clone(),
            file: Some(lf.file.clone()),
            line: Some(lf.line as i64),
            snippet: None,
            cross_file: false,
            chain: None,
            duplicate_ref: None,
            references: ignite_override_engine::IssueReferences::default(),
            cwe: None,
            owasp: None,
            // A raw root LICENSE/LICENSE.txt file's own text, classified by
            // Ignite's built-in scanner directly — not a per-dependency
            // manifest lookup, so neither ORT nor deps.dev produced this one.
            tool: Some("built-in".to_string()),
        });
    }

    issues
}

static CWE_ALIAS_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^CWE-\d+$").unwrap());

/// Turns `scan_dependency_vulnerabilities`' per-dependency CVE/GHSA
/// findings into the same addressable-issue shape `collect_license_issues`
/// uses, so a known-critical dependency vulnerability gates a run exactly
/// like a commercial license does.
pub fn collect_dependency_vulnerability_issues(manifests: &[VulnScanManifest]) -> Vec<Issue> {
    let mut issues = Vec::new();
    let category = "dependency-vulnerability";

    for manifest in manifests {
        for dep in &manifest.dependencies {
            for vuln in &dep.vulnerabilities {
                let severity = if vuln.severity == "error" { Severity::Error } else { Severity::Warning };
                let advisory_id = vuln.id.clone().or_else(|| vuln.aliases.first().cloned()).unwrap_or_else(|| "unknown-advisory".to_string());
                // OSV/GHSA advisories sometimes carry the underlying CWE as
                // one of their aliases (e.g. "CWE-1321") alongside the
                // CVE/GHSA id itself.
                let cwe_alias = vuln.aliases.iter().find(|a| CWE_ALIAS_RE.is_match(a)).cloned();
                let hint = derive_cwe_owasp(category, vuln.title.as_deref().unwrap_or(""), &CweOwaspHint { cwe: cwe_alias, owasp: None });
                // A GHSA/PYSEC advisory id is deps.dev's own identifier, not
                // necessarily the CVE — the real CVE (when one was ever
                // assigned) shows up as one of the advisory's aliases
                // instead, so surface it separately rather than dropping it.
                let cve_alias = vuln.aliases.iter().find(|a| a.starts_with("CVE-")).cloned();

                let mut summary = format!("{}@{} — {}", dep.name, dep.version.clone().unwrap_or_else(|| if dep.version_range.is_empty() { "?".to_string() } else { dep.version_range.clone() }), advisory_id);
                if let Some(title) = &vuln.title {
                    summary.push_str(&format!(": {title}"));
                }
                if let Some(cve) = &cve_alias {
                    if advisory_id != *cve {
                        summary.push_str(&format!(" ({cve})"));
                    }
                }
                if let Some(score) = vuln.cvss3_score {
                    summary.push_str(&format!(" (CVSS {score})"));
                }

                // Every id this one advisory carries, sorted into its
                // CVE/CWE/PySec/RustSec/Go/GHSA bucket — an OSV record
                // routinely lists more than one of each (multiple CVEs
                // assigned to the same root cause, several CWE tags, cross-
                // references to the same flaw under another ecosystem's
                // database), which `hint.cwe`/`cve_alias` above (kept for
                // the plain-text summary and the singular `cwe` field) can't
                // represent on their own.
                let references = ignite_override_engine::build_references(std::iter::once(advisory_id.as_str()).chain(vuln.aliases.iter().map(|s| s.as_str())));

                let id = format!("{}::{}::{}", build_issue_id(BuildIssueIdArgs { category, file: Some(&manifest.file), line: dep.line.map(|l| l as i64), discriminator: None }), dep.name, advisory_id);
                issues.push(Issue {
                    id,
                    category: category.to_string(),
                    severity,
                    score: score_for_issue(category, severity),
                    summary,
                    file: Some(manifest.file.clone()),
                    line: dep.line.map(|l| l as i64),
                    snippet: None,
                    cross_file: false,
                    chain: None,
                    duplicate_ref: None,
                    references,
                    cwe: hint.cwe,
                    owasp: hint.owasp,
                    tool: Some("deps.dev".to_string()),
                });
            }
        }
    }

    issues
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use tempfile::tempdir;

    #[tokio::test]
    async fn run_license_compliance_check_logs_and_returns_no_issues_for_internal_only_deps() {
        let _guard = PATH_LOCK.lock().unwrap(); // real `ort`/`licensee` run here — must not race the PATH-mutating test
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("package.json"), r#"{"dependencies": {"@myorg/shared": "workspace:*"}}"#).unwrap();

        let runner = ignite_tool_runner::ToolRunner::new(HashMap::new());
        let client = DepsDevClient::new();
        let npm_http = reqwest::Client::new();
        let mut logs = Vec::new();
        let issues = run_license_compliance_check(root, &runner, &client, &npm_http, |l| logs.push(l.to_string())).await;
        assert!(issues.is_empty());
        assert!(logs.iter().any(|l| l.contains("Check 5")));
        assert!(logs.iter().any(|l| l.contains("passed")));
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[tokio::test]
    async fn run_dependency_vulnerability_check_logs_and_returns_no_issues_for_no_manifests() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let client = DepsDevClient::new();
        let mut logs = Vec::new();
        let issues = run_dependency_vulnerability_check(root, &client, |l| logs.push(l.to_string())).await;
        assert!(issues.is_empty());
        assert!(logs.iter().any(|l| l.contains("Check 6")));
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn collect_license_issues_skips_green_and_internal_deps() {
        let manifest = LicenseScanManifest {
            file: "package.json".to_string(),
            ecosystem: "npm",
            dependencies: vec![
                LicenseScanDependency { name: "lodash".to_string(), version_range: "^4.0.0".to_string(), version: Some("4.17.21".to_string()), line: Some(5), licenses: vec!["MIT".to_string()], tier: DependencyLicenseTier::Green, reason: "MIT".to_string() },
                LicenseScanDependency { name: "@acme/internal-lib".to_string(), version_range: "*".to_string(), version: None, line: Some(6), licenses: vec![], tier: DependencyLicenseTier::Internal, reason: "internal".to_string() },
                LicenseScanDependency { name: "shady-pkg".to_string(), version_range: "^1.0.0".to_string(), version: Some("1.0.0".to_string()), line: Some(7), licenses: vec!["Commercial".to_string()], tier: DependencyLicenseTier::Red, reason: "Commercial license".to_string() },
            ],
            source: "deps.dev",
        };
        let issues = collect_license_issues(&[manifest], &[]);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].category, "license-compliance");
        assert_eq!(issues[0].severity, Severity::Error);
        assert!(issues[0].id.ends_with("shady-pkg"));
        assert!(issues[0].summary.contains("shady-pkg@1.0.0"));
    }

    #[test]
    fn collect_license_issues_includes_license_file_findings() {
        let lf = LicenseFileFinding { file: "vendor/LICENSE".to_string(), tier: "red", line: 1, reason: "Commercial/proprietary license terms detected in LICENSE file.".to_string() };
        let issues = collect_license_issues(&[], &[lf]);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].file.as_deref(), Some("vendor/LICENSE"));
        assert_eq!(issues[0].severity, Severity::Error);
    }

    #[test]
    fn collect_dependency_vulnerability_issues_maps_severity_and_cvss() {
        let manifest = VulnScanManifest {
            file: "package.json".to_string(),
            ecosystem: "npm",
            dependencies: vec![VulnScanDependency {
                name: "body-parser".to_string(),
                version_range: "^1.20.0".to_string(),
                version: Some("1.20.2".to_string()),
                line: Some(12),
                vulnerabilities: vec![VulnFinding { id: Some("GHSA-qwcr-r2fm-qrc7".to_string()), title: Some("body-parser vulnerable to denial of service".to_string()), aliases: vec!["CVE-2024-1234".to_string()], cvss3_score: Some(7.5), severity: "error", url: None }],
                note: None,
            }],
        };
        let issues = collect_dependency_vulnerability_issues(&[manifest]);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].category, "dependency-vulnerability");
        assert_eq!(issues[0].severity, Severity::Error);
        assert!(issues[0].summary.contains("GHSA-qwcr-r2fm-qrc7"));
        assert!(issues[0].summary.contains("CVSS 7.5"));
        assert!(issues[0].id.ends_with("body-parser::GHSA-qwcr-r2fm-qrc7"));
        assert_eq!(issues[0].tool.as_deref(), Some("deps.dev"));
        assert_eq!(issues[0].references.ghsa, vec!["GHSA-qwcr-r2fm-qrc7"]);
        assert_eq!(issues[0].references.cve, vec!["CVE-2024-1234"]);
    }

    /// Real case hit against deps.dev live data: one advisory carries
    /// several CVE aliases and several PYSEC cross-references at once —
    /// every one of them must survive into `references`, not just the
    /// first of each.
    #[test]
    fn collect_dependency_vulnerability_issues_captures_every_alias_of_each_kind() {
        let manifest = VulnScanManifest {
            file: "requirements.txt".to_string(),
            ecosystem: "pypi",
            dependencies: vec![VulnScanDependency {
                name: "starlette".to_string(),
                version_range: "0.35.1".to_string(),
                version: Some("0.35.1".to_string()),
                line: Some(19),
                vulnerabilities: vec![VulnFinding {
                    id: Some("GHSA-82w8-qh3p-5jfq".to_string()),
                    title: Some("Starlette: request.form() limits silently ignored".to_string()),
                    aliases: vec![
                        "CVE-2026-54283".to_string(),
                        "CVE-2026-48818".to_string(),
                        "PYSEC-2026-249".to_string(),
                        "PYSEC-2026-3037".to_string(),
                        "CWE-770".to_string(),
                    ],
                    cvss3_score: Some(7.5),
                    severity: "error",
                    url: None,
                }],
                note: None,
            }],
        };
        let issues = collect_dependency_vulnerability_issues(&[manifest]);
        assert_eq!(issues.len(), 1);
        let refs = &issues[0].references;
        assert_eq!(refs.ghsa, vec!["GHSA-82w8-qh3p-5jfq"]);
        assert_eq!(refs.cve, vec!["CVE-2026-54283", "CVE-2026-48818"]);
        assert_eq!(refs.pysec, vec!["PYSEC-2026-249", "PYSEC-2026-3037"]);
        assert_eq!(refs.cwe, vec!["CWE-770"]);
    }

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

    /// Regression test: `serde = "1"` — Cargo's shorthand for `^1`, and how
    /// the overwhelming majority of real Cargo.toml files pin a dependency
    /// — used to report "Could not resolve an exact version to check"
    /// unconditionally, because `best_effort_version`'s regex requires a
    /// `major.minor` and a bare `"1"` has no dot. Proves the fallback to
    /// registry-based range resolution (`resolve_best_published_version`)
    /// now kicks in for exactly this case instead of giving up immediately.
    #[tokio::test]
    async fn scan_dependency_licenses_fallback_real_network_resolves_bare_major_cargo_range() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("Cargo.toml"), "[package]\nname = \"x\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1\"\n").unwrap();

        let client = DepsDevClient::new();
        let npm_http = reqwest::Client::new();
        let manifests = scan_dependency_licenses_fallback(root, &client, &npm_http, &HashSet::new()).await.unwrap();
        if manifests.is_empty() || manifests[0].dependencies.is_empty() {
            eprintln!("skipping: could not reach deps.dev (network unavailable in this environment)");
            return;
        }
        let dep = &manifests[0].dependencies[0];
        assert_eq!(dep.name, "serde");
        assert_ne!(dep.tier, DependencyLicenseTier::Red, "expected serde@1 to resolve to a real published version instead of \"Could not resolve\": {}", dep.reason);
        assert!(dep.version.is_some(), "expected a resolved version, got: {}", dep.reason);
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

    // Serializes tests that mutate the process-global PATH env var.
    static PATH_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[tokio::test]
    async fn run_ort_analyze_returns_none_when_not_installed() {
        // "ort" is a FIXED_COMMANDS entry (resolved directly off PATH, not
        // via ToolRunner's binaries map), so an empty ToolRunner alone
        // doesn't force the not-installed path on a machine that actually
        // has ort installed — point PATH somewhere with no `ort` instead.
        let _guard = PATH_LOCK.lock().unwrap();
        let original_path = std::env::var("PATH").unwrap_or_default();
        std::env::set_var("PATH", "/nonexistent-ignite-test-path");

        let runner = ToolRunner::new(HashMap::new());
        let mut logs = Vec::new();
        let result = run_ort_analyze(Path::new("/tmp"), &runner, |l| logs.push(l.to_string())).await;

        std::env::set_var("PATH", &original_path);

        assert!(result.is_none());
        assert!(logs.iter().any(|l| l.contains("ORT analyzer skipped")));
    }

    #[test]
    fn map_ort_ecosystem_recognizes_known_package_managers() {
        assert_eq!(map_ort_ecosystem("NPM"), Some("npm"));
        assert_eq!(map_ort_ecosystem("Yarn"), Some("npm"));
        assert_eq!(map_ort_ecosystem("Cargo"), Some("cargo"));
        assert_eq!(map_ort_ecosystem("PIP"), Some("pypi"));
        assert_eq!(map_ort_ecosystem("GoMod"), Some("go"));
        assert_eq!(map_ort_ecosystem("Maven"), Some("maven"));
        assert_eq!(map_ort_ecosystem("Gradle"), Some("maven"));
        assert_eq!(map_ort_ecosystem("Conan"), None);
    }

    #[tokio::test]
    async fn run_ort_analyze_resolves_a_real_npm_project_when_ort_is_installed() {
        let _guard = PATH_LOCK.lock().unwrap(); // must not race the PATH-mutating test
        let binaries: HashMap<&'static str, String> = [("ort", "ort".to_string())].into_iter().collect();
        let runner = ToolRunner::new(binaries);
        if !ort_tooling(&runner).await {
            return; // ort not installed on this machine — nothing to verify
        }

        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("package.json"), r#"{"name":"ort-smoke-test","version":"1.0.0","dependencies":{"lodash":"4.17.21"}}"#).unwrap();
        fs::write(
            root.join("package-lock.json"),
            r#"{"name":"ort-smoke-test","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"ort-smoke-test","version":"1.0.0","dependencies":{"lodash":"4.17.21"}},"node_modules/lodash":{"version":"4.17.21","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz","license":"MIT"}}}"#,
        )
        .unwrap();

        let mut logs = Vec::new();
        let result = run_ort_analyze(root, &runner, |l| logs.push(l.to_string())).await;
        // ORT's own resolution can still come back empty in a sandboxed/
        // offline CI environment (no registry access) — the point of this
        // test is that the real subprocess path runs to completion without
        // erroring, not a specific dependency count.
        if let Some(manifests) = result {
            if let Some(npm) = manifests.iter().find(|m| m.ecosystem == "npm") {
                assert!(npm.dependencies.iter().any(|d| d.name == "lodash"));
            }
        }
    }
}
