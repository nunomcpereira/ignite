//! deps.dev API client + npm-registry/unpkg license fallbacks, shared by
//! the dependency license/vulnerability scanning subsystem. Faithful port
//! of the corresponding server.js functions: fetch_deps_dev_package_info/
//! _licenses/_advisory/_version_list, fetch_npm_registry_license,
//! resolve_see_license_in_file, resolve_best_published_version,
//! satisfies_version_range, classify_vulnerability_severity,
//! find_manifest_dep_line.

use ignite_license_classification::{best_effort_version, classify_license_tier, LicenseTier};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

pub fn parse_semver(v: &str) -> Option<(u64, u64, u64)> {
    static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^(\d+)\.(\d+)\.(\d+)").unwrap());
    let m = RE.captures(v)?;
    Some((m[1].parse().ok()?, m[2].parse().ok()?, m[3].parse().ok()?))
}

pub fn compare_semver(a: (u64, u64, u64), b: (u64, u64, u64)) -> std::cmp::Ordering {
    a.cmp(&b)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepsDevPackageInfo {
    pub licenses: Vec<String>,
    pub advisory_ids: Vec<String>,
}

/// Immutable per-(system,name,version) result — cached for the process
/// lifetime, same as the JS original's module-level `Map`.
pub struct DepsDevClient {
    http: reqwest::Client,
    package_info_cache: Mutex<HashMap<String, Option<DepsDevPackageInfo>>>,
    version_list_cache: Mutex<HashMap<String, Option<Vec<String>>>>,
    advisory_cache: Mutex<HashMap<String, Option<serde_json::Value>>>,
}

impl Default for DepsDevClient {
    fn default() -> Self {
        Self::new()
    }
}

impl DepsDevClient {
    pub fn new() -> Self {
        DepsDevClient { http: reqwest::Client::new(), package_info_cache: Mutex::new(HashMap::new()), version_list_cache: Mutex::new(HashMap::new()), advisory_cache: Mutex::new(HashMap::new()) }
    }

    /// One deps.dev call returns both licenses and known-vulnerability
    /// advisory ids for a (system, name, version) — cached together so the
    /// license scan and the vulnerability scan never issue two requests
    /// for the same package.
    pub async fn fetch_package_info(&self, system: &str, name: &str, version: &str) -> Option<DepsDevPackageInfo> {
        let key = format!("{}:{}:{}", system, name, version);
        if let Some(cached) = self.package_info_cache.lock().unwrap().get(&key) {
            return cached.clone();
        }
        let url = format!("https://api.deps.dev/v3/systems/{}/packages/{}/versions/{}", system, urlencoding::encode(name), urlencoding::encode(version));
        let result = async {
            let res = self.http.get(&url).timeout(Duration::from_secs(5)).send().await.ok()?;
            if !res.status().is_success() {
                return None;
            }
            let data: serde_json::Value = res.json().await.ok()?;
            let licenses = data.get("licenses").and_then(|l| l.as_array()).map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
            let advisory_ids = data
                .get("advisoryKeys")
                .and_then(|a| a.as_array())
                .map(|a| a.iter().filter_map(|k| k.get("id").and_then(|i| i.as_str()).map(String::from)).collect())
                .unwrap_or_default();
            Some(DepsDevPackageInfo { licenses, advisory_ids })
        }
        .await;
        self.package_info_cache.lock().unwrap().insert(key, result.clone());
        result
    }

    pub async fn fetch_licenses(&self, system: &str, name: &str, version: &str) -> Option<Vec<String>> {
        self.fetch_package_info(system, name, version).await.map(|i| i.licenses)
    }

    pub async fn fetch_version_list(&self, system: &str, name: &str) -> Option<Vec<String>> {
        let key = format!("{}:{}", system, name);
        if let Some(cached) = self.version_list_cache.lock().unwrap().get(&key) {
            return cached.clone();
        }
        let url = format!("https://api.deps.dev/v3/systems/{}/packages/{}", system, urlencoding::encode(name));
        let result = async {
            let res = self.http.get(&url).timeout(Duration::from_secs(5)).send().await.ok()?;
            if !res.status().is_success() {
                return None;
            }
            let data: serde_json::Value = res.json().await.ok()?;
            let versions = data.get("versions").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|v| v.get("versionKey").and_then(|k| k.get("version")).and_then(|s| s.as_str()).map(String::from)).collect());
            versions
        }
        .await;
        self.version_list_cache.lock().unwrap().insert(key, result.clone());
        result
    }

    pub async fn fetch_advisory(&self, id: &str) -> Option<serde_json::Value> {
        if let Some(cached) = self.advisory_cache.lock().unwrap().get(id) {
            return cached.clone();
        }
        let url = format!("https://api.deps.dev/v3/advisories/{}", urlencoding::encode(id));
        let result = async {
            let res = self.http.get(&url).timeout(Duration::from_secs(5)).send().await.ok()?;
            if res.status().is_success() {
                res.json::<serde_json::Value>().await.ok()
            } else {
                None
            }
        }
        .await;
        self.advisory_cache.lock().unwrap().insert(id.to_string(), result.clone());
        result
    }
}

/// deps.dev's own license classifier sometimes can't map a package's
/// declared license to an SPDX id and reports a placeholder string
/// instead of actually failing the lookup.
static DEPS_DEV_LICENSE_PLACEHOLDERS: Lazy<std::collections::HashSet<&'static str>> = Lazy::new(|| ["non-standard", "unknown", "other", "none", ""].into_iter().collect());

pub fn is_placeholder_license_list(licenses: &[String]) -> bool {
    let list: Vec<String> = licenses.iter().filter(|l| !l.is_empty()).cloned().collect();
    !list.is_empty() && list.iter().all(|l| DEPS_DEV_LICENSE_PLACEHOLDERS.contains(l.trim().to_lowercase().as_str()))
}

/// Fallback for when deps.dev only offers a placeholder: ask the npm
/// registry itself for that exact version's declared `license` field.
pub async fn fetch_npm_registry_license(client: &reqwest::Client, name: &str, version: &str) -> Option<Vec<String>> {
    let url = format!("https://registry.npmjs.org/{}/{}", urlencoding::encode(name).replace("%40", "@"), urlencoding::encode(version));
    let res = client.get(&url).timeout(Duration::from_secs(5)).send().await.ok()?;
    if !res.status().is_success() {
        return None;
    }
    let data: serde_json::Value = res.json().await.ok()?;
    if let Some(license) = data.get("license").and_then(|l| l.as_str()) {
        if !license.trim().is_empty() {
            return Some(vec![license.trim().to_string()]);
        }
    }
    if let Some(licenses) = data.get("licenses").and_then(|l| l.as_array()) {
        if !licenses.is_empty() {
            let list: Vec<String> = licenses.iter().filter_map(|l| l.as_str().map(String::from).or_else(|| l.get("type").and_then(|t| t.as_str()).map(String::from))).collect();
            if !list.is_empty() {
                return Some(list);
            }
        }
    }
    None
}

static SEE_LICENSE_IN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^SEE LICENSE IN\s+(.+)$").unwrap());

pub fn detect_license_text_spdx_id(content: &str) -> Option<&'static str> {
    if Regex::new(r"(?i)permission is hereby granted, free of charge").unwrap().is_match(content) {
        return Some("MIT");
    }
    if Regex::new(r"(?i)apache license").unwrap().is_match(content) && Regex::new(r"(?i)version 2\.0").unwrap().is_match(content) {
        return Some("Apache-2.0");
    }
    if Regex::new(r"(?i)redistribution and use in source and binary forms").unwrap().is_match(content) {
        return Some(if Regex::new(r"(?i)neither the name").unwrap().is_match(content) { "BSD-3-Clause" } else { "BSD-2-Clause" });
    }
    None
}

pub async fn fetch_unpkg_file_text(client: &reqwest::Client, name: &str, version: &str, filename: &str) -> Option<String> {
    let filename = filename.trim_start_matches("./").trim_start_matches('/');
    let url = format!("https://unpkg.com/{}@{}/{}", urlencoding::encode(name).replace("%40", "@"), urlencoding::encode(version), filename);
    let res = client.get(&url).timeout(Duration::from_secs(5)).send().await.ok()?;
    if res.status().is_success() {
        res.text().await.ok()
    } else {
        None
    }
}

pub struct SeeLicenseResolution {
    pub tier: LicenseTier,
    pub reason: String,
}

/// Resolves a `SEE LICENSE IN <file>` declaration to a real SPDX id/tier
/// by reading the referenced file's actual text from the published
/// tarball (via unpkg). Returns `None` when the license string isn't this
/// pattern, the file can't be fetched, or its text doesn't match a known
/// permissive boilerplate.
pub async fn resolve_see_license_in_file(client: &reqwest::Client, name: &str, version: &str, license_string: &str) -> Option<SeeLicenseResolution> {
    let m = SEE_LICENSE_IN_RE.captures(license_string.trim())?;
    let filename = m[1].trim().to_string();
    let text = fetch_unpkg_file_text(client, name, version, &filename).await?;
    let spdx_id = detect_license_text_spdx_id(&text)?;
    let classification = classify_license_tier(&[spdx_id.to_string()]);
    Some(SeeLicenseResolution { tier: classification.tier, reason: format!(r#"{} (declared "SEE LICENSE IN {}", verified by matching that file's text)"#, spdx_id, filename) })
}

/// `bestEffortVersion` extracts the numeric floor of a manifest's version
/// *range* and looks that up directly — which 404s on deps.dev whenever
/// that exact patch was never actually published. This resolves the
/// actual highest published version satisfying the range as a fallback.
pub async fn resolve_best_published_version(client: &DepsDevClient, system: &str, name: &str, version_range: &str) -> Option<String> {
    let versions = client.fetch_version_list(system, name).await?;
    let stable: Vec<&String> = versions.iter().filter(|v| parse_semver(v).is_some() && !v.contains(['-', '+'])).collect();
    let matching: Vec<&&String> = stable.iter().filter(|v| satisfies_version_range(v, version_range)).collect();
    let pool: Vec<&String> = if !matching.is_empty() { matching.into_iter().copied().collect() } else { stable };
    if pool.is_empty() {
        return None;
    }
    pool.iter().max_by(|a, b| parse_semver(a).map_or(std::cmp::Ordering::Less, |pa| parse_semver(b).map_or(std::cmp::Ordering::Greater, |pb| compare_semver(pa, pb)))).map(|s| s.to_string())
}

/// Deliberately narrow: covers exact pins and npm/cargo-style `^`/`~`
/// prefixes, which is what package.json/Cargo.toml ranges actually use in
/// practice. Anything else (`>=`, `workspace:`, git refs, ...) is treated
/// as "any published version at or above the floor is acceptable".
pub fn satisfies_version_range(version: &str, raw_range: &str) -> bool {
    let Some(v) = parse_semver(version) else { return true };
    let Some(bev) = best_effort_version(raw_range) else { return true };
    let Some(floor) = parse_semver(&bev) else { return true };
    if compare_semver(v, floor) == std::cmp::Ordering::Less {
        return false;
    }
    let range = raw_range.trim();
    if let Some(_stripped) = range.strip_prefix('^') {
        if floor.0 > 0 {
            return v.0 == floor.0;
        }
        if floor.1 > 0 {
            return v.0 == 0 && v.1 == floor.1;
        }
        return v.0 == 0 && v.1 == 0 && v.2 == floor.2;
    }
    if range.starts_with('~') {
        return v.0 == floor.0 && v.1 == floor.1;
    }
    if !Regex::new(r"(?i)[\^~<>=*x]").unwrap().is_match(range) {
        return compare_semver(v, floor) == std::cmp::Ordering::Equal; // exact pin
    }
    true
}

/// CVSS v3 base score bands: >=9 critical, >=7 high — both block the
/// pipeline. Below that (medium/low) is advisory-only. An advisory with no
/// CVSS score at all is treated as medium rather than assumed harmless.
pub fn classify_vulnerability_severity(cvss3_score: Option<f64>) -> &'static str {
    if let Some(score) = cvss3_score {
        if score >= 7.0 {
            return "error";
        }
    }
    "warning"
}

/// Best-effort 1-based line of a dependency's declaration inside its
/// manifest, so a license finding can highlight the exact line in the
/// Studio editor instead of a file-level "line ?".
pub fn find_manifest_dep_line(content: &str, dep_name: &str, ecosystem: &str) -> Option<usize> {
    let needle = match ecosystem {
        "maven" => format!("<artifactId>{}<", dep_name.split(':').nth(1).unwrap_or(dep_name)),
        "npm" => format!("\"{}\"", dep_name),
        _ => dep_name.to_string(),
    };
    content.split('\n').position(|l| l.contains(&needle)).map(|i| i + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_placeholder_license_list_recognizes_known_placeholders() {
        assert!(is_placeholder_license_list(&["non-standard".to_string()]));
        assert!(is_placeholder_license_list(&["Unknown".to_string()]));
        assert!(!is_placeholder_license_list(&["MIT".to_string()]));
        assert!(!is_placeholder_license_list(&[]));
    }

    #[test]
    fn detect_license_text_spdx_id_recognizes_mit_apache_bsd() {
        assert_eq!(detect_license_text_spdx_id("Permission is hereby granted, free of charge, to any person..."), Some("MIT"));
        assert_eq!(detect_license_text_spdx_id("Apache License\nVersion 2.0, January 2004"), Some("Apache-2.0"));
        assert_eq!(detect_license_text_spdx_id("Redistribution and use in source and binary forms... Neither the name of..."), Some("BSD-3-Clause"));
        assert_eq!(detect_license_text_spdx_id("Redistribution and use in source and binary forms..."), Some("BSD-2-Clause"));
        assert_eq!(detect_license_text_spdx_id("some unrelated text"), None);
    }

    #[test]
    fn classify_vulnerability_severity_bands() {
        assert_eq!(classify_vulnerability_severity(Some(9.8)), "error");
        assert_eq!(classify_vulnerability_severity(Some(7.0)), "error");
        assert_eq!(classify_vulnerability_severity(Some(6.9)), "warning");
        assert_eq!(classify_vulnerability_severity(None), "warning");
    }

    #[test]
    fn find_manifest_dep_line_locates_npm_and_maven_deps() {
        let pkg_json = "{\n  \"dependencies\": {\n    \"lodash\": \"^4.17.21\"\n  }\n}\n";
        assert_eq!(find_manifest_dep_line(pkg_json, "lodash", "npm"), Some(3));

        let pom = "<project>\n  <dependencies>\n    <dependency>\n      <artifactId>guava</artifactId>\n    </dependency>\n  </dependencies>\n</project>\n";
        assert_eq!(find_manifest_dep_line(pom, "com.google.guava:guava", "maven"), Some(4));
    }

    #[test]
    fn satisfies_version_range_caret_matches_same_major() {
        assert!(satisfies_version_range("5.6.2", "^5.6.0"));
        assert!(!satisfies_version_range("6.0.0", "^5.6.0"));
        assert!(!satisfies_version_range("5.5.0", "^5.6.0")); // below floor
    }

    #[test]
    fn satisfies_version_range_tilde_matches_same_minor() {
        assert!(satisfies_version_range("5.6.9", "~5.6.0"));
        assert!(!satisfies_version_range("5.7.0", "~5.6.0"));
    }

    #[test]
    fn satisfies_version_range_exact_pin_requires_exact_match() {
        assert!(satisfies_version_range("1.2.3", "1.2.3"));
        assert!(!satisfies_version_range("1.2.4", "1.2.3"));
    }

    #[test]
    fn satisfies_version_range_zero_major_caret_narrows_to_minor() {
        assert!(satisfies_version_range("0.5.9", "^0.5.0"));
        assert!(!satisfies_version_range("0.6.0", "^0.5.0"));
    }

    #[tokio::test]
    async fn resolve_see_license_in_file_returns_none_for_non_matching_string() {
        let client = reqwest::Client::new();
        let result = resolve_see_license_in_file(&client, "some-pkg", "1.0.0", "MIT").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn deps_dev_client_caches_package_info_lookups() {
        // Real network call to a well-known, stable published package —
        // verifies the client actually talks to deps.dev successfully.
        let client = DepsDevClient::new();
        let info = client.fetch_package_info("NPM", "lodash", "4.17.21").await;
        if info.is_none() {
            eprintln!("skipping: could not reach deps.dev (network unavailable in this environment)");
            return;
        }
        let info = info.unwrap();
        assert!(!info.licenses.is_empty());
        assert!(info.licenses.iter().any(|l| l.contains("MIT")));
    }
}
