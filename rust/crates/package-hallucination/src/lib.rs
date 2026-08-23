//! AI package-hallucination / slopsquat detection. Faithful port of
//! `checks/package-hallucination.js`. Built-in, no external binary — a
//! real HTTP existence check against npm/PyPI/crates.io's own registry
//! APIs. Always advisory.
//!
//! `studio_manifests` (server.js's `STUDIO_MANIFESTS` table of per-
//! ecosystem manifest parsers) isn't ported yet, so the manifest-parsing
//! side is an injectable `ManifestSpec` list here too, same as the JS
//! test suite's own approach (`fetchImpl`/`studioManifests` are both
//! constructor-injected there) — this crate ships small working parsers
//! for `package.json` (npm) and `requirements.txt` (pypi) as a real,
//! directly-usable default, not a stub.

use ignite_fs_utils::walk_files;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

static NON_REGISTRY_VERSION_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^(git\+|git:|https?:|file:|link:|workspace:|npm:.*@|github:)").unwrap());

#[derive(Debug, Clone)]
pub struct ManifestDependency {
    pub name: String,
    pub version_range: Option<String>,
}

#[derive(Clone)]
pub struct ManifestSpec {
    pub file: &'static str,
    pub ecosystem: &'static str,
    pub parse: fn(&str) -> Vec<ManifestDependency>,
}

pub fn parse_package_json(content: &str) -> Vec<ManifestDependency> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(content) else { return vec![] };
    let mut deps = Vec::new();
    for field in ["dependencies", "devDependencies"] {
        if let Some(obj) = v.get(field).and_then(|d| d.as_object()) {
            for (name, range) in obj {
                deps.push(ManifestDependency { name: name.clone(), version_range: range.as_str().map(String::from) });
            }
        }
    }
    deps
}

static REQUIREMENTS_LINE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^([A-Za-z0-9_.\-]+)\s*(.*)$").unwrap());

pub fn parse_requirements_txt(content: &str) -> Vec<ManifestDependency> {
    let mut deps = Vec::new();
    for raw_line in content.split('\n') {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('-') {
            continue;
        }
        if let Some(caps) = REQUIREMENTS_LINE_RE.captures(line) {
            let name = caps[1].to_string();
            let rest = caps.get(2).map(|m| m.as_str().trim().to_string()).filter(|s| !s.is_empty());
            deps.push(ManifestDependency { name, version_range: rest });
        }
    }
    deps
}

/// A working default manifest table (npm + pypi) — a real, immediately
/// usable subset of server.js's full `STUDIO_MANIFESTS`, not a stub.
pub fn default_manifests() -> Vec<ManifestSpec> {
    vec![
        ManifestSpec { file: "package.json", ecosystem: "npm", parse: parse_package_json },
        ManifestSpec { file: "requirements.txt", ecosystem: "pypi", parse: parse_requirements_txt },
    ]
}

/// `true` = exists, `false` = confirmed absent (404), `None` =
/// inconclusive (network/registry error, never treated as a finding).
#[async_trait::async_trait]
pub trait RegistryChecker: Send + Sync {
    async fn exists(&self, ecosystem: &str, name: &str) -> Option<bool>;
}

/// Note observed during real-network verification of this port (not a
/// Rust-vs-JS difference — the JS original doesn't set a custom
/// User-Agent either): crates.io's API returns 403 for a generic/missing
/// User-Agent per its stated data-access policy
/// (https://crates.io/data-access), so the `cargo` ecosystem currently
/// always comes back inconclusive (`None`) in practice rather than a real
/// existence check. `npm`/`pypi` don't have this requirement and work as
/// designed. Left matching the original's behavior rather than adding a
/// UA header unilaterally, since that's a scope decision (what to send as
/// this tool's identity) beyond a mechanical port.
pub struct HttpRegistryChecker {
    client: reqwest::Client,
}

impl Default for HttpRegistryChecker {
    fn default() -> Self {
        HttpRegistryChecker { client: reqwest::Client::new() }
    }
}

#[async_trait::async_trait]
impl RegistryChecker for HttpRegistryChecker {
    async fn exists(&self, ecosystem: &str, name: &str) -> Option<bool> {
        let url = match ecosystem {
            "npm" => format!("https://registry.npmjs.org/{}", urlencode_npm_name(name)),
            "pypi" => format!("https://pypi.org/pypi/{}/json", urlencoding::encode(name)),
            "cargo" => format!("https://crates.io/api/v1/crates/{}", urlencoding::encode(name)),
            _ => return None,
        };
        let result = tokio::time::timeout(Duration::from_secs(5), self.client.get(&url).send()).await;
        match result {
            Ok(Ok(resp)) if resp.status() == reqwest::StatusCode::NOT_FOUND => Some(false),
            Ok(Ok(resp)) if resp.status().is_success() => Some(true),
            _ => None,
        }
    }
}

// npm scoped package names (`@scope/name`) get percent-encoded by
// `encodeURIComponent` in JS, then the JS original explicitly un-encodes
// just the `%40` (`@`) back — npm's registry API wants the literal `@` in
// the URL path, not encoded, for a scoped package.
fn urlencode_npm_name(name: &str) -> String {
    urlencoding::encode(name).replace("%40", "@")
}

#[derive(Debug, Clone, Serialize)]
pub struct HallucinationFinding {
    pub file: String,
    pub line: Option<usize>,
    pub kind: &'static str,
    pub tool: &'static str,
    pub severity: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PackageHallucinationResult {
    pub findings: Vec<HallucinationFinding>,
    pub engine: &'static str,
    pub checked_count: usize,
}

/// process-lifetime cache: registry existence for a given (ecosystem,
/// name) doesn't change meaningfully within a single process's uptime,
/// and — unlike GuardDog's manifest cache — deliberately isn't persisted,
/// since a stale "not found" surviving a restart is exactly the failure
/// mode to avoid.
pub struct PackageHallucinationChecker<C: RegistryChecker> {
    checker: C,
    cache: Mutex<HashMap<String, Option<bool>>>,
}

impl<C: RegistryChecker> PackageHallucinationChecker<C> {
    pub fn new(checker: C) -> Self {
        PackageHallucinationChecker { checker, cache: Mutex::new(HashMap::new()) }
    }

    async fn exists_on_registry(&self, ecosystem: &str, name: &str) -> Option<bool> {
        let key = format!("{ecosystem}:{name}");
        if let Some(cached) = self.cache.lock().unwrap().get(&key) {
            return *cached;
        }
        let result = self.checker.exists(ecosystem, name).await;
        self.cache.lock().unwrap().insert(key, result);
        result
    }

    pub async fn check(&self, root: &Path, enabled: bool, manifests: &[ManifestSpec]) -> std::io::Result<PackageHallucinationResult> {
        if !enabled {
            return Ok(PackageHallucinationResult { findings: vec![], engine: "disabled", checked_count: 0 });
        }

        let mut findings = Vec::new();
        let mut checked_count = 0usize;

        for file in walk_files(root)? {
            let base = file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            let Some(spec) = manifests.iter().find(|m| m.file == base) else { continue };
            let rel = file.strip_prefix(root).unwrap_or(&file).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");

            let Ok(content) = std::fs::read_to_string(&file) else { continue };
            let deps = (spec.parse)(&content);

            for dep in deps {
                if dep.name.is_empty() {
                    continue;
                }
                if let Some(range) = &dep.version_range {
                    if NON_REGISTRY_VERSION_RE.is_match(range) {
                        continue;
                    }
                }
                checked_count += 1;
                let exists = self.exists_on_registry(spec.ecosystem, &dep.name).await;
                if exists == Some(false) {
                    findings.push(HallucinationFinding {
                        file: rel.clone(),
                        line: None,
                        kind: "possible-package-hallucination",
                        tool: "ignite-built-in",
                        severity: "warning",
                        message: format!(
                            "Dependency \"{}\" ({}) was not found on the public registry — possibly an AI-hallucinated package name, vulnerable to squatting. If this is a real private/internal package, this is a false positive.",
                            dep.name, spec.ecosystem
                        ),
                    });
                }
            }
        }

        Ok(PackageHallucinationResult { findings, engine: "built-in", checked_count })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    struct FakeRegistry {
        hallucinated: Vec<&'static str>,
    }
    #[async_trait::async_trait]
    impl RegistryChecker for FakeRegistry {
        async fn exists(&self, _ecosystem: &str, name: &str) -> Option<bool> {
            Some(!self.hallucinated.contains(&name))
        }
    }

    struct AlwaysErrorRegistry;
    #[async_trait::async_trait]
    impl RegistryChecker for AlwaysErrorRegistry {
        async fn exists(&self, _ecosystem: &str, _name: &str) -> Option<bool> {
            None
        }
    }

    #[test]
    fn parse_package_json_reads_both_dependency_fields() {
        let content = r#"{"dependencies": {"express": "^4.0.0"}, "devDependencies": {"jest": "^29.0.0"}}"#;
        let deps = parse_package_json(content);
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().any(|d| d.name == "express"));
        assert!(deps.iter().any(|d| d.name == "jest"));
    }

    #[test]
    fn parse_requirements_txt_skips_comments_and_pip_flags() {
        let content = "# a comment\nrequests==2.31.0\n-e .\nflask>=2.0\n\n";
        let deps = parse_requirements_txt(content);
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "requests");
        assert_eq!(deps[1].name, "flask");
    }

    #[tokio::test]
    async fn flags_a_hallucinated_dependency() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("package.json"), r#"{"dependencies": {"definitely-hallucinated-pkg-xyz": "^1.0.0"}}"#).unwrap();

        let checker = PackageHallucinationChecker::new(FakeRegistry { hallucinated: vec!["definitely-hallucinated-pkg-xyz"] });
        let result = checker.check(root, true, &default_manifests()).await.unwrap();
        assert_eq!(result.findings.len(), 1);
        assert!(result.findings[0].message.contains("definitely-hallucinated-pkg-xyz"));
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[tokio::test]
    async fn real_dependency_is_not_flagged() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("package.json"), r#"{"dependencies": {"express": "^4.0.0"}}"#).unwrap();

        let checker = PackageHallucinationChecker::new(FakeRegistry { hallucinated: vec![] });
        let result = checker.check(root, true, &default_manifests()).await.unwrap();
        assert!(result.findings.is_empty());
        assert_eq!(result.checked_count, 1);
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[tokio::test]
    async fn git_dependency_specifier_is_never_checked() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("package.json"), r#"{"dependencies": {"some-fork": "git+https://github.com/x/y.git"}}"#).unwrap();

        let checker = PackageHallucinationChecker::new(FakeRegistry { hallucinated: vec!["some-fork"] });
        let result = checker.check(root, true, &default_manifests()).await.unwrap();
        assert!(result.findings.is_empty());
        assert_eq!(result.checked_count, 0);
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[tokio::test]
    async fn network_error_is_inconclusive_never_a_finding() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("package.json"), r#"{"dependencies": {"whatever": "^1.0.0"}}"#).unwrap();

        let checker = PackageHallucinationChecker::new(AlwaysErrorRegistry);
        let result = checker.check(root, true, &default_manifests()).await.unwrap();
        assert!(result.findings.is_empty());
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[tokio::test]
    async fn existence_cache_avoids_a_second_lookup_for_the_same_name() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct CountingRegistry(AtomicUsize);
        #[async_trait::async_trait]
        impl RegistryChecker for CountingRegistry {
            async fn exists(&self, _ecosystem: &str, _name: &str) -> Option<bool> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Some(true)
            }
        }
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("package.json"), r#"{"dependencies": {"lodash": "^4.0.0"}, "devDependencies": {"lodash": "^4.0.0"}}"#).unwrap();

        let checker = PackageHallucinationChecker::new(CountingRegistry(AtomicUsize::new(0)));
        let result = checker.check(root, true, &default_manifests()).await.unwrap();
        // dependencies + devDependencies both declare "lodash" - only one
        // real registry lookup should happen thanks to the cache.
        assert_eq!(result.checked_count, 2);
        assert_eq!(checker.checker.0.load(Ordering::SeqCst), 1);
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[tokio::test]
    async fn disabled_returns_no_findings() {
        let dir = tempdir().unwrap();
        let checker = PackageHallucinationChecker::new(FakeRegistry { hallucinated: vec![] });
        let result = checker.check(dir.path(), false, &default_manifests()).await.unwrap();
        assert!(result.findings.is_empty());
        assert_eq!(result.engine, "disabled");
    }
}
