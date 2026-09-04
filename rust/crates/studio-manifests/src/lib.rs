//! The 5-ecosystem manifest parsers server.js's dependency license/
//! vulnerability scanning (STUDIO_MANIFESTS) uses — distinct from
//! `ignite-package-hallucination`'s own npm/PyPI-only parsers, which are a
//! separate JS module (`checks/package-hallucination.js`) with slightly
//! different regexes for a different purpose. Faithful port of
//! server.js's `parsePackageJsonDeps`/`parseCargoTomlDeps`/
//! `parseRequirementsTxtDeps`/`parseGoModDeps`/`parsePomXmlDeps` and the
//! `STUDIO_MANIFESTS` table.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManifestDep {
    pub name: String,
    pub version_range: String,
}

pub fn parse_package_json_deps(content: &str) -> Vec<ManifestDep> {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(content) else { return vec![] };
    let mut deps = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for field in ["dependencies", "devDependencies"] {
        if let Some(obj) = json.get(field).and_then(|d| d.as_object()) {
            for (name, range) in obj {
                if seen.insert(name.clone()) {
                    deps.push(ManifestDep { name: name.clone(), version_range: range.as_str().map(String::from).unwrap_or_else(|| range.to_string()) });
                } else if let Some(existing) = deps.iter_mut().find(|d: &&mut ManifestDep| &d.name == name) {
                    // devDependencies spread after dependencies in the JS
                    // object-spread merge overwrites a same-named key.
                    existing.version_range = range.as_str().map(String::from).unwrap_or_else(|| range.to_string());
                }
            }
        }
    }
    deps
}

static CARGO_SECTION_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\[.*\]$").unwrap());
static CARGO_DEPS_SECTION_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\[(dependencies|dev-dependencies|build-dependencies)\]$").unwrap());
static CARGO_LINE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^([A-Za-z0-9_-]+)\s*=\s*(.+)$").unwrap());
static CARGO_VERSION_KV_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"version\s*=\s*"([^"]+)""#).unwrap());
static CARGO_VERSION_BARE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"^"([^"]+)""#).unwrap());

pub fn parse_cargo_toml_deps(content: &str) -> Vec<ManifestDep> {
    let mut deps = Vec::new();
    let mut in_deps = false;
    for raw_line in content.split('\n') {
        let line = raw_line.trim();
        if CARGO_SECTION_RE.is_match(line) {
            in_deps = CARGO_DEPS_SECTION_RE.is_match(line);
            continue;
        }
        if !in_deps || line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(m) = CARGO_LINE_RE.captures(line) else { continue };
        let rest = &m[2];
        let version = CARGO_VERSION_KV_RE.captures(rest).or_else(|| CARGO_VERSION_BARE_RE.captures(rest)).map(|c| c[1].to_string()).unwrap_or_else(|| rest.trim().to_string());
        deps.push(ManifestDep { name: m[1].to_string(), version_range: version });
    }
    deps
}

// `[A-Za-z0-9_.\-]+` is the package name; an optional PEP 508 extras
// marker (`[security]`, `[standard,extra]`) can sit between the name and
// the version specifier (e.g. `requests[security]>=2.31.0`) and must be
// skipped, not swallowed into either capture group, or the version spec
// after it silently fails to match and `version_range` comes back empty.
// Operator is 1-3 chars to also cover PEP 440's `===` (arbitrary
// equality), not just the 1-2 char `==`/`>=`/`<=`/`!=`/`~=` forms.
static REQUIREMENTS_LINE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*([=<>!~]{1,3}\s*[0-9A-Za-z.*+\-]+)?").unwrap());

pub fn parse_requirements_txt_deps(content: &str) -> Vec<ManifestDep> {
    content
        .split('\n')
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with('-'))
        // `version_range` must stay exactly the substring that appears in
        // the manifest line (not whitespace-stripped) — auto-fix-pr's
        // `apply_fix_to_content` finds-and-replaces this exact string in
        // the raw file content, and a normalized "==1.2.3" doesn't occur
        // literally in a line written as "requests == 1.2.3", silently
        // failing to match and skipping the fix.
        .filter_map(|l| REQUIREMENTS_LINE_RE.captures(l).map(|m| ManifestDep { name: m[1].to_string(), version_range: m.get(2).map(|v| v.as_str().to_string()).unwrap_or_default() }))
        .collect()
}

static GO_REQUIRE_BLOCK_START_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^require\s*\($").unwrap());
static GO_REQUIRE_SINGLE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^require\s+(\S+)\s+(\S+)").unwrap());
static GO_TWO_TOKEN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^(\S+)\s+(\S+)").unwrap());

pub fn parse_go_mod_deps(content: &str) -> Vec<ManifestDep> {
    let mut deps = Vec::new();
    let mut in_require = false;
    for raw_line in content.split('\n') {
        let line = raw_line.trim();
        if GO_REQUIRE_BLOCK_START_RE.is_match(line) {
            in_require = true;
            continue;
        }
        if in_require && line == ")" {
            in_require = false;
            continue;
        }
        if let Some(m) = GO_REQUIRE_SINGLE_RE.captures(line) {
            deps.push(ManifestDep { name: m[1].to_string(), version_range: m[2].to_string() });
            continue;
        }
        if in_require && !line.starts_with("//") {
            if let Some(m) = GO_TWO_TOKEN_RE.captures(line) {
                deps.push(ManifestDep { name: m[1].to_string(), version_range: m[2].to_string() });
            }
        }
    }
    deps
}

static POM_DEPENDENCY_BLOCK_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?s)<dependency>.*?</dependency>").unwrap());
static POM_GROUP_ID_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"<groupId>([^<]+)</groupId>").unwrap());
static POM_ARTIFACT_ID_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"<artifactId>([^<]+)</artifactId>").unwrap());
static POM_VERSION_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"<version>([^<]+)</version>").unwrap());

pub fn parse_pom_xml_deps(content: &str) -> Vec<ManifestDep> {
    let mut deps = Vec::new();
    for block in POM_DEPENDENCY_BLOCK_RE.find_iter(content) {
        let block = block.as_str();
        let group_id = POM_GROUP_ID_RE.captures(block).map(|m| m[1].trim().to_string());
        let artifact_id = POM_ARTIFACT_ID_RE.captures(block).map(|m| m[1].trim().to_string());
        let version = POM_VERSION_RE.captures(block).map(|m| m[1].trim().to_string()).unwrap_or_default();
        if let (Some(group_id), Some(artifact_id)) = (group_id, artifact_id) {
            deps.push(ManifestDep { name: format!("{}:{}", group_id, artifact_id), version_range: version });
        }
    }
    deps
}

pub struct StudioManifestSpec {
    pub file: &'static str,
    pub ecosystem: &'static str,
    pub system: &'static str,
    pub parse: fn(&str) -> Vec<ManifestDep>,
}

pub const STUDIO_MAX_DEPS_PER_MANIFEST: usize = 60;

pub fn studio_manifests() -> &'static [StudioManifestSpec] {
    static MANIFESTS: &[StudioManifestSpec] = &[
        StudioManifestSpec { file: "package.json", ecosystem: "npm", system: "NPM", parse: parse_package_json_deps },
        StudioManifestSpec { file: "Cargo.toml", ecosystem: "cargo", system: "CARGO", parse: parse_cargo_toml_deps },
        StudioManifestSpec { file: "requirements.txt", ecosystem: "pypi", system: "PYPI", parse: parse_requirements_txt_deps },
        StudioManifestSpec { file: "go.mod", ecosystem: "go", system: "GO", parse: parse_go_mod_deps },
        StudioManifestSpec { file: "pom.xml", ecosystem: "maven", system: "MAVEN", parse: parse_pom_xml_deps },
    ];
    MANIFESTS
}

// --- Lockfiles -------------------------------------------------------
//
// A manifest's declared range (`^1.2.3`, `>=1.11`, ...) only says what's
// *permitted* — it can't say what's actually installed. When a lockfile
// is present it pins the real resolved version per dependency, which is
// strictly better than guessing a representative version out of the
// range (see `ignite-dependency-license-scan`'s callers, which prefer a
// lockfile hit over `best_effort_version`/`resolve_best_published_version`
// whenever one exists). Parsing is line/regex-based, tolerant of the
// exact same way every manifest parser above is — not a full TOML/YAML/
// JSON-schema implementation, just enough structure to pull out
// `name -> exact version` pairs.

static PACKAGE_LOCK_NODE_MODULES_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^(?:.*/)?node_modules/((?:@[^/]+/)?[^/]+)$").unwrap());

/// npm's `package-lock.json`/`npm-shrinkwrap.json`. Supports both the v2/v3
/// shape (flat `packages` map keyed by node_modules path, e.g.
/// `"node_modules/lodash"`) and the older v1 shape (nested `dependencies`
/// map keyed directly by package name).
pub fn parse_package_lock_json_versions(content: &str) -> HashMap<String, String> {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(content) else { return HashMap::new() };
    let mut result = HashMap::new();
    if let Some(packages) = json.get("packages").and_then(|p| p.as_object()) {
        // `serde_json::Value`'s object map iterates in key-sorted (not
        // insertion) order by default, so a deeply-nested override (e.g.
        // "node_modules/foo/node_modules/lodash") can sort before the
        // top-level hoisted package ("node_modules/lodash") — depth is
        // tracked explicitly and the shallowest entry wins, rather than
        // trusting whichever happened to be seen first.
        let mut best_depth: HashMap<String, usize> = HashMap::new();
        for (path, info) in packages {
            if path.is_empty() {
                continue; // the project root itself, not a dependency
            }
            let Some(name) = PACKAGE_LOCK_NODE_MODULES_RE.captures(path).map(|m| m[1].to_string()) else { continue };
            let Some(version) = info.get("version").and_then(|v| v.as_str()) else { continue };
            let depth = path.matches("node_modules/").count();
            if best_depth.get(&name).is_none_or(|&d| depth < d) {
                best_depth.insert(name.clone(), depth);
                result.insert(name, version.to_string());
            }
        }
    } else if let Some(deps) = json.get("dependencies").and_then(|d| d.as_object()) {
        for (name, info) in deps {
            if let Some(version) = info.get("version").and_then(|v| v.as_str()) {
                result.entry(name.clone()).or_insert_with(|| version.to_string());
            }
        }
    }
    result
}

fn yarn_lock_entry_name(token: &str) -> Option<String> {
    let token = token.trim().trim_matches('"');
    if let Some(rest) = token.strip_prefix('@') {
        let at_pos = rest.find('@')?;
        Some(format!("@{}", &rest[..at_pos]))
    } else {
        let at_pos = token.find('@')?;
        Some(token[..at_pos].to_string())
    }
}

/// Classic (`version "1.2.3"`) and Berry (`version: 1.2.3`) `yarn.lock`
/// block formats. Each block's header line lists one or more
/// comma-separated `"name@range"` descriptors sharing the block's single
/// resolved version.
pub fn parse_yarn_lock_versions(content: &str) -> HashMap<String, String> {
    let mut result = HashMap::new();
    let mut current_names: Vec<String> = Vec::new();
    for raw_line in content.split('\n') {
        if raw_line.starts_with('#') || raw_line.trim().is_empty() {
            continue;
        }
        if !raw_line.starts_with(' ') && !raw_line.starts_with('\t') {
            current_names = raw_line.trim().trim_end_matches(':').split(',').filter_map(yarn_lock_entry_name).collect();
            continue;
        }
        if current_names.is_empty() {
            continue;
        }
        let trimmed = raw_line.trim();
        let version = trimmed.strip_prefix("version ").or_else(|| trimmed.strip_prefix("version:")).map(|v| v.trim().trim_matches('"').to_string());
        if let Some(version) = version {
            for name in current_names.drain(..) {
                result.entry(name).or_insert_with(|| version.clone());
            }
        }
    }
    result
}

static PNPM_PACKAGE_LINE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"^\s*['"]?/?((?:@[^/@'"]+/)?[^@'"()]+)@([0-9][^'"()]*?)['"]?(?:\([^)]*\))?:\s*$"#).unwrap());

/// `pnpm-lock.yaml`'s `packages:` (and, in v9+, `snapshots:`) section keys
/// package descriptors as `name@version:` (older versions prefix a `/`;
/// scoped names may be single-quoted since they start with `@`). A
/// peer-dependency hash can be suffixed directly onto the version with an
/// underscore (`1.2.3_react@18.0.0`) — split it off to keep just the real
/// published version.
pub fn parse_pnpm_lock_yaml_versions(content: &str) -> HashMap<String, String> {
    let mut result = HashMap::new();
    for line in content.split('\n') {
        if let Some(m) = PNPM_PACKAGE_LINE_RE.captures(line) {
            let name = m[1].to_string();
            let version = m[2].split('_').next().unwrap_or("").to_string();
            if !version.is_empty() {
                result.entry(name).or_insert(version);
            }
        }
    }
    result
}

static CARGO_LOCK_NAME_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"^name\s*=\s*"([^"]+)"$"#).unwrap());
static CARGO_LOCK_VERSION_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"^version\s*=\s*"([^"]+)"$"#).unwrap());

/// `Cargo.lock`'s `[[package]]` blocks. When a crate appears more than
/// once at different semver-incompatible versions (legal in Cargo, and
/// not uncommon), only the first occurrence is kept — a best-effort
/// improvement over range-guessing, not a guarantee of picking the exact
/// instance a given `Cargo.toml` line resolves to.
pub fn parse_cargo_lock_versions(content: &str) -> HashMap<String, String> {
    let mut result = HashMap::new();
    let mut current_name: Option<String> = None;
    for raw_line in content.split('\n') {
        let line = raw_line.trim();
        if line == "[[package]]" {
            current_name = None;
            continue;
        }
        if let Some(m) = CARGO_LOCK_NAME_RE.captures(line) {
            current_name = Some(m[1].to_string());
            continue;
        }
        if let Some(m) = CARGO_LOCK_VERSION_RE.captures(line) {
            if let Some(name) = &current_name {
                result.entry(name.clone()).or_insert_with(|| m[1].to_string());
            }
        }
    }
    result
}

pub struct LockfileSpec {
    pub file: &'static str,
    pub ecosystem: &'static str,
    pub parse: fn(&str) -> HashMap<String, String>,
}

/// Priority order matters within one ecosystem: only the first lockfile
/// that both exists and parses to a non-empty map is used (see
/// `ignite-dependency-license-scan`'s lookup) — a repo normally has just
/// one, but if more than one npm lockfile is present, `package-lock.json`
/// is the most common/canonical and wins.
pub fn lockfile_specs() -> &'static [LockfileSpec] {
    static SPECS: &[LockfileSpec] = &[
        LockfileSpec { file: "package-lock.json", ecosystem: "npm", parse: parse_package_lock_json_versions },
        LockfileSpec { file: "npm-shrinkwrap.json", ecosystem: "npm", parse: parse_package_lock_json_versions },
        LockfileSpec { file: "yarn.lock", ecosystem: "npm", parse: parse_yarn_lock_versions },
        LockfileSpec { file: "pnpm-lock.yaml", ecosystem: "npm", parse: parse_pnpm_lock_yaml_versions },
        LockfileSpec { file: "Cargo.lock", ecosystem: "cargo", parse: parse_cargo_lock_versions },
    ];
    SPECS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_package_json_deps_merges_dependencies_and_dev_dependencies() {
        let content = r#"{"dependencies": {"express": "^4.0.0"}, "devDependencies": {"jest": "^29.0.0"}}"#;
        let deps = parse_package_json_deps(content);
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().any(|d| d.name == "express" && d.version_range == "^4.0.0"));
        assert!(deps.iter().any(|d| d.name == "jest" && d.version_range == "^29.0.0"));
    }

    #[test]
    fn parse_package_json_deps_dev_overwrites_same_named_dependency() {
        // Mirrors JS's { ...dependencies, ...devDependencies } spread —
        // a same-named key in devDependencies wins.
        let content = r#"{"dependencies": {"foo": "1.0.0"}, "devDependencies": {"foo": "2.0.0"}}"#;
        let deps = parse_package_json_deps(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].version_range, "2.0.0");
    }

    #[test]
    fn parse_package_json_deps_returns_empty_on_invalid_json() {
        assert!(parse_package_json_deps("not json").is_empty());
    }

    #[test]
    fn parse_cargo_toml_deps_reads_dependencies_sections_only() {
        let content = "[package]\nname = \"foo\"\n\n[dependencies]\nserde = { version = \"1.0\", features = [\"derive\"] }\ntokio = \"1.28\"\n\n[dev-dependencies]\ntempfile = \"3\"\n";
        let deps = parse_cargo_toml_deps(content);
        assert_eq!(deps.len(), 3);
        assert!(deps.iter().any(|d| d.name == "serde" && d.version_range == "1.0"));
        assert!(deps.iter().any(|d| d.name == "tokio" && d.version_range == "1.28"));
        assert!(deps.iter().any(|d| d.name == "tempfile" && d.version_range == "3"));
    }

    #[test]
    fn parse_requirements_txt_deps_skips_comments_flags_and_blank_lines() {
        let content = "# a comment\nrequests==2.31.0\n-e .\nflask>=2.0\n\nnumpy\n";
        let deps = parse_requirements_txt_deps(content);
        assert_eq!(deps.len(), 3);
        assert_eq!(deps[0], ManifestDep { name: "requests".to_string(), version_range: "==2.31.0".to_string() });
        assert_eq!(deps[1], ManifestDep { name: "flask".to_string(), version_range: ">=2.0".to_string() });
        assert_eq!(deps[2], ManifestDep { name: "numpy".to_string(), version_range: String::new() });
    }

    #[test]
    fn parse_requirements_txt_deps_handles_extras_marker_before_version() {
        // PEP 508 extras (`pkg[extra1,extra2]>=1.0`) sit between the name
        // and the version specifier — a naive regex swallows the `[...]`
        // into neither group and drops the version entirely.
        let content = "requests[security]>=2.31.0\nuvicorn[standard]==0.23.0\ncelery[redis,auth]\n";
        let deps = parse_requirements_txt_deps(content);
        assert_eq!(deps.len(), 3);
        assert_eq!(deps[0], ManifestDep { name: "requests".to_string(), version_range: ">=2.31.0".to_string() });
        assert_eq!(deps[1], ManifestDep { name: "uvicorn".to_string(), version_range: "==0.23.0".to_string() });
        assert_eq!(deps[2], ManifestDep { name: "celery".to_string(), version_range: String::new() });
    }

    #[test]
    fn parse_requirements_txt_deps_handles_common_specifier_variants() {
        let content = "flask~=2.0\nnumpy!=1.19.0\ndjango<=4.2\npytest>3.0\ntyping-extensions===4.5.0\n";
        let deps = parse_requirements_txt_deps(content);
        assert_eq!(deps.len(), 5);
        assert_eq!(deps[0], ManifestDep { name: "flask".to_string(), version_range: "~=2.0".to_string() });
        assert_eq!(deps[1], ManifestDep { name: "numpy".to_string(), version_range: "!=1.19.0".to_string() });
        assert_eq!(deps[2], ManifestDep { name: "django".to_string(), version_range: "<=4.2".to_string() });
        assert_eq!(deps[3], ManifestDep { name: "pytest".to_string(), version_range: ">3.0".to_string() });
        assert_eq!(deps[4], ManifestDep { name: "typing-extensions".to_string(), version_range: "===4.5.0".to_string() });
    }

    #[test]
    fn parse_cargo_toml_deps_handles_caret_tilde_and_comparison_ranges() {
        let content = "[dependencies]\na = \"^1.2.3\"\nb = \"~1.2\"\nc = \">=1.0, <2.0\"\nd = \"*\"\n";
        let deps = parse_cargo_toml_deps(content);
        assert_eq!(deps.len(), 4);
        assert_eq!(deps[0], ManifestDep { name: "a".to_string(), version_range: "^1.2.3".to_string() });
        assert_eq!(deps[1], ManifestDep { name: "b".to_string(), version_range: "~1.2".to_string() });
        assert_eq!(deps[2], ManifestDep { name: "c".to_string(), version_range: ">=1.0, <2.0".to_string() });
        assert_eq!(deps[3], ManifestDep { name: "d".to_string(), version_range: "*".to_string() });
    }

    #[test]
    fn parse_package_json_deps_handles_range_and_tag_specifiers() {
        let content = r#"{"dependencies": {"a": ">=1.2.3 <2.0.0", "b": "1.2.3 - 2.3.4", "c": "1.2.x", "d": "*", "e": "latest"}}"#;
        let deps = parse_package_json_deps(content);
        assert_eq!(deps.len(), 5);
        assert!(deps.iter().any(|d| d.name == "a" && d.version_range == ">=1.2.3 <2.0.0"));
        assert!(deps.iter().any(|d| d.name == "b" && d.version_range == "1.2.3 - 2.3.4"));
        assert!(deps.iter().any(|d| d.name == "c" && d.version_range == "1.2.x"));
        assert!(deps.iter().any(|d| d.name == "d" && d.version_range == "*"));
        assert!(deps.iter().any(|d| d.name == "e" && d.version_range == "latest"));
    }

    #[test]
    fn parse_go_mod_deps_reads_single_line_and_block_requires() {
        let content = "module example.com/foo\n\nrequire github.com/pkg/errors v0.9.1\n\nrequire (\n\tgithub.com/stretchr/testify v1.8.4\n\t// a comment\n\tgolang.org/x/sync v0.5.0\n)\n";
        let deps = parse_go_mod_deps(content);
        assert_eq!(deps.len(), 3);
        assert!(deps.iter().any(|d| d.name == "github.com/pkg/errors" && d.version_range == "v0.9.1"));
        assert!(deps.iter().any(|d| d.name == "github.com/stretchr/testify" && d.version_range == "v1.8.4"));
        assert!(deps.iter().any(|d| d.name == "golang.org/x/sync" && d.version_range == "v0.5.0"));
    }

    #[test]
    fn parse_pom_xml_deps_extracts_group_artifact_version() {
        let content = "<project>\n  <dependencies>\n    <dependency>\n      <groupId>com.google.guava</groupId>\n      <artifactId>guava</artifactId>\n      <version>32.1.3-jre</version>\n    </dependency>\n  </dependencies>\n</project>\n";
        let deps = parse_pom_xml_deps(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "com.google.guava:guava");
        assert_eq!(deps[0].version_range, "32.1.3-jre");
    }

    #[test]
    fn parse_pom_xml_deps_skips_dependency_missing_group_or_artifact() {
        let content = "<dependency><artifactId>orphan</artifactId></dependency>";
        assert!(parse_pom_xml_deps(content).is_empty());
    }

    #[test]
    fn studio_manifests_covers_five_ecosystems() {
        let files: Vec<&str> = studio_manifests().iter().map(|m| m.file).collect();
        assert_eq!(files, vec!["package.json", "Cargo.toml", "requirements.txt", "go.mod", "pom.xml"]);
    }

    #[test]
    fn parse_package_lock_json_versions_reads_v3_packages_map() {
        let content = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "root", "version": "0.0.0"},
                "node_modules/lodash": {"version": "4.17.21"},
                "node_modules/@babel/core": {"version": "7.20.0"},
                "node_modules/foo/node_modules/lodash": {"version": "3.10.1"}
            }
        }"#;
        let versions = parse_package_lock_json_versions(content);
        assert_eq!(versions.get("lodash"), Some(&"4.17.21".to_string()));
        assert_eq!(versions.get("@babel/core"), Some(&"7.20.0".to_string()));
        assert!(!versions.contains_key("root"));
    }

    #[test]
    fn parse_package_lock_json_versions_reads_v1_dependencies_map() {
        let content = r#"{"lockfileVersion": 1, "dependencies": {"lodash": {"version": "4.17.21"}}}"#;
        let versions = parse_package_lock_json_versions(content);
        assert_eq!(versions.get("lodash"), Some(&"4.17.21".to_string()));
    }

    #[test]
    fn parse_yarn_lock_versions_reads_classic_and_berry_formats() {
        let content = "\"@babel/code-frame@^7.0.0\", \"@babel/code-frame@^7.12.13\":\n  version \"7.12.13\"\n  resolved \"...\"\n\nlodash@^4.17.21:\n  version \"4.17.21\"\n\nreact@^18.0.0:\n  version: 18.2.0\n";
        let versions = parse_yarn_lock_versions(content);
        assert_eq!(versions.get("@babel/code-frame"), Some(&"7.12.13".to_string()));
        assert_eq!(versions.get("lodash"), Some(&"4.17.21".to_string()));
        assert_eq!(versions.get("react"), Some(&"18.2.0".to_string()));
    }

    #[test]
    fn parse_pnpm_lock_yaml_versions_reads_packages_section() {
        let content = "packages:\n\n  /lodash@4.17.21:\n    resolution: {integrity: sha512-x}\n\n  '@babel/core@7.20.0':\n    resolution: {integrity: sha512-y}\n\n  react@18.2.0_react-dom@18.2.0:\n    resolution: {integrity: sha512-z}\n";
        let versions = parse_pnpm_lock_yaml_versions(content);
        assert_eq!(versions.get("lodash"), Some(&"4.17.21".to_string()));
        assert_eq!(versions.get("@babel/core"), Some(&"7.20.0".to_string()));
        assert_eq!(versions.get("react"), Some(&"18.2.0".to_string()));
    }

    #[test]
    fn parse_cargo_lock_versions_reads_package_blocks() {
        let content = "# auto-generated\nversion = 3\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.210\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"tokio\"\nversion = \"1.28.0\"\n";
        let versions = parse_cargo_lock_versions(content);
        assert_eq!(versions.get("serde"), Some(&"1.0.210".to_string()));
        assert_eq!(versions.get("tokio"), Some(&"1.28.0".to_string()));
    }

    #[test]
    fn lockfile_specs_covers_npm_and_cargo() {
        let files: Vec<&str> = lockfile_specs().iter().map(|s| s.file).collect();
        assert_eq!(files, vec!["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "Cargo.lock"]);
    }
}
