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

static REQUIREMENTS_LINE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^([A-Za-z0-9_.\-]+)\s*([=<>!~]{1,2}\s*[0-9A-Za-z.*+\-]+)?").unwrap());
static WHITESPACE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\s+").unwrap());

pub fn parse_requirements_txt_deps(content: &str) -> Vec<ManifestDep> {
    content
        .split('\n')
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with('-'))
        .filter_map(|l| REQUIREMENTS_LINE_RE.captures(l).map(|m| ManifestDep { name: m[1].to_string(), version_range: m.get(2).map(|v| WHITESPACE_RE.replace_all(v.as_str(), "").into_owned()).unwrap_or_default() }))
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
}
