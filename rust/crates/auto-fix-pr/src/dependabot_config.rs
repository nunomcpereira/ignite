//! Parses `.github/dependabot.yml`'s `ignore:` rules — Dependabot config
//! parity for `auto-fix-pr`: a dependency (or specific versions of it)
//! this repo has already told Dependabot never to touch should be
//! respected by Ignite's own auto-fix bot too, not silently overridden.
//! `dependabot.yml` also supports per-`directory:` monorepo targeting,
//! custom schedules, and private-registry credentials — deliberately
//! **not** handled here: `directory:`-scoped targeting needs no separate
//! code since [`ignite_fs_utils::walk_files`] already recurses the whole
//! repo tree and finds every manifest regardless of which subdirectory
//! it's in; schedule/target-branch have no auto-fix-pr equivalent to
//! respect; and private-registry credentials are a security-sensitive
//! feature (secret storage, scoped access) deliberately left for a
//! separate, more careful pass.

use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct DependabotFile {
    #[serde(default)]
    updates: Vec<DependabotUpdate>,
}

#[derive(Debug, Deserialize)]
struct DependabotUpdate {
    #[serde(rename = "package-ecosystem")]
    package_ecosystem: String,
    #[serde(default)]
    ignore: Vec<DependabotIgnoreRule>,
}

#[derive(Debug, Deserialize)]
struct DependabotIgnoreRule {
    #[serde(rename = "dependency-name")]
    dependency_name: String,
}

/// Dependabot's own documented `package-ecosystem` values, mapped onto
/// `ignite-studio-manifests`' ecosystem tags. Ecosystems this codebase
/// doesn't resolve dependencies for at all (`docker`, `github-actions`,
/// `terraform`, `bundler`, `composer`, ...) are never matched — an
/// ignore rule for one of those has nothing to suppress here anyway.
fn ecosystem_tag(package_ecosystem: &str) -> Option<&'static str> {
    match package_ecosystem {
        "npm" => Some("npm"),
        "pip" => Some("pypi"),
        "cargo" => Some("cargo"),
        "gomod" => Some("go"),
        "maven" => Some("maven"),
        "gradle" => Some("gradle"),
        "nuget" => Some("nuget"),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgnoreRule {
    pub ecosystem: &'static str,
    /// Dependabot's own `dependency-name` glob syntax — a single optional
    /// `*` wildcard, everything else matched literally.
    pub dependency_name: String,
}

/// Simple glob match for Dependabot's `dependency-name` pattern syntax —
/// at most one `*` wildcard (matching any run of characters), not a full
/// glob/regex engine. A pattern with no `*` requires an exact match.
fn glob_match(pattern: &str, name: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == name,
        Some((prefix, suffix)) => name.len() >= prefix.len() + suffix.len() && name.starts_with(prefix) && name.ends_with(suffix),
    }
}

/// `true` if `dep_name` (in `ecosystem`) matches any parsed ignore rule.
/// Dependabot's own `versions:` sub-key (ignore only specific version
/// ranges of a dependency) is deliberately not range-matched here — a
/// rule naming specific versions still suppresses the dependency
/// entirely, a conservative over-suppression rather than risking
/// under-suppression from a wrong range-syntax parse of Dependabot's own
/// version-constraint mini-DSL.
pub fn is_ignored(rules: &[IgnoreRule], ecosystem: &str, dep_name: &str) -> bool {
    rules.iter().any(|r| r.ecosystem == ecosystem && glob_match(&r.dependency_name, dep_name))
}

pub fn parse_dependabot_ignore_rules(content: &str) -> Vec<IgnoreRule> {
    let Ok(file) = serde_yaml::from_str::<DependabotFile>(content) else { return vec![] };
    let mut rules = Vec::new();
    for update in file.updates {
        let Some(ecosystem) = ecosystem_tag(&update.package_ecosystem) else { continue };
        for rule in update.ignore {
            rules.push(IgnoreRule { ecosystem, dependency_name: rule.dependency_name });
        }
    }
    rules
}

/// Reads and parses `.github/dependabot.yml` (or the less common `.yaml`
/// extension) at `repo_root`, if present. Empty (not an error) when
/// neither file exists, or the file doesn't parse as the expected
/// shape — a malformed or exotic `dependabot.yml` degrades to "no ignore
/// rules known" rather than failing the whole fix-discovery run over it.
pub fn load_dependabot_ignore_rules(repo_root: &Path) -> Vec<IgnoreRule> {
    for name in [".github/dependabot.yml", ".github/dependabot.yaml"] {
        if let Ok(content) = std::fs::read_to_string(repo_root.join(name)) {
            return parse_dependabot_ignore_rules(&content);
        }
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dependabot_ignore_rules_reads_ignore_entries_by_ecosystem() {
        let yaml = r#"
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    ignore:
      - dependency-name: "aws-sdk"
      - dependency-name: "lodash*"
  - package-ecosystem: "docker"
    directory: "/"
    ignore:
      - dependency-name: "node"
"#;
        let rules = parse_dependabot_ignore_rules(yaml);
        assert_eq!(rules.len(), 2, "the docker ecosystem entry should be skipped — Ignite doesn't resolve Docker base-image deps");
        assert!(rules.contains(&IgnoreRule { ecosystem: "npm", dependency_name: "aws-sdk".to_string() }));
        assert!(rules.contains(&IgnoreRule { ecosystem: "npm", dependency_name: "lodash*".to_string() }));
    }

    #[test]
    fn parse_dependabot_ignore_rules_empty_for_malformed_yaml() {
        assert!(parse_dependabot_ignore_rules("not: valid: yaml: [").is_empty());
        assert!(parse_dependabot_ignore_rules("").is_empty());
    }

    #[test]
    fn is_ignored_matches_exact_and_wildcard_names_scoped_to_ecosystem() {
        let rules = vec![IgnoreRule { ecosystem: "npm", dependency_name: "aws-sdk".to_string() }, IgnoreRule { ecosystem: "npm", dependency_name: "@babel/*".to_string() }];
        assert!(is_ignored(&rules, "npm", "aws-sdk"));
        assert!(is_ignored(&rules, "npm", "@babel/core"));
        assert!(!is_ignored(&rules, "npm", "lodash"));
        assert!(!is_ignored(&rules, "cargo", "aws-sdk"), "a rule for one ecosystem must not suppress the same name in another");
    }

    #[test]
    fn load_dependabot_ignore_rules_empty_when_file_absent() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_dependabot_ignore_rules(dir.path()).is_empty());
    }

    #[test]
    fn load_dependabot_ignore_rules_reads_the_real_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".github")).unwrap();
        std::fs::write(dir.path().join(".github/dependabot.yml"), "version: 2\nupdates:\n  - package-ecosystem: \"cargo\"\n    directory: \"/\"\n    ignore:\n      - dependency-name: \"openssl\"\n").unwrap();
        let rules = load_dependabot_ignore_rules(dir.path());
        assert_eq!(rules, vec![IgnoreRule { ecosystem: "cargo", dependency_name: "openssl".to_string() }]);
    }
}
