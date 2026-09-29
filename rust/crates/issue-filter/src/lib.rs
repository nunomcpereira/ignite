//! Faithful port of `lib/issue-filter.js`'s `filterIssuesByChangedFiles` —
//! narrows an issue list to only those touching a given set of files, for
//! `validate-all`'s `changedFiles` param (an agent fix-verify loop's "did
//! the files I just touched get flagged" view). This is a response *view*,
//! never a gate: callers must still resolve/override every issue in the
//! full list for the run to pass.
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

use ignite_override_engine::Issue;
use std::collections::HashSet;

// Issue file paths are always forward-slash-normalized, repo-root-relative
// (no leading `./` or `/`) — see every other crate's `relative_to_root`
// calls. A caller-supplied changed-file path isn't guaranteed to already
// be in that shape (a client tool might emit `./src/main.rs`, or
// Windows-style `src\main.rs`), so it's normalized the same way before the
// set lookup, or every issue for that file silently fails to match.
fn normalize_changed_file(f: &str) -> String {
    let f = f.trim().replace('\\', "/");
    f.strip_prefix("./").unwrap_or(&f).trim_start_matches('/').to_string()
}

pub fn filter_issues_by_changed_files(issues: Vec<Issue>, changed_files: Option<&[String]>) -> Vec<Issue> {
    let Some(changed_files) = changed_files else { return issues };
    let set: HashSet<String> = changed_files.iter().map(|f| normalize_changed_file(f)).filter(|f| !f.is_empty()).collect();
    issues.into_iter().filter(|issue| issue.file.as_deref().is_some_and(|f| set.contains(f))).collect()
}

/// One org/repo-scoped ignore rule from `config.json`'s `ignoreRules` —
/// see [`apply_ignore_rules`]. Both pattern lists are regexes (unanchored
/// search): `file_patterns` against the repo-relative, forward-slash path,
/// `line_patterns` against the flagged source line. Empty `line_patterns`
/// ignores every finding in a matching file; empty `categories` means any.
/// `reason` is the justification recorded on a matched finding.
#[derive(Debug, Clone, Default)]
pub struct IgnoreRule {
    pub file_patterns: Vec<String>,
    pub line_patterns: Vec<String>,
    pub categories: Vec<String>,
    pub reason: String,
}

struct CompiledRule {
    files: Vec<regex::Regex>,
    lines: Vec<regex::Regex>,
    categories: Vec<String>,
    reason: String,
}

fn compile_rules(rules: &[IgnoreRule]) -> (Vec<CompiledRule>, Vec<String>) {
    let mut compiled = Vec::new();
    let mut errors = Vec::new();
    'rules: for rule in rules {
        let mut files = Vec::new();
        for p in rule.file_patterns.iter().filter(|p| !p.trim().is_empty()) {
            match regex::Regex::new(p) {
                Ok(r) => files.push(r),
                Err(e) => {
                    errors.push(format!("invalid file pattern {p:?}: {e}"));
                    continue 'rules;
                }
            }
        }
        let mut lines = Vec::new();
        for p in rule.line_patterns.iter().filter(|p| !p.is_empty()) {
            match regex::Regex::new(p) {
                Ok(r) => lines.push(r),
                Err(e) => {
                    errors.push(format!("invalid line pattern {p:?}: {e}"));
                    continue 'rules;
                }
            }
        }
        // A rule with neither a file nor a line pattern would silence every
        // finding in the org — never what an operator meant.
        if files.is_empty() && lines.is_empty() {
            errors.push("rule has no filePatterns or linePatterns; skipped".to_string());
            continue;
        }
        compiled.push(CompiledRule { files, lines, categories: rule.categories.iter().map(|c| c.trim().to_ascii_lowercase()).collect(), reason: rule.reason.trim().to_string() });
    }
    (compiled, errors)
}

/// Result of [`apply_ignore_rules`]: the unmatched issues, the ones a rule
/// matched (each with the first matching rule's `reason`), and any rule
/// that failed to compile (skipped, never fatal).
pub struct IgnoreOutcome {
    pub kept: Vec<Issue>,
    pub ignored: Vec<(Issue, String)>,
    pub errors: Vec<String>,
}

/// Splits out every issue matched by an org ignore rule: the issue's file must
/// match one of the rule's `file_patterns` (when any), its category one of
/// `categories` (when any), and the flagged source line — read from
/// `root/<file>` at the issue's line — one of `line_patterns` (when any).
/// An issue with line patterns in play but no file/line, or whose line
/// can't be read, is always kept: an ignore rule only ever suppresses
/// something it could positively match.
pub fn apply_ignore_rules(issues: Vec<Issue>, root: &std::path::Path, rules: &[IgnoreRule]) -> IgnoreOutcome {
    let (compiled, errors) = compile_rules(rules);
    if compiled.is_empty() {
        return IgnoreOutcome { kept: issues, ignored: Vec::new(), errors };
    }
    let mut file_lines: std::collections::HashMap<String, Option<Vec<String>>> = std::collections::HashMap::new();
    let mut kept = Vec::new();
    let mut ignored = Vec::new();
    for issue in issues {
        let file = issue.file.as_deref().map(normalize_changed_file);
        let category = issue.category.to_ascii_lowercase();
        let matched = compiled.iter().find(|rule| {
            if !rule.categories.is_empty() && !rule.categories.contains(&category) {
                return false;
            }
            if !rule.files.is_empty() && !file.as_deref().is_some_and(|f| rule.files.iter().any(|r| r.is_match(f))) {
                return false;
            }
            if rule.lines.is_empty() {
                return true;
            }
            let (Some(f), Some(line)) = (file.as_deref(), issue.line) else { return false };
            let lines = file_lines.entry(f.to_string()).or_insert_with(|| {
                std::fs::read(root.join(f)).ok().map(|b| String::from_utf8_lossy(&b).lines().map(str::to_string).collect())
            });
            let Some(text) = lines.as_ref().and_then(|l| l.get(usize::try_from(line).ok()?.checked_sub(1)?)) else { return false };
            rule.lines.iter().any(|r| r.is_match(text))
        });
        if let Some(rule) = matched {
            ignored.push((issue, rule.reason.clone()));
        } else {
            kept.push(issue);
        }
    }
    IgnoreOutcome { kept, ignored, errors }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ignite_override_engine::Severity;

    fn issue(id: &str, file: Option<&str>) -> Issue {
        Issue {
            id: id.to_string(),
            category: "test".to_string(),
            severity: Severity::Warning,
            score: 0,
            summary: "x".to_string(),
            file: file.map(|f| f.to_string()),
            line: None,
            snippet: None,
            cross_file: false,
            chain: None,
            duplicate_ref: None,
            cwe: None,
            owasp: None,
            tool: None,
            references: Default::default(),
            author: None,
        }
    }

    fn sample() -> Vec<Issue> {
        vec![issue("a", Some("src/app.js")), issue("b", Some("src/util.js")), issue("c", None)]
    }

    #[test]
    fn none_returns_unchanged() {
        let result = filter_issues_by_changed_files(sample(), None);
        assert_eq!(result.iter().map(|i| i.id.clone()).collect::<Vec<_>>(), vec!["a", "b", "c"]);
    }

    #[test]
    fn keeps_only_matching_files() {
        let changed = vec!["src/app.js".to_string()];
        let result = filter_issues_by_changed_files(sample(), Some(&changed));
        assert_eq!(result.iter().map(|i| i.id.clone()).collect::<Vec<_>>(), vec!["a"]);
    }

    #[test]
    fn project_wide_issues_always_dropped_when_filtering() {
        let changed = vec!["src/app.js".to_string(), "src/util.js".to_string()];
        let result = filter_issues_by_changed_files(sample(), Some(&changed));
        assert!(!result.iter().any(|i| i.id == "c"));
    }

    #[test]
    fn no_matches_returns_empty() {
        let changed = vec!["no/such/file.js".to_string()];
        let result = filter_issues_by_changed_files(sample(), Some(&changed));
        assert!(result.is_empty());
    }

    #[test]
    fn whitespace_and_empty_entries_ignored() {
        let changed = vec!["src/app.js".to_string(), "".to_string(), "  ".to_string()];
        let result = filter_issues_by_changed_files(sample(), Some(&changed));
        assert_eq!(result.iter().map(|i| i.id.clone()).collect::<Vec<_>>(), vec!["a"]);
    }

    fn at(id: &str, category: &str, file: &str, line: i64) -> Issue {
        let mut i = issue(id, Some(file));
        i.category = category.to_string();
        i.line = Some(line);
        i
    }

    fn sap_rule() -> IgnoreRule {
        IgnoreRule { file_patterns: vec![r"\.txt$".into()], line_patterns: vec!["SAP_IDOC_REC_Credential_Name=(.*)".into()], categories: vec![], reason: String::new() }
    }

    #[test]
    fn ignore_rule_drops_matching_line_in_matching_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("Preparation Steps")).unwrap();
        std::fs::write(dir.path().join("Preparation Steps/A~1.txt"), "a\nb\nc\nd\nSAP_IDOC_REC_Credential_Name=S4DEV_M2C_DEV01\nx\n").unwrap();
        std::fs::write(dir.path().join("app.js"), "a\nb\nc\nd\nSAP_IDOC_REC_Credential_Name=S4DEV\n").unwrap();
        let issues = vec![
            at("a", "secret", "Preparation Steps/A~1.txt", 5),
            at("b", "secret", "Preparation Steps/A~1.txt", 6),
            at("c", "secret", "app.js", 5),
        ];
        let out = apply_ignore_rules(issues, dir.path(), &[sap_rule()]);
        assert_eq!(out.ignored.iter().map(|(i, _)| i.id.as_str()).collect::<Vec<_>>(), vec!["a"]);
        assert_eq!(out.kept.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(), vec!["b", "c"]);
        assert!(out.errors.is_empty());
    }

    #[test]
    fn ignore_rule_respects_categories_and_whole_file_rules() {
        let dir = tempfile::tempdir().unwrap();
        let rule = IgnoreRule { file_patterns: vec![r"^docs/.*\.md$".into()], line_patterns: vec![], categories: vec!["Secret".into()], reason: "docs".into() };
        let issues = vec![at("a", "secret", "docs/x/y.md", 1), at("b", "security", "docs/y.md", 1), at("c", "secret", "src/docs/y.md", 1)];
        let out = apply_ignore_rules(issues, dir.path(), &[rule]);
        assert_eq!(out.ignored.iter().map(|(i, _)| i.id.as_str()).collect::<Vec<_>>(), vec!["a"]);
        assert_eq!(out.ignored[0].1, "docs");
    }

    #[test]
    fn invalid_or_empty_rules_are_skipped_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let rules = [IgnoreRule { file_patterns: vec![r"\.txt$".into()], line_patterns: vec!["(".into()], categories: vec![], reason: String::new() }, IgnoreRule::default()];
        let out = apply_ignore_rules(vec![at("a", "secret", "a.txt", 1)], dir.path(), &rules);
        assert_eq!(out.kept.len(), 1);
        assert_eq!(out.errors.len(), 2);
    }
}
