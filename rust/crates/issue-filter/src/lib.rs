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
}
