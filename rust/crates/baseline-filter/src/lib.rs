//! Faithful port of `lib/baseline-filter.js`'s `filterIssuesByBaseline` —
//! narrows an issue list to only those NOT already accepted into a
//! project's baseline (diff-adoption mode). Mirrors `ignite-issue-filter`'s
//! shape deliberately: same "view, not a gate" caveat — the caller must
//! still apply `baselineMode` handling for this to actually affect
//! pass/fail.

use ignite_override_engine::Issue;
use std::collections::HashSet;

pub fn filter_issues_by_baseline(issues: Vec<Issue>, baseline_issue_ids: Option<&HashSet<String>>) -> Vec<Issue> {
    let Some(baseline) = baseline_issue_ids else { return issues };
    if baseline.is_empty() {
        return issues;
    }
    issues.into_iter().filter(|issue| !baseline.contains(&issue.id)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ignite_override_engine::Severity;

    fn issue(id: &str) -> Issue {
        Issue { id: id.to_string(), category: "test".to_string(), severity: Severity::Warning, score: 0, summary: "x".to_string(), file: None, line: None, snippet: None, cross_file: false, chain: None, duplicate_ref: None, cwe: None, owasp: None }
    }

    #[test]
    fn none_returns_unchanged() {
        let issues = vec![issue("a"), issue("b")];
        let result = filter_issues_by_baseline(issues.clone(), None);
        assert_eq!(result.iter().map(|i| i.id.clone()).collect::<Vec<_>>(), vec!["a", "b"]);
    }

    #[test]
    fn empty_baseline_returns_unchanged() {
        let issues = vec![issue("a"), issue("b")];
        let result = filter_issues_by_baseline(issues.clone(), Some(&HashSet::new()));
        assert_eq!(result.iter().map(|i| i.id.clone()).collect::<Vec<_>>(), vec!["a", "b"]);
    }

    #[test]
    fn drops_baselined_ids() {
        let issues = vec![issue("a"), issue("b"), issue("c")];
        let baseline: HashSet<String> = ["a".to_string(), "c".to_string()].into_iter().collect();
        let result = filter_issues_by_baseline(issues, Some(&baseline));
        assert_eq!(result.iter().map(|i| i.id.clone()).collect::<Vec<_>>(), vec!["b"]);
    }
}
