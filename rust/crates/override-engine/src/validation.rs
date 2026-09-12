//! The override gate: does this set of user-submitted overrides justify
//! every blocking (error-severity) issue in the list.

use crate::model::{Issue, Severity, SubmittedOverride, ValidateOverridesResult};
use std::collections::HashMap;

/// `ok = false` when one or more error-severity issues has no matching
/// override with a non-empty justification — the caller must still block
/// in that case.
pub fn validate_overrides<'a>(issues: &'a [Issue], overrides: &[SubmittedOverride]) -> ValidateOverridesResult<'a> {
    let mut override_map: HashMap<&str, &SubmittedOverride> = HashMap::new();
    for o in overrides {
        let issue_id = o.issue_id.trim();
        let justification = o.justification.trim();
        if !issue_id.is_empty() && !justification.is_empty() {
            override_map.insert(issue_id, o);
        }
    }

    let mut applied = Vec::new();
    let mut unresolved_errors = Vec::new();
    let mut unmatched_overrides: Vec<&SubmittedOverride> = override_map.values().copied().collect();

    for issue in issues {
        if let Some(&o) = override_map.get(issue.id.as_str()) {
            applied.push((issue, o.justification.trim().to_string()));
            unmatched_overrides.retain(|&x| x.issue_id != o.issue_id);
        } else {
            // Fuzzy match by code snippet for pure line-drift
            let mut matched = false;
            let issue_code = issue.snippet.as_ref().and_then(|s| {
                let hl = s.get("highlightLine").and_then(|n| n.as_i64());
                s.get("lines")
                    .and_then(|l| l.as_array())
                    .and_then(|l| l.iter().find(|x| x.get("number").and_then(|n| n.as_i64()) == hl))
                    .and_then(|l| l.get("text"))
                    .and_then(|t| t.as_str())
                    .map(|t| t.trim())
            });

            if let Some(code) = issue_code {
                // `build_issue_id` (model.rs) joins category/file/line with
                // "::" and the file segment is the raw, unescaped path — a
                // legal (if unusual) filename containing "::" would make
                // `split("::").nth(1)` recover only the file path up to its
                // first "::", never equal to the real full path, so the
                // fuzzy match would never fire for that file even on a
                // genuine line-drift. Matching on the known `category::file::`
                // prefix instead (mirroring how the writer constructs it)
                // is safe regardless of what characters the file path itself
                // contains.
                let expected_prefix = issue.file.as_deref().map(|file| format!("{}::{file}::", issue.category));
                if let Some(pos) = unmatched_overrides.iter().position(|o| {
                    o.code.as_deref().map(|c| c.trim()) == Some(code) &&
                    expected_prefix.as_deref().is_some_and(|prefix| o.issue_id.starts_with(prefix))
                }) {
                    let o = unmatched_overrides.remove(pos);
                    applied.push((issue, o.justification.trim().to_string()));
                    matched = true;
                }
            }

            if !matched && issue.severity == Severity::Error {
                unresolved_errors.push(issue);
            }
        }
    }

    ValidateOverridesResult { ok: unresolved_errors.is_empty(), unresolved_errors, applied }
}

/// Splits `validate_overrides`'s own `applied` list into overrides that
/// can resolve their issue immediately, and ones that need a second
/// reviewer's sign-off first — dual-custody for critical-severity
/// findings (`security.overrideApproval`). `already_approved` is the set
/// of issue ids that already cleared a prior approval cycle (via
/// `DbStore::has_approved_override`), so re-submitting the same override
/// after it's been approved doesn't re-block the gate on a second round.
///
/// Pure/side-effect-free by design — the caller (`routes/effectivate.rs`/
/// `routes/pipeline_interactive/run.rs`) decides what "needs approval"
/// means for `db-store` (inserting a pending row) and for the gate
/// (treating the issue as still unresolved), since this crate has no
/// database of its own to consult.
/// One `(issue, justification)` override pair, matching what
/// `validate_overrides`'s own `applied` list already carries.
pub type AppliedOverride<'a> = (&'a Issue, String);

pub fn partition_for_dual_custody<'a>(applied: Vec<AppliedOverride<'a>>, is_critical: impl Fn(&Issue) -> bool, already_approved: &std::collections::HashSet<String>) -> (Vec<AppliedOverride<'a>>, Vec<AppliedOverride<'a>>) {
    applied.into_iter().partition(|(issue, _)| already_approved.contains(&issue.id) || !is_critical(issue))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::IssueReferences;

    fn issue(id: &str, category: &str, file: &str, snippet_code: &str) -> Issue {
        Issue {
            id: id.to_string(),
            category: category.to_string(),
            severity: Severity::Error,
            score: 8,
            summary: "test finding".to_string(),
            file: Some(file.to_string()),
            line: Some(2),
            snippet: Some(serde_json::json!({
                "highlightLine": 2,
                "lines": [{ "number": 2, "text": snippet_code }],
            })),
            cross_file: false,
            chain: None,
            duplicate_ref: None,
            cwe: None,
            owasp: None,
            tool: None,
            references: IssueReferences::default(),
        }
    }

    #[test]
    fn fuzzy_match_finds_a_line_drifted_override_by_category_file_and_code() {
        // Same category/file/code as an old override, but the line number
        // has drifted (3 instead of the override's original 2) — the exact
        // `issue.id` lookup misses, and this must fall back to matching on
        // category+file+code instead.
        let mut drifted = issue("secret::src/app.js::3", "secret", "src/app.js", "const key = \"sk_live_abc\";");
        drifted.line = Some(3);
        let overrides = vec![SubmittedOverride { issue_id: "secret::src/app.js::2".to_string(), justification: "reviewed, test fixture".to_string(), code: Some("const key = \"sk_live_abc\";".to_string()) }];
        let issues = [drifted];
        let result = validate_overrides(&issues, &overrides);
        assert!(result.ok, "line-drifted issue with matching category/file/code must still be resolved via fuzzy match");
        assert_eq!(result.applied.len(), 1);
    }

    #[test]
    fn fuzzy_match_still_works_when_the_file_path_itself_contains_double_colon() {
        // A (legal, if unusual) file path containing "::" used to break the
        // fallback matcher: `o.issue_id.split("::").nth(1)` only recovers
        // the file path up to its *first* "::", which never equals the
        // real full file path — so the fuzzy match could never fire for
        // such a file even on a genuine line-drift. Matching on the known
        // `category::file::` prefix (as the id is actually constructed)
        // fixes this regardless of what characters the file path contains.
        let weird_file = "src/weird::named::file.js";
        let mut drifted = issue(&format!("secret::{weird_file}::3"), "secret", weird_file, "const key = \"sk_live_abc\";");
        drifted.line = Some(3);
        let overrides = vec![SubmittedOverride { issue_id: format!("secret::{weird_file}::2"), justification: "reviewed, test fixture".to_string(), code: Some("const key = \"sk_live_abc\";".to_string()) }];
        let issues = [drifted];
        let result = validate_overrides(&issues, &overrides);
        assert!(result.ok, "a file path containing '::' must not break the fuzzy fallback matcher");
        assert_eq!(result.applied.len(), 1);
    }

    #[test]
    fn fuzzy_match_does_not_cross_categories_or_files() {
        let issue_a = issue("secret::src/app.js::3", "secret", "src/app.js", "const key = \"sk_live_abc\";");
        // Same code snippet, different category — must not match.
        let overrides = vec![SubmittedOverride { issue_id: "other-category::src/app.js::2".to_string(), justification: "reviewed".to_string(), code: Some("const key = \"sk_live_abc\";".to_string()) }];
        let issues = [issue_a];
        let result = validate_overrides(&issues, &overrides);
        assert!(!result.ok, "a category mismatch must not fuzzy-match even with identical code/file");
    }
}
