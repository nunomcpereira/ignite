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
                if let Some(pos) = unmatched_overrides.iter().position(|o| {
                    o.code.as_deref().map(|c| c.trim()) == Some(code) &&
                    o.issue_id.split("::").next() == Some(issue.category.as_str()) &&
                    o.issue_id.split("::").nth(1) == issue.file.as_deref()
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
