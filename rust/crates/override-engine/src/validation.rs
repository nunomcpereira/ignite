//! The override gate: does this set of user-submitted overrides justify
//! every blocking (error-severity) issue in the list.

use crate::model::{Issue, Severity, SubmittedOverride, ValidateOverridesResult};
use std::collections::HashMap;

/// `ok = false` when one or more error-severity issues has no matching
/// override with a non-empty justification — the caller must still block
/// in that case.
pub fn validate_overrides<'a>(issues: &'a [Issue], overrides: &[SubmittedOverride]) -> ValidateOverridesResult<'a> {
    let mut override_map: HashMap<&str, &str> = HashMap::new();
    for o in overrides {
        let issue_id = o.issue_id.trim();
        let justification = o.justification.trim();
        if !issue_id.is_empty() && !justification.is_empty() {
            override_map.insert(issue_id, justification);
        }
    }

    let mut applied = Vec::new();
    let mut unresolved_errors = Vec::new();

    for issue in issues {
        if let Some(&justification) = override_map.get(issue.id.as_str()) {
            applied.push((issue, justification.to_string()));
        } else if issue.severity == Severity::Error {
            unresolved_errors.push(issue);
        }
    }

    ValidateOverridesResult { ok: unresolved_errors.is_empty(), unresolved_errors, applied }
}
