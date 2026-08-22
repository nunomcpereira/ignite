'use strict';

/**
 * Narrows an issue list to only those NOT already accepted into a project's
 * baseline — closes the "no baseline/diff adoption mode" gap against
 * fallow.tools' `--save-baseline`/`--baseline`. Mirrors lib/issue-filter.js's
 * filterIssuesByChangedFiles shape deliberately: same "view, not a gate"
 * caveat applies when a caller asks for the filtered view without also
 * asking Ignite to gate on it (see routes/pipeline-validate.js's
 * `baselineMode` handling for where this actually affects pass/fail).
 *
 * @param {Array<{id: string}>} issues
 * @param {Set<string>|null} baselineIssueIds - issue ids already accepted
 *   as pre-existing debt; null/undefined means "no baseline", returns
 *   issues unchanged.
 * @returns {Array}
 */
function filterIssuesByBaseline(issues, baselineIssueIds) {
  if (!baselineIssueIds || baselineIssueIds.size === 0) return issues;
  return issues.filter((issue) => !baselineIssueIds.has(issue.id));
}

module.exports = { filterIssuesByBaseline };
