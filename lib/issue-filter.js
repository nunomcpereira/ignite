'use strict';

/**
 * Narrows an issue list to only those touching a given set of files —
 * used by validate-all's `changedFiles` param so an agent's fix-verify
 * loop can ask "did the files I just edited get flagged" without
 * re-triaging the whole project's issue list on every iteration. This is
 * a view, never a gate: callers must still resolve/override every issue
 * in the full list for the run to actually pass — filtering only changes
 * what gets echoed back in the response.
 *
 * @param {Array<{file?: string}>} issues
 * @param {string[]|Set<string>|null} changedFiles - project-relative paths;
 *   null/undefined means "no filter", returns issues unchanged.
 * @returns {Array}
 */
function filterIssuesByChangedFiles(issues, changedFiles) {
  if (!changedFiles) return issues;
  const set = changedFiles instanceof Set
    ? changedFiles
    : new Set(Array.from(changedFiles, (f) => String(f).trim()).filter(Boolean));
  return issues.filter((issue) => issue.file && set.has(issue.file));
}

module.exports = { filterIssuesByChangedFiles };
