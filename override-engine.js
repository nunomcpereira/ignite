'use strict';

/**
 * Turns the raw phase-4 check outputs (secrets / AI-governance / LLM
 * security+quality findings) into a single list of addressable "issues"
 * with stable ids, and validates a set of user-submitted overrides against
 * them. Shared by the interactive SSE pipeline and the synchronous
 * validate-all API so both enforce the same override rules.
 */

function buildIssueId({ category, file, line }) {
  return `${category}::${file || 'unknown'}::${line ?? 0}`;
}

/**
 * @param {{ findings: Array<{file,line,kind}> }} secrets
 * @param {{ findings: Array<{file,line,snippet}> }} governance
 * @param {{ available: boolean, findings: Array<{file,line,category,level,issue,recommendation}> }} llm
 * @returns {Array<{id, category, severity, summary, file, line}>}
 */
function collectPhase4Issues({ secrets, governance, llm }) {
  const issues = [];

  for (const f of secrets.findings) {
    issues.push({
      id: buildIssueId({ category: 'secret', file: f.file, line: f.line }),
      category: 'secret',
      severity: 'error',
      summary: `Hardcoded ${f.kind}`,
      file: f.file,
      line: f.line,
    });
  }

  for (const f of governance.findings) {
    issues.push({
      id: buildIssueId({ category: 'ai-governance', file: f.file, line: f.line }),
      category: 'ai-governance',
      severity: 'error',
      summary: `Ungoverned AI invocation (missing recursion_limit): ${f.snippet}`,
      file: f.file,
      line: f.line,
    });
  }

  if (llm && llm.available) {
    for (const f of llm.findings) {
      issues.push({
        id: buildIssueId({ category: f.category, file: f.file, line: f.line }),
        category: f.category,
        severity: f.level === 'error' ? 'error' : 'warning',
        summary: f.issue + (f.recommendation ? ` | fix: ${f.recommendation}` : ''),
        file: f.file,
        line: f.line,
      });
    }
  }

  return issues;
}

/**
 * @param {Array} issues - from collectPhase4Issues
 * @param {Array<{issueId, justification}>} overrides - user-submitted
 * @returns {{ ok: boolean, unresolvedErrors: Array, applied: Array<{issue, justification}> }}
 *   ok=false when one or more error-severity issues has no matching override
 *   with a non-empty justification — the caller must still block in that case.
 */
function validateOverrides(issues, overrides) {
  const overrideMap = new Map();
  for (const o of Array.isArray(overrides) ? overrides : []) {
    const issueId = String(o?.issueId || '').trim();
    const justification = String(o?.justification || '').trim();
    if (issueId && justification) overrideMap.set(issueId, justification);
  }

  const applied = [];
  const unresolvedErrors = [];

  for (const issue of issues) {
    const justification = overrideMap.get(issue.id);
    if (justification) {
      applied.push({ issue, justification });
    } else if (issue.severity === 'error') {
      unresolvedErrors.push(issue);
    }
  }

  return { ok: unresolvedErrors.length === 0, unresolvedErrors, applied };
}

module.exports = { buildIssueId, collectPhase4Issues, validateOverrides };
