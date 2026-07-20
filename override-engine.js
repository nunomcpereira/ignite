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

// Fixed 0-10 severity score per category, independent of the blocking/warning
// (error/warning) status — the latter drives override gating, this drives
// "how bad is this really" for triage. Warning-level findings in an
// otherwise error-scored category (e.g. an LLM 'security' finding demoted to
// warning by LLM_ADVISORY_LEVEL) score at half the category's base, floored
// at 1 so nothing flagged reads as a 0.
const CATEGORY_SCORES = {
  secret: 10,
  'ai-governance': 7,
  security: 8,
  dependency: 7,
  encapsulation: 3,
  quality: 2,
  'structure-audit': 8,
  'gxp-documents': 5,
  'governance-ci': 7,
  'input-validation': 4,
  'security-scan': 6,
};

/**
 * @param {{ category: string, severity: 'error'|'warning' }} issue
 * @returns {number} 0-10 severity score
 */
function scoreForIssue({ category, severity }) {
  const base = Object.prototype.hasOwnProperty.call(CATEGORY_SCORES, category)
    ? CATEGORY_SCORES[category]
    : (severity === 'error' ? 7 : 3);
  return severity === 'warning' ? Math.max(1, Math.round(base / 2)) : base;
}

/**
 * @param {{ findings: Array<{file,line,kind}> }} secrets
 * @param {{ findings: Array<{file,line,snippet}> }} governance
 * @param {{ available: boolean, findings: Array<{file,line,category,level,issue,recommendation}> }} llm
 * @returns {Array<{id, category, severity, score, summary, file, line}>}
 */
function collectPhase4Issues({ secrets, governance, llm }) {
  const issues = [];

  for (const f of secrets.findings) {
    const category = 'secret';
    const severity = 'error';
    issues.push({
      id: buildIssueId({ category, file: f.file, line: f.line }),
      category,
      severity,
      score: scoreForIssue({ category, severity }),
      summary: `Hardcoded ${f.kind}`,
      file: f.file,
      line: f.line,
      snippet: f.code || null,
    });
  }

  for (const f of governance.findings) {
    const category = 'ai-governance';
    const severity = 'error';
    issues.push({
      id: buildIssueId({ category, file: f.file, line: f.line }),
      category,
      severity,
      score: scoreForIssue({ category, severity }),
      summary: `Ungoverned AI invocation (missing recursion_limit): ${f.snippet}`,
      file: f.file,
      line: f.line,
      snippet: f.code || null,
    });
  }

  if (llm && llm.available) {
    for (const f of llm.findings) {
      const category = f.category;
      const severity = f.level === 'error' ? 'error' : 'warning';
      issues.push({
        id: buildIssueId({ category, file: f.file, line: f.line }),
        category,
        severity,
        score: scoreForIssue({ category, severity }),
        summary: f.issue + (f.recommendation ? ` | fix: ${f.recommendation}` : ''),
        file: f.file,
        line: f.line,
        snippet: f.code || null,
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

module.exports = { buildIssueId, collectPhase4Issues, validateOverrides, scoreForIssue };
