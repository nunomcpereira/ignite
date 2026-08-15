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

// A "secret" living under a test directory/filename (test/, tests/,
// __tests__/, spec/, *.test.js, *_test.py, *.spec.ts, ...) is far more
// likely to be a fixture/fake credential than a real leaked one — still
// worth a look, but not worth blocking the pipeline over. Demoted to a
// warning rather than dropped entirely, since an occasional real secret
// does end up copy-pasted into a test fixture.
const TEST_PATH_RE = /(^|\/)(tests?|__tests__|specs?)(\/|$)|[._-](test|spec)s?\.[^/.]+$/i;
function isLikelyTestFile(file) {
  return TEST_PATH_RE.test(String(file || '').replace(/\\/g, '/'));
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
  'license-compliance': 6,
  'iac-security': 6,
  'image-provenance': 4,
  'semantic-sast': 7,
  'pii-dataflow': 7,
  'code-duplication': 2,
  'api-schema-lint': 4,
  'dependency-vulnerability': 8,
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
 * @param {{ findings: Array<{file,line,kind,tool,severity,message}>, engine: string }} [iac]
 * @param {{ findings: Array<{file,line,kind,tool,severity,message}>, engine: string }} [imageProvenance]
 * @param {{ findings: Array<{file,line,kind,tool,severity,message}>, engine: string }} [semanticSast]
 * @param {{ findings: Array<{file,line,kind,tool,severity,message}>, engine: string }} [piiDataFlow]
 * @param {{ findings: Array<{file,line,kind,tool,severity,message}>, engine: string }} [duplication]
 * @param {{ findings: Array<{file,line,kind,tool,severity,message}>, engine: string }} [apiSchema]
 * @returns {Array<{id, category, severity, score, summary, file, line}>}
 */
function collectPhase4Issues({ secrets, governance, llm, iac, imageProvenance, semanticSast, piiDataFlow, duplication, apiSchema }) {
  const issues = [];

  for (const f of secrets.findings) {
    const category = 'secret';
    const inTestFile = isLikelyTestFile(f.file);
    const severity = inTestFile ? 'warning' : 'error';
    issues.push({
      id: buildIssueId({ category, file: f.file, line: f.line }),
      category,
      severity,
      score: scoreForIssue({ category, severity }),
      summary: `Hardcoded ${f.kind}${inTestFile ? ' (in a test file — likely a fixture, not a real credential)' : ''}`,
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

  if (iac) {
    for (const f of iac.findings) {
      const category = 'iac-security';
      const severity = (f.severity === 'critical' || f.severity === 'high') ? 'error' : 'warning';
      issues.push({
        id: buildIssueId({ category, file: f.file, line: f.line }),
        category,
        severity,
        score: scoreForIssue({ category, severity }),
        summary: `${f.message || f.kind}${f.tool === 'ignite-fallback' ? ' (built-in fallback check — trivy not installed)' : ''}`,
        file: f.file,
        line: f.line,
        snippet: f.code || null,
      });
    }
  }

  if (imageProvenance) {
    for (const f of imageProvenance.findings) {
      const category = 'image-provenance';
      const severity = 'warning'; // advisory only — never blocks a run on its own
      issues.push({
        id: buildIssueId({ category, file: f.file, line: f.line }),
        category,
        severity,
        score: scoreForIssue({ category, severity }),
        summary: f.message || f.kind,
        file: f.file,
        line: f.line,
        snippet: f.code || null,
      });
    }
  }

  if (semanticSast) {
    for (const f of semanticSast.findings) {
      const category = 'semantic-sast';
      const severity = f.severity === 'error' ? 'error' : 'warning';
      issues.push({
        id: buildIssueId({ category, file: f.file, line: f.line }),
        category,
        severity,
        score: scoreForIssue({ category, severity }),
        summary: f.message || f.kind,
        file: f.file,
        line: f.line,
        snippet: f.code || null,
      });
    }
  }

  if (piiDataFlow) {
    for (const f of piiDataFlow.findings) {
      const category = 'pii-dataflow';
      const severity = f.severity === 'error' ? 'error' : 'warning';
      issues.push({
        id: buildIssueId({ category, file: f.file, line: f.line }),
        category,
        severity,
        score: scoreForIssue({ category, severity }),
        summary: f.message || f.kind,
        file: f.file,
        line: f.line,
        snippet: f.code || null,
      });
    }
  }

  if (duplication) {
    for (const f of duplication.findings) {
      const category = 'code-duplication';
      const severity = 'warning'; // always advisory — duplication never blocks a run
      issues.push({
        id: buildIssueId({ category, file: f.file, line: f.line }),
        category,
        severity,
        score: scoreForIssue({ category, severity }),
        summary: f.message || f.kind,
        file: f.file,
        line: f.line,
        snippet: f.code || null,
        duplicateRef: f.duplicateRef || null,
      });
    }
  }

  if (apiSchema) {
    for (const f of apiSchema.findings) {
      const category = 'api-schema-lint';
      const severity = f.severity === 'error' ? 'error' : 'warning';
      issues.push({
        id: buildIssueId({ category, file: f.file, line: f.line }),
        category,
        severity,
        score: scoreForIssue({ category, severity }),
        summary: f.message || f.kind,
        file: f.file,
        line: f.line,
        snippet: f.code || null,
      });
    }
  }

  if (llm && llm.available) {
    for (const f of llm.findings) {
      const category = f.category;
      // Same "likely a fixture, not a real secret" reasoning as the regex
      // scan above, extended to the LLM's own credential-shaped security
      // findings — scoped to credential-sounding text specifically so an
      // otherwise-real vulnerability (e.g. actual SQL injection) sitting in
      // a test helper doesn't get blanket-demoted just for its file path.
      const looksLikeCredential = category === 'security'
        && /hardcoded|credential|api[ _-]?key|password|secret|token/i.test(f.issue || '');
      const inTestFile = looksLikeCredential && isLikelyTestFile(f.file);
      const severity = f.level === 'error' && !inTestFile ? 'error' : 'warning';
      issues.push({
        id: buildIssueId({ category, file: f.file, line: f.line }),
        category,
        severity,
        score: scoreForIssue({ category, severity }),
        summary: f.issue + (f.recommendation ? ` | fix: ${f.recommendation}` : '') + (inTestFile ? ' (in a test file — likely a fixture, not a real credential)' : ''),
        file: f.file,
        line: f.line,
        snippet: f.code || null,
      });
    }
  }

  return issues;
}

/**
 * Turns dependency-manifest license findings (`scanDependencyLicenses`'s
 * `manifests`) and raw LICENSE-file findings (`scanProjectLicenseFiles`) into
 * the same addressable-issue shape as `collectPhase4Issues`, so commercial/
 * copyleft/unrecognized licenses gate a run exactly like a hardcoded secret
 * does, instead of only ever showing up in the on-demand Dependencies view.
 * @param {{ manifests: Array<{file, dependencies: Array<{name, version, versionRange, tier, reason}>}>, licenseFiles: Array<{file, line, tier, reason}> }} scan
 * @returns {Array<{id, category, severity, score, summary, file, line}>}
 */
function collectLicenseIssues({ manifests, licenseFiles }) {
  const issues = [];
  const category = 'license-compliance';

  for (const manifest of manifests || []) {
    for (const dep of manifest.dependencies || []) {
      if (dep.tier === 'green') continue;
      const severity = dep.tier === 'red' ? 'error' : 'warning';
      const file = manifest.file;
      // The dep name (not its line) keeps the id stable across edits that
      // shift lines, so overrides survive unrelated manifest changes.
      issues.push({
        id: `${buildIssueId({ category, file, line: null })}::${dep.name}`,
        category,
        severity,
        score: scoreForIssue({ category, severity }),
        summary: `${dep.name}@${dep.version || dep.versionRange || '?'} — ${dep.reason}`,
        file,
        line: dep.line ?? null,
      });
    }
  }

  for (const lf of licenseFiles || []) {
    const severity = lf.tier === 'red' ? 'error' : 'warning';
    issues.push({
      id: buildIssueId({ category, file: lf.file, line: lf.line }),
      category,
      severity,
      score: scoreForIssue({ category, severity }),
      summary: lf.reason,
      file: lf.file,
      line: lf.line,
    });
  }

  return issues;
}

/**
 * Turns scanDependencyVulnerabilities' per-dependency CVE/GHSA findings
 * (deps.dev-backed — see server.js) into the same addressable-issue shape
 * as collectLicenseIssues, so a known-critical vulnerability in a
 * dependency gates a run exactly like a commercial license does, instead
 * of only ever showing up in the on-demand Dependencies view.
 * @param {{ manifests: Array<{file, dependencies: Array<{name, version, versionRange, line, vulnerabilities: Array<{id, title, aliases, cvss3Score, severity, url}>}>}> }} scan
 * @returns {Array<{id, category, severity, score, summary, file, line}>}
 */
function collectDependencyVulnerabilityIssues({ manifests }) {
  const issues = [];
  const category = 'dependency-vulnerability';

  for (const manifest of manifests || []) {
    for (const dep of manifest.dependencies || []) {
      for (const vuln of dep.vulnerabilities || []) {
        const severity = vuln.severity === 'error' ? 'error' : 'warning';
        const file = manifest.file;
        const advisoryId = vuln.id || vuln.aliases?.[0] || 'unknown-advisory';
        // Dep name + advisory id keeps the id stable and unique across
        // edits and across the (common) case of one dependency carrying
        // several distinct advisories at the same manifest line.
        issues.push({
          id: `${buildIssueId({ category, file, line: dep.line ?? null })}::${dep.name}::${advisoryId}`,
          category,
          severity,
          score: scoreForIssue({ category, severity }),
          summary: `${dep.name}@${dep.version || dep.versionRange || '?'} — ${advisoryId}`
            + (vuln.title ? `: ${vuln.title}` : '')
            + (typeof vuln.cvss3Score === 'number' ? ` (CVSS ${vuln.cvss3Score})` : ''),
          file,
          line: dep.line ?? null,
        });
      }
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

module.exports = {
  buildIssueId, collectPhase4Issues, collectLicenseIssues, collectDependencyVulnerabilityIssues,
  validateOverrides, scoreForIssue,
};
