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
  'container-image-cve': 8,
  'image-provenance': 4,
  'semantic-sast': 7,
  'pii-dataflow': 7,
  'code-duplication': 2,
  'code-structure': 2,
  'api-schema-lint': 4,
  'dependency-vulnerability': 8,
  'malicious-dependency': 9,
  'codeql-sast': 8,
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

// CWE/OWASP tagging (compliance/audit-trail mapping — SOC2/ISO27001-style
// reporting needs a standard identifier per finding, not just Ignite's own
// category label). Three-tier precedence, applied per issue by
// deriveCweOwasp below:
//   1. Explicit per-finding data a tool already reports (Semgrep's rule
//      metadata.cwe/metadata.owasp, Bearer's cwe_ids) — most precise,
//      passed straight through from server.js's finding-shaping code.
//   2. A keyword match against the finding's own summary text — covers the
//      LLM deep-scan's free-text findings, which carry no structured CWE of
//      their own.
//   3. A fixed category-level fallback below — coarser (one CWE for a whole
//      check, e.g. every IaC misconfiguration reads as CWE-16) but better
//      than no identifier at all for categories with no per-finding signal.
// Categories with no meaningful security mapping (quality, license-
// compliance, code-duplication, process/governance checks, ...) are
// deliberately left unmapped rather than forced onto a CWE that doesn't fit.
const CATEGORY_CWE_OWASP = {
  secret: { cwe: 'CWE-798', owasp: 'A07:2021 - Identification and Authentication Failures' },
  'ai-governance': { cwe: 'CWE-400', owasp: 'A04:2021 - Insecure Design' },
  'iac-security': { cwe: 'CWE-16', owasp: 'A05:2021 - Security Misconfiguration' },
  'container-image-cve': { cwe: 'CWE-1104', owasp: 'A06:2021 - Vulnerable and Outdated Components' },
  'image-provenance': { cwe: 'CWE-345', owasp: 'A08:2021 - Software and Data Integrity Failures' },
  'pii-dataflow': { cwe: 'CWE-359', owasp: null },
  'malicious-dependency': { cwe: 'CWE-506', owasp: 'A08:2021 - Software and Data Integrity Failures' },
  'dependency-vulnerability': { cwe: 'CWE-1104', owasp: 'A06:2021 - Vulnerable and Outdated Components' },
  'structure-audit': { cwe: 'CWE-540', owasp: 'A05:2021 - Security Misconfiguration' },
};

// Applied to free-text summaries (LLM deep-scan findings, which carry no
// structured CWE of their own) — first pattern to match wins, ordered
// roughly by specificity so e.g. "SQL injection via eval" hits sql-injection
// first rather than the generic eval/injection catch-all.
const TEXT_CWE_OWASP_PATTERNS = [
  { re: /sql\s*injection/i, cwe: 'CWE-89', owasp: 'A03:2021 - Injection' },
  { re: /\bxss\b|cross[- ]site\s*script/i, cwe: 'CWE-79', owasp: 'A03:2021 - Injection' },
  { re: /\bssrf\b|server[- ]side\s*request\s*forgery/i, cwe: 'CWE-918', owasp: 'A10:2021 - Server-Side Request Forgery' },
  { re: /path\s*traversal|directory\s*traversal/i, cwe: 'CWE-22', owasp: 'A01:2021 - Broken Access Control' },
  { re: /command\s*injection|\bos\s*command\b/i, cwe: 'CWE-78', owasp: 'A03:2021 - Injection' },
  { re: /template\s*injection/i, cwe: 'CWE-1336', owasp: 'A03:2021 - Injection' },
  { re: /insecure\s*deserializ/i, cwe: 'CWE-502', owasp: 'A08:2021 - Software and Data Integrity Failures' },
  { re: /prototype\s*pollution/i, cwe: 'CWE-1321', owasp: 'A03:2021 - Injection' },
  { re: /weak\s*crypto|broken\s*crypto|insecure\s*random|hardcoded\s*(iv|key)|\becb\s*mode\b/i, cwe: 'CWE-327', owasp: 'A02:2021 - Cryptographic Failures' },
  { re: /hardcoded\s*(password|credential|secret|api[ _-]?key|token)/i, cwe: 'CWE-798', owasp: 'A07:2021 - Identification and Authentication Failures' },
  { re: /\beval\(|unsafe\s*eval|dangerous\s*function/i, cwe: 'CWE-95', owasp: 'A03:2021 - Injection' },
  { re: /broken\s*auth|missing\s*auth|authoriz|access\s*control|\bidor\b/i, cwe: 'CWE-284', owasp: 'A01:2021 - Broken Access Control' },
  { re: /insecure\s*temp(orary)?\s*file/i, cwe: 'CWE-377', owasp: 'A01:2021 - Broken Access Control' },
  { re: /missing\s*input\s*validation|unvalidated\s*input/i, cwe: 'CWE-20', owasp: 'A03:2021 - Injection' },
];

function inferCweOwaspFromText(text) {
  const s = String(text || '');
  for (const { re, cwe, owasp } of TEXT_CWE_OWASP_PATTERNS) {
    if (re.test(s)) return { cwe, owasp };
  }
  return null;
}

/**
 * @param {string} category
 * @param {string} summary - the issue's own summary text, for keyword inference
 * @param {{cwe?: string, owasp?: string}} [explicit] - per-finding data a tool already reported
 * @returns {{cwe: string|null, owasp: string|null}}
 */
function deriveCweOwasp(category, summary, explicit) {
  if (explicit?.cwe || explicit?.owasp) {
    return { cwe: explicit.cwe || null, owasp: explicit.owasp || null };
  }
  const inferred = inferCweOwaspFromText(summary);
  if (inferred) return inferred;
  const fallback = CATEGORY_CWE_OWASP[category];
  return fallback ? { ...fallback } : { cwe: null, owasp: null };
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
 * @param {{ findings: Array<{file,line,kind,tool,severity,message}>, engine: string }} [maliciousDependencies]
 * @param {{ findings: Array<{file,line,kind,tool,severity,message,crossFile,cwe}>, engine: string }} [codeql] - deep-scan only, never present on the fast interactive pipeline's issue list
 * @returns {Array<{id, category, severity, score, summary, file, line}>}
 */
function collectPhase4Issues({ secrets, governance, llm, iac, imageVulnerabilities, imageProvenance, semanticSast, piiDataFlow, duplication, fileEncapsulation, apiSchema, maliciousDependencies, codeql }) {
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

  if (imageVulnerabilities) {
    for (const f of imageVulnerabilities.findings) {
      const category = 'container-image-cve';
      const severity = (f.severity === 'critical' || f.severity === 'high') ? 'error' : 'warning';
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
        // Carried through to the CWE/OWASP tagging pass below, then
        // stripped — Semgrep's own rule metadata (when present) is more
        // precise than the category-level/keyword fallback.
        cweHint: f.cwe || null,
        owaspHint: f.owasp || null,
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
        cweHint: f.cwe || null,
        owaspHint: null,
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

  if (fileEncapsulation) {
    for (const f of fileEncapsulation.findings) {
      const category = 'code-structure';
      const severity = 'warning'; // always advisory — file size never blocks a run
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

  if (maliciousDependencies) {
    for (const f of maliciousDependencies.findings) {
      const category = 'malicious-dependency';
      const severity = 'error'; // GuardDog's whole purpose is malicious-code heuristics, not style/license findings
      issues.push({
        id: buildIssueId({ category, file: f.file, line: f.line }),
        category,
        severity,
        score: scoreForIssue({ category, severity }),
        summary: f.message || f.kind,
        file: f.file,
        line: f.line,
        snippet: null,
      });
    }
  }

  if (codeql) {
    for (const f of codeql.findings) {
      const category = 'codeql-sast';
      const severity = f.severity === 'error' ? 'error' : 'warning';
      issues.push({
        id: buildIssueId({ category, file: f.file, line: f.line }),
        category,
        severity,
        score: scoreForIssue({ category, severity }),
        summary: f.message || f.kind,
        file: f.file,
        line: f.line,
        snippet: null,
        // Distinguishes a finding that only exists because CodeQL traced
        // taint across >=2 files (the whole reason this check runs on top
        // of Semgrep's single-file engine) from one it also caught
        // single-file — surfaced by the UI so a reviewer can tell at a
        // glance which findings are genuinely new information.
        crossFile: Boolean(f.crossFile),
        cweHint: f.cwe || null,
        owaspHint: null,
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

  // CWE/OWASP tagging pass — see deriveCweOwasp's precedence order above.
  // Runs once over every issue rather than at each push site so it applies
  // uniformly regardless of which check the issue came from, including
  // categories with no per-finding hint (secret/iac/etc — category
  // fallback) and the LLM's free-text findings (keyword inference).
  for (const issue of issues) {
    const { cwe, owasp } = deriveCweOwasp(issue.category, issue.summary, { cwe: issue.cweHint, owasp: issue.owaspHint });
    issue.cwe = cwe;
    issue.owasp = owasp;
    delete issue.cweHint;
    delete issue.owaspHint;
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
        // OSV/GHSA advisories sometimes carry the underlying CWE as one of
        // their aliases (e.g. "CWE-1321") alongside the CVE/GHSA id itself.
        const cweAlias = (vuln.aliases || []).find((a) => /^CWE-\d+$/i.test(String(a)));
        const { cwe, owasp } = deriveCweOwasp(category, vuln.title, { cwe: cweAlias || null });
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
          cwe,
          owasp,
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
  validateOverrides, scoreForIssue, deriveCweOwasp,
};
