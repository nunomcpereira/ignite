'use strict';

/**
 * CWE/OWASP tagging (deriveCweOwasp / collectPhase4Issues) — enterprise
 * SAST audit-trail requirement: every issue needs a standard identifier,
 * not just Ignite's own category label. Precedence: explicit per-finding
 * data (Semgrep rule metadata, Bearer cwe_ids) > keyword match on the
 * summary text (covers the LLM deep-scan's free-text findings) > a fixed
 * category-level fallback > null/null for categories with no security
 * mapping (quality, license-compliance, ...).
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { deriveCweOwasp, collectPhase4Issues } = require('../override-engine');

test('deriveCweOwasp: explicit per-finding data wins over everything else', () => {
  const result = deriveCweOwasp('semantic-sast', 'some generic message', { cwe: 'CWE-89', owasp: 'A03:2021 - Injection' });
  assert.deepEqual(result, { cwe: 'CWE-89', owasp: 'A03:2021 - Injection' });
});

test('deriveCweOwasp: keyword match on summary text wins over the category fallback', () => {
  // 'secret' has its own CWE-798 category fallback below, but the summary
  // text itself describes SQL injection, not a hardcoded credential — the
  // keyword match must win so the tag reflects what actually happened.
  const result = deriveCweOwasp('secret', 'Tainted input reaches a raw SQL query (SQL injection)', undefined);
  assert.equal(result.cwe, 'CWE-89');
  assert.match(result.owasp, /A03:2021/);
});

test('deriveCweOwasp: falls back to the fixed category mapping when nothing else matches', () => {
  const result = deriveCweOwasp('secret', 'Hardcoded api_key', undefined);
  assert.equal(result.cwe, 'CWE-798');
  assert.match(result.owasp, /A07:2021/);
});

test('deriveCweOwasp: categories with no security mapping stay null/null', () => {
  const result = deriveCweOwasp('code-duplication', 'Duplicated block (12 lines)', undefined);
  assert.deepEqual(result, { cwe: null, owasp: null });
});

test('deriveCweOwasp: SSRF/path-traversal/command-injection/XSS keyword coverage', () => {
  assert.equal(deriveCweOwasp('security', 'possible SSRF via unvalidated URL fetch').cwe, 'CWE-918');
  assert.equal(deriveCweOwasp('security', 'path traversal reading arbitrary files').cwe, 'CWE-22');
  assert.equal(deriveCweOwasp('security', 'command injection via unsanitized shell arg').cwe, 'CWE-78');
  assert.equal(deriveCweOwasp('security', 'reflected XSS in the search page').cwe, 'CWE-79');
});

test('collectPhase4Issues: secrets/governance/iac issues carry category-fallback CWE/OWASP', () => {
  const issues = collectPhase4Issues({
    secrets: { findings: [{ file: 'app.js', line: 5, kind: 'api_key', code: null }] },
    governance: { findings: [] },
    llm: { available: false, findings: [] },
    iac: { findings: [{ file: 'Dockerfile', line: 1, kind: 'unpinned-base-image', tool: 'trivy', severity: 'medium', message: 'unpinned tag' }], engine: 'trivy' },
  });
  const secretIssue = issues.find((i) => i.category === 'secret');
  assert.equal(secretIssue.cwe, 'CWE-798');
  const iacIssue = issues.find((i) => i.category === 'iac-security');
  assert.equal(iacIssue.cwe, 'CWE-16');
});

test('collectPhase4Issues: semgrep finding-level cwe/owasp pass through, not overridden by category fallback', () => {
  const issues = collectPhase4Issues({
    secrets: { findings: [] },
    governance: { findings: [] },
    llm: { available: false, findings: [] },
    semanticSast: {
      findings: [{ file: 'app.js', line: 10, kind: 'sql-injection', tool: 'semgrep', severity: 'error', message: 'tainted query', cwe: 'CWE-89', owasp: 'A03:2021 - Injection' }],
      engine: 'semgrep',
    },
  });
  const issue = issues.find((i) => i.category === 'semantic-sast');
  assert.equal(issue.cwe, 'CWE-89');
  assert.equal(issue.owasp, 'A03:2021 - Injection');
  // The transient hint fields never leak into the final issue shape.
  assert.equal(issue.cweHint, undefined);
  assert.equal(issue.owaspHint, undefined);
});

test('collectPhase4Issues: LLM security findings get CWE/OWASP via keyword inference on the summary', () => {
  const issues = collectPhase4Issues({
    secrets: { findings: [] },
    governance: { findings: [] },
    llm: {
      available: true,
      findings: [{ file: 'app.py', line: 20, category: 'security', level: 'error', issue: 'SSRF: unvalidated URL passed to requests.get' }],
    },
  });
  const issue = issues.find((i) => i.category === 'security');
  assert.equal(issue.cwe, 'CWE-918');
});

test('collectPhase4Issues: code-duplication issues stay unmapped (not a security category)', () => {
  const issues = collectPhase4Issues({
    secrets: { findings: [] },
    governance: { findings: [] },
    llm: { available: false, findings: [] },
    duplication: { findings: [{ file: 'a.js', line: 1, message: 'duplicated block' }], engine: 'jscpd' },
  });
  const issue = issues.find((i) => i.category === 'code-duplication');
  assert.equal(issue.cwe, null);
  assert.equal(issue.owasp, null);
});

test('collectPhase4Issues: likely-false-positive CodeQL findings in dev/test paths or project.id log formatting are demoted to warning', () => {
  const issues = collectPhase4Issues({
    secrets: { findings: [] },
    governance: { findings: [] },
    llm: { available: false, findings: [] },
    codeql: {
      findings: [
        {
          file: 'tadone/app/e2e/verify/serve-spa.mjs',
          line: 116,
          kind: 'js/path-injection',
          severity: 'error',
          message: 'This path depends on a user-provided value.',
          snippet: null,
        },
        {
          file: 'parla/ai-handler/index.js',
          line: 156,
          kind: 'js/log-injection',
          severity: 'error',
          message: 'Log entry depends on a user-provided value.',
          snippet: {
            startLine: 156,
            highlightLine: 156,
            lines: [{ number: 156, text: 'console.error(`[${project.id}] Firestore connectivity test failed:`);' }],
          },
        },
      ],
    },
  });
  const byLine = Object.fromEntries(issues.filter((i) => i.category === 'codeql-sast').map((i) => [i.line, i]));
  assert.equal(byLine[116].severity, 'warning');
  assert.equal(byLine[156].severity, 'warning');
});
