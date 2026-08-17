'use strict';

/**
 * ignite-auth-correctness-rules.yaml — JWT algorithm-confusion detection
 * (real vulnerabilities, distinct from the Compliance & Feature Posture
 * Engine's presence-only SSO/MFA classifier). Runs the real ruleset
 * against real semgrep (self-skips if semgrep isn't installed) — these
 * are hand-written AST patterns, not something a fake-CLI JSON stand-in
 * can meaningfully exercise, so unlike the rest of this suite there's no
 * fake-CLI variant of these tests.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { execFile } = require('node:child_process');

const { withServerEnv, makeTempProject } = require('./helpers');

const noopLog = () => {};
const RULESET_PATH = path.join(__dirname, '..', 'ignite-auth-correctness-rules.yaml');

function hasRealSemgrep() {
  return new Promise((resolve) => {
    execFile('semgrep', ['--version'], (err) => resolve(!err));
  });
}

test('checkSemanticSast: auth-correctness ruleset is included in the default semgrep config', withServerEnv({}, async (mod) => {
  const cfg = mod.loadConfig();
  assert.ok(cfg.security.semgrep.config.includes('ignite-auth-correctness-rules.yaml'));
}));

test('ignite-auth-correctness-rules.yaml: flags jwt.verify()/jwt.decode() missing an algorithms allowlist, clears the safe form (skipped if semgrep is not installed)', async (t) => {
  if (!(await hasRealSemgrep())) {
    t.skip('semgrep not installed on PATH — install with `brew install semgrep` to run this test');
    return;
  }
  await withServerEnv({ SEMGREP_ENABLED: 'true', SEMGREP_BINARY: 'semgrep', SEMGREP_CONFIG: RULESET_PATH }, async (mod) => {
    const dir = await makeTempProject({
      'vuln.js': "const jwt = require('jsonwebtoken');\nfunction verifyToken(token) {\n  return jwt.verify(token, publicKey);\n}\n",
      'safe.js': "const jwt = require('jsonwebtoken');\nfunction verifyToken(token) {\n  return jwt.verify(token, publicKey, { algorithms: ['RS256'] });\n}\n",
      'vuln.py': 'import jwt\n\ndef verify(token, key):\n    return jwt.decode(token, key)\n',
      'safe.py': 'import jwt\n\ndef verify(token, key):\n    return jwt.decode(token, key, algorithms=["RS256"])\n',
    });
    const { findings, engine } = await mod.checkSemanticSast(dir, noopLog);
    assert.equal(engine, 'semgrep');

    // Semgrep prefixes a local rule file's own check_id with a
    // dotted path derived from the ruleset's filesystem location (e.g.
    // "users.nuno.tests.ignite.jwt-verify-missing-algorithms-js"), so
    // match by suffix rather than exact equality.
    const jsFindings = findings.filter((f) => f.kind.endsWith('jwt-verify-missing-algorithms-js'));
    assert.equal(jsFindings.length, 1);
    assert.equal(jsFindings[0].file, 'vuln.js');
    assert.equal(jsFindings[0].line, 3);
    assert.equal(jsFindings[0].cwe, 'CWE-347');

    const pyFindings = findings.filter((f) => f.kind.endsWith('pyjwt-decode-missing-algorithms'));
    assert.equal(pyFindings.length, 1);
    assert.equal(pyFindings[0].file, 'vuln.py');

    // The safe (algorithms-allowlisted) forms must never be flagged —
    // false-positiving on the correct idiom is worse than not checking.
    assert.ok(!findings.some((f) => f.file === 'safe.js'));
    assert.ok(!findings.some((f) => f.file === 'safe.py'));
  })();
});
