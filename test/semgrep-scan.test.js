'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { execFile } = require('node:child_process');

const { withServerEnv, makeTempProject, makeFakeSemgrep } = require('./helpers');

const noopLog = () => {};

function hasRealSemgrep() {
  return new Promise((resolve) => {
    execFile('semgrep', ['--version'], (err) => resolve(!err));
  });
}

test('checkSemanticSast: semgrep is enabled by default', withServerEnv({}, async (mod) => {
  const cfg = mod.loadConfig();
  assert.equal(cfg.security.semgrep.enabled, true);
  assert.equal(cfg.security.semgrep.binary, 'semgrep');
  assert.equal(cfg.security.semgrep.config, 'p/security-audit,p/owasp-top-ten');
}));

test('checkSemanticSast: SEMGREP_* env vars are wired into CONFIG.security.semgrep', withServerEnv(
  { SEMGREP_ENABLED: 'false', SEMGREP_BINARY: '/opt/bin/semgrep', SEMGREP_CONFIG: 'p/javascript' },
  async (mod) => {
    const cfg = mod.loadConfig();
    assert.equal(cfg.security.semgrep.enabled, false);
    assert.equal(cfg.security.semgrep.binary, '/opt/bin/semgrep');
    assert.equal(cfg.security.semgrep.config, 'p/javascript');
  }
));

test('checkSemanticSast: disabled — no findings, engine "disabled"', withServerEnv(
  { SEMGREP_ENABLED: 'false' },
  async (mod) => {
    const dir = await makeTempProject({ 'app.js': 'console.log(1);\n' });
    const { findings, engine } = await mod.checkSemanticSast(dir, noopLog);
    assert.equal(engine, 'disabled');
    assert.deepEqual(findings, []);
  }
));

test('checkSemanticSast: enabled but binary missing — soft-skips, no throw', async () => {
  await withServerEnv({ SEMGREP_ENABLED: 'true', SEMGREP_BINARY: '/nonexistent/semgrep-xyz' }, async (mod) => {
    const dir = await makeTempProject({ 'app.js': 'console.log(1);\n' });
    const logs = [];
    const { findings, engine } = await mod.checkSemanticSast(dir, (m) => logs.push(m));
    assert.equal(engine, 'disabled');
    assert.deepEqual(findings, []);
    assert.ok(logs.some((l) => l.includes('semgrep')), 'failure is logged, not thrown');
  })();
});

test('checkSemanticSast: parses fake semgrep JSON output, maps ERROR/WARNING severity', async () => {
  const semgrepBinary = await makeFakeSemgrep([
    { check_id: 'js.command-injection', path: 'app.js', start: { line: 3 }, extra: { message: 'possible command injection', severity: 'ERROR' } },
    { check_id: 'js.weak-crypto', path: 'app.js', start: { line: 1 }, extra: { message: 'weak hash', severity: 'WARNING' } },
  ]);
  await withServerEnv({ SEMGREP_ENABLED: 'true', SEMGREP_BINARY: semgrepBinary }, async (mod) => {
    const dir = await makeTempProject({ 'app.js': 'const x = 1;\n\nexec("ls " + x);\n' });
    const { findings, engine } = await mod.checkSemanticSast(dir, noopLog);
    assert.equal(engine, 'semgrep');
    assert.equal(findings.length, 2);
    const bySeverity = Object.fromEntries(findings.map((f) => [f.kind, f.severity]));
    assert.equal(bySeverity['js.command-injection'], 'error');
    assert.equal(bySeverity['js.weak-crypto'], 'warning');
    assert.ok(findings.every((f) => f.tool === 'semgrep'));
    assert.ok(findings.every((f) => f.file === 'app.js'));
  })();
});

test('checkSemanticSast: real semgrep binary end-to-end against a custom local rule (skipped if semgrep is not installed)', async (t) => {
  if (!(await hasRealSemgrep())) {
    t.skip('semgrep not installed on PATH — install with `brew install semgrep` to run this test');
    return;
  }
  const dir = await makeTempProject({
    'app.js': 'const exec = require("child_process").exec;\nfunction run(userInput) {\n  exec("ls " + userInput);\n}\nmodule.exports = run;\n',
    'rule.yml': [
      'rules:',
      '  - id: test-command-injection',
      '    languages: [javascript]',
      '    severity: ERROR',
      '    message: Possible command injection via unsanitized input to exec()',
      '    patterns:',
      '      - pattern: exec($CMD)',
    ].join('\n'),
  });
  // A local rule file (not a registry pack) keeps this deterministic and
  // network-independent — a real semgrep binary, a real rule match, no
  // dependency on registry.semgrep.dev's rule content at test time.
  await withServerEnv({ SEMGREP_ENABLED: 'true', SEMGREP_BINARY: 'semgrep', SEMGREP_CONFIG: path.join(dir, 'rule.yml') }, async (mod) => {
    const { findings, engine } = await mod.checkSemanticSast(dir, noopLog);
    assert.equal(engine, 'semgrep');
    assert.equal(findings.length, 1);
    assert.equal(findings[0].file, 'app.js');
    assert.equal(findings[0].line, 3);
    assert.equal(findings[0].severity, 'error');
    assert.equal(findings[0].tool, 'semgrep');
  })();
});
