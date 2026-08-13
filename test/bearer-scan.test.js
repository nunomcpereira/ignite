'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');

const { withServerEnv, makeTempProject, makeFakeBearer } = require('./helpers');

const noopLog = () => {};

function hasRealBearer() {
  return new Promise((resolve) => {
    execFile('bearer', ['version'], (err) => resolve(!err));
  });
}

test('checkPiiDataFlow: bearer is enabled by default', withServerEnv({}, async (mod) => {
  const cfg = mod.loadConfig();
  assert.equal(cfg.security.bearer.enabled, true);
  assert.equal(cfg.security.bearer.binary, 'bearer');
}));

test('checkPiiDataFlow: BEARER_* env vars are wired into CONFIG.security.bearer', withServerEnv(
  { BEARER_ENABLED: 'true', BEARER_BINARY: '/opt/bin/bearer' },
  async (mod) => {
    const cfg = mod.loadConfig();
    assert.equal(cfg.security.bearer.enabled, true);
    assert.equal(cfg.security.bearer.binary, '/opt/bin/bearer');
  }
));

test('checkPiiDataFlow: explicitly disabled — no findings, engine "disabled"', withServerEnv(
  { BEARER_ENABLED: 'false' },
  async (mod) => {
    const dir = await makeTempProject({ 'app.js': 'console.log(1);\n' });
    const { findings, engine } = await mod.checkPiiDataFlow(dir, noopLog);
    assert.equal(engine, 'disabled');
    assert.deepEqual(findings, []);
  }
));

test('checkPiiDataFlow: enabled but binary missing — soft-skips, no throw', async () => {
  await withServerEnv({ BEARER_ENABLED: 'true', BEARER_BINARY: '/nonexistent/bearer-xyz' }, async (mod) => {
    const dir = await makeTempProject({ 'app.js': 'console.log(1);\n' });
    const logs = [];
    const { findings, engine } = await mod.checkPiiDataFlow(dir, (m) => logs.push(m));
    assert.equal(engine, 'disabled');
    assert.deepEqual(findings, []);
    assert.ok(logs.some((l) => l.includes('bearer')), 'failure is logged, not thrown');
  })();
});

test('checkPiiDataFlow: parses fake bearer severity-bucketed JSON, maps to error/warning', async () => {
  const bearerBinary = await makeFakeBearer({
    high: [{ id: 'js.pii-in-log', title: 'PII leaked to logger', filename: 'app.js', line_number: 3, category_groups: ['PII', 'Personal Data'] }],
    medium: [{ id: 'js.pii-format-string', title: 'PII in format string', filename: 'app.js', line_number: 2, category_groups: ['PII', 'Personal Data'] }],
  });
  await withServerEnv({ BEARER_ENABLED: 'true', BEARER_BINARY: bearerBinary }, async (mod) => {
    const dir = await makeTempProject({ 'app.js': 'const ssn = 1;\nconsole.log(ssn);\nlogger.info(ssn);\n' });
    const { findings, engine } = await mod.checkPiiDataFlow(dir, noopLog);
    assert.equal(engine, 'bearer');
    assert.equal(findings.length, 2);
    const bySeverity = Object.fromEntries(findings.map((f) => [f.kind, f.severity]));
    assert.equal(bySeverity['js.pii-in-log'], 'error');
    assert.equal(bySeverity['js.pii-format-string'], 'warning');
    assert.ok(findings.every((f) => f.tool === 'bearer'));
    assert.ok(findings.every((f) => f.file === 'app.js'));
  })();
});

// Regression test: `bearer scan` with no --report flag defaults to
// Bearer's general "security" report, which includes plenty of generic
// SAST rules (path traversal, weak crypto, ...) that have nothing to do
// with personal data — those must NOT be mislabeled as pii-dataflow
// findings just because they came from the same bearer invocation.
test('checkPiiDataFlow: findings without a PII/Personal Data category_groups tag are filtered out, not mislabeled', async () => {
  const bearerBinary = await makeFakeBearer({
    high: [
      { id: 'python_lang_path_traversal', title: 'Unsanitized dynamic input in file path', filename: 'restore.py', line_number: 12 }, // no category_groups — generic SAST, not PII
      { id: 'js.pii-in-log', title: 'PII leaked to logger', filename: 'app.js', line_number: 3, category_groups: ['PII', 'Personal Data'] },
    ],
  });
  await withServerEnv({ BEARER_ENABLED: 'true', BEARER_BINARY: bearerBinary }, async (mod) => {
    const dir = await makeTempProject({ 'restore.py': 'pass\n', 'app.js': 'console.log(1);\n' });
    const { findings, engine } = await mod.checkPiiDataFlow(dir, noopLog);
    assert.equal(engine, 'bearer');
    assert.equal(findings.length, 1, 'the non-PII path-traversal finding should be filtered out');
    assert.equal(findings[0].kind, 'js.pii-in-log');
  })();
});

test('checkPiiDataFlow: real bearer binary end-to-end on a fresh (non-git) project (skipped if bearer is not installed)', async (t) => {
  if (!(await hasRealBearer())) {
    t.skip('bearer not installed on PATH — install with `brew install bearer/tap/bearer` to run this test');
    return;
  }
  await withServerEnv({ BEARER_ENABLED: 'true', BEARER_BINARY: 'bearer' }, async (mod) => {
    const dir = await makeTempProject({
      'app.js': [
        'function saveUser(req, res) {',
        '  const user = { name: req.body.name, email: req.body.email, ssn: req.body.ssn };',
        '  console.log("Saving user with SSN: " + user.ssn);',
        '  db.query("INSERT INTO users (name, email, ssn) VALUES (?, ?, ?)", [user.name, user.email, user.ssn]);',
        '}',
        'module.exports = saveUser;',
        '',
      ].join('\n'),
    });
    // No git repo pre-staged here on purpose — exercises
    // ensureGitContextForBearer bootstrapping a throwaway one from scratch,
    // same as a fresh ZIP/folder upload would need.
    const { findings, engine } = await mod.checkPiiDataFlow(dir, noopLog);
    assert.equal(engine, 'bearer');
    assert.ok(findings.length >= 1, 'real bearer should flag the SSN logged/queried in plaintext');
    assert.ok(findings.every((f) => f.tool === 'bearer'));
    assert.ok(findings.every((f) => f.file === 'app.js'));
  })();
});
