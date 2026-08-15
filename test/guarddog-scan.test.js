'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');

const { withServerEnv, makeTempProject, makeFakeGuardDog } = require('./helpers');

const noopLog = () => {};

function hasRealGuardDog() {
  return new Promise((resolve) => {
    execFile('guarddog', ['--version'], (err) => resolve(!err));
  });
}

test('checkMaliciousDependencies: guarddog is enabled by default', withServerEnv({}, async (mod) => {
  const cfg = mod.loadConfig();
  assert.equal(cfg.security.guarddog.enabled, true);
  assert.equal(cfg.security.guarddog.binary, 'guarddog');
}));

test('checkMaliciousDependencies: GUARDDOG_* env vars are wired into CONFIG.security.guarddog', withServerEnv(
  { GUARDDOG_ENABLED: 'true', GUARDDOG_BINARY: '/opt/bin/guarddog' },
  async (mod) => {
    const cfg = mod.loadConfig();
    assert.equal(cfg.security.guarddog.enabled, true);
    assert.equal(cfg.security.guarddog.binary, '/opt/bin/guarddog');
  }
));

test('checkMaliciousDependencies: explicitly disabled — no findings, engine "disabled"', withServerEnv(
  { GUARDDOG_ENABLED: 'false' },
  async (mod) => {
    const dir = await makeTempProject({ 'package.json': '{"name":"demo","dependencies":{"left-pad":"1.0.0"}}' });
    const { findings, engine } = await mod.checkMaliciousDependencies(dir, noopLog);
    assert.equal(engine, 'disabled');
    assert.deepEqual(findings, []);
  }
));

test('checkMaliciousDependencies: no supported manifests in the project — no guarddog invocation, no findings', async () => {
  const guarddogBinary = await makeFakeGuardDog({});
  await withServerEnv({ GUARDDOG_ENABLED: 'true', GUARDDOG_BINARY: guarddogBinary }, async (mod) => {
    const dir = await makeTempProject({ 'README.md': '# demo\n' });
    const { findings, engine } = await mod.checkMaliciousDependencies(dir, noopLog);
    assert.equal(engine, 'guarddog');
    assert.deepEqual(findings, []);
  })();
});

test('checkMaliciousDependencies: flags an npm dependency with hit rules', async () => {
  const guarddogBinary = await makeFakeGuardDog({
    npm: {
      'evil-pkg==1.0.0': { issues: 1, results: { exfiltrate_sensitive_data: 'Package reads environment variables and sends them to a remote host', download_executable: false } },
    },
  });
  await withServerEnv({ GUARDDOG_ENABLED: 'true', GUARDDOG_BINARY: guarddogBinary }, async (mod) => {
    const dir = await makeTempProject({ 'package.json': '{"name":"demo","dependencies":{"evil-pkg":"1.0.0"}}' });
    const { findings, engine } = await mod.checkMaliciousDependencies(dir, noopLog);
    assert.equal(engine, 'guarddog');
    assert.equal(findings.length, 1);
    assert.equal(findings[0].file, 'package.json');
    assert.equal(findings[0].tool, 'guarddog');
    assert.equal(findings[0].severity, 'error');
    assert.match(findings[0].message, /evil-pkg==1\.0\.0/);
    assert.match(findings[0].message, /exfiltrate_sensitive_data/);
  })();
});

test('checkMaliciousDependencies: clean report produces no findings', async () => {
  const guarddogBinary = await makeFakeGuardDog({
    pypi: { 'requests==2.31.0': { issues: 0, results: {} } },
  });
  await withServerEnv({ GUARDDOG_ENABLED: 'true', GUARDDOG_BINARY: guarddogBinary }, async (mod) => {
    const dir = await makeTempProject({ 'requirements.txt': 'requests==2.31.0\n' });
    const { findings, engine } = await mod.checkMaliciousDependencies(dir, noopLog);
    assert.equal(engine, 'guarddog');
    assert.deepEqual(findings, []);
  })();
});

test('checkMaliciousDependencies: guarddog enabled but binary missing — soft-skips, no findings, no throw', async () => {
  await withServerEnv({ GUARDDOG_ENABLED: 'true', GUARDDOG_BINARY: '/nonexistent/guarddog-xyz' }, async (mod) => {
    const dir = await makeTempProject({ 'package.json': '{"name":"demo","dependencies":{"left-pad":"1.0.0"}}' });
    const logs = [];
    const { findings, engine } = await mod.checkMaliciousDependencies(dir, (m) => logs.push(m));
    assert.equal(engine, 'disabled');
    assert.deepEqual(findings, []);
    assert.ok(logs.some((l) => l.includes('guarddog')), 'failure is logged, not thrown');
  })();
});

test('checkMaliciousDependencies: real guarddog binary end-to-end (skipped if guarddog is not installed)', async (t) => {
  if (!(await hasRealGuardDog())) {
    t.skip('guarddog not installed on PATH — install with `pip install guarddog` to run this test');
    return;
  }
  await withServerEnv({ GUARDDOG_ENABLED: 'true', GUARDDOG_BINARY: 'guarddog' }, async (mod) => {
    const dir = await makeTempProject({ 'package.json': '{"name":"demo","dependencies":{"left-pad":"1.3.0"}}' });
    const { findings, engine } = await mod.checkMaliciousDependencies(dir, noopLog);
    assert.equal(engine, 'guarddog');
    assert.ok(findings.every((f) => f.tool === 'guarddog'));
  })();
});
