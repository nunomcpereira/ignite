'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');

const { withServerEnv, makeTempProject, makeFakePicklescan } = require('./helpers');

const noopLog = () => {};

function hasRealPicklescan() {
  return new Promise((resolve) => {
    execFile('picklescan', ['--help'], (err) => resolve(!err));
  });
}

test('checkModelArtifactSecurity: picklescan is enabled by default', withServerEnv({}, async (mod) => {
  const cfg = mod.loadConfig();
  assert.equal(cfg.security.picklescan.enabled, true);
  assert.equal(cfg.security.picklescan.binary, 'picklescan');
}));

test('checkModelArtifactSecurity: PICKLESCAN_* env vars are wired into CONFIG.security.picklescan', withServerEnv(
  { PICKLESCAN_ENABLED: 'true', PICKLESCAN_BINARY: '/opt/bin/picklescan' },
  async (mod) => {
    const cfg = mod.loadConfig();
    assert.equal(cfg.security.picklescan.enabled, true);
    assert.equal(cfg.security.picklescan.binary, '/opt/bin/picklescan');
  }
));

test('checkModelArtifactSecurity: explicitly disabled — no findings, engine "disabled"', withServerEnv(
  { PICKLESCAN_ENABLED: 'false' },
  async (mod) => {
    const dir = await makeTempProject({ 'model.pkl': 'not a real pickle' });
    const { findings, engine } = await mod.checkModelArtifactSecurity(dir, noopLog);
    assert.equal(engine, 'disabled');
    assert.deepEqual(findings, []);
  }
));

test('checkModelArtifactSecurity: no model artifacts in the project — no picklescan invocation, no findings', async () => {
  const picklescanBinary = await makeFakePicklescan([]);
  await withServerEnv({ PICKLESCAN_ENABLED: 'true', PICKLESCAN_BINARY: picklescanBinary }, async (mod) => {
    const dir = await makeTempProject({ 'README.md': '# demo\n' });
    const { findings, engine } = await mod.checkModelArtifactSecurity(dir, noopLog);
    assert.equal(engine, 'picklescan');
    assert.deepEqual(findings, []);
  })();
});

test('checkModelArtifactSecurity: flags a dangerous global import in a .pkl file', async () => {
  const picklescanBinary = await makeFakePicklescan([
    "{root}/model.pkl: global import '__builtin__ eval' FOUND",
  ]);
  await withServerEnv({ PICKLESCAN_ENABLED: 'true', PICKLESCAN_BINARY: picklescanBinary }, async (mod) => {
    const dir = await makeTempProject({ 'model.pkl': 'fake pickle bytes' });
    const { findings, engine } = await mod.checkModelArtifactSecurity(dir, noopLog);
    assert.equal(engine, 'picklescan');
    assert.equal(findings.length, 1);
    assert.equal(findings[0].file, 'model.pkl');
    assert.equal(findings[0].tool, 'picklescan');
    assert.equal(findings[0].severity, 'error');
    assert.match(findings[0].message, /__builtin__ eval/);
  })();
});

test('checkModelArtifactSecurity: flags a dangerous global import inside an archive member (.pt checkpoint)', async () => {
  const picklescanBinary = await makeFakePicklescan([
    "{root}/checkpoint.pt:archive/data.pkl: global import 'os system' FOUND",
  ]);
  await withServerEnv({ PICKLESCAN_ENABLED: 'true', PICKLESCAN_BINARY: picklescanBinary }, async (mod) => {
    const dir = await makeTempProject({ 'checkpoint.pt': 'fake weights' });
    const { findings, engine } = await mod.checkModelArtifactSecurity(dir, noopLog);
    assert.equal(engine, 'picklescan');
    assert.equal(findings.length, 1);
    assert.equal(findings[0].file, 'checkpoint.pt');
    assert.match(findings[0].message, /os system/);
    assert.match(findings[0].message, /archive\/data\.pkl/);
  })();
});

test('checkModelArtifactSecurity: clean scan produces no findings', async () => {
  const picklescanBinary = await makeFakePicklescan([]);
  await withServerEnv({ PICKLESCAN_ENABLED: 'true', PICKLESCAN_BINARY: picklescanBinary }, async (mod) => {
    const dir = await makeTempProject({ 'checkpoint.pt': 'fake weights' });
    const { findings, engine } = await mod.checkModelArtifactSecurity(dir, noopLog);
    assert.equal(engine, 'picklescan');
    assert.deepEqual(findings, []);
  })();
});

test('checkModelArtifactSecurity: only scans configured extensions', async () => {
  const picklescanBinary = await makeFakePicklescan([]);
  await withServerEnv({ PICKLESCAN_ENABLED: 'true', PICKLESCAN_BINARY: picklescanBinary }, async (mod) => {
    const dir = await makeTempProject({ 'weights.safetensors': 'not pickle-based, out of scope' });
    const { findings, engine } = await mod.checkModelArtifactSecurity(dir, noopLog);
    // No .pkl/.pt/.pth/.ckpt/.bin present -> no invocation at all.
    assert.equal(engine, 'picklescan');
    assert.deepEqual(findings, []);
  })();
});

test('checkModelArtifactSecurity: picklescan enabled but binary missing — soft-skips, no findings, no throw', async () => {
  await withServerEnv({ PICKLESCAN_ENABLED: 'true', PICKLESCAN_BINARY: '/nonexistent/picklescan-xyz' }, async (mod) => {
    const dir = await makeTempProject({ 'model.pkl': 'fake pickle bytes' });
    const logs = [];
    const { findings, engine } = await mod.checkModelArtifactSecurity(dir, (m) => logs.push(m));
    assert.equal(engine, 'disabled');
    assert.deepEqual(findings, []);
    assert.ok(logs.some((l) => l.includes('picklescan')), 'failure is logged, not thrown');
  })();
});

test('checkModelArtifactSecurity: real picklescan binary end-to-end (skipped if picklescan is not installed)', async (t) => {
  if (!(await hasRealPicklescan())) {
    t.skip('picklescan not installed on PATH — install with `pip install picklescan` to run this test');
    return;
  }
  await withServerEnv({ PICKLESCAN_ENABLED: 'true', PICKLESCAN_BINARY: 'picklescan' }, async (mod) => {
    const dir = await makeTempProject({ 'README.md': '# demo, no model artifacts\n' });
    const { findings, engine } = await mod.checkModelArtifactSecurity(dir, noopLog);
    assert.equal(engine, 'picklescan');
    assert.deepEqual(findings, []);
  })();
});
