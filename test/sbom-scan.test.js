'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');

const { withServerEnv, makeTempProject, makeFakeSyft } = require('./helpers');

const noopLog = () => {};

function hasRealSyft() {
  return new Promise((resolve) => {
    execFile('syft', ['version'], (err) => resolve(!err));
  });
}

test('generateSbom: syft is enabled by default', withServerEnv({}, async (mod) => {
  const cfg = mod.loadConfig();
  assert.equal(cfg.sbom.syft.enabled, true);
  assert.equal(cfg.sbom.syft.binary, 'syft');
}));

test('generateSbom: SYFT_* env vars are wired into CONFIG.sbom.syft', withServerEnv(
  { SYFT_ENABLED: 'false', SYFT_BINARY: '/opt/bin/syft' },
  async (mod) => {
    const cfg = mod.loadConfig();
    assert.equal(cfg.sbom.syft.enabled, false);
    assert.equal(cfg.sbom.syft.binary, '/opt/bin/syft');
  }
));

test('generateSbom: falls back to a manifest-derived component list when syft is disabled', withServerEnv(
  { SYFT_ENABLED: 'false' },
  async (mod) => {
    const dir = await makeTempProject({
      'package.json': JSON.stringify({ name: 'demo', dependencies: { lodash: '4.17.21' } }),
    });
    const { engine, sbom } = await mod.generateSbom(dir, noopLog);
    assert.equal(engine, 'fallback');
    assert.equal(sbom.bomFormat, 'ignite-fallback');
    assert.equal(sbom.components.length, 1);
    assert.equal(sbom.components[0].name, 'lodash');
    assert.equal(sbom.components[0].ecosystem, 'npm');
  }
));

test('generateSbom: syft enabled but binary missing — soft-fails back to the fallback component list', withServerEnv(
  { SYFT_ENABLED: 'true', SYFT_BINARY: '/nonexistent/syft-binary-xyz' },
  async (mod) => {
    const dir = await makeTempProject({
      'package.json': JSON.stringify({ name: 'demo', dependencies: { lodash: '4.17.21' } }),
    });
    const logs = [];
    const { engine, sbom } = await mod.generateSbom(dir, (m) => logs.push(m));
    assert.equal(engine, 'fallback');
    assert.equal(sbom.components.length, 1);
    assert.ok(logs.some((l) => l.includes('syft')), 'failure is logged, not thrown');
  }
));

test('generateSbom: parses fake syft CycloneDX output', async () => {
  const fakeSbom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.7',
    components: [{ name: 'lodash', version: '4.17.21', type: 'library' }],
  };
  const syftBinary = await makeFakeSyft(fakeSbom);
  await withServerEnv({ SYFT_ENABLED: 'true', SYFT_BINARY: syftBinary }, async (mod) => {
    const dir = await makeTempProject({ 'package.json': '{}' });
    const { engine, sbom } = await mod.generateSbom(dir, noopLog);
    assert.equal(engine, 'syft');
    assert.equal(sbom.bomFormat, 'CycloneDX');
    assert.equal(sbom.components.length, 1);
    assert.equal(sbom.components[0].name, 'lodash');
  })();
});

test('generateSbom: real syft binary end-to-end (skipped if syft is not installed)', async (t) => {
  if (!(await hasRealSyft())) {
    t.skip('syft not installed on PATH — install with `brew install syft` to run this test');
    return;
  }
  await withServerEnv({ SYFT_ENABLED: 'true', SYFT_BINARY: 'syft' }, async (mod) => {
    const dir = await makeTempProject({
      'package.json': JSON.stringify({ name: 'demo', version: '1.0.0', dependencies: { lodash: '4.17.21' } }),
      'package-lock.json': JSON.stringify({
        name: 'demo', version: '1.0.0', lockfileVersion: 3, requires: true,
        packages: {
          '': { name: 'demo', version: '1.0.0', dependencies: { lodash: '4.17.21' } },
          'node_modules/lodash': { version: '4.17.21', license: 'MIT' },
        },
      }),
    });
    const { engine, sbom } = await mod.generateSbom(dir, noopLog);
    assert.equal(engine, 'syft');
    assert.equal(sbom.bomFormat, 'CycloneDX');
    assert.ok(sbom.components.length >= 1, 'real syft should catalog at least the lodash dependency');
    assert.ok(sbom.components.some((c) => c.name === 'lodash'));
  })();
});
