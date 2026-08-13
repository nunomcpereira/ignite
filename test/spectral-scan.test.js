'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');

const { withServerEnv, makeTempProject, makeFakeSpectral } = require('./helpers');

const noopLog = () => {};

function hasRealSpectral() {
  return new Promise((resolve) => {
    execFile('spectral', ['--version'], (err) => resolve(!err));
  });
}

const OPENAPI_MISSING_INFO = [
  'openapi: 3.0.0',
  'info:',
  '  title: Demo API',
  'paths:',
  '  /users:',
  '    get:',
  '      responses:',
  "        '200':",
  '          description: OK',
  '',
].join('\n');

test('checkApiSchemas: spectral is enabled by default', withServerEnv({}, async (mod) => {
  const cfg = mod.loadConfig();
  assert.equal(cfg.api.spectral.enabled, true);
  assert.equal(cfg.api.spectral.binary, 'spectral');
  assert.ok(cfg.api.spectral.ruleset.endsWith('spectral-default-ruleset.yaml'));
}));

test('checkApiSchemas: SPECTRAL_* env vars are wired into CONFIG.api.spectral', withServerEnv(
  { SPECTRAL_ENABLED: 'false', SPECTRAL_BINARY: '/opt/bin/spectral', SPECTRAL_RULESET: '/etc/my-ruleset.yaml' },
  async (mod) => {
    const cfg = mod.loadConfig();
    assert.equal(cfg.api.spectral.enabled, false);
    assert.equal(cfg.api.spectral.binary, '/opt/bin/spectral');
    assert.equal(cfg.api.spectral.ruleset, '/etc/my-ruleset.yaml');
  }
));

test('checkApiSchemas: disabled — no findings, engine "disabled"', withServerEnv(
  { SPECTRAL_ENABLED: 'false' },
  async (mod) => {
    const dir = await makeTempProject({ 'openapi.yaml': OPENAPI_MISSING_INFO });
    const { findings, engine } = await mod.checkApiSchemas(dir, noopLog);
    assert.equal(engine, 'disabled');
    assert.deepEqual(findings, []);
  }
));

test('checkApiSchemas: enabled but binary missing — soft-skips, no throw', async () => {
  await withServerEnv({ SPECTRAL_ENABLED: 'true', SPECTRAL_BINARY: '/nonexistent/spectral-xyz' }, async (mod) => {
    const dir = await makeTempProject({ 'openapi.yaml': OPENAPI_MISSING_INFO });
    const logs = [];
    const { findings, engine } = await mod.checkApiSchemas(dir, (m) => logs.push(m));
    assert.equal(engine, 'disabled');
    assert.deepEqual(findings, []);
    assert.ok(logs.some((l) => l.includes('spectral')), 'failure is logged, not thrown');
  })();
});

test('checkApiSchemas: no OpenAPI/AsyncAPI files in the project — no spectral invocation, no findings', async () => {
  const spectralBinary = await makeFakeSpectral([]);
  await withServerEnv({ SPECTRAL_ENABLED: 'true', SPECTRAL_BINARY: spectralBinary }, async (mod) => {
    const dir = await makeTempProject({ 'README.md': '# demo\n', 'config.yaml': 'foo: bar\n' });
    const { findings, engine } = await mod.checkApiSchemas(dir, noopLog);
    assert.equal(engine, 'spectral');
    assert.deepEqual(findings, []);
  })();
});

test('checkApiSchemas: discovers a schema file by content (not just filename) and parses findings', async () => {
  const spectralBinary = await makeFakeSpectral([
    { code: 'info-contact', message: 'Info object must have "contact" object.', severity: 1, range: { start: { line: 1 } }, source: 'api/spec.yaml' },
    { code: 'oas3-api-servers', message: 'OpenAPI "servers" must be present and non-empty array.', severity: 0, range: { start: { line: 0 } }, source: 'api/spec.yaml' },
  ]);
  await withServerEnv({ SPECTRAL_ENABLED: 'true', SPECTRAL_BINARY: spectralBinary }, async (mod) => {
    const dir = await makeTempProject({ 'api/spec.yaml': OPENAPI_MISSING_INFO });
    const { findings, engine } = await mod.checkApiSchemas(dir, noopLog);
    assert.equal(engine, 'spectral');
    assert.equal(findings.length, 2);
    const byKind = Object.fromEntries(findings.map((f) => [f.kind, f]));
    assert.equal(byKind['info-contact'].severity, 'warning');
    assert.equal(byKind['info-contact'].line, 2, 'spectral 0-indexed line 1 becomes 1-indexed line 2');
    assert.equal(byKind['oas3-api-servers'].severity, 'error');
    assert.ok(findings.every((f) => f.file === 'api/spec.yaml'));
    assert.ok(findings.every((f) => f.tool === 'spectral'));
  })();
});

test('checkApiSchemas: real spectral binary end-to-end (skipped if spectral is not installed)', async (t) => {
  if (!(await hasRealSpectral())) {
    t.skip('spectral not installed on PATH — install with `npm install -g @stoplight/spectral-cli` to run this test');
    return;
  }
  await withServerEnv({ SPECTRAL_ENABLED: 'true', SPECTRAL_BINARY: 'spectral' }, async (mod) => {
    const dir = await makeTempProject({ 'openapi.yaml': OPENAPI_MISSING_INFO });
    const { findings, engine } = await mod.checkApiSchemas(dir, noopLog);
    assert.equal(engine, 'spectral');
    assert.ok(findings.length >= 3, 'real spectral (spectral:oas ruleset) should flag missing servers/contact/description at minimum');
    assert.ok(findings.every((f) => f.tool === 'spectral'));
    assert.ok(findings.every((f) => f.file === 'openapi.yaml'));
  })();
});
