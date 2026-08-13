'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');

const { withServerEnv, makeTempProject, makeFakeCosign } = require('./helpers');

const noopLog = () => {};

function hasRealCosign() {
  return new Promise((resolve) => {
    execFile('cosign', ['version'], (err) => resolve(!err));
  });
}

test('checkImageProvenance: cosign is enabled by default', withServerEnv({}, async (mod) => {
  const cfg = mod.loadConfig();
  assert.equal(cfg.security.cosign.enabled, true);
  assert.equal(cfg.security.cosign.binary, 'cosign');
  assert.equal(cfg.security.cosign.identityRegexp, '.*');
  assert.equal(cfg.security.cosign.issuerRegexp, '.*');
}));

test('checkImageProvenance: COSIGN_* env vars are wired into CONFIG.security.cosign', withServerEnv(
  { COSIGN_ENABLED: 'true', COSIGN_BINARY: '/opt/bin/cosign', COSIGN_IDENTITY_REGEXP: 'https://github.com/.*', COSIGN_ISSUER_REGEXP: 'https://token.actions.githubusercontent.com' },
  async (mod) => {
    const cfg = mod.loadConfig();
    assert.equal(cfg.security.cosign.enabled, true);
    assert.equal(cfg.security.cosign.binary, '/opt/bin/cosign');
    assert.equal(cfg.security.cosign.identityRegexp, 'https://github.com/.*');
    assert.equal(cfg.security.cosign.issuerRegexp, 'https://token.actions.githubusercontent.com');
  }
));

test('checkImageProvenance: explicitly disabled — no findings, engine "disabled"', withServerEnv(
  { COSIGN_ENABLED: 'false' },
  async (mod) => {
    const dir = await makeTempProject({ Dockerfile: 'FROM ubuntu:22.04\n' });
    const { findings, engine } = await mod.checkImageProvenance(dir, noopLog);
    assert.equal(engine, 'disabled');
    assert.deepEqual(findings, []);
  }
));

test('checkImageProvenance: no Dockerfiles in the project — no cosign invocation, no findings', async () => {
  const cosignBinary = await makeFakeCosign([]);
  await withServerEnv({ COSIGN_ENABLED: 'true', COSIGN_BINARY: cosignBinary }, async (mod) => {
    const dir = await makeTempProject({ 'README.md': '# demo\n' });
    const { findings, engine } = await mod.checkImageProvenance(dir, noopLog);
    assert.equal(engine, 'cosign');
    assert.deepEqual(findings, []);
  })();
});

test('checkImageProvenance: flags an unsigned base image, clears a signed one', async () => {
  const cosignBinary = await makeFakeCosign(['cgr.dev/chainguard/static:latest']);
  await withServerEnv({ COSIGN_ENABLED: 'true', COSIGN_BINARY: cosignBinary }, async (mod) => {
    const dir = await makeTempProject({
      Dockerfile: 'FROM cgr.dev/chainguard/static:latest AS base\nFROM ubuntu:22.04\nCOPY --from=base / /\n',
    });
    const { findings, engine } = await mod.checkImageProvenance(dir, noopLog);
    assert.equal(engine, 'cosign');
    assert.equal(findings.length, 1);
    assert.equal(findings[0].line, 2);
    assert.match(findings[0].message, /ubuntu:22\.04/);
    assert.equal(findings[0].tool, 'cosign');
    assert.equal(findings[0].severity, 'warning');
  })();
});

test('checkImageProvenance: multi-stage build-stage aliases (FROM base) are not treated as external images', async () => {
  const cosignBinary = await makeFakeCosign(['ubuntu:22.04']);
  await withServerEnv({ COSIGN_ENABLED: 'true', COSIGN_BINARY: cosignBinary }, async (mod) => {
    const dir = await makeTempProject({
      Dockerfile: 'FROM ubuntu:22.04 AS base\nFROM base\nCMD ["true"]\n',
    });
    const { findings } = await mod.checkImageProvenance(dir, noopLog);
    assert.deepEqual(findings, []);
  })();
});

test('checkImageProvenance: cosign enabled but binary missing — soft-skips, no findings, no throw', async () => {
  await withServerEnv({ COSIGN_ENABLED: 'true', COSIGN_BINARY: '/nonexistent/cosign-xyz' }, async (mod) => {
    const dir = await makeTempProject({ Dockerfile: 'FROM ubuntu:22.04\n' });
    const logs = [];
    const { findings, engine } = await mod.checkImageProvenance(dir, (m) => logs.push(m));
    assert.equal(engine, 'disabled');
    assert.deepEqual(findings, []);
    assert.ok(logs.some((l) => l.includes('cosign')), 'failure is logged, not thrown');
  })();
});

test('checkImageProvenance: real cosign binary end-to-end (skipped if cosign is not installed or offline)', async (t) => {
  if (!(await hasRealCosign())) {
    t.skip('cosign not installed on PATH — install with `brew install cosign` to run this test');
    return;
  }
  await withServerEnv({ COSIGN_ENABLED: 'true', COSIGN_BINARY: 'cosign' }, async (mod) => {
    const dir = await makeTempProject({
      Dockerfile: 'FROM cgr.dev/chainguard/static:latest AS base\nFROM ubuntu:22.04\nCOPY --from=base / /\n',
    });
    const { findings, engine } = await mod.checkImageProvenance(dir, noopLog);
    assert.equal(engine, 'cosign');
    // Network-dependent (real registry + Rekor calls) — only assert on the
    // parts that don't depend on Sigstore/registry state at test time.
    assert.ok(findings.every((f) => f.tool === 'cosign'));
    assert.ok(findings.every((f) => f.file === 'Dockerfile'));
  })();
});
