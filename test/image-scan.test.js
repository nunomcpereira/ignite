'use strict';

/**
 * checkContainerImageVulnerabilities (OWASP A06 gap: `trivy config` only
 * lints the Dockerfile source, never what's actually installed inside the
 * image it builds). Off by default — TRIVY_IMAGE_ENABLED must be explicitly
 * set. Fake `docker`/`trivy` CLIs on PATH (makeFakeDockerAndTrivyImage) so
 * the real build+scan+cleanup path is exercised without a real Docker
 * daemon or network image pull.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');

const { withServerEnv, makeTempProject, makeFakeDockerAndTrivyImage } = require('./helpers');

const noopLog = () => {};

async function withPath(binDir, fn) {
  const prevPath = process.env.PATH;
  process.env.PATH = `${binDir}:${prevPath}`;
  try {
    return await fn();
  } finally {
    process.env.PATH = prevPath;
  }
}

function hasRealDockerAndTrivy() {
  return new Promise((resolve) => {
    execFile('docker', ['info'], (dockerErr) => {
      if (dockerErr) return resolve(false);
      execFile('trivy', ['--version'], (trivyErr) => resolve(!trivyErr));
    });
  });
}

test('checkContainerImageVulnerabilities: off by default', withServerEnv({}, async (mod) => {
  const cfg = mod.loadConfig();
  assert.equal(cfg.security.trivyImage.enabled, false);
  assert.equal(cfg.security.trivyImage.severityThreshold, 'HIGH,CRITICAL');
}));

test('checkContainerImageVulnerabilities: TRIVY_IMAGE_* env vars are wired into CONFIG.security.trivyImage', withServerEnv(
  { TRIVY_IMAGE_ENABLED: 'true', TRIVY_IMAGE_SEVERITY: 'CRITICAL' },
  async (mod) => {
    const cfg = mod.loadConfig();
    assert.equal(cfg.security.trivyImage.enabled, true);
    assert.equal(cfg.security.trivyImage.severityThreshold, 'CRITICAL');
  }
));

test('checkContainerImageVulnerabilities: disabled — no findings, engine "disabled"', withServerEnv(
  { TRIVY_IMAGE_ENABLED: 'false' },
  async (mod) => {
    const dir = await makeTempProject({ Dockerfile: 'FROM ubuntu:22.04\n' });
    const { findings, engine } = await mod.checkContainerImageVulnerabilities(dir, noopLog);
    assert.equal(engine, 'disabled');
    assert.deepEqual(findings, []);
  }
));

test('checkContainerImageVulnerabilities: no Dockerfile in the project — no build, no findings', async () => {
  const binDir = await makeFakeDockerAndTrivyImage([]);
  await withPath(binDir, () => withServerEnv({ TRIVY_IMAGE_ENABLED: 'true' }, async (mod) => {
    const dir = await makeTempProject({ 'README.md': '# demo\n' });
    const { findings, engine } = await mod.checkContainerImageVulnerabilities(dir, noopLog);
    assert.equal(engine, 'trivy-image');
    assert.deepEqual(findings, []);
  })());
});

test('checkContainerImageVulnerabilities: builds the Dockerfile, parses fake trivy image findings', async () => {
  const binDir = await makeFakeDockerAndTrivyImage([
    {
      VulnerabilityID: 'CVE-2024-9999',
      PkgName: 'openssl',
      InstalledVersion: '1.1.1',
      FixedVersion: '1.1.1w',
      Severity: 'CRITICAL',
      Title: 'OpenSSL buffer overflow',
    },
  ]);
  await withPath(binDir, () => withServerEnv({ TRIVY_IMAGE_ENABLED: 'true' }, async (mod) => {
    const dir = await makeTempProject({ Dockerfile: 'FROM ubuntu:22.04\n' });
    const logs = [];
    const { findings, engine } = await mod.checkContainerImageVulnerabilities(dir, (m) => logs.push(m));
    assert.equal(engine, 'trivy-image');
    assert.equal(findings.length, 1);
    assert.equal(findings[0].file, 'Dockerfile');
    assert.equal(findings[0].severity, 'critical');
    assert.equal(findings[0].tool, 'trivy-image');
    assert.match(findings[0].message, /openssl@1\.1\.1/);
    assert.match(findings[0].message, /fixed in 1\.1\.1w/);
    assert.ok(logs.some((l) => l.includes('build')));
  })());
});

test('checkContainerImageVulnerabilities: enabled but docker/trivy missing — soft-skips, no throw', async () => {
  // PATH is replaced (not prepended) with an empty dir so this is
  // deterministic regardless of whether the host machine actually has
  // docker/trivy installed — unlike the *_BINARY env vars the rest of this
  // suite uses to force "missing" (gitleaks/trivy/cosign/...), `docker` is
  // always the literal PATH-resolved command name in runTool, not
  // configurable.
  const prevPath = process.env.PATH;
  const emptyDir = await require('node:fs/promises').mkdtemp(require('node:path').join(require('node:os').tmpdir(), 'ignite-empty-path-'));
  process.env.PATH = emptyDir;
  try {
    await withServerEnv({ TRIVY_IMAGE_ENABLED: 'true' }, async (mod) => {
      const dir = await makeTempProject({ Dockerfile: 'FROM ubuntu:22.04\n' });
      const logs = [];
      const { findings, engine } = await mod.checkContainerImageVulnerabilities(dir, (m) => logs.push(m));
      assert.equal(engine, 'disabled');
      assert.deepEqual(findings, []);
      assert.ok(logs.some((l) => l.includes('Container image CVE scan skipped')), 'failure is logged, not thrown');
    })();
  } finally {
    process.env.PATH = prevPath;
  }
});

test('checkContainerImageVulnerabilities: real docker+trivy end-to-end (skipped if either is not installed)', async (t) => {
  if (!(await hasRealDockerAndTrivy())) {
    t.skip('docker/trivy not installed or Docker daemon not running — start Docker Desktop and `brew install trivy` to run this test');
    return;
  }
  await withServerEnv({ TRIVY_IMAGE_ENABLED: 'true' }, async (mod) => {
    const dir = await makeTempProject({ Dockerfile: 'FROM alpine:3.19\n' });
    const { findings, engine } = await mod.checkContainerImageVulnerabilities(dir, noopLog);
    assert.equal(engine, 'trivy-image');
    assert.ok(findings.every((f) => f.tool === 'trivy-image'));
    assert.ok(findings.every((f) => f.file === 'Dockerfile'));
  })();
});
