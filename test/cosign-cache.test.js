'use strict';

/**
 * cosign's per-image verify verdict is cached with a TTL (db-store.js's
 * cosign_verify_cache) — unlike GuardDog's manifest cache (permanent, since
 * an npm/PyPI package version's published content never changes), a Docker
 * image *tag* is a mutable reference that can be re-pushed to point at
 * different content at any time, so caching it forever would risk serving a
 * stale signature verdict. security.cosign.cacheTtlSeconds bounds that
 * staleness window (default 1h) instead.
 *
 * Uses a fake cosign CLI that counts real `verify` invocations to a file,
 * so a cache hit/miss/TTL-expiry can be proven directly.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');

const { withServerEnv, makeTempProject } = require('./helpers');

const noopLog = () => {};

async function makeFakeCosignWithCallLog(verifiedImages, callLogPath) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ignite-fake-cosign-cache-'));
  const scriptPath = path.join(dir, 'cosign');
  const script = `#!/usr/bin/env node
const fs = require('fs');
const args = process.argv.slice(2);
if (args[0] === 'version') { process.stdout.write('fake-cosign 1.0.0\\n'); process.exit(0); }
if (args[0] === 'verify') {
  fs.appendFileSync(${JSON.stringify(callLogPath)}, '1\\n');
  const image = args[args.length - 1];
  const verified = ${JSON.stringify(verifiedImages)};
  if (verified.includes(image)) { process.stdout.write('Verification for ' + image + ' --\\n'); process.exit(0); }
  process.stderr.write('Error: no signatures found\\n');
  process.exit(1);
}
process.exit(1);
`;
  await fs.writeFile(scriptPath, script, { mode: 0o755 });
  return scriptPath;
}

async function countCalls(callLogPath) {
  try {
    const content = await fs.readFile(callLogPath, 'utf8');
    return content.split('\n').filter(Boolean).length;
  } catch {
    return 0;
  }
}

test('checkImageProvenance: same image verified twice within the TTL is a cache hit — cosign is not re-invoked', async () => {
  const callLogDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ignite-cosign-calllog-'));
  const callLogPath = path.join(callLogDir, 'calls.log');
  const cosignBinary = await makeFakeCosignWithCallLog(['cgr.dev/chainguard/static:latest'], callLogPath);

  await withServerEnv({ COSIGN_ENABLED: 'true', COSIGN_BINARY: cosignBinary }, async (mod) => {
    const dir = await makeTempProject({ Dockerfile: 'FROM cgr.dev/chainguard/static:latest\n' });

    const first = await mod.checkImageProvenance(dir, noopLog);
    assert.deepEqual(first.findings, []);
    assert.equal(await countCalls(callLogPath), 1, 'first check must actually invoke cosign');

    const logs = [];
    const second = await mod.checkImageProvenance(dir, (m) => logs.push(m));
    assert.deepEqual(second.findings, []);
    assert.equal(await countCalls(callLogPath), 1, 'second check within the TTL must be a cache hit — cosign must not run again');
    assert.ok(logs.some((l) => l.includes('signature-verdict cache')), 'cache hit should be logged, not silent');
  })();

  await fs.rm(callLogDir, { recursive: true, force: true });
});

test('checkImageProvenance: cache is scoped per (image, identityRegexp, issuerRegexp) — a different regexp is a cache miss', async () => {
  const callLogDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ignite-cosign-calllog-'));
  const callLogPath = path.join(callLogDir, 'calls.log');
  const cosignBinary = await makeFakeCosignWithCallLog(['cgr.dev/chainguard/static:latest'], callLogPath);

  await withServerEnv({ COSIGN_ENABLED: 'true', COSIGN_BINARY: cosignBinary, COSIGN_IDENTITY_REGEXP: 'https://github.com/foo/.*' }, async (mod) => {
    const dir = await makeTempProject({ Dockerfile: 'FROM cgr.dev/chainguard/static:latest\n' });
    await mod.checkImageProvenance(dir, noopLog);
    assert.equal(await countCalls(callLogPath), 1);
  })();

  // A second, differently-configured server instance (different
  // COSIGN_IDENTITY_REGEXP) sharing the same on-disk DB must NOT reuse the
  // first instance's cached verdict — a verify performed under a narrower
  // identity constraint doesn't guarantee anything under a wider one.
  const tmpDbDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ignite-cosign-shared-db-'));
  const dbPath = path.join(tmpDbDir, 'shared.db');
  await withServerEnv({ COSIGN_ENABLED: 'true', COSIGN_BINARY: cosignBinary, COSIGN_IDENTITY_REGEXP: 'https://github.com/foo/.*', IGNITE_DB_PATH: dbPath }, async (mod) => {
    const dir = await makeTempProject({ Dockerfile: 'FROM cgr.dev/chainguard/static:latest\n' });
    await mod.checkImageProvenance(dir, noopLog);
  })();
  await withServerEnv({ COSIGN_ENABLED: 'true', COSIGN_BINARY: cosignBinary, COSIGN_IDENTITY_REGEXP: '.*', IGNITE_DB_PATH: dbPath }, async (mod) => {
    const dir = await makeTempProject({ Dockerfile: 'FROM cgr.dev/chainguard/static:latest\n' });
    await mod.checkImageProvenance(dir, noopLog);
  })();
  assert.equal(await countCalls(callLogPath), 3, 'different identityRegexp must not share a cache entry');

  await fs.rm(callLogDir, { recursive: true, force: true });
  await fs.rm(tmpDbDir, { recursive: true, force: true });
});

test('checkImageProvenance: cacheTtlSeconds=0 disables caching entirely', async () => {
  const callLogDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ignite-cosign-calllog-'));
  const callLogPath = path.join(callLogDir, 'calls.log');
  const cosignBinary = await makeFakeCosignWithCallLog(['cgr.dev/chainguard/static:latest'], callLogPath);

  await withServerEnv({ COSIGN_ENABLED: 'true', COSIGN_BINARY: cosignBinary, COSIGN_CACHE_TTL_SECONDS: '0' }, async (mod) => {
    const dir = await makeTempProject({ Dockerfile: 'FROM cgr.dev/chainguard/static:latest\n' });
    await mod.checkImageProvenance(dir, noopLog);
    await mod.checkImageProvenance(dir, noopLog);
    assert.equal(await countCalls(callLogPath), 2, 'TTL=0 must re-verify every time');
  })();

  await fs.rm(callLogDir, { recursive: true, force: true });
});

test('checkImageProvenance: an expired cache entry (TTL=1s, waited past it) triggers a real re-verify', async () => {
  const callLogDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ignite-cosign-calllog-'));
  const callLogPath = path.join(callLogDir, 'calls.log');
  const cosignBinary = await makeFakeCosignWithCallLog(['cgr.dev/chainguard/static:latest'], callLogPath);

  await withServerEnv({ COSIGN_ENABLED: 'true', COSIGN_BINARY: cosignBinary, COSIGN_CACHE_TTL_SECONDS: '1' }, async (mod) => {
    const dir = await makeTempProject({ Dockerfile: 'FROM cgr.dev/chainguard/static:latest\n' });
    await mod.checkImageProvenance(dir, noopLog);
    await new Promise((r) => setTimeout(r, 1300));
    await mod.checkImageProvenance(dir, noopLog);
    assert.equal(await countCalls(callLogPath), 2, 'an entry older than the TTL must not be reused');
  })();

  await fs.rm(callLogDir, { recursive: true, force: true });
});
