'use strict';

/**
 * GuardDog's per-manifest verdict is cached globally (db-store.js's
 * manifest_scan_cache), keyed by (ecosystem, manifest content hash, guarddog
 * version) — not by org/repo, since a byte-identical manifest scanned by the
 * same guarddog version has a deterministic result regardless of which
 * project submitted it. This is what made GuardDog the single largest
 * remaining chunk of Phase 4's wall time (~16s on Ignite's own repo,
 * measured directly): a cache hit skips the real per-dependency registry
 * fetch + static inspection entirely.
 *
 * These tests use a fake guarddog CLI that counts real `verify` invocations
 * to a file, so a cache hit can be proven directly (invocation count stays
 * at 1) rather than just inferred from timing.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');

const { withServerEnv, makeTempProject } = require('./helpers');

const noopLog = () => {};

// Like makeFakeGuardDog, but appends a line to `callLogPath` on every real
// `verify` invocation, so a test can assert the cache actually prevented a
// second invocation rather than just observing identical output.
async function makeFakeGuardDogWithCallLog(reportByEcosystem, callLogPath) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ignite-fake-guarddog-cache-'));
  const scriptPath = path.join(dir, 'guarddog');
  const script = `#!/usr/bin/env node
const fs = require('fs');
const args = process.argv.slice(2);
if (args[0] === '--version') { process.stdout.write('fake-guarddog 1.0.0\\n'); process.exit(0); }
const reports = ${JSON.stringify(reportByEcosystem)};
const ecosystem = args[0];
if (args[1] === 'verify') {
  fs.appendFileSync(${JSON.stringify(callLogPath)}, '1\\n');
  const report = reports[ecosystem] || {};
  process.stdout.write(JSON.stringify(report));
  const hasIssues = Object.values(report).some((e) => (e.issues || 0) > 0 || Object.values(e.results || {}).some(Boolean));
  process.exit(hasIssues ? 1 : 0);
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

test('checkMaliciousDependencies: identical manifest content is a cache hit on the second scan — guarddog is not re-invoked', async () => {
  const callLogDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ignite-guarddog-calllog-'));
  const callLogPath = path.join(callLogDir, 'calls.log');
  const guarddogBinary = await makeFakeGuardDogWithCallLog({
    npm: { 'left-pad@1.3.0': { issues: 1, results: { typosquatting: true } } },
  }, callLogPath);

  await withServerEnv({ GUARDDOG_ENABLED: 'true', GUARDDOG_BINARY: guarddogBinary }, async (mod) => {
    const dir = await makeTempProject({ 'package.json': JSON.stringify({ dependencies: { 'left-pad': '1.3.0' } }) });

    const first = await mod.checkMaliciousDependencies(dir, noopLog);
    assert.equal(first.findings.length, 1);
    assert.match(first.findings[0].message, /typosquatting/);
    assert.equal(await countCalls(callLogPath), 1, 'first scan must actually invoke guarddog');

    const logs = [];
    const second = await mod.checkMaliciousDependencies(dir, (m) => logs.push(m));
    assert.deepEqual(second.findings, first.findings, 'cached result must match the original scan exactly');
    assert.equal(await countCalls(callLogPath), 1, 'second scan must be a cache hit — guarddog must not run again');
    assert.ok(logs.some((l) => l.includes('cached GuardDog results')), 'cache hit should be logged, not silent');
  })();

  await fs.rm(callLogDir, { recursive: true, force: true });
});

test('checkMaliciousDependencies: cache hit reattaches the *current* project\'s relative path, not a stale one from a different project', async () => {
  const callLogDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ignite-guarddog-calllog-'));
  const callLogPath = path.join(callLogDir, 'calls.log');
  const guarddogBinary = await makeFakeGuardDogWithCallLog({
    npm: { 'left-pad@1.3.0': { issues: 1, results: { typosquatting: true } } },
  }, callLogPath);

  await withServerEnv({ GUARDDOG_ENABLED: 'true', GUARDDOG_BINARY: guarddogBinary }, async (mod) => {
    const manifestContent = JSON.stringify({ dependencies: { 'left-pad': '1.3.0' } });

    // Project A: manifest at the root.
    const dirA = await makeTempProject({ 'package.json': manifestContent });
    const resultA = await mod.checkMaliciousDependencies(dirA, noopLog);
    assert.equal(resultA.findings[0].file, 'package.json');

    // Project B: byte-identical manifest content, but nested — same cache
    // key (content hash), must still be a hit, and must report *this*
    // project's own relative path, not project A's.
    const dirB = await makeTempProject({ 'backend/package.json': manifestContent });
    const resultB = await mod.checkMaliciousDependencies(dirB, noopLog);
    assert.equal(resultB.findings[0].file, 'backend/package.json');

    assert.equal(await countCalls(callLogPath), 1, 'project B must hit the cache warmed by project A, not re-scan');
  })();

  await fs.rm(callLogDir, { recursive: true, force: true });
});

// Content-sensitive fake: picks its canned report by sniffing the *actual*
// manifest file content it was invoked against, unlike the static fixture
// makeFakeGuardDogWithCallLog uses elsewhere — needed here specifically to
// prove a real rescan (not a stale cache hit) reflects the *new* content,
// which a fake that ignores its input entirely couldn't distinguish.
async function makeContentSensitiveFakeGuardDog(callLogPath) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ignite-fake-guarddog-contentaware-'));
  const scriptPath = path.join(dir, 'guarddog');
  const script = `#!/usr/bin/env node
const fs = require('fs');
const args = process.argv.slice(2);
if (args[0] === '--version') { process.stdout.write('fake-guarddog 1.0.0\\n'); process.exit(0); }
if (args[1] === 'verify') {
  fs.appendFileSync(${JSON.stringify(callLogPath)}, '1\\n');
  const manifestContent = fs.readFileSync(args[2], 'utf8');
  const flagged = manifestContent.includes('1.3.0');
  const report = flagged
    ? { 'left-pad@1.3.0': { issues: 1, results: { typosquatting: true } } }
    : {};
  process.stdout.write(JSON.stringify(report));
  process.exit(flagged ? 1 : 0);
}
process.exit(1);
`;
  await fs.writeFile(scriptPath, script, { mode: 0o755 });
  return scriptPath;
}

test('checkMaliciousDependencies: manifest content change invalidates the cache — a real rescan happens', async () => {
  const callLogDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ignite-guarddog-calllog-'));
  const callLogPath = path.join(callLogDir, 'calls.log');
  const guarddogBinary = await makeContentSensitiveFakeGuardDog(callLogPath);

  await withServerEnv({ GUARDDOG_ENABLED: 'true', GUARDDOG_BINARY: guarddogBinary }, async (mod) => {
    const dir = await makeTempProject({ 'package.json': JSON.stringify({ dependencies: { 'left-pad': '1.3.0' } }) });
    const first = await mod.checkMaliciousDependencies(dir, noopLog);
    assert.equal(first.findings.length, 1);

    await fs.writeFile(path.join(dir, 'package.json'), JSON.stringify({ dependencies: { 'left-pad': '1.3.1' } }));
    const second = await mod.checkMaliciousDependencies(dir, noopLog);
    assert.equal(second.findings.length, 0, 'the new (clean) version must be actually rescanned, not served the old cached verdict');
    assert.equal(await countCalls(callLogPath), 2, 'changed content must trigger a real second invocation');
  })();

  await fs.rm(callLogDir, { recursive: true, force: true });
});
