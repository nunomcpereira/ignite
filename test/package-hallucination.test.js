'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { withServerEnv, makeTempProject } = require('./helpers');

const noopLog = () => {};

// Fake fetch: 404s for any name in `missingNames`, 200 for everything else.
// Mirrors the real registry APIs' status-code-only contract this check
// actually reads (it never parses the response body).
function makeFakeFetch(missingNames) {
  const missing = new Set(missingNames);
  return async (url) => {
    const found = [...missing].some((name) => url.includes(encodeURIComponent(name)) || url.includes(name));
    return { status: found ? 404 : 200, ok: !found };
  };
}

test('checkPackageHallucination: enabled by default', withServerEnv({}, async (mod) => {
  const cfg = mod.loadConfig();
  assert.equal(cfg.security.packageHallucination.enabled, true);
}));

test('checkPackageHallucination: PACKAGE_HALLUCINATION_ENABLED env var is wired into CONFIG', withServerEnv(
  { PACKAGE_HALLUCINATION_ENABLED: 'false' },
  async (mod) => {
    const cfg = mod.loadConfig();
    assert.equal(cfg.security.packageHallucination.enabled, false);
  }
));

test('checkPackageHallucination: flags an npm dependency not found on the public registry', async () => {
  const { createPackageHallucinationCheck } = require('../checks/package-hallucination');
  const { walkFiles } = require('../lib/fs-utils');
  const STUDIO_MANIFESTS = [
    { file: 'package.json', ecosystem: 'npm', parse: (content) => Object.entries(JSON.parse(content).dependencies || {}).map(([name, versionRange]) => ({ name, versionRange })) },
  ];
  const { checkPackageHallucination } = createPackageHallucinationCheck({
    fsUtils: { walkFiles },
    studioManifests: STUDIO_MANIFESTS,
    config: { enabled: true, fetchImpl: makeFakeFetch(['definitely-hallucinated-pkg-xyz']) },
  });
  const dir = await makeTempProject({
    'package.json': JSON.stringify({ dependencies: { 'left-pad': '1.0.0', 'definitely-hallucinated-pkg-xyz': '1.0.0' } }),
  });
  const { findings, engine } = await checkPackageHallucination(dir, noopLog);
  assert.equal(engine, 'built-in');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].file, 'package.json');
  assert.equal(findings[0].severity, 'warning');
  assert.match(findings[0].message, /definitely-hallucinated-pkg-xyz/);
});

test('checkPackageHallucination: clean manifest — every dependency exists — no findings', async () => {
  const { createPackageHallucinationCheck } = require('../checks/package-hallucination');
  const { walkFiles } = require('../lib/fs-utils');
  const STUDIO_MANIFESTS = [
    { file: 'package.json', ecosystem: 'npm', parse: (content) => Object.entries(JSON.parse(content).dependencies || {}).map(([name, versionRange]) => ({ name, versionRange })) },
  ];
  const { checkPackageHallucination } = createPackageHallucinationCheck({
    fsUtils: { walkFiles },
    studioManifests: STUDIO_MANIFESTS,
    config: { enabled: true, fetchImpl: makeFakeFetch([]) },
  });
  const dir = await makeTempProject({ 'package.json': JSON.stringify({ dependencies: { 'left-pad': '1.0.0' } }) });
  const { findings } = await checkPackageHallucination(dir, noopLog);
  assert.deepEqual(findings, []);
});

test('checkPackageHallucination: skips git/file/workspace-protocol version specs (never a registry lookup)', async () => {
  const { createPackageHallucinationCheck } = require('../checks/package-hallucination');
  const { walkFiles } = require('../lib/fs-utils');
  const STUDIO_MANIFESTS = [
    { file: 'package.json', ecosystem: 'npm', parse: (content) => Object.entries(JSON.parse(content).dependencies || {}).map(([name, versionRange]) => ({ name, versionRange })) },
  ];
  let fetchCalls = 0;
  const fetchImpl = async () => { fetchCalls++; return { status: 200, ok: true }; };
  const { checkPackageHallucination } = createPackageHallucinationCheck({
    fsUtils: { walkFiles },
    studioManifests: STUDIO_MANIFESTS,
    config: { enabled: true, fetchImpl },
  });
  const dir = await makeTempProject({
    'package.json': JSON.stringify({
      dependencies: {
        'local-pkg': 'workspace:*',
        'git-pkg': 'git+https://github.com/example/repo.git',
        'file-pkg': 'file:../sibling',
      },
    }),
  });
  await checkPackageHallucination(dir, noopLog);
  assert.equal(fetchCalls, 0, 'non-registry version specs should never trigger a registry lookup');
});

test('checkPackageHallucination: no supported manifests in the project — no fetch calls, no findings', async () => {
  const { createPackageHallucinationCheck } = require('../checks/package-hallucination');
  const { walkFiles } = require('../lib/fs-utils');
  const STUDIO_MANIFESTS = [{ file: 'package.json', ecosystem: 'npm', parse: () => [] }];
  let fetchCalls = 0;
  const { checkPackageHallucination } = createPackageHallucinationCheck({
    fsUtils: { walkFiles },
    studioManifests: STUDIO_MANIFESTS,
    config: { enabled: true, fetchImpl: async () => { fetchCalls++; return { status: 200, ok: true }; } },
  });
  const dir = await makeTempProject({ 'README.md': '# demo\n' });
  const { findings, engine } = await checkPackageHallucination(dir, noopLog);
  assert.equal(engine, 'built-in');
  assert.deepEqual(findings, []);
  assert.equal(fetchCalls, 0);
});

test('checkPackageHallucination: disabled — no findings, engine "disabled"', async () => {
  const { createPackageHallucinationCheck } = require('../checks/package-hallucination');
  const { walkFiles } = require('../lib/fs-utils');
  const { checkPackageHallucination } = createPackageHallucinationCheck({
    fsUtils: { walkFiles },
    studioManifests: [],
    config: { enabled: false },
  });
  const dir = await makeTempProject({ 'package.json': '{}' });
  const { findings, engine } = await checkPackageHallucination(dir, noopLog);
  assert.equal(engine, 'disabled');
  assert.deepEqual(findings, []);
});

test('checkPackageHallucination: a network error for one package is inconclusive, not a finding', async () => {
  const { createPackageHallucinationCheck } = require('../checks/package-hallucination');
  const { walkFiles } = require('../lib/fs-utils');
  const STUDIO_MANIFESTS = [
    { file: 'package.json', ecosystem: 'npm', parse: (content) => Object.entries(JSON.parse(content).dependencies || {}).map(([name, versionRange]) => ({ name, versionRange })) },
  ];
  const { checkPackageHallucination } = createPackageHallucinationCheck({
    fsUtils: { walkFiles },
    studioManifests: STUDIO_MANIFESTS,
    config: { enabled: true, fetchImpl: async () => { throw new Error('network down'); } },
  });
  const dir = await makeTempProject({ 'package.json': JSON.stringify({ dependencies: { 'left-pad': '1.0.0' } }) });
  const { findings } = await checkPackageHallucination(dir, noopLog);
  assert.deepEqual(findings, []);
});
