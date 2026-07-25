'use strict';

/**
 * Proves the ORT and licensee integrations work — using fake `ort`/`licensee`
 * CLIs on PATH (makeFakeLicenseTools), so the real integration code
 * (runTool → execFile → PATH resolution, output parsing, tier
 * classification, soft-skip fallback) is exercised without either tool
 * installed. Network-free: manifest fixtures use unresolvable version
 * ranges so the deps.dev fallback never issues a fetch.
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs/promises');

const { withServerEnv, makeTempProject, makeFakeLicenseTools } = require('./helpers');

async function withPath(binDir, fn) {
  const prevPath = process.env.PATH;
  process.env.PATH = `${binDir}:${prevPath}`;
  try {
    return await fn();
  } finally {
    process.env.PATH = prevPath;
  }
}

test('runOrtAnalyze: parses a fake ORT analyzer result into classified manifests', async () => {
  const binDir = await makeFakeLicenseTools({
    ortPackages: [
      { package: { id: 'NPM::ag-grid-enterprise:31.3.2', declared_licenses: ['Commercial'] } },
      { package: { id: 'Maven:com.aspose:aspose-cells:25.3', declared_licenses: ['LicenseRef-Proprietary'] } },
      { package: { id: 'NPM::express:4.21.2', declared_licenses: ['MIT'] } },
      { package: { id: 'NPM::left-pad:1.3.0', declared_licenses: ['AGPL-3.0-only'] } },
    ],
  });
  try {
    await withPath(binDir, () => withServerEnv({}, async (mod) => {
      const dir = await makeTempProject({ 'README.md': 'fixture' });
      const manifests = await mod.runOrtAnalyze(dir, () => {});
      assert.ok(Array.isArray(manifests), 'ORT run should produce manifests, not null');

      const all = manifests.flatMap((m) => m.dependencies);
      const byName = Object.fromEntries(all.map((d) => [d.name, d]));

      assert.equal(byName['ag-grid-enterprise'].tier, 'red');
      assert.match(byName['ag-grid-enterprise'].reason, /Commercial/);
      assert.equal(byName['aspose-cells'].tier, 'red');
      assert.equal(byName['express'].tier, 'green');
      assert.equal(byName['left-pad'].tier, 'warning');
      assert.match(byName['left-pad'].reason, /Copyleft/);

      const ecosystems = manifests.map((m) => m.ecosystem).sort();
      assert.deepEqual(ecosystems, ['maven', 'npm']);
      await fs.rm(dir, { recursive: true, force: true });
    })());
  } finally {
    await fs.rm(binDir, { recursive: true, force: true });
  }
});

test('runLicenseeDetect: parses fake licensee output and classifies the project license', async () => {
  const binDir = await makeFakeLicenseTools({
    licenseeJson: {
      licenses: [{ spdx_id: 'MIT', similarity: 99 }],
      matched_files: [{ attribution: 'Copyright (c) Fixture' }],
    },
  });
  try {
    await withPath(binDir, () => withServerEnv({}, async (mod) => {
      const dir = await makeTempProject({ LICENSE: 'MIT License…' });
      const detected = await mod.runLicenseeDetect(dir, () => {});
      assert.equal(detected.spdxId, 'MIT');
      assert.equal(detected.tier, 'green');
      await fs.rm(dir, { recursive: true, force: true });
    })());
  } finally {
    await fs.rm(binDir, { recursive: true, force: true });
  }
});

test('scanDependencyLicenses: engine is "ort" and projectLicense is set when both tools work', async () => {
  const binDir = await makeFakeLicenseTools({
    ortPackages: [{ package: { id: 'NPM::highcharts:11.4.8', declared_licenses: ['Commercial'] } }],
    licenseeJson: { licenses: [{ spdx_id: 'Apache-2.0', similarity: 98 }] },
  });
  try {
    await withPath(binDir, () => withServerEnv({}, async (mod) => {
      const dir = await makeTempProject({ 'README.md': 'fixture' });
      const result = await mod.scanDependencyLicenses(dir, () => {});
      assert.equal(result.engine, 'ort');
      assert.equal(result.projectLicense.spdxId, 'Apache-2.0');
      assert.equal(result.projectLicense.tier, 'green');
      assert.equal(result.manifests[0].dependencies[0].name, 'highcharts');
      assert.equal(result.manifests[0].dependencies[0].tier, 'red');
      await fs.rm(dir, { recursive: true, force: true });
    })());
  } finally {
    await fs.rm(binDir, { recursive: true, force: true });
  }
});

test('scanDependencyLicenses: soft-skips to the built-in fallback when both tools fail', async () => {
  // Fakes that exist on PATH but exit non-zero — deterministic "not
  // installed/broken" regardless of what the host machine has.
  const binDir = await makeFakeLicenseTools({});
  try {
    await withPath(binDir, () => withServerEnv({}, async (mod) => {
      const dir = await makeTempProject({
        // git ref version range → bestEffortVersion() → null → flagged red
        // without ever calling deps.dev (keeps the test offline).
        'package.json': JSON.stringify({ name: 'x', dependencies: { 'some-lib': 'git+ssh://git@example.com/x.git' } }),
      });
      const result = await mod.scanDependencyLicenses(dir, () => {});
      assert.equal(result.engine, 'fallback');
      assert.equal(result.projectLicense, null);
      assert.equal(result.manifests.length, 1);
      assert.equal(result.manifests[0].file, 'package.json');
      assert.equal(result.manifests[0].dependencies[0].tier, 'red');
      assert.match(result.manifests[0].dependencies[0].reason, /Could not resolve an exact version/);
      await fs.rm(dir, { recursive: true, force: true });
    })());
  } finally {
    await fs.rm(binDir, { recursive: true, force: true });
  }
});

test('runOrtAnalyze: returns null (fallback) when ort emits unparseable output', async () => {
  const binDir = await makeFakeLicenseTools({ ortPackages: [] });
  // Overwrite the result with garbage — analyzer-result.json exists but has
  // no usable package list, which must soft-fail to null, never throw.
  await fs.writeFile(`${binDir}/ort-result.json`, '{"not":"an analyzer result"}');
  try {
    await withPath(binDir, () => withServerEnv({}, async (mod) => {
      const dir = await makeTempProject({ 'README.md': 'fixture' });
      assert.equal(await mod.runOrtAnalyze(dir, () => {}), null);
      await fs.rm(dir, { recursive: true, force: true });
    })());
  } finally {
    await fs.rm(binDir, { recursive: true, force: true });
  }
});
