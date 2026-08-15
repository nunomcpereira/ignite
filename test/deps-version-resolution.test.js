'use strict';

/**
 * Regression test for a real false-positive: a manifest range like
 * "^5.6.0" gets its literal floor version looked up on deps.dev
 * (bestEffortVersion strips the "^"), but that exact patch was never
 * published for plenty of real packages (typescript's actual npm history
 * has 5.6.0-beta/5.6.0-dev.* then jumps straight to 5.6.1-rc/5.6.2 — no
 * plain "5.6.0"). A 404 there used to be reported as a blocking
 * "License lookup failed" / COMMERCIAL-RISK finding even though the range
 * resolves to a real, real-licensed version. Hits the real deps.dev API —
 * self-skips if it's unreachable, same convention as the other real-tool
 * end-to-end tests in this suite.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { withServerEnv, makeTempProject } = require('./helpers');

async function hasNetwork() {
  try {
    const res = await fetch('https://api.deps.dev/v3/systems/npm/packages/react', { signal: AbortSignal.timeout(5000) });
    return res.ok;
  } catch {
    return false;
  }
}

test('scanDependencyLicenses: a range floor that was never published (e.g. "^5.6.0") resolves to a real published version instead of being flagged red', async (t) => {
  if (!(await hasNetwork())) {
    t.skip('no network access to api.deps.dev — skipping live resolution test');
    return;
  }
  await withServerEnv({}, async (mod) => {
    // typescript never published a plain 5.6.0 (only 5.6.0-beta/-dev.* then
    // 5.6.1-rc/5.6.2) and @tanstack/react-table never published 8.20.0
    // (only 8.20.1/8.20.5/8.20.6) — both real, current examples of the bug.
    const dir = await makeTempProject({
      'package.json': JSON.stringify({
        dependencies: {
          'typescript': '^5.6.0',
          '@tanstack/react-table': '^8.20.0',
        },
      }),
    });
    const { manifests } = await mod.scanDependencyLicenses(dir, () => {});
    const deps = manifests[0].dependencies;
    const ts = deps.find((d) => d.name === 'typescript');
    const table = deps.find((d) => d.name === '@tanstack/react-table');

    assert.notEqual(ts.tier, 'red', 'typescript should not be flagged red just because 5.6.0 exactly was never published');
    assert.ok(ts.licenses.length > 0, 'should have resolved a real license');
    assert.notEqual(ts.version, '5.6.0', 'resolved version should be a real published release, not the unpublished floor');
    // ^5.6.0 must resolve within major version 5
    assert.match(ts.version, /^5\./);

    assert.notEqual(table.tier, 'red', '@tanstack/react-table should not be flagged red just because 8.20.0 exactly was never published');
    assert.ok(table.licenses.length > 0, 'should have resolved a real license');
    assert.notEqual(table.version, '8.20.0');
    assert.match(table.version, /^8\.2/); // ^8.20.0 must resolve within major.minor 8.20+ (8.2x)
  })();
});

test('scanDependencyLicenses: a genuinely nonexistent package is still flagged red (no false negative introduced)', async (t) => {
  if (!(await hasNetwork())) {
    t.skip('no network access to api.deps.dev — skipping live resolution test');
    return;
  }
  await withServerEnv({}, async (mod) => {
    const dir = await makeTempProject({
      'package.json': JSON.stringify({
        dependencies: { 'this-package-definitely-does-not-exist-ignite-test-xyz123': '^1.0.0' },
      }),
    });
    const { manifests } = await mod.scanDependencyLicenses(dir, () => {});
    const dep = manifests[0].dependencies[0];
    assert.equal(dep.tier, 'red');
    assert.match(dep.reason, /License lookup failed/);
  })();
});

test('scanDependencyLicenses: OFL-1.1 (SIL Open Font License, e.g. @fontsource/*) is classified green, not an unrecognized-license false positive', async (t) => {
  if (!(await hasNetwork())) {
    t.skip('no network access to api.deps.dev — skipping live resolution test');
    return;
  }
  await withServerEnv({}, async (mod) => {
    const dir = await makeTempProject({
      'package.json': JSON.stringify({ dependencies: { '@fontsource/inter': '^5.2.8' } }),
    });
    const { manifests } = await mod.scanDependencyLicenses(dir, () => {});
    const dep = manifests[0].dependencies[0];
    assert.equal(dep.tier, 'green');
    assert.deepEqual(dep.licenses, ['OFL-1.1']);
  })();
});

test('scanDependencyLicenses: deps.dev "non-standard" placeholder falls back to the npm registry\'s declared license instead of red-flagging', async (t) => {
  // Regression for a real false positive: deps.dev reports
  // @typescript-eslint/parser@8.18.0 as licenses: ["non-standard"] even
  // though its package.json/LICENSE both say plain MIT (confirmed via
  // `npm view @typescript-eslint/parser@8.18.0 license`).
  if (!(await hasNetwork())) {
    t.skip('no network access to api.deps.dev — skipping live resolution test');
    return;
  }
  await withServerEnv({}, async (mod) => {
    const dir = await makeTempProject({
      'package.json': JSON.stringify({ devDependencies: { '@typescript-eslint/parser': '^8.18.0' } }),
    });
    const { manifests } = await mod.scanDependencyLicenses(dir, () => {});
    const dep = manifests[0].dependencies[0];
    assert.equal(dep.tier, 'green', `expected MIT (via npm registry fallback) to classify green, got: ${JSON.stringify(dep)}`);
    assert.deepEqual(dep.licenses, ['MITClause']); // raw npm registry value; classifyLicenseTier normalizes it to MIT internally
    assert.match(dep.reason, /^MIT$/);
  })();
});
