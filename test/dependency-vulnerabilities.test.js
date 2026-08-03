'use strict';

/**
 * scanDependencyVulnerabilities/classifyVulnerabilitySeverity — the MCP
 * server's check_dependency_vulnerabilities tool (and POST
 * /api/dependencies/vulnerabilities) proxy to these. Network-free: manifest
 * fixtures use unresolvable version ranges so deps.dev is never called,
 * matching test/license-scan.test.js's approach for the sibling license
 * scan.
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs/promises');

const { withServerEnv, makeTempProject } = require('./helpers');

test('classifyVulnerabilitySeverity: CVSS >= 7 is blocking, below that is advisory', async () => {
  await withServerEnv({}, async (mod) => {
    assert.equal(mod.classifyVulnerabilitySeverity(9.8), 'error');
    assert.equal(mod.classifyVulnerabilitySeverity(7.0), 'error');
    assert.equal(mod.classifyVulnerabilitySeverity(6.9), 'warning');
    assert.equal(mod.classifyVulnerabilitySeverity(0), 'warning');
    // No CVSS score at all isn't assumed harmless.
    assert.equal(mod.classifyVulnerabilitySeverity(null), 'warning');
    assert.equal(mod.classifyVulnerabilitySeverity(undefined), 'warning');
  })();
});

test('scanDependencyVulnerabilities: unresolvable version range is reported, never hits the network', async () => {
  await withServerEnv({}, async (mod) => {
    const dir = await makeTempProject({
      'package.json': JSON.stringify({
        name: 'x',
        dependencies: { 'some-lib': 'git+ssh://git@example.com/x.git' },
      }),
    });
    const manifests = await mod.scanDependencyVulnerabilities(dir);
    assert.equal(manifests.length, 1);
    assert.equal(manifests[0].file, 'package.json');
    assert.equal(manifests[0].dependencies[0].name, 'some-lib');
    assert.equal(manifests[0].dependencies[0].vulnerabilities.length, 0);
    assert.match(manifests[0].dependencies[0].note, /Could not resolve an exact version/);
    await fs.rm(dir, { recursive: true, force: true });
  })();
});

test('scanDependencyVulnerabilities: manifests with nothing to report are omitted entirely', async () => {
  // Distinct from the license scan's behavior (which reports every
  // dependency including "green" ones) — a vulnerability-free dependency
  // shouldn't show up in the response at all.
  await withServerEnv({}, async (mod) => {
    const dir = await makeTempProject({ 'README.md': 'no manifests here' });
    const manifests = await mod.scanDependencyVulnerabilities(dir);
    assert.deepEqual(manifests, []);
    await fs.rm(dir, { recursive: true, force: true });
  })();
});
