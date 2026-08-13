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
const { collectDependencyVulnerabilityIssues } = require('../override-engine');

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

test('collectDependencyVulnerabilityIssues: turns manifest findings into addressable issues with the right severity', () => {
  const manifests = [
    {
      file: 'package.json',
      dependencies: [
        {
          name: 'lodash', version: '4.17.15', versionRange: '^4.17.15', line: 12,
          vulnerabilities: [
            { id: 'GHSA-critical', title: 'Prototype Pollution', cvss3Score: 9.1, severity: 'error', url: 'https://x' },
            { id: 'GHSA-low', title: 'Minor info leak', cvss3Score: 3.1, severity: 'warning', url: 'https://y' },
          ],
        },
      ],
    },
  ];
  const issues = collectDependencyVulnerabilityIssues({ manifests });
  assert.equal(issues.length, 2);
  assert.ok(issues.every((i) => i.category === 'dependency-vulnerability'));
  assert.ok(issues.every((i) => i.file === 'package.json' && i.line === 12));
  // Distinct advisories on the same dependency/line must not collapse into
  // the same id — each carries its own override decision.
  assert.notEqual(issues[0].id, issues[1].id);
  const bySeverity = Object.fromEntries(issues.map((i) => [i.severity, i]));
  assert.ok(bySeverity.error);
  assert.ok(bySeverity.warning);
  assert.match(bySeverity.error.summary, /lodash@4\.17\.15 — GHSA-critical: Prototype Pollution \(CVSS 9\.1\)/);
});

test('collectDependencyVulnerabilityIssues: no manifests/dependencies/vulnerabilities produces no issues', () => {
  assert.deepEqual(collectDependencyVulnerabilityIssues({ manifests: [] }), []);
  assert.deepEqual(collectDependencyVulnerabilityIssues({ manifests: [{ file: 'a', dependencies: [] }] }), []);
  assert.deepEqual(
    collectDependencyVulnerabilityIssues({ manifests: [{ file: 'a', dependencies: [{ name: 'x', vulnerabilities: [] }] }] }),
    []
  );
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
