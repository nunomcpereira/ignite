'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs/promises');
const path = require('path');

const { makeTempProject } = require('./helpers');
const { computeAutoFixPlan, applyAutoFixPlan } = require('../lib/auto-fix');

test('computeAutoFixPlan: maps dead-code finding kinds to fix actions', () => {
  const findings = [
    { kind: 'unused-file', file: 'orphan.js' },
    { kind: 'unused-dependency', file: 'package.json', message: 'Dependency "lodash" is declared...' },
    { kind: 'unused-export', file: 'lib.js', line: 3, message: 'Export "helperB" in lib.js is never imported...' },
  ];
  const { actions } = computeAutoFixPlan(findings);
  assert.equal(actions.length, 3);
  assert.equal(actions[0].type, 'delete-file');
  assert.equal(actions[1].type, 'remove-dependency');
  assert.equal(actions[1].dependency, 'lodash');
  assert.equal(actions[2].type, 'narrow-export-list-or-manual');
  assert.equal(actions[2].name, 'helperB');
});

test('applyAutoFixPlan: dryRun (default) does not touch disk', async () => {
  const dir = await makeTempProject({ 'orphan.js': 'module.exports = 1;\n' });
  const plan = computeAutoFixPlan([{ kind: 'unused-file', file: 'orphan.js' }]);
  const { dryRun, results } = await applyAutoFixPlan(plan, dir);
  assert.equal(dryRun, true);
  assert.equal(results[0].applied, false);
  assert.ok(await fs.stat(path.join(dir, 'orphan.js')).then(() => true));
  await fs.rm(dir, { recursive: true, force: true });
});

test('applyAutoFixPlan: apply deletes an unused file', async () => {
  const dir = await makeTempProject({ 'orphan.js': 'module.exports = 1;\n' });
  const plan = computeAutoFixPlan([{ kind: 'unused-file', file: 'orphan.js' }]);
  const { results } = await applyAutoFixPlan(plan, dir, { dryRun: false });
  assert.equal(results[0].applied, true);
  await assert.rejects(fs.stat(path.join(dir, 'orphan.js')));
  await fs.rm(dir, { recursive: true, force: true });
});

test('applyAutoFixPlan: apply removes an unused dependency from package.json', async () => {
  const dir = await makeTempProject({
    'package.json': JSON.stringify({ name: 'x', dependencies: { lodash: '^4.0.0', express: '^4.0.0' } }, null, 2),
  });
  const plan = computeAutoFixPlan([{ kind: 'unused-dependency', file: 'package.json', message: 'Dependency "lodash" is declared in package.json...' }]);
  const { results } = await applyAutoFixPlan(plan, dir, { dryRun: false });
  assert.equal(results[0].applied, true);
  const pkg = JSON.parse(await fs.readFile(path.join(dir, 'package.json'), 'utf8'));
  assert.equal(pkg.dependencies.lodash, undefined);
  assert.equal(pkg.dependencies.express, '^4.0.0');
  await fs.rm(dir, { recursive: true, force: true });
});

test('applyAutoFixPlan: apply narrows an export { } list, keeping the declaration', async () => {
  const dir = await makeTempProject({
    'lib.js': 'function helperA() { return 1; }\nfunction helperB() { return 2; }\nexport { helperA, helperB };\n',
  });
  const plan = computeAutoFixPlan([{ kind: 'unused-export', file: 'lib.js', line: 3, message: 'Export "helperB" in lib.js is never imported...' }]);
  const { results } = await applyAutoFixPlan(plan, dir, { dryRun: false });
  assert.equal(results[0].applied, true);
  const content = await fs.readFile(path.join(dir, 'lib.js'), 'utf8');
  assert.match(content, /export \{ helperA \}/);
  assert.match(content, /function helperB/, 'the declaration itself must survive — only the export changes');
  await fs.rm(dir, { recursive: true, force: true });
});

test('applyAutoFixPlan: unused export not in an export list is left as a manual action', async () => {
  const dir = await makeTempProject({
    'lib.js': 'export function helperA() { return 1; }\n',
  });
  const plan = computeAutoFixPlan([{ kind: 'unused-export', file: 'lib.js', line: 1, message: 'Export "helperA" in lib.js is never imported...' }]);
  const { results } = await applyAutoFixPlan(plan, dir, { dryRun: false });
  assert.equal(results[0].applied, false);
  assert.equal(results[0].manual, true);
  await fs.rm(dir, { recursive: true, force: true });
});
