'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs/promises');

const { makeTempProject } = require('./helpers');
const { createBoundariesCheck, globToRegExp } = require('../checks/boundaries');
const { walkFiles, looksBinary, buildSnippet } = require('../lib/fs-utils');

function make(config) {
  return createBoundariesCheck({ fsUtils: { walkFiles, looksBinary, buildSnippet }, config }).checkBoundaries;
}

test('globToRegExp: ** matches any depth, * matches one segment, {a,b} alternates', () => {
  assert.ok(globToRegExp('src/features/*/**').test('src/features/auth/index.js'));
  assert.ok(globToRegExp('src/features/*/**').test('src/features/auth/nested/deep.js'));
  assert.ok(!globToRegExp('src/features/*/**').test('src/other/index.js'));
  assert.ok(globToRegExp('{src,lib}/domain/**').test('lib/domain/user.js'));
  assert.ok(!globToRegExp('{src,lib}/domain/**').test('app/domain/user.js'));
});

test('checkBoundaries: disabled returns no findings', async () => {
  const checkBoundaries = make({ enabled: false });
  const dir = await makeTempProject({ 'index.js': 'console.log(1);\n' });
  const result = await checkBoundaries(dir, null);
  assert.deepEqual(result, { findings: [], engine: 'disabled' });
  await fs.rm(dir, { recursive: true, force: true });
});

test('checkBoundaries: enabled with no zones configured skips cleanly', async () => {
  const checkBoundaries = make({ enabled: true });
  const dir = await makeTempProject({ 'index.js': 'console.log(1);\n' });
  const result = await checkBoundaries(dir, null);
  assert.equal(result.engine, 'unconfigured');
  await fs.rm(dir, { recursive: true, force: true });
});

test('checkBoundaries: bulletproof preset flags a feature importing from another feature', async () => {
  const checkBoundaries = make({ enabled: true, preset: 'bulletproof' });
  const dir = await makeTempProject({
    'src/features/auth/index.js': "const { billingHelper } = require('../billing/helper');\nbillingHelper();\n",
    'src/features/billing/helper.js': 'function billingHelper() { return 1; }\nmodule.exports = { billingHelper };\n',
    'src/shared/util.js': 'module.exports = { util: () => 1 };\n',
  });
  const { findings, engine } = await checkBoundaries(dir, null);
  assert.equal(engine, 'built-in');
  const violation = findings.find((f) => f.kind === 'boundary-violation');
  assert.ok(violation, 'feature-to-feature import should be flagged');
  assert.match(violation.message, /features.*features/);
  await fs.rm(dir, { recursive: true, force: true });
});

test('checkBoundaries: bulletproof preset allows a feature importing from shared', async () => {
  const checkBoundaries = make({ enabled: true, preset: 'bulletproof' });
  const dir = await makeTempProject({
    'src/features/auth/index.js': "const { util } = require('../../shared/util');\nutil();\n",
    'src/shared/util.js': 'module.exports = { util: () => 1 };\n',
  });
  const { findings } = await checkBoundaries(dir, null);
  assert.deepEqual(findings, []);
  await fs.rm(dir, { recursive: true, force: true });
});

test('checkBoundaries: custom zones override preset zones by name', async () => {
  const checkBoundaries = make({
    enabled: true,
    preset: 'bulletproof',
    zones: [{ name: 'features', pattern: 'src/features/*/**', allow: ['shared', 'features'] }],
  });
  const dir = await makeTempProject({
    'src/features/auth/index.js': "const { billingHelper } = require('../billing/helper');\nbillingHelper();\n",
    'src/features/billing/helper.js': 'function billingHelper() { return 1; }\nmodule.exports = { billingHelper };\n',
  });
  const { findings } = await checkBoundaries(dir, null);
  assert.deepEqual(findings, [], 'custom override permits feature-to-feature imports');
  await fs.rm(dir, { recursive: true, force: true });
});
