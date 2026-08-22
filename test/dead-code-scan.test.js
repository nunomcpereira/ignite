'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs/promises');

const { makeTempProject } = require('./helpers');
const { createDeadCodeCheck } = require('../checks/dead-code');
const { walkFiles, looksBinary, buildSnippet } = require('../lib/fs-utils');

function make(config = { enabled: true }) {
  return createDeadCodeCheck({ fsUtils: { walkFiles, looksBinary, buildSnippet }, config }).checkDeadCode;
}

test('checkDeadCode: disabled returns no findings', async () => {
  const checkDeadCode = make({ enabled: false });
  const dir = await makeTempProject({ 'index.js': 'console.log(1);' });
  const result = await checkDeadCode(dir, null);
  assert.deepEqual(result, { findings: [], engine: 'disabled' });
  await fs.rm(dir, { recursive: true, force: true });
});

test('checkDeadCode: flags a file never imported from any entry point', async () => {
  const checkDeadCode = make();
  const dir = await makeTempProject({
    'package.json': JSON.stringify({ name: 'x', main: 'index.js' }),
    'index.js': "const used = require('./used');\nconsole.log(used);\n",
    'used.js': 'module.exports = 42;\n',
    'orphan.js': 'module.exports = 1;\n',
  });
  const { findings, engine } = await checkDeadCode(dir, null);
  assert.equal(engine, 'built-in');
  const orphan = findings.find((f) => f.file === 'orphan.js' && f.kind === 'unused-file');
  assert.ok(orphan, 'orphan.js should be flagged as unused-file');
  const used = findings.find((f) => f.file === 'used.js' && f.kind === 'unused-file');
  assert.equal(used, undefined, 'used.js is reachable and must not be flagged');
  await fs.rm(dir, { recursive: true, force: true });
});

test('checkDeadCode: flags an unused named export in a reachable file', async () => {
  const checkDeadCode = make();
  const dir = await makeTempProject({
    'package.json': JSON.stringify({ name: 'x', main: 'index.js' }),
    'index.js': "const { helperA } = require('./lib');\nconsole.log(helperA());\n",
    'lib.js': 'function helperA() { return 1; }\nfunction helperB() { return 2; }\nmodule.exports = { helperA, helperB };\n',
  });
  const { findings } = await checkDeadCode(dir, null);
  const unused = findings.find((f) => f.kind === 'unused-export' && f.file === 'lib.js');
  assert.ok(unused, 'helperB should be flagged as an unused export');
  assert.match(unused.message, /helperB/);
  await fs.rm(dir, { recursive: true, force: true });
});

test('checkDeadCode: flags an unused package.json dependency', async () => {
  const checkDeadCode = make();
  const dir = await makeTempProject({
    'package.json': JSON.stringify({ name: 'x', main: 'index.js', dependencies: { lodash: '^4.0.0', express: '^4.0.0' } }),
    'index.js': "const express = require('express');\nexpress();\n",
  });
  const { findings } = await checkDeadCode(dir, null);
  const dep = findings.find((f) => f.kind === 'unused-dependency');
  assert.ok(dep, 'lodash should be flagged as unused');
  assert.match(dep.message, /lodash/);
  const expressFinding = findings.find((f) => f.kind === 'unused-dependency' && /express/.test(f.message));
  assert.equal(expressFinding, undefined, 'express is required and must not be flagged');
  await fs.rm(dir, { recursive: true, force: true });
});

test('checkDeadCode: test files count as entry points', async () => {
  const checkDeadCode = make();
  const dir = await makeTempProject({
    'package.json': JSON.stringify({ name: 'x', main: 'index.js' }),
    'index.js': 'console.log(1);\n',
    'foo.test.js': "const { helper } = require('./foo');\nhelper();\n",
    'foo.js': 'function helper() { return 1; }\nmodule.exports = { helper };\n',
  });
  const { findings } = await checkDeadCode(dir, null);
  const fooUnused = findings.find((f) => f.file === 'foo.js' && f.kind === 'unused-file');
  assert.equal(fooUnused, undefined, 'foo.js is reachable via its test file and must not be flagged');
  await fs.rm(dir, { recursive: true, force: true });
});
