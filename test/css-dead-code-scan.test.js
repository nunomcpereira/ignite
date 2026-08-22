'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs/promises');

const { makeTempProject } = require('./helpers');
const { createCssDeadCodeCheck } = require('../checks/css-dead-code');
const { walkFiles, looksBinary, buildSnippet } = require('../lib/fs-utils');

function make(config = { enabled: true }) {
  return createCssDeadCodeCheck({ fsUtils: { walkFiles, looksBinary, buildSnippet }, config }).checkCssDeadCode;
}

test('checkCssDeadCode: disabled returns no findings', async () => {
  const checkCssDeadCode = make({ enabled: false });
  const dir = await makeTempProject({ 'a.css': '.foo {}' });
  const result = await checkCssDeadCode(dir, null);
  assert.deepEqual(result, { findings: [], engine: 'disabled' });
  await fs.rm(dir, { recursive: true, force: true });
});

test('checkCssDeadCode: no CSS files present — no findings', async () => {
  const checkCssDeadCode = make();
  const dir = await makeTempProject({ 'index.js': 'console.log(1);\n' });
  const { findings, scanned } = await checkCssDeadCode(dir, null);
  assert.deepEqual(findings, []);
  assert.equal(scanned.cssFiles, 0);
  await fs.rm(dir, { recursive: true, force: true });
});

test('checkCssDeadCode: flags a declared class never referenced in markup', async () => {
  const checkCssDeadCode = make();
  const dir = await makeTempProject({
    'styles.css': '.button {\n  color: red;\n}\n.orphan-class {\n  color: blue;\n}\n',
    'App.jsx': 'export default function App() {\n  return <div className="button">Hi</div>;\n}\n',
  });
  const { findings } = await checkCssDeadCode(dir, null);
  const orphan = findings.find((f) => f.message.includes('orphan-class'));
  assert.ok(orphan, 'orphan-class should be flagged');
  const button = findings.find((f) => f.message.includes('".button"'));
  assert.equal(button, undefined, 'button is referenced and must not be flagged');
  await fs.rm(dir, { recursive: true, force: true });
});

test('checkCssDeadCode: is-/has-/js- prefixed classes are not flagged', async () => {
  const checkCssDeadCode = make();
  const dir = await makeTempProject({
    'styles.css': '.is-active {\n  color: red;\n}\n',
    'App.jsx': 'export default function App() { return <div />; }\n',
  });
  const { findings } = await checkCssDeadCode(dir, null);
  assert.deepEqual(findings, []);
  await fs.rm(dir, { recursive: true, force: true });
});
