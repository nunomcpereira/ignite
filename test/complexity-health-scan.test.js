'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs/promises');

const { makeTempProject } = require('./helpers');
const { createComplexityHealthCheck, cyclomaticAndCognitive, maintainabilityIndex, crapScore } = require('../checks/complexity-health');
const { walkFiles, looksBinary, buildSnippet } = require('../lib/fs-utils');

function make(config = { enabled: true }) {
  return createComplexityHealthCheck({ runTool: null, fsUtils: { walkFiles, looksBinary, buildSnippet }, config }).checkComplexityHealth;
}

test('cyclomaticAndCognitive: counts decision points, cognitive weights nesting', () => {
  const flat = 'if (a) { x(); }\nif (b) { y(); }\n';
  const nested = 'if (a) {\n  if (b) {\n    if (c) { x(); }\n  }\n}\n';
  const flatResult = cyclomaticAndCognitive(flat);
  const nestedResult = cyclomaticAndCognitive(nested);
  assert.equal(flatResult.cyclomatic, 3); // base 1 + 2 ifs
  assert.equal(nestedResult.cyclomatic, 4); // base 1 + 3 ifs
  assert.ok(nestedResult.cognitive > flatResult.cognitive, 'deeper nesting must cost more cognitively for the same decision count');
});

test('maintainabilityIndex: small low-branching file scores high, large complex file scores low', () => {
  const small = maintainabilityIndex(2, 20);
  const large = maintainabilityIndex(80, 900);
  assert.ok(small > 70, `expected small file MI > 70, got ${small}`);
  assert.ok(large < 25, `expected large complex file MI < 25, got ${large}`);
  assert.ok(small >= 0 && small <= 100);
  assert.ok(large >= 0 && large <= 100);
});

test('crapScore: full coverage minimizes the penalty term, zero coverage maximizes it', () => {
  const covered = crapScore(10, 100);
  const uncovered = crapScore(10, 0);
  assert.equal(covered, 10); // CC + CC^2*(1-1)^3 == CC
  assert.equal(uncovered, 110); // CC^2 + CC == 100 + 10
});

test('checkComplexityHealth: disabled returns no findings', async () => {
  const checkComplexityHealth = make({ enabled: false });
  const dir = await makeTempProject({ 'index.js': 'console.log(1);\n' });
  const result = await checkComplexityHealth(dir, null);
  assert.deepEqual(result.findings, []);
  assert.equal(result.engine, 'disabled');
  await fs.rm(dir, { recursive: true, force: true });
});

test('checkComplexityHealth: flags a dense, branch-heavy file and ranks it as a hotspot', async () => {
  const checkComplexityHealth = make();
  const denseLines = [];
  for (let i = 0; i < 30; i++) denseLines.push(`if (x${i} && y${i}) { doSomething${i}(); } else if (z${i}) { doOther${i}(); }`);
  const dir = await makeTempProject({
    'dense.js': denseLines.join('\n') + '\n',
    'plain.js': 'function add(a, b) {\n  return a + b;\n}\nmodule.exports = { add };\n',
  });
  const { findings, engine, metrics } = await checkComplexityHealth(dir, null);
  assert.equal(engine, 'built-in');
  const denseFinding = findings.find((f) => f.file === 'dense.js');
  assert.ok(denseFinding, 'dense.js should be flagged');
  const plainFinding = findings.find((f) => f.file === 'plain.js');
  assert.equal(plainFinding, undefined, 'plain.js should not be flagged');
  assert.ok(metrics.hotspots.length > 0);
  assert.equal(metrics.hotspots[0].file, 'dense.js');
  await fs.rm(dir, { recursive: true, force: true });
});

test('checkComplexityHealth: uses ingested runtime coverage in the CRAP score', async () => {
  const checkComplexityHealth = make();
  const denseLines = [];
  for (let i = 0; i < 30; i++) denseLines.push(`if (x${i} && y${i}) { doSomething${i}(); } else if (z${i}) { doOther${i}(); }`);
  const dir = await makeTempProject({ 'dense.js': denseLines.join('\n') + '\n' });
  const withoutCoverage = await checkComplexityHealth(dir, null, {});
  const withCoverage = await checkComplexityHealth(dir, null, { getCoverageForFile: async () => 100 });
  const findingWithout = withoutCoverage.findings.find((f) => f.file === 'dense.js');
  const findingWith = withCoverage.findings.find((f) => f.file === 'dense.js');
  const crapWithout = Number(findingWithout.message.match(/CRAP score (\d+)/)[1]);
  const crapWith = Number(findingWith.message.match(/CRAP score (\d+)/)[1]);
  assert.ok(crapWith < crapWithout, `100% coverage should lower CRAP (${crapWith} vs ${crapWithout})`);
  await fs.rm(dir, { recursive: true, force: true });
});
