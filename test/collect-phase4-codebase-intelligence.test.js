'use strict';

/**
 * override-engine.js's collectPhase4Issues handling of the four new
 * codebase-intelligence check groups (dead-code, health, cssDeadCode,
 * boundaries) — verifies they're tagged into the right issue category and
 * always advisory (severity 'warning'), matching every other heuristic
 * built-in check's precedent.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { collectPhase4Issues } = require('../override-engine');

const empty = { findings: [] };

test('collectPhase4Issues: dead-code findings become category "dead-code", severity "warning"', () => {
  const issues = collectPhase4Issues({
    secrets: empty, governance: empty,
    deadCode: { findings: [{ file: 'orphan.js', line: 1, kind: 'unused-file', message: 'orphan.js is unused', code: null }] },
  });
  assert.equal(issues.length, 1);
  assert.equal(issues[0].category, 'dead-code');
  assert.equal(issues[0].severity, 'warning');
  assert.equal(issues[0].summary, 'orphan.js is unused');
});

test('collectPhase4Issues: health/cssDeadCode/boundaries findings map to distinct categories', () => {
  const issues = collectPhase4Issues({
    secrets: empty, governance: empty,
    health: { findings: [{ file: 'big.js', line: 1, kind: 'high-complexity', message: 'too complex', code: null }] },
    cssDeadCode: { findings: [{ file: 'a.css', line: 2, kind: 'unused-css-class', message: 'unused class', code: null }] },
    boundaries: { findings: [{ file: 'a.js', line: 3, kind: 'boundary-violation', message: 'crosses zone', code: null }] },
  });
  const byCategory = Object.fromEntries(issues.map((i) => [i.category, i]));
  assert.equal(byCategory['complexity-health'].summary, 'too complex');
  assert.equal(byCategory['css-dead-code'].summary, 'unused class');
  assert.equal(byCategory['architecture-boundary'].summary, 'crosses zone');
  for (const issue of issues) assert.equal(issue.severity, 'warning');
});

test('collectPhase4Issues: missing groups (undefined) are tolerated, no crash', () => {
  const issues = collectPhase4Issues({ secrets: empty, governance: empty });
  assert.deepEqual(issues, []);
});
