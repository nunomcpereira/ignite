'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { normalizeCoverageReport, isIstanbulReport } = require('../lib/runtime-coverage');

test('isIstanbulReport: detects Istanbul coverage-final.json shape', () => {
  assert.ok(isIstanbulReport({ '/root/a.js': { statementMap: {}, s: {} } }));
  assert.ok(!isIstanbulReport({ 'a.js': 5 }));
  assert.ok(!isIstanbulReport({}));
  assert.ok(!isIstanbulReport(null));
});

test('normalizeCoverageReport: simple map format', () => {
  const { normalized, format } = normalizeCoverageReport({ 'src/a.js': 5, 'src/b.js': 0 });
  assert.equal(format, 'simple');
  assert.deepEqual(normalized['src/a.js'], { hitCount: 5, coveredPct: 100 });
  assert.deepEqual(normalized['src/b.js'], { hitCount: 0, coveredPct: 0 });
});

test('normalizeCoverageReport: Istanbul format computes hit count and covered percentage', () => {
  const report = {
    '/project/src/a.js': {
      statementMap: { 0: {}, 1: {}, 2: {} },
      s: { 0: 3, 1: 0, 2: 2 },
    },
  };
  const { normalized, format } = normalizeCoverageReport(report, '/project');
  assert.equal(format, 'istanbul');
  const entry = normalized['src/a.js'];
  assert.equal(entry.hitCount, 5); // 3 + 0 + 2
  assert.equal(entry.coveredPct, Math.round((2 / 3) * 1000) / 10); // 2 of 3 statements covered
});

test('normalizeCoverageReport: Istanbul absolute path outside projectRoot falls back to raw key', () => {
  const report = { '/elsewhere/a.js': { s: { 0: 1 } } };
  const { normalized } = normalizeCoverageReport(report, '/project');
  assert.ok(Object.prototype.hasOwnProperty.call(normalized, '/elsewhere/a.js'));
});
