'use strict';

/**
 * db-store.js's issue_baselines and runtime_coverage tables + accessor
 * methods — the persistence side of the baseline/diff adoption mode and
 * runtime-coverage ingestion gaps (see routes/baseline.js,
 * routes/runtime-coverage.js, and project memory).
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');

const { createDbStore } = require('../db-store');

async function withTempDb(fn) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ignite-test-db-'));
  const store = createDbStore(path.join(dir, 'test.db'));
  try {
    await fn(store);
  } finally {
    await fs.rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

test('saveBaseline + getBaselineIssueIds round-trips per org/repo', () => withTempDb((store) => {
  store.saveBaseline('acme', 'widgets', ['a', 'b', 'c']);
  assert.deepEqual(store.getBaselineIssueIds('acme', 'widgets'), new Set(['a', 'b', 'c']));
  assert.deepEqual(store.getBaselineIssueIds('acme', 'other-repo'), new Set());
}));

test('saveBaseline replaces the previous baseline rather than accumulating', () => withTempDb((store) => {
  store.saveBaseline('acme', 'widgets', ['a', 'b']);
  store.saveBaseline('acme', 'widgets', ['c']);
  assert.deepEqual(store.getBaselineIssueIds('acme', 'widgets'), new Set(['c']));
}));

test('clearBaseline removes all rows for that org/repo', () => withTempDb((store) => {
  store.saveBaseline('acme', 'widgets', ['a', 'b']);
  const removed = store.clearBaseline('acme', 'widgets');
  assert.equal(removed, 2);
  assert.deepEqual(store.getBaselineIssueIds('acme', 'widgets'), new Set());
}));

test('ingestRuntimeCoverage + getRuntimeCoverageForFile round-trips', () => withTempDb((store) => {
  store.ingestRuntimeCoverage('acme', 'widgets', { 'src/a.js': { hitCount: 5, coveredPct: 80 } });
  const row = store.getRuntimeCoverageForFile('acme', 'widgets', 'src/a.js');
  assert.equal(row.hit_count, 5);
  assert.equal(row.covered_pct, 80);
  assert.equal(store.getRuntimeCoverageForFile('acme', 'widgets', 'src/missing.js'), null);
}));

test('ingestRuntimeCoverage upserts on repeat ingestion of the same file', () => withTempDb((store) => {
  store.ingestRuntimeCoverage('acme', 'widgets', { 'src/a.js': { hitCount: 1, coveredPct: 10 } });
  store.ingestRuntimeCoverage('acme', 'widgets', { 'src/a.js': { hitCount: 9, coveredPct: 90 } });
  const row = store.getRuntimeCoverageForFile('acme', 'widgets', 'src/a.js');
  assert.equal(row.hit_count, 9);
  assert.equal(row.covered_pct, 90);
}));

test('getRuntimeCoverageMap + clearRuntimeCoverage', () => withTempDb((store) => {
  store.ingestRuntimeCoverage('acme', 'widgets', { 'a.js': { hitCount: 1, coveredPct: 50 }, 'b.js': { hitCount: 2, coveredPct: 60 } });
  const map = store.getRuntimeCoverageMap('acme', 'widgets');
  assert.equal(map.size, 2);
  const removed = store.clearRuntimeCoverage('acme', 'widgets');
  assert.equal(removed, 2);
  assert.equal(store.getRuntimeCoverageMap('acme', 'widgets').size, 0);
}));
