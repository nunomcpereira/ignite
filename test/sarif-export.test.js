'use strict';

/**
 * lib/sarif.js's issue-list → SARIF 2.1.0 mapping, and routes/sarif.js's
 * GET /api/pipeline/:jobId/sarif endpoint (live in-flight job, completed
 * job read from the DB, and unknown job id → 404).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const express = require('express');

const { buildSarif } = require('../lib/sarif');
const { mountSarifRoute } = require('../routes/sarif');

function makeIssue(overrides = {}) {
  return {
    id: 'secret::src/app.js::12',
    phase: 4,
    category: 'secret',
    severity: 'error',
    score: 9,
    summary: 'Hardcoded AWS key detected.',
    file: 'src/app.js',
    line: 12,
    status: 'open',
    ...overrides,
  };
}

test('buildSarif: shape matches SARIF 2.1.0 top level', () => {
  const doc = buildSarif([makeIssue()]);
  assert.equal(doc.version, '2.1.0');
  assert.ok(doc.$schema.includes('sarif-schema-2.1.0'));
  assert.equal(doc.runs.length, 1);
  assert.equal(doc.runs[0].tool.driver.name, 'Ignite');
});

test('buildSarif: blocking (error) issue maps to SARIF level "error"', () => {
  const doc = buildSarif([makeIssue({ severity: 'error', status: 'open' })]);
  assert.equal(doc.runs[0].results[0].level, 'error');
});

test('buildSarif: warning issue maps to SARIF level "warning"', () => {
  const doc = buildSarif([makeIssue({ severity: 'warning', status: 'open' })]);
  assert.equal(doc.runs[0].results[0].level, 'warning');
});

test('buildSarif: overridden issue is downgraded to "note" regardless of original severity', () => {
  const doc = buildSarif([makeIssue({ severity: 'error', status: 'overridden' })]);
  assert.equal(doc.runs[0].results[0].level, 'note');
});

test('buildSarif: result carries file/line location and a stable fingerprint', () => {
  const doc = buildSarif([makeIssue()]);
  const [result] = doc.runs[0].results;
  assert.equal(result.locations[0].physicalLocation.artifactLocation.uri, 'src/app.js');
  assert.equal(result.locations[0].physicalLocation.region.startLine, 12);
  assert.equal(result.partialFingerprints.igniteIssueId, 'secret::src/app.js::12');
});

test('buildSarif: project-wide issue with no file has no locations block', () => {
  const doc = buildSarif([makeIssue({ file: null, line: null })]);
  assert.equal(doc.runs[0].results[0].locations, undefined);
});

test('buildSarif: dedups rules by category, one rule entry per distinct category', () => {
  const doc = buildSarif([
    makeIssue({ id: 'a', category: 'secret' }),
    makeIssue({ id: 'b', category: 'secret', file: 'other.js' }),
    makeIssue({ id: 'c', category: 'ai-governance' }),
  ]);
  assert.equal(doc.runs[0].tool.driver.rules.length, 2);
  assert.equal(doc.runs[0].results.length, 3);
});

test('buildSarif: crossFile CodeQL findings preserve crossFile + chain in properties', () => {
  const doc = buildSarif([makeIssue({
    category: 'codeql',
    crossFile: true,
    chain: [{ file: 'a.js', line: 1 }, { file: 'b.js', line: 9 }],
  })]);
  const props = doc.runs[0].results[0].properties;
  assert.equal(props.crossFile, true);
  assert.deepEqual(props.chain, [{ file: 'a.js', line: 1 }, { file: 'b.js', line: 9 }]);
});

async function withSarifServer(store, runningRuns, fn) {
  const app = express();
  mountSarifRoute(app, { store, runningRuns });
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('GET /api/pipeline/:jobId/sarif: unknown job id returns 404', async () => {
  const store = { getProjectIdByJobId: () => null };
  await withSarifServer(store, new Map(), async (base) => {
    const res = await fetch(`${base}/api/pipeline/nope/sarif`);
    assert.equal(res.status, 404);
  });
});

test('GET /api/pipeline/:jobId/sarif: completed job reads issues from the store by project id', async () => {
  const store = {
    getProjectIdByJobId: (jobId) => (jobId === 'job-1' ? 42 : null),
    getProjectIssues: (projectId) => (projectId === 42 ? [makeIssue()] : []),
  };
  await withSarifServer(store, new Map(), async (base) => {
    const res = await fetch(`${base}/api/pipeline/job-1/sarif`);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('content-type'), 'application/sarif+json; charset=utf-8');
    const doc = await res.json();
    assert.equal(doc.runs[0].results.length, 1);
  });
});

test('GET /api/pipeline/:jobId/sarif: in-flight job reads from runningRuns, not the store', async () => {
  const store = { getProjectIdByJobId: () => { throw new Error('should not be called for a live job'); } };
  const runningRuns = new Map([['job-live', { allIssues: [makeIssue({ id: 'live-1' })] }]]);
  await withSarifServer(store, runningRuns, async (base) => {
    const res = await fetch(`${base}/api/pipeline/job-live/sarif`);
    assert.equal(res.status, 200);
    const doc = await res.json();
    assert.equal(doc.runs[0].results[0].partialFingerprints.igniteIssueId, 'live-1');
  });
});
