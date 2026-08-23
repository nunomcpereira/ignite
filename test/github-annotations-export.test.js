'use strict';

/**
 * lib/github-annotations.js's issue-list -> GitHub workflow-command mapping,
 * and routes/github-annotations.js's GET /api/pipeline/:jobId/annotations
 * endpoint (live in-flight job, completed job read from the DB, unknown
 * job id -> 404) — mirrors test/sarif-export.test.js's structure.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const express = require('express');

const { buildGithubAnnotations } = require('../lib/github-annotations');
const { mountGithubAnnotationsRoute } = require('../routes/github-annotations');

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

test('buildGithubAnnotations: error severity maps to ::error', () => {
  const out = buildGithubAnnotations([makeIssue({ severity: 'error' })]);
  assert.match(out, /^::error /);
});

test('buildGithubAnnotations: warning severity maps to ::warning', () => {
  const out = buildGithubAnnotations([makeIssue({ severity: 'warning' })]);
  assert.match(out, /^::warning /);
});

test('buildGithubAnnotations: includes file, line, and message', () => {
  const out = buildGithubAnnotations([makeIssue()]);
  assert.match(out, /file=src\/app\.js/);
  assert.match(out, /line=12/);
  assert.match(out, /::Hardcoded AWS key detected\.$/);
});

test('buildGithubAnnotations: overridden issues are omitted', () => {
  const out = buildGithubAnnotations([makeIssue({ status: 'overridden' })]);
  assert.equal(out, '');
});

test('buildGithubAnnotations: project-wide issue with no file omits the file property', () => {
  const out = buildGithubAnnotations([makeIssue({ file: null, line: null })]);
  assert.doesNotMatch(out, /file=/);
  assert.doesNotMatch(out, /line=/);
});

test('buildGithubAnnotations: escapes newlines and commas in the message/property values', () => {
  const out = buildGithubAnnotations([makeIssue({ summary: 'line1\nline2', category: 'a,b' })]);
  assert.doesNotMatch(out, /\n/);
  assert.match(out, /%0A/);
  assert.match(out, /title=Ignite: a%2Cb/);
});

test('buildGithubAnnotations: one line per issue', () => {
  const out = buildGithubAnnotations([makeIssue({ id: 'a' }), makeIssue({ id: 'b', file: 'other.js' })]);
  assert.equal(out.split('\n').length, 2);
});

async function withAnnotationsServer(store, runningRuns, fn) {
  const app = express();
  mountGithubAnnotationsRoute(app, { store, runningRuns });
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('GET /api/pipeline/:jobId/annotations: unknown job id returns 404', async () => {
  const store = { getProjectIdByJobId: () => null };
  await withAnnotationsServer(store, new Map(), async (base) => {
    const res = await fetch(`${base}/api/pipeline/nope/annotations`);
    assert.equal(res.status, 404);
  });
});

test('GET /api/pipeline/:jobId/annotations: completed job reads issues from the store by project id', async () => {
  const store = {
    getProjectIdByJobId: (jobId) => (jobId === 'job-1' ? 42 : null),
    getProjectIssues: (projectId) => (projectId === 42 ? [makeIssue()] : []),
  };
  await withAnnotationsServer(store, new Map(), async (base) => {
    const res = await fetch(`${base}/api/pipeline/job-1/annotations`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-type'), /text\/plain/);
    const text = await res.text();
    assert.match(text, /::error /);
  });
});

test('GET /api/pipeline/:jobId/annotations: in-flight job reads from runningRuns, not the store', async () => {
  const store = { getProjectIdByJobId: () => { throw new Error('should not be called for a live job'); } };
  const runningRuns = new Map([['job-live', { allIssues: [makeIssue({ id: 'live-1', summary: 'live finding' })] }]]);
  await withAnnotationsServer(store, runningRuns, async (base) => {
    const res = await fetch(`${base}/api/pipeline/job-live/annotations`);
    assert.equal(res.status, 200);
    const text = await res.text();
    assert.match(text, /live finding/);
  });
});
