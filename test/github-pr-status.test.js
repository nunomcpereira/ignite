'use strict';

/**
 * routes/github-pr-status.js's POST /api/pipeline/:jobId/github-check —
 * posts a commit status + optional PR comment summarizing an Ignite run's
 * issues, using the same live/store issue lookup as routes/sarif.js.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const express = require('express');

const { mountGithubCheckRoute } = require('../routes/github-pr-status');

const GITHUB_NAME_REGEX = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPO_NAME_REGEX = /^[A-Za-z0-9._-]{1,100}$/;

function makeIssue(overrides = {}) {
  return {
    id: 'secret::src/app.js::12',
    category: 'secret',
    severity: 'error',
    summary: 'Hardcoded AWS key detected.',
    file: 'src/app.js',
    line: 12,
    status: 'open',
    ...overrides,
  };
}

async function withServer(deps, fn) {
  const app = express();
  app.use(express.json());
  mountGithubCheckRoute(app, {
    repoNameRegex: REPO_NAME_REGEX,
    githubNameRegex: GITHUB_NAME_REGEX,
    auth: { resolveGithubToken: () => null },
    resolveServerGithubToken: () => 'server-token',
    ghApiWrite: async () => {},
    ghCommentOnPr: async () => {},
    ...deps,
  });
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('POST github-check: unknown job id returns 404', async () => {
  const store = { getProjectIdByJobId: () => null };
  await withServer({ store, runningRuns: new Map() }, async (base) => {
    const res = await fetch(`${base}/api/pipeline/nope/github-check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ owner: 'acme', repo: 'widgets', sha: '0123456' }),
    });
    assert.equal(res.status, 404);
  });
});

test('POST github-check: invalid owner/repo/sha are rejected with 400', async () => {
  const store = { getProjectIdByJobId: () => 1, getProjectIssues: () => [] };
  await withServer({ store, runningRuns: new Map() }, async (base) => {
    const bad = [
      { owner: 'bad/owner', repo: 'widgets', sha: '0123456' },
      { owner: 'acme', repo: 'bad repo', sha: '0123456' },
      { owner: 'acme', repo: 'widgets', sha: 'not-a-sha' },
      { owner: 'acme', repo: 'widgets', sha: '0123456', prNumber: -1 },
    ];
    for (const body of bad) {
      const res = await fetch(`${base}/api/pipeline/job-1/github-check`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      assert.equal(res.status, 400, JSON.stringify(body));
    }
  });
});

test('POST github-check: no GitHub token available returns 401', async () => {
  const store = { getProjectIdByJobId: () => 1, getProjectIssues: () => [] };
  await withServer({
    store, runningRuns: new Map(),
    auth: { resolveGithubToken: () => null },
    resolveServerGithubToken: () => '',
  }, async (base) => {
    const res = await fetch(`${base}/api/pipeline/job-1/github-check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ owner: 'acme', repo: 'widgets', sha: '0123456' }),
    });
    assert.equal(res.status, 401);
  });
});

test('POST github-check: blocking error issue posts a failure status, no comment without prNumber', async () => {
  const store = { getProjectIdByJobId: () => 1, getProjectIssues: () => [makeIssue()] };
  const statusCalls = [];
  const commentCalls = [];
  await withServer({
    store, runningRuns: new Map(),
    ghApiWrite: async (method, path, fields) => statusCalls.push({ method, path, fields }),
    ghCommentOnPr: async (args) => commentCalls.push(args),
  }, async (base) => {
    const res = await fetch(`${base}/api/pipeline/job-1/github-check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ owner: 'acme', repo: 'widgets', sha: '0123456' }),
    });
    assert.equal(res.status, 200);
    const json = await res.json();
    assert.equal(json.state, 'failure');
    assert.equal(json.commented, false);
    assert.equal(statusCalls.length, 1);
    assert.equal(statusCalls[0].path, 'repos/acme/widgets/statuses/0123456');
    assert.equal(statusCalls[0].fields.state, 'failure');
    assert.equal(statusCalls[0].fields.context, 'ignite/gate');
    assert.equal(commentCalls.length, 0);
  });
});

test('POST github-check: no error issues posts a success status and comments when prNumber is given', async () => {
  const store = { getProjectIdByJobId: () => 1, getProjectIssues: () => [makeIssue({ severity: 'warning' })] };
  const commentCalls = [];
  await withServer({
    store, runningRuns: new Map(),
    ghCommentOnPr: async (args) => commentCalls.push(args),
  }, async (base) => {
    const res = await fetch(`${base}/api/pipeline/job-1/github-check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ owner: 'acme', repo: 'widgets', sha: '0123456', prNumber: 7 }),
    });
    assert.equal(res.status, 200);
    const json = await res.json();
    assert.equal(json.state, 'success');
    assert.equal(json.commented, true);
    assert.equal(commentCalls.length, 1);
    assert.equal(commentCalls[0].fullName, 'acme/widgets');
    assert.equal(commentCalls[0].prNumber, 7);
    assert.match(commentCalls[0].body, /Ignite gate passed/);
  });
});

test('POST github-check: overridden/baselined issues are excluded from the blocking count', async () => {
  const store = {
    getProjectIdByJobId: () => 1,
    getProjectIssues: () => [makeIssue({ status: 'overridden' }), makeIssue({ id: 'b', status: 'baselined' })],
  };
  await withServer({ store, runningRuns: new Map() }, async (base) => {
    const res = await fetch(`${base}/api/pipeline/job-1/github-check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ owner: 'acme', repo: 'widgets', sha: '0123456' }),
    });
    const json = await res.json();
    assert.equal(json.state, 'success');
  });
});

test('POST github-check: reads issues from runningRuns for an in-flight job', async () => {
  const store = { getProjectIdByJobId: () => { throw new Error('should not be called for a live job'); } };
  const runningRuns = new Map([['job-live', { allIssues: [makeIssue()] }]]);
  await withServer({ store, runningRuns }, async (base) => {
    const res = await fetch(`${base}/api/pipeline/job-live/github-check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ owner: 'acme', repo: 'widgets', sha: '0123456' }),
    });
    assert.equal(res.status, 200);
    const json = await res.json();
    assert.equal(json.state, 'failure');
  });
});

test('POST github-check: a GitHub API failure is reported as 502', async () => {
  const store = { getProjectIdByJobId: () => 1, getProjectIssues: () => [] };
  await withServer({
    store, runningRuns: new Map(),
    ghApiWrite: async () => { throw new Error('boom'); },
  }, async (base) => {
    const res = await fetch(`${base}/api/pipeline/job-1/github-check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ owner: 'acme', repo: 'widgets', sha: '0123456' }),
    });
    assert.equal(res.status, 502);
  });
});
