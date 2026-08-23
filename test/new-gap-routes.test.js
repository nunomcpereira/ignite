'use strict';

/**
 * Covers the three new gap-closing route modules (routes/baseline.js,
 * routes/runtime-coverage.js, routes/auto-fix.js) against real express
 * apps + an in-memory fake db-store — same lightweight pattern
 * test/api-key-auth.test.js uses, rather than booting the whole server.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const express = require('express');
const fs = require('fs/promises');
const path = require('path');

const { makeTempProject } = require('./helpers');
const { mountBaselineRoutes } = require('../routes/baseline');
const { mountRuntimeCoverageRoutes } = require('../routes/runtime-coverage');
const { mountAutoFixRoute } = require('../routes/auto-fix');

function makeFakeStore() {
  const baselines = new Map(); // "org/repo" -> Set<issueId>
  const coverage = new Map(); // "org/repo" -> Map<relPath, row>
  const key = (org, repo) => `${org}/${repo}`;
  return {
    saveBaseline(org, repo, issueIds) {
      baselines.set(key(org, repo), new Set(issueIds));
      return issueIds.length;
    },
    getBaselineIssueIds(org, repo) {
      return baselines.get(key(org, repo)) || new Set();
    },
    clearBaseline(org, repo) {
      const had = baselines.has(key(org, repo));
      baselines.delete(key(org, repo));
      return had ? 1 : 0;
    },
    ingestRuntimeCoverage(org, repo, fileStats) {
      const k = key(org, repo);
      if (!coverage.has(k)) coverage.set(k, new Map());
      const map = coverage.get(k);
      for (const [relPath, row] of Object.entries(fileStats)) map.set(relPath, row);
      return Object.keys(fileStats).length;
    },
    getRuntimeCoverageMap(org, repo) {
      return coverage.get(key(org, repo)) || new Map();
    },
    clearRuntimeCoverage(org, repo) {
      const had = coverage.has(key(org, repo));
      coverage.delete(key(org, repo));
      return had ? 1 : 0;
    },
  };
}

async function startApp(mount) {
  const app = express();
  app.use(express.json());
  mount(app);
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  return { server, baseUrl: `http://127.0.0.1:${port}` };
}

test('baseline routes: save, get, clear round-trip', async () => {
  const store = makeFakeStore();
  const { server, baseUrl } = await startApp((app) => mountBaselineRoutes(app, { store }));
  try {
    const saveRes = await fetch(`${baseUrl}/api/baseline/acme/widgets`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ issueIds: ['a', 'b', 'c'] }),
    });
    assert.equal(saveRes.status, 200);
    assert.deepEqual(await saveRes.json(), { ok: true, org: 'acme', repo: 'widgets', savedCount: 3 });

    const getRes = await fetch(`${baseUrl}/api/baseline/acme/widgets`);
    const body = await getRes.json();
    assert.equal(body.count, 3);
    assert.deepEqual(new Set(body.issueIds), new Set(['a', 'b', 'c']));

    const clearRes = await fetch(`${baseUrl}/api/baseline/acme/widgets`, { method: 'DELETE' });
    assert.deepEqual(await clearRes.json(), { ok: true, org: 'acme', repo: 'widgets', removed: 1 });
  } finally {
    server.close();
  }
});

test('baseline routes: missing issueIds is a 400', async () => {
  const store = makeFakeStore();
  const { server, baseUrl } = await startApp((app) => mountBaselineRoutes(app, { store }));
  try {
    const res = await fetch(`${baseUrl}/api/baseline/acme/widgets`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({}),
    });
    assert.equal(res.status, 400);
  } finally {
    server.close();
  }
});

test('runtime-coverage routes: ingest simple map and Istanbul format, then read back', async () => {
  const store = makeFakeStore();
  const { server, baseUrl } = await startApp((app) => mountRuntimeCoverageRoutes(app, { store }));
  try {
    const simpleRes = await fetch(`${baseUrl}/api/runtime-coverage/acme/widgets`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ 'src/a.js': 5 }),
    });
    const simpleBody = await simpleRes.json();
    assert.equal(simpleBody.format, 'simple');
    assert.equal(simpleBody.filesIngested, 1);

    const getRes = await fetch(`${baseUrl}/api/runtime-coverage/acme/widgets`);
    const getBody = await getRes.json();
    assert.deepEqual(getBody.files['src/a.js'], { hitCount: 5, coveredPct: 100 });

    const delRes = await fetch(`${baseUrl}/api/runtime-coverage/acme/widgets`, { method: 'DELETE' });
    assert.deepEqual(await delRes.json(), { ok: true, org: 'acme', repo: 'widgets', removed: 1 });
  } finally {
    server.close();
  }
});

test('auto-fix route: dryRun by default, apply on request', async () => {
  const dir = await makeTempProject({ 'orphan.js': 'module.exports = 1;\n' });
  const sanitizeAbsoluteProjectPath = (p) => path.resolve(p);
  const checkDeadCode = async () => ({ findings: [{ kind: 'unused-file', file: 'orphan.js' }] });
  const { server, baseUrl } = await startApp((app) => mountAutoFixRoute(app, { sanitizeAbsoluteProjectPath, checkDeadCode }));
  try {
    const dryRes = await fetch(`${baseUrl}/api/pipeline/auto-fix`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ projectPath: dir }),
    });
    const dryBody = await dryRes.json();
    assert.equal(dryBody.dryRun, true);
    assert.equal(dryBody.actions[0].applied, false);
    assert.ok(await fs.stat(path.join(dir, 'orphan.js')).then(() => true));

    const applyRes = await fetch(`${baseUrl}/api/pipeline/auto-fix`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ projectPath: dir, dryRun: false }),
    });
    const applyBody = await applyRes.json();
    assert.equal(applyBody.actions[0].applied, true);
    await assert.rejects(fs.stat(path.join(dir, 'orphan.js')));
  } finally {
    server.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('auto-fix route: fixes an ungoverned AI invocation alongside dead code, both on by default', async () => {
  const dir = await makeTempProject({
    'orphan.js': 'module.exports = 1;\n',
    'agent.ts': 'const result = await graph.invoke(input);\n',
  });
  const sanitizeAbsoluteProjectPath = (p) => path.resolve(p);
  const checkDeadCode = async () => ({ findings: [{ kind: 'unused-file', file: 'orphan.js' }] });
  const checkAiGovernance = async () => ({ findings: [{ file: 'agent.ts', line: 1, snippet: 'const result = await graph.invoke(input);' }] });
  const { server, baseUrl } = await startApp((app) => mountAutoFixRoute(app, { sanitizeAbsoluteProjectPath, checkDeadCode, checkAiGovernance }));
  try {
    const res = await fetch(`${baseUrl}/api/pipeline/auto-fix`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ projectPath: dir, dryRun: false }),
    });
    const body = await res.json();
    assert.equal(body.actionCount, 2);
    const governanceAction = body.actions.find((a) => a.type === 'add-recursion-limit-or-manual');
    assert.equal(governanceAction.applied, true);
    const content = await fs.readFile(path.join(dir, 'agent.ts'), 'utf8');
    assert.match(content, /recursionLimit: 25/);
  } finally {
    server.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('auto-fix route: categories narrows to just ai-governance', async () => {
  const dir = await makeTempProject({
    'orphan.js': 'module.exports = 1;\n',
    'agent.ts': 'const result = await graph.invoke(input);\n',
  });
  const sanitizeAbsoluteProjectPath = (p) => path.resolve(p);
  const checkDeadCode = async () => ({ findings: [{ kind: 'unused-file', file: 'orphan.js' }] });
  const checkAiGovernance = async () => ({ findings: [{ file: 'agent.ts', line: 1, snippet: 'const result = await graph.invoke(input);' }] });
  const { server, baseUrl } = await startApp((app) => mountAutoFixRoute(app, { sanitizeAbsoluteProjectPath, checkDeadCode, checkAiGovernance }));
  try {
    const res = await fetch(`${baseUrl}/api/pipeline/auto-fix`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ projectPath: dir, dryRun: false, categories: ['ai-governance'] }),
    });
    const body = await res.json();
    assert.equal(body.actionCount, 1);
    assert.equal(body.actions[0].type, 'add-recursion-limit-or-manual');
    assert.ok(await fs.stat(path.join(dir, 'orphan.js')).then(() => true), 'dead-code fix must not run when narrowed to ai-governance only');
  } finally {
    server.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});
