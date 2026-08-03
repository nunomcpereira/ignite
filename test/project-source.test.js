'use strict';

/**
 * Onboarded-projects history annotates *how* a run was started — ui (the
 * browser form), api (validate-all/onboard hit directly), or mcp
 * (mcp-server.js's tools, tagged via the X-Ignite-Client header server.js's
 * resolveRequestSource reads). Covers db-store.js's createProject/listProjects
 * side; server.js's header-to-source mapping is exercised live in
 * e2e/studio-license-issues.spec.js and by hand (see session notes) since it
 * needs a running HTTP server.
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

test('createProject: defaults to source "ui" when not specified', () => withTempDb((store) => {
  const id = store.createProject('job-1', 'acme', 'widget', false);
  const [project] = store.listProjects();
  assert.equal(project.id, id);
  assert.equal(project.source, 'ui');
}));

test('createProject: explicit source is persisted and listed', () => withTempDb((store) => {
  store.createProject('job-2', 'acme', 'widget-api', false, 'api');
  store.createProject('job-3', 'acme', 'widget-mcp', false, 'mcp');
  const bySource = Object.fromEntries(store.listProjects().map((p) => [p.repo, p.source]));
  assert.equal(bySource['widget-api'], 'api');
  assert.equal(bySource['widget-mcp'], 'mcp');
}));

test('getProjectDetails: includes source', () => withTempDb((store) => {
  const id = store.createProject('job-4', 'acme', 'widget', false, 'mcp');
  const details = store.getProjectDetails(id);
  assert.equal(details.source, 'mcp');
}));
