'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const fs = require('node:fs/promises');
const path = require('node:path');

const { withServerEnv, makeTempProject, makeFakeOasdiff } = require('./helpers');

const noopLog = () => {};

async function runGit(cwd, args) {
  return new Promise((resolve, reject) => {
    execFile('git', args, { cwd }, (err, stdout) => (err ? reject(err) : resolve(stdout)));
  });
}

const OPENAPI_V1 = 'openapi: 3.0.0\ninfo:\n  title: demo\n  version: "1.0"\npaths:\n  /users:\n    get:\n      responses:\n        "200":\n          description: ok\n';
const OPENAPI_V2 = 'openapi: 3.0.0\ninfo:\n  title: demo\n  version: "1.1"\npaths:\n  /users:\n    get:\n      responses:\n        "200":\n          description: ok updated\n';

// Two-commit repo with a clean working tree — resolveGitDiffBase only ever
// shells out to git, never to oasdiff itself, so this needs no fake CLI.
async function makeDiffableGitRepo(files) {
  const dir = await makeTempProject(files);
  await runGit(dir, ['init', '-q', '-b', 'main']);
  await runGit(dir, ['-c', 'user.email=t@t.com', '-c', 'user.name=t', 'add', '-A']);
  await runGit(dir, ['-c', 'user.email=t@t.com', '-c', 'user.name=t', 'commit', '-q', '-m', 'base']);
  await fs.writeFile(path.join(dir, 'openapi.yaml'), OPENAPI_V2);
  await runGit(dir, ['-c', 'user.email=t@t.com', '-c', 'user.name=t', 'commit', '-q', '-am', 'revise spec']);
  return dir;
}

function hasRealGit() {
  return new Promise((resolve) => {
    execFile('git', ['--version'], (err) => resolve(!err));
  });
}

function hasRealOasdiff() {
  return new Promise((resolve) => {
    execFile('oasdiff', ['--version'], (err) => resolve(!err));
  });
}

test('checkApiSchemaDrift: oasdiff is enabled by default', withServerEnv({}, async (mod) => {
  const cfg = mod.loadConfig();
  assert.equal(cfg.api.oasdiff.enabled, true);
  assert.equal(cfg.api.oasdiff.binary, 'oasdiff');
}));

test('checkApiSchemaDrift: OASDIFF_* env vars are wired into CONFIG.api.oasdiff', withServerEnv(
  { OASDIFF_ENABLED: 'true', OASDIFF_BINARY: '/opt/bin/oasdiff' },
  async (mod) => {
    const cfg = mod.loadConfig();
    assert.equal(cfg.api.oasdiff.enabled, true);
    assert.equal(cfg.api.oasdiff.binary, '/opt/bin/oasdiff');
  }
));

test('checkApiSchemaDrift: explicitly disabled — no findings, engine "disabled"', withServerEnv(
  { OASDIFF_ENABLED: 'false' },
  async (mod) => {
    const dir = await makeTempProject({ 'openapi.yaml': OPENAPI_V1 });
    const { findings, engine } = await mod.checkApiSchemaDrift(dir, noopLog);
    assert.equal(engine, 'disabled');
    assert.deepEqual(findings, []);
  }
));

test('checkApiSchemaDrift: no OpenAPI/AsyncAPI files in the project — no oasdiff invocation, no findings', async (t) => {
  if (!(await hasRealGit())) { t.skip('git not installed'); return; }
  const oasdiffBinary = await makeFakeOasdiff([]);
  await withServerEnv({ OASDIFF_ENABLED: 'true', OASDIFF_BINARY: oasdiffBinary }, async (mod) => {
    const dir = await makeTempProject({ 'README.md': '# demo\n' });
    const { findings, engine } = await mod.checkApiSchemaDrift(dir, noopLog);
    assert.equal(engine, 'oasdiff');
    assert.deepEqual(findings, []);
  })();
});

test('checkApiSchemaDrift: no prior git revision (fresh upload) — soft-skips, no findings', async (t) => {
  if (!(await hasRealGit())) { t.skip('git not installed'); return; }
  const oasdiffBinary = await makeFakeOasdiff([{ id: 'api-removed-without-deprecation', level: 'ERR', text: 'endpoint removed' }]);
  await withServerEnv({ OASDIFF_ENABLED: 'true', OASDIFF_BINARY: oasdiffBinary }, async (mod) => {
    const dir = await makeTempProject({ 'openapi.yaml': OPENAPI_V1 });
    // Single-commit repo (or no repo at all) — nothing to diff against.
    await runGit(dir, ['init', '-q', '-b', 'main']);
    await runGit(dir, ['-c', 'user.email=t@t.com', '-c', 'user.name=t', 'add', '-A']);
    await runGit(dir, ['-c', 'user.email=t@t.com', '-c', 'user.name=t', 'commit', '-q', '-m', 'only commit']);
    const { findings, engine } = await mod.checkApiSchemaDrift(dir, noopLog);
    assert.equal(engine, 'oasdiff');
    assert.deepEqual(findings, []);
  })();
});

test('checkApiSchemaDrift: flags a breaking change against the prior git revision', async (t) => {
  if (!(await hasRealGit())) { t.skip('git not installed'); return; }
  const oasdiffBinary = await makeFakeOasdiff([
    { id: 'api-removed-without-deprecation', level: 'ERR', text: 'API removed without deprecation', operation: 'GET', path: '/users' },
  ]);
  await withServerEnv({ OASDIFF_ENABLED: 'true', OASDIFF_BINARY: oasdiffBinary }, async (mod) => {
    const dir = await makeDiffableGitRepo({ 'openapi.yaml': OPENAPI_V1 });
    const { findings, engine } = await mod.checkApiSchemaDrift(dir, noopLog);
    assert.equal(engine, 'oasdiff');
    assert.equal(findings.length, 1);
    assert.equal(findings[0].file, 'openapi.yaml');
    assert.equal(findings[0].tool, 'oasdiff');
    assert.equal(findings[0].severity, 'error');
    assert.match(findings[0].message, /API removed without deprecation/);
    assert.match(findings[0].message, /GET \/users/);
  })();
});

test('checkApiSchemaDrift: WARN-level changes surface as warnings, not errors', async (t) => {
  if (!(await hasRealGit())) { t.skip('git not installed'); return; }
  const oasdiffBinary = await makeFakeOasdiff([
    { id: 'response-property-type-changed', level: 'WARN', text: 'response property type changed' },
  ]);
  await withServerEnv({ OASDIFF_ENABLED: 'true', OASDIFF_BINARY: oasdiffBinary }, async (mod) => {
    const dir = await makeDiffableGitRepo({ 'openapi.yaml': OPENAPI_V1 });
    const { findings } = await mod.checkApiSchemaDrift(dir, noopLog);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].severity, 'warning');
  })();
});

test('checkApiSchemaDrift: clean diff produces no findings', async (t) => {
  if (!(await hasRealGit())) { t.skip('git not installed'); return; }
  const oasdiffBinary = await makeFakeOasdiff([]);
  await withServerEnv({ OASDIFF_ENABLED: 'true', OASDIFF_BINARY: oasdiffBinary }, async (mod) => {
    const dir = await makeDiffableGitRepo({ 'openapi.yaml': OPENAPI_V1 });
    const { findings, engine } = await mod.checkApiSchemaDrift(dir, noopLog);
    assert.equal(engine, 'oasdiff');
    assert.deepEqual(findings, []);
  })();
});

test('checkApiSchemaDrift: oasdiff enabled but binary missing — soft-skips, no findings, no throw', async (t) => {
  if (!(await hasRealGit())) { t.skip('git not installed'); return; }
  await withServerEnv({ OASDIFF_ENABLED: 'true', OASDIFF_BINARY: '/nonexistent/oasdiff-xyz' }, async (mod) => {
    const dir = await makeDiffableGitRepo({ 'openapi.yaml': OPENAPI_V1 });
    const logs = [];
    const { findings, engine } = await mod.checkApiSchemaDrift(dir, (m) => logs.push(m));
    assert.equal(engine, 'disabled');
    assert.deepEqual(findings, []);
    assert.ok(logs.some((l) => l.includes('oasdiff')), 'failure is logged, not thrown');
  })();
});

test('checkApiSchemaDrift: real oasdiff binary end-to-end (skipped if oasdiff is not installed)', async (t) => {
  if (!(await hasRealGit())) { t.skip('git not installed'); return; }
  if (!(await hasRealOasdiff())) {
    t.skip('oasdiff not installed on PATH — install with `brew install oasdiff` to run this test');
    return;
  }
  await withServerEnv({ OASDIFF_ENABLED: 'true', OASDIFF_BINARY: 'oasdiff' }, async (mod) => {
    const dir = await makeDiffableGitRepo({ 'openapi.yaml': OPENAPI_V1 });
    const { findings, engine } = await mod.checkApiSchemaDrift(dir, noopLog);
    assert.equal(engine, 'oasdiff');
    assert.ok(findings.every((f) => f.tool === 'oasdiff'));
  })();
});
