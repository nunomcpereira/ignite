'use strict';

/**
 * .igniteignore: lib/fs-utils.js's walkFiles honoring it (paths excluded
 * from every check's file discovery, not just this one) and
 * checks/igniteignore.js's checkIgniteIgnoreCommitted (a present-but-
 * uncommitted .igniteignore is a blocking finding — a silent, unreviewable
 * scan bypass).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const fs = require('node:fs/promises');

const { makeTempProject, withServerEnv } = require('./helpers');
const { walkFiles } = require('../lib/fs-utils');
const { createToolRunner } = require('../lib/tool-runner');
const { createIgniteIgnoreCheck } = require('../checks/igniteignore');

async function runGit(cwd, args) {
  return new Promise((resolve, reject) => {
    execFile('git', args, { cwd }, (err, stdout) => (err ? reject(err) : resolve(stdout)));
  });
}

async function initGitRepo(dir) {
  await runGit(dir, ['init', '-q', '-b', 'main']);
  await runGit(dir, ['-c', 'user.email=t@t.com', '-c', 'user.name=t', 'add', '-A']);
  await runGit(dir, ['-c', 'user.email=t@t.com', '-c', 'user.name=t', 'commit', '-q', '-m', 'init']);
}

async function relFiles(dir) {
  const out = [];
  for await (const f of walkFiles(dir)) out.push(require('path').relative(dir, f).split(require('path').sep).join('/'));
  return out.sort();
}

function make(config = { enabled: true }) {
  const { runTool } = createToolRunner({});
  return createIgniteIgnoreCheck({ runTool, config }).checkIgniteIgnoreCommitted;
}

test('.igniteignore commit check is enabled by default', withServerEnv({}, async (mod) => {
  const cfg = mod.loadConfig();
  assert.equal(cfg.ignoreFile.enabled, true);
}));

test('IGNOREFILE_ENABLED env var is wired into CONFIG.ignoreFile', withServerEnv({ IGNOREFILE_ENABLED: 'false' }, async (mod) => {
  const cfg = mod.loadConfig();
  assert.equal(cfg.ignoreFile.enabled, false);
}));

test('walkFiles: a file pattern in .igniteignore is skipped entirely', async () => {
  const dir = await makeTempProject({
    '.igniteignore': 'secret-fixture.js\n',
    'index.js': 'console.log(1);\n',
    'secret-fixture.js': 'module.exports = 1;\n',
  });
  const files = await relFiles(dir);
  assert.ok(files.includes('index.js'));
  assert.ok(!files.includes('secret-fixture.js'));
  await fs.rm(dir, { recursive: true, force: true });
});

test('walkFiles: a directory pattern in .igniteignore prunes the whole subtree (never descended into)', async () => {
  const dir = await makeTempProject({
    '.igniteignore': 'vendored/\n',
    'index.js': 'console.log(1);\n',
    'vendored/lib.js': 'module.exports = 1;\n',
    'vendored/nested/deep.js': 'module.exports = 2;\n',
  });
  const files = await relFiles(dir);
  assert.ok(files.includes('index.js'));
  assert.ok(!files.some((f) => f.startsWith('vendored/')));
  await fs.rm(dir, { recursive: true, force: true });
});

test('walkFiles: glob and negation patterns in .igniteignore behave like .gitignore', async () => {
  const dir = await makeTempProject({
    '.igniteignore': '*.generated.js\n!keep.generated.js\n',
    'a.generated.js': '1',
    'keep.generated.js': '2',
    'b.js': '3',
  });
  const files = await relFiles(dir);
  assert.ok(!files.includes('a.generated.js'));
  assert.ok(files.includes('keep.generated.js'));
  assert.ok(files.includes('b.js'));
  await fs.rm(dir, { recursive: true, force: true });
});

test('walkFiles: no .igniteignore present — walks everything as before', async () => {
  const dir = await makeTempProject({ 'a.js': '1', 'b.js': '2' });
  const files = await relFiles(dir);
  assert.deepEqual(files, ['a.js', 'b.js']);
  await fs.rm(dir, { recursive: true, force: true });
});

test('checkIgniteIgnoreCommitted: disabled returns no findings', async () => {
  const checkIgniteIgnoreCommitted = make({ enabled: false });
  const dir = await makeTempProject({ '.igniteignore': 'foo\n' });
  const result = await checkIgniteIgnoreCommitted(dir, null);
  assert.deepEqual(result, { findings: [], engine: 'disabled' });
  await fs.rm(dir, { recursive: true, force: true });
});

test('checkIgniteIgnoreCommitted: no .igniteignore file — no findings', async () => {
  const checkIgniteIgnoreCommitted = make();
  const dir = await makeTempProject({ 'index.js': '1' });
  await initGitRepo(dir);
  const result = await checkIgniteIgnoreCommitted(dir, null);
  assert.deepEqual(result.findings, []);
  await fs.rm(dir, { recursive: true, force: true });
});

test('checkIgniteIgnoreCommitted: not a git repo yet (fresh onboarding) — no findings even though uncommitted', async () => {
  const checkIgniteIgnoreCommitted = make();
  const dir = await makeTempProject({ '.igniteignore': 'foo\n' });
  const result = await checkIgniteIgnoreCommitted(dir, null);
  assert.deepEqual(result.findings, []);
  await fs.rm(dir, { recursive: true, force: true });
});

test('checkIgniteIgnoreCommitted: .igniteignore present and committed — no findings', async () => {
  const checkIgniteIgnoreCommitted = make();
  const dir = await makeTempProject({ '.igniteignore': 'foo\n', 'index.js': '1' });
  await initGitRepo(dir);
  const result = await checkIgniteIgnoreCommitted(dir, null);
  assert.deepEqual(result.findings, []);
  await fs.rm(dir, { recursive: true, force: true });
});

test('checkIgniteIgnoreCommitted: .igniteignore present but untracked in an existing git repo — blocking finding', async () => {
  const checkIgniteIgnoreCommitted = make();
  const dir = await makeTempProject({ 'index.js': '1' });
  await initGitRepo(dir);
  await fs.writeFile(require('path').join(dir, '.igniteignore'), 'foo\n');

  const { findings } = await checkIgniteIgnoreCommitted(dir, null);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].kind, 'igniteignore-not-committed');
  assert.equal(findings[0].severity, 'error');
  assert.equal(findings[0].file, '.igniteignore');
  await fs.rm(dir, { recursive: true, force: true });
});
