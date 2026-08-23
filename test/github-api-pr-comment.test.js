'use strict';

/**
 * lib/github-api.js's ghCommentOnPr — the one function here with real risk
 * (a multi-line markdown body can't go through runTool's CLI-arg sanitizer,
 * which rejects \n in any argument, so this has to go through a temp
 * --body-file instead of --body). Covers both the `gh` CLI path (verified
 * against a fake `gh` script on PATH) and the token-only REST fallback.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');

const { createGithubApi } = require('../lib/github-api');
const { createToolRunner } = require('../lib/tool-runner');

async function makeFakeGh(callLogPath) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ignite-fake-gh-'));
  const scriptPath = path.join(dir, 'gh');
  const script = `#!/usr/bin/env node
const fs = require('fs');
const args = process.argv.slice(2);
if (args[0] === '--version') { process.stdout.write('gh version 2.0.0 fake\\n'); process.exit(0); }
if (args[0] === 'pr' && args[1] === 'comment') {
  const bodyFileIdx = args.indexOf('--body-file');
  const bodyFileContents = bodyFileIdx !== -1 ? fs.readFileSync(args[bodyFileIdx + 1], 'utf8') : null;
  fs.writeFileSync(${JSON.stringify(callLogPath)}, JSON.stringify({ args, bodyFileContents }));
  process.exit(0);
}
process.exit(1);
`;
  await fs.writeFile(scriptPath, script, { mode: 0o755 });
  return dir;
}

async function withPrependedPath(dir, fn) {
  const original = process.env.PATH;
  process.env.PATH = `${dir}${path.delimiter}${original}`;
  try {
    await fn();
  } finally {
    process.env.PATH = original;
  }
}

test('ghCommentOnPr: gh CLI path writes a multi-line body to --body-file, not --body', async () => {
  const callLogPath = path.join(os.tmpdir(), `ignite-gh-call-${Date.now()}.json`);
  const fakeGhDir = await makeFakeGh(callLogPath);
  const { runTool, runToolStreaming } = createToolRunner({});
  const { ghCommentOnPr } = createGithubApi({ runTool, runToolStreaming });

  const multilineBody = '### Ignite gate failed\n\n- one\n- two\n';
  await withPrependedPath(fakeGhDir, async () => {
    await ghCommentOnPr({ fullName: 'acme/widgets', prNumber: 7, body: multilineBody, token: 'tok' });
  });

  const call = JSON.parse(await fs.readFile(callLogPath, 'utf8'));
  assert.deepEqual(call.args.slice(0, 4), ['pr', 'comment', '7', '--repo']);
  assert.equal(call.args[4], 'acme/widgets');
  assert.ok(call.args.includes('--body-file'));
  assert.ok(!call.args.includes('--body'));
  assert.equal(call.bodyFileContents, multilineBody);

  await fs.rm(callLogPath, { force: true });
  await fs.rm(fakeGhDir, { recursive: true, force: true });
});

test('ghCommentOnPr: temp body file is removed after the call', async () => {
  const callLogPath = path.join(os.tmpdir(), `ignite-gh-call-${Date.now()}.json`);
  const fakeGhDir = await makeFakeGh(callLogPath);
  const { runTool, runToolStreaming } = createToolRunner({});
  const { ghCommentOnPr } = createGithubApi({ runTool, runToolStreaming });

  await withPrependedPath(fakeGhDir, async () => {
    await ghCommentOnPr({ fullName: 'acme/widgets', prNumber: 1, body: 'hello', token: 'tok' });
  });

  const call = JSON.parse(await fs.readFile(callLogPath, 'utf8'));
  const bodyFileIdx = call.args.indexOf('--body-file');
  const tmpFile = call.args[bodyFileIdx + 1];
  await assert.rejects(() => fs.access(tmpFile));

  await fs.rm(callLogPath, { force: true });
  await fs.rm(fakeGhDir, { recursive: true, force: true });
});

test('ghCommentOnPr: REST fallback posts to /repos/:fullName/issues/:prNumber/comments when gh is unavailable', async () => {
  const { runTool, runToolStreaming } = createToolRunner({});
  const { ghCommentOnPr } = createGithubApi({ runTool, runToolStreaming });

  const calls = [];
  const originalFetch = global.fetch;
  global.fetch = async (url, opts) => {
    calls.push({ url, opts });
    return { ok: true, text: async () => '' };
  };

  await withPrependedPath(path.join(os.tmpdir(), 'ignite-empty-path-dir-that-does-not-exist'), async () => {
    // Force gh CLI resolution to fail by pointing PATH somewhere with no `gh`.
    const original = process.env.PATH;
    process.env.PATH = '/nonexistent-ignite-test-path';
    try {
      await ghCommentOnPr({ fullName: 'acme/widgets', prNumber: 3, body: 'hi', token: 'tok' });
    } finally {
      process.env.PATH = original;
    }
  });

  global.fetch = originalFetch;
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://api.github.com/repos/acme/widgets/issues/3/comments');
  assert.equal(calls[0].opts.method, 'POST');
  assert.deepEqual(JSON.parse(calls[0].opts.body), { body: 'hi' });
});
