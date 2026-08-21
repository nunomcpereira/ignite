'use strict';

/**
 * bin/ignite.js — the `ignite scan` CLI wrapper around POST
 * /api/pipeline/validate-all, for agents/CI that want a plain command +
 * exit code instead of driving the HTTP API themselves. Exercised end to
 * end as a real child process against a fake HTTP server standing in for
 * Ignite, since the whole point of this entrypoint is its process
 * boundary (argv parsing, exit codes, stdout shape).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');

const execFileP = promisify(execFile);
const CLI_PATH = path.join(__dirname, '..', 'bin', 'ignite.js');

async function withFakeIgniteServer(handler, fn) {
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => handler(req, res, body ? JSON.parse(body) : {}));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

function runCli(args, env = {}) {
  return execFileP('node', [CLI_PATH, ...args], { env: { ...process.env, ...env } })
    .then((r) => ({ ...r, code: 0 }))
    .catch((e) => ({ stdout: e.stdout, stderr: e.stderr, code: e.code }));
}

test('ignite scan: exits 0 and prints PASSED on ok:true', async () => {
  await withFakeIgniteServer(
    (req, res) => {
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ ok: true, issues: [], phases: [], events: [] }));
    },
    async (baseUrl) => {
      const { stdout, code } = await runCli(['scan', '.'], { IGNITE_BASE_URL: baseUrl });
      assert.equal(code, 0);
      assert.match(stdout, /PASSED/);
    }
  );
});

test('ignite scan: exits 1 and prints FAILED with issue count on ok:false', async () => {
  await withFakeIgniteServer(
    (req, res) => {
      res.end(JSON.stringify({
        ok: false,
        error: 'Phase 4 has 1 unresolved blocking finding(s).',
        failedPhase: 4,
        issues: [{ id: 'x', file: 'a.js', line: 3, severity: 'error', status: 'open', summary: 'Hardcoded secret.' }],
      }));
    },
    async (baseUrl) => {
      const { stdout, code } = await runCli(['scan', '.'], { IGNITE_BASE_URL: baseUrl });
      assert.equal(code, 1);
      assert.match(stdout, /FAILED/);
      assert.match(stdout, /1 blocking issue/);
      assert.match(stdout, /a\.js:3/);
    }
  );
});

test('ignite scan --json: prints the raw JSON response verbatim', async () => {
  await withFakeIgniteServer(
    (req, res) => {
      res.end(JSON.stringify({ ok: true, issues: [], phases: [], events: [], jobId: 'job-xyz' }));
    },
    async (baseUrl) => {
      const { stdout, code } = await runCli(['scan', '.', '--json'], { IGNITE_BASE_URL: baseUrl });
      assert.equal(code, 0);
      const parsed = JSON.parse(stdout);
      assert.equal(parsed.jobId, 'job-xyz');
    }
  );
});

test('ignite scan --changed-files: forwards a parsed changedFiles array in the request body', async () => {
  let received = null;
  await withFakeIgniteServer(
    (req, res, body) => {
      received = body;
      res.end(JSON.stringify({ ok: true, issues: [], phases: [], events: [] }));
    },
    async (baseUrl) => {
      await runCli(['scan', '.', '--changed-files', 'a.js,b.py'], { IGNITE_BASE_URL: baseUrl });
      assert.deepEqual(received.changedFiles, ['a.js', 'b.py']);
    }
  );
});

test('ignite scan: sends Authorization header when IGNITE_API_KEY is set', async () => {
  let receivedAuth = null;
  await withFakeIgniteServer(
    (req, res) => {
      receivedAuth = req.headers.authorization;
      res.end(JSON.stringify({ ok: true, issues: [], phases: [], events: [] }));
    },
    async (baseUrl) => {
      await runCli(['scan', '.'], { IGNITE_BASE_URL: baseUrl, IGNITE_API_KEY: 'ignite_cli_key' });
      assert.equal(receivedAuth, 'Bearer ignite_cli_key');
    }
  );
});

test('ignite scan: unreachable server exits 2 with a clear stderr message', async () => {
  const { stderr, code } = await runCli(['scan', '.'], { IGNITE_BASE_URL: 'http://127.0.0.1:1' });
  assert.equal(code, 2);
  assert.match(stderr, /Could not reach Ignite server/);
});

test('ignite: unknown/missing command exits 2 with usage on stderr', async () => {
  const { stderr, code } = await runCli([]);
  assert.equal(code, 2);
  assert.match(stderr, /Usage: ignite scan/);
});
