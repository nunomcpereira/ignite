'use strict';

/**
 * mcp-server.js's resolve_review_decision and effectivate_project tools —
 * thin proxies to a running Ignite server's review-gate endpoints (same
 * "thin proxy" pattern onboard_project already uses), added so an agent
 * can resume a paused interactive run or ship a prior dryRun simulation
 * without the browser UI. Also covers proxyToIgnite's IGNITE_API_KEY
 * Authorization header, added alongside these tools since headless
 * (non-dryRun) calls now require it (see auth.js's attachUser).
 *
 * Exercises the tool callbacks directly against a fake HTTP server
 * standing in for Ignite, rather than through the MCP transport/protocol
 * layer — the transport itself is the SDK's concern, not this codebase's.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const MCP_SERVER_PATH = require.resolve('../mcp-server.js');

async function withFakeIgniteServer(handler, fn) {
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => handler(req, res, body ? JSON.parse(body) : {}));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const prevBase = process.env.IGNITE_BASE_URL;
  const prevKey = process.env.IGNITE_API_KEY;
  process.env.IGNITE_BASE_URL = `http://127.0.0.1:${port}`;
  delete require.cache[MCP_SERVER_PATH];
  try {
    const { buildServer } = require(MCP_SERVER_PATH);
    await fn(buildServer());
  } finally {
    if (prevBase === undefined) delete process.env.IGNITE_BASE_URL; else process.env.IGNITE_BASE_URL = prevBase;
    if (prevKey === undefined) delete process.env.IGNITE_API_KEY; else process.env.IGNITE_API_KEY = prevKey;
    delete require.cache[MCP_SERVER_PATH];
    await new Promise((resolve) => server.close(resolve));
  }
}

function callTool(server, name, args) {
  return server._registeredTools[name].handler(args, {});
}

test('resolve_review_decision: posts to /api/pipeline/:jobId/review-decision with the given body', async () => {
  let received = null;
  await withFakeIgniteServer(
    (req, res, body) => {
      received = { method: req.method, url: req.url, body };
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ ok: true }));
    },
    async (server) => {
      const result = await callTool(server, 'resolve_review_decision', {
        jobId: 'job-abc',
        proceed: true,
        overrides: [{ issueId: 'secret::x.js::1', justification: 'false positive' }],
        actor: { email: 'agent@example.com' },
      });
      assert.equal(received.method, 'POST');
      assert.equal(received.url, '/api/pipeline/job-abc/review-decision');
      assert.equal(received.body.proceed, true);
      assert.equal(received.body.overrides[0].issueId, 'secret::x.js::1');
      assert.equal(result.isError, false);
    }
  );
});

test('resolve_review_decision: URL-encodes the job id', async () => {
  let receivedUrl = null;
  await withFakeIgniteServer(
    (req, res) => {
      receivedUrl = req.url;
      res.end(JSON.stringify({ ok: true }));
    },
    async (server) => {
      await callTool(server, 'resolve_review_decision', { jobId: 'job/with slash', proceed: false });
      assert.equal(receivedUrl, '/api/pipeline/job%2Fwith%20slash/review-decision');
    }
  );
});

test('effectivate_project: posts to /api/projects/:projectId/effectivate', async () => {
  let received = null;
  await withFakeIgniteServer(
    (req, res, body) => {
      received = { url: req.url, body };
      res.end(JSON.stringify({ ok: true, repoUrl: 'https://github.com/acme/widget' }));
    },
    async (server) => {
      const result = await callTool(server, 'effectivate_project', { projectId: 42 });
      assert.equal(received.url, '/api/projects/42/effectivate');
      const payload = JSON.parse(result.content[0].text);
      assert.equal(payload.repoUrl, 'https://github.com/acme/widget');
    }
  );
});

test('effectivate_project: surfaces server error responses as isError', async () => {
  await withFakeIgniteServer(
    (req, res) => {
      res.statusCode = 409;
      res.end(JSON.stringify({ ok: false, error: 'still has blocking issues' }));
    },
    async (server) => {
      const result = await callTool(server, 'effectivate_project', { projectId: 1 });
      assert.equal(result.isError, true);
    }
  );
});

test('proxyToIgnite: attaches Authorization: Bearer when IGNITE_API_KEY is set', async () => {
  let receivedAuth = null;
  process.env.IGNITE_API_KEY = 'ignite_test_key';
  await withFakeIgniteServer(
    (req, res) => {
      receivedAuth = req.headers.authorization;
      res.end(JSON.stringify({ ok: true }));
    },
    async (server) => {
      await callTool(server, 'resolve_review_decision', { jobId: 'job-1', proceed: true });
      assert.equal(receivedAuth, 'Bearer ignite_test_key');
    }
  );
});

test('proxyToIgnite: no Authorization header when IGNITE_API_KEY is unset', async () => {
  let receivedAuth = null;
  delete process.env.IGNITE_API_KEY;
  await withFakeIgniteServer(
    (req, res) => {
      receivedAuth = req.headers.authorization;
      res.end(JSON.stringify({ ok: true }));
    },
    async (server) => {
      await callTool(server, 'resolve_review_decision', { jobId: 'job-1', proceed: true });
      assert.equal(receivedAuth, undefined);
    }
  );
});

test('proxyToIgnite: unreachable server reports a clear error instead of throwing', async () => {
  const prevBase = process.env.IGNITE_BASE_URL;
  process.env.IGNITE_BASE_URL = 'http://127.0.0.1:1'; // reserved, always refused
  delete require.cache[MCP_SERVER_PATH];
  try {
    const { buildServer } = require(MCP_SERVER_PATH);
    const server = buildServer();
    const result = await callTool(server, 'effectivate_project', { projectId: 1 });
    assert.equal(result.isError, true);
    assert.match(result.content[0].text, /Could not reach Ignite server/);
  } finally {
    if (prevBase === undefined) delete process.env.IGNITE_BASE_URL; else process.env.IGNITE_BASE_URL = prevBase;
    delete require.cache[MCP_SERVER_PATH];
  }
});
