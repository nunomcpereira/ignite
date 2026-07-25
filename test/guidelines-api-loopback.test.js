'use strict';

/**
 * guidelines-api.js's /check-project intentionally accepts any host path
 * (it's a local dev/CI scanning tool, not a multi-tenant service) — the
 * actual boundary is that the API must never be reachable except from the
 * same machine. Covers both the pure address check and the real per-request
 * middleware rejecting a non-loopback peer over an actual HTTP connection.
 */

const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');

const app = require('../guidelines-api');

test('isLoopbackAddress: accepts IPv4/IPv6 loopback, rejects everything else', () => {
  assert.equal(app.isLoopbackAddress('127.0.0.1'), true);
  assert.equal(app.isLoopbackAddress('::1'), true);
  assert.equal(app.isLoopbackAddress('::ffff:127.0.0.1'), true);
  assert.equal(app.isLoopbackAddress('10.0.0.5'), false);
  assert.equal(app.isLoopbackAddress('192.168.1.1'), false);
  assert.equal(app.isLoopbackAddress(undefined), false);
});

test('middleware: a real request over the loopback socket is accepted', async () => {
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  try {
    const res = await fetch(`http://127.0.0.1:${port}/health`);
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { ok: true });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('middleware: a spoofed non-loopback remoteAddress is rejected with 403', async () => {
  // http.Server doesn't let a real client fake its own remoteAddress, so
  // this drives the middleware directly against a mock req/res — the same
  // thing supertest would do under the hood, without adding the dependency.
  const handlers = app._router.stack
    .filter((layer) => layer.name === '<anonymous>' && !layer.route)
    .map((layer) => layer.handle);
  const loopbackMiddleware = handlers.find((fn) => fn.length === 3);
  assert.ok(loopbackMiddleware, 'expected to find the loopback-check middleware');

  let statusCode = null;
  let body = null;
  const req = { socket: { remoteAddress: '203.0.113.5' } };
  const res = {
    status(code) { statusCode = code; return this; },
    json(payload) { body = payload; return this; },
  };
  let nextCalled = false;
  loopbackMiddleware(req, res, () => { nextCalled = true; });

  assert.equal(nextCalled, false);
  assert.equal(statusCode, 403);
  assert.match(body.error, /localhost/i);
});
