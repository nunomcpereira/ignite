'use strict';

/**
 * Covers auth.js's headless API-key path (attachUser's Authorization:
 * Bearer ignite_<key> branch) — the mechanism that lets an agent/CLI
 * caller authenticate for a real (non-dryRun) onboard without a browser
 * OAuth/session-cookie flow. No coverage existed before this; the session-
 * cookie path already has test/auth-security.test.js.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const express = require('express');

const { createAuth, generateApiKey, hashApiKey } = require('../auth');

// Minimal in-memory fake of the subset of db-store.js's api_keys interface
// attachUser actually calls.
function makeFakeStore() {
  const keys = new Map(); // hash -> { id, user_id, email, name, provider, revoked }
  let nextId = 1;
  const touched = [];
  return {
    seedKey({ email, name = email, provider = 'local' }) {
      const rawKey = generateApiKey();
      const id = nextId++;
      keys.set(hashApiKey(rawKey), { id, user_id: id, email, name, provider, revoked: false });
      return rawKey;
    },
    getActiveApiKeyByHash(hash) {
      const row = keys.get(hash);
      if (!row || row.revoked) return null;
      const { revoked, ...rest } = row;
      return rest;
    },
    touchApiKeyLastUsed(id) {
      touched.push(id);
    },
    revokeByHash(rawKey) {
      const row = keys.get(hashApiKey(rawKey));
      if (row) row.revoked = true;
    },
    touchedIds: touched,
    getSession() {
      return null;
    },
  };
}

async function withAuthedServer(store, fn) {
  const { attachUser, requireAuth } = createAuth(store, { mode: 'standalone' }, {});
  const app = express();
  app.use(attachUser);
  app.get('/whoami', requireAuth, (req, res) => res.json({ user: req.user }));
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('API key: a valid Bearer ignite_ key resolves req.user with no session cookie', async () => {
  const store = makeFakeStore();
  const rawKey = store.seedKey({ email: 'agent@example.com', name: 'CI Agent' });
  await withAuthedServer(store, async (base) => {
    const res = await fetch(`${base}/whoami`, { headers: { Authorization: `Bearer ${rawKey}` } });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.user.email, 'agent@example.com');
    assert.equal(body.user.name, 'CI Agent');
  });
});

test('API key: touches last_used_at on every authenticated request', async () => {
  const store = makeFakeStore();
  const rawKey = store.seedKey({ email: 'agent@example.com' });
  await withAuthedServer(store, async (base) => {
    await fetch(`${base}/whoami`, { headers: { Authorization: `Bearer ${rawKey}` } });
    await fetch(`${base}/whoami`, { headers: { Authorization: `Bearer ${rawKey}` } });
    assert.equal(store.touchedIds.length, 2);
  });
});

test('API key: revoked key is rejected (401, no req.user)', async () => {
  const store = makeFakeStore();
  const rawKey = store.seedKey({ email: 'agent@example.com' });
  store.revokeByHash(rawKey);
  await withAuthedServer(store, async (base) => {
    const res = await fetch(`${base}/whoami`, { headers: { Authorization: `Bearer ${rawKey}` } });
    assert.equal(res.status, 401);
  });
});

test('API key: garbage/malformed bearer token is ignored, not thrown', async () => {
  const store = makeFakeStore();
  await withAuthedServer(store, async (base) => {
    const res = await fetch(`${base}/whoami`, { headers: { Authorization: 'Bearer not-an-ignite-key' } });
    assert.equal(res.status, 401);
  });
});

test('API key: missing Authorization header entirely is ignored, not thrown', async () => {
  const store = makeFakeStore();
  await withAuthedServer(store, async (base) => {
    const res = await fetch(`${base}/whoami`);
    assert.equal(res.status, 401);
  });
});

test('hashApiKey: deterministic and never equal to the raw key', () => {
  const rawKey = generateApiKey();
  assert.equal(hashApiKey(rawKey), hashApiKey(rawKey));
  assert.notEqual(hashApiKey(rawKey), rawKey);
});

test('generateApiKey: produces unique, prefixed keys', () => {
  const a = generateApiKey();
  const b = generateApiKey();
  assert.notEqual(a, b);
  assert.ok(a.startsWith('ignite_'));
});
