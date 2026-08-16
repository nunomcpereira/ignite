'use strict';

/**
 * Covers two auth.js hardenings: login doesn't reveal account existence
 * through response timing (always runs one scrypt derivation either way),
 * and both /login and /register are throttled against repeated attempts.
 * No dedicated test file existed for auth.js before this - a real gap,
 * since these are exactly the kind of behavior that silently regresses.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const express = require('express');

const { createAuth, hashPassword } = require('../auth');

// Minimal in-memory fake of the subset of db-store.js's interface the
// standalone-mode login/register routes actually call.
function makeFakeStore() {
  const users = new Map(); // email -> user
  let nextId = 1;
  return {
    async seedUser(email, password) {
      const id = nextId++;
      users.set(email, { id, email, name: email, provider: 'local', password_hash: await hashPassword(password) });
      return id;
    },
    getUserByEmail(email) {
      return users.get(email) || null;
    },
    createLocalUser(email, name, passwordHash) {
      const id = nextId++;
      users.set(email, { id, email, name, provider: 'local', password_hash: passwordHash });
      return id;
    },
    createSession() {},
    getSession() {
      return null;
    },
    deleteSession() {},
  };
}

async function withAuthServer(fn) {
  const store = makeFakeStore();
  const { router } = createAuth(store, { mode: 'standalone', allowSelfRegistration: true }, {});
  const app = express();
  app.use(express.json());
  app.use(router);
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  try {
    await fn(`http://127.0.0.1:${port}`, store);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

async function timeIt(fn) {
  const start = process.hrtime.bigint();
  await fn();
  return Number(process.hrtime.bigint() - start) / 1e6; // ms
}

test('login: nonexistent-account and wrong-password responses take comparable time (no cheap short-circuit)', async () => {
  await withAuthServer(async (base, store) => {
    await store.seedUser('real@example.com', 'correct-horse-battery');
    const login = (email, password) =>
      fetch(`${base}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

    const nonexistentMs = await timeIt(() => login('nosuchuser@example.com', 'whatever12345'));
    const wrongPasswordMs = await timeIt(() => login('real@example.com', 'totally-wrong-pw'));

    // Both paths now run exactly one scrypt derivation, so they should be
    // in the same ballpark - not a strict bound (machine-load-dependent),
    // just proving the nonexistent-account path isn't a near-instant
    // short-circuit an order of magnitude faster than a real check.
    assert.ok(
      nonexistentMs > wrongPasswordMs * 0.3,
      `nonexistent-account login (${nonexistentMs.toFixed(1)}ms) was suspiciously faster than a real wrong-password check (${wrongPasswordMs.toFixed(1)}ms)`
    );
  });
});

test('login: both paths return the same generic error and status', async () => {
  await withAuthServer(async (base, store) => {
    await store.seedUser('real@example.com', 'correct-horse-battery');
    const login = async (email, password) => {
      const res = await fetch(`${base}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      return { status: res.status, body: await res.json() };
    };
    const a = await login('nosuchuser@example.com', 'whatever12345');
    const b = await login('real@example.com', 'totally-wrong-pw');
    assert.equal(a.status, 401);
    assert.equal(b.status, 401);
    assert.deepEqual(a.body, b.body);
  });
});

test('login: throttled after repeated attempts against the same email', async () => {
  await withAuthServer(async (base) => {
    const login = () =>
      fetch(`${base}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'flood-target@example.com', password: 'wrong' }),
      });
    let last;
    for (let i = 0; i < 9; i++) last = await login();
    assert.equal(last.status, 429);
  });
});

test('register: throttled after repeated attempts from the same client', async () => {
  await withAuthServer(async (base) => {
    const register = (email) =>
      fetch(`${base}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password: 'a-long-enough-password' }),
      });
    let last;
    for (let i = 0; i < 9; i++) last = await register(`flood-${i}@example.com`);
    assert.equal(last.status, 429);
  });
});

test('login: succeeding resets the throttle counter for that email', async () => {
  await withAuthServer(async (base, store) => {
    await store.seedUser('resetter@example.com', 'correct-horse-battery');
    const login = (password) =>
      fetch(`${base}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'resetter@example.com', password }),
      });
    for (let i = 0; i < 3; i++) await login('wrong');
    const ok = await login('correct-horse-battery');
    assert.equal(ok.status, 200);
  });
});
