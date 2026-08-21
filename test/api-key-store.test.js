'use strict';

/**
 * db-store.js's api_keys table + accessor methods — the persistence side of
 * headless API-key auth (see auth.js's attachUser and
 * test/api-key-auth.test.js for the request-handling side, and
 * scripts/create-api-key.js for the minting CLI these methods back).
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

test('createApiKey + getActiveApiKeyByHash: round-trips to the owning user', () => withTempDb((store) => {
  const userId = store.createLocalUser('agent@example.com', 'CI Agent', 'unused-hash');
  const id = store.createApiKey(userId, 'deadbeef'.repeat(8), 'ci-runner');
  assert.equal(typeof id, 'number');

  const row = store.getActiveApiKeyByHash('deadbeef'.repeat(8));
  assert.equal(row.user_id, userId);
  assert.equal(row.email, 'agent@example.com');
  assert.equal(row.name, 'CI Agent');
}));

test('getActiveApiKeyByHash: unknown hash returns null', () => withTempDb((store) => {
  assert.equal(store.getActiveApiKeyByHash('no-such-hash'), null);
}));

test('revokeApiKey: revoked key stops resolving via getActiveApiKeyByHash', () => withTempDb((store) => {
  const userId = store.createLocalUser('agent@example.com', 'CI Agent', 'unused-hash');
  const id = store.createApiKey(userId, 'cafebabe'.repeat(8), null);
  assert.ok(store.getActiveApiKeyByHash('cafebabe'.repeat(8)));

  const changed = store.revokeApiKey(id);
  assert.equal(changed, true);
  assert.equal(store.getActiveApiKeyByHash('cafebabe'.repeat(8)), null);
}));

test('revokeApiKey: revoking an already-revoked (or nonexistent) key is a no-op, returns false', () => withTempDb((store) => {
  const userId = store.createLocalUser('agent@example.com', 'CI Agent', 'unused-hash');
  const id = store.createApiKey(userId, 'facefeed'.repeat(8), null);
  assert.equal(store.revokeApiKey(id), true);
  assert.equal(store.revokeApiKey(id), false);
  assert.equal(store.revokeApiKey(999999), false);
}));

test('touchApiKeyLastUsed: sets last_used_at, initially null', () => withTempDb((store) => {
  const userId = store.createLocalUser('agent@example.com', 'CI Agent', 'unused-hash');
  const id = store.createApiKey(userId, 'a1b2c3d4'.repeat(8), null);

  let [before] = store.listApiKeysForUser(userId);
  assert.equal(before.last_used_at, null);

  store.touchApiKeyLastUsed(id);
  const [after] = store.listApiKeysForUser(userId);
  assert.ok(after.last_used_at);
}));

test('listApiKeysForUser: scoped to the owning user only', () => withTempDb((store) => {
  const userA = store.createLocalUser('a@example.com', 'A', 'unused-hash');
  const userB = store.createLocalUser('b@example.com', 'B', 'unused-hash');
  store.createApiKey(userA, '1111'.repeat(16), 'key-a');
  store.createApiKey(userB, '2222'.repeat(16), 'key-b');

  const listA = store.listApiKeysForUser(userA);
  assert.equal(listA.length, 1);
  assert.equal(listA[0].label, 'key-a');
}));

test('createApiKey: key_hash is unique across users', () => withTempDb((store) => {
  const userA = store.createLocalUser('a@example.com', 'A', 'unused-hash');
  const userB = store.createLocalUser('b@example.com', 'B', 'unused-hash');
  store.createApiKey(userA, 'shared-hash-value', null);
  assert.throws(() => store.createApiKey(userB, 'shared-hash-value', null));
}));
