#!/usr/bin/env node
'use strict';

/**
 * Mints a headless API key for an existing Ignite user — the only way to
 * authenticate an agent/CLI caller for a real (non-dryRun) onboard, since
 * auth.js's session-cookie flow requires a browser OAuth/login redirect
 * that no unattended agent can complete.
 *
 * Usage: node scripts/create-api-key.js <email> [label]
 *
 * The user must already exist (sign up / log in once via the web UI, or
 * via OIDC/GitHub) — this script does not create accounts, only keys for
 * one. Prints the raw key exactly once; only its SHA-256 hash is stored,
 * so it can never be recovered or displayed again after this.
 */

const path = require('path');
const { createDbStore } = require('../db-store');
const { generateApiKey, hashApiKey } = require('../auth');

function main() {
  const [, , email, label] = process.argv;
  if (!email) {
    console.error('Usage: node scripts/create-api-key.js <email> [label]');
    process.exit(1);
  }

  const store = createDbStore(process.env.IGNITE_DB_PATH || path.join(__dirname, '..', 'ignite.db'));
  const user = store.getUserByEmail(email);
  if (!user) {
    console.error(`No Ignite user found for "${email}". Log in via the web UI at least once first.`);
    process.exit(1);
  }

  const rawKey = generateApiKey();
  const id = store.createApiKey(user.id, hashApiKey(rawKey), label || null);

  console.log(`API key #${id} created for ${email}${label ? ` (${label})` : ''}.`);
  console.log('');
  console.log(rawKey);
  console.log('');
  console.log('Store this now — it will not be shown again. Use it as:');
  console.log(`  Authorization: Bearer ${rawKey}`);
}

main();
