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
 *
 * Nothing here proves the operator running this script owns <email> — it
 * only proves the account exists. That's a real impersonation vector for
 * anyone with shell access to run it, so every mint is (a) attributed to
 * the operator (api_keys.created_by/created_via) and (b) emailed to the
 * account owner, so a misuse is attributable and gets noticed.
 */

const os = require('os');
const path = require('path');
const { createDbStore } = require('../db-store');
const { generateApiKey, hashApiKey } = require('../auth');
const { loadConfig } = require('../config');
const { createNotifications } = require('../lib/notifications');

function currentOperator() {
  return process.env.IGNITE_OPERATOR || `${os.userInfo().username}@${os.hostname()}`;
}

async function main() {
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

  const operator = currentOperator();
  const rawKey = generateApiKey();
  const id = store.createApiKey(user.id, hashApiKey(rawKey), label || null, operator, 'cli');

  console.log(`API key #${id} created for ${email}${label ? ` (${label})` : ''}.`);
  console.log(`Recorded created_by=${operator} in the audit log.`);
  console.log('');
  console.log(rawKey);
  console.log('');
  console.log('Store this now — it will not be shown again. Use it as:');
  console.log(`  Authorization: Bearer ${rawKey}`);

  // Best-effort: notify the account owner so an impersonation-by-key-creation
  // attempt doesn't go unnoticed. Never blocks key creation on SMTP failure.
  try {
    const config = loadConfig();
    const { sendApiKeyCreatedNotification } = createNotifications({ config: config.notifications, phaseTitles: {} });
    const result = await sendApiKeyCreatedNotification({
      ownerEmail: user.email,
      ownerName: user.name,
      label: label || null,
      createdBy: operator,
      createdVia: 'cli',
    });
    if (result.sent) {
      console.log(`Notified ${result.to} that this key was created.`);
    } else {
      console.log(`Owner notification not sent (${result.reason}).`);
    }
  } catch (err) {
    console.error(`Failed to send owner notification email: ${err.message}`);
  }
}

main();
