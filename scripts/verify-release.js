#!/usr/bin/env node
'use strict';

/**
 * Verifies a signed Ignite release (see scripts/sign-release.js's doc
 * comment for why this exists — the fallow.tools GH Action signed-binary
 * parity gap). Checks:
 *
 *  1. release-checksums.json.sig is a valid Ed25519 signature over
 *     release-checksums.json, under keys/ignite-release-public.pem.
 *  2. Every file listed in release-checksums.json currently on disk still
 *     hashes to the recorded sha256 (tamper/corruption detection).
 *
 * Exit code 0 = verified, 1 = verification failed. Intended for CI
 * (`node scripts/verify-release.js`) before `npm publish`, and for any
 * consumer who wants to confirm a downloaded tarball matches what was
 * actually signed.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const PUBLIC_KEY_PATH = path.join(ROOT, 'keys', 'ignite-release-public.pem');
const CHECKSUMS_PATH = path.join(ROOT, 'release-checksums.json');
const SIGNATURE_PATH = path.join(ROOT, 'release-checksums.json.sig');

function fail(msg) {
  // eslint-disable-next-line no-console
  console.error(`✗ ${msg}`);
  process.exitCode = 1;
}

function main() {
  for (const p of [PUBLIC_KEY_PATH, CHECKSUMS_PATH, SIGNATURE_PATH]) {
    if (!fs.existsSync(p)) {
      fail(`Missing ${path.relative(ROOT, p)} — run scripts/sign-release.js first.`);
      return;
    }
  }

  const publicKey = crypto.createPublicKey(fs.readFileSync(PUBLIC_KEY_PATH, 'utf8'));
  const manifestBytes = fs.readFileSync(CHECKSUMS_PATH);
  const signature = Buffer.from(fs.readFileSync(SIGNATURE_PATH, 'utf8').trim(), 'base64');

  const signatureValid = crypto.verify(null, manifestBytes, publicKey, signature);
  if (!signatureValid) {
    fail('Signature does not match release-checksums.json under keys/ignite-release-public.pem — the manifest was modified after signing, or signed with a different key.');
    return;
  }

  const checksums = JSON.parse(manifestBytes.toString('utf8'));
  let mismatches = 0;
  for (const [relPath, expected] of Object.entries(checksums.files)) {
    const full = path.join(ROOT, relPath);
    if (!fs.existsSync(full)) { fail(`${relPath} is listed in the signed manifest but missing on disk.`); mismatches++; continue; }
    const actual = crypto.createHash('sha256').update(fs.readFileSync(full)).digest('hex');
    if (actual !== expected) { fail(`${relPath} hash mismatch — expected ${expected}, got ${actual}.`); mismatches++; }
  }

  if (mismatches === 0) {
    // eslint-disable-next-line no-console
    console.log(`✓ Signature valid; ${Object.keys(checksums.files).length} file(s) match the signed manifest.`);
  }
}

if (require.main === module) main();

module.exports = {};
