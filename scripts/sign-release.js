#!/usr/bin/env node
'use strict';

/**
 * Signs a release of Ignite's own CLI/npm artifact — closes the "no signed-
 * binary verification for its own CLI/action" gap against fallow.tools'
 * GitHub Action, which verifies its own binary via Ed25519 signature +
 * SHA-256 digest before execution (see project memory). Ignite ships as an
 * npm package (`bin/ignite.js`), not a compiled binary, so the equivalent
 * supply-chain control is: hash every file npm would publish, sign that
 * manifest with an Ed25519 key, and verify both at install/CI time
 * (scripts/verify-release.js) before trusting `npx ignite` output.
 *
 * Usage:
 *   node scripts/sign-release.js [--key path/to/private-key.pem]
 *
 * Without --key, generates a fresh Ed25519 keypair on first run, writes the
 * PUBLIC half to keys/ignite-release-public.pem (commit this — it's what
 * verify-release.js and CI trust), and prints the PRIVATE half to stdout
 * ONCE (never written to disk) — store it in your release-signing secret
 * manager and pass it via --key on every subsequent run. Losing it means
 * generating a new keypair and re-distributing the new public key.
 *
 * Output: release-checksums.json (file path -> sha256) and
 * release-checksums.json.sig (base64 Ed25519 signature over the exact
 * bytes of release-checksums.json), both written to the repo root.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const PUBLIC_KEY_PATH = path.join(ROOT, 'keys', 'ignite-release-public.pem');
const CHECKSUMS_PATH = path.join(ROOT, 'release-checksums.json');
const SIGNATURE_PATH = path.join(ROOT, 'release-checksums.json.sig');

function listPublishedFiles() {
  // `npm pack --dry-run --json` is the ground truth for "what npm would
  // actually publish" (respects package.json's `files` field / .npmignore)
  // — signing that exact set, not an ad-hoc glob, is what makes this
  // verification meaningful.
  const out = execFileSync('npm', ['pack', '--dry-run', '--json'], { cwd: ROOT, encoding: 'utf8' });
  const [{ files }] = JSON.parse(out);
  return files.map((f) => f.path);
}

function sha256File(relPath) {
  const buf = fs.readFileSync(path.join(ROOT, relPath));
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function loadOrGenerateKeyPair(keyPathArg) {
  if (keyPathArg) {
    const privateKey = crypto.createPrivateKey(fs.readFileSync(keyPathArg, 'utf8'));
    const publicKey = crypto.createPublicKey(privateKey);
    return { privateKey, publicKey };
  }
  if (fs.existsSync(PUBLIC_KEY_PATH)) {
    throw new Error(`A public key already exists at ${path.relative(ROOT, PUBLIC_KEY_PATH)}. Pass --key <private-key.pem> (the matching private half) to sign with it — refusing to silently generate a new keypair that would invalidate it.`);
  }
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  fs.mkdirSync(path.dirname(PUBLIC_KEY_PATH), { recursive: true });
  fs.writeFileSync(PUBLIC_KEY_PATH, publicKey.export({ type: 'spki', format: 'pem' }));
  // eslint-disable-next-line no-console
  console.log(`Generated a new Ed25519 keypair. Public key written to ${path.relative(ROOT, PUBLIC_KEY_PATH)} — commit it.`);
  // eslint-disable-next-line no-console
  console.log('PRIVATE KEY (save this now — it is not written to disk, and this is the only time it is printed):\n');
  // eslint-disable-next-line no-console
  console.log(privateKey.export({ type: 'pkcs8', format: 'pem' }));
  return { privateKey, publicKey };
}

function main() {
  const keyArgIdx = process.argv.indexOf('--key');
  const keyPathArg = keyArgIdx >= 0 ? process.argv[keyArgIdx + 1] : null;
  const { privateKey } = loadOrGenerateKeyPair(keyPathArg);

  const files = listPublishedFiles();
  const checksums = { algorithm: 'sha256', generatedAt: new Date().toISOString(), files: {} };
  for (const f of files) checksums.files[f] = sha256File(f);

  const manifestBytes = Buffer.from(JSON.stringify(checksums, null, 2) + '\n', 'utf8');
  fs.writeFileSync(CHECKSUMS_PATH, manifestBytes);

  const signature = crypto.sign(null, manifestBytes, privateKey); // Ed25519: no digest algo param
  fs.writeFileSync(SIGNATURE_PATH, signature.toString('base64') + '\n');

  // eslint-disable-next-line no-console
  console.log(`Signed ${Object.keys(checksums.files).length} file(s) -> ${path.relative(ROOT, CHECKSUMS_PATH)} + ${path.relative(ROOT, SIGNATURE_PATH)}`);
}

if (require.main === module) main();

module.exports = { listPublishedFiles, sha256File };
