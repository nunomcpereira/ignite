'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');

const SERVER_PATH = require.resolve('../server.js');

/**
 * Re-requires server.js with a fresh module cache after applying env var
 * overrides, since CONFIG (and the gitleaks toggles derived from it) are
 * computed once at module load time. Pass `undefined` for a key to unset it.
 *
 * Also points the re-required server.js at its own throwaway sqlite file
 * (unless the caller already set IGNITE_DB_PATH) instead of the real
 * ignite.db — otherwise every test file that re-requires server.js opens a
 * fresh connection to the same on-disk dev database, which both corrupts
 * dev data and races other test files under node --test's default
 * parallelism ("database is locked").
 */
function withServerEnv(env, fn) {
  return async (...args) => {
    const prev = {};
    const setEnv = (k, v) => {
      prev[k] = process.env[k];
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    };
    for (const k of Object.keys(env)) setEnv(k, env[k]);

    let tmpDbDir = null;
    if (!('IGNITE_DB_PATH' in env)) {
      tmpDbDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ignite-test-db-'));
      setEnv('IGNITE_DB_PATH', path.join(tmpDbDir, 'test.db'));
    }

    delete require.cache[SERVER_PATH];
    try {
      const mod = require(SERVER_PATH);
      return await fn(mod, ...args);
    } finally {
      for (const k of Object.keys(prev)) {
        if (prev[k] === undefined) delete process.env[k];
        else process.env[k] = prev[k];
      }
      delete require.cache[SERVER_PATH];
      if (tmpDbDir) await fs.rm(tmpDbDir, { recursive: true, force: true }).catch(() => {});
    }
  };
}

async function makeTempProject(files) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ignite-test-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    await fs.mkdir(path.dirname(full), { recursive: true });
    await fs.writeFile(full, content);
  }
  return dir;
}

/**
 * Writes a small Node script that stands in for the real `gitleaks` CLI, so
 * tests can exercise the integration without requiring gitleaks to be
 * installed. Understands just enough of the real CLI surface: `version` and
 * `detect ... --report-path <path>`.
 */
async function makeFakeGitleaks(report) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ignite-fake-gitleaks-'));
  const scriptPath = path.join(dir, 'gitleaks');
  const script = `#!/usr/bin/env node
const fs = require('fs');
const args = process.argv.slice(2);
if (args[0] === 'version') {
  process.stdout.write('fake-gitleaks 1.0.0\\n');
  process.exit(0);
}
if (args[0] === 'detect') {
  const idx = args.indexOf('--report-path');
  const reportPath = args[idx + 1];
  fs.writeFileSync(reportPath, ${JSON.stringify(JSON.stringify(report))});
  process.exit(0);
}
process.exit(1);
`;
  await fs.writeFile(scriptPath, script, { mode: 0o755 });
  return scriptPath;
}

/**
 * Writes fake `ort` and `licensee` CLIs into a fresh directory, for
 * prepending to PATH — server.js resolves both via PATH, so tests (and the
 * e2e suite) can exercise the real integration code without either tool
 * installed.
 *
 * @param {object} opts
 * @param {Array}  [opts.ortPackages]  entries for analyzer-result.json's
 *   analyzer.result.packages; omit to make `ort` fail (soft-skip path).
 * @param {object} [opts.licenseeJson] JSON for `licensee detect --json`;
 *   omit to make `licensee` fail (soft-skip path).
 * @returns {Promise<string>} the bin directory to prepend to PATH
 */
async function makeFakeLicenseTools({ ortPackages, licenseeJson } = {}) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ignite-fake-license-tools-'));

  const failScript = '#!/usr/bin/env node\nprocess.exit(1);\n';

  if (ortPackages) {
    await fs.writeFile(path.join(dir, 'ort-result.json'),
      JSON.stringify({ analyzer: { result: { packages: ortPackages } } }));
  }
  const ortScript = ortPackages
    ? `#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const args = process.argv.slice(2);
if (args[0] === '--version') { process.stdout.write('fake-ort 1.0.0\\n'); process.exit(0); }
if (args[0] === 'analyze') {
  const outDir = args[args.indexOf('-o') + 1];
  fs.mkdirSync(outDir, { recursive: true });
  fs.copyFileSync(path.join(__dirname, 'ort-result.json'), path.join(outDir, 'analyzer-result.json'));
  process.exit(0);
}
process.exit(1);
`
    : failScript;
  await fs.writeFile(path.join(dir, 'ort'), ortScript, { mode: 0o755 });

  if (licenseeJson) {
    await fs.writeFile(path.join(dir, 'licensee-result.json'), JSON.stringify(licenseeJson));
  }
  const licenseeScript = licenseeJson
    ? `#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const args = process.argv.slice(2);
if (args[0] === 'version') { process.stdout.write('fake-licensee 9.18.0\\n'); process.exit(0); }
if (args[0] === 'detect') { process.stdout.write(fs.readFileSync(path.join(__dirname, 'licensee-result.json'), 'utf8')); process.exit(0); }
process.exit(1);
`
    : failScript;
  await fs.writeFile(path.join(dir, 'licensee'), licenseeScript, { mode: 0o755 });

  return dir;
}

module.exports = { withServerEnv, makeTempProject, makeFakeGitleaks, makeFakeLicenseTools };
