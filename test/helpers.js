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
    if (!('IGNITE_DB_PATH' in env) || !('IGNITE_CONFIG_PATH' in env) || !('DOTENV_PATH' in env)) {
      tmpDbDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ignite-test-db-'));
      if (!('IGNITE_DB_PATH' in env)) setEnv('IGNITE_DB_PATH', path.join(tmpDbDir, 'test.db'));
      // Without this, loadConfig() reads this developer's real, locally-
      // customized config.json — a test asserting on *default* values (e.g.
      // "gitleaks is disabled by default") would pass or fail depending on
      // what's actually configured on whoever's machine runs the suite.
      // An empty file here means every default in loadConfig() applies.
      if (!('IGNITE_CONFIG_PATH' in env)) {
        const emptyConfigPath = path.join(tmpDbDir, 'empty-config.json');
        await fs.writeFile(emptyConfigPath, '{}');
        setEnv('IGNITE_CONFIG_PATH', emptyConfigPath);
      }
      // Same reasoning, for the real .env — dotenv fills in any var that's
      // still unset, so a test that deletes e.g. GITLEAKS_ENABLED to assert
      // on the default would otherwise have it silently re-populated from
      // this developer's real .env on every require(). A nonexistent path
      // is a deliberate, documented dotenv no-op.
      if (!('DOTENV_PATH' in env)) {
        setEnv('DOTENV_PATH', path.join(tmpDbDir, 'nonexistent.env'));
      }
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

/**
 * Writes a small Node script that stands in for the real `trivy` CLI, so
 * tests can exercise the IaC-scan integration without requiring trivy to be
 * installed. Understands just enough of the real CLI surface: `--version`
 * and `config ... --output <path>`.
 */
async function makeFakeTrivy(results) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ignite-fake-trivy-'));
  const scriptPath = path.join(dir, 'trivy');
  const script = `#!/usr/bin/env node
const fs = require('fs');
const args = process.argv.slice(2);
if (args[0] === '--version') {
  process.stdout.write('Version: fake-trivy 1.0.0\\n');
  process.exit(0);
}
if (args[0] === 'config') {
  const idx = args.indexOf('--output');
  const outputPath = args[idx + 1];
  fs.writeFileSync(outputPath, ${JSON.stringify(JSON.stringify({ Results: results }))});
  process.exit(0);
}
process.exit(1);
`;
  await fs.writeFile(scriptPath, script, { mode: 0o755 });
  return scriptPath;
}

/**
 * Writes a small Node script that stands in for the real `checkov` CLI, so
 * tests can exercise the supplemental IaC-scan integration without
 * requiring checkov to be installed. Understands just enough of the real
 * CLI surface: `--version` and `-d ... --output json`. `report` is written
 * verbatim as the single-framework object shape ({check_type, results});
 * pass an array to exercise the multi-framework shape instead.
 */
async function makeFakeCheckov(report) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ignite-fake-checkov-'));
  const scriptPath = path.join(dir, 'checkov');
  const script = `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args[0] === '--version') {
  process.stdout.write('1.0.0\\n');
  process.exit(0);
}
if (args.includes('-d')) {
  process.stdout.write(${JSON.stringify(JSON.stringify(report))});
  process.exit(0);
}
process.exit(1);
`;
  await fs.writeFile(scriptPath, script, { mode: 0o755 });
  return scriptPath;
}

/**
 * Writes a small Node script that stands in for the real `hadolint` CLI, so
 * tests can exercise the supplemental Dockerfile-lint integration without
 * requiring hadolint to be installed. Understands just enough of the real
 * CLI surface: `--version` and `--format json <files...>`.
 */
async function makeFakeHadolint(results) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ignite-fake-hadolint-'));
  const scriptPath = path.join(dir, 'hadolint');
  const script = `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args[0] === '--version') {
  process.stdout.write('Haskell Dockerfile Linter 1.0.0\\n');
  process.exit(0);
}
if (args[0] === '--format') {
  process.stdout.write(${JSON.stringify(JSON.stringify(results))});
  process.exit(${results.length > 0 ? 1 : 0});
}
process.exit(1);
`;
  await fs.writeFile(scriptPath, script, { mode: 0o755 });
  return scriptPath;
}

/**
 * Writes a small Node script that stands in for the real `syft` CLI, so
 * tests can exercise the SBOM-generation integration without requiring
 * syft to be installed. Understands just enough of the real CLI surface:
 * `version` and `<path> -o cyclonedx-json=<file>`.
 */
async function makeFakeSyft(sbom) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ignite-fake-syft-'));
  const scriptPath = path.join(dir, 'syft');
  const script = `#!/usr/bin/env node
const fs = require('fs');
const args = process.argv.slice(2);
if (args[0] === 'version') {
  process.stdout.write('Application: syft\\nVersion: 1.0.0\\n');
  process.exit(0);
}
const outArg = args.find((a) => a.startsWith('cyclonedx-json='));
if (outArg) {
  fs.writeFileSync(outArg.slice('cyclonedx-json='.length), ${JSON.stringify(JSON.stringify(sbom))});
  process.exit(0);
}
process.exit(1);
`;
  await fs.writeFile(scriptPath, script, { mode: 0o755 });
  return scriptPath;
}

/**
 * Writes a small Node script that stands in for the real `cosign` CLI, so
 * tests can exercise the image-signature integration without requiring
 * cosign (or real network/registry access) to be installed. `verifiedImages`
 * is the set of image references that should verify successfully (exit 0);
 * every other `verify` invocation exits 1, matching cosign's real behavior
 * for an unsigned/unverifiable image.
 */
async function makeFakeCosign(verifiedImages) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ignite-fake-cosign-'));
  const scriptPath = path.join(dir, 'cosign');
  const script = `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args[0] === 'version') { process.stdout.write('fake-cosign 1.0.0\\n'); process.exit(0); }
if (args[0] === 'verify') {
  const image = args[args.length - 1];
  const verified = ${JSON.stringify(verifiedImages)};
  if (verified.includes(image)) { process.stdout.write('Verification for ' + image + ' --\\n'); process.exit(0); }
  process.stderr.write('Error: no signatures found\\n');
  process.exit(1);
}
process.exit(1);
`;
  await fs.writeFile(scriptPath, script, { mode: 0o755 });
  return scriptPath;
}

/**
 * Writes a small Node script that stands in for the real `semgrep` CLI, so
 * tests can exercise the semantic-SAST integration without requiring
 * semgrep (or registry/network access) to be installed. Understands just
 * enough of the real CLI surface: `--version` and `scan --json ...`.
 */
async function makeFakeSemgrep(results) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ignite-fake-semgrep-'));
  const scriptPath = path.join(dir, 'semgrep');
  const script = `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args[0] === '--version') { process.stdout.write('1.0.0\\n'); process.exit(0); }
if (args[0] === 'scan') {
  process.stdout.write(${JSON.stringify(JSON.stringify({ results, errors: [] }))});
  process.exit(0);
}
process.exit(1);
`;
  await fs.writeFile(scriptPath, script, { mode: 0o755 });
  return scriptPath;
}

/**
 * Writes a small Node script that stands in for the real `bearer` CLI, so
 * tests can exercise the PII/data-flow integration without requiring
 * bearer (or its git-context bookkeeping) to be installed. Understands
 * just enough of the real CLI surface: `version` and `scan ... --format json`.
 */
async function makeFakeBearer(bySeverity) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ignite-fake-bearer-'));
  const scriptPath = path.join(dir, 'bearer');
  const script = `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args[0] === 'version') { process.stdout.write('bearer version 1.0.0\\n'); process.exit(0); }
if (args[0] === 'scan') {
  process.stdout.write(${JSON.stringify(JSON.stringify(bySeverity))});
  process.exit(0);
}
process.exit(1);
`;
  await fs.writeFile(scriptPath, script, { mode: 0o755 });
  return scriptPath;
}

/**
 * Writes a small Node script that stands in for the real `jscpd` CLI, so
 * tests can exercise the duplication-scan integration without requiring
 * jscpd to be installed. Understands just enough of the real CLI surface:
 * `--version` and `<path> --reporters json --output <dir>`.
 */
async function makeFakeJscpd(report) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ignite-fake-jscpd-'));
  const scriptPath = path.join(dir, 'jscpd');
  const script = `#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const args = process.argv.slice(2);
if (args[0] === '--version') { process.stdout.write('cpd 1.0.0\\n'); process.exit(0); }
const idx = args.indexOf('--output');
if (idx !== -1) {
  const outDir = args[idx + 1];
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, 'jscpd-report.json'), ${JSON.stringify(JSON.stringify(report))});
  // Written next to this script (not outDir, which checkCodeDuplication
  // deletes in its finally block) so tests can inspect exactly what CLI
  // args it was invoked with after the call returns.
  fs.writeFileSync(path.join(__dirname, 'jscpd-invocation-args.json'), JSON.stringify(args));
  process.exit(0);
}
process.exit(1);
`;
  await fs.writeFile(scriptPath, script, { mode: 0o755 });
  return scriptPath;
}

/**
 * Writes a small Node script that stands in for the real `gocloc` CLI, so
 * tests can exercise the LOC-metrics integration without requiring gocloc
 * to be installed. Understands just enough of the real CLI surface:
 * `--version` and `--output-type json <path>`.
 */
async function makeFakeGocloc(metrics) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ignite-fake-gocloc-'));
  const scriptPath = path.join(dir, 'gocloc');
  const script = `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args[0] === '--version') { process.stdout.write('gocloc 1.0.0\\n'); process.exit(0); }
if (args.includes('--output-type')) {
  process.stdout.write(${JSON.stringify(JSON.stringify(metrics))});
  process.exit(0);
}
process.exit(1);
`;
  await fs.writeFile(scriptPath, script, { mode: 0o755 });
  return scriptPath;
}

/**
 * Writes a small Node script that stands in for the real `spectral` CLI, so
 * tests can exercise the API-schema-lint integration without requiring
 * spectral to be installed. Understands just enough of the real CLI
 * surface: `--version` and `lint ... --format json`.
 */
async function makeFakeSpectral(results) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ignite-fake-spectral-'));
  const scriptPath = path.join(dir, 'spectral');
  const script = `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args[0] === '--version') { process.stdout.write('1.0.0\\n'); process.exit(0); }
if (args[0] === 'lint') {
  process.stdout.write(${JSON.stringify(JSON.stringify(results))});
  process.exit(${results.length > 0 ? 1 : 0});
}
process.exit(1);
`;
  await fs.writeFile(scriptPath, script, { mode: 0o755 });
  return scriptPath;
}

module.exports = {
  withServerEnv, makeTempProject, makeFakeGitleaks, makeFakeLicenseTools, makeFakeTrivy, makeFakeCheckov, makeFakeHadolint, makeFakeSyft, makeFakeCosign, makeFakeSemgrep, makeFakeBearer, makeFakeJscpd, makeFakeGocloc, makeFakeSpectral,
};
