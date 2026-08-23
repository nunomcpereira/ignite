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

/**
 * Writes a small Node script that stands in for the real `guarddog` CLI, so
 * tests can exercise the malicious-dependency integration without requiring
 * guarddog (or real PyPI/npm registry access) to be installed. Understands
 * `--version` and `<ecosystem> verify <file> --output-format json`.
 * `reportByEcosystem` maps 'npm'/'pypi' to the JSON object guarddog would
 * print for that invocation (keyed by "name==version" per its real output).
 */
async function makeFakeGuardDog(reportByEcosystem) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ignite-fake-guarddog-'));
  const scriptPath = path.join(dir, 'guarddog');
  const script = `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args[0] === '--version') { process.stdout.write('fake-guarddog 1.0.0\\n'); process.exit(0); }
const reports = ${JSON.stringify(reportByEcosystem)};
const ecosystem = args[0];
if (args[1] === 'verify') {
  const report = reports[ecosystem] || {};
  process.stdout.write(JSON.stringify(report));
  const hasIssues = Object.values(report).some((e) => (e.issues || 0) > 0 || Object.values(e.results || {}).some(Boolean));
  process.exit(hasIssues ? 1 : 0);
}
process.exit(1);
`;
  await fs.writeFile(scriptPath, script, { mode: 0o755 });
  return scriptPath;
}

/**
 * Writes fake `docker` and `trivy` CLIs into a fresh directory, for
 * prepending to PATH — checkContainerImageVulnerabilities shells out to the
 * literal `docker` command name (not a configurable binary setting, unlike
 * trivy/checkov/etc), so faking it needs a PATH-based stand-in the same way
 * makeFakeLicenseTools fakes `ort`/`licensee`. The fake `docker` understands
 * `info` (tooling probe), `build` (always succeeds, ignores -f/-t/context),
 * and `rmi` (cleanup); the fake `trivy` understands `--version` and
 * `image --output <path>`, writing `vulnerabilities` as that image's
 * Vulnerabilities list regardless of which tag was scanned.
 *
 * @param {Array} vulnerabilities - trivy `image` JSON Vulnerabilities entries
 * @returns {Promise<string>} the bin directory to prepend to PATH
 */
async function makeFakeDockerAndTrivyImage(vulnerabilities) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ignite-fake-docker-trivy-'));

  const dockerScript = `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args[0] === 'info') { process.stdout.write('fake-docker 1.0.0\\n'); process.exit(0); }
if (args[0] === 'build') { process.exit(0); }
if (args[0] === 'rmi') { process.exit(0); }
process.exit(1);
`;
  await fs.writeFile(path.join(dir, 'docker'), dockerScript, { mode: 0o755 });

  const trivyScript = `#!/usr/bin/env node
const fs = require('fs');
const args = process.argv.slice(2);
if (args[0] === '--version') { process.stdout.write('Version: fake-trivy 1.0.0\\n'); process.exit(0); }
if (args[0] === 'image') {
  const idx = args.indexOf('--output');
  const outputPath = args[idx + 1];
  fs.writeFileSync(outputPath, ${JSON.stringify(JSON.stringify({ Results: [{ Vulnerabilities: vulnerabilities }] }))});
  process.exit(0);
}
process.exit(1);
`;
  await fs.writeFile(path.join(dir, 'trivy'), trivyScript, { mode: 0o755 });

  return dir;
}

/**
 * Writes a small Node script that stands in for the real `codeql` CLI, so
 * tests can exercise the cross-file scan integration without requiring the
 * CodeQL CLI (or a real, minutes-long database build) to be installed.
 * Understands just enough of the real CLI surface: `version --format=json`,
 * `database create <dbPath> ...`, `database analyze <dbPath> <suite>
 * --format=sarif-latest --output=<path>`.
 *
 * `analyze` has no --language flag of its own (language is implicit in the
 * database), so this fake recovers it the same way a real deep-scan run's
 * per-language work directories are actually named by
 * checks/codeql-cross-file.js (`ignite-codeql-<language>-XXXXXX/db`) —
 * reading it back out of dbPath's parent directory name.
 *
 * Every `database create`/`database analyze` invocation is appended to
 * `<returned>.callLogPath` (one word per line) so a test can assert on the
 * cache short-circuit (a cache hit should mean zero further CLI calls for
 * that language on a second run).
 *
 * @param {object} sarifByLanguage - e.g. { javascript: { runs: [...] } }
 * @returns {Promise<{binary: string, callLogPath: string}>}
 */
async function makeFakeCodeQL(sarifByLanguage) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ignite-fake-codeql-'));
  const scriptPath = path.join(dir, 'codeql');
  const callLogPath = path.join(dir, 'calls.log');
  const script = `#!/usr/bin/env node
const fsn = require('fs');
const pathn = require('path');
const args = process.argv.slice(2);
const callLog = ${JSON.stringify(callLogPath)};
if (args[0] === 'version') {
  fsn.writeFileSync(callLog, 'version\\n', { flag: 'a' });
  process.stdout.write(JSON.stringify({ version: '2.99.0' }) + '\\n');
  process.exit(0);
}
if (args[0] === 'database' && args[1] === 'create') {
  fsn.writeFileSync(callLog, 'create\\n', { flag: 'a' });
  fsn.mkdirSync(args[2], { recursive: true });
  process.exit(0);
}
if (args[0] === 'database' && args[1] === 'analyze') {
  fsn.writeFileSync(callLog, 'analyze\\n', { flag: 'a' });
  const dbPath = args[2];
  const outFlag = args.find((a) => a.startsWith('--output='));
  const outPath = outFlag.slice('--output='.length);
  const m = pathn.basename(pathn.dirname(dbPath)).match(/^ignite-codeql-([a-z]+)-/);
  const lang = m ? m[1] : null;
  const sarifByLanguage = ${JSON.stringify(sarifByLanguage)};
  const sarif = (lang && sarifByLanguage[lang]) || { runs: [{ tool: { driver: { rules: [] } }, results: [] }] };
  fsn.writeFileSync(outPath, JSON.stringify(sarif));
  process.exit(0);
}
process.exit(1);
`;
  await fs.writeFile(scriptPath, script, { mode: 0o755 });
  return { binary: scriptPath, callLogPath };
}

/**
 * Writes a small Node script that stands in for the real `picklescan` CLI,
 * so tests can exercise the model-artifact-security integration without
 * requiring picklescan (or real model weight files) to be installed.
 * Understands `--help` (tooling probe) and `--path <dir>` (scan), replaying
 * the given plain-text finding-line templates (mirroring picklescan's real
 * "<path>[:<member>]: global import '<name>' FOUND" line format). Each
 * template's literal string `{root}` is substituted at run time with the
 * actual directory picklescan was invoked against (the `--path` argument),
 * since the check module resolves each finding's file back to a real
 * filesystem path via relativeToRoot.
 *
 * @param {string[]} findingLineTemplates - e.g. ["{root}/model.pkl: global import '__builtin__ eval' FOUND"] (empty array = clean scan)
 */
async function makeFakePicklescan(findingLineTemplates) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ignite-fake-picklescan-'));
  const scriptPath = path.join(dir, 'picklescan');
  const script = `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args[0] === '--help') { process.stdout.write('usage: picklescan\\n'); process.exit(0); }
if (args[0] === '--path') {
  const root = args[1];
  const templates = ${JSON.stringify(findingLineTemplates)};
  const lines = templates.map((t) => t.split('{root}').join(root));
  for (const line of lines) process.stdout.write(line + '\\n');
  process.stdout.write('----------- SCAN SUMMARY -----------\\n');
  process.exit(lines.length > 0 ? 1 : 0);
}
process.exit(2);
`;
  await fs.writeFile(scriptPath, script, { mode: 0o755 });
  return scriptPath;
}

/**
 * Writes a small Node script that stands in for the real `oasdiff` CLI, so
 * tests can exercise the API-breaking-change integration without requiring
 * oasdiff to be installed. Understands `--version` (tooling probe) and
 * `breaking <base> <revision> --format json` (scan), replaying the given
 * canned array of change objects (empty array = no breaking changes,
 * matching oasdiff's own exit-code convention: 0 clean, 1 breaking changes
 * found).
 *
 * @param {Array} changes - change objects (id/text/level/operation/path)
 */
async function makeFakeOasdiff(changes) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ignite-fake-oasdiff-'));
  const scriptPath = path.join(dir, 'oasdiff');
  const script = `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args[0] === '--version') { process.stdout.write('oasdiff version 1.0.0\\n'); process.exit(0); }
if (args[0] === 'breaking') {
  const changes = ${JSON.stringify(changes)};
  process.stdout.write(JSON.stringify(changes));
  process.exit(changes.length > 0 ? 1 : 0);
}
process.exit(2);
`;
  await fs.writeFile(scriptPath, script, { mode: 0o755 });
  return scriptPath;
}

module.exports = {
  withServerEnv, makeTempProject, makeFakeGitleaks, makeFakeLicenseTools, makeFakeTrivy, makeFakeCheckov, makeFakeHadolint, makeFakeSyft, makeFakeCosign, makeFakeSemgrep, makeFakeBearer, makeFakeJscpd, makeFakeGocloc, makeFakeSpectral, makeFakeGuardDog, makeFakeDockerAndTrivyImage, makeFakeCodeQL, makeFakePicklescan, makeFakeOasdiff,
};
