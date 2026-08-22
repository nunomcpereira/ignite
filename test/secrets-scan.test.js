'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const { execFile } = require('node:child_process');

const { withServerEnv, makeTempProject, makeFakeGitleaks } = require('./helpers');

const noopLog = () => {};

function hasRealGitleaks() {
  return new Promise((resolve) => {
    execFile('gitleaks', ['version'], (err) => resolve(!err));
  });
}

test('checkSecrets: regex scan still finds hardcoded credentials (baseline, gitleaks untouched)', withServerEnv({}, async (mod) => {
  const dir = await makeTempProject({
    'config.js': `module.exports = { apiKey: "api_key\x3a 'not_a_real_secret_1234567890abcdef'" };\n`,
  });
  const { findings, scanned } = await mod.checkSecrets(dir, noopLog);
  assert.ok(scanned >= 1);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].kind, 'api_key');
  assert.equal(findings[0].tool, undefined, 'regex findings are not tagged with a tool');
}));

test('checkSecrets: files excluded by the project\'s own .gitignore are not scanned', withServerEnv({}, async (mod) => {
  const dir = await makeTempProject({
    '.gitignore': '.env\n',
    '.env': "OPENAI_API_KEY\x3dsk-proj-1234567890abcdef1234567890abcdef\n",
    'config.js': `module.exports = { apiKey: "api_key\x3a 'sk_live_1234567890abcdef'" };\n`,
  });
  const { findings } = await mod.checkSecrets(dir, noopLog);
  assert.equal(findings.length, 1, 'only the tracked file is flagged; the gitignored .env is skipped');
  assert.equal(findings[0].file, 'config.js');
}));

test('checkSecrets: generated review artifacts and bundled skill docs are ignored to prevent recursive false positives', withServerEnv({}, async (mod) => {
  const dir = await makeTempProject({
    '.ignite-review.md': '# Code: api_key = request.headers.get(\'X-API-Key\')\n',
    '.github/skills/gh-cli/SKILL.md': 'export GH_TOKEN=ghp_xxxxxxxxxxxx\n',
    'config.js': 'module.exports = { token: "tok_1234567890abcdef" };\n',
  });
  const { findings } = await mod.checkSecrets(dir, noopLog);
  assert.equal(findings.length, 1, 'only the real project source finding should remain');
  assert.equal(findings[0].file, 'config.js');
}));

test('checkSecrets: env-var references (process.env.X, os.environ, getenv) are not flagged as hardcoded', withServerEnv({}, async (mod) => {
  const dir = await makeTempProject({
    'llmService.js': [
      "const OPENAI_API_KEY \x3d process.env.OPENAI_API_KEY || '';",
      "const other = process.env.OTHER_TOKEN;",
    ].join('\n') + '\n',
    'app.py': [
      "import os",
      "api_key \x3d os.environ.get('API_KEY')",
      "token \x3d os.getenv('TOKEN_VALUE')",
    ].join('\n') + '\n',
  });
  const { findings } = await mod.checkSecrets(dir, noopLog);
  assert.deepEqual(findings, [], 'env-var references must not be treated as hardcoded secrets');
}));

test('checkSecrets: unquoted variable/property references in source code are not hardcoded secrets', withServerEnv({}, async (mod) => {
  const dir = await makeTempProject({
    'cpiApi.js': [
      "const res = await axios.post(tokenUrl, 'grant_type=client_credentials', {",
      "  auth: { username: clientId, password\x3a clientSecret }",
      "});",
      "const token \x3d res.data.access_token;",
    ].join('\n') + '\n',
  });
  const { findings } = await mod.checkSecrets(dir, noopLog);
  assert.deepEqual(findings, [], 'unquoted identifiers/property access in JS are syntax, never literals');
}));

test('checkSecrets: unquoted literals in config/env-style files are still flagged', withServerEnv({}, async (mod) => {
  const dir = await makeTempProject({
    'settings.yaml': 'api_key\x3a sk_live_1234567890abcdef\n',
  });
  const { findings } = await mod.checkSecrets(dir, noopLog);
  assert.equal(findings.length, 1, 'config formats have no quoting rule, so unquoted long values can still be real secrets');
}));

test('checkSecrets: unquoted dotted identifier chains in config-like files are treated as references, not literals', withServerEnv({}, async (mod) => {
  const dir = await makeTempProject({
    'scripts/dev.sh': 'FIREBASE_APPCHECK_DEBUG_TOKEN=environment.fb.appCheck\n',
  });
  const { findings } = await mod.checkSecrets(dir, noopLog);
  assert.deepEqual(findings, [], 'dotted identifier chains are code/config references rather than inline secret values');
}));

test('checkSecrets: gitleaks disabled by default — old regex-only behavior, even if a gitleaks binary is configured', withServerEnv(
  { GITLEAKS_ENABLED: undefined, GITLEAKS_BINARY: '/nonexistent/should-never-run' },
  async (mod) => {
    const dir = await makeTempProject({ 'clean.js': 'module.exports = {};\n' });
    const { findings } = await mod.checkSecrets(dir, noopLog);
    assert.deepEqual(findings, [], 'disabled gitleaks must never be invoked, so a broken binary path is harmless');
  }
));

test('checkSecrets: gitleaks enabled — supplements the regex scan with findings the regex misses', async () => {
  const dir = await makeTempProject({
    // Bare token with no "password|token|api_key|..." keyword prefix — the
    // built-in SECRET_REGEX requires that keyword, so it will miss this.
    'creds.txt': 'ghp_1234567890abcdef1234567890abcdef1234\n',
  });
  const fakeGitleaks = await makeFakeGitleaks([
    { File: 'creds.txt', StartLine: 1, RuleID: 'github-pat' },
  ]);

  await withServerEnv({ GITLEAKS_ENABLED: 'true', GITLEAKS_BINARY: fakeGitleaks }, async (mod) => {
    const { findings } = await mod.checkSecrets(dir, noopLog);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].file, 'creds.txt');
    assert.equal(findings[0].line, 1);
    assert.equal(findings[0].kind, 'github-pat');
    assert.equal(findings[0].tool, 'gitleaks');
  })();
});

test('checkSecrets: gitleaks findings are deduped against regex findings at the same file/line', async () => {
  const dir = await makeTempProject({
    'secret.py': `token\x3a "abcdefghij1234567890"\n`,
  });
  const fakeGitleaks = await makeFakeGitleaks([
    { File: 'secret.py', StartLine: 1, RuleID: 'generic-api-key' },
  ]);

  await withServerEnv({ GITLEAKS_ENABLED: 'true', GITLEAKS_BINARY: fakeGitleaks }, async (mod) => {
    const { findings } = await mod.checkSecrets(dir, noopLog);
    // Regex already flagged secret.py:1 — gitleaks's finding at the same
    // location must not produce a second entry.
    assert.equal(findings.length, 1);
    assert.equal(findings[0].file, 'secret.py');
    assert.equal(findings[0].line, 1);
  })();
});

test('checkSecrets: gitleaks enabled but binary missing — soft-fails back to regex-only results', async () => {
  const dir = await makeTempProject({
    'config.js': `password\x3a "supersecretvalue123"\n`,
  });
  const logs = [];

  await withServerEnv({ GITLEAKS_ENABLED: 'true', GITLEAKS_BINARY: '/nonexistent/gitleaks-binary-xyz' }, async (mod) => {
    const { findings } = await mod.checkSecrets(dir, (line) => logs.push(line));
    assert.equal(findings.length, 1, 'regex finding still comes through');
    assert.equal(findings[0].kind, 'password');
    assert.ok(logs.some((l) => l.includes('gitleaks')), 'failure is logged, not thrown');
  })();
});

test('checkSecrets: gitleaks enabled and finds nothing beyond an empty report — clean project stays clean', async () => {
  const dir = await makeTempProject({ 'clean.js': 'module.exports = {};\n' });
  const fakeGitleaks = await makeFakeGitleaks([]);

  await withServerEnv({ GITLEAKS_ENABLED: 'true', GITLEAKS_BINARY: fakeGitleaks }, async (mod) => {
    const { findings } = await mod.checkSecrets(dir, noopLog);
    assert.deepEqual(findings, []);
  })();
});

test('loadConfig: GITLEAKS_* env vars are wired into CONFIG.security.gitleaks', withServerEnv(
  { GITLEAKS_ENABLED: 'true', GITLEAKS_BINARY: '/opt/bin/gitleaks', GITLEAKS_CONFIG_PATH: '/etc/gitleaks.toml' },
  async (mod) => {
    const cfg = mod.loadConfig();
    assert.equal(cfg.security.gitleaks.enabled, true);
    assert.equal(cfg.security.gitleaks.binary, '/opt/bin/gitleaks');
    assert.equal(cfg.security.gitleaks.configPath, '/etc/gitleaks.toml');
  }
));

test('loadConfig: gitleaks is disabled by default with no env vars set', withServerEnv(
  { GITLEAKS_ENABLED: undefined, GITLEAKS_BINARY: undefined, GITLEAKS_CONFIG_PATH: undefined },
  async (mod) => {
    const cfg = mod.loadConfig();
    assert.equal(cfg.security.gitleaks.enabled, false);
    assert.equal(cfg.security.gitleaks.binary, 'gitleaks');
  }
));

test('runGitleaksScan: passes --config through when a gitleaks config path is set', async () => {
  const dir = await makeTempProject({ 'a.txt': 'nothing interesting\n' });
  const capturePath = `${dir}/captured-args.json`;
  const fakeGitleaksDir = await fs.mkdtemp(`${require('node:os').tmpdir()}/ignite-fake-gitleaks-args-`);
  const scriptPath = `${fakeGitleaksDir}/gitleaks`;
  await fs.writeFile(
    scriptPath,
    `#!/usr/bin/env node
const fs = require('fs');
const args = process.argv.slice(2);
if (args[0] === 'detect') {
  fs.writeFileSync(${JSON.stringify(capturePath)}, JSON.stringify(args));
  const idx = args.indexOf('--report-path');
  fs.writeFileSync(args[idx + 1], '[]');
}
process.exit(0);
`,
    { mode: 0o755 }
  );

  await withServerEnv(
    { GITLEAKS_ENABLED: 'true', GITLEAKS_BINARY: scriptPath, GITLEAKS_CONFIG_PATH: '/etc/custom-gitleaks.toml' },
    async (mod) => {
      await mod.checkSecrets(dir, noopLog);
      const capturedArgs = JSON.parse(await fs.readFile(capturePath, 'utf8'));
      const idx = capturedArgs.indexOf('--config');
      assert.notEqual(idx, -1, '--config flag should be forwarded to gitleaks');
      assert.equal(capturedArgs[idx + 1], '/etc/custom-gitleaks.toml');
    }
  )();
});

test('checkSecrets: real gitleaks binary end-to-end (skipped if gitleaks is not installed)', async (t) => {
  if (!(await hasRealGitleaks())) {
    t.skip('gitleaks not installed on PATH — install with `brew install gitleaks` to run this test');
    return;
  }

  const dir = await makeTempProject({
    // No "password|token|api_key|..." keyword prefix, so the built-in
    // SECRET_REGEX won't catch it — only gitleaks' github-pat rule will.
    'creds.txt': 'ghp_1234567890abcdef1234567890abcdef1234\n',
    // Caught by both: proves dedup also holds against the real binary,
    // not just the fake one used elsewhere in this file.
    'config.js': `module.exports = { apiKey: "api_key\x3a 'sk_live_1234567890abcdef'" };\n`,
  });

  await withServerEnv({ GITLEAKS_ENABLED: 'true', GITLEAKS_BINARY: 'gitleaks' }, async (mod) => {
    const { findings } = await mod.checkSecrets(dir, noopLog);

    const byFile = Object.fromEntries(findings.map((f) => [f.file, f]));
    assert.equal(findings.length, 2, 'one regex hit + one gitleaks-only hit, deduped on the shared line');
    assert.equal(byFile['config.js'].tool, undefined, 'regex already had this one — no duplicate gitleaks entry');
    assert.equal(byFile['creds.txt'].tool, 'gitleaks', 'only gitleaks catches the keyword-less PAT');
    assert.equal(byFile['creds.txt'].kind, 'github-pat');
  })();
});
