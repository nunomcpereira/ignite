'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');

const SERVER_PATH = require.resolve('../server.js');

/**
 * Re-requires server.js with a fresh module cache after applying env var
 * overrides, since CONFIG (and the gitleaks toggles derived from it) are
 * computed once at module load time. Pass `undefined` for a key to unset it.
 */
function withServerEnv(env, fn) {
  return async (...args) => {
    const prev = {};
    for (const k of Object.keys(env)) {
      prev[k] = process.env[k];
      if (env[k] === undefined) delete process.env[k];
      else process.env[k] = env[k];
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

module.exports = { withServerEnv, makeTempProject, makeFakeGitleaks };
