'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');

/**
 * Writes fake `ort`/`licensee` CLI stand-ins to a throwaway PATH dir, so
 * ort-licensee-engines.spec.js can exercise the real tool-invocation and
 * parsing path in ignite-server's Rust license-compliance check without
 * either tool actually installed. Trimmed down from the Node suite's old
 * test/helpers.js (removed along with the rest of the Node server — see
 * README.md) to just the one helper this e2e suite still needs.
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

module.exports = { makeFakeLicenseTools };
