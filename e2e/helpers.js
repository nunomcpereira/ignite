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

/**
 * Minimal stand-in for a "local" provider LLM endpoint (ignite-llm-client's
 * `Provider::Local` — `GET /health` + `POST /v1/chat/completions`, OpenAI
 * chat-completions-shaped), so e2e tests can exercise the real HTTP round
 * trip for "Explain this issue", "Generate suggested fix", and the
 * `aiAutoJustify` auto-justification pass without a real LLM installed.
 *
 * Replies are chosen by sniffing the system prompt each of those three
 * server-side call sites sends (rust/crates/server/src/routes/issues.rs's
 * ISSUE_EXPLAIN_PROMPT/ISSUE_SUGGEST_FIX_PROMPT, rust/crates/server/src/
 * ai_justify.rs's SYSTEM_PROMPT) — each is textually distinct enough to
 * match on a short substring.
 */
function startFakeLocalLlm() {
  const http = require('http');
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      if (req.method === 'GET' && req.url === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
        return;
      }
      if (req.method === 'POST' && req.url === '/v1/chat/completions') {
        let raw = '';
        req.on('data', (chunk) => { raw += chunk; });
        req.on('end', () => {
          let body;
          try { body = JSON.parse(raw); } catch { body = {}; }
          const messages = Array.isArray(body.messages) ? body.messages : [];
          const system = (messages.find((m) => m.role === 'system') || {}).content || '';
          const user = (messages.find((m) => m.role === 'user') || {}).content || '';
          let content;
          if (system.includes('drafting override justifications')) {
            let ids = [];
            try { ids = JSON.parse(user).map((f) => f.id); } catch { ids = []; }
            content = JSON.stringify({
              justifications: ids.map((id) => ({
                id,
                justification: 'Fake-LLM (e2e): reviewed — a known, already-acknowledged commercial dependency for this internal tool; no source change needed.',
              })),
            });
          } else if (system.includes('proposing a concrete fix')) {
            content = 'EXPLANATION: Fake-LLM (e2e) test fix — proves the suggest-fix round trip works end to end.\nREPLACEMENT:\n// fake-llm-suggested-fix';
          } else {
            content = 'Fake-LLM (e2e) plain-language explanation for testing.';
          }
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ choices: [{ message: { content } }] }));
        });
        return;
      }
      res.writeHead(404);
      res.end();
    });
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}

module.exports = { makeFakeLicenseTools, startFakeLocalLlm };
