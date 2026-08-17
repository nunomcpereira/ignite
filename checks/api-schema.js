'use strict';

/**
 * Lints every discovered OpenAPI/AsyncAPI file against Spectral's ruleset.
 * Phase C of the server.js module split (see
 * /Users/nuno/.claude/plans/cuddly-roaming-pearl.md).
 *
 * @param {object} deps
 * @param {Function} deps.runTool - from lib/tool-runner.js's createToolRunner()
 * @param {object} deps.fsUtils - lib/fs-utils.js exports (walkFiles, looksBinary, buildSnippet, relativeToRoot)
 * @param {object} deps.config - { enabled, ruleset }
 */
function createApiSchemaCheck({ runTool, fsUtils, config }) {
  const fsp = require('fs/promises');
  const path = require('path');
  const os = require('os');
  const { walkFiles, looksBinary, buildSnippet, relativeToRoot } = fsUtils;

  const SPECTRAL_ENABLED = Boolean(config.enabled);
  const SPECTRAL_RULESET = String(config.ruleset || '');

  async function spectralTooling() {
    try {
      await runTool('spectral', ['--version'], os.tmpdir());
      return { ok: true };
    } catch {
      return { ok: false, reason: '`spectral` is not installed (npm install -g @stoplight/spectral-cli) — API schema lint findings are simply omitted.' };
    }
  }

  const API_SCHEMA_TOP_LEVEL_RE = /^\s*("?(openapi|swagger|asyncapi)"?\s*:)/m;

  // Spectral (unlike trivy/checkov/jscpd) has no directory-scan mode — it
  // only lints files explicitly passed on the command line — so this does
  // its own discovery: any .yaml/.yml/.json file whose top-level content
  // declares openapi/swagger/asyncapi. Cheap content sniff rather than a
  // filename convention, since these files are named all sorts of things
  // (openapi.yaml, api-spec.json, schema/users.yaml, ...).
  async function discoverApiSchemaFiles(root) {
    const files = [];
    for await (const file of walkFiles(root)) {
      const ext = path.extname(file).toLowerCase();
      if (!['.yaml', '.yml', '.json'].includes(ext)) continue;
      const buffer = await fsp.readFile(file).catch(() => null);
      if (!buffer || looksBinary(buffer)) continue;
      const content = buffer.toString('utf8');
      if (API_SCHEMA_TOP_LEVEL_RE.test(content)) files.push(path.relative(root, file));
    }
    return files;
  }

  const SPECTRAL_SEVERITY_TO_ISSUE = { 0: 'error', 1: 'warning', 2: 'warning', 3: 'warning' };

  // Lints every discovered OpenAPI/AsyncAPI file against Spectral's ruleset
  // (org REST/AsyncAPI conventions, not just schema validity). No built-in
  // fallback when disabled/missing — schema linting needs the real rule
  // engine, so this simply contributes nothing rather than pretending to.
  async function checkApiSchemas(root, log) {
    const tooling = SPECTRAL_ENABLED ? await spectralTooling() : { ok: false, reason: 'spectral is disabled (api.spectral.enabled=false).' };
    if (!tooling.ok) {
      log?.(`⚠ Spectral API schema lint skipped: ${tooling.reason}`);
      return { findings: [], engine: 'disabled' };
    }

    const relFiles = await discoverApiSchemaFiles(root);
    if (relFiles.length === 0) return { findings: [], engine: 'spectral' };

    log?.(`Engine: Spectral CLI (External) — linting ${relFiles.length} OpenAPI/AsyncAPI file(s)...`);
    try {
      const { stdout } = await runTool('spectral', [
        'lint', ...relFiles, '--ruleset', SPECTRAL_RULESET, '--format', 'json', '-q',
      ], root, { allowedExitCodes: [0, 1] });
      const results = stdout.trim() ? JSON.parse(stdout) : [];
      const findings = [];
      for (const r of results) {
        const relFile = await relativeToRoot(root, r.source);
        const line = (Number(r.range?.start?.line) || 0) + 1; // spectral lines are 0-indexed
        let content = null;
        try { content = await fsp.readFile(path.join(root, relFile), 'utf8'); } catch { /* best-effort */ }
        findings.push({
          file: relFile,
          line,
          kind: String(r.code || 'api-schema-lint').toLowerCase(),
          tool: 'spectral',
          severity: SPECTRAL_SEVERITY_TO_ISSUE[r.severity] || 'warning',
          message: r.message || 'API schema lint finding',
          code: content ? buildSnippet(content, line) : null,
        });
      }
      return { findings, engine: 'spectral' };
    } catch (e) {
      log?.(`⚠ Spectral API schema lint failed: ${e.message}`);
      return { findings: [], engine: 'disabled' };
    }
  }

  return { checkApiSchemas, spectralTooling, discoverApiSchemaFiles };
}

module.exports = { createApiSchemaCheck };
