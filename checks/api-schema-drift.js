'use strict';

/**
 * API breaking-change / shadow-endpoint detection via oasdiff
 * (https://github.com/oasdiff/oasdiff). checks/api-schema.js (Spectral)
 * lints a spec in isolation — this instead diffs each OpenAPI/AsyncAPI
 * file discovered against its own previous git revision, catching what
 * lint alone can't: an endpoint an AI coding agent silently removed,
 * renamed, or made backwards-incompatible (a field that became required,
 * a removed response field, a changed type) versus what shipped last.
 *
 * Needs real git history to diff against — same constraint
 * checks/pii-dataflow.js's Bearer --diff mode has, and solved the same
 * way: a fresh ZIP/folder upload with no prior commit has nothing to
 * diff, so this soft-skips with zero findings rather than fabricating a
 * "before" state. Only meaningfully active for an already-onboarded repo
 * being re-scanned (a real push), which is exactly when "did this change
 * break existing clients" is the useful question to ask.
 *
 * @param {object} deps
 * @param {Function} deps.runTool - from lib/tool-runner.js's createToolRunner()
 * @param {object} deps.discoverApiSchemaFiles - checks/api-schema.js's
 *   discoverApiSchemaFiles(root) — reused so both checks agree on what
 *   counts as an OpenAPI/AsyncAPI file, rather than re-implementing the
 *   content-sniff independently.
 * @param {object} deps.config - { enabled }
 */
function createApiSchemaDriftCheck({ runTool, discoverApiSchemaFiles, config }) {
  const fsp = require('fs/promises');
  const path = require('path');
  const os = require('os');

  const OASDIFF_ENABLED = Boolean(config.enabled);

  async function oasdiffTooling() {
    try {
      const { stdout } = await runTool('oasdiff', ['--version'], os.tmpdir());
      return { ok: true, version: stdout.trim() || null };
    } catch {
      return { ok: false, reason: '`oasdiff` is not installed (brew install oasdiff, or see https://github.com/oasdiff/oasdiff) — API breaking-change detection is skipped.' };
    }
  }

  // Mirrors checks/pii-dataflow.js's resolveBearerDiffBase: only diff
  // against a real ancestor commit, on a clean working tree. A dirty tree
  // or a single-commit repo (the ensureGitContextForBearer-bootstrapped
  // state for a fresh upload) has no genuine "before" to diff against.
  async function resolveGitDiffBase(root) {
    try {
      const { stdout: statusOut } = await runTool('git', ['status', '--porcelain'], root);
      if (statusOut.trim()) return null;

      const { stdout: headOut } = await runTool('git', ['rev-parse', 'HEAD'], root);
      const head = headOut.trim();
      if (!head) return null;

      const { stdout: parentOut } = await runTool('git', ['rev-parse', '--verify', '--quiet', 'HEAD~1'], root).catch(() => ({ stdout: '' }));
      const parent = parentOut.trim();
      if (!parent || parent === head) return null;

      return parent;
    } catch {
      return null;
    }
  }

  // ERR-level findings genuinely break existing clients — the same bar
  // GuardDog/CodeQL use to earn a hard block. WARN-level ("potential
  // breaking change, can't be confirmed programmatically") stays advisory.
  function severityForLevel(level) {
    const s = String(level ?? '').toUpperCase();
    if (s === 'ERR' || s === 'ERROR' || Number(level) >= 2) return 'error';
    return 'warning';
  }

  // oasdiff's `breaking --format json` output is an array of change
  // objects (id/text/level/operation/path at minimum — exact field set has
  // shifted across versions, so this reads tolerantly rather than assuming
  // one fixed schema).
  function parseOasdiffChanges(stdout) {
    if (!stdout.trim()) return [];
    let parsed;
    try {
      parsed = JSON.parse(stdout);
    } catch {
      return [];
    }
    if (Array.isArray(parsed)) return parsed;
    if (Array.isArray(parsed?.changes)) return parsed.changes;
    if (Array.isArray(parsed?.breakingChanges)) return parsed.breakingChanges;
    return [];
  }

  async function checkApiSchemaDrift(root, log) {
    const tooling = OASDIFF_ENABLED ? await oasdiffTooling() : { ok: false, reason: 'oasdiff is disabled (api.oasdiff.enabled=false).' };
    if (!tooling.ok) {
      log?.(`⚠ oasdiff API breaking-change scan skipped: ${tooling.reason}`);
      return { findings: [], engine: 'disabled' };
    }

    const relFiles = await discoverApiSchemaFiles(root);
    if (relFiles.length === 0) return { findings: [], engine: 'oasdiff' };

    const diffBase = await resolveGitDiffBase(root);
    if (!diffBase) {
      log?.('✓ oasdiff API breaking-change scan skipped — no prior git revision to diff against (nothing shipped yet, or a dirty working tree).');
      return { findings: [], engine: 'oasdiff' };
    }

    log?.(`Engine: oasdiff CLI (External) — diffing ${relFiles.length} OpenAPI/AsyncAPI file(s) against ${diffBase}...`);
    const findings = [];
    const tmpDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'ignite-oasdiff-'));
    try {
      for (const relFile of relFiles) {
        let baseContent;
        try {
          const { stdout } = await runTool('git', ['show', `${diffBase}:${relFile}`], root);
          baseContent = stdout;
        } catch {
          continue; // file didn't exist at diffBase — a new spec, nothing to diff yet
        }
        const baseFilePath = path.join(tmpDir, `base-${path.basename(relFile)}`);
        await fsp.writeFile(baseFilePath, baseContent);

        try {
          const { stdout } = await runTool(
            'oasdiff',
            ['breaking', baseFilePath, path.join(root, relFile), '--format', 'json'],
            root,
            { allowedExitCodes: [0, 1] }
          );
          for (const change of parseOasdiffChanges(stdout)) {
            findings.push({
              file: relFile,
              line: null,
              kind: String(change.id || 'api-breaking-change'),
              tool: 'oasdiff',
              severity: severityForLevel(change.level),
              message: [
                change.text || change.comment || change.id || 'API breaking change detected',
                change.operation && change.path ? `(${String(change.operation).toUpperCase()} ${change.path})` : null,
              ].filter(Boolean).join(' '),
            });
          }
        } catch (e) {
          log?.(`⚠ oasdiff comparison of ${relFile} failed: ${e.message}`);
        }
      }
    } finally {
      await fsp.rm(tmpDir, { recursive: true, force: true }).catch(() => {});
    }
    return { findings, engine: 'oasdiff' };
  }

  return { checkApiSchemaDrift, oasdiffTooling };
}

module.exports = { createApiSchemaDriftCheck };
