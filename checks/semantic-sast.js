'use strict';

/**
 * Semantic pattern-matching SAST via Semgrep OSS. Phase C of the server.js
 * module split (see /Users/nuno/.claude/plans/cuddly-roaming-pearl.md).
 *
 * semgrepTooling is re-exported (not just checkSemanticSast) because
 * checkFeaturePosture (still in server.js) reuses the same Semgrep binary
 * probe — the Compliance & Feature Posture Engine shares Semgrep's tooling
 * check rather than adding its own binary.
 *
 * @param {object} deps
 * @param {Function} deps.runTool - from lib/tool-runner.js's createToolRunner()
 * @param {object} deps.fsUtils - lib/fs-utils.js exports (buildSnippet, relativeToRoot)
 * @param {object} deps.config - { enabled, binary, semgrepConfig }
 */
function createSemanticSastCheck({ runTool, fsUtils, config }) {
  const fsp = require('fs/promises');
  const path = require('path');
  const os = require('os');
  const { buildSnippet, relativeToRoot, SKIP_DIRS } = fsUtils;

  const SEMGREP_ENABLED = Boolean(config.enabled);
  const SEMGREP_BINARY = String(config.binary || 'semgrep');
  const SEMGREP_CONFIG = String(config.semgrepConfig || 'p/security-audit');
  const SEMGREP_TIMEOUT_MS = 10 * 60_000;

  async function buildSemgrepEnv() {
    const semgrepHome = path.join(os.tmpdir(), 'ignite-semgrep-home');
    const semgrepCache = path.join(semgrepHome, 'cache');
    await Promise.all([
      fsp.mkdir(semgrepHome, { recursive: true }).catch(() => {}),
      fsp.mkdir(semgrepCache, { recursive: true }).catch(() => {}),
    ]);
    return {
      HOME: semgrepHome,
      XDG_CONFIG_HOME: semgrepHome,
      XDG_CACHE_HOME: semgrepCache,
      SEMGREP_SEND_METRICS: 'off',
    };
  }

  async function semgrepTooling() {
    try {
      const env = await buildSemgrepEnv();
      const { stdout } = await runTool('semgrep', ['--version'], os.tmpdir(), { env });
      return { ok: true, version: stdout.trim() || null, path: SEMGREP_BINARY };
    } catch {
      return { ok: false, reason: '`semgrep` is not installed (brew install semgrep / pip install semgrep) — semantic SAST and posture findings are simply omitted.' };
    }
  }

  const SEMGREP_SEVERITY_TO_ISSUE = { ERROR: 'error', WARNING: 'warning', INFO: 'warning' };

  // These rule messages are known noisy/low-confidence findings that can be
  // reported as ERROR by individual rule metadata despite not materially
  // changing the real risk level. Keep them as warnings to avoid false
  // blockers while preserving the raw finding details for review.
  // Same rationale as BEARER_FORCE_WARNING_TITLES in checks/pii-dataflow.js.
  const SEMGREP_FORCE_WARNING_TITLES = [
    /unsanitized dynamic input in file path/i,
    /observable timing discrepancy/i,
    /timing discrepancy/i,
  ];

  // Semantic pattern-matching SAST via Semgrep OSS, run over the whole staged
  // project in one pass (semgrep does its own multi-language file discovery).
  // No built-in fallback when disabled/missing — there's no meaningful
  // heuristic substitute for a semantic rule engine, so this simply
  // contributes nothing rather than pretending to.
  // NOTE: running each --config pack as its own concurrent semgrep process
  // was tried here and measured *slower* in practice (343s vs. 264s on a
  // 950k-LOC monorepo, both worse than doing nothing) — each process
  // re-parses every file from scratch, and that duplicated parse/AST-build
  // cost plus GC pressure from two full-size processes outweighed any
  // parallelism gained, exactly the oversubscription cost semgrep's own
  // docs warn about. Reverted to one process, multiple --config flags —
  // semgrep parses each file once and matches every pack's rules against
  // that single parse.
  async function checkSemanticSast(root, log) {
    const tooling = SEMGREP_ENABLED ? await semgrepTooling() : { ok: false, reason: 'semgrep is disabled (security.semgrep.enabled=false).' };
    if (!tooling.ok) {
      log?.(`⚠ Semgrep semantic SAST scan skipped: ${tooling.reason}`);
      return { findings: [], engine: 'disabled' };
    }

    const semgrepConfigPacks = SEMGREP_CONFIG.split(',').map((c) => c.trim()).filter(Boolean);
    log?.(`Engine: Semgrep CLI (External) — running semantic SAST rules (config: ${semgrepConfigPacks.join(', ')})...`);
    try {
      const env = await buildSemgrepEnv();
      const { stdout } = await runTool('semgrep', [
        'scan', ...semgrepConfigPacks.flatMap((c) => ['--config', c]),
        // Same directory exclusions as Ignite's own walkFiles (SKIP_DIRS) —
        // semgrep does its own file discovery, so without these it happily
        // pattern-matches vendored/generated bundles (Angular/Vite's
        // .angular cache, a committed dist/build output, ...) that were
        // never meant to be scanned in the first place. Real cost on a
        // large monorepo: these directories can hold more lines than the
        // project's actual source.
        ...[...SKIP_DIRS].flatMap((d) => ['--exclude', d]),
        '--json', '--quiet', '--metrics', 'off', root,
      ], root, { allowedExitCodes: [0, 1], env, timeoutMs: SEMGREP_TIMEOUT_MS });
      const data = stdout.trim() ? JSON.parse(stdout) : { results: [] };
      const results = Array.isArray(data.results) ? data.results : [];
      const findings = [];
      for (const r of results) {
        const relFile = await relativeToRoot(root, r.path);
        const line = Number(r.start?.line) || 1;
        let content = null;
        try { content = await fsp.readFile(path.join(root, relFile), 'utf8'); } catch { /* best-effort */ }
        const semgrepSeverity = String(r.extra?.severity || 'WARNING').toUpperCase();
        const message = r.extra?.message || 'Semgrep finding';
        const forcedWarning = SEMGREP_FORCE_WARNING_TITLES.some((re) => re.test(message));
        // Semgrep's registry rules (p/security-audit, p/owasp-top-ten, ...)
        // carry their own CWE/OWASP metadata per-rule — far more precise than
        // Ignite's own category-level/keyword CWE fallback (override-engine's
        // deriveCweOwasp), so pass it straight through when present. Each is
        // an array (a rule can map to more than one CWE/OWASP category);
        // only the first is kept, same "most specific wins" reasoning as
        // picking one severity per finding.
        const cweList = Array.isArray(r.extra?.metadata?.cwe) ? r.extra.metadata.cwe : [];
        const owaspList = Array.isArray(r.extra?.metadata?.owasp) ? r.extra.metadata.owasp : [];
        const cweMatch = String(cweList[0] || '').match(/^CWE-\d+/);
        findings.push({
          file: relFile,
          line,
          kind: String(r.check_id || 'semgrep-finding').toLowerCase(),
          tool: 'semgrep',
          severity: forcedWarning ? 'warning' : (SEMGREP_SEVERITY_TO_ISSUE[semgrepSeverity] || 'warning'),
          message,
          code: content ? buildSnippet(content, line) : null,
          cwe: cweMatch ? cweMatch[0] : null,
          owasp: owaspList[0] || null,
        });
      }
      return { findings, engine: 'semgrep' };
    } catch (e) {
      log?.(`⚠ Semgrep semantic SAST scan failed: ${e.message}`);
      return { findings: [], engine: 'failed' };
    }
  }

  return { checkSemanticSast, semgrepTooling };
}

module.exports = { createSemanticSastCheck };
