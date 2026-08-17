'use strict';

/**
 * Per-language LOC metrics via gocloc. Phase C of the server.js module
 * split (see /Users/nuno/.claude/plans/cuddly-roaming-pearl.md).
 *
 * @param {object} deps
 * @param {Function} deps.runTool - from lib/tool-runner.js's createToolRunner()
 * @param {object} deps.fsUtils - lib/fs-utils.js exports (relativeToRoot, SKIP_DIRS_REGEX)
 * @param {object} deps.config - { enabled }
 */
function createLocMetricsCheck({ runTool, fsUtils, config }) {
  const os = require('os');
  const { relativeToRoot, SKIP_DIRS_REGEX } = fsUtils;

  const GOCLOC_ENABLED = Boolean(config.enabled);

  async function goclocTooling() {
    try {
      await runTool('gocloc', ['--version'], os.tmpdir());
      return { ok: true };
    } catch {
      return { ok: false, reason: '`gocloc` is not installed (brew install gocloc) — LOC metrics are simply omitted.' };
    }
  }

  // Precise per-language LOC counts via gocloc, which does its own
  // multi-language file discovery over `root` in one pass. Purely
  // descriptive — never produces issues — so the caller attaches the result
  // as a downloadable project document (same treatment as generateSbom),
  // not something collectPhase4Issues touches.
  async function generateLocMetrics(root, log) {
    const tooling = GOCLOC_ENABLED ? await goclocTooling() : { ok: false, reason: 'gocloc is disabled (metrics.gocloc.enabled=false).' };
    if (!tooling.ok) {
      log?.(`⚠ gocloc LOC metrics skipped: ${tooling.reason}`);
      return { engine: 'disabled', metrics: null };
    }

    log?.('Engine: gocloc CLI (External) — computing per-language LOC metrics...');
    try {
      // --by-file (rather than gocloc's default per-language-only rollup)
      // so Studio can offer "click a language, see just its files" — the
      // per-language `languages` summary below is aggregated from this same
      // per-file list rather than issuing a second gocloc call.
      const { stdout } = await runTool('gocloc', ['--by-file', '--output-type', 'json', '--fullpath', '--not-match-d', SKIP_DIRS_REGEX, root], root);
      const raw = stdout.trim() ? JSON.parse(stdout) : null;
      if (!raw) return { engine: 'gocloc', metrics: null };
      const files = await Promise.all((raw.files || []).map(async (f) => ({
        file: await relativeToRoot(root, f.name),
        language: f.language,
        code: f.code,
        comment: f.comment,
        blank: f.blank,
      })));
      const byLanguage = new Map();
      for (const f of files) {
        const agg = byLanguage.get(f.language) || { name: f.language, files: 0, code: 0, comment: 0, blank: 0 };
        agg.files++; agg.code += f.code; agg.comment += f.comment; agg.blank += f.blank;
        byLanguage.set(f.language, agg);
      }
      const metrics = { languages: [...byLanguage.values()], total: raw.total, files };
      return { engine: 'gocloc', metrics };
    } catch (e) {
      log?.(`⚠ gocloc LOC metrics failed: ${e.message}`);
      return { engine: 'disabled', metrics: null };
    }
  }

  return { generateLocMetrics, goclocTooling };
}

module.exports = { createLocMetricsCheck };
