'use strict';

/**
 * Code-duplication scan via jscpd. Phase C of the server.js module split
 * (see /Users/nuno/.claude/plans/cuddly-roaming-pearl.md).
 *
 * @param {object} deps
 * @param {Function} deps.runTool - from lib/tool-runner.js's createToolRunner()
 * @param {object} deps.fsUtils - lib/fs-utils.js exports (buildSnippet)
 * @param {object} deps.config - { enabled, minLines, minTokens, ignorePatterns }
 */
function createCodeDuplicationCheck({ runTool, fsUtils, config }) {
  const fsp = require('fs/promises');
  const path = require('path');
  const os = require('os');
  const crypto = require('crypto');
  const { buildSnippet } = fsUtils;

  const JSCPD_ENABLED = Boolean(config.enabled);
  const JSCPD_MIN_LINES = Number(config.minLines) || 5;
  const JSCPD_MIN_TOKENS = Number(config.minTokens) || 50;
  const JSCPD_IGNORE_PATTERNS = Array.isArray(config.ignorePatterns) ? config.ignorePatterns : [];

  async function jscpdTooling() {
    try {
      await runTool('jscpd', ['--version'], os.tmpdir());
      return { ok: true };
    } catch {
      return { ok: false, reason: '`jscpd` is not installed (npm install -g jscpd) — duplication findings are simply omitted.' };
    }
  }

  // Code-duplication scan via jscpd, which does its own multi-language file
  // discovery over `root` in one pass. Each clone becomes one finding
  // anchored at its first occurrence, referencing the second in the message
  // (Studio can only address one file/line per finding). No built-in
  // fallback — duplicate-block detection needs the real tool.
  async function checkCodeDuplication(root, log) {
    const tooling = JSCPD_ENABLED ? await jscpdTooling() : { ok: false, reason: 'jscpd is disabled (metrics.jscpd.enabled=false).' };
    if (!tooling.ok) {
      log?.(`⚠ jscpd duplication scan skipped: ${tooling.reason}`);
      return { findings: [], engine: 'disabled' };
    }

    log?.('Engine: jscpd CLI (External) — scanning for duplicated code blocks...');
    const outDir = path.join(os.tmpdir(), `ignite-jscpd-${crypto.randomBytes(8).toString('hex')}`);
    try {
      await runTool('jscpd', [
        root, '--reporters', 'json', '--output', outDir, '--silent',
        '--min-lines', String(JSCPD_MIN_LINES), '--min-tokens', String(JSCPD_MIN_TOKENS),
        ...(JSCPD_IGNORE_PATTERNS.length > 0 ? ['--ignore', JSCPD_IGNORE_PATTERNS.join(',')] : []),
      ], root, { allowedExitCodes: [0, 1] });
      const raw = await fsp.readFile(path.join(outDir, 'jscpd-report.json'), 'utf8').catch(() => null);
      if (raw === null) return { findings: [], engine: 'jscpd' };
      const data = JSON.parse(raw);
      const duplicates = Array.isArray(data.duplicates) ? data.duplicates : [];
      const findings = [];
      for (const dup of duplicates) {
        // Defensive guard on top of --min-lines: jscpd's own `lines` count
        // can still undercount for a duplicate that's really just
        // punctuation (a run of closing brackets/braces), so also require
        // the reported span to actually meet the configured minimum here.
        const dupLines = Number(dup.lines) || 0;
        if (dupLines < JSCPD_MIN_LINES) continue;
        const relFile = path.relative(root, path.resolve(root, dup.firstFile?.name || ''));
        const line = Number(dup.firstFile?.startLoc?.line) || 1;
        const endLine = Number(dup.firstFile?.endLoc?.line) || line;
        const otherFile = dup.secondFile?.name ? path.relative(root, path.resolve(root, dup.secondFile.name)) : '?';
        const otherLine = Number(dup.secondFile?.startLoc?.line) || 1;
        const otherEndLine = Number(dup.secondFile?.endLoc?.line) || otherLine;
        const otherRange = otherEndLine > otherLine ? `${otherLine}-${otherEndLine}` : String(otherLine);
        let content = null;
        try { content = await fsp.readFile(path.join(root, relFile), 'utf8'); } catch { /* best-effort */ }
        // Skip blocks whose duplicated span is nothing but punctuation/
        // whitespace (stray closing braces, brackets, semicolons) — not a
        // meaningful duplicate even if it cleared the token/line thresholds.
        if (content) {
          const spanLines = content.split('\n').slice(line - 1, endLine);
          const meaningful = spanLines.some((l) => /[A-Za-z0-9_]/.test(l));
          if (!meaningful) continue;
        }
        findings.push({
          file: relFile,
          line,
          kind: 'duplicate-code',
          tool: 'jscpd',
          severity: 'warning',
          message: `${dup.lines || 0}-line duplicate block, also found in ${otherFile}:${otherRange}.`,
          code: content ? buildSnippet(content, line, { endLine }) : null,
          // Structured pointer to the other occurrence (message above is the
          // human-readable form of the same data) so Studio can render it as
          // a link that jumps straight to — and highlights — that exact span,
          // instead of making the reader go find it themselves.
          duplicateRef: { file: otherFile, line: otherLine, endLine: otherEndLine },
        });
      }
      return { findings, engine: 'jscpd' };
    } catch (e) {
      log?.(`⚠ jscpd duplication scan failed: ${e.message}`);
      return { findings: [], engine: 'disabled' };
    } finally {
      await fsp.rm(outDir, { recursive: true, force: true }).catch(() => {});
    }
  }

  return { checkCodeDuplication, jscpdTooling };
}

module.exports = { createCodeDuplicationCheck };
