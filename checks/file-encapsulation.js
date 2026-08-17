'use strict';

/**
 * Built-in "low encapsulation" check — no external tool, no fallback needed
 * (there's nothing to fall back *from*). Flags any single source file over
 * maxLines lines. Phase C of the server.js module split (see
 * /Users/nuno/.claude/plans/cuddly-roaming-pearl.md).
 *
 * @param {object} deps
 * @param {object} deps.fsUtils - lib/fs-utils.js exports (walkFiles, looksBinary, buildSnippet, SECRET_SCAN_CODE_EXTS)
 * @param {object} deps.config - { enabled, maxLines }
 */
function createFileEncapsulationCheck({ fsUtils, config }) {
  const fsp = require('fs/promises');
  const path = require('path');
  const { walkFiles, looksBinary, buildSnippet, SECRET_SCAN_CODE_EXTS } = fsUtils;

  const FILE_SIZE_ENABLED = Boolean(config.enabled);
  const FILE_SIZE_MAX_LINES = Number(config.maxLines) || 1000;

  // Deliberately narrow: a raw line count, not an attempt to measure
  // cyclomatic complexity or responsibility count — those need real
  // per-language parsing to do honestly, while "this file is huge" is a
  // cheap, language-agnostic, directionally-correct proxy for the same
  // smell (harder to review, harder to test in isolation, and —
  // concretely — a bigger target for any per-file-cached SAST tool's
  // cache to miss on every unrelated change elsewhere in the file).
  // Always advisory: file size is something to track and gradually
  // address, not a hard gate.
  async function checkFileEncapsulation(root, log) {
    if (!FILE_SIZE_ENABLED) {
      log?.('File-size check is disabled (metrics.fileSize.enabled=false).');
      return { findings: [], engine: 'disabled' };
    }

    const findings = [];
    for await (const file of walkFiles(root)) {
      const ext = path.extname(file).toLowerCase();
      if (!SECRET_SCAN_CODE_EXTS.has(ext)) continue;

      const buffer = await fsp.readFile(file);
      if (looksBinary(buffer)) continue;
      const content = buffer.toString('utf8');
      const lineCount = content.split(/\r?\n/).length;
      if (lineCount <= FILE_SIZE_MAX_LINES) continue;

      const rel = path.relative(root, file);
      findings.push({
        file: rel,
        line: 1,
        kind: 'file-too-large',
        tool: 'ignite-built-in',
        severity: 'warning',
        message: `${rel} is ${lineCount} lines — over the ${FILE_SIZE_MAX_LINES}-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.`,
        code: buildSnippet(content, 1),
      });
    }
    return { findings, engine: 'built-in' };
  }

  return { checkFileEncapsulation };
}

module.exports = { createFileEncapsulationCheck };
