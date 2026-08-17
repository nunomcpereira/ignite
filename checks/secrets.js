'use strict';

/**
 * Regex-based secret scan + optional gitleaks supplement. Phase D of the
 * server.js module split (see
 * /Users/nuno/.claude/plans/cuddly-roaming-pearl.md).
 *
 * @param {object} deps
 * @param {Function} deps.runTool - from lib/tool-runner.js's createToolRunner()
 * @param {object} deps.fsUtils - lib/fs-utils.js exports (walkFiles, looksBinary, buildSnippet, mapWithConcurrency, hashBuffer, BINARY_EXTENSIONS, SECRET_SCAN_CODE_EXTS, isGitignored, loadGitignorePatterns)
 * @param {object} deps.fileScanCache - lib/file-scan-cache.js's createFileScanCache(store) result
 * @param {object} deps.config - { gitleaksEnabled, gitleaksConfigPath, maxScanFileBytes, concurrency }
 */
function createSecretsCheck({ runTool, fsUtils, fileScanCache, config }) {
  const fsp = require('fs/promises');
  const path = require('path');
  const os = require('os');
  const crypto = require('crypto');
  const {
    walkFiles, looksBinary, buildSnippet, mapWithConcurrency, hashBuffer,
    BINARY_EXTENSIONS, SECRET_SCAN_CODE_EXTS, isGitignored, loadGitignorePatterns,
  } = fsUtils;
  const { loadFileScanCache, saveFileScanCache } = fileScanCache;

  const GITLEAKS_ENABLED = Boolean(config.gitleaksEnabled);
  const GITLEAKS_CONFIG_PATH = String(config.gitleaksConfigPath || '');
  const MAX_SCAN_FILE_BYTES = Number(config.maxScanFileBytes) || 5 * 1024 * 1024;
  // How many files' worth of stat+readFile are ever in flight at once —
  // high enough to hide I/O latency behind concurrency, low enough not to
  // blow past a reasonable open-fd count on a repo with thousands of files.
  const FILE_SCAN_CONCURRENCY = Number(config.concurrency) || 16;

  // Captures the quote char (if any) separately from the value so callers can
  // tell a string literal from a bare identifier/property-access reference —
  // e.g. a `password` key aliased to a `clientSecret` variable, or a `token`
  // variable assigned from `res.data.access_token`, are references (unquoted
  // is only ever code syntax in a source file), while `apiKey: 'sk-proj-...'`
  // is an inline literal.
  const SECRET_REGEX =
    /(password|aws_secret|api_key|token|private_key)\s*[:=]\s*(['"]?)([a-zA-Z0-9_\-.~]{10,})/i;

  function isLikelySecretValue(quote, ext) {
    return Boolean(quote) || !SECRET_SCAN_CODE_EXTS.has(ext);
  }

  async function gitleaksTooling() {
    try {
      await runTool('gitleaks', ['version'], os.tmpdir());
      return { ok: true };
    } catch {
      return { ok: false, reason: '`gitleaks` is not installed (brew install gitleaks) or not on PATH.' };
    }
  }

  /**
   * Optional secret-detection pass using gitleaks (https://github.com/gitleaks/gitleaks),
   * when CONFIG.security.gitleaks.enabled is set. Soft-fails (returns no extra
   * findings) if the binary is missing or the scan errors, so a misconfigured
   * or absent install never breaks the pipeline — it just falls back to the
   * built-in regex scan.
   */
  async function runGitleaksScan(root, log) {
    const reportPath = path.join(
      os.tmpdir(),
      `ignite-gitleaks-${crypto.randomBytes(8).toString('hex')}.json`
    );
    try {
      const args = ['detect', '--source', root, '--no-git', '--report-format', 'json',
        '--report-path', reportPath, '--exit-code', '0'];
      if (GITLEAKS_CONFIG_PATH) args.push('--config', GITLEAKS_CONFIG_PATH);
      await runTool('gitleaks', args, root);

      let raw;
      try {
        raw = await fsp.readFile(reportPath, 'utf8');
      } catch {
        return []; // no report written (e.g. nothing found on some gitleaks versions)
      }
      const results = raw.trim() ? JSON.parse(raw) : [];
      return await Promise.all(results.map(async (r) => {
        const relFile = path.relative(root, path.resolve(root, r.File || r.file || ''));
        const line = Number.isInteger(r.StartLine) ? r.StartLine : Number(r.startLine) || 0;
        const colStart = Number.isInteger(r.StartColumn) ? r.StartColumn - 1 : undefined;
        const colEnd = Number.isInteger(r.EndColumn) ? r.EndColumn : undefined;
        let code = null;
        try {
          const content = await fsp.readFile(path.join(root, relFile), 'utf8');
          code = buildSnippet(content, line, { colStart, colEnd });
        } catch { /* best-effort only */ }
        return {
          file: relFile,
          line,
          kind: String(r.RuleID || r.ruleID || 'secret').toLowerCase(),
          tool: 'gitleaks',
          code,
        };
      }));
    } catch (e) {
      log(`⚠ gitleaks scan skipped: ${e.message}`);
      return [];
    } finally {
      await fsp.unlink(reportPath).catch(() => {});
    }
  }

  async function checkSecrets(root, log, cacheKey) {
    const findings = [];
    let scanned = 0;
    let cacheHits = 0;
    let gitignoredSkipped = 0;
    const gitignorePatterns = await loadGitignorePatterns(root);
    const prevCache = loadFileScanCache(cacheKey, 'secrets');
    const newCacheEntries = [];

    // Cheap, synchronous, order-preserving filtering (extension + gitignore)
    // happens up front while collecting the candidate list; the expensive
    // part (stat + readFile) is what actually benefits from concurrency
    // below, so only that part is parallelized.
    const candidates = [];
    for await (const file of walkFiles(root)) {
      const ext = path.extname(file).toLowerCase();
      if (BINARY_EXTENSIONS.has(ext)) continue;
      const rel = path.relative(root, file);
      if (gitignorePatterns.length > 0 && isGitignored(gitignorePatterns, rel)) {
        gitignoredSkipped++;
        continue;
      }
      candidates.push({ file, rel, ext });
    }

    const results = await mapWithConcurrency(candidates, FILE_SCAN_CONCURRENCY, async ({ file, rel, ext }) => {
      const stat = await fsp.stat(file);
      if (stat.size > MAX_SCAN_FILE_BYTES) return { rel, oversizedMb: stat.size / 1e6 };

      const buffer = await fsp.readFile(file);
      if (looksBinary(buffer)) return { rel, skip: true };

      const hash = hashBuffer(buffer);
      const cached = prevCache && prevCache.get(rel);
      if (cached && cached.hash === hash) return { rel, hash, findings: cached.findings, cacheHit: true };

      const content = buffer.toString('utf8');
      const fileFindings = [];
      const lines = content.split(/\r?\n/);
      lines.forEach((line, i) => {
        const match = line.match(SECRET_REGEX);
        if (match && isLikelySecretValue(match[2], ext)) {
          fileFindings.push({
            file: rel,
            line: i + 1,
            kind: match[1].toLowerCase(),
            code: buildSnippet(content, i + 1, { colStart: match.index, colEnd: match.index + match[0].length }),
          });
        }
      });
      return { rel, hash, findings: fileFindings };
    });

    // Results are merged back in the original walk order (mapWithConcurrency
    // guarantees this) so findings/log output are identical to the old
    // strictly-sequential version — only how the I/O got there is different.
    for (const r of results) {
      if (r.oversizedMb !== undefined) {
        log(`Skipping oversized file (${r.oversizedMb.toFixed(1)} MB): ${r.rel}`);
        continue;
      }
      if (r.skip) continue;
      scanned++;
      if (r.cacheHit) cacheHits++;
      findings.push(...r.findings);
      newCacheEntries.push({ relPath: r.rel, hash: r.hash, findings: r.findings });
    }

    saveFileScanCache(cacheKey, 'secrets', newCacheEntries);

    if (GITLEAKS_ENABLED) {
      log('Gitleaks enabled — running supplemental secret-detection scan...');
      // gitleaks walks the raw filesystem tree itself (--no-git), so it has no
      // gitignore awareness of its own — filter its findings the same way the
      // regex scan above was filtered.
      const gitleaksFindings = (await runGitleaksScan(root, log)).filter((f) => {
        const ignored = gitignorePatterns.length > 0 && isGitignored(gitignorePatterns, f.file);
        if (ignored) gitignoredSkipped++;
        return !ignored;
      });
      const seen = new Set(findings.map((f) => `${f.file}:${f.line}`));
      let added = 0;
      for (const f of gitleaksFindings) {
        const key = `${f.file}:${f.line}`;
        if (seen.has(key)) continue; // already caught by the regex scan
        seen.add(key);
        findings.push(f);
        added++;
      }
      log(`Gitleaks scan complete — ${gitleaksFindings.length} finding(s), ${added} new.`);
    }

    if (gitignoredSkipped > 0) {
      log(`ℹ ${gitignoredSkipped} gitignored file(s) excluded from credential scan — not blocking.`);
    }
    if (cacheHits > 0) {
      log(`♻ ${cacheHits} file(s) unchanged since the last run for this org/repo — reused cached results.`);
    }

    return { findings, scanned, cacheHits };
  }

  return { checkSecrets, runGitleaksScan, gitleaksTooling, SECRET_REGEX, isLikelySecretValue };
}

module.exports = { createSecretsCheck };
