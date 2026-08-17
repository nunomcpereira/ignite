'use strict';

/**
 * Flags LangChain/LangGraph-style `.invoke()`/`.stream()` calls with no
 * `recursion_limit` guard (unbounded agent-loop risk). Phase D of the
 * server.js module split (see
 * /Users/nuno/.claude/plans/cuddly-roaming-pearl.md).
 *
 * @param {object} deps
 * @param {object} deps.fsUtils - lib/fs-utils.js exports (walkFiles, looksBinary, buildSnippet, mapWithConcurrency, hashBuffer)
 * @param {object} deps.fileScanCache - lib/file-scan-cache.js's createFileScanCache(store) result
 * @param {object} deps.config - { concurrency }
 */
function createAiGovernanceCheck({ fsUtils, fileScanCache, config }) {
  const fsp = require('fs/promises');
  const path = require('path');
  const { walkFiles, looksBinary, buildSnippet, mapWithConcurrency, hashBuffer } = fsUtils;
  const { loadFileScanCache, saveFileScanCache } = fileScanCache;

  const FILE_SCAN_CONCURRENCY = Number(config.concurrency) || 16;
  const AI_INVOKE_REGEX = /\.(invoke|stream|ainvoke|astream)\(/;

  async function checkAiGovernance(root, cacheKey) {
    const findings = [];
    let scanned = 0;
    let cacheHits = 0;
    const prevCache = loadFileScanCache(cacheKey, 'governance');
    const newCacheEntries = [];

    const candidates = [];
    for await (const file of walkFiles(root)) {
      const ext = path.extname(file).toLowerCase();
      if (!['.py', '.js', '.ts'].includes(ext)) continue;
      candidates.push({ file, rel: path.relative(root, file) });
    }

    const results = await mapWithConcurrency(candidates, FILE_SCAN_CONCURRENCY, async ({ file, rel }) => {
      const buffer = await fsp.readFile(file);
      if (looksBinary(buffer)) return { rel, skip: true };

      const hash = hashBuffer(buffer);
      const cached = prevCache && prevCache.get(rel);
      if (cached && cached.hash === hash) return { rel, hash, findings: cached.findings, cacheHit: true };

      const content = buffer.toString('utf8');
      const fileFindings = [];
      if (!content.includes('recursion_limit')) { // governed — compliant otherwise
        const lines = content.split(/\r?\n/);
        lines.forEach((line, i) => {
          const match = line.match(AI_INVOKE_REGEX);
          if (match) {
            fileFindings.push({
              file: rel,
              line: i + 1,
              snippet: line.trim().slice(0, 120),
              code: buildSnippet(content, i + 1, { colStart: match.index, colEnd: match.index + match[0].length }),
            });
          }
        });
      }
      return { rel, hash, findings: fileFindings };
    });

    for (const r of results) {
      if (r.skip) continue;
      scanned++;
      if (r.cacheHit) cacheHits++;
      findings.push(...r.findings);
      newCacheEntries.push({ relPath: r.rel, hash: r.hash, findings: r.findings });
    }

    saveFileScanCache(cacheKey, 'governance', newCacheEntries);

    return { findings, scanned, cacheHits };
  }

  return { checkAiGovernance };
}

module.exports = { createAiGovernanceCheck };
