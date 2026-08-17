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
  // Captures the receiver so a call can be checked against the generic-
  // client denylist below before it's ever counted as a finding.
  const AI_INVOKE_REGEX = /\b([A-Za-z_$][\w.]*)\.(invoke|stream|ainvoke|astream)\(/;

  // `.invoke(`/`.stream(` are common method names far beyond agent
  // frameworks (httpx/requests-style HTTP clients, RxJS, generic RPC
  // dispatchers, ...) — matching the bare method name alone flags things
  // like `await client.stream("POST", url)` in an httpx call as an
  // "ungoverned AI invocation", which it isn't. The catalog's own stated
  // scope is LangChain/LangGraph-style chains/agents specifically (see
  // guidelines/catalog.js's ai-governance entry: "Pass a recursion_limit
  // (LangGraph/LangChain) or equivalent"), so only flag a file that
  // actually references one of those frameworks — a plain HTTP client
  // never does.
  const AGENT_FRAMEWORK_HINT_REGEX = /\b(langchain|langgraph|autogen|crewai)\b/i;

  // Second, independent backstop on top of the file-wide framework hint
  // above: even inside a file that genuinely uses LangChain/LangGraph
  // elsewhere, an httpx/requests-style HTTP client is commonly named
  // `client`/`http`/`session`/etc. and calling `.stream(`/`.invoke(` on
  // *that* object is still not an agent invocation — real case hit in
  // practice: `async with httpx.AsyncClient(...) as client: ... async with
  // client.stream("POST", url, json=payload) as resp:` inside a hand-rolled
  // OpenAI-compatible streaming client, flagged purely because the
  // receiver was named `client`. Whatever the receiver's last identifier
  // segment is (`foo.bar.client` -> `client`), skip it if it's one of
  // these generic transport-object names.
  const GENERIC_CLIENT_RECEIVER_RE = /^(client|http|httpclient|session|conn|connection|resp|response|req|request)$/i;

  // Test files exercise mocked/stubbed AI calls (see e.g. this repo's own
  // test/*.test.js, which import server.js's real functions but never make
  // a real unbounded agent call) — the runaway-execution risk this
  // guideline exists for is a production-runtime concern, not a testing
  // one, so test paths are excluded even if they happen to reference an
  // agent framework in a fixture/mock.
  const TEST_FILE_REGEX = /(^|\/)(tests?|__tests__|spec)\/|(^|\/)(test_[^/]+\.py|[^/]+_test\.py|[^/]+\.(test|spec)\.[jt]sx?)$/i;

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
      const rel = path.relative(root, file);
      if (TEST_FILE_REGEX.test(rel)) continue;
      candidates.push({ file, rel });
    }

    const results = await mapWithConcurrency(candidates, FILE_SCAN_CONCURRENCY, async ({ file, rel }) => {
      const buffer = await fsp.readFile(file);
      if (looksBinary(buffer)) return { rel, skip: true };

      const hash = hashBuffer(buffer);
      const cached = prevCache && prevCache.get(rel);
      if (cached && cached.hash === hash) return { rel, hash, findings: cached.findings, cacheHit: true };

      const content = buffer.toString('utf8');
      const fileFindings = [];
      if (AGENT_FRAMEWORK_HINT_REGEX.test(content) && !content.includes('recursion_limit')) { // governed — compliant otherwise
        const lines = content.split(/\r?\n/);
        lines.forEach((line, i) => {
          const match = line.match(AI_INVOKE_REGEX);
          if (match) {
            const receiver = match[1].split('.').pop();
            if (GENERIC_CLIENT_RECEIVER_RE.test(receiver)) return;
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
