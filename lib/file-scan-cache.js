'use strict';

/**
 * Per-file scan-result cache, keyed by (org, repo, checkName). Lets Phase 4's
 * checks (secrets/governance/LLM deep-scan) skip re-evaluating a file whose
 * content hash matches what was recorded on the previous run for the same
 * org/repo, reusing its stored findings instead. `cacheKey` is optional
 * ({ org, repo }) — callers with no project identity (e.g. tests) simply get
 * no caching. Phase D of the server.js module split (see
 * /Users/nuno/.claude/plans/cuddly-roaming-pearl.md).
 *
 * @param {object} store - db-store.js instance (getFileScanCache/replaceFileScanCache)
 */
function createFileScanCache(store) {
  function loadFileScanCache(cacheKey, checkName) {
    if (!cacheKey || !cacheKey.org || !cacheKey.repo) return null;
    return store.getFileScanCache(cacheKey.org, cacheKey.repo, checkName);
  }

  // Replaces the full cache for this (org, repo, checkName) with `entries`, so
  // files removed/renamed since the last run don't linger in the DB forever.
  function saveFileScanCache(cacheKey, checkName, entries) {
    if (!cacheKey || !cacheKey.org || !cacheKey.repo) return;
    store.replaceFileScanCache(cacheKey.org, cacheKey.repo, checkName, entries);
  }

  return { loadFileScanCache, saveFileScanCache };
}

module.exports = { createFileScanCache };
