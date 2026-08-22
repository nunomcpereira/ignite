'use strict';

/**
 * Normalizes an ingested runtime coverage report into the
 * { relPath: { hitCount, coveredPct } } shape db-store.js's
 * ingestRuntimeCoverage stores — the Ignite-side counterpart to
 * fallow.tools' Beacon (see project memory: "no runtime/production
 * signal" gap). Ignite doesn't run a browser/Node beacon itself (that
 * requires instrumenting the *target* project's runtime, out of scope for
 * an onboarding gatekeeper) — instead a project's own CI uploads whatever
 * coverage report its test suite already produces to
 * POST /api/projects/:projectId/runtime-coverage (routes/runtime-coverage.js),
 * and this module makes sense of either format Ignite accepts:
 *
 *  - Istanbul's `coverage-final.json` (what nyc/jest/vitest produce):
 *    per-file `s`/`statementMap` hit counts, from which we derive a
 *    covered-statement percentage.
 *  - A simple `{ "path/to/file.js": <hitCount> }` map, for any other
 *    instrumentation/telemetry pipeline that only tracks "was this file
 *    touched at all" rather than full statement coverage.
 */

function isIstanbulReport(data) {
  if (!data || typeof data !== 'object') return false;
  const firstKey = Object.keys(data)[0];
  if (!firstKey) return false;
  const entry = data[firstKey];
  return entry && typeof entry === 'object' && ('statementMap' in entry || 's' in entry);
}

function normalizeIstanbul(data, projectRoot) {
  const out = {};
  for (const [absOrRel, fileCov] of Object.entries(data)) {
    const relPath = projectRoot && absOrRel.startsWith(projectRoot)
      ? absOrRel.slice(projectRoot.length).replace(/^[/\\]/, '')
      : absOrRel;
    const hits = Object.values(fileCov.s || {});
    const hitCount = hits.reduce((sum, n) => sum + (Number(n) || 0), 0);
    const covered = hits.filter((n) => Number(n) > 0).length;
    const coveredPct = hits.length > 0 ? Math.round((covered / hits.length) * 1000) / 10 : null;
    out[relPath] = { hitCount, coveredPct };
  }
  return out;
}

function normalizeSimpleMap(data) {
  const out = {};
  for (const [relPath, value] of Object.entries(data)) {
    const hitCount = Number(value) || 0;
    out[relPath] = { hitCount, coveredPct: hitCount > 0 ? 100 : 0 };
  }
  return out;
}

/**
 * @param {object} rawReport - parsed JSON body of the uploaded report
 * @param {string|null} projectRoot - absolute path prefix to strip from
 *   Istanbul's absolute file keys, when known (best-effort; falls back to
 *   the raw key when it doesn't match)
 * @returns {{ normalized: object, format: 'istanbul'|'simple' }}
 */
function normalizeCoverageReport(rawReport, projectRoot = null) {
  if (isIstanbulReport(rawReport)) {
    return { normalized: normalizeIstanbul(rawReport, projectRoot), format: 'istanbul' };
  }
  return { normalized: normalizeSimpleMap(rawReport || {}), format: 'simple' };
}

module.exports = { normalizeCoverageReport, isIstanbulReport };
