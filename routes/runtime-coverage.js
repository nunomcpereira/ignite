'use strict';

/**
 * Runtime coverage ingestion — the Ignite-side counterpart to
 * fallow.tools' Beacon (closes the "no runtime/production signal" gap, see
 * project memory). A project's CI (or any process holding a coverage
 * report) POSTs it here after tests run; Ignite stores per-file hit
 * counts/coverage %, keyed by org/repo, for checks/complexity-health.js's
 * CRAP score and checks/dead-code.js's confidence signal to consume on the
 * next scan.
 *
 * @param {import('express').Express} app
 * @param {object} deps
 * @param {object} deps.store - db-store.js instance
 */
function mountRuntimeCoverageRoutes(app, { store }) {
  const { normalizeCoverageReport } = require('../lib/runtime-coverage');

  // Keyed by org/repo (not projectId) — coverage is a property of the
  // *codebase* across pushes, not one specific onboarding run, matching
  // how file_scan_cache is keyed.
  app.post('/api/runtime-coverage/:org/:repo', (req, res) => {
    const { org, repo } = req.params;
    const body = req.body;
    if (!body || typeof body !== 'object') {
      return res.status(400).json({ error: 'Request body must be a JSON coverage report.' });
    }
    const projectRoot = typeof req.query.projectRoot === 'string' ? req.query.projectRoot : null;
    let normalized, format;
    try {
      ({ normalized, format } = normalizeCoverageReport(body, projectRoot));
    } catch (e) {
      return res.status(400).json({ error: `Could not parse coverage report: ${e.message}` });
    }
    const fileCount = store.ingestRuntimeCoverage(org, repo, normalized);
    res.json({ ok: true, org, repo, format, filesIngested: fileCount });
  });

  app.get('/api/runtime-coverage/:org/:repo', (req, res) => {
    const { org, repo } = req.params;
    const map = store.getRuntimeCoverageMap(org, repo);
    res.json({ ok: true, org, repo, files: Object.fromEntries(map) });
  });

  app.delete('/api/runtime-coverage/:org/:repo', (req, res) => {
    const { org, repo } = req.params;
    const removed = store.clearRuntimeCoverage(org, repo);
    res.json({ ok: true, org, repo, removed });
  });
}

module.exports = { mountRuntimeCoverageRoutes };
