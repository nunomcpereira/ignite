'use strict';

/**
 * GET /api/pipeline/:jobId/sarif — the whole project's flagged-issue list
 * (secrets, AI-governance, LLM deep-scan, license/vuln, and the eleven
 * external-tool + CodeQL checks server.js's Phase 4 already collects into
 * one flat list via collectPhase4Issues) reshaped into SARIF 2.1.0 (see
 * lib/sarif.js), so any SARIF-consuming tool (GitHub code scanning, most
 * SAST dashboards, or an agent that already speaks SARIF) can ingest a
 * run's output with no Ignite-specific parsing. Read-only — always
 * reflects `issues`, the same table GET /api/pipeline/:jobId/issues and
 * the Studio UI already read.
 *
 * Deliberately excludes non-issue artifacts (SBOM, LOC metrics, posture
 * report) — SARIF is a findings format, not a document format; those stay
 * on their existing document-download endpoints.
 *
 * @param {import('express').Express} app
 * @param {object} deps
 * @param {object} deps.store - db-store.js instance
 * @param {Map} deps.runningRuns - server.js's in-flight SSE pipeline job map
 */
function mountSarifRoute(app, { store, runningRuns }) {
  const { buildSarif } = require('../lib/sarif');

  app.get('/api/pipeline/:jobId/sarif', (req, res) => {
    const jobId = String(req.params.jobId || '').trim();
    const live = runningRuns.get(jobId);
    const issues = live
      ? live.allIssues
      : (() => {
          const projectId = store.getProjectIdByJobId(jobId);
          return projectId === null ? null : store.getProjectIssues(projectId);
        })();
    if (issues === null) return res.status(404).json({ error: 'Unknown job id.' });

    res.setHeader('Content-Type', 'application/sarif+json');
    res.json(buildSarif(issues));
  });
}

module.exports = { mountSarifRoute };
