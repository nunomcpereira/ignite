'use strict';

/**
 * Standalone, on-demand report endpoints for the three non-issue Phase 4
 * artifacts (SBOM, LOC metrics, compliance posture) — same `projectPath`
 * convention as /api/pipeline/validate-all and /api/dependencies/*
 * (routes/dependencies.js), for callers with a local path on disk and no
 * jobId/review-gate state to hang a Studio request off of (the VS Code
 * extension in particular: it only ever calls validate-all, which never
 * creates the runningRuns/kept-run state routes/studio.js's
 * resolveStudioContext requires).
 *
 * @param {import('express').Express} app
 * @param {object} deps
 * @param {Function} deps.sanitizeAbsoluteProjectPath - from lib/tool-runner.js's createToolRunner()
 * @param {Function} deps.generateSbom
 * @param {Function} deps.generateLocMetrics
 * @param {Function} deps.checkFeaturePosture
 */
function mountReportsRoutes(app, { sanitizeAbsoluteProjectPath, generateSbom, generateLocMetrics, checkFeaturePosture }) {
  const fsp = require('fs/promises');

  function noopLog() {}

  function resolveProjectPath(req, res) {
    let projectPath;
    try {
      projectPath = sanitizeAbsoluteProjectPath(req.body?.projectPath || '');
    } catch (e) {
      res.status(400).json({ error: e.message });
      return null;
    }
    return projectPath;
  }

  async function requireDirectory(projectPath, res) {
    const stat = await fsp.stat(projectPath).catch(() => null);
    if (!stat || !stat.isDirectory()) {
      res.status(400).json({ error: `projectPath does not exist or is not a directory: ${projectPath}` });
      return false;
    }
    return true;
  }

  app.post('/api/reports/sbom', async (req, res) => {
    const projectPath = resolveProjectPath(req, res);
    if (!projectPath) return;
    if (!(await requireDirectory(projectPath, res))) return;
    try {
      res.json({ ok: true, projectPath, ...(await generateSbom(projectPath, noopLog)) });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  app.post('/api/reports/loc-metrics', async (req, res) => {
    const projectPath = resolveProjectPath(req, res);
    if (!projectPath) return;
    if (!(await requireDirectory(projectPath, res))) return;
    try {
      res.json({ ok: true, projectPath, ...(await generateLocMetrics(projectPath, noopLog)) });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  app.post('/api/reports/posture', async (req, res) => {
    const projectPath = resolveProjectPath(req, res);
    if (!projectPath) return;
    if (!(await requireDirectory(projectPath, res))) return;
    try {
      res.json({ ok: true, projectPath, ...(await checkFeaturePosture(projectPath, noopLog)) });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });
}

module.exports = { mountReportsRoutes };
