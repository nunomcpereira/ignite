'use strict';

/**
 * POST /api/pipeline/auto-fix — closes the "detect-only, no auto-fix" gap
 * against fallow.tools' `fallow fix` (see project memory). Runs
 * checkDeadCode against a local projectPath (same convention as
 * /api/pipeline/validate-all — no upload/staging needed) and either
 * returns the fix plan (dryRun, the default) or applies it in place.
 *
 * @param {import('express').Express} app
 * @param {object} deps
 * @param {Function} deps.sanitizeAbsoluteProjectPath - from lib/tool-runner.js's createToolRunner()
 * @param {Function} deps.checkDeadCode - checks/dead-code.js
 */
function mountAutoFixRoute(app, { sanitizeAbsoluteProjectPath, checkDeadCode }) {
  const fsp = require('fs/promises');
  const { computeAutoFixPlan, applyAutoFixPlan } = require('../lib/auto-fix');

  app.post('/api/pipeline/auto-fix', async (req, res) => {
    let projectPath;
    try {
      projectPath = sanitizeAbsoluteProjectPath(req.body?.projectPath || '');
    } catch (e) {
      return res.status(400).json({ error: e.message });
    }
    const stat = await fsp.stat(projectPath).catch(() => null);
    if (!stat || !stat.isDirectory()) {
      return res.status(400).json({ error: `projectPath does not exist or is not a directory: ${projectPath}` });
    }
    const dryRun = req.body?.dryRun !== false;
    try {
      const { findings } = await checkDeadCode(projectPath, null);
      const plan = computeAutoFixPlan(findings);
      const { results } = await applyAutoFixPlan(plan, projectPath, { dryRun });
      res.json({ ok: true, projectPath, dryRun, actionCount: results.length, actions: results });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });
}

module.exports = { mountAutoFixRoute };
