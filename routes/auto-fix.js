'use strict';

/**
 * POST /api/pipeline/auto-fix — closes the "detect-only, no auto-fix" gap
 * against fallow.tools' `fallow fix` (see project memory). Runs
 * checkDeadCode and checkAiGovernance against a local projectPath (same
 * convention as /api/pipeline/validate-all — no upload/staging needed) and
 * either returns the combined fix plan (dryRun, the default) or applies it
 * in place. `categories` (optional array, default both) narrows which
 * check(s) run — e.g. `["ai-governance"]` to fix only ungoverned AI
 * invocations without touching dead code.
 *
 * @param {import('express').Express} app
 * @param {object} deps
 * @param {Function} deps.sanitizeAbsoluteProjectPath - from lib/tool-runner.js's createToolRunner()
 * @param {Function} deps.checkDeadCode - checks/dead-code.js
 * @param {Function} deps.checkAiGovernance - checks/ai-governance.js
 */
function mountAutoFixRoute(app, { sanitizeAbsoluteProjectPath, checkDeadCode, checkAiGovernance }) {
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
    const categories = Array.isArray(req.body?.categories) && req.body.categories.length > 0
      ? new Set(req.body.categories)
      : new Set(['dead-code', 'ai-governance']);
    try {
      const findings = [];
      if (categories.has('dead-code')) {
        const deadCode = await checkDeadCode(projectPath, null);
        findings.push(...deadCode.findings);
      }
      if (categories.has('ai-governance') && checkAiGovernance) {
        const governance = await checkAiGovernance(projectPath, {});
        findings.push(...governance.findings.map((f) => ({ ...f, kind: 'ungoverned-ai-invocation' })));
      }
      const plan = computeAutoFixPlan(findings);
      const { results } = await applyAutoFixPlan(plan, projectPath, { dryRun });
      res.json({ ok: true, projectPath, dryRun, actionCount: results.length, actions: results });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });
}

module.exports = { mountAutoFixRoute };
