'use strict';

/**
 * Standalone dependency license/vulnerability scan endpoints — same
 * projectPath convention as /api/pipeline/validate-all, for agent/CI use
 * (and the endpoint the MCP server's check_dependency_vulnerabilities tool
 * proxies to). Phase F of the server.js module split (see
 * /Users/nuno/.claude/plans/cuddly-roaming-pearl.md).
 *
 * @param {import('express').Express} app
 * @param {object} deps
 * @param {Function} deps.sanitizeAbsoluteProjectPath - from lib/tool-runner.js's createToolRunner()
 * @param {Function} deps.scanDependencyLicenses - server.js (Black Duck-style license classification)
 * @param {Function} deps.scanDependencyVulnerabilities - server.js (deps.dev CVE/GHSA scan)
 */
function mountDependenciesRoutes(app, { sanitizeAbsoluteProjectPath, scanDependencyLicenses, scanDependencyVulnerabilities }) {
  const fsp = require('fs/promises');

  app.post('/api/dependencies/check', async (req, res) => {
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
    try {
      res.json({ ok: true, projectPath, ...(await scanDependencyLicenses(projectPath)) });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  app.post('/api/dependencies/vulnerabilities', async (req, res) => {
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
    try {
      const manifests = await scanDependencyVulnerabilities(projectPath);
      const counts = { critical: 0, advisory: 0 };
      for (const m of manifests) {
        for (const d of m.dependencies) {
          for (const v of d.vulnerabilities) {
            if (v.severity === 'error') counts.critical++; else counts.advisory++;
          }
        }
      }
      res.json({ ok: true, projectPath, manifests, counts });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });
}

module.exports = { mountDependenciesRoutes };
