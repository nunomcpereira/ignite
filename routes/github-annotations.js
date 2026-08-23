'use strict';

/**
 * GET /api/pipeline/:jobId/annotations — the same issue list routes/sarif.js
 * exports, reshaped into GitHub Actions workflow-command annotations (see
 * lib/github-annotations.js). Mirrors routes/sarif.js's live/completed-job
 * lookup exactly, so a CI step can `curl` this right after a job finishes
 * and the annotations show up on that same run's job log with zero extra
 * permissions or upload step.
 *
 * @param {import('express').Express} app
 * @param {object} deps
 * @param {object} deps.store - db-store.js instance
 * @param {Map} deps.runningRuns - server.js's in-flight SSE pipeline job map
 */
function mountGithubAnnotationsRoute(app, { store, runningRuns }) {
  const { buildGithubAnnotations } = require('../lib/github-annotations');

  app.get('/api/pipeline/:jobId/annotations', (req, res) => {
    const jobId = String(req.params.jobId || '').trim();
    const live = runningRuns.get(jobId);
    const issues = live
      ? live.allIssues
      : (() => {
          const projectId = store.getProjectIdByJobId(jobId);
          return projectId === null ? null : store.getProjectIssues(projectId);
        })();
    if (issues === null) return res.status(404).json({ error: 'Unknown job id.' });

    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.send(buildGithubAnnotations(issues));
  });
}

module.exports = { mountGithubAnnotationsRoute };
