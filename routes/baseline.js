'use strict';

/**
 * Baseline/diff adoption-mode endpoints — closes the "no baseline/diff
 * adoption mode" gap against fallow.tools' --save-baseline (see project
 * memory). Saving a baseline accepts the project's *current* issue ids as
 * pre-existing debt; validate-all's `baselineMode: 'gate'` param (see
 * routes/pipeline-validate.js) then only fails the run on issues NOT in
 * that saved set, letting a large codebase adopt Ignite incrementally
 * instead of needing every historical finding fixed/overridden on day one.
 *
 * @param {import('express').Express} app
 * @param {object} deps
 * @param {object} deps.store - db-store.js instance
 */
function mountBaselineRoutes(app, { store }) {
  app.post('/api/baseline/:org/:repo', (req, res) => {
    const { org, repo } = req.params;
    const issueIds = Array.isArray(req.body?.issueIds) ? req.body.issueIds.map(String) : null;
    if (!issueIds) {
      return res.status(400).json({ error: 'Request body must include issueIds: string[] — typically the `issues[].id` list from a prior validate-all response.' });
    }
    const saved = store.saveBaseline(org, repo, issueIds);
    res.json({ ok: true, org, repo, savedCount: saved });
  });

  app.get('/api/baseline/:org/:repo', (req, res) => {
    const { org, repo } = req.params;
    const ids = [...store.getBaselineIssueIds(org, repo)];
    res.json({ ok: true, org, repo, issueIds: ids, count: ids.length });
  });

  app.delete('/api/baseline/:org/:repo', (req, res) => {
    const { org, repo } = req.params;
    const removed = store.clearBaseline(org, repo);
    res.json({ ok: true, org, repo, removed });
  });
}

module.exports = { mountBaselineRoutes };
