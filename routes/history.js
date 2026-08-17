'use strict';

/**
 * Onboarding history: project list, per-project steps + documents, document
 * download, and the effectivated-repo scheduling toggle. Document blobs
 * never leave the DB except via download. Phase F of the server.js module
 * split (see /Users/nuno/.claude/plans/cuddly-roaming-pearl.md).
 *
 * @param {import('express').Express} app
 * @param {object} deps
 * @param {object} deps.store - db-store.js instance
 * @param {object} deps.auth - auth.js instance (requireAuth)
 * @param {Map} deps.runningRuns - server.js's in-flight SSE pipeline job map
 * @param {Set} deps.scheduleIntervals - SCHEDULE_INTERVALS (lib/scheduled-rechecks.js)
 * @param {Function} deps.computeNextRunAt - lib/scheduled-rechecks.js's createScheduledRechecks() result
 */
function mountHistoryRoutes(app, { store, auth, runningRuns, scheduleIntervals, computeNextRunAt }) {
  app.get('/api/projects', (req, res) => {
    res.json(store.listProjects());
  });

  // "Effectivated" repos: projects that actually shipped (a real repo_url from
  // a successful run — see the /effectivate endpoint, elsewhere, which is the
  // other place a project earns this same status). Each can opt into a
  // recurring re-check of its default branch — see the scheduler below.
  //
  // Registered before the /:id route below on purpose — a pre-existing bug
  // (present since before this module split, verified against the
  // pre-refactor server.js) had this literal-segment route registered much
  // later in the file than /api/projects/:id, so Express always matched
  // /:id first (with id="effectivated", failing the Number() check) and
  // this endpoint was unreachable. Discovered live during this batch's
  // smoke test, fixed here since it's a one-line reordering directly in the
  // file already being restructured — not otherwise part of the module
  // split's scope.
  app.get('/api/projects/effectivated', (req, res) => {
    res.json({ projects: store.listEffectivatedProjects() });
  });

  app.get('/api/projects/:id', (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid project id.' });
    const project = store.getProjectDetails(id);
    if (!project) return res.status(404).json({ error: 'Project not found.' });
    res.json(project);
  });

  // Flagged issues for one project — same shape whether the run is still in
  // progress (read from the live in-memory pipeline state) or long finished
  // (read from the `issues` table), so the UI can show the list at any time.
  app.get('/api/projects/:id/issues', (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid project id.' });
    if (!store.projectExists(id)) return res.status(404).json({ error: 'Project not found.' });
    res.json({ ok: true, issues: store.getProjectIssues(id) });
  });

  // Same, but addressable by the in-flight job id while a pipeline is still
  // streaming — lets the UI show the issue list mid-run, before Phase 6.
  app.get('/api/pipeline/:jobId/issues', (req, res) => {
    const jobId = String(req.params.jobId || '').trim();
    const live = runningRuns.get(jobId);
    if (live) {
      return res.json({ ok: true, running: true, issues: live.allIssues, projectId: live.projectId });
    }
    const projectId = store.getProjectIdByJobId(jobId);
    if (projectId === null) return res.status(404).json({ error: 'Unknown job id.' });
    res.json({ ok: true, running: false, issues: store.getProjectIssues(projectId), projectId });
  });

  app.delete('/api/projects/:id', (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid project id.' });
    if (!store.projectExists(id)) return res.status(404).json({ error: 'Project not found.' });
    store.deleteProjectById(id);
    res.json({ ok: true });
  });

  app.delete('/api/projects', (req, res) => {
    store.deleteAllProjects();
    res.json({ ok: true });
  });

  app.post('/api/projects/:id/schedule', auth.requireAuth, (req, res) => {
    const projectId = Number(req.params.id);
    if (!Number.isInteger(projectId)) return res.status(400).json({ error: 'Invalid project id.' });
    if (!store.projectExists(projectId)) return res.status(404).json({ error: 'Project not found.' });

    const enabled = Boolean(req.body?.enabled);
    const interval = String(req.body?.interval || '').toLowerCase();
    if (enabled && !scheduleIntervals.has(interval)) {
      return res.status(400).json({ error: `interval must be one of: ${[...scheduleIntervals].join(', ')}` });
    }
    const nextRunAt = enabled ? computeNextRunAt(interval) : null;
    store.setProjectSchedule(projectId, enabled, enabled ? interval : null, nextRunAt);
    res.json({ ok: true, enabled, interval: enabled ? interval : null, nextRunAt });
  });

  app.get('/api/documents/:id', (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid document id.' });
    const doc = store.getDocument(id);
    if (!doc) return res.status(404).json({ error: 'Document not found.' });
    if (doc.kind === 'link') return res.redirect(doc.url);
    res.setHeader('Content-Type', doc.mime || 'application/octet-stream');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename*=UTF-8''${encodeURIComponent(doc.name)}`
    );
    res.send(Buffer.from(doc.data));
  });
}

module.exports = { mountHistoryRoutes };
