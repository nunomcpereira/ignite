'use strict';

/**
 * Review-gate resolution (proceed/stop + inline overrides on a paused
 * interactive run) and "Effectivate" (turn a completed dryRun simulation
 * into the real thing — provisions and pushes the exact snapshot that was
 * already validated, without re-running phases 1-5). Phase F of the
 * server.js module split (see
 * /Users/nuno/.claude/plans/cuddly-roaming-pearl.md).
 *
 * @param {import('express').Express} app
 * @param {object} deps
 * @param {object} deps.store
 * @param {object} deps.auth
 * @param {object} deps.reviewDecisions
 * @param {Map} deps.pendingEffectivations
 * @param {Function} deps.cleanupExpiredEffectivations
 * @param {Function} deps.resolveActor
 * @param {Function} deps.validateOverrides - override-engine.js
 * @param {Function} deps.recordOverrides - server.js (persist + notify)
 * @param {Function} deps.cloneDirectoryWithoutSymlinks - server.js
 * @param {Function} deps.archivePhase6Payload - lib/shipping.js's createShipping() result
 * @param {Function} deps.shipToGitHub - lib/shipping.js's createShipping() result
 * @param {object} deps.phaseTitles - PHASE_TITLES
 */
function mountReviewGateRoutes(app, {
  store, auth, reviewDecisions, pendingEffectivations, cleanupExpiredEffectivations,
  resolveActor, validateOverrides, recordOverrides, cloneDirectoryWithoutSymlinks,
  archivePhase6Payload, shipToGitHub, phaseTitles,
}) {
  const fsp = require('fs/promises');

  app.post('/api/pipeline/:jobId/review-decision', (req, res) => {
    const jobId = String(req.params.jobId || '').trim();
    const proceed = req.body?.proceed === true;
    const overrides = Array.isArray(req.body?.overrides) ? req.body.overrides : [];

    let actor = null;
    if (overrides.length > 0) {
      actor = resolveActor(req);
      if (!actor) {
        return res.status(401).json({ error: 'Log in, or provide actor {email,name}, to submit overrides.' });
      }
    }

    const ok = reviewDecisions.resolve(jobId, {
      proceed,
      overrides,
      actor,
      reason: proceed ? 'user-continue' : 'user-stop',
    });
    if (!ok) return res.status(404).json({ error: 'No pending review decision for this job.' });
    res.json({ ok: true });
  });

  // Turns a completed simulation (dryRun) into the real thing: provisions and
  // pushes the exact snapshot that was already validated, without re-running
  // phases 1-5. Still hard-gated on any blocking finding that hasn't been
  // justified — same rule as the live review gate, just re-checked here
  // against the project's current (possibly since-updated) issue list.
  app.post('/api/projects/:projectId/effectivate', async (req, res) => {
    const projectId = Number(req.params.projectId);
    if (!Number.isInteger(projectId)) return res.status(400).json({ error: 'Invalid project id.' });

    const ghToken =
      auth.resolveGithubToken(req);
    if (!ghToken) {
      return res.status(401).json({
        error: req.user
          ? 'Connect your GitHub account before effectivating (GET /api/auth/github/connect).'
          : 'Log in and connect your GitHub account before effectivating.',
      });
    }

    cleanupExpiredEffectivations();
    const pending = pendingEffectivations.get(projectId);
    if (!pending) {
      return res.status(404).json({ error: 'No simulation output available to effectivate for this project (missing, expired, or already effectivated).' });
    }

    const issues = store.getProjectIssues(projectId);
    // Issues already justified at the live review gate (during the
    // simulation itself) are already `status: 'overridden'` in the DB — don't
    // demand a second justification for those here, only for ones still open.
    const stillOpen = issues.filter((i) => i.status !== 'overridden');
    const requestedOverrides = Array.isArray(req.body?.overrides) ? req.body.overrides : [];
    const { ok, unresolvedErrors, applied } = validateOverrides(stillOpen, requestedOverrides);

    if (!ok) {
      return res.status(409).json({
        error: `${unresolvedErrors.length} blocking finding(s) still need to be checked + justified before this simulation can be effectivated.`,
        needsReview: true,
        issues,
      });
    }

    let actor = null;
    if (applied.length > 0) {
      actor = resolveActor(req);
      if (!actor) {
        return res.status(401).json({ error: 'Log in, or provide actor {email,name}, to submit overrides.', needsReview: true, issues });
      }
    }

    const { org, repo, sourceBackupDir } = pending;
    const publishDir = sourceBackupDir + '-effectivate-publish';
    const effectivateLogs = ['Effectivating simulation — provisioning + pushing the previously validated snapshot.'];
    const log = (message) => {
      effectivateLogs.push(message);
      try { store.upsertStep(projectId, 6, phaseTitles[6], 'running', effectivateLogs.join('\n')); } catch { /* best-effort */ }
    };

    try {
      const backupStat = await fsp.stat(sourceBackupDir).catch(() => null);
      if (!backupStat || !backupStat.isDirectory()) {
        pendingEffectivations.delete(projectId);
        return res.status(410).json({ error: 'Simulation snapshot is no longer available (expired or already effectivated). Re-run the simulation to try again.' });
      }

      if (applied.length > 0) {
        const byPhase = new Map();
        for (const item of applied) {
          const p = item.issue.phase;
          if (!byPhase.has(p)) byPhase.set(p, []);
          byPhase.get(p).push(item);
        }
        for (const [p, group] of byPhase) {
          await recordOverrides({ projectId, jobId: `effectivate-${projectId}`, org, repo, phase: p, actor, applied: group });
        }
        store.replaceProjectIssues(projectId, issues, applied.map(({ issue }) => issue.id).concat(
          issues.filter((i) => i.status === 'overridden').map((i) => i.id)
        ));
      }

      await fsp.rm(publishDir, { recursive: true, force: true }).catch(() => {});
      await cloneDirectoryWithoutSymlinks(sourceBackupDir, publishDir);
      await archivePhase6Payload(publishDir, projectId, log);
      const { repoUrl, prUrl } = await shipToGitHub(publishDir, org, repo, log, ghToken);

      store.finishProject('success', null, repoUrl, prUrl || null, projectId);
      effectivateLogs.push(`✓ Effectivated — repository live at ${repoUrl}`);
      store.upsertStep(projectId, 6, phaseTitles[6], 'success', effectivateLogs.join('\n'));
      pendingEffectivations.delete(projectId);
      await fsp.rm(sourceBackupDir, { recursive: true, force: true }).catch(() => {});
      await fsp.rm(publishDir, { recursive: true, force: true }).catch(() => {});
      res.json({ ok: true, repoUrl, prUrl });
    } catch (e) {
      effectivateLogs.push(`✗ Effectivate failed: ${e.message}`);
      store.upsertStep(projectId, 6, phaseTitles[6], 'failed', effectivateLogs.join('\n'));
      res.status(502).json({ error: `Effectivate failed: ${e.message}` });
    }
  });
}

module.exports = { mountReviewGateRoutes };
