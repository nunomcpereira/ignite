'use strict';

/**
 * POST /api/pipeline/onboard — full onboarding pipeline from a project
 * already on the local filesystem (no multipart upload) — the endpoint for
 * agent/MCP callers that want the real outcome: phases 1-5 exactly as
 * validate-all, and, if everything passes, phase 6 provisioning + push,
 * same as the browser-driven /api/pipeline. Set `dryRun: true` to get
 * validate-all's behavior (skip the push) from this same request shape.
 * Phase F of the server.js module split (see
 * /Users/nuno/.claude/plans/cuddly-roaming-pearl.md).
 *
 * @param {import('express').Express} app
 * @param {object} deps
 * @param {object} deps.store
 * @param {object} deps.auth
 * @param {object} deps.phaseEnabled - PHASE_ENABLED
 * @param {object} deps.phaseTitles - PHASE_TITLES
 * @param {RegExp} deps.repoNameRegex - REPO_NAME_REGEX
 * @param {RegExp} deps.githubNameRegex - GITHUB_NAME_REGEX
 * @param {string} deps.actEvent - ACT_EVENT
 * @param {Function} deps.sanitizeAbsoluteProjectPath
 * @param {Function} deps.resolveRequestSource
 * @param {Function} deps.stageExistingProject
 * @param {Function} deps.resolveProjectRoot
 * @param {Function} deps.cloneDirectoryWithoutSymlinks
 * @param {Function} deps.checkEnvFiles
 * @param {Function} deps.checkCodeowners
 * @param {Function} deps.runProjectUnitTests
 * @param {Function} deps.runLicenseComplianceCheck
 * @param {Function} deps.runDependencyVulnerabilityCheck
 * @param {Function} deps.runPhase4Checks
 * @param {Function} deps.validateOverrides
 * @param {Function} deps.resolveActor
 * @param {Function} deps.recordOverrides
 * @param {Function} deps.actTooling
 * @param {Function} deps.fetchGovernanceWorkflow
 * @param {Function} deps.runActionsLocally
 * @param {Function} deps.archivePhase6Payload
 * @param {Function} deps.shipToGitHub
 */
function mountOnboardRoute(app, {
  store, auth, phaseEnabled, phaseTitles, repoNameRegex, githubNameRegex, actEvent,
  sanitizeAbsoluteProjectPath, resolveRequestSource, stageExistingProject, resolveProjectRoot,
  cloneDirectoryWithoutSymlinks, checkEnvFiles, checkCodeowners, runProjectUnitTests,
  runLicenseComplianceCheck, runDependencyVulnerabilityCheck, runPhase4Checks, validateOverrides,
  resolveActor, recordOverrides, actTooling, fetchGovernanceWorkflow, runActionsLocally,
  archivePhase6Payload, shipToGitHub,
}) {
  const fsp = require('fs/promises');
  const path = require('path');
  const os = require('os');
  const crypto = require('crypto');

  app.post('/api/pipeline/onboard', async (req, res) => {
    const body = req.body || {};
    const org = String(body.org || '').trim();
    const repo = String(body.repo || '').trim();
    // Phase 2 disabled by config (default) means GxP isn't a concept this
    // Ignite install offers at all — a caller passing gxp:true anyway is
    // ignored rather than honored, matching "hidden and therefore not checked".
    const isGxp = phaseEnabled[2] && body.gxp === true;
    const runLocalCi = body.runLocalCi !== false;
    const dryRun = body.dryRun === true;
    const warningDecision = String(body.warningDecision || 'continue').toLowerCase();
    const projectPath = sanitizeAbsoluteProjectPath(body.projectPath || process.cwd());
    const gxpLinks = Array.isArray(body.gxpLinks) ? body.gxpLinks : [];
    const requestedOverrides = Array.isArray(body.overrides) ? body.overrides : [];

    // Provisioning (Phase 6) must run as the actual caller's own GitHub
    // account, not a shared host-level `gh auth login` session — fail fast
    // rather than burning phases 1-5 only to find this out at the finish line.
    const ghToken = dryRun ? null : auth.resolveGithubToken(req);
    if (!dryRun && !ghToken) {
      return res.status(401).json({
        error: req.user
          ? 'Connect your GitHub account before onboarding for real (GET /api/auth/github/connect), or pass dryRun: true.'
          : 'Log in and connect your GitHub account before onboarding for real, or pass dryRun: true.',
      });
    }

    const jobId = crypto.randomUUID();
    const stagingDir = path.join(os.tmpdir(), 'gatekeeper-staging', `${jobId}-onboard`);
    const sourceBackupDir = stagingDir + '-source-backup';
    const publishDir = stagingDir + '-publish';
    const workflowDir = stagingDir + '-workflows';
    let projectId = null;

    const events = [];
    const record = {};
    const rec = (phase) => (record[phase] ??= { state: 'pending', logs: [] });
    const persistPhase = (phase) => {
      if (projectId === null) return;
      const ph = rec(phase);
      try {
        store.upsertStep(projectId, phase, phaseTitles[phase], ph.state, ph.logs.join('\n'));
      } catch {
        // Live history persistence is best-effort.
      }
    };
    const phaseLog = (phase) => (message) => {
      rec(phase).logs.push(message);
      events.push({ type: 'log', phase, message });
      persistPhase(phase);
    };

    let currentPhase = 1;
    const status = (phase, state, extra = {}) => {
      if (state === 'running') currentPhase = phase;
      rec(phase).state = state;
      events.push({ type: 'status', phase, state, ...extra });
      persistPhase(phase);
    };

    const phaseSummary = () => Object.keys(phaseTitles)
      .map((id) => {
        const ph = record[id] || { state: 'pending', logs: [] };
        return {
          phase: Number(id),
          title: phaseTitles[id],
          state: ph.state,
          logs: ph.logs,
        };
      });

    try {
      status(1, 'running');
      const log1 = phaseLog(1);

      if (!githubNameRegex.test(org)) {
        throw Object.assign(new Error(`Invalid GitHub organization name: "${org}"`), { phase: 1 });
      }
      if (!repoNameRegex.test(repo) || repo === '.' || repo === '..') {
        throw Object.assign(new Error(`Invalid repository name: "${repo}"`), { phase: 1 });
      }

      log1(`Onboarding job ${jobId}`);
      log1(`Source project path: ${projectPath}`);
      log1(`Target: ${org}/${repo} (private)`);
      log1(`GxP-regulated process: ${isGxp ? 'YES' : 'no'}`);
      if (dryRun) log1('Simulation mode (dryRun) — phase 6 provisioning/push will be skipped.');
      projectId = store.createProject(jobId, org, repo, isGxp, resolveRequestSource(req, 'api'));
      for (const id of Object.keys(record)) persistPhase(Number(id));
      status(1, 'success');

      if (!isGxp) {
        phaseLog(2)('Process declared non-GxP — no validation documents required.');
        status(2, 'skipped');
      } else {
        status(2, 'running');
        const logG = phaseLog(2);
        const validLinks = [];
        for (const l of gxpLinks) {
          const url = String(l?.url || '').trim();
          let parsed = null;
          try { parsed = new URL(url); } catch { /* invalid */ }
          if (!parsed || !['http:', 'https:'].includes(parsed.protocol)) {
            throw Object.assign(new Error(`Invalid GxP document link: "${url}" (must be http/https).`), { phase: 2 });
          }
          validLinks.push({ url, name: String(l?.name || '').trim() || parsed.hostname + parsed.pathname });
        }
        if (validLinks.length === 0) {
          throw Object.assign(new Error('GxP process declared but no gxpLinks provided in API payload.'), { phase: 2 });
        }
        for (const link of validLinks) {
          store.addLinkDocument(projectId, link.name, link.url);
        }
        logG(`Received ${validLinks.length} GxP document link(s) for validation context.`);
        status(2, 'success');
      }

      status(3, 'running');
      const log2 = phaseLog(3);
      await stageExistingProject(projectPath, stagingDir, log2);
      const projectRoot = await resolveProjectRoot(stagingDir);

      await cloneDirectoryWithoutSymlinks(projectRoot, sourceBackupDir);
      log2('Created immutable source snapshot for final publish phase.');

      // License compliance runs first — same ordering rationale as the
      // interactive and validate-all pipelines: the checks below throw.
      const licenseIssues = [
        ...await runLicenseComplianceCheck(projectRoot, log2),
        ...await runDependencyVulnerabilityCheck(projectRoot, log2),
      ];

      log2('Check 1 — scanning for raw environment files (.env*)...');
      const envCheck = await checkEnvFiles(projectRoot);
      if (envCheck.ignored.length > 0) {
        log2(`ℹ ${envCheck.ignored.length} .env file(s) found but already excluded by this project's .gitignore — not blocking: ${envCheck.ignored.join(', ')}`);
      }
      if (envCheck.blocking.length > 0) {
        log2(`✗ ${envCheck.blocking.length} forbidden environment file(s) found:`);
        envCheck.blocking.forEach((f) => log2(`    ✗ ${f}`));
        throw Object.assign(
          new Error(`Raw environment files detected (${envCheck.blocking.length}). Remove them before onboarding.`),
          { phase: 3 }
        );
      }
      log2('✓ Check 1 passed — no raw environment files present.');
      log2('Check 2 — checking for a CODEOWNERS file...');
      const codeownersCheck = await checkCodeowners(projectRoot);
      log2(codeownersCheck.found
        ? `✓ CODEOWNERS found at ${codeownersCheck.path} (${codeownersCheck.emails.length} contact email(s)).`
        : 'ℹ No CODEOWNERS file found (advisory — checked root, .github/, docs/).');
      await runProjectUnitTests(projectRoot, log2);
      status(3, 'success');

      status(4, 'running');
      const log3 = phaseLog(4);
      let issues = [...licenseIssues];
      if (!phaseEnabled[4]) {
        log3('Skipped — disabled by config (phases: [{ id: 4, enabled: false }]).');
      } else {
        const phase4 = await runPhase4Checks(projectRoot, log3, { org, repo, projectId, store });
        // Studio's rescan-diffing (replacePhase4) keys off issue.phase === 4 to
        // know which persisted rows to replace — collectPhase4Issues doesn't
        // set it itself, so it has to be stamped here before persisting.
        issues = [...phase4.issues.map((i) => ({ ...i, phase: 4 })), ...licenseIssues];
      }
      // Persisted as soon as they're known — including the per-file/line
      // detail (file, line, summary, snippet) collectPhase4Issues carries —
      // so this run's "N issues" entry in the recent-projects list is
      // populated even if phase 4's override gate below throws and the run
      // never reaches provisioning. Re-persisted after overrides are applied
      // (see below) so overridden issues flip to status 'overridden' instead
      // of staying 'open'.
      let appliedOverrideIds = [];
      if (projectId !== null) {
        try { store.replaceProjectIssues(projectId, issues, appliedOverrideIds); } catch { /* best-effort */ }
      }
      const errorIssues = issues.filter((i) => i.severity === 'error');

      const issuesRequiringOverride =
        warningDecision === 'continue' ? errorIssues : issues;

      if (issuesRequiringOverride.length > 0) {
        const { ok, unresolvedErrors, applied } = validateOverrides(issuesRequiringOverride, requestedOverrides);
        if (applied.length > 0) {
          const actor = resolveActor(req);
          if (!actor) {
            throw Object.assign(
              new Error('Overrides were submitted but no authenticated user or actor {email,name} was provided — cannot attribute the audit record.'),
              { phase: 4 }
            );
          }
          log3(`⚠ ${applied.length} flagged issue(s) overridden by ${actor.email}:`);
          applied.forEach(({ issue, justification }) => log3(`    ⚠ [override] [${issue.severity}] ${issue.file}:${issue.line} — ${issue.summary} — "${justification}"`));
          await recordOverrides({ projectId, jobId, org, repo, phase: 4, actor, applied });
          appliedOverrideIds = applied.map(({ issue }) => issue.id);
          if (projectId !== null) {
            try { store.replaceProjectIssues(projectId, issues, appliedOverrideIds); } catch { /* best-effort */ }
          }
        }
        if (!ok) {
          log3(`✗ ${unresolvedErrors.length} blocking finding(s) were not overridden:`);
          unresolvedErrors.forEach((issue) =>
            log3(`    ✗ [${issue.category}] ${issue.file ? issue.file + (issue.line ? ':' + issue.line : '') : 'Phase 4'} — ${issue.summary}`)
          );
          throw Object.assign(
            new Error(`Phase 4 has ${unresolvedErrors.length} unresolved blocking finding(s). Submit an override with a justification for each, or fix them.`),
            // Carried through to the response below so a non-browser caller
            // (the CLI/pre-push hook) can list and override these without
            // ever needing the web UI's review gate.
            { phase: 4, issues: unresolvedErrors }
          );
        }
      }
      status(4, 'success');

      status(5, 'running');
      const log4 = phaseLog(5);
      if (!phaseEnabled[5]) {
        log4('Skipped — disabled by config (phases: [{ id: 5, enabled: false }]).');
        log4('⚠ The org governance workflows will still gate the repo on GitHub after push.');
        status(5, 'skipped');
      } else if (!runLocalCi) {
        log4('Local CI execution disabled by request (runLocalCi=false).');
        status(5, 'skipped');
      } else {
        const tooling = await actTooling();
        if (!tooling.ok) {
          log4(`⚠ Local CI skipped: ${tooling.reason}`);
          log4('⚠ The org governance workflows will still gate the repo on GitHub after push.');
          status(5, 'success');
        } else {
          const wfFile = await fetchGovernanceWorkflow(workflowDir, log4);
          log4(`Executing org governance workflows locally with act (event: ${actEvent}).`);
          await runActionsLocally(projectRoot, wfFile, log4);
          log4('✓ All org governance jobs passed locally.');
          status(5, 'success');
        }
      }

      let repoUrl = null;
      let prUrl = null;
      if (dryRun) {
        const log5 = phaseLog(6);
        log5('Simulation mode (dryRun) — all checks passed; skipping repository provisioning and push.');
        status(6, 'skipped');
        if (projectId !== null) {
          store.finishProject('success', null, null, null, projectId);
        }
      } else {
        status(6, 'running');
        const log5 = phaseLog(6);

        const backupStat = await fsp.stat(sourceBackupDir).catch(() => null);
        if (!backupStat || !backupStat.isDirectory()) {
          throw Object.assign(new Error('Immutable source snapshot is missing before phase 6.'), { phase: 6 });
        }
        await fsp.rm(publishDir, { recursive: true, force: true }).catch(() => {});
        await cloneDirectoryWithoutSymlinks(sourceBackupDir, publishDir);
        log5('Prepared clean publish workspace from immutable source snapshot.');

        await archivePhase6Payload(publishDir, projectId, log5);

        ({ repoUrl, prUrl } = await shipToGitHub(publishDir, org, repo, log5, ghToken));
        log5(`✓ Repository live at ${repoUrl}`);
        status(6, 'success', { repoUrl, prUrl });

        if (projectId !== null) {
          store.finishProject('success', null, repoUrl, prUrl || null, projectId);
        }
      }

      return res.json({
        ok: true,
        mode: 'onboard',
        dryRun,
        jobId,
        projectPath,
        repoUrl,
        prUrl,
        phases: phaseSummary(),
        events,
      });
    } catch (err) {
      const phase = err.phase || currentPhase;
      phaseLog(phase)(`✗ ${err.message}`);
      status(phase, 'failed', { error: err.message });
      if (projectId !== null) {
        try { store.finishProject('failed', err.message, null, null, projectId); } catch { /* best-effort */ }
      }
      return res.status(400).json({
        ok: false,
        mode: 'onboard',
        dryRun,
        jobId,
        projectPath,
        error: err.message,
        failedPhase: phase,
        // Unresolved Phase 4 issues (see the throw above), when this is that
        // kind of failure — lets a non-browser caller (the CLI/pre-push hook)
        // list and override them without the web UI's review gate.
        issues: Array.isArray(err.issues) ? err.issues : undefined,
        phases: phaseSummary(),
        events,
      });
    } finally {
      await fsp.rm(stagingDir, { recursive: true, force: true }).catch(() => {});
      await fsp.rm(sourceBackupDir, { recursive: true, force: true }).catch(() => {});
      await fsp.rm(publishDir, { recursive: true, force: true }).catch(() => {});
      await fsp.rm(workflowDir, { recursive: true, force: true }).catch(() => {});
    }
  });
}

module.exports = { mountOnboardRoute };
