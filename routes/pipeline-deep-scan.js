'use strict';

/**
 * POST /api/pipeline/deep-scan — streaming NDJSON, the same scan set as
 * POST /api/pipeline/validate-all (phases 1/3/4/5 — structure audit, unit
 * tests, the full phase-4 check set, and org governance CI via `act`) plus
 * CodeQL cross-file static analysis on top (`runPhase4Checks(...,
 * { deepScan: true })`). Never phase 6 — this endpoint never provisions or
 * pushes anything.
 *
 * Deliberately separate from validate-all in two ways:
 *   1. Source of the code to scan: `projectPath` (a local folder, for a
 *      brand-new/not-yet-pushed repo) OR, when omitted, a fresh shallow
 *      `git clone` of `org`/`repo` from GitHub (an already-onboarded repo —
 *      Ignite keeps no pushed repo's files on disk, see the hardening
 *      invariants, so this reuses lib/shipping.js's `gh auth
 *      git-credential` helper trick rather than plumbing a separate token).
 *   2. Diagnostic, not gating: always resolves `{ ok: true, issues }` —
 *      including blocking `error` issues — rather than 400ing on unresolved
 *      overrides the way validate-all does. A scheduled/background caller
 *      has no one present to submit an override against; overrides on the
 *      returned issues go through the normal Studio flow afterward, same
 *      audit trail as any other phase-4 issue.
 *
 * A CodeQL database build can take minutes per language, so — unlike
 * validate-all/onboard/the interactive pipeline, all of which a developer
 * or CI run is actively waiting on — this endpoint is meant to be called
 * from the in-app scheduler (already-onboarded repos, on a cadence) or as
 * an explicit pre-push gate a caller opts into for a brand-new repo, never
 * silently substituted for the fast pipeline.
 *
 * @param {import('express').Express} app
 * @param {object} deps
 * @param {object} deps.store
 * @param {object} deps.phaseTitles - PHASE_TITLES
 * @param {object} deps.phaseEnabled - PHASE_ENABLED
 * @param {RegExp} deps.repoNameRegex - REPO_NAME_REGEX
 * @param {RegExp} deps.githubNameRegex - GITHUB_NAME_REGEX
 * @param {string} deps.actEvent - ACT_EVENT
 * @param {Function} deps.sanitizeAbsoluteProjectPath
 * @param {Function} deps.stageExistingProject
 * @param {Function} deps.resolveProjectRoot
 * @param {Function} deps.checkEnvFiles
 * @param {Function} deps.checkCodeowners
 * @param {Function} deps.runProjectUnitTests
 * @param {Function} deps.runLicenseComplianceCheck
 * @param {Function} deps.runDependencyVulnerabilityCheck
 * @param {Function} deps.runPhase4Checks
 * @param {Function} deps.actTooling
 * @param {Function} deps.fetchGovernanceWorkflow
 * @param {Function} deps.runActionsLocally
 * @param {Function} deps.runTool - from lib/tool-runner.js's createToolRunner(), for the clone-from-GitHub path
 */
function mountDeepScanRoute(app, {
  store, phaseTitles, phaseEnabled, repoNameRegex, githubNameRegex, actEvent,
  sanitizeAbsoluteProjectPath, stageExistingProject, resolveProjectRoot,
  checkEnvFiles, checkCodeowners, runProjectUnitTests, runLicenseComplianceCheck,
  runDependencyVulnerabilityCheck, runPhase4Checks, actTooling, fetchGovernanceWorkflow,
  runActionsLocally, runTool,
}) {
  const fsp = require('fs/promises');
  const path = require('path');
  const os = require('os');
  const crypto = require('crypto');

  // Same credential-helper flags as lib/shipping.js's push path: gh as a
  // one-shot, non-interactive credential helper (no separate token
  // plumbing needed here), never a persistent git config change.
  const GIT_CRED_ARGS = ['-c', 'credential.helper=', '-c', 'credential.helper=!gh auth git-credential', '-c', 'core.askPass='];

  async function cloneRepoForDeepScan(org, repo, destDir, log) {
    const remoteUrl = `https://github.com/${org}/${repo}.git`;
    log(`$ git clone --depth 1 "${remoteUrl}"`);
    await runTool('git', [...GIT_CRED_ARGS, 'clone', '--depth', '1', remoteUrl, destDir], os.tmpdir());
  }

  app.post('/api/pipeline/deep-scan', async (req, res) => {
    res.setHeader('Content-Type', 'application/x-ndjson');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('X-Accel-Buffering', 'no');
    const send = (event) => res.write(JSON.stringify(event) + '\n');

    const body = req.body || {};
    const org = String(body.org || '').trim();
    const repo = String(body.repo || '').trim();
    const runLocalCi = body.runLocalCi !== false;
    const hasLocalPath = typeof body.projectPath === 'string' && body.projectPath.trim() !== '';
    const projectPath = hasLocalPath ? sanitizeAbsoluteProjectPath(body.projectPath) : null;

    const jobId = crypto.randomUUID();
    const stagingDir = path.join(os.tmpdir(), 'gatekeeper-staging', `${jobId}-deep-scan`);
    const workflowDir = stagingDir + '-workflows';
    let projectId = null;

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
      send({ type: 'log', phase, message });
      persistPhase(phase);
    };
    const status = (phase, state, extra = {}) => {
      rec(phase).state = state;
      send({ type: 'status', phase, state, ...extra });
      persistPhase(phase);
    };

    const phaseSummary = () => Object.keys(phaseTitles)
      .map((id) => {
        const ph = record[id] || { state: 'pending', logs: [] };
        return { phase: Number(id), title: phaseTitles[id], state: ph.state, logs: ph.logs };
      });

    try {
      status(1, 'running');
      const log1 = phaseLog(1);
      if (!repoNameRegex.test(repo) || repo === '.' || repo === '..') {
        throw new Error(`Invalid repository name: "${repo}"`);
      }
      if (!githubNameRegex.test(org)) {
        throw new Error(`Invalid organization name: "${org}"`);
      }
      log1(`Deep scan job ${jobId} — target ${org}/${repo}`);
      // 'deep-scan' as a project-history source distinguishes these runs
      // from ui/api/mcp-triggered onboarding in the same projects list —
      // db-store.js's `source` column is free text, no enum to extend.
      projectId = store.createProject(jobId, org, repo, false, 'deep-scan');
      status(1, 'success');
      rec(2).state = 'skipped';
      phaseLog(2)('GxP validation not applicable to a deep scan.');
      status(2, 'skipped');

      status(3, 'running');
      const log2 = phaseLog(3);
      if (hasLocalPath) {
        log2(`Source project path: ${projectPath}`);
        await stageExistingProject(projectPath, stagingDir, log2);
      } else {
        log2(`No projectPath given — cloning ${org}/${repo} from GitHub for the deep scan (already-onboarded repo / scheduled run).`);
        await cloneRepoForDeepScan(org, repo, stagingDir, log2);
      }
      const projectRoot = await resolveProjectRoot(stagingDir);

      log2('Check 1 — scanning for raw environment files (.env*)...');
      const envCheck = await checkEnvFiles(projectRoot);
      if (envCheck.ignored.length > 0) {
        log2(`ℹ ${envCheck.ignored.length} .env file(s) found but already excluded by this project's .gitignore — not blocking: ${envCheck.ignored.join(', ')}`);
      }
      if (envCheck.blocking.length > 0) {
        log2(`✗ ${envCheck.blocking.length} forbidden environment file(s) found: ${envCheck.blocking.join(', ')}`);
      } else {
        log2('✓ Check 1 passed — no raw environment files present.');
      }
      log2('Check 2 — checking for a CODEOWNERS file...');
      const codeownersCheck = await checkCodeowners(projectRoot);
      log2(codeownersCheck.found
        ? `✓ CODEOWNERS found at ${codeownersCheck.path} (${codeownersCheck.emails.length} contact email(s)).`
        : 'ℹ No CODEOWNERS file found (advisory — checked root, .github/, docs/).');
      await runProjectUnitTests(projectRoot, log2);
      status(3, 'success');

      status(4, 'running');
      const log3 = phaseLog(4);
      let issues = [];
      if (!phaseEnabled[4]) {
        log3('Skipped — disabled by config (phases: [{ id: 4, enabled: false }]).');
        log2('Check 3 — dependency & license compliance scan (manifests + LICENSE files)...');
        issues = [
          ...await runLicenseComplianceCheck(projectRoot, log2),
          ...await runDependencyVulnerabilityCheck(projectRoot, log2),
        ];
      } else {
        log2('Check 3 — dependency & license compliance scan (manifests + LICENSE files)...');
        const [licenseIssues, phase4] = await Promise.all([
          (async () => [
            ...await runLicenseComplianceCheck(projectRoot, log2),
            ...await runDependencyVulnerabilityCheck(projectRoot, log2),
          ])(),
          runPhase4Checks(projectRoot, log3, { org, repo, projectId, store, deepScan: true }),
        ]);
        issues = [...phase4.issues, ...licenseIssues];
      }
      const errorCount = issues.filter((i) => i.severity === 'error').length;
      if (errorCount > 0) {
        log3(`⚠ ${errorCount} blocking finding(s) — deep scan is diagnostic-only and does not gate on them. Review and override via Studio.`);
      }
      status(4, 'success');

      status(5, 'running');
      const log4 = phaseLog(5);
      if (!phaseEnabled[5]) {
        log4('Skipped — disabled by config (phases: [{ id: 5, enabled: false }]).');
        status(5, 'skipped');
      } else if (!runLocalCi) {
        log4('Local CI execution disabled by request (runLocalCi=false).');
        status(5, 'skipped');
      } else {
        const tooling = await actTooling();
        if (!tooling.ok) {
          log4(`⚠ Local CI skipped: ${tooling.reason}`);
          status(5, 'skipped');
        } else {
          const wfFile = await fetchGovernanceWorkflow(workflowDir, log4);
          log4(`Executing org governance workflows locally with act (event: ${actEvent}).`);
          try {
            await runActionsLocally(projectRoot, wfFile, log4);
            log4('✓ All org governance jobs passed locally.');
            status(5, 'success');
          } catch (e) {
            log4(`✗ ${e.message}`);
            status(5, 'failed', { error: e.message });
          }
        }
      }

      rec(6).state = 'skipped';
      phaseLog(6)('Shipping phase skipped — deep scan never provisions or pushes.');
      status(6, 'skipped');

      log3(`Deep scan complete — ${issues.length} total issue(s), ${errorCount} blocking.`);
      store.finishProject('success', null, null, null, projectId);
      send({ type: 'done', ok: true, jobId, org, repo, issues, phases: phaseSummary() });
    } catch (err) {
      const phase = err.phase || 1;
      phaseLog(phase)(`✗ ${err.message}`);
      status(phase, 'failed', { error: err.message });
      if (projectId !== null) {
        try { store.finishProject('failed', err.message, null, null, projectId); } catch { /* best-effort */ }
      }
      send({ type: 'done', ok: false, jobId, org, repo, error: err.message, phases: phaseSummary() });
    } finally {
      res.end();
      await fsp.rm(stagingDir, { recursive: true, force: true }).catch(() => {});
      await fsp.rm(workflowDir, { recursive: true, force: true }).catch(() => {});
    }
  });
}

module.exports = { mountDeepScanRoute };
