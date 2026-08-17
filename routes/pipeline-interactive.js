'use strict';

/**
 * POST /api/pipeline — the browser UI's interactive pipeline: multipart
 * ZIP/folder upload, streaming NDJSON progress over the whole response,
 * pausing at a review gate (all issues from every phase shown together)
 * before phase 6 provisioning/push. Also mounts the trailing multer/
 * general error-handling middleware, which must be registered after every
 * other route. Phase F of the server.js module split (see
 * /Users/nuno/.claude/plans/cuddly-roaming-pearl.md).
 *
 * @param {import('express').Express} app
 * @param {object} deps
 * @param {Function} deps.upload - multer instance
 * @param {object} deps.store
 * @param {object} deps.auth
 * @param {object} deps.phaseEnabled - PHASE_ENABLED
 * @param {object} deps.phaseTitles - PHASE_TITLES
 * @param {RegExp} deps.repoNameRegex - REPO_NAME_REGEX
 * @param {RegExp} deps.githubNameRegex - GITHUB_NAME_REGEX
 * @param {string} deps.actEvent - ACT_EVENT
 * @param {Function} deps.scoreForIssue - override-engine.js
 * @param {Function} deps.resolveRequestSource
 * @param {Function} deps.extractZip
 * @param {Function} deps.stageDirectoryUpload
 * @param {Function} deps.resolveProjectRoot
 * @param {Function} deps.cloneDirectoryWithoutSymlinks
 * @param {Function} deps.runLicenseComplianceCheck
 * @param {Function} deps.runDependencyVulnerabilityCheck
 * @param {Function} deps.checkEnvFiles
 * @param {Function} deps.checkCodeowners
 * @param {Function} deps.runProjectUnitTests
 * @param {Function} deps.runPhase4Checks
 * @param {Function} deps.actTooling
 * @param {Function} deps.fetchGovernanceWorkflow
 * @param {Function} deps.runActionsLocally
 * @param {Function} deps.resolveGovernanceCiLocation
 * @param {Function} deps.filterGovernanceCiFailureLines
 * @param {object} deps.reviewDecisions
 * @param {Function} deps.validateOverrides
 * @param {Function} deps.recordOverrides
 * @param {Function} deps.archivePhase6Payload
 * @param {Function} deps.shipToGitHub
 * @param {Function} deps.generateFailureInsight
 * @param {Function} deps.sendFailureNotification
 * @param {Map} deps.runningRuns
 * @param {Map} deps.pendingEffectivations
 * @param {Function} deps.cleanupExpiredEffectivations
 */
function mountInteractivePipelineRoute(app, {
  upload, store, auth, phaseEnabled, phaseTitles, repoNameRegex, githubNameRegex, actEvent,
  scoreForIssue, resolveRequestSource, extractZip, stageDirectoryUpload, resolveProjectRoot,
  cloneDirectoryWithoutSymlinks, runLicenseComplianceCheck, runDependencyVulnerabilityCheck,
  checkEnvFiles, checkCodeowners, runProjectUnitTests, runPhase4Checks, actTooling,
  fetchGovernanceWorkflow, runActionsLocally, resolveGovernanceCiLocation, filterGovernanceCiFailureLines,
  reviewDecisions, validateOverrides, recordOverrides, archivePhase6Payload, shipToGitHub,
  generateFailureInsight, sendFailureNotification, runningRuns, pendingEffectivations,
  cleanupExpiredEffectivations,
}) {
  const fsp = require('fs/promises');
  const path = require('path');
  const os = require('os');
  const crypto = require('crypto');

  app.post(
    '/api/pipeline',
    upload.fields([
      { name: 'archive', maxCount: 1 },
      { name: 'files', maxCount: 5000 },
      { name: 'gxpDocs', maxCount: 50 },
    ]),
    async (req, res) => {
    res.setHeader('Content-Type', 'application/x-ndjson');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('X-Accel-Buffering', 'no');

    let projectId = null;
    const send = (event) => res.write(JSON.stringify(event) + '\n');
    // Server-side record of every phase's state and logs, for failure emails.
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
    let currentPhase = 1;
    const status = (phase, state, extra = {}) => {
      if (state === 'running') currentPhase = phase;
      rec(phase).state = state;
      send({ type: 'status', phase, state, ...extra });
      persistPhase(phase);
    };

    const jobId = crypto.randomUUID();
    send({ type: 'job', jobId });
    const stagingDir = path.join(os.tmpdir(), 'gatekeeper-staging', jobId);
    const sourceBackupDir = stagingDir + '-source-backup';
    const publishDir = stagingDir + '-publish';
    // Governance workflow cache lives OUTSIDE the project tree so it is never
    // committed or pushed with the user's code.
    const workflowDir = stagingDir + '-workflows';

    const zipFile = req.files?.archive?.[0] || null;
    const dirFiles = req.files?.files || [];
    const gxpDocFiles = req.files?.gxpDocs || [];
    let relPaths = [];
    try {
      relPaths = JSON.parse(req.body.paths || '[]');
    } catch { /* validated below */ }

    const org = (req.body.org || '').trim();
    const repo = (req.body.repo || '').trim();
    // See the other two pipeline entry points: phase 2 disabled by config
    // (default) means gxp is ignored even if the client sends it.
    const isGxp = phaseEnabled[2] && req.body.gxp === 'true';
    const dryRun = req.body.dryRun === 'true';
    let gxpLinks = [];
    try {
      const parsed = JSON.parse(req.body.gxpLinks || '[]');
      if (Array.isArray(parsed)) gxpLinks = parsed;
    } catch { /* validated in phase 2 */ }

    // Issues/failures accumulate here from every phase instead of aborting the
    // stream immediately. They are only surfaced — and gated — together, right
    // before phase 6 (provisioning/push), so a single run always shows the full
    // picture instead of stopping at the first thing that went wrong.
    const allIssues = [];
    let phase1Ok = false;
    let phase3Ok = false;
    let projectRootReady = false;
    let ghToken = null;
    let projectRoot = null;
    let keepSourceBackupDir = false;
    // Set once the immutable snapshot exists (i.e. structure audit passed) and
    // cleared once the code actually ships for real. Anything that ends the
    // run in between — a dry run, the user stopping at the review gate,
    // unresolved findings, even a governance-CI failure (this app already lets
    // the human override that at the final gate) — leaves a resumable
    // snapshot behind so "Effectivate" can finish the job later instead of
    // forcing a full re-upload + re-scan.
    let snapshotReady = false;
    let shippedForReal = false;

    // projectRoot/sourceBackupDir/reviewActive are filled in once known (see
    // below) — Ignite Studio's routes (registered outside this closure) read
    // them off runningRuns.get(jobId) to browse/edit the live staging tree
    // while, and only while, this run is paused at the review gate.
    const runState = { org, repo, projectId: null, allIssues, projectRoot: null, sourceBackupDir: null, reviewActive: false };
    runningRuns.set(jobId, runState);
    const persistIssuesSnapshot = (overriddenIds) => {
      if (runState.projectId === null) return;
      try { store.replaceProjectIssues(runState.projectId, allIssues, overriddenIds); } catch { /* best-effort */ }
    };
    runState.persistIssuesSnapshot = persistIssuesSnapshot;

    try {
      /* ---------------- Phase 1: input validation ---------------- */
      status(1, 'running');
      const log1 = phaseLog(1);
      try {
        if (!zipFile && dirFiles.length === 0) {
          throw new Error('No ZIP archive or folder upload received.');
        }
        if (dirFiles.length > 0 && !Array.isArray(relPaths)) {
          throw new Error('Folder upload metadata is invalid: paths must be an array.');
        }
        if (!githubNameRegex.test(org)) {
          throw new Error(`Invalid GitHub organization name: "${org}"`);
        }
        if (!repoNameRegex.test(repo) || repo === '.' || repo === '..') {
          throw new Error(`Invalid repository name: "${repo}"`);
        }
        // Provisioning (Phase 6) must run as the actual caller's own GitHub
        // account, not a shared host-level `gh auth login` session — fail
        // fast rather than burning phases 1-5 only to find this out at the
        // finish line. Dry runs never reach Phase 6, so they're exempt.
        if (!dryRun) {
          ghToken =
            auth.resolveGithubToken(req);
          if (!ghToken) {
            throw new Error(
              req.user
                ? 'Connect your GitHub account before running for real (GET /api/auth/github/connect), or check "Simulation mode".'
                : 'Log in and connect your GitHub account before running for real, or check "Simulation mode".'
            );
          }
        }

        log1(`Job ${jobId}`);
        if (zipFile) {
          log1(`Archive: ${zipFile.originalname} (${(zipFile.size / 1024).toFixed(1)} KB)`);
        } else {
          const totalMb = dirFiles.reduce((sum, f) => sum + f.size, 0) / 1048576;
          log1(`Folder upload: ${dirFiles.length} files (${totalMb.toFixed(1)} MB)`);
        }
        log1(`Target: ${org}/${repo} (private)`);
        log1(`GxP-regulated process: ${isGxp ? 'YES — validation documents are mandatory' : 'no'}`);
        if (dryRun) log1('Simulation mode (dryRun) — phase 6 provisioning/push will be skipped.');
        projectId = store.createProject(jobId, org, repo, isGxp, resolveRequestSource(req, 'ui'));
        runState.projectId = projectId;
        for (const id of Object.keys(record)) persistPhase(Number(id));
        status(1, 'success');
        phase1Ok = true;
      } catch (err) {
        log1(`✗ ${err.message}`);
        status(1, 'failed', { error: err.message });
        allIssues.push({
          id: 'phase1::input-validation', phase: 1, category: 'input-validation',
          severity: 'error', score: scoreForIssue({ category: 'input-validation', severity: 'error' }), summary: err.message, file: null, line: null,
        });
        persistIssuesSnapshot();
      }

      /* ---------------- Phase 2: GxP validation documents ---------------- */
      if (!phase1Ok) {
        phaseLog(2)('Skipped — blocked by Phase 1 failure (no project record to attach documents to).');
        status(2, 'skipped');
      } else if (!isGxp) {
        phaseLog(2)('Process declared non-GxP — no validation documents required.');
        status(2, 'skipped');
      } else {
        status(2, 'running');
        const logG = phaseLog(2);
        try {
          const validLinks = [];
          for (const l of gxpLinks) {
            const url = String(l?.url || '').trim();
            let parsed = null;
            try { parsed = new URL(url); } catch { /* invalid */ }
            if (!parsed || !['http:', 'https:'].includes(parsed.protocol)) {
              throw new Error(`Invalid GxP document link: "${url}" (must be http/https).`);
            }
            validLinks.push({ url, name: String(l?.name || '').trim() || parsed.hostname + parsed.pathname });
          }

          if (gxpDocFiles.length === 0 && validLinks.length === 0) {
            throw new Error('GxP process declared but no validation documents provided. Attach at least one document (upload or link).');
          }

          logG(`Collecting ${gxpDocFiles.length} uploaded document(s) and ${validLinks.length} link(s)...`);
          for (const doc of gxpDocFiles) {
            const data = await fsp.readFile(doc.path);
            store.addUploadDocument(projectId, doc.originalname, doc.mimetype || null, doc.size, data);
            logG(`✓ Archived upload: ${doc.originalname} (${(doc.size / 1024).toFixed(1)} KB)`);
          }
          for (const link of validLinks) {
            store.addLinkDocument(projectId, link.name, link.url);
            logG(`✓ Archived link: ${link.name} → ${link.url}`);
          }
          logG(`✓ ${gxpDocFiles.length + validLinks.length} GxP validation document(s) saved to the database.`);
          status(2, 'success');
        } catch (err) {
          logG(`✗ ${err.message}`);
          status(2, 'failed', { error: err.message });
          allIssues.push({
            id: 'phase2::gxp-documents', phase: 2, category: 'gxp-documents',
            severity: 'error', score: scoreForIssue({ category: 'gxp-documents', severity: 'error' }), summary: err.message, file: null, line: null,
          });
          persistIssuesSnapshot();
        }
      }

      /* ---------------- Phase 3: extraction + structure audit ---------------- */
      status(3, 'running');
      const log2 = phaseLog(3);
      try {
        await fsp.mkdir(stagingDir, { recursive: true });
        log2(`Staging directory: ${stagingDir}`);

        let staged;
        if (zipFile) {
          staged = await extractZip(zipFile.path, stagingDir, log2);
          log2(`Extracted ${staged.fileCount} files (${(staged.totalBytes / 1024).toFixed(1)} KB).`);
        } else {
          staged = await stageDirectoryUpload(dirFiles, relPaths, stagingDir, log2);
          log2(`Staged ${staged.fileCount} files (${(staged.totalBytes / 1024).toFixed(1)} KB) from folder upload.`);
        }

        projectRoot = await resolveProjectRoot(stagingDir);
        if (projectRoot !== stagingDir) {
          log2(`Detected single top-level folder — project root: ${path.basename(projectRoot)}/`);
        }

        await cloneDirectoryWithoutSymlinks(projectRoot, sourceBackupDir);
        log2('Created immutable source snapshot for final publish phase.');
        snapshotReady = true;
        projectRootReady = true;
        runState.projectRoot = projectRoot;
        runState.sourceBackupDir = sourceBackupDir;

        // License compliance runs FIRST inside phase 3 — the env-file check and
        // unit-test run below both throw on failure, and this fixture-style
        // project can fail either while still having license findings the
        // review gate must show. Findings are non-throwing issues, so
        // collecting them before the hard checks loses nothing. Dependency
        // vulnerability findings ride along right after, same reasoning.
        const licenseIssues = [
          ...await runLicenseComplianceCheck(projectRoot, log2),
          ...await runDependencyVulnerabilityCheck(projectRoot, log2),
        ];
        if (licenseIssues.length > 0) {
          allIssues.push(...licenseIssues);
          persistIssuesSnapshot();
        }

        log2('Check 1 — scanning for raw environment files (.env*)...');
        const envCheck = await checkEnvFiles(projectRoot);
        if (envCheck.ignored.length > 0) {
          log2(`ℹ ${envCheck.ignored.length} .env file(s) found but already excluded by this project's .gitignore — not blocking: ${envCheck.ignored.join(', ')}`);
        }
        if (envCheck.blocking.length > 0) {
          log2(`✗ ${envCheck.blocking.length} forbidden environment file(s) found:`);
          envCheck.blocking.forEach((f) => log2(`    ✗ ${f}`));
          throw new Error(`Raw environment files detected (${envCheck.blocking.length}). Remove them and re-upload.`);
        }
        log2('✓ Check 1 passed — no raw environment files present.');
        log2('Check 2 — checking for a CODEOWNERS file...');
        const codeownersCheck = await checkCodeowners(projectRoot);
        log2(codeownersCheck.found
          ? `✓ CODEOWNERS found at ${codeownersCheck.path} (${codeownersCheck.emails.length} contact email(s)).`
          : 'ℹ No CODEOWNERS file found (advisory — checked root, .github/, docs/).');
        await runProjectUnitTests(projectRoot, log2);
        status(3, 'success');
        phase3Ok = true;
      } catch (err) {
        log2(`✗ ${err.message}`);
        status(3, 'failed', { error: err.message });
        allIssues.push({
          id: 'phase3::structure-audit', phase: 3, category: 'structure-audit',
          severity: 'error', score: scoreForIssue({ category: 'structure-audit', severity: 'error' }), summary: err.message, file: null, line: null,
        });
        persistIssuesSnapshot();
      }

      /* ---------------- Phase 4: security + AI compliance ---------------- */
      // Gated on the project actually being staged on disk (projectRootReady),
      // not on Phase 3 passing outright — a blocking .env file or failing unit
      // test still leaves a scannable checkout, and this run's whole point is
      // to surface every issue across every phase together, not stop at the
      // first one (see the allIssues comment above).
      if (!projectRootReady) {
        phaseLog(4)('Skipped — blocked by Phase 3 failure (no staged project root to scan).');
        status(4, 'skipped');
      } else if (!phaseEnabled[4]) {
        phaseLog(4)('Skipped — disabled by config (phases: [{ id: 4, enabled: false }]).');
        status(4, 'skipped');
      } else {
        status(4, 'running');
        const log3 = phaseLog(4);
        try {
          const { issues } = await runPhase4Checks(projectRoot, log3, { org, repo, projectId, store });
          for (const issue of issues) allIssues.push({ ...issue, phase: 4 });
          const blockingCount = issues.filter((i) => i.severity === 'error').length;
          if (issues.length > 0) {
            log3(`⚠ ${issues.length} flagged issue(s) (${blockingCount} blocking) — will be presented for final review before push.`);
          }
          persistIssuesSnapshot();
          // The scan itself completed cleanly either way — findings (if any)
          // are deferred to the final review gate, not a phase 4 failure — but
          // the client still needs the count to avoid showing a bare "Success"
          // next to a log full of ✗ [error] lines.
          status(4, 'success', { issueCount: issues.length, blockingCount });
        } catch (err) {
          log3(`✗ ${err.message}`);
          status(4, 'failed', { error: err.message });
          allIssues.push({
            id: 'phase4::security-scan', phase: 4, category: 'security-scan',
            severity: 'error', score: scoreForIssue({ category: 'security-scan', severity: 'error' }), summary: err.message, file: null, line: null,
          });
          persistIssuesSnapshot();
        }
      }

      /* ---------------- Phase 5: local GitHub Actions run (act) ---------------- */
      if (!projectRootReady) {
        phaseLog(5)('Skipped — blocked by Phase 3 failure (no staged project root to run CI against).');
        status(5, 'skipped');
      } else if (!phaseEnabled[5]) {
        phaseLog(5)('Skipped — disabled by config (phases: [{ id: 5, enabled: false }]).');
        phaseLog(5)('⚠ The org governance workflows will still gate the repo on GitHub after push.');
        status(5, 'skipped');
      } else {
        status(5, 'running');
        const log4 = phaseLog(5);
        try {
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
        } catch (err) {
          log4(`✗ ${err.message}`);
          status(5, 'failed', { error: err.message });
          // `act` (and git/gh/docker) failing only ever surfaces a generic
          // "exited with code N" — worthless as a single finding. When the
          // output actually contained recognizable failure lines (❌, "Error:",
          // "Failure -", ...), report each one as its own issue instead of
          // collapsing them into that one meaningless blob.
          if (Array.isArray(err.failureLines) && err.failureLines.length > 0) {
            const located = [];
            for (let i = 0; i < err.failureLines.length; i++) {
              const failureLine = err.failureLines[i];
              const loc = projectRootReady
                ? await resolveGovernanceCiLocation(projectRoot, failureLine)
                : { file: null, line: null, code: null };
              located.push({ i, summary: failureLine, file: loc.file, line: loc.line, code: loc.code });
            }
            // A flagged issue is only addressable (View code / Studio highlighting,
            // override targeting) if it has a real file AND line — an unresolved
            // location is worthless as an issue card, so those lines are dropped
            // here rather than shown with "unknown" location. The raw failure text
            // is still visible in the phase log above regardless.
            for (const l of filterGovernanceCiFailureLines(located)) {
              if (!l.file || l.line == null) continue;
              allIssues.push({
                id: `phase5::governance-ci::${l.i}`, phase: 5, category: 'governance-ci',
                severity: 'error', score: scoreForIssue({ category: 'governance-ci', severity: 'error' }), summary: l.summary,
                file: l.file, line: l.line, snippet: l.code,
              });
            }
          }
          persistIssuesSnapshot();
        }
      }

      /* ---------------- Final review gate — every issue from every phase, ----
         ---------------- shown together right before provisioning/push. ----- */
      let repoUrl = null;
      let prUrl = null;
      status(6, 'running');
      const log6 = phaseLog(6);

      if (allIssues.length > 0) {
        const errorCount = allIssues.filter((i) => i.severity === 'error').length;
        log6(`⚠ ${allIssues.length} issue(s) accumulated across the run (${errorCount} blocking) — waiting for final review before provisioning/push.`);
        const decisionPromise = reviewDecisions.wait(jobId);
        // Only open for editing while actually paused here — Ignite Studio's
        // file/rescan routes check this and 409 outside this window, so a run
        // still mid-scan (or one that already resolved/timed out) never
        // exposes the staging tree.
        runState.reviewActive = true;
        send({ type: 'review_required', phase: 6, jobId, issues: allIssues });
        const decision = await decisionPromise;
        runState.reviewActive = false;

        const { ok, unresolvedErrors, applied } = validateOverrides(allIssues, decision.overrides || []);
        persistIssuesSnapshot(applied.map(({ issue }) => issue.id));
        if (applied.length > 0) {
          const byPhase = new Map();
          for (const item of applied) {
            const p = item.issue.phase;
            if (!byPhase.has(p)) byPhase.set(p, []);
            byPhase.get(p).push(item);
          }
          for (const [p, group] of byPhase) {
            log6(`⚠ ${group.length} flagged issue(s) from Phase ${p} overridden by ${decision.actor.email}:`);
            group.forEach(({ issue, justification }) =>
              log6(`    ⚠ [override] [${issue.severity}] ${issue.file ? issue.file + (issue.line ? ':' + issue.line : '') : `Phase ${issue.phase}`} — ${issue.summary} — "${justification}"`)
            );
            await recordOverrides({ projectId, jobId, org, repo, phase: p, actor: decision.actor, applied: group });
          }
        }

        if (!decision.proceed) {
          throw Object.assign(
            new Error('Pipeline interrupted by user after reviewing all flagged issues.'),
            { phase: 6 }
          );
        }
        if (!ok) {
          log6(`✗ ${unresolvedErrors.length} blocking finding(s) were not overridden:`);
          unresolvedErrors.forEach((issue) =>
            log6(`    ✗ [Phase ${issue.phase}] [${issue.category}] ${issue.file ? issue.file + (issue.line ? ':' + issue.line : '') : 'unknown location'} — ${issue.summary}`)
          );
          throw Object.assign(
            new Error(`${unresolvedErrors.length} unresolved blocking finding(s) remain across the run. Override each with a justification, or fix them and re-run.`),
            { phase: 6, unresolvedErrors }
          );
        }
        log6('✓ User chose to continue after reviewing all flagged issues.');
      }

      /* ---------------- Phase 6: provisioning + shipping ---------------- */
      if (dryRun) {
        log6(allIssues.length > 0
          ? 'Simulation mode (dryRun) — all flagged issues were fixed or overridden; skipping repository provisioning and push.'
          : 'Simulation mode (dryRun) — all checks passed; skipping repository provisioning and push.');
        log6('The validated snapshot is kept so this run can be effectivated (provisioned + pushed for real) later, still gated on any unresolved blocking findings.');
        status(6, 'skipped');
        if (projectId !== null) {
          store.finishProject('success', null, null, null, projectId);
        }
      } else {
        const backupStat = await fsp.stat(sourceBackupDir).catch(() => null);
        if (!backupStat || !backupStat.isDirectory()) {
          throw Object.assign(new Error('Immutable source snapshot is missing before phase 6 — an earlier phase failed to produce a publishable project.'), { phase: 6 });
        }
        await fsp.rm(publishDir, { recursive: true, force: true }).catch(() => {});
        await cloneDirectoryWithoutSymlinks(sourceBackupDir, publishDir);
        log6('Prepared clean publish workspace from immutable source snapshot.');

        await archivePhase6Payload(publishDir, projectId, log6);

        ({ repoUrl, prUrl } = await shipToGitHub(publishDir, org, repo, log6, ghToken));
        log6(`✓ Repository live at ${repoUrl}`);
        status(6, 'success', { repoUrl, prUrl });
        shippedForReal = true;

        if (projectId !== null) {
          store.finishProject('success', null, repoUrl, prUrl || null, projectId);
        }
      }
      send({ type: 'done', ok: true, dryRun, repoUrl, prUrl, effectivatable: snapshotReady && !shippedForReal, projectId });
    } catch (err) {
      const phase = err.phase || currentPhase;
      phaseLog(phase)(`✗ ${err.message}`);
      status(phase, 'failed', { error: err.message });

      // AI insight: pass the failed step's full log to the local LLM for a
      // user-friendly explanation. Soft-fails if the LLM is unavailable.
      let insight = null;
      send({ type: 'insight', phase, state: 'generating' });
      try {
        insight = await generateFailureInsight(phase, err.message, record, err.unresolvedErrors);
      } catch { /* insight is best-effort */ }
      send(insight
        ? { type: 'insight', phase, state: 'ready', text: insight }
        : { type: 'insight', phase, state: 'unavailable' });

      try {
        const mail = await sendFailureNotification({
          jobId, org, repo, error: err.message, failedPhase: phase, record, insight,
        });
        if (mail.sent) {
          phaseLog(phase)(`📧 Failure report emailed to ${mail.to}.`);
        }
      } catch (mailErr) {
        phaseLog(phase)(`⚠ Could not send failure email: ${mailErr.message}`);
      }

      if (projectId !== null) {
        try { store.finishProject('failed', err.message, null, null, projectId); } catch { /* best-effort */ }
      }
      send({ type: 'done', ok: false, error: err.message, phase, effectivatable: snapshotReady && !shippedForReal, projectId });
    } finally {
      runningRuns.delete(jobId);
      if (snapshotReady && !shippedForReal && projectId !== null) {
        cleanupExpiredEffectivations();
        pendingEffectivations.set(projectId, { org, repo, sourceBackupDir, createdAt: Date.now() });
        keepSourceBackupDir = true;
      }
      // Persist every phase's state and logs for the onboarding history panel.
      if (projectId !== null) {
        try {
          for (const id of Object.keys(phaseTitles)) {
            const ph = record[id] || { state: 'pending', logs: [] };
            store.upsertStep(projectId, Number(id), phaseTitles[id], ph.state, ph.logs.join('\n'));
          }
        } catch (e) {
          console.error(`Could not persist step history for job ${jobId}: ${e.message}`);
        }
      }
      // Forceful cleanup regardless of outcome: staging dir, the uploaded ZIP,
      // and any multer temp files not yet moved into staging. The one exception
      // is the source snapshot of a run that didn't ship for real (dry run,
      // stopped at review, unresolved findings, CI failure) — kept for a later
      // "Effectivate" call — see pendingEffectivations.
      await fsp.rm(stagingDir, { recursive: true, force: true }).catch(() => {});
      if (!keepSourceBackupDir) {
        await fsp.rm(sourceBackupDir, { recursive: true, force: true }).catch(() => {});
      }
      await fsp.rm(publishDir, { recursive: true, force: true }).catch(() => {});
      await fsp.rm(workflowDir, { recursive: true, force: true }).catch(() => {});
      if (zipFile) await fsp.rm(zipFile.path, { force: true }).catch(() => {});
      for (const f of dirFiles) await fsp.rm(f.path, { force: true }).catch(() => {});
      for (const f of gxpDocFiles) await fsp.rm(f.path, { force: true }).catch(() => {});
      res.end();
    }
  });
}

/* Multer / general error handler (e.g. file too large) — must be registered
   after every other route. */
function mountErrorMiddleware(app) {
  app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    res.status(400).json({ error: err.message });
  });
}

module.exports = { mountInteractivePipelineRoute, mountErrorMiddleware };
