'use strict';

/**
 * Scheduled re-checks: effectivated repos can opt into a recurring re-run
 * of Phases 1/3/4/5 against their default branch. A failure notifies the
 * repo's CODEOWNERS contact(s) by email, or — if none can be resolved —
 * files a GitHub issue on the repo instead. Phase E of the server.js
 * module split (see /Users/nuno/.claude/plans/cuddly-roaming-pearl.md).
 *
 * @param {object} deps
 * @param {object} deps.store - db-store.js instance
 * @param {Function} deps.ghCloneRepo - lib/github-api.js's createGithubApi() result
 * @param {Function} deps.ghCreateIssue - lib/github-api.js's createGithubApi() result
 * @param {Function} deps.resolveServerGithubToken - lib/github-api.js's createGithubApi() result
 * @param {Function} deps.buildMailTransport - lib/notifications.js's createNotifications() result
 * @param {Function} deps.escapeHtmlMail - lib/notifications.js's createNotifications() result
 * @param {Function} deps.checkEnvFiles - server.js (Phase 3 raw-.env check)
 * @param {Function} deps.checkCodeowners - server.js (CODEOWNERS lookup)
 * @param {Function} deps.runProjectUnitTests - checks/unit-test-runner.js's createUnitTestRunnerCheck() result
 * @param {Function} deps.runLicenseComplianceCheck - server.js (ORT-based license check)
 * @param {Function} deps.runDependencyVulnerabilityCheck - server.js (ORT-based vuln check)
 * @param {Function} deps.runPhase4Checks - server.js (Phase 4 orchestration)
 * @param {Function} deps.actTooling - server.js (act/Docker probe)
 * @param {Function} deps.fetchGovernanceWorkflow - server.js (governance workflow fetch)
 * @param {Function} deps.runActionsLocally - server.js (act runner)
 * @param {object} deps.phaseEnabled - PHASE_ENABLED (id -> bool)
 * @param {object} deps.notificationsConfig - CONFIG.notifications ({ enabled, from })
 */
function createScheduledRechecks({
  store, ghCloneRepo, ghCreateIssue, resolveServerGithubToken,
  buildMailTransport, escapeHtmlMail,
  checkEnvFiles, checkCodeowners, runProjectUnitTests,
  runLicenseComplianceCheck, runDependencyVulnerabilityCheck, runPhase4Checks,
  actTooling, fetchGovernanceWorkflow, runActionsLocally,
  phaseEnabled, notificationsConfig,
}) {
  const fsp = require('fs/promises');
  const path = require('path');
  const os = require('os');

  const SCHEDULE_INTERVALS = new Set(['daily', 'weekly', 'monthly']);

  function computeNextRunAt(interval, from = new Date()) {
    const next = new Date(from);
    if (interval === 'weekly') next.setDate(next.getDate() + 7);
    else if (interval === 'monthly') next.setMonth(next.getMonth() + 1);
    else next.setDate(next.getDate() + 1); // 'daily', and the fallback for any unrecognized value
    return next.toISOString();
  }

  function buildScheduledCheckFailureEmail({ org, repo, error }) {
    const subject = `[Ignite] ❌ Scheduled re-check failed — ${org}/${repo}`;
    const html = `
    <div style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:640px;margin:0 auto;color:#334155;">
      <h2 style="color:#e11d48;">Ignite scheduled re-check failed</h2>
      <p><strong>Repository:</strong> ${escapeHtmlMail(org)}/${escapeHtmlMail(repo)} (default branch)<br/>
         <strong>Error:</strong> ${escapeHtmlMail(error)}</p>
      <p style="color:#94a3b8;font-size:12px;margin-top:24px;">Sent by Ignite to this repository's CODEOWNERS contact(s) — update CODEOWNERS to change who receives this.</p>
    </div>`;
    return { subject, html };
  }

  // Unlike sendFailureNotification/sendOverrideNotification, the recipient is
  // per-repo (CODEOWNERS emails), not the fixed CONFIG.notifications.to — the
  // global `enabled` kill switch still applies.
  async function sendScheduledCheckFailureEmail({ org, repo, error, to }) {
    const { enabled, from } = notificationsConfig;
    if (!enabled) return { sent: false, reason: 'notifications disabled' };
    const transport = buildMailTransport();
    const { subject, html } = buildScheduledCheckFailureEmail({ org, repo, error });
    await transport.sendMail({ from, to, subject, html });
    return { sent: true, to };
  }

  async function notifyScheduledFailure({ org, repo, error, codeownersCheck }, log) {
    if (codeownersCheck.emails.length > 0) {
      try {
        const result = await sendScheduledCheckFailureEmail({ org, repo, error, to: codeownersCheck.emails.join(', ') });
        log(result.sent ? `✓ Notified CODEOWNERS contact(s): ${result.to}` : `⚠ Email not sent: ${result.reason}`);
      } catch (e) {
        log(`⚠ Failed to email CODEOWNERS contact(s): ${e.message}`);
      }
      return;
    }
    log('⚠ No CODEOWNERS contact email resolved — filing a GitHub issue instead.');
    try {
      await ghCreateIssue({
        fullName: `${org}/${repo}`,
        title: 'Ignite scheduled check failed',
        body:
          `Ignite's scheduled re-check of the default branch failed:\n\n${error}\n\n`
          + 'No CODEOWNERS contact could be resolved (no CODEOWNERS file, or no email-address owner listed in it), '
          + 'so this issue was filed automatically instead of emailing a contact. Add a CODEOWNERS file with at least '
          + 'one email-address owner to route future failures by email instead.',
        token:
          resolveServerGithubToken(),
      });
      log('✓ Filed a GitHub issue on the repo.');
    } catch (e) {
      log(`⚠ Failed to file a GitHub issue: ${e.message}`);
    }
  }

  async function runScheduledRecheck(project) {
    const { id: projectId, org, repo, schedule_interval: interval } = project;
    const stagingDir = path.join(os.tmpdir(), 'gatekeeper-staging', `scheduled-${projectId}-${Date.now()}`);
    const workflowDir = `${stagingDir}-workflows`;
    const log = (message) => console.log(`[scheduled ${org}/${repo}] ${message}`);
    let codeownersCheck = { found: false, path: null, emails: [] };

    try {
      log('Cloning default branch (main)...');
      await ghCloneRepo({
        fullName: `${org}/${repo}`,
        destDir: stagingDir,
        token:
          resolveServerGithubToken(),
      });

      const licenseIssues = [
        ...await runLicenseComplianceCheck(stagingDir, log),
        ...await runDependencyVulnerabilityCheck(stagingDir, log),
      ];

      const envCheck = await checkEnvFiles(stagingDir);
      if (envCheck.blocking.length > 0) {
        throw new Error(`Raw environment file(s) present on default branch: ${envCheck.blocking.join(', ')}`);
      }
      codeownersCheck = await checkCodeowners(stagingDir);
      log(codeownersCheck.found
        ? `✓ CODEOWNERS found at ${codeownersCheck.path} (${codeownersCheck.emails.length} contact email(s)).`
        : 'ℹ No CODEOWNERS file found.');

      await runProjectUnitTests(stagingDir, log);

      let issues = [...licenseIssues];
      if (phaseEnabled[4]) {
        const phase4 = await runPhase4Checks(stagingDir, log, { org, repo, projectId, store });
        issues = [...phase4.issues, ...licenseIssues];
      }
      const errorIssues = issues.filter((i) => i.severity === 'error');
      if (errorIssues.length > 0) {
        throw new Error(`${errorIssues.length} blocking finding(s) on default branch: ${errorIssues.slice(0, 5).map((i) => `${i.category} — ${i.summary}`).join('; ')}`);
      }

      if (phaseEnabled[5]) {
        const tooling = await actTooling();
        if (tooling.ok) {
          const wfFile = await fetchGovernanceWorkflow(workflowDir, log);
          await runActionsLocally(stagingDir, wfFile, log);
        } else {
          log(`⚠ Local CI skipped: ${tooling.reason}`);
        }
      }

      store.recordScheduledRunResult(projectId, 'ok', null, computeNextRunAt(interval));
      log('✓ Scheduled re-check passed.');
    } catch (e) {
      store.recordScheduledRunResult(projectId, 'failed', e.message, computeNextRunAt(interval));
      log(`✗ Scheduled re-check failed: ${e.message}`);
      await notifyScheduledFailure({ org, repo, error: e.message, codeownersCheck }, log);
    } finally {
      await fsp.rm(stagingDir, { recursive: true, force: true }).catch(() => {});
      await fsp.rm(workflowDir, { recursive: true, force: true }).catch(() => {});
    }
  }

  const scheduledRechecksInFlight = new Set();

  // Runs due repos concurrently (fire-and-forget) rather than one at a time —
  // each clones into its own staging dir, so there's no shared state to race
  // on — but never starts the same project twice while its previous run is
  // still in flight (a slow act/Docker run outlasting the sweep interval).
  function sweepScheduledRechecks() {
    const due = store.getDueScheduledProjects(new Date().toISOString());
    for (const project of due) {
      if (scheduledRechecksInFlight.has(project.id)) continue;
      scheduledRechecksInFlight.add(project.id);
      runScheduledRecheck(project).finally(() => scheduledRechecksInFlight.delete(project.id));
    }
  }

  return {
    SCHEDULE_INTERVALS,
    computeNextRunAt,
    buildScheduledCheckFailureEmail,
    sendScheduledCheckFailureEmail,
    notifyScheduledFailure,
    runScheduledRecheck,
    sweepScheduledRechecks,
  };
}

module.exports = { createScheduledRechecks };
