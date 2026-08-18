'use strict';

/**
 * POST /api/pipeline/deep-scan — streaming NDJSON, phase 4's full check set
 * (secrets/governance/LLM/IaC/SBOM-adjacent/SAST/PII/duplication/API-schema/
 * malicious-dependency/posture) plus CodeQL cross-file static analysis
 * (`runPhase4Checks(..., { deepScan: true })`) and license/dependency-
 * vulnerability scanning — never phases 1/2/3/5/6 (no unit tests, no local
 * governance CI, never provisions or pushes anything).
 *
 * Deliberately separate from POST /api/pipeline/validate-all: this is the
 * slow path. A CodeQL database build can take minutes per language, so
 * unlike validate-all/onboard/the interactive pipeline (all of which a
 * developer or CI run is actively waiting on), this endpoint is meant to be
 * called from the in-app scheduler (already-onboarded repos, on a cadence)
 * or as an explicit pre-push gate a caller opts into for a brand-new repo —
 * never silently substituted for the fast pipeline.
 *
 * Diagnostic, not gating: always resolves `ok: true` with the full issue
 * list (including blocking `error` ones) rather than 400ing on unresolved
 * blocking issues the way validate-all does — a scheduled run has no
 * "submit an override right now" caller to fail closed against. Overrides
 * on the returned issues go through the normal Studio override flow
 * afterward, same audit trail as any other phase-4 issue.
 *
 * Two ways to get source onto disk for the scan, chosen by whether the
 * caller supplies `projectPath`:
 *   - `projectPath` given: a local folder (validate-all's own model) — the
 *     brand-new/not-yet-pushed-repo case, where Ignite already has the code
 *     on disk from wherever the caller staged it.
 *   - `projectPath` omitted: `org`/`repo` alone — the already-onboarded/
 *     scheduled-run case. Ignite doesn't keep pushed repos on disk (staging
 *     dirs are always removed in a `finally` block, see the hardening
 *     invariants), so this shallow-clones the repo fresh via `git`, reusing
 *     the exact `gh auth git-credential` helper trick lib/shipping.js's
 *     push path already uses (no interactive prompts, no separate token
 *     plumbing).
 *
 * @param {import('express').Express} app
 * @param {object} deps
 * @param {object} deps.store
 * @param {RegExp} deps.repoNameRegex - REPO_NAME_REGEX
 * @param {RegExp} deps.githubNameRegex - GITHUB_NAME_REGEX
 * @param {Function} deps.sanitizeAbsoluteProjectPath
 * @param {Function} deps.stageExistingProject
 * @param {Function} deps.resolveProjectRoot
 * @param {Function} deps.runLicenseComplianceCheck
 * @param {Function} deps.runDependencyVulnerabilityCheck
 * @param {Function} deps.runPhase4Checks
 * @param {Function} deps.runTool - from lib/tool-runner.js's createToolRunner(), for the clone-from-GitHub path
 */
function mountDeepScanRoute(app, {
  store, repoNameRegex, githubNameRegex, sanitizeAbsoluteProjectPath,
  stageExistingProject, resolveProjectRoot, runLicenseComplianceCheck,
  runDependencyVulnerabilityCheck, runPhase4Checks, runTool,
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
    const log = (message) => send({ type: 'log', message });

    const body = req.body || {};
    const org = String(body.org || '').trim();
    const repo = String(body.repo || '').trim();
    const hasLocalPath = typeof body.projectPath === 'string' && body.projectPath.trim() !== '';
    const projectPath = hasLocalPath ? sanitizeAbsoluteProjectPath(body.projectPath) : null;

    const jobId = crypto.randomUUID();
    const stagingDir = path.join(os.tmpdir(), 'gatekeeper-staging', `${jobId}-deep-scan`);
    let projectId = null;

    try {
      if (!repoNameRegex.test(repo) || repo === '.' || repo === '..') {
        throw new Error(`Invalid repository name: "${repo}"`);
      }
      if (!githubNameRegex.test(org)) {
        throw new Error(`Invalid organization name: "${org}"`);
      }
      log(`Deep scan job ${jobId} — target ${org}/${repo}`);
      // 'deep-scan' as a project-history source distinguishes these runs
      // from ui/api/mcp-triggered onboarding in the same projects list —
      // db-store.js's `source` column is free text, no enum to extend.
      projectId = store.createProject(jobId, org, repo, false, 'deep-scan');

      if (hasLocalPath) {
        log(`Source project path: ${projectPath}`);
        await stageExistingProject(projectPath, stagingDir, log);
      } else {
        log(`No projectPath given — cloning ${org}/${repo} from GitHub for the deep scan (already-onboarded repo / scheduled run).`);
        await cloneRepoForDeepScan(org, repo, stagingDir, log);
      }
      const projectRoot = await resolveProjectRoot(stagingDir);

      log('Dependency & license compliance scan (manifests + LICENSE files)...');
      const licenseIssues = [
        ...await runLicenseComplianceCheck(projectRoot, log),
        ...await runDependencyVulnerabilityCheck(projectRoot, log),
      ];

      const phase4 = await runPhase4Checks(projectRoot, log, { org, repo, projectId, store, deepScan: true });
      const issues = [...phase4.issues, ...licenseIssues];
      const errorCount = issues.filter((i) => i.severity === 'error').length;

      log(`Deep scan complete — ${issues.length} total issue(s), ${errorCount} blocking.`);
      store.finishProject('success', null, null, null, projectId);
      send({ type: 'done', ok: true, jobId, org, repo, issues });
    } catch (err) {
      log(`✗ ${err.message}`);
      if (projectId !== null) {
        try { store.finishProject('failed', err.message, null, null, projectId); } catch { /* best-effort */ }
      }
      send({ type: 'done', ok: false, jobId, org, repo, error: err.message });
    } finally {
      res.end();
      await fsp.rm(stagingDir, { recursive: true, force: true }).catch(() => {});
    }
  });
}

module.exports = { mountDeepScanRoute };
