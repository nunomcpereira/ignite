'use strict';

/**
 * Ignite Studio — file-tree/editor + rescan, plus the on-demand report
 * views (dependencies/SBOM/LOC-metrics/posture/provenance) available at
 * the review gate before a run ships. Available in two windows:
 *  - 'live': the run is still paused at the review gate — projectRoot
 *    and sourceBackupDir are both on disk, issues live in runState.
 *  - 'kept': the review gate already resolved, but the run didn't ship
 *    for real (dry run / user stopped / unresolved findings / CI
 *    failure) — sourceBackupDir is the one already kept alive by
 *    pendingEffectivations for the "Effectivate" feature (24h TTL,
 *    cleared on Effectivate, or gone on server restart); issues live
 *    in the DB. A run that DID ship for real gets neither: the code is
 *    already safely on GitHub, so Studio has nothing to open — fixing
 *    it means a normal PR, not reopening a local copy indefinitely.
 * Phase F of the server.js module split (see
 * /Users/nuno/.claude/plans/cuddly-roaming-pearl.md).
 *
 * @param {import('express').Express} app
 * @param {object} deps
 * @param {Map} deps.runningRuns
 * @param {object} deps.reviewDecisions
 * @param {object} deps.store
 * @param {Map} deps.pendingEffectivations
 * @param {Function} deps.cleanupExpiredEffectivations
 * @param {object} deps.fsUtils - { walkFiles, looksBinary }
 * @param {Function} deps.resolveWithinRoot
 * @param {object} deps.checks - { checkSecrets, checkAiGovernance, checkLlmDeepScan, checkIacSecurity, generateSbom, generateLocMetrics, checkFeaturePosture, generateProvenance }
 * @param {object} deps.overrideEngine - { collectPhase4Issues, collectLicenseIssues, collectDependencyVulnerabilityIssues }
 * @param {object} deps.licenseScan - { scanDependencyLicenses, scanProjectLicenseFiles, scanDependencyVulnerabilities }
 */
function mountStudioRoutes(app, {
  runningRuns, reviewDecisions, store, pendingEffectivations, cleanupExpiredEffectivations,
  fsUtils, resolveWithinRoot, checks, overrideEngine, licenseScan,
}) {
  const fsp = require('fs/promises');
  const path = require('path');
  const { walkFiles, looksBinary } = fsUtils;
  const {
    checkSecrets, checkAiGovernance, checkLlmDeepScan, checkIacSecurity,
    generateSbom, generateLocMetrics, checkFeaturePosture, generateProvenance,
    checkCodeqlCrossFile,
  } = checks;
  const { collectPhase4Issues, collectCodeqlIssues, collectLicenseIssues, collectDependencyVulnerabilityIssues } = overrideEngine;
  const { scanDependencyLicenses, scanProjectLicenseFiles, scanDependencyVulnerabilities } = licenseScan;

  const STUDIO_MAX_FILE_BYTES = 500_000; // browser-editor cap, independent of the LLM deep-scan's own per-file cap
  function studioNoopLog() {}

  function resolveStudioContext(req, res) {
    const jobId = String(req.params.jobId || '').trim();

    const runState = runningRuns.get(jobId);
    if (runState && runState.reviewActive && runState.projectRoot) {
      reviewDecisions.touch(jobId);
      return {
        jobId,
        root: runState.projectRoot,
        backupRoot: runState.sourceBackupDir,
        org: runState.org,
        repo: runState.repo,
        getIssues: () => runState.allIssues,
        replacePhase4: (freshIssues) => {
          const others = runState.allIssues.filter((i) => i.phase !== 4);
          runState.allIssues.length = 0;
          runState.allIssues.push(...others, ...freshIssues);
          runState.persistIssuesSnapshot();
        },
        replaceLicense: (freshIssues) => {
          const others = runState.allIssues.filter((i) => i.category !== 'license-compliance');
          runState.allIssues.length = 0;
          runState.allIssues.push(...others, ...freshIssues);
          runState.persistIssuesSnapshot();
        },
        replaceDependencyVulns: (freshIssues) => {
          const others = runState.allIssues.filter((i) => i.category !== 'dependency-vulnerability');
          runState.allIssues.length = 0;
          runState.allIssues.push(...others, ...freshIssues);
          runState.persistIssuesSnapshot();
        },
        replaceCodeql: (freshIssues) => {
          const others = runState.allIssues.filter((i) => i.category !== 'codeql-sast');
          runState.allIssues.length = 0;
          runState.allIssues.push(...others, ...freshIssues);
          runState.persistIssuesSnapshot();
        },
      };
    }

    const projectId = store.getProjectIdByJobId(jobId);
    if (projectId !== null) {
      cleanupExpiredEffectivations();
      const kept = pendingEffectivations.get(projectId);
      if (kept) {
        return {
          jobId,
          root: kept.sourceBackupDir,
          backupRoot: kept.sourceBackupDir,
          org: kept.org,
          repo: kept.repo,
          getIssues: () => store.getProjectIssues(projectId),
          replacePhase4: (freshIssues) => {
            const current = store.getProjectIssues(projectId);
            const overriddenIds = new Set(current.filter((i) => i.status === 'overridden').map((i) => i.id));
            const merged = [...current.filter((i) => i.phase !== 4), ...freshIssues];
            store.replaceProjectIssues(projectId, merged, overriddenIds);
          },
          replaceLicense: (freshIssues) => {
            const current = store.getProjectIssues(projectId);
            const overriddenIds = new Set(current.filter((i) => i.status === 'overridden').map((i) => i.id));
            const merged = [...current.filter((i) => i.category !== 'license-compliance'), ...freshIssues];
            store.replaceProjectIssues(projectId, merged, overriddenIds);
          },
          replaceDependencyVulns: (freshIssues) => {
            const current = store.getProjectIssues(projectId);
            const overriddenIds = new Set(current.filter((i) => i.status === 'overridden').map((i) => i.id));
            const merged = [...current.filter((i) => i.category !== 'dependency-vulnerability'), ...freshIssues];
            store.replaceProjectIssues(projectId, merged, overriddenIds);
          },
          replaceCodeql: (freshIssues) => {
            const current = store.getProjectIssues(projectId);
            const overriddenIds = new Set(current.filter((i) => i.status === 'overridden').map((i) => i.id));
            const merged = [...current.filter((i) => i.category !== 'codeql-sast'), ...freshIssues];
            store.replaceProjectIssues(projectId, merged, overriddenIds);
          },
        };
      }
    }

    res.status(409).json({ error: 'This run\'s source is no longer available (already shipped for real, expired, or unknown job).' });
    return null;
  }

  app.get('/api/pipeline/:jobId/studio/tree', async (req, res) => {
    const ctx = resolveStudioContext(req, res);
    if (!ctx) return;
    try {
      const files = [];
      for await (const file of walkFiles(ctx.root)) {
        const stat = await fsp.stat(file);
        files.push({ path: path.relative(ctx.root, file), size: stat.size });
      }
      res.json({ ok: true, files });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  app.get('/api/pipeline/:jobId/studio/file', async (req, res) => {
    const ctx = resolveStudioContext(req, res);
    if (!ctx) return;
    try {
      const target = resolveWithinRoot(ctx.root, String(req.query.path || ''));
      const buffer = await fsp.readFile(target);
      if (looksBinary(buffer)) return res.status(415).json({ error: 'Binary file — cannot display in Studio.' });
      if (buffer.length > STUDIO_MAX_FILE_BYTES) return res.status(413).json({ error: 'File too large to display in Studio.' });
      res.json({ ok: true, content: buffer.toString('utf8') });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  // In 'live' mode, writes to BOTH the live staging tree and the immutable
  // sourceBackupDir — Phase 6 always clones the publish workspace from
  // sourceBackupDir, never from projectRoot, so a fix written only to
  // projectRoot would validate here but silently vanish from what actually
  // gets pushed. In 'kept' mode root === backupRoot (only sourceBackupDir is
  // still on disk), so it's a single write.
  app.put('/api/pipeline/:jobId/studio/file', async (req, res) => {
    const ctx = resolveStudioContext(req, res);
    if (!ctx) return;
    const relPath = String(req.body?.path || '');
    const content = req.body?.content;
    if (typeof content !== 'string') return res.status(400).json({ error: 'content (string) is required.' });
    try {
      const liveTarget = resolveWithinRoot(ctx.root, relPath);
      await fsp.mkdir(path.dirname(liveTarget), { recursive: true });
      await fsp.writeFile(liveTarget, content, 'utf8');
      if (ctx.backupRoot !== ctx.root) {
        const backupTarget = resolveWithinRoot(ctx.backupRoot, relPath);
        await fsp.mkdir(path.dirname(backupTarget), { recursive: true });
        await fsp.writeFile(backupTarget, content, 'utf8');
      }
      res.json({ ok: true });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  // Re-runs the phase-4 checks against the (now-edited) tree and replaces just
  // that phase's slice of the run's issue list — the other phases' issues are
  // untouched. All three checks are per-file-hash cached (file_scan_cache,
  // same {org, repo} key used for the original scan), so re-scanning after
  // editing one or two files is cheap: everything else is a cache hit.
  app.post('/api/pipeline/:jobId/studio/rescan', async (req, res) => {
    const ctx = resolveStudioContext(req, res);
    if (!ctx) return;
    try {
      const cacheKey = { org: ctx.org, repo: ctx.repo };
      const secrets = await checkSecrets(ctx.root, studioNoopLog, cacheKey);
      const governance = await checkAiGovernance(ctx.root, cacheKey);
      const llm = await checkLlmDeepScan(ctx.root, studioNoopLog, cacheKey);
      const iac = await checkIacSecurity(ctx.root, studioNoopLog);
      const freshIssues = collectPhase4Issues({ secrets, governance, llm, iac }).map((issue) => ({ ...issue, phase: 4 }));

      // License compliance runs alongside the phase 4 checks here too — same
      // scan Phase 3 runs on a fresh upload (manifests via scanDependencyLicenses
      // + every LICENSE file in the tree), so "Rescan" picks up dependency/
      // license changes without needing the separate Dependencies view.
      const licenseScanResult = await scanDependencyLicenses(ctx.root, studioNoopLog);
      const licenseFileFindings = await scanProjectLicenseFiles(ctx.root);
      const freshLicenseIssues = collectLicenseIssues({ manifests: licenseScanResult.manifests, licenseFiles: licenseFileFindings })
        .map((issue) => ({ ...issue, phase: 3 }));

      // Same reasoning as license compliance just above — the deps.dev CVE/GHSA
      // scan Phase 3 runs on a fresh upload, so an edit that bumps a vulnerable
      // dependency's version resolves that finding on "Rescan" too.
      const depVulnManifests = await scanDependencyVulnerabilities(ctx.root);
      const freshDependencyVulnIssues = collectDependencyVulnerabilityIssues({ manifests: depVulnManifests })
        .map((issue) => ({ ...issue, phase: 3 }));

      const previousIssues = ctx.getIssues();
      const previousPhase4Ids = new Set(previousIssues.filter((i) => i.phase === 4).map((i) => i.id));
      const previousLicenseIds = new Set(previousIssues.filter((i) => i.category === 'license-compliance').map((i) => i.id));
      const previousDependencyVulnIds = new Set(previousIssues.filter((i) => i.category === 'dependency-vulnerability').map((i) => i.id));
      const freshIds = new Set(freshIssues.map((i) => i.id));
      const freshLicenseIds = new Set(freshLicenseIssues.map((i) => i.id));
      const freshDependencyVulnIds = new Set(freshDependencyVulnIssues.map((i) => i.id));
      const resolvedIds = [
        ...[...previousPhase4Ids].filter((id) => !freshIds.has(id)),
        ...[...previousLicenseIds].filter((id) => !freshLicenseIds.has(id)),
        ...[...previousDependencyVulnIds].filter((id) => !freshDependencyVulnIds.has(id)),
      ];
      const newIds = [
        ...[...freshIds].filter((id) => !previousPhase4Ids.has(id)),
        ...[...freshLicenseIds].filter((id) => !previousLicenseIds.has(id)),
        ...[...freshDependencyVulnIds].filter((id) => !previousDependencyVulnIds.has(id)),
      ];

      ctx.replacePhase4(freshIssues);
      ctx.replaceLicense(freshLicenseIssues);
      ctx.replaceDependencyVulns(freshDependencyVulnIssues);

      res.json({ ok: true, issues: ctx.getIssues(), resolvedIds, newIds });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // On-demand CodeQL run against the currently staged tree — streaming
  // NDJSON, unlike /studio/rescan just above, because a CodeQL database
  // build is a real per-language build+analyze that can take tens of
  // seconds to minutes, nothing like the per-file-cached checks rescan
  // covers. Ignite Studio's "Run CodeQL" button consumes this the same way
  // the interactive pipeline consumes POST /api/pipeline: read the response
  // body as a stream, one JSON event per line, rendering each `log` line
  // live into a terminal-style output panel rather than waiting for one
  // final response the way /studio/rescan's callers do.
  app.post('/api/pipeline/:jobId/studio/codeql', async (req, res) => {
    const ctx = resolveStudioContext(req, res);
    if (!ctx) return;
    res.setHeader('Content-Type', 'application/x-ndjson');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('X-Accel-Buffering', 'no');
    const send = (event) => res.write(JSON.stringify(event) + '\n');
    const log = (message) => send({ type: 'log', message });
    try {
      const codeql = await checkCodeqlCrossFile(ctx.root, log, { org: ctx.org, repo: ctx.repo });
      if (codeql.engine !== 'codeql') {
        log(`✓ CodeQL skipped — disabled or not installed (security.codeql.enabled).`);
      } else if (codeql.findings.length === 0) {
        log(`✓ No CodeQL findings across ${codeql.languages.length} language(s) scanned.`);
      } else {
        const crossFileCount = codeql.findings.filter((f) => f.crossFile).length;
        log(`✗ ${codeql.findings.length} CodeQL finding(s) (${crossFileCount} genuinely cross-file).`);
      }
      const freshIssues = collectCodeqlIssues(codeql);

      const previousIds = new Set(ctx.getIssues().filter((i) => i.category === 'codeql-sast').map((i) => i.id));
      const freshIds = new Set(freshIssues.map((i) => i.id));
      const resolvedIds = [...previousIds].filter((id) => !freshIds.has(id));
      const newIds = [...freshIds].filter((id) => !previousIds.has(id));

      ctx.replaceCodeql(freshIssues);
      send({ type: 'done', ok: true, issues: ctx.getIssues(), resolvedIds, newIds });
    } catch (e) {
      log(`✗ ${e.message}`);
      send({ type: 'done', ok: false, error: e.message });
    } finally {
      res.end();
    }
  });

  app.get('/api/pipeline/:jobId/studio/dependencies', async (req, res) => {
    const ctx = resolveStudioContext(req, res);
    if (!ctx) return;
    try {
      res.json({ ok: true, ...(await scanDependencyLicenses(ctx.root)) });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // Studio report views for the three non-issue Phase 4 artifacts (SBOM, LOC
  // metrics, compliance posture) — same on-demand-recompute pattern as
  // /studio/dependencies above, so Studio can show them live at the review
  // gate without waiting for the pipeline to finish and persist a document.
  app.get('/api/pipeline/:jobId/studio/sbom', async (req, res) => {
    const ctx = resolveStudioContext(req, res);
    if (!ctx) return;
    try {
      res.json({ ok: true, ...(await generateSbom(ctx.root, studioNoopLog)) });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  app.get('/api/pipeline/:jobId/studio/loc-metrics', async (req, res) => {
    const ctx = resolveStudioContext(req, res);
    if (!ctx) return;
    try {
      res.json({ ok: true, ...(await generateLocMetrics(ctx.root, studioNoopLog)) });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  app.get('/api/pipeline/:jobId/studio/posture', async (req, res) => {
    const ctx = resolveStudioContext(req, res);
    if (!ctx) return;
    try {
      res.json({ ok: true, ...(await checkFeaturePosture(ctx.root, studioNoopLog)) });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  app.get('/api/pipeline/:jobId/studio/provenance', async (req, res) => {
    const ctx = resolveStudioContext(req, res);
    if (!ctx) return;
    try {
      const provenance = await generateProvenance(ctx.root, studioNoopLog, { org: ctx.org, repo: ctx.repo });
      res.json({ ok: true, provenance });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

}

module.exports = { mountStudioRoutes };
