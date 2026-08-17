'use strict';

/**
 * Malicious-dependency heuristic scan via GuardDog. Phase C of the
 * server.js module split (see /Users/nuno/.claude/plans/cuddly-roaming-pearl.md).
 *
 * @param {object} deps
 * @param {Function} deps.runTool - from lib/tool-runner.js's createToolRunner()
 * @param {object} deps.store - db-store.js instance (manifest scan cache)
 * @param {object} deps.fsUtils - lib/fs-utils.js exports (walkFiles, hashBuffer)
 * @param {object} deps.config - { enabled }
 */
function createMaliciousDependenciesCheck({ runTool, store, fsUtils, config }) {
  const fsp = require('fs/promises');
  const path = require('path');
  const os = require('os');
  const { walkFiles, hashBuffer } = fsUtils;

  const GUARDDOG_ENABLED = Boolean(config.enabled);

  async function guarddogTooling() {
    try {
      const { stdout } = await runTool('guarddog', ['--version'], os.tmpdir());
      return { ok: true, version: stdout.trim() || null };
    } catch {
      return { ok: false, reason: '`guarddog` is not installed (pip install guarddog) — malicious-dependency heuristic scanning is skipped.' };
    }
  }

  // GuardDog (https://github.com/DataDog/guarddog) verifies every dependency
  // in a manifest against Semgrep-based heuristics for supply-chain-attack
  // patterns (exfiltration in install scripts, obfuscated/encoded payloads,
  // silent network calls, typosquatting) — behavioral signals a known-CVE
  // database (deps.dev, scanDependencyVulnerabilities in server.js) can't
  // catch, since a freshly-published malicious package has no advisory yet.
  // Only npm (package.json) and PyPI (requirements.txt) are supported —
  // GuardDog doesn't cover the other manifest ecosystems Ignite otherwise
  // scans.
  const GUARDDOG_MANIFESTS = [
    { file: 'package.json', ecosystem: 'npm' },
    { file: 'requirements.txt', ecosystem: 'pypi' },
  ];

  // GuardDog's verdict for a given manifest's exact byte content is
  // deterministic (a published package's contents don't change), so the raw
  // per-dependency verdicts are cached globally (db-store.js's
  // manifest_scan_cache) keyed by (ecosystem, content hash, guarddog
  // version) — not by org/repo, since the same dependency set onboarded by
  // a different project should hit the same cache. Cached as pkgKey/
  // hitRules/issueCount tuples rather than finished `findings` objects,
  // since a finding's `file` is the manifest's path *within this particular
  // project* (e.g. "package.json" vs "backend/package.json") — something
  // the cache must stay agnostic to so a hit is valid regardless of where
  // the identical manifest happens to live in a different project.
  function guarddogVerdictsFromReport(report) {
    const verdicts = [];
    for (const [pkgKey, entry] of Object.entries(report || {})) {
      if (!entry || typeof entry !== 'object') continue;
      const hitRules = Object.entries(entry.results || {})
        .filter(([, v]) => v && v !== false)
        .map(([ruleId]) => ruleId);
      const issueCount = typeof entry.issues === 'number' ? entry.issues : hitRules.length;
      if (issueCount <= 0 && hitRules.length === 0) continue;
      verdicts.push({ pkgKey, hitRules, issueCount });
    }
    return verdicts;
  }

  async function checkMaliciousDependencies(root, log) {
    const tooling = GUARDDOG_ENABLED ? await guarddogTooling() : { ok: false, reason: 'guarddog is disabled (security.guarddog.enabled=false).' };
    if (!tooling.ok) {
      log?.(`⚠ GuardDog malicious-dependency scan skipped: ${tooling.reason}`);
      return { findings: [], engine: 'disabled' };
    }

    const findings = [];
    let cacheHits = 0;
    for await (const file of walkFiles(root)) {
      const spec = GUARDDOG_MANIFESTS.find((m) => m.file === path.basename(file));
      if (!spec) continue;
      const rel = path.relative(root, file);

      const contentHash = hashBuffer(await fsp.readFile(file));
      let verdicts = tooling.version
        ? store.getManifestScanCache('guarddog', spec.ecosystem, contentHash, tooling.version)
        : null;

      if (verdicts) {
        cacheHits++;
      } else {
        let report;
        try {
          const { stdout } = await runTool(
            'guarddog',
            [spec.ecosystem, 'verify', file, '--output-format', 'json'],
            root,
            { allowedExitCodes: [0, 1] } // GuardDog exits 1 (not 0) whenever it finds >=1 issue
          );
          report = JSON.parse(stdout);
        } catch (e) {
          log?.(`⚠ GuardDog scan of ${rel} failed: ${e.message}`);
          continue;
        }
        // `guarddog <ecosystem> verify` reports one entry per manifest
        // dependency, keyed by "name==version"/"name@version". Tolerant of
        // exactly which shape a given GuardDog version emits: any entry
        // carrying a positive `issues` count, or any truthy value in
        // `results`, counts as a hit.
        verdicts = guarddogVerdictsFromReport(report);
        if (tooling.version) {
          store.saveManifestScanCache('guarddog', spec.ecosystem, contentHash, tooling.version, verdicts);
        }
      }

      for (const { pkgKey, hitRules, issueCount } of verdicts) {
        findings.push({
          file: rel,
          line: null,
          kind: 'malicious-dependency',
          tool: 'guarddog',
          severity: 'error',
          message: `Dependency "${pkgKey}" flagged by GuardDog (${spec.ecosystem}): ${hitRules.length > 0 ? hitRules.join(', ') : `${issueCount} issue(s)`}.`,
        });
      }
    }
    if (cacheHits > 0) {
      log?.(`♻ ${cacheHits} manifest(s) unchanged since a previous scan (any project) — reused cached GuardDog results.`);
    }
    return { findings, engine: 'guarddog' };
  }

  return { checkMaliciousDependencies, guarddogTooling };
}

module.exports = { createMaliciousDependenciesCheck };
