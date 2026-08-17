'use strict';

/**
 * CycloneDX SBOM generation via Syft. Phase C of the server.js module
 * split (see /Users/nuno/.claude/plans/cuddly-roaming-pearl.md).
 *
 * @param {object} deps
 * @param {Function} deps.runTool - from lib/tool-runner.js's createToolRunner()
 * @param {object} deps.fsUtils - lib/fs-utils.js exports (walkFiles)
 * @param {object} deps.config - { enabled }
 * @param {Array} deps.studioManifests - STUDIO_MANIFESTS (same manifest parsers scanDependencyLicensesFallback uses)
 * @param {number} deps.studioMaxDepsPerManifest - STUDIO_MAX_DEPS_PER_MANIFEST
 */
function createSbomCheck({ runTool, fsUtils, config, studioManifests, studioMaxDepsPerManifest }) {
  const fsp = require('fs/promises');
  const path = require('path');
  const os = require('os');
  const crypto = require('crypto');
  const { walkFiles } = fsUtils;

  const SYFT_ENABLED = Boolean(config.enabled);

  async function syftTooling() {
    try {
      await runTool('syft', ['version'], os.tmpdir());
      return { ok: true };
    } catch {
      return { ok: false, reason: '`syft` is not installed (brew install syft) — falling back to a minimal manifest-derived component list (no standards-format SBOM).' };
    }
  }

  // Best-effort component list built purely from this app's own manifest
  // parsers (studioManifests — the same ones scanDependencyLicensesFallback
  // uses), used only when syft is disabled or not installed. Intentionally
  // minimal: name/version pairs per ecosystem, no dependency graph, no CPEs,
  // no license metadata — real SBOM generation needs the real tool.
  async function generateSbomFallback(root) {
    const components = [];
    for await (const file of walkFiles(root)) {
      const spec = studioManifests.find((m) => m.file === path.basename(file));
      if (!spec) continue;
      const content = await fsp.readFile(file, 'utf8').catch(() => null);
      if (content == null) continue;
      const rawDeps = spec.parse(content).slice(0, studioMaxDepsPerManifest);
      for (const dep of rawDeps) {
        components.push({ name: dep.name, version: dep.versionRange || null, ecosystem: spec.ecosystem, type: 'library' });
      }
    }
    return { bomFormat: 'ignite-fallback', specVersion: null, components };
  }

  // Generates a CycloneDX SBOM for the staged project via Syft, which does
  // its own multi-ecosystem manifest/lockfile discovery in one pass (same
  // relationship trivy has to checkIacSecurityFallback's narrow heuristic).
  // Never throws: returns the built-in fallback component list on any
  // missing-tool/parse failure, so a run is never blocked on it.
  async function generateSbom(root, log) {
    const tooling = SYFT_ENABLED ? await syftTooling() : { ok: false, reason: 'syft is disabled (sbom.syft.enabled=false).' };
    if (!tooling.ok) {
      log?.(`⚠ Syft SBOM generation skipped: ${tooling.reason}`);
      return { engine: 'fallback', sbom: await generateSbomFallback(root) };
    }

    log?.('Engine: Syft CLI (External) — generating a CycloneDX SBOM...');
    const reportPath = path.join(os.tmpdir(), `ignite-syft-${crypto.randomBytes(8).toString('hex')}.json`);
    try {
      await runTool('syft', [root, '-o', `cyclonedx-json=${reportPath}`, '--quiet'], root);
      const raw = await fsp.readFile(reportPath, 'utf8');
      const sbom = JSON.parse(raw);
      return { engine: 'syft', sbom };
    } catch (e) {
      log?.(`⚠ Syft SBOM generation failed, falling back to a minimal component list: ${e.message}`);
      return { engine: 'fallback', sbom: await generateSbomFallback(root) };
    } finally {
      await fsp.unlink(reportPath).catch(() => {});
    }
  }

  return { generateSbom, generateSbomFallback, syftTooling };
}

module.exports = { createSbomCheck };
