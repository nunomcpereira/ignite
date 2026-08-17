'use strict';

/**
 * Verifies Sigstore/cosign keyless signatures on every unique external base
 * image referenced by a Dockerfile FROM. Phase C of the server.js module
 * split (see /Users/nuno/.claude/plans/cuddly-roaming-pearl.md).
 *
 * Factory: createImageProvenanceCheck({ runTool, store, fsUtils, config })
 * takes its dependencies as parameters rather than reading CONFIG/store
 * from a module-level singleton, per the split's design rule.
 */

const fsp = require('fs/promises');
const path = require('path');

/**
 * @param {object} deps
 * @param {Function} deps.runTool - from lib/tool-runner.js's createToolRunner()
 * @param {object} deps.store - db-store.js instance (cosign verify cache)
 * @param {object} deps.fsUtils - lib/fs-utils.js exports (walkFiles, looksBinary, buildSnippet, DOCKERFILE_NAME_RE)
 * @param {object} deps.config - { enabled, identityRegexp, issuerRegexp, cacheTtlSeconds }
 */
function createImageProvenanceCheck({ runTool, store, fsUtils, config }) {
  const { walkFiles, looksBinary, buildSnippet, DOCKERFILE_NAME_RE } = fsUtils;
  const COSIGN_ENABLED = Boolean(config.enabled);
  const COSIGN_IDENTITY_REGEXP = String(config.identityRegexp || '.*');
  const COSIGN_ISSUER_REGEXP = String(config.issuerRegexp || '.*');
  const COSIGN_CACHE_TTL_SECONDS = Number.isFinite(Number(config.cacheTtlSeconds)) ? Number(config.cacheTtlSeconds) : 3600;

  async function cosignTooling() {
    try {
      await runTool('cosign', ['version'], require('os').tmpdir());
      return { ok: true };
    } catch {
      return { ok: false, reason: '`cosign` is not installed (brew install cosign) — base-image signature verification is skipped.' };
    }
  }

  // Collects every external base image referenced by FROM in the project's
  // Dockerfiles, alongside the exact file/line it came from (for Studio
  // addressability). Multi-stage build aliases (`FROM builder` referencing an
  // earlier `AS builder` stage) are excluded — they're not external images
  // and cosign has nothing to verify against.
  async function discoverBaseImages(root) {
    const occurrences = [];
    for await (const file of walkFiles(root)) {
      if (!DOCKERFILE_NAME_RE.test(path.basename(file))) continue;
      const buffer = await fsp.readFile(file);
      if (looksBinary(buffer)) continue;
      const content = buffer.toString('utf8');
      const rel = path.relative(root, file);
      const lines = content.split(/\r?\n/);
      const stageNames = new Set();
      lines.forEach((line, i) => {
        const m = line.match(/^\s*FROM\s+(\S+?)(?:\s+AS\s+(\S+))?\s*$/i);
        if (!m) return;
        const image = m[1];
        if (m[2]) stageNames.add(m[2]);
        if (stageNames.has(image) || image.toLowerCase() === 'scratch') return;
        occurrences.push({ file: rel, line: i + 1, image });
      });
    }
    return occurrences;
  }

  // Verifies Sigstore/cosign keyless signatures on every unique external base
  // image found across the project's Dockerfiles. Each unique image is
  // verified once (cosign verify is a real network call to the image
  // registry + Rekor transparency log) and the result is fanned back out to
  // every file/line occurrence that referenced it. Never throws: any
  // tool/network failure is reported as an "unverifiable" finding rather than
  // aborting the run.
  async function checkImageProvenance(root, log) {
    const tooling = COSIGN_ENABLED ? await cosignTooling() : { ok: false, reason: 'cosign is disabled (security.cosign.enabled=false).' };
    if (!tooling.ok) {
      log?.(`⚠ Cosign base-image signature check skipped: ${tooling.reason}`);
      return { findings: [], engine: 'disabled' };
    }

    const occurrences = await discoverBaseImages(root);
    if (occurrences.length === 0) return { findings: [], engine: 'cosign' };

    log?.('Engine: Cosign CLI (External) — verifying Sigstore signatures on referenced base images...');
    const uniqueImages = [...new Set(occurrences.map((o) => o.image))];
    const verdictByImage = new Map();
    let cacheHits = 0;
    await Promise.all(uniqueImages.map(async (image) => {
      if (COSIGN_CACHE_TTL_SECONDS > 0) {
        const cached = store.getCosignVerifyCache(image, COSIGN_IDENTITY_REGEXP, COSIGN_ISSUER_REGEXP, COSIGN_CACHE_TTL_SECONDS);
        if (cached) {
          cacheHits++;
          verdictByImage.set(image, cached);
          log?.(`♻ ${image} — reused a signature verdict checked within the last ${COSIGN_CACHE_TTL_SECONDS}s.`);
          return;
        }
      }
      try {
        await runTool('cosign', [
          'verify',
          '--certificate-identity-regexp', COSIGN_IDENTITY_REGEXP,
          '--certificate-oidc-issuer-regexp', COSIGN_ISSUER_REGEXP,
          image,
        ], root, { allowedExitCodes: [0] });
        verdictByImage.set(image, { verified: true });
        log?.(`✓ ${image} — verifiable Sigstore signature.`);
      } catch (e) {
        verdictByImage.set(image, { verified: false, reason: e.message });
        log?.(`⚠ ${image} — no verifiable Sigstore signature: ${e.message}`);
      }
      if (COSIGN_CACHE_TTL_SECONDS > 0) {
        const v = verdictByImage.get(image);
        store.saveCosignVerifyCache(image, COSIGN_IDENTITY_REGEXP, COSIGN_ISSUER_REGEXP, v.verified, v.reason);
      }
    }));
    if (cacheHits > 0) log?.(`♻ ${cacheHits} image(s) served from the signature-verdict cache — no network call.`);

    const findings = [];
    const contentByFile = new Map();
    for (const occ of occurrences) {
      const verdict = verdictByImage.get(occ.image);
      if (verdict.verified) continue;
      let content = contentByFile.get(occ.file);
      if (content === undefined) {
        content = null;
        try { content = await fsp.readFile(path.join(root, occ.file), 'utf8'); } catch { /* best-effort */ }
        contentByFile.set(occ.file, content);
      }
      findings.push({
        file: occ.file,
        line: occ.line,
        kind: 'unsigned-base-image',
        tool: 'cosign',
        severity: 'warning',
        message: `Base image "${occ.image}" has no verifiable Sigstore/cosign signature — supply-chain provenance can't be confirmed.`,
        code: content ? buildSnippet(content, occ.line) : null,
      });
    }
    return { findings, engine: 'cosign' };
  }

  return { checkImageProvenance, cosignTooling, discoverBaseImages };
}

module.exports = { createImageProvenanceCheck };
