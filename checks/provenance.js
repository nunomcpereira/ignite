'use strict';

/**
 * Minimal build/commit provenance — always runs, no external tool. Phase C
 * of the server.js module split (see
 * /Users/nuno/.claude/plans/cuddly-roaming-pearl.md).
 *
 * @param {object} deps
 * @param {Function} deps.runTool - from lib/tool-runner.js's createToolRunner()
 * @param {object} deps.fsUtils - lib/fs-utils.js exports (walkFiles)
 * @param {string} deps.igniteVersion - package.json version, recorded in runDetails.builder
 */
function createProvenanceCheck({ runTool, fsUtils, igniteVersion }) {
  const fsp = require('fs/promises');
  const path = require('path');
  const crypto = require('crypto');
  const { walkFiles } = fsUtils;

  // Content-addressed identity of exactly what was staged/scanned: a sha256
  // over every non-.git file's own sha256, sorted by relative path so the
  // digest is deterministic regardless of directory-walk order. Lets an
  // auditor confirm the tree that passed the pipeline is the same tree that
  // got pushed, without needing the staging directory to still exist (it's
  // force-removed after every run) — the digest alone is enough to compare
  // against a later re-hash of the pushed repo.
  async function digestProjectTree(root) {
    const entries = [];
    for await (const file of walkFiles(root)) {
      const rel = path.relative(root, file).split(path.sep).join('/');
      const buffer = await fsp.readFile(file).catch(() => null);
      if (buffer === null) continue;
      entries.push([rel, crypto.createHash('sha256').update(buffer).digest('hex')]);
    }
    entries.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
    const combined = crypto.createHash('sha256');
    for (const [rel, hash] of entries) combined.update(`${rel}:${hash}\n`);
    return { sha256: combined.digest('hex'), fileCount: entries.length };
  }

  // Minimal build/commit provenance document — OWASP A08 (Software and Data
  // Integrity Failures) gap: cosign (checks/image-provenance.js) verifies a
  // Dockerfile's *base image* provenance, but nothing previously recorded
  // provenance for the code Ignite itself is about to push. This is NOT a
  // signed SLSA attestation (no keyless/KMS signing, no transparency-log
  // entry, no SLSA builder-identity verification) — it's a same-shape,
  // unsigned in-toto Statement/SLSA-provenance-v1 predicate recording what
  // was scanned, by what, and when, so an auditor has *something*
  // machine-readable to check a later "is this the code that actually
  // passed the pipeline" question against. Attached as a downloadable
  // project document (provenance.json), same as the SBOM/LOC-metrics/
  // posture-report artifacts — never gates a run. Full SLSA L3 (signed,
  // verifiable builder identity) is out of scope; see the "note" field
  // below, which says so explicitly rather than implying more assurance
  // than this actually provides.
  async function generateProvenance(root, log, { org, repo, jobId } = {}) {
    const digest = await digestProjectTree(root);
    let sourceCommit = null;
    try {
      const { stdout } = await runTool('git', ['rev-parse', 'HEAD'], root);
      sourceCommit = stdout.trim() || null;
    } catch { /* no git context (fresh ZIP/folder upload before Phase 5/6 init) — fine, omitted */ }

    const provenance = {
      _type: 'https://in-toto.io/Statement/v1',
      subject: [{ name: org && repo ? `${org}/${repo}` : 'unknown', digest: { sha256: digest.sha256 } }],
      predicateType: 'https://slsa.dev/provenance/v1',
      predicate: {
        buildDefinition: {
          buildType: 'https://github.com/nunomcpereira/ignite/onboarding-pipeline/v1',
          externalParameters: { org: org || null, repo: repo || null, jobId: jobId || null },
          resolvedDependencies: sourceCommit ? [{ uri: `git+commit:${sourceCommit}` }] : [],
        },
        runDetails: {
          builder: { id: 'https://github.com/nunomcpereira/ignite', version: { ignite: igniteVersion } },
          metadata: { generatedAt: new Date().toISOString(), fileCount: digest.fileCount },
        },
      },
      note: 'Minimal build/commit provenance for audit purposes — NOT a signed SLSA attestation (no keyless/KMS signing, no transparency-log entry, no verified builder identity). subject.digest is a sha256 over every staged file\'s own sha256, sorted by relative path.',
    };
    log?.(`✓ Provenance recorded — ${digest.fileCount} file(s), tree digest sha256:${digest.sha256.slice(0, 12)}…${sourceCommit ? `, source commit ${sourceCommit.slice(0, 12)}` : ''}.`);
    return provenance;
  }

  return { digestProjectTree, generateProvenance };
}

module.exports = { createProvenanceCheck };
