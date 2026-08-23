'use strict';

/**
 * AI package-hallucination / slopsquat detection: flags a manifest
 * dependency whose name doesn't exist on its ecosystem's real public
 * registry. An LLM asked to write code routinely invents a plausible-
 * looking package name that was never published — a known failure mode
 * ("slopsquatting") an attacker can exploit by registering that exact
 * name and shipping malware to the next developer/agent who "helpfully"
 * `pip install`s or `npm install`s whatever the AI suggested. GuardDog
 * (checks/malicious-dependencies.js) inspects a package's *contents* once
 * it exists; this check is upstream of that — it asks "does this package
 * exist at all", the question that matters before GuardDog's question is
 * even reachable.
 *
 * Built-in, no external binary — a real HTTP existence check against each
 * ecosystem's own registry API (npm, PyPI, crates.io). Deliberately scoped
 * to those three: Go has no single central name registry to check against
 * (module paths are VCS URLs, not registry-assigned names), and Maven's
 * groupId:artifactId namespacing makes "does this exist" a fuzzier
 * question than a flat name lookup — both out of scope by design, not an
 * oversight.
 *
 * Always advisory (`severity: 'warning'`), never a hard blocker: "not
 * found on the public registry" is real signal but not proof of
 * hallucination — a private/internal package on a company registry, or a
 * git/workspace/file dependency that was never meant to resolve against
 * the public registry in the first place, looks identical from here.
 *
 * @param {object} deps
 * @param {object} deps.fsUtils - lib/fs-utils.js exports (walkFiles)
 * @param {Array} deps.studioManifests - server.js's STUDIO_MANIFESTS: [{ file, ecosystem, parse(content) => [{name, versionRange}] }]
 * @param {object} deps.config - { enabled, fetchImpl? } — fetchImpl overridable for tests, defaults to global fetch
 */
function createPackageHallucinationCheck({ fsUtils, studioManifests, config }) {
  const fsp = require('fs/promises');
  const path = require('path');
  const { walkFiles } = fsUtils;

  const ENABLED = Boolean(config.enabled);
  const doFetch = config.fetchImpl || globalThis.fetch;

  // Registry ecosystems this check knows how to ask "does this name exist"
  // of, and how to ask it. Each returns true (exists), false (confirmed
  // absent — a 404), or null (inconclusive — network/registry error,
  // never treated as a finding).
  const REGISTRY_CHECKERS = {
    npm: async (name) => {
      const res = await doFetch(`https://registry.npmjs.org/${encodeURIComponent(name).replaceAll('%40', '@')}`, { signal: AbortSignal.timeout(5000) });
      if (res.status === 404) return false;
      if (res.ok) return true;
      return null;
    },
    pypi: async (name) => {
      const res = await doFetch(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`, { signal: AbortSignal.timeout(5000) });
      if (res.status === 404) return false;
      if (res.ok) return true;
      return null;
    },
    cargo: async (name) => {
      const res = await doFetch(`https://crates.io/api/v1/crates/${encodeURIComponent(name)}`, { signal: AbortSignal.timeout(5000) });
      if (res.status === 404) return false;
      if (res.ok) return true;
      return null;
    },
  };

  // Version specifiers that never hit a public registry in the first
  // place (git/file/link/workspace-protocol deps) — checking these for
  // "hallucination" would just be noise, not signal.
  const NON_REGISTRY_VERSION_RE = /^(git\+|git:|https?:|file:|link:|workspace:|npm:.*@|github:)/i;

  // process-lifetime cache: registry existence for a given (ecosystem,
  // name) doesn't change meaningfully within a single Ignite process's
  // uptime, and (unlike GuardDog's manifest cache) it deliberately isn't
  // persisted to db-store — a "not found" result going stale across
  // restarts is exactly the failure mode to avoid, since the whole point
  // is catching a name that didn't exist at scan time.
  const existenceCache = new Map();

  async function existsOnRegistry(ecosystem, name) {
    const key = `${ecosystem}:${name}`;
    if (existenceCache.has(key)) return existenceCache.get(key);
    let result;
    try {
      result = await REGISTRY_CHECKERS[ecosystem](name);
    } catch {
      result = null;
    }
    existenceCache.set(key, result);
    return result;
  }

  async function checkPackageHallucination(root, log) {
    if (!ENABLED) {
      log?.('⚠ Package-hallucination scan skipped: disabled (security.packageHallucination.enabled=false).');
      return { findings: [], engine: 'disabled' };
    }
    if (typeof doFetch !== 'function') {
      log?.('⚠ Package-hallucination scan skipped: no fetch implementation available in this runtime.');
      return { findings: [], engine: 'disabled' };
    }

    const findings = [];
    let checkedCount = 0;
    for await (const file of walkFiles(root)) {
      const spec = studioManifests.find((m) => m.file === path.basename(file) && REGISTRY_CHECKERS[m.ecosystem]);
      if (!spec) continue;
      const rel = path.relative(root, file);

      let deps;
      try {
        deps = spec.parse(await fsp.readFile(file, 'utf8'));
      } catch {
        continue;
      }

      for (const { name, versionRange } of deps) {
        if (!name || NON_REGISTRY_VERSION_RE.test(String(versionRange || ''))) continue;
        checkedCount++;
        const exists = await existsOnRegistry(spec.ecosystem, name);
        if (exists === false) {
          findings.push({
            file: rel,
            line: null,
            kind: 'possible-package-hallucination',
            tool: 'ignite-built-in',
            severity: 'warning',
            message: `Dependency "${name}" (${spec.ecosystem}) was not found on the public registry — possibly an AI-hallucinated package name, vulnerable to squatting. If this is a real private/internal package, this is a false positive.`,
          });
        }
      }
    }
    log?.(`Checked ${checkedCount} manifest dependency name(s) against their public registries.`);
    return { findings, engine: 'built-in' };
  }

  return { checkPackageHallucination };
}

module.exports = { createPackageHallucinationCheck };
