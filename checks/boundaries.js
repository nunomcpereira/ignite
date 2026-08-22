'use strict';

/**
 * Built-in architecture-boundary enforcement — closes the "no architecture/
 * boundary enforcement" gap against fallow.tools (see project memory).
 * Reuses lib/module-graph.js's import graph (same parser dead-code.js
 * uses) rather than a second one. A project opts in via
 * CONFIG.architecture.boundaries: either a named preset (bulletproof/
 * layered/hexagonal/feature-sliced — same four Fallow ships) or custom
 * `zones: [{ name, pattern, allow: [zoneName,...] }]`. A file belongs to
 * the first zone whose glob-ish `pattern` matches its project-relative
 * path (first match wins, mirroring Fallow's own rule); files matching no
 * zone are unrestricted. Self-imports within a zone are always allowed.
 *
 * Off by default (architecture.boundaries.enabled=false) — unlike the
 * always-on built-ins (LOC/file-size), a wrong/default zone layout would
 * produce pure noise for a project that doesn't follow one of these
 * conventions, so this only activates on explicit project opt-in.
 */

const path = require('path');

const PRESETS = {
  bulletproof: {
    zones: [
      { name: 'shared', pattern: 'src/shared/**', allow: [] },
      { name: 'features', pattern: 'src/features/*/**', allow: ['shared'] },
      { name: 'app', pattern: 'src/app/**', allow: ['shared', 'features'] },
    ],
  },
  layered: {
    zones: [
      { name: 'domain', pattern: '{src,lib}/domain/**', allow: [] },
      { name: 'service', pattern: '{src,lib}/service*/**', allow: ['domain'] },
      { name: 'controller', pattern: '{src,lib}/{controllers,routes,api}/**', allow: ['service', 'domain'] },
    ],
  },
  hexagonal: {
    zones: [
      { name: 'domain', pattern: '{src,lib}/domain/**', allow: [] },
      { name: 'ports', pattern: '{src,lib}/ports/**', allow: ['domain'] },
      { name: 'adapters', pattern: '{src,lib}/adapters/**', allow: ['ports', 'domain'] },
    ],
  },
  'feature-sliced': {
    zones: [
      { name: 'shared', pattern: 'src/shared/**', allow: [] },
      { name: 'entities', pattern: 'src/entities/*/**', allow: ['shared'] },
      { name: 'features', pattern: 'src/features/*/**', allow: ['shared', 'entities'] },
      { name: 'widgets', pattern: 'src/widgets/*/**', allow: ['shared', 'entities', 'features'] },
      { name: 'pages', pattern: 'src/pages/*/**', allow: ['shared', 'entities', 'features', 'widgets'] },
    ],
  },
};

// Minimal glob-ish matcher: '**' = any depth, '*' = one path segment,
// '{a,b}' = alternation. Enough for the zone patterns above and any
// reasonable custom pattern without pulling in a glob library.
function globToRegExp(glob) {
  let out = '^';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    // A single '*' (not part of '**') becomes a *capturing* group — zoneOf
    // uses it to tell apart sibling instances of the same zone (e.g.
    // src/features/auth vs src/features/billing both match zone "features",
    // but they're different feature instances, and Bulletproof/Feature-
    // Sliced isolate siblings from each other by design, not just from
    // other zone tiers). '**' stays a plain, non-capturing "any depth".
    if (c === '*' && glob[i + 1] === '*') { out += '.*'; i++; }
    else if (c === '*') out += '([^/]*)';
    else if (c === '{') {
      const end = glob.indexOf('}', i);
      const alts = glob.slice(i + 1, end).split(',').map((a) => a.trim().replace(/[.+^${}()|[\]\\]/g, '\\$&'));
      out += `(?:${alts.join('|')})`;
      i = end;
    } else if ('.+^${}()|[]\\'.includes(c)) out += '\\' + c;
    else out += c;
  }
  return new RegExp(out + '$');
}

function resolveZones(config) {
  if (config.preset && PRESETS[config.preset]) {
    const base = PRESETS[config.preset].zones;
    if (!Array.isArray(config.zones)) return base;
    // Preset + overrides: custom zones win by name, rest of preset kept.
    const byName = new Map(base.map((z) => [z.name, z]));
    for (const z of config.zones) byName.set(z.name, z);
    return [...byName.values()];
  }
  return Array.isArray(config.zones) ? config.zones : [];
}

// Returns { zone, instance } — instance is the first captured '*' segment
// (e.g. "auth" for src/features/auth/index.js under "src/features/*/**"),
// or null when the zone's pattern has no single-'*' segment (a zone with
// no sibling concept, like "shared" or "domain").
function zoneOf(zones, rel) {
  for (const z of zones) {
    const m = globToRegExp(z.pattern).exec(rel);
    if (m) return { zone: z, instance: m[1] ?? null };
  }
  return null;
}

function createBoundariesCheck({ fsUtils, config }) {
  const { walkFiles, looksBinary, buildSnippet } = fsUtils;
  const ENABLED = Boolean(config.enabled);

  async function checkBoundaries(root, log) {
    if (!ENABLED) {
      log?.('Architecture boundary check is disabled (architecture.boundaries.enabled=false).');
      return { findings: [], engine: 'disabled' };
    }
    const zones = resolveZones(config);
    if (zones.length === 0) {
      log?.('Architecture boundary check enabled but no zones configured (set architecture.boundaries.preset or .zones) — skipping.');
      return { findings: [], engine: 'unconfigured' };
    }

    const { buildModuleGraph } = require('../lib/module-graph');
    const { graph } = await buildModuleGraph(root, { walkFiles, looksBinary });

    const findings = [];
    for (const [file, node] of graph) {
      const rel = path.relative(root, file);
      const from = zoneOf(zones, rel);
      if (!from) continue;
      for (const imp of node.imports) {
        const impRel = path.relative(root, imp);
        const to = zoneOf(zones, impRel);
        if (!to) continue;
        // Same zone AND same sibling instance (or a zone with no sibling
        // concept at all, e.g. "shared"/"domain") — an ordinary same-
        // feature import, always allowed.
        const sameInstance = to.zone.name === from.zone.name && to.instance === from.instance;
        if (sameInstance) continue;
        const allowed = Array.isArray(from.zone.allow) && from.zone.allow.includes(to.zone.name);
        if (allowed) continue;
        const lineIdx = node.content.split('\n').findIndex((l) => l.includes(impRel) || (l.includes('import') && l.includes(path.basename(imp).replace(/\.[^.]+$/, ''))));
        const line = lineIdx >= 0 ? lineIdx + 1 : 1;
        const toLabel = to.zone.name === from.zone.name ? `${to.zone.name} (sibling "${to.instance}")` : to.zone.name;
        findings.push({
          file: rel,
          line,
          kind: 'boundary-violation',
          tool: 'ignite-built-in',
          severity: 'warning',
          message: `Zone "${from.zone.name}"${from.instance ? ` (sibling "${from.instance}")` : ''} imports from zone "${toLabel}" (${impRel}), which its allowed-imports list (${from.zone.allow?.length ? from.zone.allow.join(', ') : 'none'}) doesn't permit — architecture drift from the configured ${config.preset || 'custom'} layout.`,
          code: buildSnippet(node.content, line),
        });
      }
    }

    log?.(`Checked ${graph.size} file(s) against ${zones.length} zone(s); ${findings.length} boundary violation(s).`);
    return { findings, engine: 'built-in', zoneCount: zones.length };
  }

  return { checkBoundaries };
}

module.exports = { createBoundariesCheck, PRESETS, globToRegExp, resolveZones, zoneOf };
