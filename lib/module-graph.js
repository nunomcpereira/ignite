'use strict';

/**
 * Lightweight JS/TS module graph: parses import/require/export statements
 * with regexes (no bundled parser dependency — keeps this zero-install,
 * same philosophy as checks/feature-posture.js's fallback engine) and
 * resolves relative specifiers to real files on disk. Shared by
 * checks/dead-code.js (reachability) and checks/boundaries.js (import
 * direction) so both walk the exact same graph instead of maintaining two
 * parsers that could disagree on what "imports what" means.
 *
 * Deliberately not a full parser: template-literal-constructed imports,
 * `eval`, and re-exports through `export * from` chains beyond one hop are
 * out of scope, the same tradeoff every regex-based check in this
 * repo (secrets, ai-governance) already makes. A file that's actually used
 * only through such a path is a false positive this module can produce —
 * acceptable for an advisory signal, not for a blocking one (see
 * checks/dead-code.js's severity choice).
 */

const fsp = require('fs/promises');
const path = require('path');

const JS_TS_EXT = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.mts', '.cts'];
const RESOLVABLE_EXTS = [...JS_TS_EXT, '.json'];

// import x from 'y'; import {a,b} from 'y'; import * as z from 'y';
// export {a} from 'y'; export * from 'y'; dynamic import('y'); require('y')
const IMPORT_RE = /\bimport\s+(?:[\w*{},\s]+\s+from\s+)?['"]([^'"]+)['"]/g;
const EXPORT_FROM_RE = /\bexport\s+(?:\*|\{[^}]*\})\s+from\s+['"]([^'"]+)['"]/g;
const DYNAMIC_IMPORT_RE = /\bimport\(\s*['"]([^'"]+)['"]\s*\)/g;
const REQUIRE_RE = /\brequire\(\s*['"]([^'"]+)['"]\s*\)/g;

// Named export surface: `export function foo`, `export const bar =`,
// `export class Baz`, `export { a, b as c }`, `export default ...`,
// `module.exports.foo =`, `exports.foo =`.
const EXPORT_DECL_RE = /\bexport\s+(?:async\s+)?(?:function\*?|class|const|let|var)\s+([A-Za-z_$][\w$]*)/g;
const EXPORT_LIST_RE = /\bexport\s*\{([^}]*)\}(?!\s*from)/g;
const EXPORT_DEFAULT_RE = /\bexport\s+default\b/;
const CJS_EXPORT_RE = /\b(?:module\.exports\.|exports\.)([A-Za-z_$][\w$]*)\s*=/g;
// The other common CommonJS shape: `module.exports = { a, b, c: renamed }`
// — an object-literal assignment rather than per-property assignment.
// Deliberately only matches a single-line-ish shorthand/aliased property
// list (no nested objects/computed keys), the same scoping tradeoff
// EXPORT_LIST_RE makes for ES `export { }` lists.
const CJS_EXPORT_OBJECT_RE = /\bmodule\.exports\s*=\s*\{([^}]*)\}/;

function isRelativeSpecifier(spec) {
  return spec.startsWith('.') || spec.startsWith('/');
}

async function resolveSpecifier(fromFile, spec, root, fileSet) {
  if (!isRelativeSpecifier(spec)) return null; // bare package specifier — not project-local
  const base = path.resolve(path.dirname(fromFile), spec);
  const candidates = [base, ...RESOLVABLE_EXTS.map((ext) => base + ext), ...RESOLVABLE_EXTS.map((ext) => path.join(base, 'index' + ext))];
  for (const c of candidates) {
    if (fileSet.has(c)) return c;
  }
  return null;
}

function extractSpecifiers(content) {
  const specs = [];
  for (const re of [IMPORT_RE, EXPORT_FROM_RE, DYNAMIC_IMPORT_RE, REQUIRE_RE]) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(content))) specs.push(m[1]);
  }
  return specs;
}

function extractExports(content) {
  const names = new Set();
  let hasDefault = EXPORT_DEFAULT_RE.test(content);
  let m;
  EXPORT_DECL_RE.lastIndex = 0;
  while ((m = EXPORT_DECL_RE.exec(content))) names.add(m[1]);
  EXPORT_LIST_RE.lastIndex = 0;
  while ((m = EXPORT_LIST_RE.exec(content))) {
    for (const part of m[1].split(',')) {
      const piece = part.trim();
      if (!piece) continue;
      const asMatch = piece.match(/^([\w$]+)(?:\s+as\s+([\w$]+))?$/);
      if (!asMatch) continue;
      if (asMatch[1] === 'default') { hasDefault = true; continue; }
      names.add(asMatch[2] || asMatch[1]);
    }
  }
  CJS_EXPORT_RE.lastIndex = 0;
  while ((m = CJS_EXPORT_RE.exec(content))) names.add(m[1]);
  const objMatch = content.match(CJS_EXPORT_OBJECT_RE);
  if (objMatch) {
    for (const part of objMatch[1].split(',')) {
      const piece = part.trim();
      if (!piece) continue;
      // `{ key: value }` -> exported name is the key (what a consumer
      // destructures as), not the local value identifier.
      const key = piece.split(':')[0].trim().replace(/^\.\.\.$/, '');
      if (key && /^[A-Za-z_$][\w$]*$/.test(key)) names.add(key);
    }
  }
  return { names: [...names], hasDefault };
}

/**
 * Builds { files: Map<absPath, {content, imports:[abs...], exports, bareImports:[spec...]}> }
 * over every JS/TS-family file under root.
 */
async function buildModuleGraph(root, { walkFiles, looksBinary }) {
  const files = [];
  for await (const f of walkFiles(root)) {
    if (JS_TS_EXT.includes(path.extname(f))) files.push(f);
  }
  const fileSet = new Set(files);
  const graph = new Map();

  for (const file of files) {
    let buffer;
    try { buffer = await fsp.readFile(file); } catch { continue; }
    if (looksBinary(buffer)) continue;
    const content = buffer.toString('utf8');
    const specs = extractSpecifiers(content);
    const imports = [];
    const bareImports = [];
    for (const spec of specs) {
      if (isRelativeSpecifier(spec)) {
        const resolved = await resolveSpecifier(file, spec, root, fileSet);
        if (resolved) imports.push(resolved);
      } else {
        bareImports.push(spec);
      }
    }
    graph.set(file, { content, imports, bareImports, exports: extractExports(content) });
  }

  return { files, graph };
}

/**
 * Finds import cycles in a module graph (as built by buildModuleGraph),
 * closing the "no circular-dependency detection" gap against fallow.tools
 * (see project memory). Standard three-color DFS: WHITE (unvisited), GRAY
 * (on the current DFS stack), BLACK (fully explored) — hitting a GRAY node
 * means the path from that node back to itself through the current stack
 * is a cycle.
 *
 * Returns one array of absolute file paths per distinct cycle, each
 * starting at its lexicographically-smallest member (a rotation-invariant
 * canonical form) so the same cycle reached via two different entry files
 * is reported once, not once per participant.
 */
function findCycles(graph) {
  const WHITE = 0, GRAY = 1, BLACK = 2;
  const color = new Map();
  for (const file of graph.keys()) color.set(file, WHITE);

  const stack = [];
  const stackIndex = new Map();
  const seen = new Set();
  const cycles = [];

  function canonicalize(cycleFiles) {
    let minIdx = 0;
    for (let i = 1; i < cycleFiles.length; i++) {
      if (cycleFiles[i] < cycleFiles[minIdx]) minIdx = i;
    }
    return [...cycleFiles.slice(minIdx), ...cycleFiles.slice(0, minIdx)];
  }

  function dfs(file) {
    color.set(file, GRAY);
    stackIndex.set(file, stack.length);
    stack.push(file);

    const node = graph.get(file);
    for (const imp of node?.imports || []) {
      if (!graph.has(imp)) continue;
      const c = color.get(imp);
      if (c === WHITE) {
        dfs(imp);
      } else if (c === GRAY) {
        const cycleFiles = canonicalize(stack.slice(stackIndex.get(imp)));
        const key = cycleFiles.join('\n');
        if (!seen.has(key)) {
          seen.add(key);
          cycles.push(cycleFiles);
        }
      }
    }

    stack.pop();
    stackIndex.delete(file);
    color.set(file, BLACK);
  }

  for (const file of graph.keys()) {
    if (color.get(file) === WHITE) dfs(file);
  }

  return cycles;
}

module.exports = { buildModuleGraph, extractSpecifiers, extractExports, isRelativeSpecifier, findCycles, JS_TS_EXT };
