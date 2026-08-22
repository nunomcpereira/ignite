'use strict';

/**
 * Built-in dead-code / unused-export / unused-dependency scan for JS/TS
 * projects — closes the "no reachability analysis" gap against
 * fallow.tools (see project memory). No external tool required: builds a
 * module graph (lib/module-graph.js) via regex-based import/export
 * parsing, walks it from a heuristic entry-point set, and flags anything
 * unreached. Optionally upgrades to a type-aware confirmation pass when the
 * *scanned project itself* has `typescript` installed in its own
 * node_modules — same soft-dependency shape as gitleaks/trivy/etc, except
 * the "tool" here is a library already inside the project being scanned
 * rather than a separate CLI binary.
 *
 * Always advisory (`severity: 'warning'`), never blocking: this is a
 * heuristic, regex-based reachability graph (see lib/module-graph.js's doc
 * comment on what it can't see — template-literal imports, deep
 * `export *` chains, tsconfig path aliases) — false positives are possible,
 * so a human should confirm before deleting, not be blocked by it.
 */

const fsp = require('fs/promises');
const path = require('path');

function createDeadCodeCheck({ fsUtils, config }) {
  const { walkFiles, looksBinary, buildSnippet } = fsUtils;
  const { buildModuleGraph, JS_TS_EXT } = require('../lib/module-graph');

  const ENABLED = config.enabled !== false;
  const TEST_FILE_RE = /(\.test\.|\.spec\.|[/\\]__tests__[/\\]|[/\\]__mocks__[/\\])/i;
  const CONFIG_FILE_RE = /\.config\.(js|cjs|mjs|ts)$|^(jest|vitest|webpack|rollup|vite|babel|eslint|tailwind|postcss|next|playwright)\.config\./i;
  const ENTRY_BASENAME_RE = /^(index|main|server|app|cli)\.(js|jsx|ts|tsx|mjs|cjs)$/i;

  async function readJson(file) {
    try { return JSON.parse(await fsp.readFile(file, 'utf8')); } catch { return null; }
  }

  function collectPkgEntryPoints(pkg, pkgDir, fileSet) {
    const rels = [];
    const push = (v) => { if (typeof v === 'string') rels.push(v); };
    push(pkg.main); push(pkg.module); push(pkg.types); push(pkg.typings);
    if (pkg.bin) {
      if (typeof pkg.bin === 'string') push(pkg.bin);
      else if (typeof pkg.bin === 'object') Object.values(pkg.bin).forEach(push);
    }
    if (pkg.exports) {
      const walk = (node) => {
        if (typeof node === 'string') push(node);
        else if (node && typeof node === 'object') Object.values(node).forEach(walk);
      };
      walk(pkg.exports);
    }
    const resolved = new Set();
    for (const rel of rels) {
      const base = path.resolve(pkgDir, rel);
      for (const cand of [base, ...JS_TS_EXT.map((e) => base.replace(/\.[^./]+$/, '') + e), base + '.js']) {
        if (fileSet.has(cand)) resolved.add(cand);
      }
    }
    return resolved;
  }

  async function typescriptAvailableFor(root) {
    try {
      const require2 = require('module').createRequire(path.join(root, 'package.json'));
      return require2.resolve('typescript');
    } catch {
      return null;
    }
  }

  /**
   * Type-aware confirmation: uses TypeScript's own parser (not the regex
   * heuristic above) to re-derive the real top-level export symbol names
   * for a .ts/.tsx file via its AST, so a regex match that actually landed
   * inside a comment/string/nested-scope declaration (a false positive the
   * plain-regex pass in extractExports can't distinguish) gets filtered
   * out before being reported. This is the "type-aware" half of the gap —
   * real syntax tree, not text pattern matching — scoped to what's cheap
   * to do without a full program+checker (no cross-file symbol resolution
   * needed for this narrowing). Best-effort: any parse failure just keeps
   * the regex-only candidate as-is.
   */
  function realExportNamesViaTs(ts, filePath, content) {
    const isTs = /\.tsx?$/.test(filePath);
    if (!isTs) return null; // AST narrowing only applies where TS's parser understands the syntax best
    try {
      const sf = ts.createSourceFile(filePath, content, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
      const names = new Set();
      const hasExportModifier = (node) => (ts.getCombinedModifierFlags?.(node) || 0) & ts.ModifierFlags.Export;
      const visit = (node) => {
        if (ts.isFunctionDeclaration(node) && node.name && hasExportModifier(node)) names.add(node.name.text);
        else if (ts.isClassDeclaration(node) && node.name && hasExportModifier(node)) names.add(node.name.text);
        else if (ts.isVariableStatement(node) && hasExportModifier(node)) {
          for (const decl of node.declarationList.declarations) {
            if (ts.isIdentifier(decl.name)) names.add(decl.name.text);
          }
        } else if (ts.isExportDeclaration(node) && node.exportClause && ts.isNamedExports(node.exportClause)) {
          for (const el of node.exportClause.elements) names.add((el.propertyName || el.name).text);
        }
        ts.forEachChild(node, visit);
      };
      visit(sf);
      return names;
    } catch {
      return null;
    }
  }

  function confirmCandidatesWithTypescript(candidatesByFile, ts) {
    const kept = [];
    for (const [file, names] of candidatesByFile) {
      const content = names[0]?.content;
      const realNames = realExportNamesViaTs(ts, file, content);
      for (const cand of names) {
        if (realNames === null || realNames.has(cand.name)) kept.push(cand);
      }
    }
    return kept;
  }

  async function checkDeadCode(root, log) {
    if (!ENABLED) {
      log?.('Dead-code scan is disabled (deadCode.enabled=false).');
      return { findings: [], engine: 'disabled' };
    }

    const { files, graph } = await buildModuleGraph(root, { walkFiles, looksBinary });
    if (files.length === 0) {
      return { findings: [], engine: 'built-in', scanned: 0 };
    }
    const fileSet = new Set(files);

    // --- Entry points -------------------------------------------------
    const entries = new Set();
    for (const f of files) {
      const base = path.basename(f);
      if (TEST_FILE_RE.test(f) || CONFIG_FILE_RE.test(base) || ENTRY_BASENAME_RE.test(base)) entries.add(f);
    }
    const pkgFiles = files.filter((f) => path.basename(f) === 'package.json'); // none — package.json isn't JS_TS_EXT
    const pkgJsonPath = path.join(root, 'package.json');
    const pkg = await readJson(pkgJsonPath);
    if (pkg) {
      for (const e of collectPkgEntryPoints(pkg, root, fileSet)) entries.add(e);
    }

    // --- Reachability (BFS from entries) -------------------------------
    const reached = new Set(entries);
    const queue = [...entries];
    while (queue.length) {
      const cur = queue.shift();
      const node = graph.get(cur);
      if (!node) continue;
      for (const imp of node.imports) {
        if (!reached.has(imp)) { reached.add(imp); queue.push(imp); }
      }
    }

    const findings = [];

    // --- Unused files ---------------------------------------------------
    for (const f of files) {
      if (reached.has(f)) continue;
      const rel = path.relative(root, f);
      findings.push({
        file: rel,
        line: 1,
        kind: 'unused-file',
        tool: 'ignite-built-in',
        severity: 'warning',
        message: `${rel} is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.`,
        code: buildSnippet(graph.get(f)?.content || '', 1),
      });
    }

    // --- Unused exports (within reached files only — an unreached file's
    // exports are already covered by the unused-file finding above) -----
    // Build a project-wide "referenced names" set from every import
    // specifier list and every bare identifier access, so a named export
    // used anywhere (including from an unreached file, conservatively) is
    // not double-flagged.
    // Two destructuring shapes count as "this name is referenced elsewhere":
    // ES `import { name } from '...'` and CJS `const { name } = require('...')`.
    const namedImportRe = /\bimport\s*\{([^}]*)\}\s*from\s*['"][^'"]+['"]/g;
    const cjsDestructureRe = /\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(/g;
    const referencedNames = new Set();
    for (const [, node] of graph) {
      let m;
      namedImportRe.lastIndex = 0;
      while ((m = namedImportRe.exec(node.content))) {
        for (const part of m[1].split(',')) {
          const piece = part.trim();
          if (!piece) continue;
          const asMatch = piece.match(/^([\w$]+)(?:\s+as\s+([\w$]+))?$/);
          if (asMatch) referencedNames.add(asMatch[1]);
        }
      }
      cjsDestructureRe.lastIndex = 0;
      while ((m = cjsDestructureRe.exec(node.content))) {
        for (const part of m[1].split(',')) {
          const piece = part.trim().split(':')[0].trim();
          if (piece && /^[\w$]+$/.test(piece)) referencedNames.add(piece);
        }
      }
    }

    let unusedExportCandidates = [];
    for (const f of files) {
      if (!reached.has(f)) continue; // already flagged as a whole unused file
      const node = graph.get(f);
      if (!node) continue;
      for (const name of node.exports.names) {
        if (referencedNames.has(name)) continue;
        unusedExportCandidates.push({ file: f, name, content: node.content });
      }
    }

    let engine = 'built-in';
    const tsPath = await typescriptAvailableFor(root);
    if (tsPath && unusedExportCandidates.length > 0) {
      try {
        const ts = require(tsPath);
        const byFile = new Map();
        for (const c of unusedExportCandidates) {
          if (!byFile.has(c.file)) byFile.set(c.file, []);
          byFile.get(c.file).push(c);
        }
        unusedExportCandidates = confirmCandidatesWithTypescript(byFile, ts);
        engine = 'built-in+typescript-ast';
      } catch { /* stay on regex-only results */ }
    }

    for (const cand of unusedExportCandidates) {
      const rel = path.relative(root, cand.file);
      const node = graph.get(cand.file);
      const lineIdx = node.content.split('\n').findIndex((l) => new RegExp(`\\b${cand.name}\\b`).test(l) && /export/.test(l));
      const line = lineIdx >= 0 ? lineIdx + 1 : 1;
      findings.push({
        file: rel,
        line,
        kind: 'unused-export',
        tool: 'ignite-built-in',
        severity: 'warning',
        message: `Export "${cand.name}" in ${rel} is never imported by name anywhere else in the project — a candidate for removal.`,
        code: buildSnippet(node.content, line),
      });
    }

    // --- Unused dependencies --------------------------------------------
    if (pkg && (pkg.dependencies || pkg.devDependencies)) {
      const allDeps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
      const wholeSource = [...graph.values()].map((n) => n.content).join('\n');
      for (const dep of Object.keys(allDeps)) {
        // A dep is "used" if it's ever the target of a bare import/require
        // (exact name, or a subpath of it e.g. 'lodash/get').
        const escaped = dep.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const usedRe = new RegExp(`(?:from|require\\()\\s*['"]${escaped}(?:/[^'"]*)?['"]`);
        if (usedRe.test(wholeSource)) continue;
        // Common non-import usage: CLI-only tools invoked via package.json
        // scripts/config, never require()'d from source — skip flagging
        // those to avoid noisy false positives on build tooling.
        const scripts = JSON.stringify(pkg.scripts || {});
        if (scripts.includes(dep)) continue;
        findings.push({
          file: 'package.json',
          line: 1,
          kind: 'unused-dependency',
          tool: 'ignite-built-in',
          severity: 'warning',
          message: `Dependency "${dep}" is declared in package.json but never imported/required from any scanned source file and isn't referenced by an npm script.`,
          code: null,
        });
      }
    }

    log?.(`Scanned ${files.length} JS/TS file(s); ${reached.size} reachable from ${entries.size} entry point(s).`);
    return { findings, engine, scanned: files.length, reached: reached.size, entries: entries.size };
  }

  return { checkDeadCode };
}

module.exports = { createDeadCodeCheck };
