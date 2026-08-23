'use strict';

/**
 * Auto-fix for dead-code (checks/dead-code.js) and AI-governance
 * (checks/ai-governance.js) findings — closes the "detect-only, no
 * auto-fix" gap against fallow.tools' `fallow fix` (see project memory).
 * Actions safe enough to apply mechanically:
 *
 *  - `unused-file`: delete the file outright.
 *  - `unused-dependency`: remove the key from package.json
 *    dependencies/devDependencies.
 *  - ungoverned AI invocation (`.invoke(`/`.stream(`/... with no
 *    `recursion_limit`): insert an explicit recursion-limit argument, but
 *    only when the call is a single-line, single-argument call with no
 *    existing second (config) argument already there to respect —
 *    anything else becomes `manual` (see applyGovernanceFix below).
 *
 * `unused-export` is deliberately NOT deleted (that would mean removing a
 * function/class/const body via regex, with no real parser backing the
 * edit — too easy to corrupt a file that has a subtly different shape than
 * expected). Where the export is a named-export-list entry
 * (`export { foo, bar }`) it's safe to narrow the list itself (the
 * declaration stays, just stops being exported) — anything else becomes a
 * `manual` action the caller can show a human instead of applying blindly.
 *
 * Always dry-run by default; `apply: true` is required to actually touch
 * disk, mirroring `fallow fix --dry-run` being the default posture.
 */

const fsp = require('fs/promises');
const path = require('path');

const EXPORT_LIST_RE = /\bexport\s*\{([^}]*)\}(?!\s*from)/;
const AI_INVOKE_REGEX = /\b([A-Za-z_$][\w.]*)\.(invoke|stream|ainvoke|astream)\(/;
// LangGraph's own documented default recursion_limit — making it explicit
// changes nothing about runtime behavior, it only turns an implicit
// framework default into something a human/reviewer can actually see and
// tune, which is what the governance guideline is really asking for.
const DEFAULT_RECURSION_LIMIT = 25;

function computeAutoFixPlan(findings) {
  const actions = [];
  for (const f of findings) {
    if (f.kind === 'unused-file') {
      actions.push({ type: 'delete-file', file: f.file, detail: `Delete ${f.file} — unreferenced from any detected entry point.` });
    } else if (f.kind === 'unused-dependency') {
      const dep = f.message.match(/"([^"]+)"/)?.[1];
      if (dep) actions.push({ type: 'remove-dependency', file: 'package.json', dependency: dep, detail: `Remove "${dep}" from package.json dependencies/devDependencies.` });
    } else if (f.kind === 'unused-export') {
      const name = f.message.match(/Export "([^"]+)"/)?.[1];
      actions.push({ type: 'narrow-export-list-or-manual', file: f.file, line: f.line, name, detail: `Export "${name}" in ${f.file}:${f.line} is unused — narrowed out of an \`export { }\` list if present, otherwise flagged for manual review (deleting the declaration itself needs a human).` });
    } else if (f.kind === 'ungoverned-ai-invocation') {
      actions.push({ type: 'add-recursion-limit-or-manual', file: f.file, line: f.line, detail: `${f.file}:${f.line} — \`.invoke()\`/\`.stream()\` call with no recursion_limit; inserted an explicit limit if the call is a simple single-line/single-argument call, otherwise flagged for manual review (an existing second argument needs a human to merge into, not overwrite).` });
    }
  }
  return { actions };
}

// Finds the AI_INVOKE_REGEX call's own argument list on `line`, tracking
// paren/bracket/brace depth and string state so a comma inside a nested
// object/array/string isn't mistaken for a second top-level argument.
// Returns null (never auto-fixable) when the call's closing paren isn't on
// this same line (a real parser would be needed past that point) or a
// top-level comma is found (a second argument already exists — safer to
// leave to a human than guess how to merge into it).
function findSingleArgCallClose(line, openParenIdx) {
  let depth = 1;
  let quote = null;
  for (let i = openParenIdx + 1; i < line.length; i++) {
    const ch = line[i];
    if (quote) {
      if (ch === '\\') { i++; continue; }
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { quote = ch; continue; }
    if (ch === '(' || ch === '[' || ch === '{') { depth++; continue; }
    if (ch === ')' || ch === ']' || ch === '}') {
      depth--;
      if (depth === 0) return i; // this is the invoke(...) call's own close-paren
      continue;
    }
    if (ch === ',' && depth === 1) return null; // second top-level argument already present
  }
  return null; // call doesn't close on this line
}

async function applyGovernanceFix(root, action) {
  const abs = path.resolve(root, action.file);
  const content = await fsp.readFile(abs, 'utf8');
  const usesCrlf = content.includes('\r\n');
  const lines = content.split(/\r?\n/);
  const lineIdx = action.line - 1;
  const line = lines[lineIdx];
  if (line === undefined) return { ...action, applied: false, manual: true };

  const match = line.match(AI_INVOKE_REGEX);
  if (!match) return { ...action, applied: false, manual: true };

  const openParenIdx = match.index + match[0].length - 1;
  const closeParenIdx = findSingleArgCallClose(line, openParenIdx);
  if (closeParenIdx === null) return { ...action, applied: false, manual: true };

  const isPython = path.extname(action.file).toLowerCase() === '.py';
  const insertion = isPython
    ? `, config={"recursion_limit": ${DEFAULT_RECURSION_LIMIT}}`
    : `, { recursionLimit: ${DEFAULT_RECURSION_LIMIT} }`;
  lines[lineIdx] = line.slice(0, closeParenIdx) + insertion + line.slice(closeParenIdx);
  await fsp.writeFile(abs, lines.join(usesCrlf ? '\r\n' : '\n'), 'utf8');
  return { ...action, applied: true };
}

async function applyDeleteFile(root, action) {
  const abs = path.resolve(root, action.file);
  await fsp.unlink(abs);
  return { ...action, applied: true };
}

async function applyRemoveDependency(root, action) {
  const pkgPath = path.join(root, 'package.json');
  const pkg = JSON.parse(await fsp.readFile(pkgPath, 'utf8'));
  let removed = false;
  for (const field of ['dependencies', 'devDependencies']) {
    if (pkg[field] && Object.prototype.hasOwnProperty.call(pkg[field], action.dependency)) {
      delete pkg[field][action.dependency];
      removed = true;
    }
  }
  if (removed) await fsp.writeFile(pkgPath, JSON.stringify(pkg, null, 2) + '\n', 'utf8');
  return { ...action, applied: removed };
}

async function applyNarrowExport(root, action) {
  const abs = path.resolve(root, action.file);
  const content = await fsp.readFile(abs, 'utf8');
  const m = content.match(EXPORT_LIST_RE);
  if (!m || !action.name) {
    return { ...action, applied: false, manual: true };
  }
  const names = m[1].split(',').map((s) => s.trim()).filter(Boolean);
  const kept = names.filter((n) => n.replace(/\s+as\s+\w+$/, '').trim() !== action.name);
  if (kept.length === names.length) {
    return { ...action, applied: false, manual: true }; // name wasn't in an export list — needs a human
  }
  const replacement = kept.length > 0 ? `export { ${kept.join(', ')} }` : '';
  const newContent = content.replace(EXPORT_LIST_RE, replacement);
  await fsp.writeFile(abs, newContent, 'utf8');
  return { ...action, applied: true };
}

/**
 * @param {{actions: Array}} plan - from computeAutoFixPlan
 * @param {string} root - absolute project root
 * @param {{ dryRun?: boolean }} opts
 */
async function applyAutoFixPlan(plan, root, { dryRun = true } = {}) {
  if (dryRun) return { dryRun: true, results: plan.actions.map((a) => ({ ...a, applied: false })) };

  const results = [];
  for (const action of plan.actions) {
    try {
      if (action.type === 'delete-file') results.push(await applyDeleteFile(root, action));
      else if (action.type === 'remove-dependency') results.push(await applyRemoveDependency(root, action));
      else if (action.type === 'narrow-export-list-or-manual') results.push(await applyNarrowExport(root, action));
      else if (action.type === 'add-recursion-limit-or-manual') results.push(await applyGovernanceFix(root, action));
      else results.push({ ...action, applied: false, manual: true });
    } catch (e) {
      results.push({ ...action, applied: false, error: e.message });
    }
  }
  return { dryRun: false, results };
}

module.exports = { computeAutoFixPlan, applyAutoFixPlan };
