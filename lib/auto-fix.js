'use strict';

/**
 * Auto-fix for dead-code findings (checks/dead-code.js) — closes the
 * "detect-only, no auto-fix" gap against fallow.tools' `fallow fix` (see
 * project memory). Two actions are safe enough to apply mechanically:
 *
 *  - `unused-file`: delete the file outright.
 *  - `unused-dependency`: remove the key from package.json
 *    dependencies/devDependencies.
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
    }
  }
  return { actions };
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
      else results.push({ ...action, applied: false, manual: true });
    } catch (e) {
      results.push({ ...action, applied: false, error: e.message });
    }
  }
  return { dryRun: false, results };
}

module.exports = { computeAutoFixPlan, applyAutoFixPlan };
