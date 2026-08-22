'use strict';

/**
 * Built-in CSS/Tailwind dead-class scan — closes the "no CSS/Tailwind
 * dead-code or style-drift tracking" gap against fallow.tools (see project
 * memory). No external tool: extracts every class selector declared in
 * project .css/.scss/.less files and every Tailwind-style utility class
 * (arbitrary, since Tailwind classes are never "declared" locally) used in
 * JS/TS/HTML `class`/`className` attributes, then flags declared classes
 * that are never referenced anywhere in the scanned source.
 *
 * Deliberately one-directional: only *declared-but-unused* CSS classes are
 * flagged (a css-modules `.button {}` nobody references). It does not
 * (and cannot, without a Tailwind config + full utility-class table) flag
 * "unused Tailwind utilities" the way a purge step would — Tailwind
 * classes only exist if referenced in the first place, so there's nothing
 * to call dead. Always advisory: a class matched by a dynamic
 * `className={\`btn-${variant}\`}` template is a false positive this
 * static, non-evaluating scan can't rule out.
 */

const fsp = require('fs/promises');
const path = require('path');

const CSS_EXT_RE = /\.(css|scss|less)$/i;
const MARKUP_EXT_RE = /\.(js|jsx|ts|tsx|mjs|cjs|html|vue|svelte)$/i;
const CLASS_SELECTOR_RE = /\.(-?[A-Za-z_][A-Za-z0-9_-]*)(?=[\s,.:#[{>+~)])/g;
const CLASS_ATTR_RE = /\b(?:class|className)\s*=\s*(?:"([^"]*)"|'([^']*)'|\{`([^`]*)`\})/g;

function extractDeclaredClasses(cssContent) {
  const names = new Set();
  let m;
  CLASS_SELECTOR_RE.lastIndex = 0;
  while ((m = CLASS_SELECTOR_RE.exec(cssContent))) names.add(m[1]);
  return names;
}

function extractUsedClasses(markupContent) {
  const names = new Set();
  let m;
  CLASS_ATTR_RE.lastIndex = 0;
  while ((m = CLASS_ATTR_RE.exec(markupContent))) {
    const raw = m[1] ?? m[2] ?? m[3] ?? '';
    for (const cls of raw.split(/\s+/)) if (cls) names.add(cls);
  }
  return names;
}

function createCssDeadCodeCheck({ fsUtils, config }) {
  const { walkFiles, looksBinary, buildSnippet } = fsUtils;
  const ENABLED = config.enabled !== false;

  async function checkCssDeadCode(root, log) {
    if (!ENABLED) {
      log?.('CSS dead-class scan is disabled (cssDeadCode.enabled=false).');
      return { findings: [], engine: 'disabled' };
    }

    const cssFiles = [];
    const usedClasses = new Set();
    let cssFileCount = 0;
    let markupFileCount = 0;

    for await (const file of walkFiles(root)) {
      const isCss = CSS_EXT_RE.test(file);
      const isMarkup = MARKUP_EXT_RE.test(file);
      if (!isCss && !isMarkup) continue;
      const buffer = await fsp.readFile(file).catch(() => null);
      if (!buffer || looksBinary(buffer)) continue;
      const content = buffer.toString('utf8');
      if (isCss) { cssFiles.push({ file, content }); cssFileCount++; }
      if (isMarkup) { for (const c of extractUsedClasses(content)) usedClasses.add(c); markupFileCount++; }
    }

    if (cssFileCount === 0) {
      return { findings: [], engine: 'built-in', scanned: { cssFiles: 0, markupFiles: markupFileCount } };
    }

    const findings = [];
    for (const { file, content } of cssFiles) {
      const declared = extractDeclaredClasses(content);
      const rel = path.relative(root, file);
      for (const cls of declared) {
        if (usedClasses.has(cls)) continue;
        // CSS Modules composition and pseudo/utility naming (is-, has-,
        // js- prefixes commonly toggled purely by JS via classList, never
        // appearing as a literal class="..." string) are common
        // legitimate-but-invisible-to-this-scan patterns — skip those
        // prefixes to keep the signal actionable rather than noisy.
        if (/^(is-|has-|js-)/.test(cls)) continue;
        const lineIdx = content.split('\n').findIndex((l) => l.includes(`.${cls}`));
        const line = lineIdx >= 0 ? lineIdx + 1 : 1;
        findings.push({
          file: rel,
          line,
          kind: 'unused-css-class',
          tool: 'ignite-built-in',
          severity: 'warning',
          message: `CSS class ".${cls}" is declared in ${rel} but never referenced in a class/className attribute across ${markupFileCount} scanned markup file(s).`,
          code: buildSnippet(content, line),
        });
      }
    }

    log?.(`Scanned ${cssFileCount} CSS file(s) against ${markupFileCount} markup file(s); ${findings.length} unused class(es).`);
    return { findings, engine: 'built-in', scanned: { cssFiles: cssFileCount, markupFiles: markupFileCount } };
  }

  return { checkCssDeadCode };
}

module.exports = { createCssDeadCodeCheck, extractDeclaredClasses, extractUsedClasses };
