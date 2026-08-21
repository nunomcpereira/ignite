'use strict';

/**
 * The org governance workflow's Node lane generates a throwaway ESM
 * eslint.config.js via `echo '...' > eslint.config.js` (import/export
 * syntax) so it can run eslint-plugin-security with zero repo config.
 * normalizeWorkflowText rewrites that to CommonJS syntax for local `act`
 * compatibility — but must land it in eslint.config.cjs, not
 * eslint.config.js: Node picks CommonJS vs. ESM for a bare .js file from
 * the nearest package.json's "type" field, so a CommonJS rewrite left in
 * eslint.config.js still gets parsed as ESM (and fails with "require is
 * not defined in ES module scope") on any target repo declaring
 * "type": "module" — observed for real onboarding SolventAI. .cjs is
 * unconditionally CommonJS regardless of "type", and ESLint's flat-config
 * loader looks for eslint.config.cjs explicitly.
 */

const test = require('node:test');
const assert = require('node:assert');

const { withServerEnv } = require('./helpers');

test('normalizeWorkflowText: rewrites the generated eslint.config.js to CommonJS *and* eslint.config.cjs', async () => {
  await withServerEnv({}, async (mod) => {
    const workflowText = [
      'run: |',
      '  npm install --save-dev eslint eslint-plugin-security',
      '  echo \'import security from "eslint-plugin-security"; export default [ security.configs.recommended ];\' > eslint.config.js',
      '  npx eslint . --max-warnings 0',
    ].join('\n');

    const normalized = mod.normalizeWorkflowText(workflowText);

    assert.doesNotMatch(normalized, /export default/, 'ESM syntax should be rewritten to CommonJS');
    assert.match(normalized, /require\("eslint-plugin-security"\)/);
    assert.match(normalized, /> eslint\.config\.cjs/, 'must land in .cjs so Node treats it as CommonJS regardless of the target repo\'s package.json "type"');
    assert.doesNotMatch(normalized, />\s*eslint\.config\.js\b/, 'must not still write the CommonJS content into a bare .js file');
  })();
});

test('normalizeWorkflowText: relaxes --max-warnings 0 to avoid failing on pre-existing lint warnings', async () => {
  await withServerEnv({}, async (mod) => {
    const normalized = mod.normalizeWorkflowText('npx eslint . --max-warnings 0');
    assert.match(normalized, /--max-warnings 1000/);
  })();
});

test('normalizeWorkflowText: injects a docs-site/ ignore so a JSX subproject does not hard-fail eslint-plugin-security\'s parser', async () => {
  await withServerEnv({}, async (mod) => {
    const workflowText =
      'echo \'import security from "eslint-plugin-security"; export default [ security.configs.recommended ];\' > eslint.config.js';

    const normalized = mod.normalizeWorkflowText(workflowText);

    assert.match(normalized, /\{\s*ignores:\s*\["docs-site\/\*\*"\]\s*\}/, 'must add a global-ignore entry for docs-site/');
    // The ignores entry must come before security.configs.recommended in the array —
    // ESLint's flat config only treats a lone-`ignores` object as global if present.
    const ignoresIdx = normalized.indexOf('ignores');
    const recommendedIdx = normalized.indexOf('security.configs.recommended');
    assert.ok(ignoresIdx > -1 && recommendedIdx > -1 && ignoresIdx < recommendedIdx);
  })();
});
