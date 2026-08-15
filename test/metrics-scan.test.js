'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');

const { withServerEnv, makeTempProject, makeFakeJscpd, makeFakeGocloc } = require('./helpers');
const { collectPhase4Issues } = require('../override-engine');

const noopLog = () => {};

function hasRealJscpd() {
  return new Promise((resolve) => {
    execFile('jscpd', ['--version'], (err) => resolve(!err));
  });
}

function hasRealGocloc() {
  return new Promise((resolve) => {
    execFile('gocloc', ['--version'], (err) => resolve(!err));
  });
}

const DUP_BLOCK = [
  'function calculateTotal(items) {',
  '  let total = 0;',
  '  for (let i = 0; i < items.length; i++) {',
  '    total += items[i].price * items[i].quantity;',
  '    if (items[i].discount) {',
  '      total -= items[i].discount;',
  '    }',
  '  }',
  '  return total;',
  '}',
  '',
].join('\n');

test('checkCodeDuplication: jscpd is disabled by default', withServerEnv({}, async (mod) => {
  const cfg = mod.loadConfig();
  assert.equal(cfg.metrics.jscpd.enabled, false);
  assert.equal(cfg.metrics.jscpd.binary, 'jscpd');
}));

// Regression: real duplication-scan runs consistently surfaced two classes
// of noise instead of maintenance risk — generated/design-export mockups
// (docs/**, e.g. Stitch-exported static HTML) and test-fixture duplication
// across suites (standard practice, not logic that could drift). Both are
// excluded from jscpd's scan by default now.
test('checkCodeDuplication: default ignorePatterns exclude docs/** and test files', withServerEnv({}, async (mod) => {
  const cfg = mod.loadConfig();
  assert.deepEqual(cfg.metrics.jscpd.ignorePatterns, ['docs/**', '**/*.test.*', '**/*.spec.*', '**/__tests__/**']);
}));

test('checkCodeDuplication: JSCPD_IGNORE overrides the default ignore patterns', withServerEnv(
  { JSCPD_IGNORE: 'vendor/**, generated/**' },
  async (mod) => {
    const cfg = mod.loadConfig();
    assert.deepEqual(cfg.metrics.jscpd.ignorePatterns, ['vendor/**', 'generated/**']);
  }
));

test('checkCodeDuplication: JSCPD_* env vars are wired into CONFIG.metrics.jscpd', withServerEnv(
  { JSCPD_ENABLED: 'false', JSCPD_BINARY: '/opt/bin/jscpd' },
  async (mod) => {
    const cfg = mod.loadConfig();
    assert.equal(cfg.metrics.jscpd.enabled, false);
    assert.equal(cfg.metrics.jscpd.binary, '/opt/bin/jscpd');
  }
));

test('checkCodeDuplication: disabled — no findings, engine "disabled"', withServerEnv(
  { JSCPD_ENABLED: 'false' },
  async (mod) => {
    const dir = await makeTempProject({ 'a.js': 'console.log(1);\n' });
    const { findings, engine } = await mod.checkCodeDuplication(dir, noopLog);
    assert.equal(engine, 'disabled');
    assert.deepEqual(findings, []);
  }
));

test('checkCodeDuplication: enabled but binary missing — soft-skips, no throw', async () => {
  await withServerEnv({ JSCPD_ENABLED: 'true', JSCPD_BINARY: '/nonexistent/jscpd-xyz' }, async (mod) => {
    const dir = await makeTempProject({ 'a.js': 'console.log(1);\n' });
    const logs = [];
    const { findings, engine } = await mod.checkCodeDuplication(dir, (m) => logs.push(m));
    assert.equal(engine, 'disabled');
    assert.deepEqual(findings, []);
    assert.ok(logs.some((l) => l.includes('jscpd')), 'failure is logged, not thrown');
  })();
});

test('checkCodeDuplication: parses fake jscpd JSON report into a warning finding', async () => {
  const jscpdBinary = await makeFakeJscpd({
    duplicates: [{
      format: 'javascript',
      lines: 10,
      firstFile: { name: 'a.js', startLoc: { line: 1 } },
      secondFile: { name: 'b.js', startLoc: { line: 1 } },
    }],
  });
  await withServerEnv({ JSCPD_ENABLED: 'true', JSCPD_BINARY: jscpdBinary }, async (mod) => {
    const dir = await makeTempProject({ 'a.js': DUP_BLOCK, 'b.js': DUP_BLOCK });
    const { findings, engine } = await mod.checkCodeDuplication(dir, noopLog);
    assert.equal(engine, 'jscpd');
    assert.equal(findings.length, 1);
    assert.equal(findings[0].file, 'a.js');
    assert.equal(findings[0].severity, 'warning');
    assert.match(findings[0].message, /b\.js:1/);
  })();
});

test('checkCodeDuplication: message and duplicateRef reference the full range of the other occurrence, not just its start line', async () => {
  const jscpdBinary = await makeFakeJscpd({
    duplicates: [{
      format: 'typescript',
      lines: 16,
      firstFile: { name: 'a.js', startLoc: { line: 1 }, endLoc: { line: 9 } },
      secondFile: { name: 'sub/b.js', startLoc: { line: 79 }, endLoc: { line: 94 } },
    }],
  });
  await withServerEnv({ JSCPD_ENABLED: 'true', JSCPD_BINARY: jscpdBinary }, async (mod) => {
    const dir = await makeTempProject({ 'a.js': DUP_BLOCK, 'sub/b.js': DUP_BLOCK.repeat(10) });
    const { findings } = await mod.checkCodeDuplication(dir, noopLog);
    assert.equal(findings.length, 1);
    assert.match(findings[0].message, /also found in sub\/b\.js:79-94\./);
    assert.deepEqual(findings[0].duplicateRef, { file: 'sub/b.js', line: 79, endLine: 94 });
  })();
});

test('collectPhase4Issues: threads a duplication finding\'s duplicateRef through to the issue Studio consumes', async () => {
  const jscpdBinary = await makeFakeJscpd({
    duplicates: [{
      format: 'typescript',
      lines: 16,
      firstFile: { name: 'a.js', startLoc: { line: 1 }, endLoc: { line: 9 } },
      secondFile: { name: 'sub/b.js', startLoc: { line: 79 }, endLoc: { line: 94 } },
    }],
  });
  await withServerEnv({ JSCPD_ENABLED: 'true', JSCPD_BINARY: jscpdBinary }, async (mod) => {
    const dir = await makeTempProject({ 'a.js': DUP_BLOCK, 'sub/b.js': DUP_BLOCK.repeat(10) });
    const duplication = await mod.checkCodeDuplication(dir, noopLog);
    const empty = { findings: [] };
    const issues = collectPhase4Issues({ secrets: empty, governance: empty, llm: empty, duplication });
    assert.equal(issues.length, 1);
    assert.deepEqual(issues[0].duplicateRef, { file: 'sub/b.js', line: 79, endLine: 94 });
  })();
});

test('checkCodeDuplication: snippet highlights the whole duplicated span, not just its first line', async () => {
  const jscpdBinary = await makeFakeJscpd({
    duplicates: [{
      format: 'javascript',
      lines: 9,
      firstFile: { name: 'a.js', startLoc: { line: 1 }, endLoc: { line: 9 } },
      secondFile: { name: 'b.js', startLoc: { line: 1 } },
    }],
  });
  await withServerEnv({ JSCPD_ENABLED: 'true', JSCPD_BINARY: jscpdBinary }, async (mod) => {
    const dir = await makeTempProject({ 'a.js': DUP_BLOCK, 'b.js': DUP_BLOCK });
    const { findings } = await mod.checkCodeDuplication(dir, noopLog);
    assert.equal(findings.length, 1);
    const { code } = findings[0];
    assert.equal(code.highlightLine, 1);
    assert.equal(code.highlightEndLine, 9);
    const lineNumbers = code.lines.map((l) => l.number);
    for (let n = 1; n <= 9; n++) assert.ok(lineNumbers.includes(n), `expected line ${n} in snippet, got ${lineNumbers}`);
  })();
});

test('checkCodeDuplication: invokes jscpd with --ignore set to the default docs/test-file exclusions', async () => {
  const jscpdBinary = await makeFakeJscpd({ duplicates: [] });
  const argsFile = require('node:path').join(require('node:path').dirname(jscpdBinary), 'jscpd-invocation-args.json');
  await withServerEnv({ JSCPD_ENABLED: 'true', JSCPD_BINARY: jscpdBinary }, async (mod) => {
    const dir = await makeTempProject({ 'a.js': 'console.log(1);\n' });
    await mod.checkCodeDuplication(dir, noopLog);
    const args = JSON.parse(await require('node:fs/promises').readFile(argsFile, 'utf8'));
    const idx = args.indexOf('--ignore');
    assert.notEqual(idx, -1, `expected --ignore in jscpd invocation, got: ${args.join(' ')}`);
    assert.equal(args[idx + 1], 'docs/**,**/*.test.*,**/*.spec.*,**/__tests__/**');
  })();
});

test('checkCodeDuplication: real jscpd binary end-to-end (skipped if jscpd is not installed)', async (t) => {
  if (!(await hasRealJscpd())) {
    t.skip('jscpd not installed on PATH — install with `npm install -g jscpd` to run this test');
    return;
  }
  await withServerEnv({ JSCPD_ENABLED: 'true', JSCPD_BINARY: 'jscpd' }, async (mod) => {
    const dir = await makeTempProject({
      'a.js': DUP_BLOCK.replace('calculateTotal', 'calculateTotal'),
      'b.js': DUP_BLOCK.replace('calculateTotal', 'computeSum'),
    });
    const { findings, engine } = await mod.checkCodeDuplication(dir, noopLog);
    assert.equal(engine, 'jscpd');
    assert.ok(findings.length >= 1, 'real jscpd should flag the duplicated block shared by a.js/b.js');
    assert.ok(findings.every((f) => f.tool === 'jscpd'));
  })();
});

test('generateLocMetrics: gocloc is enabled by default', withServerEnv({}, async (mod) => {
  const cfg = mod.loadConfig();
  assert.equal(cfg.metrics.gocloc.enabled, true);
  assert.equal(cfg.metrics.gocloc.binary, 'gocloc');
}));

test('generateLocMetrics: GOCLOC_* env vars are wired into CONFIG.metrics.gocloc', withServerEnv(
  { GOCLOC_ENABLED: 'false', GOCLOC_BINARY: '/opt/bin/gocloc' },
  async (mod) => {
    const cfg = mod.loadConfig();
    assert.equal(cfg.metrics.gocloc.enabled, false);
    assert.equal(cfg.metrics.gocloc.binary, '/opt/bin/gocloc');
  }
));

test('generateLocMetrics: explicitly disabled — engine "disabled", metrics null', withServerEnv(
  { GOCLOC_ENABLED: 'false' },
  async (mod) => {
    const dir = await makeTempProject({ 'a.js': 'console.log(1);\n' });
    const { metrics, engine } = await mod.generateLocMetrics(dir, noopLog);
    assert.equal(engine, 'disabled');
    assert.equal(metrics, null);
  }
));

test('generateLocMetrics: enabled but binary missing — soft-skips, no throw', async () => {
  await withServerEnv({ GOCLOC_ENABLED: 'true', GOCLOC_BINARY: '/nonexistent/gocloc-xyz' }, async (mod) => {
    const dir = await makeTempProject({ 'a.js': 'console.log(1);\n' });
    const logs = [];
    const { metrics, engine } = await mod.generateLocMetrics(dir, (m) => logs.push(m));
    assert.equal(engine, 'disabled');
    assert.equal(metrics, null);
    assert.ok(logs.some((l) => l.includes('gocloc')), 'failure is logged, not thrown');
  })();
});

test('generateLocMetrics: parses fake gocloc --by-file JSON output, aggregates into a per-language summary', async () => {
  const goclocBinary = await makeFakeGocloc({
    files: [
      { name: 'a.js', language: 'JavaScript', code: 5, comment: 0, blank: 0 },
      { name: 'sub/b.js', language: 'JavaScript', code: 3, comment: 1, blank: 0 },
      { name: 'c.py', language: 'Python', code: 2, comment: 0, blank: 0 },
    ],
    total: { files: 3, code: 10, comment: 1, blank: 0 },
  });
  await withServerEnv({ GOCLOC_ENABLED: 'true', GOCLOC_BINARY: goclocBinary }, async (mod) => {
    // relativeToRoot canonicalizes (realpath) both the project root and
    // each reported file before diffing — matching files must actually
    // exist on disk for that to resolve cleanly, same as it would for a
    // real gocloc run.
    const dir = await makeTempProject({ 'a.js': 'console.log(1);\n', 'sub/b.js': 'console.log(2);\n', 'c.py': 'print(1)\n' });
    const { metrics, engine } = await mod.generateLocMetrics(dir, noopLog);
    assert.equal(engine, 'gocloc');
    assert.equal(metrics.total.code, 10);
    const js = metrics.languages.find((l) => l.name === 'JavaScript');
    assert.equal(js.files, 2);
    assert.equal(js.code, 8, 'JavaScript code lines should be aggregated across both JS files');
    assert.equal(metrics.languages.find((l) => l.name === 'Python').code, 2);
    // Per-file list drives Studio's "click a language, filter the tree" —
    // paths must be relative to root, not gocloc's raw (possibly absolute)
    // --by-file name.
    assert.equal(metrics.files.length, 3);
    assert.ok(metrics.files.some((f) => f.file === 'sub/b.js' && f.language === 'JavaScript'));
  })();
});

test('generateLocMetrics: real gocloc binary end-to-end (skipped if gocloc is not installed)', async (t) => {
  if (!(await hasRealGocloc())) {
    t.skip('gocloc not installed on PATH — install with `brew install gocloc` to run this test');
    return;
  }
  await withServerEnv({ GOCLOC_ENABLED: 'true', GOCLOC_BINARY: 'gocloc' }, async (mod) => {
    const dir = await makeTempProject({ 'a.js': 'console.log(1);\nconsole.log(2);\n' });
    const { metrics, engine } = await mod.generateLocMetrics(dir, noopLog);
    assert.equal(engine, 'gocloc');
    assert.ok(metrics.total.code >= 2, 'real gocloc should count at least the 2 console.log lines');
    assert.ok(metrics.languages.some((l) => l.name === 'JavaScript'));
    assert.ok(metrics.files.some((f) => f.file === 'a.js' && f.language === 'JavaScript'), 'per-file list should include the real relative path');
  })();
});
