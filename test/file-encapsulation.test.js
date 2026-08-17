'use strict';

/**
 * checkFileEncapsulation — built-in (no external tool) "low encapsulation"
 * check: flags any single source file over metrics.fileSize.maxLines as an
 * advisory finding. Added after investigating Ignite's own pipeline
 * performance — a monolithic file is both a maintainability smell and a
 * concrete cost multiplier for per-file-cached SAST tools (Bearer), whose
 * cache has nothing to exploit when one huge file dominates the codebase
 * and changes on nearly every commit.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { withServerEnv, makeTempProject } = require('./helpers');

const noopLog = () => {};

test('checkFileEncapsulation: enabled by default, maxLines defaults to 1000', withServerEnv({}, async (mod) => {
  const cfg = mod.loadConfig();
  assert.equal(cfg.metrics.fileSize.enabled, true);
  assert.equal(cfg.metrics.fileSize.maxLines, 1000);
}));

test('checkFileEncapsulation: FILE_SIZE_* env vars are wired into CONFIG.metrics.fileSize', withServerEnv(
  { FILE_SIZE_ENABLED: 'false', FILE_SIZE_MAX_LINES: '250' },
  async (mod) => {
    const cfg = mod.loadConfig();
    assert.equal(cfg.metrics.fileSize.enabled, false);
    assert.equal(cfg.metrics.fileSize.maxLines, 250);
  }
));

test('checkFileEncapsulation: disabled — no findings, engine "disabled"', withServerEnv(
  { FILE_SIZE_ENABLED: 'false' },
  async (mod) => {
    const dir = await makeTempProject({ 'big.js': 'const x = 1;\n'.repeat(2000) });
    const { findings, engine } = await mod.checkFileEncapsulation(dir, noopLog);
    assert.equal(engine, 'disabled');
    assert.deepEqual(findings, []);
  }
));

test('checkFileEncapsulation: a file under the threshold produces no finding', withServerEnv(
  { FILE_SIZE_MAX_LINES: '10' },
  async (mod) => {
    const dir = await makeTempProject({ 'small.js': 'const x = 1;\n'.repeat(5) });
    const { findings, engine } = await mod.checkFileEncapsulation(dir, noopLog);
    assert.equal(engine, 'built-in');
    assert.deepEqual(findings, []);
  }
));

test('checkFileEncapsulation: a file over the threshold is flagged as an advisory (warning) finding', withServerEnv(
  { FILE_SIZE_MAX_LINES: '10' },
  async (mod) => {
    const dir = await makeTempProject({ 'huge.js': 'const x = 1;\n'.repeat(50) });
    const { findings, engine } = await mod.checkFileEncapsulation(dir, noopLog);
    assert.equal(engine, 'built-in');
    assert.equal(findings.length, 1);
    assert.equal(findings[0].file, 'huge.js');
    assert.equal(findings[0].kind, 'file-too-large');
    assert.equal(findings[0].tool, 'ignite-built-in');
    assert.match(findings[0].message, /over the 10-line guideline/);
  }
));

test('checkFileEncapsulation: only source-code extensions are checked — a huge JSON/lockfile-style file is ignored', withServerEnv(
  { FILE_SIZE_MAX_LINES: '10' },
  async (mod) => {
    const dir = await makeTempProject({
      'package-lock.json': '{\n'.repeat(50) + '}\n'.repeat(50),
      'huge.js': 'const x = 1;\n'.repeat(50),
    });
    const { findings } = await mod.checkFileEncapsulation(dir, noopLog);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].file, 'huge.js');
  }
));

test('checkFileEncapsulation: collectPhase4Issues tags findings as advisory "code-structure", never blocking', withServerEnv({}, async (mod) => {
  const { collectPhase4Issues } = require('../override-engine');
  const issues = collectPhase4Issues({
    secrets: { findings: [] },
    governance: { findings: [] },
    llm: { available: false, findings: [] },
    fileEncapsulation: {
      findings: [{ file: 'huge.js', line: 1, kind: 'file-too-large', tool: 'ignite-built-in', severity: 'warning', message: 'huge.js is 1500 lines' }],
      engine: 'built-in',
    },
  });
  assert.equal(issues.length, 1);
  assert.equal(issues[0].category, 'code-structure');
  assert.equal(issues[0].severity, 'warning');
  assert.equal(issues[0].cwe, null, 'file size is a maintainability smell, not a security/CWE-mappable finding');
}));
