'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const { execFile } = require('node:child_process');

const { withServerEnv, makeTempProject, makeFakeCodeQL } = require('./helpers');

const noopLog = () => {};

function hasRealCodeQL() {
  return new Promise((resolve) => {
    execFile('codeql', ['version'], (err) => resolve(!err));
  });
}

const CROSS_FILE_SARIF = {
  runs: [{
    tool: {
      driver: {
        rules: [{
          id: 'js/sql-injection',
          shortDescription: { text: 'Database query built from user-controlled sources' },
          defaultConfiguration: { level: 'error' },
          properties: { 'security-severity': '9.8', tags: ['external/cwe/cwe-089', 'security'] },
        }],
      },
    },
    results: [{
      ruleId: 'js/sql-injection',
      level: 'error',
      message: { text: 'This query depends on a user-provided value from controller.js.' },
      locations: [{ physicalLocation: { artifactLocation: { uri: 'db.js' }, region: { startLine: 12 } } }],
      codeFlows: [{
        threadFlows: [{
          locations: [
            { location: { physicalLocation: { artifactLocation: { uri: 'controller.js' } } } },
            { location: { physicalLocation: { artifactLocation: { uri: 'db.js' } } } },
          ],
        }],
      }],
    }],
  }],
};

const SINGLE_FILE_SARIF = {
  runs: [{
    tool: { driver: { rules: [{ id: 'js/useless-check', shortDescription: { text: 'Useless check' }, defaultConfiguration: { level: 'warning' }, properties: {} }] } },
    results: [{
      ruleId: 'js/useless-check',
      message: { text: 'Comparison always evaluates to the same result.' },
      locations: [{ physicalLocation: { artifactLocation: { uri: 'db.js' }, region: { startLine: 3 } } }],
    }],
  }],
};

test('checkCodeqlCrossFile: codeql is enabled by default', withServerEnv({}, async (mod) => {
  const cfg = mod.loadConfig();
  assert.equal(cfg.security.codeql.enabled, true);
  assert.equal(cfg.security.codeql.binary, 'codeql');
  assert.deepEqual(cfg.security.codeql.languages, ['javascript', 'python', 'java', 'go']);
}));

test('checkCodeqlCrossFile: CODEQL_* env vars are wired into CONFIG.security.codeql', withServerEnv(
  { CODEQL_ENABLED: 'true', CODEQL_BINARY: '/opt/bin/codeql', CODEQL_LANGUAGES: 'javascript,python' },
  async (mod) => {
    const cfg = mod.loadConfig();
    assert.equal(cfg.security.codeql.enabled, true);
    assert.equal(cfg.security.codeql.binary, '/opt/bin/codeql');
    assert.deepEqual(cfg.security.codeql.languages, ['javascript', 'python']);
  }
));

test('checkCodeqlCrossFile: explicitly disabled — no findings, engine "disabled"', withServerEnv(
  { CODEQL_ENABLED: 'false' },
  async (mod) => {
    const dir = await makeTempProject({ 'db.js': 'module.exports = {};\n' });
    const { findings, engine } = await mod.checkCodeqlCrossFile(dir, noopLog);
    assert.equal(engine, 'disabled');
    assert.deepEqual(findings, []);
  }
));

test('checkCodeqlCrossFile: enabled but binary missing — soft-skips, no findings, no throw', async () => {
  await withServerEnv({ CODEQL_ENABLED: 'true', CODEQL_BINARY: '/nonexistent/codeql-xyz' }, async (mod) => {
    const dir = await makeTempProject({ 'db.js': 'module.exports = {};\n' });
    const logs = [];
    const { findings, engine } = await mod.checkCodeqlCrossFile(dir, (m) => logs.push(m));
    assert.equal(engine, 'disabled');
    assert.deepEqual(findings, []);
    assert.ok(logs.some((l) => l.includes('codeql')), 'failure is logged, not thrown');
  })();
});

test('checkCodeqlCrossFile: no supported-language files in the project — no database build, no findings', async () => {
  const { binary } = await makeFakeCodeQL({});
  await withServerEnv({ CODEQL_ENABLED: 'true', CODEQL_BINARY: binary }, async (mod) => {
    const dir = await makeTempProject({ 'README.md': '# demo\n' });
    const { findings, engine, languages } = await mod.checkCodeqlCrossFile(dir, noopLog);
    assert.equal(engine, 'codeql');
    assert.deepEqual(findings, []);
    assert.deepEqual(languages, []);
  })();
});

test('checkCodeqlCrossFile: flags a cross-file finding (codeFlow spans >1 file) and tags crossFile:true', async () => {
  const { binary } = await makeFakeCodeQL({ javascript: CROSS_FILE_SARIF });
  await withServerEnv({ CODEQL_ENABLED: 'true', CODEQL_BINARY: binary }, async (mod) => {
    const dir = await makeTempProject({
      'controller.js': 'module.exports = (req) => req.query.id;\n',
      'db.js': 'module.exports = (id) => db.query(`SELECT * FROM t WHERE id=${id}`);\n',
    });
    const { findings, engine } = await mod.checkCodeqlCrossFile(dir, noopLog);
    assert.equal(engine, 'codeql');
    assert.equal(findings.length, 1);
    const f = findings[0];
    assert.equal(f.file, 'db.js');
    assert.equal(f.line, 12);
    assert.equal(f.tool, 'codeql');
    assert.equal(f.severity, 'error');
    assert.equal(f.crossFile, true);
    assert.equal(f.cwe, 'CWE-089');
  })();
});

test('checkCodeqlCrossFile: a single-file finding is still reported, tagged crossFile:false', async () => {
  const { binary } = await makeFakeCodeQL({ javascript: SINGLE_FILE_SARIF });
  await withServerEnv({ CODEQL_ENABLED: 'true', CODEQL_BINARY: binary }, async (mod) => {
    const dir = await makeTempProject({ 'db.js': 'if (1 === 1) { doThing(); }\n' });
    const { findings } = await mod.checkCodeqlCrossFile(dir, noopLog);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].crossFile, false);
    assert.equal(findings[0].severity, 'warning');
  })();
});

test('checkCodeqlCrossFile: unchanged file set on a second scan of the same (org, repo) reuses the cache — no second database build', async () => {
  const { binary, callLogPath } = await makeFakeCodeQL({ javascript: CROSS_FILE_SARIF });
  await withServerEnv({ CODEQL_ENABLED: 'true', CODEQL_BINARY: binary }, async (mod) => {
    const dir = await makeTempProject({
      'controller.js': 'module.exports = (req) => req.query.id;\n',
      'db.js': 'module.exports = (id) => db.query(`SELECT * FROM t WHERE id=${id}`);\n',
    });
    const ctx = { org: 'acme', repo: 'widgets' };
    const first = await mod.checkCodeqlCrossFile(dir, noopLog, ctx);
    assert.equal(first.findings.length, 1);
    const callsAfterFirst = (await fs.readFile(callLogPath, 'utf8')).split('\n').filter((l) => l === 'create').length;
    assert.equal(callsAfterFirst, 1);

    const second = await mod.checkCodeqlCrossFile(dir, noopLog, ctx);
    assert.deepEqual(second.findings, first.findings);
    const callsAfterSecond = (await fs.readFile(callLogPath, 'utf8')).split('\n').filter((l) => l === 'create').length;
    assert.equal(callsAfterSecond, 1, 'second scan of an unchanged file set should not rebuild the database');
  })();
});

test('checkCodeqlCrossFile: real codeql binary end-to-end (skipped if codeql is not installed)', async (t) => {
  if (!(await hasRealCodeQL())) {
    t.skip('codeql CLI not installed on PATH — see https://github.com/github/codeql-cli-binaries to run this test');
    return;
  }
  await withServerEnv({ CODEQL_ENABLED: 'true', CODEQL_BINARY: 'codeql', CODEQL_TIMEOUT_MS: '600000' }, async (mod) => {
    const dir = await makeTempProject({
      'index.js': 'function add(a, b) { return a + b; }\nmodule.exports = { add };\n',
    });
    const { findings, engine } = await mod.checkCodeqlCrossFile(dir, noopLog);
    assert.equal(engine, 'codeql');
    assert.ok(findings.every((f) => f.tool === 'codeql'));
  })();
});
