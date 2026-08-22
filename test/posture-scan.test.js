'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');

const { withServerEnv, makeTempProject, makeFakeSemgrep } = require('./helpers');

const noopLog = () => {};

function hasRealSemgrep() {
  return new Promise((resolve) => {
    execFile('semgrep', ['--version'], (err) => resolve(!err));
  });
}

test('checkFeaturePosture: posture scan is enabled by default', withServerEnv({}, async (mod) => {
  const cfg = mod.loadConfig();
  assert.equal(cfg.compliance.posture.enabled, true);
  assert.ok(cfg.compliance.posture.ruleset.endsWith('ignite-posture-rules.yaml'));
}));

test('checkFeaturePosture: POSTURE_* env vars are wired into CONFIG.compliance.posture', withServerEnv(
  { POSTURE_ENABLED: 'false', POSTURE_RULESET: '/etc/my-posture-rules.yaml' },
  async (mod) => {
    const cfg = mod.loadConfig();
    assert.equal(cfg.compliance.posture.enabled, false);
    assert.equal(cfg.compliance.posture.ruleset, '/etc/my-posture-rules.yaml');
  }
));

test('checkFeaturePosture: disabled — falls back to the built-in scanner (never just skips)', withServerEnv(
  { POSTURE_ENABLED: 'false' },
  async (mod) => {
    const dir = await makeTempProject({ 'app.js': 'const x = require("passport-saml");\n' });
    const { engine, posture } = await mod.checkFeaturePosture(dir, noopLog);
    assert.equal(engine, 'fallback');
    assert.equal(posture['sso-saml-oidc'].status, 'PARTIAL');
  }
));

test('checkFeaturePosture: semgrep enabled but binary missing — soft-falls back, no throw', async () => {
  await withServerEnv({ POSTURE_ENABLED: 'true', SEMGREP_BINARY: '/nonexistent/semgrep-xyz' }, async (mod) => {
    const dir = await makeTempProject({ 'app.js': 'const x = require("passport-saml");\n' });
    const logs = [];
    const { engine, posture } = await mod.checkFeaturePosture(dir, (m) => logs.push(m));
    assert.equal(engine, 'fallback');
    assert.equal(posture['sso-saml-oidc'].status, 'PARTIAL');
    assert.ok(logs.some((l) => l.includes('Ignite Built-In Posture Scanner (Fallback)')));
  })();
});

test('checkFeaturePosture: fallback scanner classifies DETECTED/PARTIAL/MISSING correctly', withServerEnv(
  { POSTURE_ENABLED: 'false' },
  async (mod) => {
    const dir = await makeTempProject({
      'app.js': [
        'const helmet = require("helmet");',
        'app.use(helmet.hsts({ maxAge: 1 }));', // strong https-tls signal
        'import casbin from "casbin";',          // weak-only rbac-abac signal
      ].join('\n'),
    });
    const { posture } = await mod.checkFeaturePosture(dir, noopLog);
    assert.equal(posture['https-tls'].status, 'DETECTED');
    assert.equal(posture['rbac-abac'].status, 'PARTIAL');
    assert.equal(posture['audit-logging'].status, 'MISSING');
    assert.deepEqual(posture['audit-logging'].matches, []);
  }
));

test('checkFeaturePosture: parses fake semgrep output via extra.metadata.category/tier, dedupes exact repeats', async () => {
  const semgrepBinary = await makeFakeSemgrep([
    {
      check_id: 'posture-https-tls-strong', path: 'app.js', start: { line: 2 },
      extra: { message: 'HSTS configured', metadata: { category: 'https-tls', tier: 'strong' } },
    },
    // exact duplicate (same category/file/line/tier) — Semgrep's generic
    // engine is observed to occasionally emit overlapping-span duplicates
    {
      check_id: 'posture-https-tls-strong', path: 'app.js', start: { line: 2 },
      extra: { message: 'HSTS configured', metadata: { category: 'https-tls', tier: 'strong' } },
    },
    {
      check_id: 'posture-rbac-abac-weak', path: 'app.js', start: { line: 3 },
      extra: { message: 'casbin referenced', metadata: { category: 'rbac-abac', tier: 'weak' } },
    },
  ]);
  await withServerEnv({ POSTURE_ENABLED: 'true', SEMGREP_BINARY: semgrepBinary }, async (mod) => {
    const dir = await makeTempProject({ 'app.js': 'x\nhelmet.hsts()\ncasbin\n' });
    const { engine, posture } = await mod.checkFeaturePosture(dir, noopLog);
    assert.equal(engine, 'semgrep');
    assert.equal(posture['https-tls'].status, 'DETECTED');
    assert.equal(posture['https-tls'].matches.length, 1, 'exact-duplicate Semgrep match should be deduped');
    assert.equal(posture['rbac-abac'].status, 'PARTIAL');
    assert.equal(posture['sso-saml-oidc'].status, 'MISSING');
  })();
});

test('checkFeaturePosture: fallback scanner detects EU AI Act signals (prohibited-practice, transparency, ai-logging)', withServerEnv(
  { POSTURE_ENABLED: 'false' },
  async (mod) => {
    const dir = await makeTempProject({
      'app.js': [
        'const rekognition = require("@aws-sdk/client-rekognition");', // weak prohibited-practice
        'rekognition.compareFaces({});', // strong prohibited-practice
        'const msg = "You are interacting with an AI system.";', // strong transparency
        'import mlflow from "mlflow";', // weak ai-logging
      ].join('\n'),
    });
    const { posture } = await mod.checkFeaturePosture(dir, noopLog);
    assert.equal(posture['ai-act-prohibited-practice'].status, 'DETECTED');
    assert.equal(posture['ai-act-transparency-disclosure'].status, 'DETECTED');
    assert.equal(posture['ai-act-ai-logging'].status, 'PARTIAL');
  }
));

test('checkFeaturePosture: real semgrep binary end-to-end against ignite-posture-rules.yaml (skipped if semgrep is not installed)', async (t) => {
  if (!(await hasRealSemgrep())) {
    t.skip('semgrep not installed on PATH — install with `brew install semgrep` to run this test');
    return;
  }
  await withServerEnv({ POSTURE_ENABLED: 'true', SEMGREP_BINARY: 'semgrep' }, async (mod) => {
    const dir = await makeTempProject({
      'app.js': [
        'const SamlStrategy = require("passport-saml").Strategy;',
        'const helmet = require("helmet");',
        'app.use(helmet.hsts({ maxAge: 31536000 }));',
        'const limiter = rateLimit({ windowMs: 60000, max: 100 });',
      ].join('\n'),
      'auth.py': 'import casbin\n',
    });
    const { engine, posture } = await mod.checkFeaturePosture(dir, noopLog);
    assert.equal(engine, 'semgrep');
    assert.equal(posture['sso-saml-oidc'].status, 'PARTIAL', 'import-only passport-saml reference');
    assert.equal(posture['rbac-abac'].status, 'PARTIAL', 'import-only casbin reference');
    assert.equal(posture['https-tls'].status, 'DETECTED', 'helmet.hsts() is a confirmed usage site');
    assert.equal(posture['rate-limiting'].status, 'DETECTED', 'rateLimit({...}) is a confirmed usage site');
    assert.equal(posture['audit-logging'].status, 'MISSING');
    assert.ok(posture['https-tls'].matches.every((m) => m.tool === 'semgrep'));
  })();
});
