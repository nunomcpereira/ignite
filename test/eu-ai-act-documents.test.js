'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { withServerEnv, makeTempProject } = require('./helpers');

const noopLog = () => {};

test('checkComplianceDocuments: enabled by default', withServerEnv({}, async (mod) => {
  const cfg = mod.loadConfig();
  assert.equal(cfg.compliance.euAiActDocuments.enabled, true);
}));

test('checkComplianceDocuments: EU_AI_ACT_DOCS_ENABLED env var wired into CONFIG.compliance.euAiActDocuments', withServerEnv(
  { EU_AI_ACT_DOCS_ENABLED: 'false' },
  async (mod) => {
    const cfg = mod.loadConfig();
    assert.equal(cfg.compliance.euAiActDocuments.enabled, false);
  }
));

test('compliance.euAiAct.reportAsFindings defaults to false (advisory only)', withServerEnv({}, async (mod) => {
  const cfg = mod.loadConfig();
  assert.equal(cfg.compliance.euAiAct.reportAsFindings, false);
}));

test('EU_AI_ACT_REPORT_AS_FINDINGS env var wired into CONFIG.compliance.euAiAct.reportAsFindings', withServerEnv(
  { EU_AI_ACT_REPORT_AS_FINDINGS: 'true' },
  async (mod) => {
    const cfg = mod.loadConfig();
    assert.equal(cfg.compliance.euAiAct.reportAsFindings, true);
  }
));

test('checkComplianceDocuments: disabled — returns MISSING for everything without scanning', withServerEnv(
  { EU_AI_ACT_DOCS_ENABLED: 'false' },
  async (mod) => {
    const dir = await makeTempProject({ 'RISK_MANAGEMENT_SYSTEM.md': '# RMS\n' });
    const { engine, documents } = await mod.checkComplianceDocuments(dir, noopLog);
    assert.equal(engine, 'disabled');
    assert.equal(documents['risk-management-system'].status, 'MISSING');
  }
));

test('checkComplianceDocuments: detects each category by filename/path match', withServerEnv({}, async (mod) => {
  const dir = await makeTempProject({
    'docs/RISK_MANAGEMENT_SYSTEM.md': '# RMS\n',
    'docs/annex-iv-technical-documentation.md': '# Annex IV\n',
    'compliance/FRIA.pdf': '',
    'MODEL_CARD.md': '# Model card / training data summary\n',
    'docs/post-market-monitoring-plan.md': '# PMMP\n',
    'src/app.js': 'console.log("hi");\n',
  });
  const { engine, documents } = await mod.checkComplianceDocuments(dir, noopLog);
  assert.equal(engine, 'built-in');
  assert.equal(documents['risk-management-system'].status, 'DETECTED');
  assert.equal(documents['technical-documentation'].status, 'DETECTED');
  assert.equal(documents['fria'].status, 'DETECTED');
  assert.equal(documents['training-data-summary'].status, 'DETECTED');
  assert.equal(documents['post-market-monitoring'].status, 'DETECTED');
}));

test('checkComplianceDocuments: none present — everything MISSING, never an issue/blocker', withServerEnv({}, async (mod) => {
  const dir = await makeTempProject({ 'src/app.js': 'console.log("hi");\n' });
  const { documents } = await mod.checkComplianceDocuments(dir, noopLog);
  for (const category of mod.DOCUMENT_CATEGORIES || Object.keys(documents)) {
    assert.equal(documents[category].status, 'MISSING');
    assert.deepEqual(documents[category].matches, []);
  }
}));
