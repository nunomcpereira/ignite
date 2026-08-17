'use strict';

/**
 * generateProvenance / digestProjectTree — minimal, unsigned build/commit
 * provenance document (OWASP A08: cosign above verifies a Dockerfile's
 * *base image* provenance, but nothing previously recorded provenance for
 * the code Ignite itself pushes). Deliberately NOT a signed SLSA
 * attestation — these tests check the shape and the "note" disclaimer are
 * both present, not that it satisfies SLSA L3.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { withServerEnv, makeTempProject } = require('./helpers');

const noopLog = () => {};

test('digestProjectTree: deterministic regardless of directory-walk order, changes when content changes', withServerEnv({}, async (mod) => {
  const dirA = await makeTempProject({ 'b.js': 'console.log(2);', 'a.js': 'console.log(1);' });
  const dirB = await makeTempProject({ 'a.js': 'console.log(1);', 'b.js': 'console.log(2);' });
  const digestA = await mod.digestProjectTree(dirA);
  const digestB = await mod.digestProjectTree(dirB);
  assert.equal(digestA.sha256, digestB.sha256);
  assert.equal(digestA.fileCount, 2);

  const dirC = await makeTempProject({ 'a.js': 'console.log(1);', 'b.js': 'console.log(999);' });
  const digestC = await mod.digestProjectTree(dirC);
  assert.notEqual(digestA.sha256, digestC.sha256);
}));

test('generateProvenance: shape matches an unsigned in-toto Statement/SLSA-provenance-v1 predicate, carries the disclaimer note', withServerEnv({}, async (mod) => {
  const dir = await makeTempProject({ 'app.js': 'module.exports = 1;\n' });
  const logs = [];
  const provenance = await mod.generateProvenance(dir, (l) => logs.push(l), { org: 'my-org', repo: 'my-repo' });

  assert.equal(provenance._type, 'https://in-toto.io/Statement/v1');
  assert.equal(provenance.predicateType, 'https://slsa.dev/provenance/v1');
  assert.equal(provenance.subject[0].name, 'my-org/my-repo');
  assert.match(provenance.subject[0].digest.sha256, /^[a-f0-9]{64}$/);
  assert.equal(provenance.predicate.buildDefinition.externalParameters.org, 'my-org');
  assert.equal(provenance.predicate.buildDefinition.externalParameters.repo, 'my-repo');
  assert.ok(provenance.predicate.runDetails.builder.id);
  assert.ok(provenance.predicate.runDetails.metadata.generatedAt);
  assert.equal(provenance.predicate.runDetails.metadata.fileCount, 1);

  // The whole point of calling this "minimal" rather than a real
  // attestation is saying so in the artifact itself, not just in docs.
  assert.match(provenance.note, /NOT a signed SLSA attestation/);

  assert.ok(logs.some((l) => l.includes('Provenance recorded')));
}));

test('generateProvenance: no git context in a fresh upload — resolvedDependencies omits the commit rather than throwing', withServerEnv({}, async (mod) => {
  const dir = await makeTempProject({ 'app.js': 'module.exports = 1;\n' });
  const provenance = await mod.generateProvenance(dir, noopLog, { org: 'o', repo: 'r' });
  assert.deepEqual(provenance.predicate.buildDefinition.resolvedDependencies, []);
}));

test('generateProvenance: picks up the real source commit when the staged tree has git context', withServerEnv({}, async (mod) => {
  const dir = await makeTempProject({ 'app.js': 'module.exports = 1;\n' });
  const { execFile } = require('node:child_process');
  const run = (args) => new Promise((resolve, reject) => execFile('git', args, { cwd: dir }, (err) => (err ? reject(err) : resolve())));
  await run(['init', '-q']);
  await run(['-c', 'user.email=t@t.com', '-c', 'user.name=t', 'add', '-A']);
  await run(['-c', 'user.email=t@t.com', '-c', 'user.name=t', 'commit', '-q', '-m', 'init']);

  const provenance = await mod.generateProvenance(dir, noopLog, { org: 'o', repo: 'r' });
  assert.equal(provenance.predicate.buildDefinition.resolvedDependencies.length, 1);
  assert.match(provenance.predicate.buildDefinition.resolvedDependencies[0].uri, /^git\+commit:[0-9a-f]{40}$/);
}));
