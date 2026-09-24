import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import {
  isLocalHost, resolveScanMode, collectUploadFiles, uploadPathFor, checkUploadLimits,
  PipelineRunState, overridesForReview, splitNdjson,
} from './upload';

test('resolveScanMode sends a path to localhost and uploads to anything else', () => {
  assert.equal(resolveScanMode('auto', 'http://localhost:51337'), 'path');
  assert.equal(resolveScanMode('auto', 'http://127.0.0.1:51337'), 'path');
  assert.equal(resolveScanMode('auto', 'http://[::1]:51337'), 'path');
  assert.equal(resolveScanMode('auto', 'https://ignite.example.com'), 'upload');
  assert.equal(resolveScanMode(undefined, 'http://10.0.0.5:51337'), 'upload');
  assert.equal(resolveScanMode('upload', 'http://localhost:51337'), 'upload');
  assert.equal(resolveScanMode('path', 'https://ignite.example.com'), 'path');
  assert.equal(isLocalHost('not a url'), false);
});

test('collectUploadFiles skips dependency/build dirs and extension snapshots outside git', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ignite-upload-'));
  // GIT_CEILING_DIRECTORIES keeps git from finding an enclosing repo, so this exercises the walk.
  process.env.GIT_CEILING_DIRECTORIES = path.dirname(root);
  try {
    await fs.mkdir(path.join(root, 'src'), { recursive: true });
    await fs.mkdir(path.join(root, 'node_modules/x'), { recursive: true });
    await fs.mkdir(path.join(root, '.ignite/scans/t1'), { recursive: true });
    await fs.writeFile(path.join(root, 'src/a.ts'), 'export {}');
    await fs.writeFile(path.join(root, 'node_modules/x/index.js'), '');
    await fs.writeFile(path.join(root, '.ignite/scans/t1/findings.md'), '');
    await fs.writeFile(path.join(root, '.ignite/acknowledgments.md'), '');
    await fs.symlink(path.join(root, 'src/a.ts'), path.join(root, 'link.ts'));
    const rels = (await collectUploadFiles(root)).map((f) => f.rel).sort();
    assert.deepEqual(rels, ['.ignite/acknowledgments.md', 'src/a.ts']);
  } finally {
    delete process.env.GIT_CEILING_DIRECTORIES;
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('uploadPathFor prefixes the folder name so the server keeps paths relative to it', () => {
  assert.equal(uploadPathFor('/work/my app', 'src/a.ts'), 'my_app/src/a.ts');
  assert.equal(uploadPathFor('/work/svc/', 'x'), 'svc/x');
});

test('checkUploadLimits rejects empty and oversized uploads', () => {
  assert.throws(() => checkUploadLimits([]), /no files/);
  assert.throws(() => checkUploadLimits([{ rel: 'a', abs: '/a', size: 2 * 1024 * 1024 * 1024 }]), /too large/);
  assert.doesNotThrow(() => checkUploadLimits([{ rel: 'a', abs: '/a', size: 10 }]));
  const mb = 1024 * 1024;
  assert.doesNotThrow(() => checkUploadLimits([{ rel: 'a', abs: '/a', size: 1250 * mb }]), 'exactly 1250 MB is allowed');
  assert.throws(() => checkUploadLimits([{ rel: 'a', abs: '/a', size: 1250 * mb + 1 }]), /limit is 1250 MB/);
});

test('PipelineRunState folds the event stream into phases, issues and outcome', () => {
  const run = new PipelineRunState(new Map([[1, 'Input'], [4, 'Security']]));
  run.apply({ type: 'job', jobId: 'j1' });
  run.apply({ type: 'status', phase: 1, state: 'running' });
  run.apply({ type: 'log', phase: 1, message: 'hello' });
  run.apply({ type: 'status', phase: 1, state: 'success' });
  run.apply({ type: 'status', phase: 4, state: 'success' });
  run.apply({
    type: 'review_required',
    jobId: 'j1',
    issues: [
      { id: 'a', severity: 'error' },
      { id: 'b', severity: 'error', status: 'overridden' },
    ],
  });
  run.submitted.add('a');
  run.apply({ type: 'done', ok: true });

  assert.equal(run.jobId, 'j1');
  assert.deepEqual(run.sortedPhases().map((p) => [p.phase, p.title, p.state, p.logs.length]), [[1, 'Input', 'success', 1], [4, 'Security', 'success', 0]]);
  assert.deepEqual(run.finalIssues().map((i) => i.status), ['overridden', 'overridden']);
  assert.deepEqual(run.done, { ok: true, error: undefined, phase: undefined });
});

test('overridesForReview only submits justified entries for still-open issues', () => {
  const issues = [
    { id: 'open', severity: 'error' as const },
    { id: 'done', severity: 'error' as const, status: 'overridden' },
  ];
  const acks = [
    { issueId: 'open', justification: 'reviewed' },
    { issueId: 'done', justification: 'already' },
    { issueId: 'other', justification: 'stale' },
    { issueId: 'open', justification: '   ' },
  ];
  assert.deepEqual(overridesForReview(issues, acks), [{ issueId: 'open', justification: 'reviewed' }]);
});

test('splitNdjson carries a partial line over to the next chunk', () => {
  const first = splitNdjson('', '{"a":1}\n{"b":');
  assert.deepEqual(first, { lines: ['{"a":1}'], rest: '{"b":' });
  const second = splitNdjson(first.rest, '2}\n\n');
  assert.deepEqual(second, { lines: ['{"b":2}'], rest: '' });
});
