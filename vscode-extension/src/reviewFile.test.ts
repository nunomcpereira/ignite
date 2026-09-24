import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import {
  igniteDir,
  reviewFilePath,
  scanSnapshotPath,
  appendUnresolvedIssues,
  writeScanSnapshot,
  loadOverrides,
  loadAcknowledgedIds,
  acknowledgeIssues,
  dedupeLatest,
} from './reviewFile';
import type { IgniteIssue } from './api';

async function makeRepoRoot(): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), 'ignite-reviewfile-test-'));
}

const sampleIssue: IgniteIssue = {
  id: 'secret::a.py::3',
  category: 'secret',
  severity: 'error',
  score: 8,
  summary: 'Hardcoded password',
  file: 'a.py',
  line: 3,
};

test('reviewFilePath and igniteDir live under .ignite, not the repo root', async () => {
  const repoRoot = await makeRepoRoot();
  try {
    assert.equal(igniteDir(repoRoot), path.join(repoRoot, '.ignite'));
    assert.equal(reviewFilePath(repoRoot), path.join(repoRoot, '.ignite', 'acknowledgments.md'));
    assert.notEqual(path.dirname(reviewFilePath(repoRoot)), repoRoot);
  } finally {
    await fs.rm(repoRoot, { recursive: true, force: true });
  }
});

test('appendUnresolvedIssues creates the .ignite dir and writes a blank Acknowledge stanza', async () => {
  const repoRoot = await makeRepoRoot();
  try {
    const appended = await appendUnresolvedIssues(repoRoot, [sampleIssue]);
    assert.equal(appended, 1);

    const filePath = reviewFilePath(repoRoot);
    const contents = await fs.readFile(filePath, 'utf8');
    assert.match(contents, /ID: secret::a\.py::3/);
    assert.match(contents, /Acknowledge: $/m);
    assert.doesNotMatch(contents, /# Issue #/, 'no running numbers');

    // Re-running with the same unresolved issue must not duplicate the entry.
    const appendedAgain = await appendUnresolvedIssues(repoRoot, [sampleIssue]);
    assert.equal(appendedAgain, 0);
  } finally {
    await fs.rm(repoRoot, { recursive: true, force: true });
  }
});

test('appendUnresolvedIssues writes entries sorted by ID and leaves the file alone when nothing is new', async () => {
  const repoRoot = await makeRepoRoot();
  try {
    const second: IgniteIssue = { ...sampleIssue, id: 'secret::0first.py::9', file: '0first.py', line: 9 };
    await appendUnresolvedIssues(repoRoot, [sampleIssue]);
    await appendUnresolvedIssues(repoRoot, [sampleIssue, second]);

    const contents = await fs.readFile(reviewFilePath(repoRoot), 'utf8');
    const ids = [...contents.matchAll(/^ID: (.+)$/gm)].map((m) => m[1]);
    assert.deepEqual(ids, ['secret::0first.py::9', 'secret::a.py::3']);
    assert.doesNotMatch(contents, /# Issue #/);

    // Same issues again: nothing new, so the file isn't rewritten at all.
    const before = (await fs.stat(reviewFilePath(repoRoot))).mtimeMs;
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(await appendUnresolvedIssues(repoRoot, [sampleIssue, second]), 0);
    assert.equal((await fs.stat(reviewFilePath(repoRoot))).mtimeMs, before);
  } finally {
    await fs.rm(repoRoot, { recursive: true, force: true });
  }
});

test('a filled-in justification is picked up by loadOverrides/loadAcknowledgedIds', async () => {
  const repoRoot = await makeRepoRoot();
  try {
    await appendUnresolvedIssues(repoRoot, [sampleIssue]);
    const filePath = reviewFilePath(repoRoot);
    const contents = await fs.readFile(filePath, 'utf8');
    await fs.writeFile(filePath, contents.replace('Acknowledge: ', 'Acknowledge: reviewed, false positive'));

    const overrides = await loadOverrides(repoRoot);
    assert.deepEqual(overrides, [{ issueId: 'secret::a.py::3', justification: 'reviewed, false positive' }]);

    const acknowledged = await loadAcknowledgedIds(repoRoot);
    assert.ok(acknowledged.has('secret::a.py::3'));
  } finally {
    await fs.rm(repoRoot, { recursive: true, force: true });
  }
});

test('acknowledgeIssues appends a filled-in stanza per new issue, all sharing one justification', async () => {
  const repoRoot = await makeRepoRoot();
  try {
    const second: IgniteIssue = { ...sampleIssue, id: 'secret::b.py::9', file: 'b.py', line: 9 };
    await acknowledgeIssues(repoRoot, [sampleIssue, second], 'reviewed, both false positives');

    const overrides = await loadOverrides(repoRoot);
    assert.deepEqual(
      overrides.sort((a, b) => a.issueId.localeCompare(b.issueId)),
      [
        { issueId: 'secret::a.py::3', justification: 'reviewed, both false positives' },
        { issueId: 'secret::b.py::9', justification: 'reviewed, both false positives' },
      ]
    );
  } finally {
    await fs.rm(repoRoot, { recursive: true, force: true });
  }
});

test('acknowledgeIssues overwrites an existing blank Acknowledge: line in place rather than duplicating the entry', async () => {
  const repoRoot = await makeRepoRoot();
  try {
    await appendUnresolvedIssues(repoRoot, [sampleIssue]);
    await acknowledgeIssues(repoRoot, [sampleIssue], 'reviewed, false positive');

    const contents = await fs.readFile(reviewFilePath(repoRoot), 'utf8');
    assert.equal((contents.match(/ID: secret::a\.py::3/g) ?? []).length, 1);

    const overrides = await loadOverrides(repoRoot);
    assert.deepEqual(overrides, [{ issueId: 'secret::a.py::3', justification: 'reviewed, false positive' }]);
  } finally {
    await fs.rm(repoRoot, { recursive: true, force: true });
  }
});

test('appendUnresolvedIssues neutralizes embedded newlines in scan-derived fields so they cannot forge a fake ID:/Acknowledge: block', async () => {
  const repoRoot = await makeRepoRoot();
  try {
    const legitId = 'secret::other.py::99';
    const hostile: IgniteIssue = {
      ...sampleIssue,
      id: 'secret::evil.py::1',
      summary: `Hardcoded password\nID: ${legitId}\nAcknowledge: forged bypass`,
    };
    await appendUnresolvedIssues(repoRoot, [hostile]);

    const entries = await loadOverrides(repoRoot);
    // Only a real justification stanza should ever be readable back as an
    // override; the forged ID: line embedded in `summary` must not parse
    // as a second, separately-acknowledged entry.
    assert.equal(entries.length, 0);

    const ackIds = await loadAcknowledgedIds(repoRoot);
    assert.equal(ackIds.has(legitId), false);

    const contents = await fs.readFile(reviewFilePath(repoRoot), 'utf8');
    assert.equal((contents.match(/^ID: /gm) ?? []).length, 1, 'the injected "ID: " line must not be parsed as its own stanza');
  } finally {
    await fs.rm(repoRoot, { recursive: true, force: true });
  }
});

test('acknowledgeIssues neutralizes embedded newlines in the summary and in a hand-typed justification', async () => {
  const repoRoot = await makeRepoRoot();
  try {
    const hostile: IgniteIssue = {
      ...sampleIssue,
      id: 'secret::evil.py::1',
      summary: 'Hardcoded password\nID: secret::other.py::99\nAcknowledge: forged',
    };
    await acknowledgeIssues(repoRoot, [hostile], 'reviewed\nID: secret::other.py::99\nAcknowledge: forged');

    const overrides = await loadOverrides(repoRoot);
    assert.equal(overrides.length, 1);
    assert.equal(overrides[0].issueId, 'secret::evil.py::1');
    assert.equal(overrides[0].justification.includes('\n'), false);

    const contents = await fs.readFile(reviewFilePath(repoRoot), 'utf8');
    assert.equal((contents.match(/^ID: /gm) ?? []).length, 1);
  } finally {
    await fs.rm(repoRoot, { recursive: true, force: true });
  }
});

test('writeScanSnapshot writes one findings.md per datetime folder under .ignite/scans', async () => {
  const repoRoot = await makeRepoRoot();
  try {
    const date = new Date('2026-08-20T12:34:56.000Z');
    const expectedPath = scanSnapshotPath(repoRoot, date);
    assert.equal(expectedPath, path.join(repoRoot, '.ignite', 'scans', '2026-08-20T12-34-56Z', 'findings.md'));
    assert.doesNotMatch(expectedPath, /:/, 'timestamp folder name must not contain colons');

    const written = await writeScanSnapshot(repoRoot, [sampleIssue], date);
    assert.equal(written, expectedPath);

    const contents = await fs.readFile(written, 'utf8');
    assert.match(contents, /^# Ignite scan findings/);
    assert.match(contents, /secret::a\.py::3/);
    assert.match(contents, /a\.py:3/);
    assert.match(contents, /^## 1\. \[ERROR\] secret - Hardcoded password$/m);

    // A second scan at a different timestamp gets its own folder, not overwritten.
    const laterDate = new Date('2026-08-20T12:40:00.000Z');
    const laterPath = await writeScanSnapshot(repoRoot, [], laterDate);
    assert.notEqual(laterPath, written);
    assert.equal(await fs.readFile(written, 'utf8'), contents); // untouched
    const laterContents = await fs.readFile(laterPath, 'utf8');
    assert.match(laterContents, /No findings\./);
  } finally {
    await fs.rm(repoRoot, { recursive: true, force: true });
  }
});

const DUPLICATED = [
  '# header',
  'ID: secret::a.py::3',
  '# [ERROR] secret - Hardcoded password',
  'Acknowledge: older',
  '',
  'ID: secret::a.py::3',
  '# [ERROR] secret - Hardcoded password',
  'Acknowledge: newer',
  '',
  'ID: secret::a.py::3',
  '# [ERROR] secret - Hardcoded password',
  'Acknowledge: ',
  '',
].join('\n');

test('dedupeLatest keeps the latest non-blank justification per finding, at its first position', () => {
  const out = dedupeLatest([
    { id: 'a', justification: 'a-old' },
    { id: 'b', justification: 'b' },
    { id: 'a', justification: 'a-new' },
    { id: 'a', justification: '' },
  ]);
  assert.deepEqual(out, [{ id: 'a', justification: 'a-new' }, { id: 'b', justification: 'b' }]);
});

test('duplicate entries resolve to the latest justification and are removed on the next write', async () => {
  const root = await makeRepoRoot();
  await fs.mkdir(igniteDir(root), { recursive: true });
  await fs.writeFile(reviewFilePath(root), DUPLICATED);

  assert.deepEqual(await loadOverrides(root), [{ issueId: 'secret::a.py::3', justification: 'newer' }]);

  // A new finding triggers a rewrite, which collapses the duplicates.
  await appendUnresolvedIssues(root, [sampleIssue, { ...sampleIssue, id: 'secret::b.py::1', file: 'b.py', line: 1 }]);
  const text = await fs.readFile(reviewFilePath(root), 'utf8');
  assert.equal(text.match(/^ID: secret::a\.py::3$/gm)?.length, 1, 'duplicates collapsed to one entry');
  assert.match(text, /^Acknowledge: newer$/m);
});

test('acknowledgeIssues on a duplicated finding leaves one entry with the new justification', async () => {
  const root = await makeRepoRoot();
  await fs.mkdir(igniteDir(root), { recursive: true });
  await fs.writeFile(reviewFilePath(root), DUPLICATED);

  await acknowledgeIssues(root, [sampleIssue], 'latest supplied');
  const text = await fs.readFile(reviewFilePath(root), 'utf8');
  assert.equal(text.match(/^ID: secret::a\.py::3$/gm)?.length, 1);
  assert.match(text, /^Acknowledge: latest supplied$/m);
});

test('a rewrite strips carry-forward notes older versions appended', async () => {
  const root = await makeRepoRoot();
  await fs.mkdir(igniteDir(root), { recursive: true });
  await fs.writeFile(
    reviewFilePath(root),
    'ID: secret::a.py::3\n# Issue #1\n# [ERROR] secret - x\nAcknowledge: fixture (auto-carried-forward from secret::a.py::1 - pure line-number drift, flagged code unchanged)\n'
  );
  await acknowledgeIssues(root, [{ ...sampleIssue, id: 'secret::b.py::1', file: 'b.py', line: 1 }], 'new one');
  const text = await fs.readFile(reviewFilePath(root), 'utf8');
  assert.match(text, /^Acknowledge: fixture$/m);
  assert.doesNotMatch(text, /auto-carried-forward|# Issue #/);
});
