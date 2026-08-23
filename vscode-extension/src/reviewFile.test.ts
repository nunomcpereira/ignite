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
    assert.match(contents, /^ID: secret::a\.py::3\n# Issue #1\n/m);

    // Re-running with the same unresolved issue must not duplicate the entry.
    const appendedAgain = await appendUnresolvedIssues(repoRoot, [sampleIssue]);
    assert.equal(appendedAgain, 0);
  } finally {
    await fs.rm(repoRoot, { recursive: true, force: true });
  }
});

test('appendUnresolvedIssues renumbers "# Issue #N" fresh on every write instead of accumulating', async () => {
  const repoRoot = await makeRepoRoot();
  try {
    await appendUnresolvedIssues(repoRoot, [sampleIssue]);
    const second: IgniteIssue = { ...sampleIssue, id: 'secret::b.py::9', file: 'b.py', line: 9 };
    await appendUnresolvedIssues(repoRoot, [sampleIssue, second]);

    const contents = await fs.readFile(reviewFilePath(repoRoot), 'utf8');
    assert.match(contents, /^ID: secret::a\.py::3\n# Issue #1\n/m);
    assert.match(contents, /^ID: secret::b\.py::9\n# Issue #2\n/m);
    // No leftover/duplicate numbering from the first write.
    assert.equal((contents.match(/# Issue #\d+/g) ?? []).length, 2);
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
