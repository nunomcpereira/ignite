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

    // Re-running with the same unresolved issue must not duplicate the entry.
    const appendedAgain = await appendUnresolvedIssues(repoRoot, [sampleIssue]);
    assert.equal(appendedAgain, 0);
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
