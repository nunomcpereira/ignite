import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { getActor, getOriginOrgRepo, getRepoRoot, getChangedFiles } from './git';

const execFileAsync = promisify(execFile);

// getActor's "unset" tests rely on git config *not* falling back to this
// machine's real ~/.gitconfig — isolate every git invocation in this file
// (both the test helper's and git.ts's own, since it inherits process.env)
// from the user's actual global/system config.
process.env.GIT_CONFIG_GLOBAL = '/dev/null';
process.env.GIT_CONFIG_SYSTEM = '/dev/null';
process.env.GIT_CONFIG_NOSYSTEM = '1';

async function git(args: string[], cwd: string): Promise<void> {
  await execFileAsync('git', args, { cwd });
}

async function makeRepo(): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ignite-git-test-'));
  await git(['init', '-q'], dir);
  await git(['config', 'user.email', 'dev@example.com'], dir);
  await git(['config', 'user.name', 'Dev Person'], dir);
  return dir;
}

test('getActor reads user.email/user.name from git config', async () => {
  const dir = await makeRepo();
  try {
    assert.deepEqual(await getActor(dir), { email: 'dev@example.com', name: 'Dev Person' });
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('getActor falls back to email as name when user.name is unset', async () => {
  const dir = await makeRepo();
  try {
    await git(['config', '--unset', 'user.name'], dir);
    assert.deepEqual(await getActor(dir), { email: 'dev@example.com', name: 'dev@example.com' });
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('getActor returns null when user.email is unset', async () => {
  const dir = await makeRepo();
  try {
    await git(['config', '--unset', 'user.email'], dir);
    assert.equal(await getActor(dir), null);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('getOriginOrgRepo parses org/repo out of an SSH remote URL', async () => {
  const dir = await makeRepo();
  try {
    await git(['remote', 'add', 'origin', 'git@github.com:acme/widgets.git'], dir);
    assert.deepEqual(await getOriginOrgRepo(dir), { org: 'acme', repo: 'widgets' });
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('getOriginOrgRepo parses org/repo out of an HTTPS remote URL with no .git suffix', async () => {
  const dir = await makeRepo();
  try {
    await git(['remote', 'add', 'origin', 'https://github.com/acme/widgets'], dir);
    assert.deepEqual(await getOriginOrgRepo(dir), { org: 'acme', repo: 'widgets' });
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('getOriginOrgRepo returns blank org/repo when there is no remote', async () => {
  const dir = await makeRepo();
  try {
    assert.deepEqual(await getOriginOrgRepo(dir), { org: '', repo: '' });
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('getRepoRoot resolves to the top-level dir from a nested subdirectory', async () => {
  const dir = await makeRepo();
  try {
    const nested = path.join(dir, 'a', 'b');
    await fs.mkdir(nested, { recursive: true });
    const root = await getRepoRoot(nested);
    assert.equal(await fs.realpath(root ?? ''), await fs.realpath(dir));
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('getRepoRoot returns null outside any git repository', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ignite-not-a-repo-'));
  try {
    assert.equal(await getRepoRoot(dir), null);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('getChangedFiles reports untracked and modified-tracked files, not clean ones', async () => {
  const dir = await makeRepo();
  try {
    await fs.writeFile(path.join(dir, 'committed.txt'), 'v1\n');
    await fs.writeFile(path.join(dir, 'unchanged.txt'), 'v1\n');
    await git(['add', '.'], dir);
    await git(['commit', '-q', '-m', 'initial'], dir);

    await fs.writeFile(path.join(dir, 'committed.txt'), 'v2\n');
    await fs.writeFile(path.join(dir, 'new.txt'), 'brand new\n');

    const files = (await getChangedFiles(dir)).sort();
    assert.deepEqual(files, ['committed.txt', 'new.txt']);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('getChangedFiles reports working-tree files even with no commits yet', async () => {
  const dir = await makeRepo();
  try {
    await fs.writeFile(path.join(dir, 'untracked.txt'), 'hello\n');
    assert.deepEqual(await getChangedFiles(dir), ['untracked.txt']);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('getChangedFiles returns nothing for a clean working tree', async () => {
  const dir = await makeRepo();
  try {
    await fs.writeFile(path.join(dir, 'a.txt'), 'v1\n');
    await git(['add', '.'], dir);
    await git(['commit', '-q', '-m', 'initial'], dir);
    assert.deepEqual(await getChangedFiles(dir), []);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});
