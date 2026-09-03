import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

async function git(args: string[], cwd: string): Promise<string> {
  try {
    const { stdout } = await execFileAsync('git', args, { cwd });
    return stdout.trim();
  } catch {
    return '';
  }
}

export interface Actor {
  email: string;
  name: string;
}

export async function getActor(repoPath: string): Promise<Actor | null> {
  const email = await git(['config', '--get', 'user.email'], repoPath);
  if (!email) return null;
  const name = (await git(['config', '--get', 'user.name'], repoPath)) || email;
  return { email, name };
}

/** Mirrors hooks/pre-push's sed-based org/repo extraction from remote.origin.url. */
export async function getOriginOrgRepo(repoPath: string): Promise<{ org: string; repo: string }> {
  const url = await git(['config', '--get', 'remote.origin.url'], repoPath);
  const m = url.match(/[:/]([^/]+)\/([^/.]+?)(\.git)?$/);
  return { org: m?.[1] ?? '', repo: m?.[2] ?? '' };
}

export async function getRepoRoot(startPath: string): Promise<string | null> {
  const root = await git(['rev-parse', '--show-toplevel'], startPath);
  return root || null;
}

/**
 * Every file with uncommitted changes (staged, unstaged, or new/untracked),
 * as paths relative to `cwd` — matches the shape validate-all's `changedFiles`
 * filter expects (issue.file is relative to the scanned projectPath, which
 * the caller passes as `cwd` here). `--relative` on `diff` keeps that true
 * even when the open workspace folder is a subdirectory of the git repo;
 * `ls-files --others` is already cwd-relative. Falls back to `HEAD~1` when
 * there's no `HEAD` yet (a brand-new repo with no commits) so a first-commit
 * workspace still reports its working-tree changes instead of silently
 * reporting none.
 */
export async function getChangedFiles(cwd: string): Promise<string[]> {
  let tracked = await git(['diff', '--name-only', '--relative', 'HEAD'], cwd);
  if (!tracked) {
    // No HEAD (no commits yet) diffs against nothing rather than failing loudly —
    // fall back to every tracked file's index-vs-working-tree diff instead.
    tracked = await git(['diff', '--name-only', '--relative'], cwd);
  }
  const untracked = await git(['ls-files', '--others', '--exclude-standard'], cwd);
  const files = new Set<string>();
  for (const f of [...tracked.split('\n'), ...untracked.split('\n')]) {
    const trimmed = f.trim();
    if (trimmed) files.add(trimmed);
  }
  return [...files];
}
