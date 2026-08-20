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
