/**
 * Upload-mode scanning, for an Ignite server that can't see this machine's
 * disk (anything not on localhost). `validate-all` scans a *server-local*
 * `projectPath`, so against a remote server the folder has to travel with
 * the request instead: this collects its files and replays the interactive
 * pipeline's NDJSON event stream (`POST /api/pipeline`, always `dryRun`)
 * into the same result shape `validate-all` returns.
 *
 * No vscode import — node:test covers everything here directly.
 */
import * as fs from 'fs/promises';
import * as path from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

/** Same caps the server enforces on a folder upload (`MAX_FILES`, upload size). */
export const MAX_UPLOAD_FILES = 100_000;
export const MAX_UPLOAD_BYTES = 1024 * 1024 * 1024;

/** Directories never worth uploading when there's no .gitignore to go by. */
const SKIP_DIRS = new Set([
  '.git', 'node_modules', '.venv', 'venv', '__pycache__', '.mypy_cache', '.pytest_cache',
  'target', 'dist', 'build', 'out', '.next', '.nuxt', '.gradle', '.idea', '.vs', 'coverage',
]);

export interface UploadFile {
  /** Path relative to the scanned folder, `/`-separated. */
  rel: string;
  abs: string;
  size: number;
}

export function isLocalHost(baseUrl: string): boolean {
  try {
    const host = new URL(baseUrl).hostname.replace(/^\[|\]$/g, '');
    return host === 'localhost' || host === '127.0.0.1' || host === '::1' || host.endsWith('.localhost');
  } catch {
    return false;
  }
}

export type ScanMode = 'auto' | 'path' | 'upload';

/** `auto` = send a path to a server on this machine, upload to anything else. */
export function resolveScanMode(setting: ScanMode | undefined, baseUrl: string): 'path' | 'upload' {
  if (setting === 'path' || setting === 'upload') return setting;
  return isLocalHost(baseUrl) ? 'path' : 'upload';
}

/**
 * Files to upload for `root`: git's own view (tracked + untracked, honouring
 * .gitignore) when `root` is inside a work tree, else a directory walk that
 * skips the usual dependency/build folders. Symlinks are never followed.
 * `.ignite/scans` (this extension's own snapshots) is always left out.
 */
export async function collectUploadFiles(root: string): Promise<UploadFile[]> {
  const rels = (await gitListFiles(root)) ?? (await walk(root));
  const files: UploadFile[] = [];
  for (const rel of rels) {
    if (rel.startsWith('.ignite/scans/') || rel.split('/').includes('.git')) continue;
    const abs = path.join(root, rel);
    const stat = await fs.lstat(abs).catch(() => null);
    if (!stat || !stat.isFile()) continue; // deleted-but-tracked, symlink, submodule dir
    files.push({ rel, abs, size: stat.size });
  }
  return files;
}

async function gitListFiles(root: string): Promise<string[] | null> {
  try {
    const { stdout } = await execFileAsync('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z', '--', '.'], {
      cwd: root,
      maxBuffer: 256 * 1024 * 1024,
    });
    return stdout.split('\0').filter(Boolean);
  } catch {
    return null;
  }
}

async function walk(root: string): Promise<string[]> {
  const out: string[] = [];
  const visit = async (dir: string, prefix: string): Promise<void> => {
    const entries = await fs.readdir(dir, { withFileTypes: true }).catch(() => []);
    for (const entry of entries) {
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) await visit(path.join(dir, entry.name), rel);
      } else if (entry.isFile()) {
        out.push(rel);
      }
      if (out.length > MAX_UPLOAD_FILES) return;
    }
  };
  await visit(root, '');
  return out;
}

/** Throws a readable error when the folder is over the server's upload limits. */
export function checkUploadLimits(files: UploadFile[]): void {
  if (files.length === 0) throw new Error('Nothing to upload — the folder has no files (after .gitignore).');
  if (files.length > MAX_UPLOAD_FILES) throw new Error(`Too many files to upload (${files.length}; the server accepts at most ${MAX_UPLOAD_FILES}).`);
  const total = files.reduce((n, f) => n + f.size, 0);
  if (total > MAX_UPLOAD_BYTES) throw new Error(`Folder is too large to upload (${(total / 1024 / 1024).toFixed(0)} MB; the limit is 1024 MB).`);
}

/**
 * Upload path for one file. Every path gets the folder's own name as a
 * prefix, like a browser folder upload: the server descends into a single
 * top-level folder, so finding paths come back relative to the scanned
 * folder itself — even when that folder has only one subdirectory.
 */
export function uploadPathFor(root: string, rel: string): string {
  const top = path.basename(path.resolve(root)).replace(/[^A-Za-z0-9._-]/g, '_') || 'project';
  return `${top}/${rel}`;
}

// ---------------------------------------------------------------------------
// NDJSON event stream → validate-all-shaped result
// ---------------------------------------------------------------------------

export interface StreamIssue {
  id: string;
  severity: 'error' | 'warning';
  status?: string | null;
  file?: string | null;
  [key: string]: unknown;
}

export interface StreamPhase {
  phase: number;
  title: string;
  state: 'pending' | 'running' | 'success' | 'failed' | 'skipped';
  logs: string[];
}

export type PipelineEvent =
  | { type: 'job'; jobId: string }
  | { type: 'log'; phase: number; message: string }
  | { type: 'status'; phase: number; state: StreamPhase['state']; error?: string }
  | { type: 'review_required'; jobId: string; issues: StreamIssue[] }
  | { type: 'done'; ok: boolean; error?: string; phase?: number }
  | { type: string; [key: string]: unknown };

/** Accumulates the event stream into phases/issues/outcome. */
export class PipelineRunState {
  jobId: string | undefined;
  phases = new Map<number, StreamPhase>();
  issues: StreamIssue[] = [];
  done: { ok: boolean; error?: string; phase?: number } | undefined;
  /** Issue ids this client submitted a justification for at the review gate. */
  submitted = new Set<string>();

  constructor(private titles: Map<number, string> = new Map()) {}

  apply(event: PipelineEvent): void {
    switch (event.type) {
      case 'job':
        this.jobId = String((event as { jobId: string }).jobId);
        return;
      case 'log': {
        const e = event as { phase: number; message: string };
        this.phase(e.phase).logs.push(String(e.message));
        return;
      }
      case 'status': {
        const e = event as { phase: number; state: StreamPhase['state'] };
        this.phase(e.phase).state = e.state;
        return;
      }
      case 'review_required':
        this.issues = ((event as { issues?: StreamIssue[] }).issues ?? []).map((i) => ({ ...i }));
        return;
      case 'done': {
        const e = event as { ok: boolean; error?: string; phase?: number };
        this.done = { ok: Boolean(e.ok), error: e.error, phase: e.phase };
        return;
      }
    }
  }

  phase(n: number): StreamPhase {
    let p = this.phases.get(n);
    if (!p) {
      p = { phase: n, title: this.titles.get(n) ?? `Phase ${n}`, state: 'pending', logs: [] };
      this.phases.set(n, p);
    }
    return p;
  }

  /** Issues with this client's own review-gate justifications reflected as `overridden`. */
  finalIssues(): StreamIssue[] {
    return this.issues.map((i) => (this.submitted.has(i.id) ? { ...i, status: 'overridden' } : i));
  }

  sortedPhases(): StreamPhase[] {
    return [...this.phases.values()].sort((a, b) => a.phase - b.phase);
  }
}

/** Justifications (from .ignite/acknowledgments.md) that apply to this review gate's still-open issues. */
export function overridesForReview(
  issues: StreamIssue[],
  acknowledged: { issueId: string; justification: string }[]
): { issueId: string; justification: string }[] {
  const open = new Set(issues.filter((i) => i.status !== 'overridden').map((i) => i.id));
  return acknowledged.filter((o) => open.has(o.issueId) && o.justification.trim());
}

/** Splits a streamed chunk into complete NDJSON lines, carrying the partial tail over. */
export function splitNdjson(buffer: string, chunk: string): { lines: string[]; rest: string } {
  const text = buffer + chunk;
  const parts = text.split('\n');
  const rest = parts.pop() ?? '';
  return { lines: parts.map((l) => l.trim()).filter(Boolean), rest };
}
