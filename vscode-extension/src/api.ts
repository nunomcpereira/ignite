import * as vscode from 'vscode';

export interface IgniteIssue {
  id: string;
  category: string;
  severity: 'error' | 'warning';
  score: number;
  summary: string;
  file: string | null;
  line: number | null;
  snippet?: {
    startLine: number;
    lines: { number: number; text: string }[];
    highlightLine?: number;
    highlightStart?: number;
    highlightEnd?: number;
  } | null;
  cwe?: string | null;
  owasp?: string | null;
  status?: 'overridden' | null;
}

export interface IgnitePhase {
  phase: number;
  title: string;
  state: 'pending' | 'running' | 'success' | 'failed' | 'skipped';
  logs: string[];
}

export interface ValidateAllResult {
  ok: boolean;
  mode: string;
  jobId?: string;
  projectPath: string;
  error?: string;
  failedPhase?: number | null;
  issues: IgniteIssue[];
  phases: IgnitePhase[];
}

export interface ToolStatus {
  name: string;
  installed: boolean;
  enabled: boolean;
  detail?: string;
}

function baseUrl(): string {
  return vscode.workspace.getConfiguration('ignite').get<string>('baseUrl', 'http://localhost:51337').replace(/\/+$/, '');
}

/** Thrown when the Ignite server isn't reachable — same precondition hooks/pre-push already documents. */
export class IgniteUnreachableError extends Error {
  constructor(url: string, cause?: unknown) {
    super(`Ignite isn't reachable at ${url}. Start it with 'npm start' in the ignite repo, or set the "ignite.baseUrl" setting to point elsewhere.`);
    this.name = 'IgniteUnreachableError';
    if (cause) this.cause = cause;
  }
}

export async function checkReachable(): Promise<boolean> {
  const url = baseUrl();
  try {
    const res = await fetch(url, { method: 'GET', signal: AbortSignal.timeout(3000) });
    return res.ok || res.status < 500;
  } catch {
    return false;
  }
}

export interface OverrideSubmission {
  issueId: string;
  justification: string;
}

export interface ValidateAllOptions {
  runLocalCi: boolean;
  org?: string;
  repo?: string;
  /** Justified entries read from .ignite-review.md — same shape hooks/pre-push resubmits. */
  overrides?: OverrideSubmission[];
  actor?: { email: string; name: string };
}

export async function validateAll(projectPath: string, opts: ValidateAllOptions): Promise<ValidateAllResult> {
  const url = baseUrl();
  let res: Response;
  try {
    res = await fetch(`${url}/api/pipeline/validate-all`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        projectPath,
        runLocalCi: opts.runLocalCi,
        org: opts.org,
        repo: opts.repo,
        overrides: opts.overrides ?? [],
        actor: opts.actor,
      }),
      // Phase 4's heavier tools (Bearer, CodeQL database builds, GuardDog's
      // per-dependency fetches) can genuinely take minutes on a real project.
      signal: AbortSignal.timeout(20 * 60 * 1000),
    });
  } catch (e) {
    throw new IgniteUnreachableError(url, e);
  }
  if (res.status >= 500) {
    const text = await res.text().catch(() => '');
    throw new Error(`Ignite validate-all returned HTTP ${res.status}: ${text.slice(0, 300)}`);
  }
  // 400 is a normal "checks failed" response here (see routes/pipeline-validate.js),
  // not a transport error — its body still has the {ok:false, issues, phases} shape.
  return (await res.json()) as ValidateAllResult;
}

export async function toolsStatus(): Promise<ToolStatus[]> {
  const url = baseUrl();
  let res: Response;
  try {
    res = await fetch(`${url}/api/tools/status`, { signal: AbortSignal.timeout(10000) });
  } catch (e) {
    throw new IgniteUnreachableError(url, e);
  }
  if (!res.ok) throw new Error(`Ignite /api/tools/status returned HTTP ${res.status}`);
  // Shape: { <toolName>: { ok: boolean, reason?: string, enabled: boolean }, ... }
  // — each xTooling() probe's own return shape (see checks/secrets.js's gitleaksTooling
  // for the canonical example), passed through mountToolsStatusRoutes unchanged.
  const data = (await res.json()) as Record<string, { ok: boolean; reason?: string; enabled: boolean }>;
  return Object.entries(data).map(([name, v]) => ({
    name,
    installed: Boolean(v.ok),
    enabled: Boolean(v.enabled),
    detail: v.reason,
  }));
}
