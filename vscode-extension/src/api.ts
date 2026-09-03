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
  /** Present when `changedFiles` was passed — how many issues existed before that filter. */
  totalIssueCount?: number;
  filteredByChangedFiles?: boolean;
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

/**
 * `Authorization: Bearer ignite_<key>` when "ignite.apiKey" is set (minted via
 * `ignite create-api-key`) — most routes this extension calls work fine
 * unauthenticated, but resolve_effective_github_token (fix-PR's apply step)
 * prefers a resolved session/API-key user's own connected GitHub account over
 * the server's fallback token, so a PR opens attributed to the right person
 * once this is set instead of always falling back to the server's own token.
 */
function authHeaders(): Record<string, string> {
  const key = vscode.workspace.getConfiguration('ignite').get<string>('apiKey', '').trim();
  return key ? { Authorization: `Bearer ${key}` } : {};
}

/** Thrown when the Ignite server isn't reachable — same precondition hooks/pre-push already documents. */
export class IgniteUnreachableError extends Error {
  constructor(url: string, cause?: unknown) {
    super(`Ignite isn't reachable at ${url}. Start it with 'npm start' in the ignite repo, or set the "ignite.baseUrl" setting to point elsewhere.`);
    this.name = 'IgniteUnreachableError';
    if (cause) this.cause = cause;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * A single quick probe can read as "down" purely because the server's
 * event loop is momentarily saturated by CPU-bound work from an in-flight
 * scan (large JSON.parse of a tool's output, a big regex sweep, etc.) —
 * that is a live, busy process, not an unreachable one. Three attempts
 * with a generous per-attempt timeout and a short backoff between them
 * gives a transient stall room to clear before this reports "unreachable".
 *
 * `onAttempt`, when passed, is called after every attempt with a one-line
 * summary (timing + the concrete reason it failed: timeout, ECONNREFUSED,
 * a 5xx body, etc.) — surfaced in the Output channel so a spurious
 * "Ignite isn't reachable" report is diagnosable instead of a dead end.
 */
export async function checkReachable(onAttempt?: (line: string) => void): Promise<boolean> {
  const url = baseUrl();
  for (let attempt = 1; attempt <= 3; attempt++) {
    const startedAt = Date.now();
    try {
      const res = await fetch(url, { method: 'GET', headers: authHeaders(), signal: AbortSignal.timeout(8000) });
      const elapsed = Date.now() - startedAt;
      if (res.ok || res.status < 500) {
        onAttempt?.(`  probe ${attempt}/3 → HTTP ${res.status} in ${elapsed}ms — reachable`);
        return true;
      }
      onAttempt?.(`  probe ${attempt}/3 → HTTP ${res.status} in ${elapsed}ms — treated as down (5xx)`);
    } catch (e) {
      const elapsed = Date.now() - startedAt;
      const reason = e instanceof Error ? `${e.name}: ${e.message}` : String(e);
      onAttempt?.(`  probe ${attempt}/3 → failed after ${elapsed}ms — ${reason}`);
    }
    if (attempt < 3) await sleep(1500);
  }
  return false;
}

export interface OverrideSubmission {
  issueId: string;
  justification: string;
}

export interface ValidateAllOptions {
  runLocalCi: boolean;
  org?: string;
  repo?: string;
  /** Justified entries read from .ignite/acknowledgments.md — same shape hooks/pre-push resubmits. */
  overrides?: OverrideSubmission[];
  actor?: { email: string; name: string };
  /**
   * Project-relative paths (git-diff-style) to restrict the *returned*
   * issues to — the scan itself still runs in full (validate-all has no
   * per-file skip mode), but the response's `issues` only include ones
   * whose `file` is in this set, same as the CLI's `--changed-files`.
   */
  changedFiles?: string[];
}

export async function validateAll(projectPath: string, opts: ValidateAllOptions): Promise<ValidateAllResult> {
  const url = baseUrl();
  let res: Response;
  try {
    res = await fetch(`${url}/api/pipeline/validate-all`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({
        projectPath,
        runLocalCi: opts.runLocalCi,
        org: opts.org,
        repo: opts.repo,
        overrides: opts.overrides ?? [],
        actor: opts.actor,
        changedFiles: opts.changedFiles,
      }),
      // Phase 4's heavier tools (Bearer, CodeQL database builds, GuardDog's
      // per-dependency fetches) can genuinely take minutes on a real project.
      signal: AbortSignal.timeout(20 * 60 * 1000),
    });
  } catch (e) {
    // A fetch failure here doesn't necessarily mean the server went down —
    // this request runs for up to 20 minutes (Bearer/CodeQL/GuardDog can
    // genuinely take that long), and a mid-scan connection drop (proxy/
    // keep-alive idle timeout, this AbortSignal itself firing, a transient
    // socket reset) throws the exact same way a real "server never
    // started" failure would. Re-checking reachability at the moment of
    // failure — instead of assuming the worst from the fetch error alone —
    // is what tells apart "Ignite isn't running" from "that request died
    // but the server the scan was queued to is still up".
    if (await checkReachable()) {
      const detail = e instanceof Error ? e.message : String(e);
      throw new Error(
        `The request to ${url}/api/pipeline/validate-all failed (${detail}), but Ignite itself is still reachable — ` +
        'the scan may still be running server-side. Check the server\'s own console/logs before assuming it crashed, ' +
        'then retry once it settles.'
      );
    }
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

export interface ProjectSummary {
  id: number;
  job_id: string;
  org: string;
  repo: string;
  status: string;
  created_at: string;
  finished_at: string | null;
}

export interface ProjectStep {
  phase: number;
  title: string;
  state: string;
  logs: string;
}

export interface ProjectDetails extends ProjectSummary {
  steps: ProjectStep[];
}

/**
 * validate-all is a single synchronous request with no NDJSON streaming
 * (unlike POST /api/pipeline) — but store.upsertStep persists each phase's
 * state/logs to the DB live as the run progresses (see routes/pipeline-
 * validate.js's persistPhase), so polling these two existing history
 * endpoints (already used by the web UI's project history panel) is how
 * the extension gets real progress out of a request it can't stream.
 */
export async function listProjects(): Promise<ProjectSummary[]> {
  const res = await fetch(`${baseUrl()}/api/projects`, { headers: authHeaders(), signal: AbortSignal.timeout(5000) });
  if (!res.ok) throw new Error(`GET /api/projects returned HTTP ${res.status}`);
  return (await res.json()) as ProjectSummary[];
}

export async function getProjectDetails(id: number): Promise<ProjectDetails | null> {
  const res = await fetch(`${baseUrl()}/api/projects/${id}`, { headers: authHeaders(), signal: AbortSignal.timeout(5000) });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`GET /api/projects/${id} returned HTTP ${res.status}`);
  return (await res.json()) as ProjectDetails;
}

export interface LicenseManifestDependency {
  name: string;
  version?: string;
  license?: string | null;
  classification?: string;
  [key: string]: unknown;
}

export interface LicenseManifest {
  file: string;
  ecosystem?: string;
  dependencies: LicenseManifestDependency[];
  [key: string]: unknown;
}

export interface LicenseComplianceResult {
  ok: boolean;
  projectPath: string;
  manifests: LicenseManifest[];
  [key: string]: unknown;
}

export interface SbomResult {
  ok: boolean;
  projectPath: string;
  engine?: string;
  sbom?: unknown;
  [key: string]: unknown;
}

export interface LocMetricsResult {
  ok: boolean;
  projectPath: string;
  engine?: string;
  metrics?: unknown;
  [key: string]: unknown;
}

export interface PostureResult {
  ok: boolean;
  projectPath: string;
  engine?: string;
  posture?: unknown;
  [key: string]: unknown;
}

async function postReport<T>(path: string, projectPath: string): Promise<T> {
  const url = baseUrl();
  let res: Response;
  try {
    res = await fetch(`${url}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ projectPath }),
      // These reuse the same tool binaries (syft/gocloc/semgrep) validate-all's
      // Phase 4 runs, so a cold run on a large project can take a while.
      signal: AbortSignal.timeout(5 * 60 * 1000),
    });
  } catch (e) {
    throw new IgniteUnreachableError(url, e);
  }
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`${path} returned HTTP ${res.status}: ${text.slice(0, 300)}`);
  }
  return (await res.json()) as T;
}

export function getLicenseCompliance(projectPath: string): Promise<LicenseComplianceResult> {
  return postReport<LicenseComplianceResult>('/api/dependencies/check', projectPath);
}

export function getSbom(projectPath: string): Promise<SbomResult> {
  return postReport<SbomResult>('/api/reports/sbom', projectPath);
}

export function getLocMetrics(projectPath: string): Promise<LocMetricsResult> {
  return postReport<LocMetricsResult>('/api/reports/loc-metrics', projectPath);
}

export function getPosture(projectPath: string): Promise<PostureResult> {
  return postReport<PostureResult>('/api/reports/posture', projectPath);
}

export interface FixCandidate {
  issueId: string;
  file: string;
  category: string;
  severity: string;
  summary: string;
  startLine: number;
  endLine: number;
  explanation: string;
  original: string;
  replacement: string;
}

export interface FixPrPreviewResult {
  ok: boolean;
  candidates: FixCandidate[];
  consideredCount: number;
  reason?: string;
}

export interface FixPrApplyResult {
  ok: boolean;
  alreadyOpen?: boolean;
  branch?: string;
  prUrl?: string;
  filesChanged?: string[];
  error?: string;
}

async function postJson<T>(path: string, body: unknown, timeoutMs: number): Promise<T> {
  const url = baseUrl();
  let res: Response;
  try {
    res = await fetch(`${url}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (e) {
    throw new IgniteUnreachableError(url, e);
  }
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`${path} returned HTTP ${res.status}: ${text.slice(0, 300)}`);
  }
  return (await res.json()) as T;
}

/** Runs the scan-wide LLM suggest-fix pass over every open issue in a job — no git involved yet. */
export function previewFixPr(jobId: string): Promise<FixPrPreviewResult> {
  // LLM calls over every open issue's snippet — generous timeout to match the server's own headroom.
  return postJson<FixPrPreviewResult>(`/api/pipeline/${encodeURIComponent(jobId)}/fix-pr/preview`, {}, 10 * 60 * 1000);
}

/** Clones the repo's default branch, applies the accepted candidates, and opens one PR bundling all of them. */
export function applyFixPr(jobId: string, candidates: FixCandidate[]): Promise<FixPrApplyResult> {
  return postJson<FixPrApplyResult>(`/api/pipeline/${encodeURIComponent(jobId)}/fix-pr/apply`, { candidates }, 5 * 60 * 1000);
}

function issueBody(issue: IgniteIssue): Record<string, unknown> {
  return {
    category: issue.category,
    severity: issue.severity,
    file: issue.file,
    line: issue.line,
    summary: issue.summary,
    snippet: issue.snippet,
  };
}

export interface ExplainIssueResult {
  ok: boolean;
  explanation: string | null;
  cached?: boolean;
  reason?: string;
  error?: string;
}

/** Plain-language explanation of one finding — cached server-side by issue identity. */
export function explainIssue(issue: IgniteIssue): Promise<ExplainIssueResult> {
  return postJson<ExplainIssueResult>('/api/issues/explain', issueBody(issue), 90_000);
}

export interface SuggestFixResult {
  ok: boolean;
  suggestion: { explanation: string; replacement: string | null; startLine: number; endLine: number } | null;
  reason?: string;
  error?: string;
}

/** One-off LLM-proposed diff for a single finding — needs `issue.snippet` (validate-all always includes it for file-addressable issues). */
export function suggestFix(issue: IgniteIssue): Promise<SuggestFixResult> {
  return postJson<SuggestFixResult>('/api/issues/suggest-fix', issueBody(issue), 90_000);
}

export async function toolsStatus(): Promise<ToolStatus[]> {
  const url = baseUrl();
  let res: Response;
  try {
    res = await fetch(`${url}/api/tools/status`, { headers: authHeaders(), signal: AbortSignal.timeout(10000) });
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
