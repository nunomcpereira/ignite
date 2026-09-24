import * as vscode from 'vscode';
import type { DailyReportOptions, DailyReportResult } from './dailyReport';
import { DEFAULT_BASE_URL, normalizeBaseUrl, cleanApiKey } from './serverUrl';
import * as fs from 'fs/promises';
import {
  collectUploadFiles, checkUploadLimits, uploadPathFor, PipelineRunState, overridesForReview, splitNdjson,
  type PipelineEvent, type StreamPhase,
} from './upload';

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

export function baseUrl(): string {
  const configured = vscode.workspace.getConfiguration('ignite').get<string>('baseUrl', DEFAULT_BASE_URL);
  const normalized = normalizeBaseUrl(configured || DEFAULT_BASE_URL);
  return normalized.ok ? normalized.url : configured.replace(/\/+$/, '');
}

/**
 * API key held in VS Code's SecretStorage (OS keychain) — set from the
 * sidebar's Server panel. Kept in a module variable because every request
 * builds its headers synchronously; extension.ts loads it at activation and
 * on every SecretStorage change.
 */
let storedApiKey = '';

export function setStoredApiKey(key: string | undefined): void {
  storedApiKey = cleanApiKey(key ?? '');
}

export type ApiKeySource = 'secret' | 'settings' | 'none';

/** Which key requests actually carry: the keychain one wins over the plaintext `ignite.apiKey` setting. */
export function effectiveApiKey(): { key: string; source: ApiKeySource } {
  if (storedApiKey) return { key: storedApiKey, source: 'secret' };
  const fromSettings = cleanApiKey(vscode.workspace.getConfiguration('ignite').get<string>('apiKey', ''));
  if (fromSettings) return { key: fromSettings, source: 'settings' };
  return { key: '', source: 'none' };
}

/**
 * `Authorization: Bearer ignite_<key>` when an API key is configured (minted via
 * `create-api-key`) — most routes this extension calls work fine
 * unauthenticated, but resolve_effective_github_token (fix-PR's apply step)
 * prefers a resolved session/API-key user's own connected GitHub account over
 * the server's fallback token, so a PR opens attributed to the right person
 * once this is set instead of always falling back to the server's own token.
 */
function authHeaders(key: string = effectiveApiKey().key): Record<string, string> {
  return key ? { Authorization: `Bearer ${key}` } : {};
}

export interface MintedKey {
  key: string;
  user?: { email?: string; name?: string | null };
}

/**
 * Standalone-auth sign-in → mint → sign-out, all in one go: logs in with the
 * account's email/password to get a short-lived session, uses it on
 * POST /api/auth/api-keys (which only accepts a session, never a key), then
 * logs that session out again. The password is only ever held for these
 * three requests — the caller stores just the returned key.
 */
export async function mintApiKeyWithPassword(email: string, password: string, label: string): Promise<MintedKey> {
  const url = baseUrl();
  const login = await fetch(`${url}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
    signal: AbortSignal.timeout(15000),
  }).catch((e) => {
    throw new IgniteUnreachableError(url, e);
  });
  if (!login.ok) {
    const body = (await login.json().catch(() => null)) as { error?: string } | null;
    throw new Error(body?.error ?? `Sign-in failed (HTTP ${login.status}).`);
  }
  const setCookies = typeof login.headers.getSetCookie === 'function' ? login.headers.getSetCookie() : [login.headers.get('set-cookie') ?? ''];
  const session = setCookies.map((c) => c.split(';')[0]).find((c) => c.startsWith('ignite_sid='));
  if (!session) throw new Error('Signed in, but the server returned no session cookie.');
  try {
    const res = await fetch(`${url}/api/auth/api-keys`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: session },
      body: JSON.stringify({ label, client: 'vscode' }),
      signal: AbortSignal.timeout(15000),
    });
    const body = (await res.json().catch(() => null)) as (MintedKey & { error?: string }) | null;
    if (res.status === 404) throw new Error('This Ignite server is too old to create API keys from the UI — update it, or use create-api-key on the server.');
    if (!res.ok || !body?.key) throw new Error(body?.error ?? `Creating the key failed (HTTP ${res.status}).`);
    return { key: body.key, user: body.user };
  } finally {
    await fetch(`${url}/api/auth/logout`, { method: 'POST', headers: { Cookie: session }, signal: AbortSignal.timeout(5000) }).catch(() => undefined);
  }
}

export interface ServerProbe {
  ok: boolean;
  url: string;
  latencyMs?: number;
  authMode?: string;
  /** Resolved from GET /api/auth/me — who the API key authenticates as, if anyone. */
  user?: { email?: string; name?: string } | null;
  /** Set when a key was sent but the server didn't resolve it to a user. */
  keyRejected?: boolean;
  error?: string;
}

/**
 * One quick, non-retrying probe for the sidebar's connection indicator —
 * `checkReachable` below is the patient 3-attempt variant a scan uses.
 * `urlOverride`/`keyOverride` let the panel test a value before saving it.
 */
export async function probeServer(urlOverride?: string, keyOverride?: string): Promise<ServerProbe> {
  const url = urlOverride ?? baseUrl();
  const key = keyOverride ?? effectiveApiKey().key;
  const startedAt = Date.now();
  try {
    const res = await fetch(`${url}/api/auth/config`, { signal: AbortSignal.timeout(5000) });
    const latencyMs = Date.now() - startedAt;
    if (!res.ok) return { ok: false, url, latencyMs, error: `HTTP ${res.status} from /api/auth/config — is this an Ignite server?` };
    const config = (await res.json().catch(() => null)) as { mode?: string } | null;
    if (!config || typeof config.mode !== 'string') {
      return { ok: false, url, latencyMs, error: 'Something answered, but it doesn\'t look like Ignite.' };
    }
    let user: ServerProbe['user'] = null;
    let keyRejected = false;
    if (key) {
      try {
        const me = await fetch(`${url}/api/auth/me`, { headers: authHeaders(key), signal: AbortSignal.timeout(5000) });
        const body = me.ok ? ((await me.json().catch(() => null)) as { user?: ServerProbe['user'] } | null) : null;
        user = body?.user ?? null;
        keyRejected = !user;
      } catch {
        // Reachability already confirmed — an /auth/me hiccup isn't worth failing the probe over.
      }
    }
    return { ok: true, url, latencyMs, authMode: config.mode, user, keyRejected };
  } catch (e) {
    const cause = e instanceof Error ? ((e.cause as { code?: string } | undefined)?.code ?? e.name) : String(e);
    const error = cause === 'ECONNREFUSED'
      ? 'Connection refused — nothing is listening there.'
      : cause === 'TimeoutError'
      ? 'Timed out after 5s.'
      : cause === 'ENOTFOUND'
      ? 'Host not found.'
      : `Unreachable (${cause}).`;
    return { ok: false, url, latencyMs: Date.now() - startedAt, error };
  }
}

/** The server answered, but wants credentials this request didn't carry (or rejected the ones it did). */
export class IgniteAuthError extends Error {
  constructor(path: string, readonly status: number, url?: string, serverMessage?: string, sentKey = false, unauthFlag = 'security.allowUnauthenticatedValidateAll') {
    const where = url ? `${url}${path}` : path;
    const why = status === 403
      ? `your API key isn't allowed to do this${serverMessage ? ` (${serverMessage})` : ''}`
      : sentKey
      ? 'the server didn\'t accept your API key and requires sign-in for this'
      : `the server requires sign-in for this — set an API key, or enable ${unauthFlag} on the server`;
    super(`${where} returned HTTP ${status}: ${why}.`);
    this.name = 'IgniteAuthError';
  }
}

/** Thrown when the Ignite server isn't reachable — same precondition hooks/pre-push already documents. */
export class IgniteUnreachableError extends Error {
  constructor(url: string, cause?: unknown) {
    super(`Ignite isn't reachable at ${url}. Start ignite-server, or change the server URL in the Ignite sidebar (or the "ignite.baseUrl" setting).`);
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
  // Probing "/" would 200 against *any* static file server on that port
  // (including a stray dev server left running from something else) since
  // it just serves the SPA fallback — /api/auth/config is a cheap,
  // unauthenticated, Ignite-specific route, so a response here actually
  // means Ignite is what's listening.
  const probeUrl = `${url}/api/auth/config`;
  for (let attempt = 1; attempt <= 3; attempt++) {
    const startedAt = Date.now();
    try {
      const res = await fetch(probeUrl, { method: 'GET', headers: authHeaders(), signal: AbortSignal.timeout(8000) });
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
  if (res.status === 401 || res.status === 403) {
    const body = (await res.json().catch(() => null)) as { error?: string; code?: string } | null;
    throw new IgniteAuthError('/api/pipeline/validate-all', res.status, url, body?.error, effectiveApiKey().source !== 'none');
  }
  if (res.status >= 500) {
    const text = await res.text().catch(() => '');
    throw new Error(`Ignite validate-all returned HTTP ${res.status}: ${text.slice(0, 300)}`);
  }
  // 400 is a normal "checks failed" response here (see routes/pipeline-validate.js),
  // not a transport error — its body still has the {ok:false, issues, phases} shape.
  return (await res.json()) as ValidateAllResult;
}

export interface UploadProgress {
  /** Upload/prepare stage before the pipeline starts. */
  stage?: string;
  /** A phase just changed state or logged — full log list so far for it. */
  phase?: StreamPhase;
}

/** Phase titles from GET /api/config (unauthenticated) — best-effort, numbers only on failure. */
async function fetchPhaseTitles(url: string): Promise<Map<number, string>> {
  try {
    const res = await fetch(`${url}/api/config`, { headers: authHeaders(), signal: AbortSignal.timeout(5000) });
    const body = (await res.json()) as { phases?: { id: number; title: string }[] };
    return new Map((body.phases ?? []).map((p) => [p.id, p.title]));
  } catch {
    return new Map();
  }
}

/**
 * Scans `projectPath` on a server that can't see this machine's disk: uploads
 * the folder to POST /api/pipeline as a simulation (`dryRun` — never
 * provisions or pushes), follows the NDJSON event stream, answers the review
 * gate with whatever `.ignite/acknowledgments.md` already justifies, and
 * returns the same shape `validateAll` does. Works unauthenticated when the
 * server sets security.allowUnauthenticatedInteractiveDryRun.
 */
export async function uploadScan(
  projectPath: string,
  opts: ValidateAllOptions,
  onProgress: (p: UploadProgress) => void
): Promise<ValidateAllResult> {
  const url = baseUrl();
  onProgress({ stage: 'Collecting files…' });
  const files = await collectUploadFiles(projectPath);
  checkUploadLimits(files);
  const totalMb = files.reduce((n, f) => n + f.size, 0) / 1024 / 1024;

  onProgress({ stage: `Reading ${files.length} files (${totalMb.toFixed(1)} MB)…` });
  const form = new FormData();
  form.append('org', opts.org || 'local-validation');
  form.append('repo', opts.repo || 'local-project');
  form.append('dryRun', 'true');
  form.append('paths', JSON.stringify(files.map((f) => uploadPathFor(projectPath, f.rel))));
  for (const f of files) {
    form.append('files', new Blob([await fs.readFile(f.abs)]), f.rel.split('/').pop() ?? f.rel);
  }

  const titles = await fetchPhaseTitles(url);
  onProgress({ stage: `Uploading ${files.length} files (${totalMb.toFixed(1)} MB)…` });
  let res: Response;
  try {
    res = await fetch(`${url}/api/pipeline`, {
      method: 'POST',
      headers: authHeaders(),
      body: form,
      signal: AbortSignal.timeout(60 * 60 * 1000),
    });
  } catch (e) {
    if (await checkReachable()) {
      throw new Error(`Uploading to ${url}/api/pipeline failed (${e instanceof Error ? e.message : String(e)}), but Ignite is reachable — a proxy in front of it may be limiting request size or duration.`);
    }
    throw new IgniteUnreachableError(url, e);
  }
  if (res.status === 401 || res.status === 403) {
    const body = (await res.json().catch(() => null)) as { error?: string } | null;
    throw new IgniteAuthError('/api/pipeline', res.status, url, body?.error, effectiveApiKey().source !== 'none', 'security.allowUnauthenticatedInteractiveDryRun');
  }
  if (!res.ok || !res.body) {
    const text = await res.text().catch(() => '');
    throw new Error(`Ignite /api/pipeline returned HTTP ${res.status}: ${text.slice(0, 300)}`);
  }

  const run = new PipelineRunState(titles);
  const decoder = new TextDecoder();
  const reader = res.body.getReader();
  let rest = '';
  let reviewAnswered = false;
  for (;;) {
    const { value, done } = await reader.read();
    const split = splitNdjson(rest, done ? '\n' : decoder.decode(value, { stream: true }));
    rest = split.rest;
    for (const line of split.lines) {
      let event: PipelineEvent;
      try {
        event = JSON.parse(line) as PipelineEvent;
      } catch {
        continue;
      }
      run.apply(event);
      if ((event.type === 'log' || event.type === 'status') && typeof (event as { phase?: unknown }).phase === 'number') {
        onProgress({ phase: run.phase((event as { phase: number }).phase) });
      }
      if (event.type === 'review_required' && !reviewAnswered) {
        reviewAnswered = true;
        const overrides = overridesForReview(run.issues, opts.overrides ?? []);
        overrides.forEach((o) => run.submitted.add(o.issueId));
        onProgress({ stage: `Review gate: submitting ${overrides.length} justification(s) from acknowledgments.md…` });
        const decision = await fetch(`${url}/api/pipeline/${encodeURIComponent(run.jobId ?? '')}/review-decision`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...authHeaders() },
          body: JSON.stringify({ proceed: true, overrides }),
          signal: AbortSignal.timeout(60_000),
        }).catch((e) => {
          throw new Error(`Couldn't answer the review gate: ${e instanceof Error ? e.message : String(e)}`);
        });
        if (!decision.ok) {
          const body = (await decision.json().catch(() => null)) as { error?: string } | null;
          await reader.cancel().catch(() => undefined);
          throw new Error(`The server rejected the review decision (HTTP ${decision.status}${body?.error ? `: ${body.error}` : ''}).`);
        }
      }
    }
    if (done) break;
  }

  if (!run.done) throw new Error('The scan stream ended before the server reported a result — check the server logs.');
  let issues = run.finalIssues() as unknown as IgniteIssue[];
  const totalIssueCount = issues.length;
  if (opts.changedFiles) {
    const changed = new Set(opts.changedFiles);
    issues = issues.filter((i) => i.file && changed.has(i.file));
  }
  return {
    ok: run.done.ok,
    mode: 'upload',
    jobId: run.jobId,
    projectPath,
    error: run.done.error,
    failedPhase: run.done.phase ?? null,
    issues,
    phases: run.sortedPhases(),
    ...(opts.changedFiles ? { totalIssueCount, filteredByChangedFiles: true } : {}),
  };
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
  if (res.status === 401 || res.status === 403) throw new IgniteAuthError('/api/tools/status', res.status);
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

/**
 * Triggers the org daily findings report on the server (`POST /api/reports/daily/run`) —
 * email / Sentinel webhook / Azure Blob, per `channels` (omitted = whatever the server has configured).
 */
export function runDailyReport(options: DailyReportOptions): Promise<DailyReportResult> {
  const body: Record<string, unknown> = { dryRun: options.dryRun ?? false, channels: options.channels ?? [] };
  if (options.org) body.org = options.org;
  if (options.webhookUrl) body.webhookUrl = options.webhookUrl;
  if (options.to) body.to = options.to;
  // Each channel is a network call (and Azure Blob may render a PDF first) — allow a few minutes.
  return postJson<DailyReportResult>('/api/reports/daily/run', body, 5 * 60 * 1000);
}

/** The org's daily report rendered as a PDF by the server's headless Chrome (`GET /api/reports/daily/pdf`). */
export async function downloadDailyReportPdf(org: string): Promise<Uint8Array> {
  const url = baseUrl();
  let res: Response;
  try {
    res = await fetch(`${url}/api/reports/daily/pdf?org=${encodeURIComponent(org)}`, { headers: authHeaders(), signal: AbortSignal.timeout(3 * 60 * 1000) });
  } catch (e) {
    throw new IgniteUnreachableError(url, e);
  }
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    let detail = text.slice(0, 300);
    try { detail = (JSON.parse(text) as { error?: string }).error ?? detail; } catch { /* not JSON */ }
    throw new Error(`PDF export failed (HTTP ${res.status}): ${detail}`);
  }
  return new Uint8Array(await res.arrayBuffer());
}
