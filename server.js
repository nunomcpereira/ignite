/**
 * Ignite (onboarding gatekeeper) — backend server
 *
 * Pipeline: ZIP upload -> extraction to isolated staging dir -> structure audit
 * (.env* denial) -> secret regex scan -> AI governance audit -> git/gh shipping.
 * Progress is streamed to the client as NDJSON events over a single POST
 * response. Staging directories are force-removed in a `finally` block no
 * matter how the pipeline ends.
 */

// Test-only override (see test/helpers.js's withServerEnv) so the suite
// isn't at the mercy of whatever this developer's real .env happens to
// contain — dotenv only ever fills in vars that are still unset, so a test
// that deletes GITLEAKS_ENABLED (say) to assert on the *default* would
// otherwise have it silently re-populated from the real .env on every
// require(). Pointing at a nonexistent path is a deliberate, documented
// dotenv no-op (ENOENT), not an error.
require('dotenv').config({ path: process.env.DOTENV_PATH || require('path').join(__dirname, '.env') });

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const StreamZip = require('node-stream-zip');
const { execFile, spawn } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const fsp = require('fs/promises');
const os = require('os');
const path = require('path');
const { createDbStore } = require('./db-store');
const { createReviewDecisionStore } = require('./review-decisions-store');
const { createAuth, isValidEmail } = require('./auth');
const { loadConfig } = require('./config');
const {
  collectPhase4Issues, collectCodeqlIssues, collectLicenseIssues, collectDependencyVulnerabilityIssues, validateOverrides, scoreForIssue,
} = require('./override-engine');
const {
  SKIP_DIRS, SKIP_DIRS_REGEX, BINARY_EXTENSIONS, DOCKERFILE_NAME_RE, SECRET_SCAN_CODE_EXTS, looksBinary, buildSnippet, walkFiles, mapWithConcurrency, hashBuffer, relativeToRoot,
  isEnvTemplateFile, isGitignored, loadGitignorePatterns, gitignorePatternToRegex,
} = require('./lib/fs-utils');

/* ------------------------------------------------------------------ */
/* Configuration: config.json < environment variables                  */
/* ------------------------------------------------------------------ */

const CONFIG = loadConfig();

// package.json is the single source of truth for the version — surfaced in
// the UI (top-left, next to the logo) and via GET /api/config so it never
// drifts out of sync with what's actually installed/running.
const IGNITE_VERSION = require('./package.json').version;

const store = createDbStore(process.env.IGNITE_DB_PATH || path.join(__dirname, 'ignite.db'));
store.abortStaleRunningProjects();

// Expired-session cleanup used to run inline on every request (attachUser ->
// getSession); moved to a periodic sweep since a stale row is harmless until
// swept (both getSession call sites already check expires_at in JS).
store.sweepExpiredSessions();
setInterval(() => store.sweepExpiredSessions(), 10 * 60_000).unref();

const PORT = process.env.PORT || CONFIG.port;
const MAX_ZIP_BYTES = 1024 * 1024 * 1024; // 1 GB upload cap
const MAX_EXTRACTED_BYTES = 4 * 1024 * 1024 * 1024; // zip-bomb guard
const MAX_SCAN_FILE_BYTES = 5 * 1024 * 1024; // skip huge files in text scans

const app = express();

// Security headers (OWASP A05 - Security Misconfiguration). CSP allows
// 'unsafe-inline' script/style because public/index.html is a single-file
// app with inline <script>/<style> blocks and no build step to add nonces -
// tightening this needs a frontend refactor, tracked as follow-up work, not
// silently skipped. crossOriginEmbedderPolicy is disabled because it would
// block the classic (non-CORS) <script src="https://cdn.tailwindcss.com">
// tag the UI depends on.
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", 'https://cdn.tailwindcss.com'],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

// Coarse global rate limit on the API surface (OWASP A05/A04 - unbounded
// request volume). Deliberately loose - narrower per-route limits already
// exist where it matters more (auth.js's login/register limiters); this is
// a backstop against a client hammering any /api endpoint, not a
// replacement for those.
app.use('/api', rateLimit({
  windowMs: 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
}));

app.use(express.json({ limit: '1mb' }));

// Onboarded-projects history annotates *how* each run was kicked off — the
// browser UI, a direct API call (validate-all/onboard hit straight from
// curl/CI, bypassing MCP), or MCP (mcp-server.js's proxyToIgnite sets this
// header on every call it makes). Anyone can technically send this header
// directly, same as any other client-supplied metadata — it's an audit
// label for the onboarded-projects list, not a trust/security boundary.
function resolveRequestSource(req, fallback) {
  return req.get('X-Ignite-Client') === 'mcp' ? 'mcp' : fallback;
}

const auth = createAuth(store, CONFIG.auth, CONFIG.github);
app.use(auth.attachUser);
app.use(auth.router);

app.use(express.static(path.join(__dirname, 'public')));

const reviewDecisions = createReviewDecisionStore();

// jobId -> { org, repo, projectId, allIssues } for the interactive SSE
// pipeline, so its flagged-issues list can be viewed live at any point
// during the run, not only at the final review gate. Entries are removed
// once the run ends; after that the same data lives in the `issues` table.
const runningRuns = new Map();

// projectId -> { org, repo, sourceBackupDir } — the immutable, validated
// source snapshot kept around after a successful simulation (dryRun) so an
// "Effectivate" action can provision/push it later without re-running the
// whole pipeline. Cleared once effectivated, or on server restart (tmpdir).
const pendingEffectivations = new Map();
const EFFECTIVATION_TTL_MS = 24 * 60 * 60 * 1000;

function cleanupExpiredEffectivations() {
  const now = Date.now();
  for (const [projectId, entry] of pendingEffectivations) {
    if (now - entry.createdAt > EFFECTIVATION_TTL_MS) {
      fsp.rm(entry.sourceBackupDir, { recursive: true, force: true }).catch(() => {});
      pendingEffectivations.delete(projectId);
    }
  }
}

/* Overriding a flagged guideline must be attributable to a real person for
   the audit log — either the logged-in session (standalone or OIDC), or,
   when auth isn't enforced globally, an explicit actor identity on the
   request body. Returns null (caller responds 401) if neither is present. */
function resolveActor(req) {
  if (req.user) return { email: req.user.email, name: req.user.name || req.user.email };
  const email = String(req.body?.actor?.email || '').trim().toLowerCase();
  const name = String(req.body?.actor?.name || '').trim();
  if (!isValidEmail(email)) return null;
  return { email, name: name || email };
}

const upload = multer({
  dest: path.join(os.tmpdir(), 'gatekeeper-uploads'),
  limits: { fileSize: MAX_ZIP_BYTES, files: 100000 },
});

/* ------------------------------------------------------------------ */
/* Scan configuration                                                  */
/* ------------------------------------------------------------------ */

/* Local LLM deep-scan (llama.cpp / OpenAI-compatible API) */
function parseTrustedLlmOrigins(raw, fallbackOrigin) {
  const origins = new Set([fallbackOrigin]);
  for (const item of String(raw || '').split(',')) {
    const value = item.trim();
    if (!value) continue;
    try {
      const u = new URL(value);
      origins.add(u.origin);
    } catch {
      // Ignore malformed trusted-origin entries.
    }
  }
  return origins;
}

function resolveTrustedLlmScanUrl(rawUrl, trustedOrigins) {
  const candidate = String(rawUrl || '').trim();
  const parsed = new URL(candidate);
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error(`LLM_SCAN_URL protocol must be http/https: ${candidate}`);
  }
  if (parsed.username || parsed.password) {
    throw new Error('LLM_SCAN_URL must not include credentials.');
  }
  if (!trustedOrigins.has(parsed.origin)) {
    throw new Error(
      `LLM_SCAN_URL origin is not trusted: ${parsed.origin}. Allowed origins: ${Array.from(trustedOrigins).join(', ')}`
    );
  }

  // Enforce TLS for remote endpoints; allow plain HTTP only for loopback/local development.
  const isLoopback = ['localhost', '127.0.0.1', '::1'].includes(parsed.hostname);
  if (parsed.protocol !== 'https:' && !isLoopback) {
    throw new Error(`LLM_SCAN_URL must use https for non-loopback hosts: ${parsed.origin}`);
  }
  return parsed.origin;
}

const LLM_SCAN_FALLBACK_URL = String(CONFIG.llm.url || 'http://localhost:8050');
const LLM_SCAN_FALLBACK_ORIGIN = new URL(LLM_SCAN_FALLBACK_URL).origin;
const TRUSTED_LLM_ORIGINS = Object.freeze(parseTrustedLlmOrigins(
  process.env.LLM_SCAN_TRUSTED_ORIGINS,
  LLM_SCAN_FALLBACK_ORIGIN
));
const LLM_SCAN_URL = resolveTrustedLlmScanUrl(
  process.env.LLM_SCAN_URL || CONFIG.llm.url,
  TRUSTED_LLM_ORIGINS
);
const LLM_SCAN_MODEL = process.env.LLM_SCAN_MODEL || CONFIG.llm.model;
const LLM_SCAN_MODE = process.env.LLM_SCAN_MODE || CONFIG.llm.mode; // 'warn' | 'block'
const LLM_DEEP_SCAN_ENABLED = process.env.LLM_DEEP_SCAN_ENABLED !== undefined
  ? String(process.env.LLM_DEEP_SCAN_ENABLED) === 'true'
  : CONFIG.llm.deepScanEnabled !== false;
const LLM_ADVISORY_LEVEL = ['warning', 'info'].includes(String(process.env.LLM_ADVISORY_LEVEL || '').toLowerCase())
  ? String(process.env.LLM_ADVISORY_LEVEL).toLowerCase()
  : 'info';
function parsePositiveInt(raw, fallback, { min = 1, max = Number.MAX_SAFE_INTEGER } = {}) {
  const parsed = Number.parseInt(String(raw), 10);
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) return fallback;
  return parsed;
}
const LLM_MAX_FILES = parsePositiveInt(
  process.env.LLM_MAX_FILES ?? CONFIG.llm.maxFiles,
  40,
  { min: 1, max: 1000 }
);
// Per-request source budget. Smaller chunks mean more requests but each one
// completes faster and is less likely to stall/timeout on a local CPU-bound
// llama.cpp server, where prompt-processing time grows with context size.
const LLM_CHUNK_CHARS = parsePositiveInt(
  process.env.LLM_CHUNK_CHARS ?? CONFIG.llm.chunkChars,
  10_000,
  { min: 1000, max: 100_000 }
);
// Which backend the deep-scan/insight/explain calls talk to. 'local' keeps
// the existing llama.cpp-compatible server at LLM_SCAN_URL; 'openai' routes
// the same requests to the OpenAI (or OpenAI-compatible) Chat Completions
// API instead — useful when no local model is available or a stronger
// hosted model is wanted. Same request/response shape either way.
const LLM_PROVIDER = ['local', 'openai'].includes(String(process.env.LLM_PROVIDER || CONFIG.llm.provider || '').toLowerCase())
  ? String(process.env.LLM_PROVIDER || CONFIG.llm.provider).toLowerCase()
  : 'local';
const OPENAI_API_KEY =
  process.env.OPENAI_API_KEY || CONFIG.llm.openai?.apiKey || '';
const OPENAI_BASE_URL = String(process.env.OPENAI_BASE_URL || CONFIG.llm.openai?.baseUrl || 'https://api.openai.com/v1').replace(/\/+$/, '');
const OPENAI_MODEL = process.env.OPENAI_MODEL || CONFIG.llm.openai?.model || 'gpt-4o-mini';
if (LLM_PROVIDER === 'openai' && !/^https:\/\//i.test(OPENAI_BASE_URL) && !/^http:\/\/(localhost|127\.0\.0\.1)/i.test(OPENAI_BASE_URL)) {
  throw new Error(`OPENAI_BASE_URL must use https (got ${OPENAI_BASE_URL}).`);
}

const { createLlmClient } = require('./lib/llm-client');
const {
  llmTarget, traceLlmCall, llmChat, llmAvailable, llmAvailableCached, llmComplete,
} = createLlmClient({
  provider: LLM_PROVIDER,
  openai: { apiKey: OPENAI_API_KEY, baseUrl: OPENAI_BASE_URL, model: OPENAI_MODEL },
  scanUrl: LLM_SCAN_URL,
  scanModel: LLM_SCAN_MODEL,
});

const LLM_SOURCE_EXTS = Object.freeze(new Set([
  '.py', '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs', '.go', '.rb', '.php',
  '.java', '.cs', '.sh', '.yaml', '.yml', '.json', '.sql', '.tf',
])) ;

/* Optional gitleaks-powered secret scan (see CONFIG.security.gitleaks) */
const GITLEAKS_ENABLED = Boolean(CONFIG.security.gitleaks.enabled);
const GITLEAKS_BINARY = String(CONFIG.security.gitleaks.binary || 'gitleaks');
const GITLEAKS_CONFIG_PATH = String(CONFIG.security.gitleaks.configPath || '');

// Opt-in, project-declared regex patterns for secret VALUES known to be
// public by design (see config.js's security.secrets comment). Invalid
// entries are dropped with a startup warning rather than crashing config
// load over one bad regex.
const KNOWN_PUBLIC_KEY_PATTERNS = (CONFIG.security.secrets?.knownPublicKeyPatterns || [])
  .map((raw) => {
    try { return new RegExp(raw); } catch { console.error(`Ignoring invalid security.secrets.knownPublicKeyPatterns entry: ${raw}`); return null; }
  })
  .filter(Boolean);

// Opt-in, project-declared path excludes for the iac-security/
// container-image-cve categories only (see config.js's security.excludePaths
// comment for why it's scoped to just those two).
const SECURITY_EXCLUDE_PATTERNS = (CONFIG.security.excludePaths || []).map(gitignorePatternToRegex);
const PATH_EXCLUDABLE_CATEGORIES = new Set(['iac-security', 'container-image-cve']);
function isExcludedSecurityFinding(issue) {
  return PATH_EXCLUDABLE_CATEGORIES.has(issue.category)
    && SECURITY_EXCLUDE_PATTERNS.length > 0
    && isGitignored(SECURITY_EXCLUDE_PATTERNS, String(issue.file || ''));
}

/* Optional trivy-powered IaC/container misconfig scan (see CONFIG.security.trivy) */
const TRIVY_ENABLED = Boolean(CONFIG.security.trivy.enabled);
const TRIVY_BINARY = String(CONFIG.security.trivy.binary || 'trivy');

/* Optional trivy-powered built-image CVE scan (see CONFIG.security.trivyImage) — reuses TRIVY_BINARY above */
const TRIVY_IMAGE_ENABLED = Boolean(CONFIG.security.trivyImage.enabled);
const TRIVY_IMAGE_SEVERITY = String(CONFIG.security.trivyImage.severityThreshold || 'HIGH,CRITICAL');
const TRIVY_IMAGE_BUILD_TIMEOUT_MS = Number(CONFIG.security.trivyImage.buildTimeoutMs) || 8 * 60_000;

/* Optional checkov-powered supplemental IaC misconfig scan (see CONFIG.security.checkov) */
const CHECKOV_ENABLED = Boolean(CONFIG.security.checkov.enabled);
const CHECKOV_BINARY = String(CONFIG.security.checkov.binary || 'checkov');

/* Optional hadolint-powered supplemental Dockerfile lint (see CONFIG.security.hadolint) */
const HADOLINT_ENABLED = Boolean(CONFIG.security.hadolint.enabled);
const HADOLINT_BINARY = String(CONFIG.security.hadolint.binary || 'hadolint');

/* Optional syft-powered SBOM generation (see CONFIG.sbom.syft) */
const SYFT_ENABLED = Boolean(CONFIG.sbom.syft.enabled);
const SYFT_BINARY = String(CONFIG.sbom.syft.binary || 'syft');

/* Optional cosign-powered base-image signature verification (see CONFIG.security.cosign) */
const COSIGN_ENABLED = Boolean(CONFIG.security.cosign.enabled);
const COSIGN_BINARY = String(CONFIG.security.cosign.binary || 'cosign');
const COSIGN_IDENTITY_REGEXP = String(CONFIG.security.cosign.identityRegexp || '.*');
const COSIGN_ISSUER_REGEXP = String(CONFIG.security.cosign.issuerRegexp || '.*');
const COSIGN_CACHE_TTL_SECONDS = Number.isFinite(Number(CONFIG.security.cosign.cacheTtlSeconds)) ? Number(CONFIG.security.cosign.cacheTtlSeconds) : 3600;

/* Optional semgrep-powered semantic SAST scan (see CONFIG.security.semgrep) */
const SEMGREP_ENABLED = Boolean(CONFIG.security.semgrep.enabled);
const SEMGREP_BINARY = String(CONFIG.security.semgrep.binary || 'semgrep');
const SEMGREP_CONFIG = String(CONFIG.security.semgrep.config || 'p/security-audit');

/* Optional bearer-powered PII/GDPR data-flow scan (see CONFIG.security.bearer) */
const BEARER_ENABLED = Boolean(CONFIG.security.bearer.enabled);
const BEARER_BINARY = String(CONFIG.security.bearer.binary || 'bearer');

/* Optional GuardDog-powered malicious-dependency heuristic scan (see CONFIG.security.guarddog) */
const GUARDDOG_ENABLED = Boolean(CONFIG.security.guarddog.enabled);
const GUARDDOG_BINARY = String(CONFIG.security.guarddog.binary || 'guarddog');

/* Optional picklescan-powered malicious ML model artifact scan (see CONFIG.security.picklescan) */
const PICKLESCAN_ENABLED = Boolean(CONFIG.security.picklescan.enabled);
const PICKLESCAN_BINARY = String(CONFIG.security.picklescan.binary || 'picklescan');
const PICKLESCAN_EXTENSIONS = Array.isArray(CONFIG.security.picklescan.extensions) ? CONFIG.security.picklescan.extensions : [];

/* Optional AI package-hallucination / slopsquat detection — built-in, no external binary (see CONFIG.security.packageHallucination) */
const PACKAGE_HALLUCINATION_ENABLED = Boolean(CONFIG.security.packageHallucination.enabled);

/* Optional CodeQL-powered cross-file static analysis (see CONFIG.security.codeql) — deep-scan only, never the fast pipeline */
const CODEQL_ENABLED = Boolean(CONFIG.security.codeql.enabled);
const CODEQL_BINARY = String(CONFIG.security.codeql.binary || 'codeql');
const CODEQL_LANGUAGES = Array.isArray(CONFIG.security.codeql.languages) ? CONFIG.security.codeql.languages : ['javascript', 'python', 'java', 'go'];
const CODEQL_QUERY_SUITES = CONFIG.security.codeql.querySuites || {};
const CODEQL_THREADS = Number(CONFIG.security.codeql.threads) || 0;
const CODEQL_RAM_MB = Number(CONFIG.security.codeql.ramMB) || 0;
const CODEQL_TIMEOUT_MS = Number(CONFIG.security.codeql.timeoutMs) || (20 * 60_000);

/* Optional Compliance & Feature Posture Engine — shares SEMGREP_BINARY (see CONFIG.compliance.posture) */
const POSTURE_ENABLED = Boolean(CONFIG.compliance.posture.enabled);
const POSTURE_RULESET = String(CONFIG.compliance.posture.ruleset || path.join(__dirname, 'ignite-posture-rules.yaml'));

/* Optional EU AI Act document-presence scan (see CONFIG.compliance.euAiActDocuments) */
const EU_AI_ACT_DOCS_ENABLED = Boolean(CONFIG.compliance.euAiActDocuments.enabled);
/* Whether EU AI Act signals (posture + doc-presence) surface as issues vs. advisory-only reports (see CONFIG.compliance.euAiAct) */
const EU_AI_ACT_REPORT_AS_FINDINGS = Boolean(CONFIG.compliance.euAiAct.reportAsFindings);

/* Optional jscpd-powered code-duplication scan (see CONFIG.metrics.jscpd) */
const JSCPD_ENABLED = Boolean(CONFIG.metrics.jscpd.enabled);
const JSCPD_BINARY = String(CONFIG.metrics.jscpd.binary || 'jscpd');
// jscpd's own defaults (5 lines / 50 tokens) flag trivial boilerplate repetition
// as findings; raised so only genuinely substantial duplicate blocks surface.
const JSCPD_MIN_LINES = Number(CONFIG.metrics.jscpd.minLines) || 15;
const JSCPD_MIN_TOKENS = Number(CONFIG.metrics.jscpd.minTokens) || 150;
const JSCPD_IGNORE_PATTERNS = Array.isArray(CONFIG.metrics.jscpd.ignorePatterns) ? CONFIG.metrics.jscpd.ignorePatterns : [];

/* Optional gocloc-powered LOC metrics (see CONFIG.metrics.gocloc) */
const GOCLOC_ENABLED = Boolean(CONFIG.metrics.gocloc.enabled);
const GOCLOC_BINARY = String(CONFIG.metrics.gocloc.binary || 'gocloc');

/* Built-in file-size ("low encapsulation") check (see CONFIG.metrics.fileSize) */
const FILE_SIZE_ENABLED = Boolean(CONFIG.metrics.fileSize.enabled);
const FILE_SIZE_MAX_LINES = Number(CONFIG.metrics.fileSize.maxLines) || 1000;

/* Optional spectral-powered API schema lint (see CONFIG.api.spectral) */
const SPECTRAL_ENABLED = Boolean(CONFIG.api.spectral.enabled);
const SPECTRAL_BINARY = String(CONFIG.api.spectral.binary || 'spectral');

/* Optional oasdiff-powered API breaking-change / shadow-endpoint scan (see CONFIG.api.oasdiff) */
const OASDIFF_ENABLED = Boolean(CONFIG.api.oasdiff.enabled);
const OASDIFF_BINARY = String(CONFIG.api.oasdiff.binary || 'oasdiff');

/* Built-in codebase-intelligence checks (see CONFIG.codeIntelligence / CONFIG.architecture) — no external tool for any of these */
const DEAD_CODE_ENABLED = Boolean(CONFIG.codeIntelligence.deadCode.enabled);
const HEALTH_ENABLED = Boolean(CONFIG.codeIntelligence.health.enabled);
const HEALTH_CYCLOMATIC_WARN = Number(CONFIG.codeIntelligence.health.cyclomaticWarnThreshold) || 20;
const HEALTH_DENSITY_WARN = Number(CONFIG.codeIntelligence.health.complexityDensityWarnThreshold) || 0.3;
const HEALTH_MI_WARN = Number(CONFIG.codeIntelligence.health.maintainabilityWarnThreshold) || 40;
const HEALTH_TOP_HOTSPOTS = Number(CONFIG.codeIntelligence.health.topHotspots) || 10;
const CSS_DEAD_CODE_ENABLED = Boolean(CONFIG.codeIntelligence.cssDeadCode.enabled);
const BOUNDARIES_ENABLED = Boolean(CONFIG.architecture.boundaries.enabled);
const BOUNDARIES_PRESET = String(CONFIG.architecture.boundaries.preset || '');
const BOUNDARIES_ZONES = Array.isArray(CONFIG.architecture.boundaries.zones) ? CONFIG.architecture.boundaries.zones : [];

// See lib/tool-runner.js — a factory, not a bare require, so the resolved
// binary paths above are threaded in explicitly rather than the module
// re-deriving them from CONFIG itself (keeps CONFIG-derived state living
// only in server.js, which is what test/helpers.js's per-test re-require
// cycle depends on).
const { createToolRunner } = require('./lib/tool-runner');
const {
  ALLOWED_COMMANDS, runTool, runToolStreaming, extractFailureLines,
  sanitizeCliArg, sanitizeCommand, sanitizeCliArgs, sanitizeCwd,
  sanitizeAbsoluteProjectPath, sanitizeEnv, sanitizeUploadRelativePath,
} = createToolRunner({
  gitleaks: GITLEAKS_BINARY, trivy: TRIVY_BINARY, checkov: CHECKOV_BINARY, hadolint: HADOLINT_BINARY,
  syft: SYFT_BINARY, cosign: COSIGN_BINARY, semgrep: SEMGREP_BINARY, bearer: BEARER_BINARY,
  guarddog: GUARDDOG_BINARY, jscpd: JSCPD_BINARY, gocloc: GOCLOC_BINARY, spectral: SPECTRAL_BINARY,
  codeql: CODEQL_BINARY, picklescan: PICKLESCAN_BINARY, oasdiff: OASDIFF_BINARY,
});
const SPECTRAL_RULESET = String(CONFIG.api.spectral.ruleset || path.join(__dirname, 'spectral-default-ruleset.yaml'));

const GITHUB_NAME_REGEX = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/; // org login rules
const REPO_NAME_REGEX = /^[A-Za-z0-9._-]{1,100}$/;

/**
 * Resolves a relative path against a root and throws if it escapes that
 * root (zip-slip-style traversal) — shared by archive extraction and the
 * Ignite Studio file read/write endpoints, which both accept a
 * caller-supplied relative path.
 */
function resolveWithinRoot(root, relPath) {
  const entryPath = String(relPath || '').replace(/\\/g, '/');
  if (!entryPath || entryPath.includes('\0')) {
    throw new Error('Invalid path.');
  }
  const target = path.resolve(root, entryPath);
  if (target !== root && !target.startsWith(root + path.sep)) {
    throw new Error(`Blocked path-traversal: ${entryPath}`);
  }
  return target;
}

/**
 * Safe ZIP extraction: rejects entries that escape the staging root
 * (zip-slip), skips symlink entries, and enforces a total-size cap.
 */
async function extractZip(zipPath, destDir, log) {
  const zip = new StreamZip.async({ file: zipPath });
  let totalBytes = 0;
  let fileCount = 0;

  try {
    const entries = await zip.entries();
    for (const entry of Object.values(entries)) {
      if (entry.isDirectory) continue;

      const entryPath = String(entry.name || '').replace(/\\/g, '/');
      if (!entryPath || entryPath.includes('\0')) {
        throw new Error('Archive contains an invalid entry path.');
      }

      // Zip-slip guard: resolved target must stay inside destDir.
      const target = resolveWithinRoot(destDir, entryPath);

      // Skip symlink entries (unix mode stored in high bits of external attrs).
      const unixMode = (Number(entry.attr || 0) >>> 16) & 0xffff;
      if ((unixMode & 0o170000) === 0o120000) {
        log(`Skipping symlink entry: ${entryPath}`);
        continue;
      }

      // The pre-check below on entry.size (the archive's own declared,
      // forgeable metadata) is a fast-path only - the enforced cap is the
      // running total of bytes actually streamed out, checked per chunk,
      // so a crafted archive that understates its own entry sizes can't
      // bypass the guard by lying about them.
      if (totalBytes + Number(entry.size || 0) > MAX_EXTRACTED_BYTES) {
        throw new Error('Archive exceeds maximum extracted size (possible zip bomb). Aborting.');
      }

      await fsp.mkdir(path.dirname(target), { recursive: true });
      const source = await zip.stream(entry.name);
      await new Promise((resolve, reject) => {
        const sink = fs.createWriteStream(target, { mode: 0o600 });
        let bailed = false;
        source.on('data', (chunk) => {
          if (bailed) return;
          totalBytes += chunk.length;
          if (totalBytes > MAX_EXTRACTED_BYTES) {
            bailed = true;
            source.destroy();
            sink.destroy();
            reject(new Error('Archive exceeds maximum extracted size (possible zip bomb). Aborting.'));
          }
        });
        source.on('error', (err) => { if (!bailed) reject(err); });
        sink.on('error', (err) => { if (!bailed) reject(err); });
        sink.on('finish', () => { if (!bailed) resolve(); });
        source.pipe(sink);
      });
      fileCount++;
    }
  } finally {
    await zip.close().catch(() => {});
  }

  return { fileCount, totalBytes };
}

/**
 * If the archive contains a single top-level folder (the common
 * "project-folder.zip" layout), descend into it so scans and git run at the
 * real project root.
 */
async function resolveProjectRoot(stagingDir) {
  const entries = (await fsp.readdir(stagingDir, { withFileTypes: true })).filter(
    (e) => e.name !== '__MACOSX' && e.name !== '.DS_Store'
  );
  if (entries.length === 1 && entries[0].isDirectory()) {
    return path.join(stagingDir, entries[0].name);
  }
  return stagingDir;
}

/**
 * Direct folder upload: move multer temp files into the staging dir at their
 * client-provided relative paths. Same guards as ZIP extraction: paths must
 * resolve inside the staging root, and total size is capped.
 */
async function stageDirectoryUpload(files, relPaths, destDir, log) {
  if (files.length !== relPaths.length) {
    throw new Error('Folder upload malformed: file/path count mismatch.');
  }
  let totalBytes = 0;
  for (let i = 0; i < files.length; i++) {
    const rel = sanitizeUploadRelativePath(relPaths[i]);

    const target = path.resolve(destDir, rel);
    if (target !== destDir && !target.startsWith(destDir + path.sep)) {
      throw new Error(`Blocked path-traversal entry in folder upload: ${rel}`);
    }

    totalBytes += files[i].size;
    if (totalBytes > MAX_EXTRACTED_BYTES) {
      throw new Error('Folder upload exceeds maximum staged size. Aborting.');
    }

    await fsp.mkdir(path.dirname(target), { recursive: true });
    await fsp.rename(files[i].path, target).catch(async (err) => {
      if (err.code !== 'EXDEV') throw err; // cross-device: fall back to copy
      await fsp.copyFile(files[i].path, target);
      await fsp.rm(files[i].path, { force: true });
    });
  }
  return { fileCount: files.length, totalBytes };
}

async function stageExistingProject(sourceDir, destDir, log) {
  const safeSource = sanitizeAbsoluteProjectPath(sourceDir);
  const stat = await fsp.stat(safeSource).catch(() => null);
  if (!stat || !stat.isDirectory()) {
    throw new Error(`projectPath does not exist or is not a directory: ${safeSource}`);
  }

  await fsp.mkdir(destDir, { recursive: true });

  let totalBytes = 0;
  let fileCount = 0;
  for await (const file of walkFiles(safeSource)) {
    const rel = path.relative(safeSource, file);
    const target = path.resolve(destDir, rel);
    if (target !== destDir && !target.startsWith(destDir + path.sep)) {
      throw new Error(`Blocked path traversal while staging project file: ${rel}`);
    }
    const fileStat = await fsp.stat(file);
    totalBytes += fileStat.size;
    if (totalBytes > MAX_EXTRACTED_BYTES) {
      throw new Error('Project exceeds maximum staged size. Aborting validation.');
    }
    await fsp.mkdir(path.dirname(target), { recursive: true });
    await fsp.copyFile(file, target);
    fileCount++;
  }

  // walkFiles deliberately skips .git (it's in SKIP_DIRS) during the
  // per-file copy above, so a staged local-path project (the pre-push
  // hook's real usage: projectPath is `git rev-parse --show-toplevel`,
  // a genuine working repo) would otherwise lose its entire git history —
  // and with it, checkPiiDataFlow's ability to use bearer's `--diff` mode
  // (resolveBearerDiffBase needs a real origin/HEAD-tracked ancestor commit
  // physically present in the scanned directory; bearer's --diff literally
  // `git switch`es between commits inside the directory it's told to scan).
  // Copied as a best-effort extra, not size-capped against
  // MAX_EXTRACTED_BYTES like real project files above — .git isn't part of
  // what's being reviewed/pushed, just auxiliary metadata that makes the
  // incremental PII scan possible. Any failure here (no .git, permissions,
  // whatever) just means checkPiiDataFlow falls back to its existing
  // full-scan behavior — never blocks staging.
  try {
    const sourceGitDir = path.join(safeSource, '.git');
    if ((await fsp.stat(sourceGitDir).catch(() => null))?.isDirectory()) {
      await fsp.cp(sourceGitDir, path.join(destDir, '.git'), { recursive: true });
    }
  } catch (e) {
    log(`⚠ Could not copy .git history into the staging dir (non-blocking, incremental PII scanning will fall back to a full scan): ${e.message}`);
  }

  log(`Staged existing project: ${fileCount} files (${(totalBytes / 1024).toFixed(1)} KB).`);
  return { fileCount, totalBytes };
}

async function cloneDirectoryWithoutSymlinks(sourceDir, destDir) {
  const src = path.resolve(sourceDir);
  const dst = path.resolve(destDir);
  await fsp.mkdir(dst, { recursive: true });

  const stack = [{ src, dst }];
  while (stack.length > 0) {
    const current = stack.pop();
    const entries = await fsp.readdir(current.src, { withFileTypes: true });
    for (const entry of entries) {
      const childSrc = path.join(current.src, entry.name);
      const childDst = path.join(current.dst, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        await fsp.mkdir(childDst, { recursive: true });
        stack.push({ src: childSrc, dst: childDst });
      } else if (entry.isFile()) {
        await fsp.mkdir(path.dirname(childDst), { recursive: true });
        await fsp.copyFile(childSrc, childDst);
      }
    }
  }
}

/* ------------------------------------------------------------------ */
/* Checks                                                              */
/* ------------------------------------------------------------------ */

const { createFileScanCache } = require('./lib/file-scan-cache');
const { loadFileScanCache, saveFileScanCache } = createFileScanCache(store);

/**
 * Flags raw .env files in the uploaded project. Returns `blocking` (real env
 * files that must be removed before shipping) separately from `ignored`
 * (env files that are also listed in the project's own .gitignore — since
 * they'd never be committed/pushed by this same pipeline, they're surfaced
 * as an informational note instead of failing the phase).
 */
async function checkEnvFiles(root) {
  const gitignorePatterns = await loadGitignorePatterns(root);

  const blocking = [];
  const ignored = [];
  for await (const file of walkFiles(root)) {
    const base = path.basename(file);
    if (base !== '.env' && !base.startsWith('.env.')) continue;
    if (isEnvTemplateFile(base)) continue;
    const rel = path.relative(root, file);
    if (gitignorePatterns.length > 0 && isGitignored(gitignorePatterns, rel)) {
      ignored.push(rel);
    } else {
      blocking.push(rel);
    }
  }
  return { blocking, ignored };
}

// GitHub recognizes CODEOWNERS in exactly these three locations (root,
// .github/, docs/) and uses the first one found, in that order.
const CODEOWNERS_LOCATIONS = ['CODEOWNERS', '.github/CODEOWNERS', 'docs/CODEOWNERS'];
const EMAIL_RE = /[\w.+-]+@[\w-]+\.[\w.-]+/g;

// Advisory-only presence/contact check (never blocks onboarding): locates a
// CODEOWNERS file and extracts any email-address owners from it (@username
// entries aren't actionable for automated notification, so they're not
// collected here). Used both as a Phase 3 log line and, later, by the
// scheduled re-check to resolve who to notify on a failure.
async function checkCodeowners(root) {
  for (const rel of CODEOWNERS_LOCATIONS) {
    let content;
    try {
      content = await fsp.readFile(path.join(root, rel), 'utf8');
    } catch {
      continue;
    }
    const emails = [...new Set((content.match(EMAIL_RE) || []).map((e) => e.toLowerCase()))];
    return { found: true, path: rel, emails };
  }
  return { found: false, path: null, emails: [] };
}

// How many files' worth of stat+readFile are ever in flight at once for
// checkSecrets/checkAiGovernance — high enough to hide I/O latency behind
// concurrency, low enough not to blow past a reasonable open-fd count on
// a repo with thousands of files.
const FILE_SCAN_CONCURRENCY = 16;

const { createSecretsCheck } = require('./checks/secrets');
const {
  checkSecrets, runGitleaksScan, gitleaksTooling, SECRET_REGEX, isLikelySecretValue,
} = createSecretsCheck({
  runTool,
  fsUtils: {
    walkFiles, looksBinary, buildSnippet, mapWithConcurrency, hashBuffer,
    BINARY_EXTENSIONS, SECRET_SCAN_CODE_EXTS, isGitignored, loadGitignorePatterns,
  },
  fileScanCache: { loadFileScanCache, saveFileScanCache },
  config: {
    gitleaksEnabled: GITLEAKS_ENABLED, gitleaksConfigPath: GITLEAKS_CONFIG_PATH,
    maxScanFileBytes: MAX_SCAN_FILE_BYTES, concurrency: FILE_SCAN_CONCURRENCY,
    knownPublicKeyPatterns: KNOWN_PUBLIC_KEY_PATTERNS,
  },
});

// The org governance CI workflow's own raw output only ever names a file
// ("... matched in: ./server.js"), never a line — it's a `grep -l`-style
// report, not `grep -n`. Re-locate the actual line by re-scanning that file
// with the same secret pattern Phase 4's own scan uses, so the finding is
// still file:line-addressable (View code / Studio highlighting) instead of
// showing "unknown". Best-effort: any failure (file not found, no matching
// line) just leaves file/line null, same as before this existed.
async function resolveGovernanceCiLocation(root, failureLine) {
  const m = failureLine.match(/matched in:\s*(\S+)/i);
  if (!m) return { file: null, line: null, code: null };
  const relPath = m[1].replace(/^\.\//, '').replace(/[),.:;]+$/, '');
  try {
    const full = path.join(root, relPath);
    if (path.relative(root, full).startsWith('..')) return { file: null, line: null, code: null };
    const content = await fsp.readFile(full, 'utf8');
    const ext = path.extname(full).toLowerCase();
    const lines = content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const match = lines[i].match(SECRET_REGEX);
      if (match && isLikelySecretValue(match[2], ext)) {
        return { file: relPath, line: i + 1, code: buildSnippet(content, i + 1) };
      }
    }
    return { file: relPath, line: null, code: null };
  } catch {
    return { file: null, line: null, code: null };
  }
}

// `act`/the runner's own wrapper text around a failing job/step — "the job
// failed", "the container exited non-zero", "this scan step failed" — never
// carries file/line info of its own and only ever shows up alongside the
// more specific per-match lines (the ones resolveGovernanceCiLocation can
// usually place a file on). Once at least one line in the run resolved to a
// real file, these add nothing but noise; filterGovernanceCiFailureLines
// drops them — but only then, so a run where NOTHING resolved still shows
// something rather than going silent.
const GOVERNANCE_CI_BOILERPLATE_RE = /^Error: Job '.+' failed$|exitcode '\d+': failure$|^\[.+\]\s*❌?\s*Failure - .+\[[\d.]+m?s\]$/i;
function filterGovernanceCiFailureLines(locatedIssues) {
  const anyResolved = locatedIssues.some((i) => i.file);
  if (!anyResolved) return locatedIssues;
  return locatedIssues.filter((i) => i.file || !GOVERNANCE_CI_BOILERPLATE_RE.test(i.summary));
}

const { createAiGovernanceCheck } = require('./checks/ai-governance');
const { checkAiGovernance } = createAiGovernanceCheck({
  fsUtils: { walkFiles, looksBinary, buildSnippet, mapWithConcurrency, hashBuffer },
  fileScanCache: { loadFileScanCache, saveFileScanCache },
  config: { concurrency: FILE_SCAN_CONCURRENCY },
});

/* ------------------------------------------------------------------ */
/* Check 3: local LLM security deep-scan (optional, Ollama-compatible) */
/* ------------------------------------------------------------------ */

const { createLlmDeepScanCheck } = require('./checks/llm-deep-scan');
const { checkLlmDeepScan, validateLlmFinding } = createLlmDeepScanCheck({
  llmChat,
  traceLlmCall,
  parseSemver,
  compareSemver,
  fsUtils: { walkFiles, looksBinary, buildSnippet, hashBuffer, isGitignored, loadGitignorePatterns },
  fileScanCache: { loadFileScanCache, saveFileScanCache },
  config: {
    deepScanEnabled: LLM_DEEP_SCAN_ENABLED,
    provider: LLM_PROVIDER,
    openaiApiKey: OPENAI_API_KEY,
    openaiModel: OPENAI_MODEL,
    openaiBaseUrl: OPENAI_BASE_URL,
    scanUrl: LLM_SCAN_URL,
    scanModel: LLM_SCAN_MODEL,
    advisoryLevel: LLM_ADVISORY_LEVEL,
    maxFiles: LLM_MAX_FILES,
    chunkChars: LLM_CHUNK_CHARS,
    sourceExts: LLM_SOURCE_EXTS,
  },
});

/* ------------------------------------------------------------------ */
/* GitHub API access without requiring the `gh` CLI binary             */
/* ------------------------------------------------------------------ */

const { createGithubApi } = require('./lib/github-api');
const {
  isGhCliAvailable, resolveServerGithubToken, githubApiRequest, githubGraphqlRequest,
  ghApiWrite, ghApiGet, ghFetchFileRaw, ghListCommits, ghCreatePr, ghArmAutoMerge,
  ghWatchPrChecks, ghCreateIssue, ghCloneRepo, ghCommentOnPr,
} = createGithubApi({ runTool, runToolStreaming });

/* ------------------------------------------------------------------ */
/* Phase 4: run the repo's own GitHub Actions locally via `act`        */
/* ------------------------------------------------------------------ */

const ACT_EVENT = process.env.ACT_EVENT || CONFIG.governance.event;
const ACT_TIMEOUT_MIN = parseInt(process.env.ACT_TIMEOUT_MIN || String(CONFIG.governance.timeoutMinutes), 10);

/* Central org governance repo whose workflows gate every onboarded project.
   The orchestrator is fetched fresh each run and executed via act; the
   reusable sub-workflows it `uses:` are resolved from GitHub at run time. */
const GOVERNANCE_REPO = process.env.GOVERNANCE_REPO || CONFIG.governance.repo;
const GOVERNANCE_WORKFLOW = process.env.GOVERNANCE_WORKFLOW || CONFIG.governance.workflow;

/* Checks the workflow file's latest commit sha (a small `commits?path=...`
   lookup — no file content transferred) against the sha we fetched it under
   last time. A match means the file hasn't changed upstream, so the caller
   can reuse the cached raw content instead of re-fetching it. Any failure
   (rate limit, path never committed standalone, etc.) just means "fetch
   fresh" — this is a fast-path optimization, never a correctness gate. */
async function latestCommitSha(repo, filePath) {
  try {
    const commits = await ghListCommits(repo, filePath, resolveServerGithubToken());
    return commits[0]?.sha || null;
  } catch {
    return null;
  }
}

async function fetchWorkflowFileCached(repo, filePath, filename) {
  const sha = await latestCommitSha(repo, filePath);
  if (sha) {
    const cached = store.getWorkflowCache(repo, filename);
    if (cached && cached.commitSha === sha) {
      return { content: cached.content, cacheHit: true };
    }
  }
  const stdout = await ghFetchFileRaw(repo, filePath, resolveServerGithubToken());
  if (sha) store.saveWorkflowCache(repo, filename, sha, stdout);
  return { content: stdout, cacheHit: false };
}

async function fetchGovernanceWorkflow(wfDir, log) {
  log(`Fetching ${GOVERNANCE_WORKFLOW} from ${GOVERNANCE_REPO}@main...`);
  const { content: rawText, cacheHit } = await fetchWorkflowFileCached(
    GOVERNANCE_REPO, `.github/workflows/${GOVERNANCE_WORKFLOW}`, GOVERNANCE_WORKFLOW
  );
  if (cacheHit) log(`✓ ${GOVERNANCE_WORKFLOW} unchanged upstream — reused cached copy.`);
  await fsp.mkdir(wfDir, { recursive: true });
  const wfFile = path.join(wfDir, GOVERNANCE_WORKFLOW);
  const reusableMatches = [...rawText.matchAll(new RegExp(`uses:\\s*${GOVERNANCE_REPO}/\\.github/workflows/([A-Za-z0-9._-]+)@[^\\s]+`, 'g'))];

  let workflowText = normalizeWorkflowText(rawText);

  for (const match of reusableMatches) {
    const filename = match[1];
    if (!filename) continue;
    try {
      const { content: reusableText, cacheHit: reusableCacheHit } = await fetchWorkflowFileCached(
        GOVERNANCE_REPO, `.github/workflows/${filename}`, filename
      );

      const localReusablePath = path.join(wfDir, filename);
      await fsp.writeFile(localReusablePath, normalizeWorkflowText(reusableText));
      workflowText = workflowText.replace(
        new RegExp(`uses:\\s*${GOVERNANCE_REPO}/\\.github/workflows/${filename}@[^\\s]+`, 'g'),
        `uses: ./.github/workflows/${filename}`
      );
      log(`✓ Localized reusable workflow: ${filename}${reusableCacheHit ? ' (cached, unchanged)' : ''}`);
    } catch (e) {
      log(`⚠ Could not localize reusable workflow ${filename}: ${e.message}`);
    }
  }

  await fsp.writeFile(wfFile, workflowText);
  log(`✓ Central governance workflow cached (${workflowText.length} bytes).`);
  return wfFile;
}

function normalizeWorkflowText(text) {
  // Some governance workflows generate an ESM eslint.config.js in CommonJS repos.
  // Normalize to CommonJS for local `act` compatibility. Written to
  // eslint.config.cjs (not .js): Node picks CommonJS vs. ESM for a plain
  // .js file from the nearest package.json's "type" field, so a CommonJS
  // rewrite left in eslint.config.js still gets parsed as ESM — and fails
  // with "require is not defined in ES module scope" — on any target repo
  // that declares "type": "module" (observed for real onboarding
  // SolventAI). .cjs is unconditionally CommonJS regardless of "type",
  // and ESLint's flat-config loader looks for eslint.config.cjs
  // explicitly, so this works on both CommonJS and ESM repos.
  // The echo-destined-to-eslint.config.js patterns must run BEFORE the
  // generic content-only one below: they need to see the original ESM
  // `import ... export default` text intact so they can rewrite the
  // destination filename in the same match. Reversing the order lets the
  // generic replace consume the ESM text first, leaving nothing for these
  // to match — silently keeping the broken .js destination.
  //
  // Each rewritten config also gets a leading `{ ignores: [...] }` entry
  // (ESLint flat-config's global-ignore form) for docs-site/ and other
  // known non-Node subprojects this repo carries — a plain
  // security.configs.recommended has no JSX/TSX parser, so any subproject
  // source using JSX (e.g. docs-site's Docusaurus theme components) is a
  // hard parse error, not a suppressible warning; `--max-warnings` can't
  // help. This profile is meant to check the Node backend, not lint
  // every subproject's own toolchain.
  const IGNORED_SUBPROJECTS = ['docs-site/**'];
  const ignoresConfig = `{ ignores: ${JSON.stringify(IGNORED_SUBPROJECTS)} }`;
  return String(text)
    .replace(/echo\s+'import\s+security\s+from\s+"eslint-plugin-security";\s*export\s+default\s+\[\s*security\.configs\.recommended\s*\];'\s*>\s*eslint\.config\.js/g,
      `echo 'const security = require("eslint-plugin-security"); module.exports = [${ignoresConfig}, security.configs.recommended];' > eslint.config.cjs`)
    .replace(/echo\s+"import\s+security\s+from\s+'eslint-plugin-security';\s*export\s+default\s+\[\s*security\.configs\.recommended\s*\];"\s*>\s*eslint\.config\.js/g,
      `echo "const security = require(\\"eslint-plugin-security\\"); module.exports = [${ignoresConfig}, security.configs.recommended];" > eslint.config.cjs`)
    .replace(/import\s+security\s+from\s+["']eslint-plugin-security["'];?\s*export\s+default\s+\[\s*security\.configs\.recommended\s*\];?/g,
      `const security = require("eslint-plugin-security"); module.exports = [${ignoresConfig}, security.configs.recommended];`)
    .replace(/npx\s+eslint\s+\.\s+--max-warnings(?:\s+|=)0\b/g, 'npx eslint . --max-warnings 1000');
}

const { createIacSecurityCheck } = require('./checks/iac-security');
const {
  checkIacSecurity, checkIacSecurityFallback, runTrivyIacScan, runCheckovIacScan, runHadolintIacScan,
  trivyTooling, checkovTooling, hadolintTooling,
} = createIacSecurityCheck({
  runTool,
  fsUtils: { walkFiles, looksBinary, buildSnippet, DOCKERFILE_NAME_RE },
  config: { trivyEnabled: TRIVY_ENABLED, checkovEnabled: CHECKOV_ENABLED, hadolintEnabled: HADOLINT_ENABLED },
});

const { createContainerImageVulnerabilitiesCheck } = require('./checks/container-image-vulnerabilities');
const { checkContainerImageVulnerabilities, trivyImageTooling } = createContainerImageVulnerabilitiesCheck({
  runTool,
  runToolStreaming,
  fsUtils: { walkFiles, DOCKERFILE_NAME_RE },
  config: { enabled: TRIVY_IMAGE_ENABLED, severityThreshold: TRIVY_IMAGE_SEVERITY, buildTimeoutMs: TRIVY_IMAGE_BUILD_TIMEOUT_MS },
});

const { createProvenanceCheck } = require('./checks/provenance');
const { digestProjectTree, generateProvenance } = createProvenanceCheck({
  runTool,
  fsUtils: { walkFiles },
  igniteVersion: IGNITE_VERSION,
});

const { createImageProvenanceCheck } = require('./checks/image-provenance');
const { cosignTooling, discoverBaseImages, checkImageProvenance } = createImageProvenanceCheck({
  runTool,
  store,
  fsUtils: { walkFiles, looksBinary, buildSnippet, DOCKERFILE_NAME_RE },
  config: {
    enabled: COSIGN_ENABLED, identityRegexp: COSIGN_IDENTITY_REGEXP, issuerRegexp: COSIGN_ISSUER_REGEXP, cacheTtlSeconds: COSIGN_CACHE_TTL_SECONDS,
  },
});

const { createMaliciousDependenciesCheck } = require('./checks/malicious-dependencies');
const { checkMaliciousDependencies, guarddogTooling } = createMaliciousDependenciesCheck({
  runTool,
  store,
  fsUtils: { walkFiles, hashBuffer },
  config: { enabled: GUARDDOG_ENABLED },
});

const { createModelArtifactSecurityCheck } = require('./checks/model-artifact-security');
const { checkModelArtifactSecurity, picklescanTooling } = createModelArtifactSecurityCheck({
  runTool,
  fsUtils: { walkFiles, relativeToRoot },
  config: { enabled: PICKLESCAN_ENABLED, extensions: PICKLESCAN_EXTENSIONS },
});

const { createCodeqlCrossFileCheck } = require('./checks/codeql-cross-file');
const { checkCodeqlCrossFile, codeqlTooling, discoverCodeqlLanguages, runCustomCodeqlQuery } = createCodeqlCrossFileCheck({
  runTool,
  runToolStreaming,
  store,
  fsUtils: { walkFiles, hashBuffer, relativeToRoot, buildSnippet },
  config: {
    enabled: CODEQL_ENABLED, binary: CODEQL_BINARY, languages: CODEQL_LANGUAGES,
    querySuites: CODEQL_QUERY_SUITES, threads: CODEQL_THREADS, ramMB: CODEQL_RAM_MB, timeoutMs: CODEQL_TIMEOUT_MS,
  },
});

const { createSemanticSastCheck } = require('./checks/semantic-sast');
const { checkSemanticSast, semgrepTooling } = createSemanticSastCheck({
  runTool,
  fsUtils: { buildSnippet, relativeToRoot },
  config: { enabled: SEMGREP_ENABLED, binary: SEMGREP_BINARY, semgrepConfig: SEMGREP_CONFIG },
});

const { createPiiDataFlowCheck } = require('./checks/pii-dataflow');
const { checkPiiDataFlow, bearerTooling, ensureGitContextForBearer } = createPiiDataFlowCheck({
  runTool,
  fsUtils: { buildSnippet },
  config: { enabled: BEARER_ENABLED },
});

const { createCodeDuplicationCheck } = require('./checks/code-duplication');
const { checkCodeDuplication, jscpdTooling } = createCodeDuplicationCheck({
  runTool,
  fsUtils: { buildSnippet },
  config: {
    enabled: JSCPD_ENABLED, minLines: JSCPD_MIN_LINES, minTokens: JSCPD_MIN_TOKENS, ignorePatterns: JSCPD_IGNORE_PATTERNS,
  },
});

const { createFileEncapsulationCheck } = require('./checks/file-encapsulation');
const { checkFileEncapsulation } = createFileEncapsulationCheck({
  fsUtils: { walkFiles, looksBinary, buildSnippet, SECRET_SCAN_CODE_EXTS },
  config: { enabled: FILE_SIZE_ENABLED, maxLines: FILE_SIZE_MAX_LINES },
});

const { createLocMetricsCheck } = require('./checks/loc-metrics');
const { generateLocMetrics, goclocTooling } = createLocMetricsCheck({
  runTool,
  fsUtils: { relativeToRoot, SKIP_DIRS_REGEX },
  config: { enabled: GOCLOC_ENABLED },
});

const { createApiSchemaCheck } = require('./checks/api-schema');
const { checkApiSchemas, spectralTooling, discoverApiSchemaFiles } = createApiSchemaCheck({
  runTool,
  fsUtils: { walkFiles, looksBinary, buildSnippet, relativeToRoot },
  config: { enabled: SPECTRAL_ENABLED, ruleset: SPECTRAL_RULESET },
});

const { createApiSchemaDriftCheck } = require('./checks/api-schema-drift');
const { checkApiSchemaDrift, oasdiffTooling } = createApiSchemaDriftCheck({
  runTool,
  discoverApiSchemaFiles,
  config: { enabled: OASDIFF_ENABLED },
});

const { createFeaturePostureCheck } = require('./checks/feature-posture');
const { checkFeaturePosture, checkFeaturePostureFallback, POSTURE_CATEGORIES } = createFeaturePostureCheck({
  runTool,
  semgrepTooling,
  fsUtils: { walkFiles, looksBinary, buildSnippet, relativeToRoot, BINARY_EXTENSIONS },
  config: { enabled: POSTURE_ENABLED, ruleset: POSTURE_RULESET, maxScanFileBytes: MAX_SCAN_FILE_BYTES },
});

const { createComplianceDocumentsCheck } = require('./checks/compliance-documents');
const { checkComplianceDocuments, DOCUMENT_CATEGORIES } = createComplianceDocumentsCheck({
  fsUtils: { walkFiles, relativeToRoot },
  config: { enabled: EU_AI_ACT_DOCS_ENABLED },
});

// Built-in codebase-intelligence checks (dead code, complexity/health, CSS
// dead-class scan, architecture boundaries) — closes the fallow.tools gap
// set (see project memory). No external tool for any of these.
const { createDeadCodeCheck } = require('./checks/dead-code');
const { checkDeadCode } = createDeadCodeCheck({
  fsUtils: { walkFiles, looksBinary, buildSnippet },
  config: { enabled: DEAD_CODE_ENABLED },
});

const { createComplexityHealthCheck } = require('./checks/complexity-health');
const { checkComplexityHealth } = createComplexityHealthCheck({
  runTool,
  fsUtils: { walkFiles, looksBinary, buildSnippet },
  config: {
    enabled: HEALTH_ENABLED, cyclomaticWarnThreshold: HEALTH_CYCLOMATIC_WARN,
    complexityDensityWarnThreshold: HEALTH_DENSITY_WARN, maintainabilityWarnThreshold: HEALTH_MI_WARN,
    topHotspots: HEALTH_TOP_HOTSPOTS,
  },
});

const { createCssDeadCodeCheck } = require('./checks/css-dead-code');
const { checkCssDeadCode } = createCssDeadCodeCheck({
  fsUtils: { walkFiles, looksBinary, buildSnippet },
  config: { enabled: CSS_DEAD_CODE_ENABLED },
});

const { createBoundariesCheck } = require('./checks/boundaries');
const { checkBoundaries } = createBoundariesCheck({
  fsUtils: { walkFiles, looksBinary, buildSnippet },
  config: { enabled: BOUNDARIES_ENABLED, preset: BOUNDARIES_PRESET, zones: BOUNDARIES_ZONES },
});

// Runs Phase 4's 11 external-tool checks (secrets, AI-governance, LLM deep-
// scan, IaC, SBOM, image provenance, semantic SAST, PII/data-flow, code
// duplication, LOC metrics, API-schema lint, feature posture) concurrently
// instead of one after another. Every check only ever reads projectRoot and
// produces its own independent findings — nothing downstream depends on
// another check's result until they're all merged by collectPhase4Issues
// below — so this turns Phase 4's wall time from the sum of all 11
// runtimes into roughly the slowest single one (LLM deep-scan/semgrep/
// bearer are typically the long poles). Each check's log lines are
// buffered while it runs and flushed here in the original, stable
// Check-2..Check-11 order once every check has settled, so the streamed
// log still reads top-to-bottom the same way it did when checks ran
// sequentially — only the actual scanning happens in parallel.
//
// checkPiiDataFlow's one side effect on projectRoot (bootstrapping a
// throwaway git context for Bearer, see ensureGitContextForBearer) only
// ever adds files under .git/, which every other tool here already ignores
// by default, so running it alongside the rest is safe.
//
// Shared by all three pipeline entry points (validate-all, onboard, the
// interactive SSE pipeline) — they were each running an identical,
// independently-maintained copy of this block.
//
// CodeQL cross-file static analysis (checks/codeql-cross-file.js) runs as
// one more task in the same concurrent batch, unconditionally — measured
// for real (a full self-scan of Ignite's own codebase) to add roughly 3
// seconds of wall time on top of the rest of Phase 4, because its 34.8s
// cold database build finishes well inside Bearer's own ~67s tail; Phase
// 4's concurrency already hides it almost entirely. That's what makes it
// safe to run on every push, not just a separate opt-in "deep scan" path —
// there used to be one (routes/pipeline-deep-scan.js), removed once the
// measurement showed the split wasn't earning its complexity. Still fully
// toggleable via CONFIG.security.codeql.enabled (on by default) for
// environments where Bearer/Semgrep/GuardDog are disabled or fast enough
// that CodeQL's cost would actually show up.
// `fast: true` (the pre-push/CLI "lightning" mode) narrows the batch to the
// handful of checks that are inherently sub-second/local — secrets,
// AI-governance, file-encapsulation (all built-in, no external process) and
// semantic SAST (semgrep, still a real process spawn but the only one of
// the twenty-odd checks fast enough not to defeat the purpose of a
// pre-push hook). Every other task is skipped outright rather than run
// with a shorter timeout — collectPhase4Issues already treats every
// non-secrets/governance group as optional (`if (group) ...`), so leaving
// the rest of `byName` undefined below is exactly the same shape as "tool
// not installed", nothing further to special-case.
const FAST_MODE_TASKS = new Set(['secrets', 'governance', 'semanticSast', 'fileEncapsulation']);

async function runPhase4Checks(projectRoot, log, { org, repo, projectId, store, fast = false }) {
  const tasks = [
    {
      name: 'secrets',
      run: async (blog) => {
        blog('Check 2 — scanning text files for hardcoded credentials...');
        const secrets = await checkSecrets(projectRoot, blog, { org, repo });
        blog(`Scanned ${secrets.scanned} text files.`);
        if (secrets.findings.length > 0) {
          blog(`✗ ${secrets.findings.length} potential credential leak(s):`);
          secrets.findings.forEach((f) => blog(`    ✗ ${f.file}:${f.line} — hardcoded ${f.kind}`));
        } else {
          blog('✓ Check 2 passed — no credential leakage detected.');
        }
        return secrets;
      },
    },
    {
      name: 'governance',
      run: async (blog) => {
        blog('Check 4 — AI governance audit (.py/.js/.ts LangChain/LangGraph calls)...');
        const governance = await checkAiGovernance(projectRoot, { org, repo });
        blog(`Audited ${governance.scanned} source files.`);
        if (governance.findings.length > 0) {
          blog(`✗ ${governance.findings.length} ungoverned AI invocation(s) — missing recursion_limit:`);
          governance.findings.forEach((f) => blog(`    ✗ ${f.file}:${f.line} — ${f.snippet}`));
        } else {
          blog('✓ Check 4 passed — all AI invocations are governed.');
        }
        return governance;
      },
    },
    {
      name: 'llm',
      run: async (blog) => {
        blog(`Check 3 — local LLM code review (security, dependency, quality, encapsulation; mode: ${LLM_SCAN_MODE})...`);
        const llm = await checkLlmDeepScan(projectRoot, blog, { org, repo });
        if (!llm.available) {
          blog(`⚠ Deep-scan skipped: ${llm.reason}`);
        } else if (llm.findings.length === 0) {
          blog(`✓ Check 3 passed — LLM found no security/dependency errors or quality/encapsulation warnings in ${llm.scanned} files.`);
        } else {
          blog(`LLM reported ${llm.findings.length} finding(s):`);
          llm.findings.forEach((f) =>
            blog(`    ${f.level === 'error' ? '✗' : '⚠'} [${f.level}] [${f.category}] ${f.file}:${f.line} — ${f.issue}${f.recommendation ? ` | fix: ${f.recommendation}` : ''}`)
          );
        }
        return llm;
      },
    },
    {
      name: 'iac',
      run: async (blog) => {
        blog('Check 5 — IaC/container misconfiguration scan (Dockerfiles/Terraform/Kubernetes/Helm)...');
        const iac = await checkIacSecurity(projectRoot, blog);
        if (iac.findings.length > 0) {
          blog(`✗ ${iac.findings.length} IaC misconfiguration(s) [engine: ${iac.engine}]:`);
          iac.findings.forEach((f) => blog(`    ✗ [${f.severity}] ${f.file}:${f.line} — ${f.message || f.kind}`));
        } else {
          blog(`✓ Check 5 passed — no IaC misconfigurations detected [engine: ${iac.engine}].`);
        }
        return iac;
      },
    },
    {
      name: 'imageVulnerabilities',
      run: async (blog) => {
        blog('Check 13 — container image CVE scan (trivy image; off by default)...');
        const imageVulnerabilities = await checkContainerImageVulnerabilities(projectRoot, blog);
        if (imageVulnerabilities.findings.length > 0) {
          blog(`✗ ${imageVulnerabilities.findings.length} known CVE(s) in built image(s):`);
          imageVulnerabilities.findings.forEach((f) => blog(`    ${f.severity === 'critical' || f.severity === 'high' ? '✗' : '⚠'} [${f.severity}] ${f.file} — ${f.message}`));
        } else if (imageVulnerabilities.engine === 'trivy-image') {
          blog('✓ Check 13 passed — no known CVEs found in built image(s) (or no Dockerfile present).');
        } else {
          blog('✓ Check 13 skipped — trivyImage disabled or trivy/Docker not available.');
        }
        return imageVulnerabilities;
      },
    },
    {
      name: 'sbom',
      run: async (blog) => {
        blog('Generating SBOM...');
        const { engine: sbomEngine, sbom } = await generateSbom(projectRoot, blog);
        blog(`✓ SBOM generated [engine: ${sbomEngine}] — ${(sbom.components || []).length} component(s).`);
        if (projectId !== null) {
          const sbomBuffer = Buffer.from(JSON.stringify(sbom, null, 2));
          store.addUploadDocument(projectId, `sbom.${sbomEngine === 'syft' ? 'cyclonedx' : 'fallback'}.json`, 'application/json', sbomBuffer.length, sbomBuffer);
        }
        return { sbomEngine, sbom };
      },
    },
    {
      name: 'provenance',
      run: async (blog) => {
        blog('Recording build/commit provenance (unsigned — not a SLSA attestation)...');
        const provenance = await generateProvenance(projectRoot, blog, { org, repo });
        if (projectId !== null) {
          const provenanceBuffer = Buffer.from(JSON.stringify(provenance, null, 2));
          store.addUploadDocument(projectId, 'provenance.json', 'application/json', provenanceBuffer.length, provenanceBuffer);
        }
        return { provenance };
      },
    },
    {
      name: 'imageProvenance',
      run: async (blog) => {
        blog('Check 6 — base-image signature/provenance verification (cosign)...');
        const imageProvenance = await checkImageProvenance(projectRoot, blog);
        if (imageProvenance.findings.length > 0) {
          blog(`⚠ ${imageProvenance.findings.length} base image(s) without a verifiable Sigstore signature:`);
          imageProvenance.findings.forEach((f) => blog(`    ⚠ ${f.file}:${f.line} — ${f.message}`));
        } else if (imageProvenance.engine === 'cosign') {
          blog('✓ Check 6 passed — every referenced base image has a verifiable Sigstore signature (or none was referenced).');
        } else {
          blog('✓ Check 6 skipped — cosign disabled or not installed.');
        }
        return imageProvenance;
      },
    },
    {
      name: 'semanticSast',
      run: async (blog) => {
        blog(`Check 7 — semantic SAST (semgrep, config: ${SEMGREP_CONFIG})...`);
        const semanticSast = await checkSemanticSast(projectRoot, blog);
        if (semanticSast.findings.length > 0) {
          blog(`✗ ${semanticSast.findings.length} semantic SAST finding(s):`);
          semanticSast.findings.forEach((f) => blog(`    ${f.severity === 'error' ? '✗' : '⚠'} [${f.severity}] ${f.file}:${f.line} — ${f.message}`));
        } else if (semanticSast.engine === 'semgrep') {
          blog('✓ Check 7 passed — no semantic SAST findings.');
        } else if (semanticSast.engine === 'failed') {
          blog('⚠ Check 7 degraded — semgrep execution failed; no semantic SAST findings were produced.');
        } else {
          blog('✓ Check 7 skipped — semgrep disabled or not installed.');
        }
        return semanticSast;
      },
    },
    {
      name: 'piiDataFlow',
      run: async (blog) => {
        blog('Check 8 — PII/GDPR data-flow scan (bearer)...');
        const piiDataFlow = await checkPiiDataFlow(projectRoot, blog);
        if (piiDataFlow.findings.length > 0) {
          blog(`✗ ${piiDataFlow.findings.length} PII/data-flow finding(s):`);
          piiDataFlow.findings.forEach((f) => blog(`    ${f.severity === 'error' ? '✗' : '⚠'} [${f.severity}] ${f.file}:${f.line} — ${f.message}`));
        } else if (piiDataFlow.engine === 'bearer') {
          blog('✓ Check 8 passed — no PII/data-flow findings.');
        } else {
          blog('✓ Check 8 skipped — bearer disabled or not installed.');
        }
        return piiDataFlow;
      },
    },
    {
      name: 'duplication',
      run: async (blog) => {
        blog('Check 9 — code duplication scan (jscpd)...');
        const duplication = await checkCodeDuplication(projectRoot, blog);
        if (duplication.findings.length > 0) {
          blog(`⚠ ${duplication.findings.length} duplicate block(s) found:`);
          duplication.findings.forEach((f) => blog(`    ⚠ ${f.file}:${f.line} — ${f.message}`));
        } else if (duplication.engine === 'jscpd') {
          blog('✓ Check 9 passed — no duplicate blocks above jscpd\'s default threshold.');
        } else {
          blog('✓ Check 9 skipped — jscpd disabled or not installed.');
        }
        return duplication;
      },
    },
    {
      name: 'fileEncapsulation',
      run: async (blog) => {
        blog(`Check 14 — file-size / encapsulation scan (built-in, >${FILE_SIZE_MAX_LINES} lines)...`);
        const fileEncapsulation = await checkFileEncapsulation(projectRoot, blog);
        if (fileEncapsulation.findings.length > 0) {
          blog(`⚠ ${fileEncapsulation.findings.length} oversized file(s) found:`);
          fileEncapsulation.findings.forEach((f) => blog(`    ⚠ ${f.file} — ${f.message}`));
        } else if (fileEncapsulation.engine === 'built-in') {
          blog(`✓ Check 14 passed — no file over ${FILE_SIZE_MAX_LINES} lines.`);
        } else {
          blog('✓ Check 14 skipped — disabled by config.');
        }
        return fileEncapsulation;
      },
    },
    {
      name: 'loc',
      run: async (blog) => {
        blog('Computing LOC metrics...');
        const { engine: locEngine, metrics: locMetrics } = await generateLocMetrics(projectRoot, blog);
        if (locMetrics) {
          blog(`✓ LOC metrics computed [engine: ${locEngine}] — ${locMetrics.total?.code ?? 0} lines of code across ${locMetrics.languages?.length ?? 0} language(s).`);
          if (projectId !== null) {
            const locBuffer = Buffer.from(JSON.stringify(locMetrics, null, 2));
            store.addUploadDocument(projectId, 'loc-metrics.json', 'application/json', locBuffer.length, locBuffer);
          }
        }
        return { locEngine, locMetrics };
      },
    },
    {
      name: 'apiSchema',
      run: async (blog) => {
        blog('Check 10 — API schema lint (spectral, OpenAPI/AsyncAPI)...');
        const apiSchema = await checkApiSchemas(projectRoot, blog);
        if (apiSchema.findings.length > 0) {
          blog(`✗ ${apiSchema.findings.length} API schema lint finding(s):`);
          apiSchema.findings.forEach((f) => blog(`    ${f.severity === 'error' ? '✗' : '⚠'} [${f.severity}] ${f.file}:${f.line} — ${f.message}`));
        } else if (apiSchema.engine === 'spectral') {
          blog('✓ Check 10 passed — no API schema lint findings (or no OpenAPI/AsyncAPI files found).');
        } else {
          blog('✓ Check 10 skipped — spectral disabled or not installed.');
        }
        return apiSchema;
      },
    },
    {
      name: 'apiSchemaDrift',
      run: async (blog) => {
        blog('Check 22 — API breaking-change / shadow-endpoint scan (oasdiff, vs. prior git revision)...');
        const apiSchemaDrift = await checkApiSchemaDrift(projectRoot, blog);
        if (apiSchemaDrift.findings.length > 0) {
          blog(`✗ ${apiSchemaDrift.findings.length} API breaking-change finding(s):`);
          apiSchemaDrift.findings.forEach((f) => blog(`    ${f.severity === 'error' ? '✗' : '⚠'} [${f.severity}] ${f.file} — ${f.message}`));
        } else if (apiSchemaDrift.engine === 'oasdiff') {
          blog('✓ Check 22 passed — no API breaking changes detected (or nothing to diff against).');
        } else {
          blog('✓ Check 22 skipped — oasdiff disabled or not installed.');
        }
        return apiSchemaDrift;
      },
    },
    {
      name: 'maliciousDependencies',
      run: async (blog) => {
        blog('Check 12 — malicious-dependency heuristic scan (guarddog, npm/PyPI)...');
        const maliciousDependencies = await checkMaliciousDependencies(projectRoot, blog);
        if (maliciousDependencies.findings.length > 0) {
          blog(`✗ ${maliciousDependencies.findings.length} suspicious dependency/dependencies flagged:`);
          maliciousDependencies.findings.forEach((f) => blog(`    ✗ ${f.file} — ${f.message}`));
        } else if (maliciousDependencies.engine === 'guarddog') {
          blog('✓ Check 12 passed — no suspicious dependencies found.');
        } else {
          blog('✓ Check 12 skipped — guarddog disabled or not installed.');
        }
        return maliciousDependencies;
      },
    },
    {
      name: 'modelArtifactSecurity',
      run: async (blog) => {
        blog('Check 21 — malicious ML model artifact scan (picklescan, .pkl/.pt/.pth/.ckpt/.bin)...');
        const modelArtifactSecurity = await checkModelArtifactSecurity(projectRoot, blog);
        if (modelArtifactSecurity.findings.length > 0) {
          blog(`✗ ${modelArtifactSecurity.findings.length} unsafe pickle payload(s) flagged:`);
          modelArtifactSecurity.findings.forEach((f) => blog(`    ✗ ${f.file} — ${f.message}`));
        } else if (modelArtifactSecurity.engine === 'picklescan') {
          blog('✓ Check 21 passed — no unsafe pickle payloads found (or no model artifacts present).');
        } else {
          blog('✓ Check 21 skipped — picklescan disabled or not installed.');
        }
        return modelArtifactSecurity;
      },
    },
    {
      name: 'packageHallucination',
      run: async (blog) => {
        blog('Check 23 — AI package-hallucination / slopsquat scan (built-in, npm/PyPI/crates.io)...');
        const packageHallucination = await checkPackageHallucination(projectRoot, blog);
        if (packageHallucination.findings.length > 0) {
          blog(`⚠ ${packageHallucination.findings.length} possibly-hallucinated dependency/dependencies flagged:`);
          packageHallucination.findings.forEach((f) => blog(`    ⚠ ${f.file} — ${f.message}`));
        } else if (packageHallucination.engine === 'built-in') {
          blog('✓ Check 23 passed — every checked dependency name exists on its public registry.');
        } else {
          blog('✓ Check 23 skipped — disabled by config.');
        }
        return packageHallucination;
      },
    },
    {
      name: 'posture',
      run: async (blog) => {
        blog('Check 11 — Compliance & Feature Posture Scan...');
        const { engine: postureEngine, posture } = await checkFeaturePosture(projectRoot, blog);
        for (const category of POSTURE_CATEGORIES) {
          const { status, matches } = posture[category];
          blog(`    ${status === 'DETECTED' ? '✓' : status === 'PARTIAL' ? '⚠' : '·'} ${category}: ${status}${matches.length > 0 ? ` (${matches.length} signal(s))` : ''}`);
        }
        if (projectId !== null) {
          const postureBuffer = Buffer.from(JSON.stringify({ engine: postureEngine, posture }, null, 2));
          store.addUploadDocument(projectId, 'posture-report.json', 'application/json', postureBuffer.length, postureBuffer);
        }
        return { postureEngine, posture };
      },
    },
    {
      name: 'euAiActDocuments',
      run: async (blog) => {
        blog('Check 20 — EU AI Act document-presence scan (built-in, advisory only)...');
        const { engine: docsEngine, documents } = await checkComplianceDocuments(projectRoot, blog);
        for (const category of DOCUMENT_CATEGORIES) {
          const { status, matches } = documents[category];
          blog(`    ${status === 'DETECTED' ? '✓' : '·'} ${category}: ${status}${matches.length > 0 ? ` (${matches.length} file(s))` : ''}`);
        }
        if (projectId !== null) {
          const docsBuffer = Buffer.from(JSON.stringify({ engine: docsEngine, documents }, null, 2));
          store.addUploadDocument(projectId, 'ai-act-documents-report.json', 'application/json', docsBuffer.length, docsBuffer);
        }
        return { docsEngine, documents };
      },
    },
    {
      name: 'deadCode',
      run: async (blog) => {
        blog('Check 16 — dead-code / unused-export / unused-dependency scan (built-in)...');
        const deadCode = await checkDeadCode(projectRoot, blog);
        if (deadCode.findings.length > 0) {
          blog(`⚠ ${deadCode.findings.length} dead-code finding(s) [engine: ${deadCode.engine}]:`);
          deadCode.findings.forEach((f) => blog(`    ⚠ ${f.file}${f.line ? ':' + f.line : ''} — ${f.kind}`));
        } else if (deadCode.engine === 'built-in') {
          blog('✓ Check 16 passed — no dead code/unused exports/unused dependencies detected.');
        } else {
          blog('✓ Check 16 skipped — disabled by config.');
        }
        return deadCode;
      },
    },
    {
      name: 'health',
      run: async (blog) => {
        blog('Check 17 — complexity/maintainability health scan (built-in)...');
        const health = await checkComplexityHealth(projectRoot, blog, {
          getCoverageForFile: async (relPath) => {
            const row = store.getRuntimeCoverageForFile(org, repo, relPath.split(path.sep).join('/'));
            return row?.covered_pct ?? null;
          },
        });
        if (health.findings.length > 0) {
          blog(`⚠ ${health.findings.length} file(s) over complexity/maintainability threshold.`);
        } else if (health.engine === 'built-in') {
          blog('✓ Check 17 passed — no file over the configured complexity/maintainability thresholds.');
        } else {
          blog('✓ Check 17 skipped — disabled by config.');
        }
        return health;
      },
    },
    {
      name: 'cssDeadCode',
      run: async (blog) => {
        blog('Check 18 — CSS/Tailwind dead-class scan (built-in)...');
        const cssDeadCode = await checkCssDeadCode(projectRoot, blog);
        if (cssDeadCode.findings.length > 0) {
          blog(`⚠ ${cssDeadCode.findings.length} unused CSS class(es) found.`);
        } else if (cssDeadCode.engine === 'built-in') {
          blog('✓ Check 18 passed — no unused CSS classes detected (or no CSS files present).');
        } else {
          blog('✓ Check 18 skipped — disabled by config.');
        }
        return cssDeadCode;
      },
    },
    {
      name: 'boundaries',
      run: async (blog) => {
        blog('Check 19 — architecture/import boundary enforcement (built-in)...');
        const boundaries = await checkBoundaries(projectRoot, blog);
        if (boundaries.findings.length > 0) {
          blog(`⚠ ${boundaries.findings.length} architecture boundary violation(s):`);
          boundaries.findings.forEach((f) => blog(`    ⚠ ${f.file}:${f.line} — ${f.message}`));
        } else if (boundaries.engine === 'built-in') {
          blog('✓ Check 19 passed — no architecture boundary violations.');
        } else {
          blog('✓ Check 19 skipped — disabled by config or no zones configured.');
        }
        return boundaries;
      },
    },
    {
      name: 'codeql',
      run: async (blog) => {
        blog('Check 15 — cross-file static analysis (CodeQL)...');
        const codeql = await checkCodeqlCrossFile(projectRoot, blog, { org, repo });
        if (codeql.findings.length > 0) {
          const crossFileCount = codeql.findings.filter((f) => f.crossFile).length;
          blog(`✗ ${codeql.findings.length} CodeQL finding(s) (${crossFileCount} genuinely cross-file):`);
          codeql.findings.forEach((f) => blog(`    ${f.severity === 'error' ? '✗' : '⚠'} [${f.severity}]${f.crossFile ? ' [cross-file]' : ''} ${f.file}:${f.line} — ${f.message}`));
        } else if (codeql.engine === 'codeql') {
          blog(`✓ Check 15 passed — no CodeQL findings across ${codeql.languages.length} language(s) scanned.`);
        } else {
          blog('✓ Check 15 skipped — codeql disabled or not installed.');
        }
        return codeql;
      },
    },
  ];

  const activeTasks = fast ? tasks.filter((t) => FAST_MODE_TASKS.has(t.name)) : tasks;
  if (fast) log?.(`⚡ Fast mode — running ${activeTasks.map((t) => t.name).join(', ')} only, skipping the rest of Phase 4's checks.`);
  const settled = await Promise.all(activeTasks.map(async (t) => {
    const value = await t.run((line) => log?.(line));
    return { name: t.name, value };
  }));
  const byName = Object.fromEntries(settled.map((r) => [r.name, r.value]));

  const euAiAct = EU_AI_ACT_REPORT_AS_FINDINGS
    ? deriveEuAiActFindings(byName.posture?.posture, byName.euAiActDocuments?.documents)
    : null;

  const issues = collectPhase4Issues({
    secrets: byName.secrets,
    governance: byName.governance,
    llm: byName.llm,
    iac: byName.iac,
    imageVulnerabilities: byName.imageVulnerabilities,
    imageProvenance: byName.imageProvenance,
    semanticSast: byName.semanticSast,
    piiDataFlow: byName.piiDataFlow,
    duplication: byName.duplication,
    fileEncapsulation: byName.fileEncapsulation,
    apiSchema: byName.apiSchema,
    apiSchemaDrift: byName.apiSchemaDrift,
    maliciousDependencies: byName.maliciousDependencies,
    modelArtifactSecurity: byName.modelArtifactSecurity,
    packageHallucination: byName.packageHallucination,
    codeql: byName.codeql,
    deadCode: byName.deadCode,
    health: byName.health,
    cssDeadCode: byName.cssDeadCode,
    boundaries: byName.boundaries,
    euAiAct,
  }).filter((issue) => !isExcludedSecurityFinding(issue));
  return { issues };
}

// Only called when CONFIG.compliance.euAiAct.reportAsFindings is true (see
// runPhase4Checks above) — turns the three ai-act-* posture categories'
// matches and the doc-presence scan's MISSING categories into the same
// {kind,file,line,message,code} shape collectPhase4Issues' codebase-
// intelligence loop already consumes for deadCode/health/cssDeadCode/
// boundaries. `posture`/`documents` are the raw per-category reports from
// checkFeaturePosture/checkComplianceDocuments; either can be undefined if
// that check itself is disabled.
function deriveEuAiActFindings(posture, documents) {
  const findings = [];
  const POSTURE_KIND = {
    'ai-act-prohibited-practice': 'ai-act-prohibited-practice',
    'ai-act-transparency-disclosure': 'ai-act-transparency-disclosure',
    'ai-act-ai-logging': 'ai-act-ai-logging',
  };
  for (const [category, kind] of Object.entries(POSTURE_KIND)) {
    for (const m of posture?.[category]?.matches || []) {
      findings.push({ kind, file: m.file, line: m.line, message: m.message, code: m.code });
    }
  }
  const DOCUMENT_LABELS = {
    'risk-management-system': 'Risk-management system documentation (Art. 9) not found in this repo.',
    'technical-documentation': 'Annex IV technical documentation (Art. 11) not found in this repo.',
    'fria': 'Fundamental rights impact assessment (Art. 27) not found in this repo.',
    'training-data-summary': 'GPAI training-data summary / model card (Art. 53) not found in this repo.',
    'post-market-monitoring': 'Post-market monitoring plan (Art. 72) not found in this repo.',
  };
  for (const [category, message] of Object.entries(DOCUMENT_LABELS)) {
    if (documents?.[category]?.status === 'MISSING') {
      findings.push({ kind: 'ai-act-compliance-documents', discriminator: category, file: null, line: null, message });
    }
  }
  return { findings };
}

async function actTooling() {
  try {
    await runTool('act', ['--version'], os.tmpdir());
  } catch {
    return { ok: false, reason: '`act` is not installed (brew install act).' };
  }
  try {
    await runTool('docker', ['info', '--format', '{{.ServerVersion}}'], os.tmpdir());
  } catch {
    return { ok: false, reason: 'Docker daemon is not running (start Docker Desktop).' };
  }
  return { ok: true };
}

async function runActionsLocally(root, wfFile, log) {
  const localGithubDir = path.join(root, '.github');
  const localWorkflowDir = path.join(root, '.github', 'workflows');
  const hadGithubDir = fs.existsSync(localGithubDir);
  const hadLocalWorkflowDir = fs.existsSync(localWorkflowDir);
  await fsp.mkdir(localWorkflowDir, { recursive: true });

  // Reusable workflows referenced as ./.github/workflows/*.yml must exist
  // inside the repo being executed by act.
  const sourceWorkflowDir = path.dirname(wfFile);
  const sourceWorkflowFiles = await fsp.readdir(sourceWorkflowDir);
  const existingLocalWorkflowFiles = new Set(
    await fsp.readdir(localWorkflowDir).catch(() => [])
  );
  const injectedWorkflowFiles = [];
  const overwrittenWorkflowBackups = new Map();
  for (const name of sourceWorkflowFiles) {
    if (!/\.ya?ml$/i.test(name)) continue;
    const src = path.join(sourceWorkflowDir, name);
    const dst = path.join(localWorkflowDir, name);

    if (existingLocalWorkflowFiles.has(name) && !overwrittenWorkflowBackups.has(name)) {
      const original = await fsp.readFile(dst).catch(() => null);
      if (original) overwrittenWorkflowBackups.set(name, original);
    }

    await fsp.copyFile(src, dst);
    if (!existingLocalWorkflowFiles.has(name)) {
      injectedWorkflowFiles.push(dst);
    }
  }
  const wfPathForAct = path.join(localWorkflowDir, path.basename(wfFile));

  // act needs the workspace to be a git repo for ref/branch metadata. Bearer
  // (checkPiiDataFlow, Phase 4, on by default) may already have initialized
  // and committed this same root via ensureGitContextForBearer — reuse that
  // instead of re-running init/add/commit unconditionally: a bare `git
  // commit` (no --allow-empty) fails outright with "nothing to commit" once
  // Bearer's own commit already staged everything, which would otherwise
  // throw here every time Bearer ran first with no intervening file edits.
  // Same guard Phase 6 (shipToGitHub) already uses for the same reason.
  const alreadyRepo = fs.existsSync(path.join(root, '.git'));
  if (alreadyRepo) {
    log('Reusing repository initialized during Phase 4 (Bearer PII/data-flow scan).');
  } else {
    await runTool('git', ['init', '-b', 'main'], root);
    await runTool('git', ['add', '.'], root);
    await runTool(
      'git',
      ['-c', 'user.name=Onboarding Gatekeeper', '-c', 'user.email=gatekeeper@localhost',
       'commit', '-m', 'chore: initial compliant code drop via onboarding gatekeeper'],
      root
    );
  }

  let token = '';
  if (await isGhCliAvailable()) {
    try {
      token = (await runTool('gh', ['auth', 'token'], root)).stdout;
    } catch { /* fall through to the env-var fallback below */ }
  }
  if (!token) {
    token =
      resolveServerGithubToken();
  }
  if (!token) log('⚠ No GitHub token available (gh not installed/authenticated, and GH_TOKEN/GITHUB_TOKEN not set) — remote reusable workflows may fail to resolve.');

  const args = [
    ACT_EVENT,
    '-W', wfPathForAct,
    '-P', 'ubuntu-latest=catthehacker/ubuntu:act-latest',
    '--rm',
  ];
  if (token) args.push('-s', `GITHUB_TOKEN=${token}`);

  log(`$ act ${ACT_EVENT} -W ${path.relative(root, wfPathForAct)} -P ubuntu-latest=catthehacker/ubuntu:act-latest --rm`);
  log('(first run downloads runner/tool images — may take a few minutes)');
  try {
    await runToolStreaming('act', args, root, (line) => log(line.slice(0, 400)), {
      timeoutMs: ACT_TIMEOUT_MIN * 60_000,
    });
  } finally {
    // Do not leak localized governance workflows into phase 6 shipping.
    for (const file of injectedWorkflowFiles) {
      await fsp.rm(file, { force: true }).catch(() => {});
    }

    // Restore original workflow files that existed in the user's repo.
    for (const [name, originalBytes] of overwrittenWorkflowBackups.entries()) {
      const dst = path.join(localWorkflowDir, name);
      await fsp.writeFile(dst, originalBytes).catch(() => {});
    }

    // Remove scaffolding created only for local act execution.
    if (!hadLocalWorkflowDir) {
      await fsp.rm(localWorkflowDir, { recursive: true, force: true }).catch(() => {});
    }
    if (!hadGithubDir) {
      await fsp.rm(localGithubDir, { recursive: true, force: true }).catch(() => {});
    }
  }
}

/* ------------------------------------------------------------------ */
/* Phase 5 (cont.): run the onboarded project's own unit test suite,   */
/* sandboxed inside a throwaway Docker container (never on the host). */
/* ------------------------------------------------------------------ */

const { createUnitTestRunnerCheck } = require('./checks/unit-test-runner');
const { runProjectUnitTests } = createUnitTestRunnerCheck({ runTool, runToolStreaming });

/* ------------------------------------------------------------------ */
/* Phase 5: git + gh shipping                                          */
/* ------------------------------------------------------------------ */

const { createShipping } = require('./lib/shipping');
const { shipToGitHub, archivePhase6Payload } = createShipping({
  runTool,
  sanitizeCliArg,
  githubApi: { ghApiGet, ghApiWrite, ghCreatePr, ghArmAutoMerge, ghWatchPrChecks },
  store,
  config: {
    bootstrapBranch: process.env.BOOTSTRAP_BRANCH || CONFIG.github.bootstrapBranch,
    remoteProtocol: process.env.GITHUB_REMOTE_PROTOCOL || CONFIG.github.remoteProtocol,
  },
});

const INSIGHT_SYSTEM_PROMPT = `You are a DevOps incident explainer writing for a non-technical reader (e.g. a project manager).
Explain the real reason this phase failed and the next concrete fix, in plain language with no CI/security jargon.
If the log or issue list contains several distinct blockers, do NOT summarize them together (never say something like "fix all N issues" or "address all blocking findings") — write one short, numbered paragraph per distinct blocker, each naming its file/line when known and explaining, concretely, what is wrong with THAT one and why it matters. Skip issues that were already overridden or resolved.`;

const INSIGHT_ISSUES_SYSTEM_PROMPT = `You are a DevOps incident explainer writing for a non-technical reader (e.g. a project manager).
The pipeline was blocked because a list of specific flagged issues were never overridden or fixed. You will receive that exact list as JSON.
Write one short, numbered paragraph per issue in the list — never collapse or summarize multiple issues into one paragraph, and never write generic advice like "fix all N issues". Each paragraph must:
- Reference that issue's file and line (when present).
- Explain, in plain language with no jargon, what is concretely wrong with that specific instance and why it matters.
- End with one concrete next step for that specific issue.
Cover every issue in the list, in the order given. Keep each paragraph to 2-3 sentences.`;

/**
 * @param {Array} unresolvedIssues - when the failure is the review gate
 *   rejecting unoverridden findings, the exact structured issue list, so
 *   every one of them gets its own explanation instead of a vague summary.
 */
async function generateFailureInsight(failedPhase, error, record, unresolvedIssues) {
  if (!(await llmAvailableCached())) return null;

  if (Array.isArray(unresolvedIssues) && unresolvedIssues.length > 0) {
    const payload = unresolvedIssues.map((i, idx) => ({
      number: idx + 1,
      file: i.file || null,
      line: i.line || null,
      category: i.category,
      severity: i.severity,
      summary: i.summary,
    }));
    return await llmComplete(
      INSIGHT_ISSUES_SYSTEM_PROMPT,
      `Pipeline phase ${failedPhase} ("${PHASE_TITLES[failedPhase] || 'Unknown'}") failed.\n${JSON.stringify(payload, null, 2)}`,
      { label: `failure-insight phase ${failedPhase} (issues)` }
    );
  }

  // Generic phase failure (crash, tooling error, etc.) — no structured issue
  // list exists, so ground the explanation in the phase's own full log.
  const logs = (record[failedPhase]?.logs || []).join('\n').slice(-18_000);
  return await llmComplete(
    INSIGHT_SYSTEM_PROMPT,
    `Pipeline phase ${failedPhase} ("${PHASE_TITLES[failedPhase] || 'Unknown'}") failed.\nReported error: ${error}\n\nFull step log:\n${logs}`,
    { label: `failure-insight phase ${failedPhase} (log)` }
  );
}

/* ------------------------------------------------------------------ */
/* Failure notifications (email)                                       */
/* ------------------------------------------------------------------ */

// Built-in phase titles/descriptions — CONFIG.phases (config.json) can
// override title/desc per id; any id it doesn't mention keeps these
// defaults, and the whole thing is identical to today's hardcoded UI when
// config.json has no `phases` key at all.
const DEFAULT_PHASE_META = [
  { id: 1, title: 'Input & Metadata Configuration', desc: 'Validate archive and target repository metadata', enabled: true },
  { id: 2, title: 'GxP Validation Documents', desc: 'Mandatory for GxP processes · documents archived to the database', enabled: false },
  { id: 3, title: 'Extraction, Structure Audit & Unit Tests', desc: 'Unpack to staging · deny raw .env* files · auto-detect Node/Go/Rust/Python/Java and run its native test suite in an isolated Docker container', enabled: true },
  { id: 4, title: 'Security & AI Compliance Scan', desc: 'Credential leak regex · LangChain/LangGraph governance · LLM deep-scan', enabled: true },
  { id: 5, title: 'Org Governance CI — GitHub Actions', desc: 'Runs devops-governance org workflows locally in Docker via act', enabled: true },
  { id: 6, title: 'Provisioning & Shipping', desc: 'git init · gh repo create --private · push to main', enabled: true },
];

// Phases everything downstream structurally depends on — extraction (3)
// stages the project every later phase scans/ships, input validation (1)
// creates the project record, and shipping (6) is the pipeline's actual
// purpose (dryRun, not a disabled phase, is the "don't ship" switch). An
// `enabled: false` override on these ids is ignored rather than silently
// breaking the run.
const PHASE_ALWAYS_ENABLED = new Set([1, 3, 6]);

const PHASE_META = DEFAULT_PHASE_META.map((def) => {
  const override = (CONFIG.phases || []).find((p) => Number(p?.id) === def.id) || {};
  return {
    id: def.id,
    title: String(override.title || def.title),
    desc: String(override.desc || def.desc),
    enabled: PHASE_ALWAYS_ENABLED.has(def.id) ? true : (override.enabled !== undefined ? Boolean(override.enabled) : def.enabled),
  };
});

const PHASE_TITLES = Object.fromEntries(PHASE_META.map((p) => [p.id, p.title]));
const PHASE_ENABLED = Object.fromEntries(PHASE_META.map((p) => [p.id, p.enabled]));

const { createNotifications } = require('./lib/notifications');
const {
  buildMailTransport, escapeHtmlMail, buildFailureEmail, sendFailureNotification,
  buildOverrideEmail, sendOverrideNotification,
} = createNotifications({ config: CONFIG.notifications, phaseTitles: PHASE_TITLES });

/* ------------------------------------------------------------------ */
/* Scheduled re-checks: effectivated repos can opt into a recurring     */
/* re-run of Phases 1/3/4/5 against their default branch. A failure     */
/* notifies the repo's CODEOWNERS contact(s) by email, or — if none can */
/* be resolved — files a GitHub issue on the repo instead.              */
/* ------------------------------------------------------------------ */

const { createScheduledRechecks } = require('./lib/scheduled-rechecks');
const {
  SCHEDULE_INTERVALS, computeNextRunAt, buildScheduledCheckFailureEmail,
  sendScheduledCheckFailureEmail, notifyScheduledFailure, runScheduledRecheck,
  sweepScheduledRechecks,
} = createScheduledRechecks({
  store,
  ghCloneRepo,
  ghCreateIssue,
  resolveServerGithubToken,
  buildMailTransport,
  escapeHtmlMail,
  checkEnvFiles,
  checkCodeowners,
  runProjectUnitTests,
  runLicenseComplianceCheck,
  runDependencyVulnerabilityCheck,
  runPhase4Checks,
  actTooling,
  fetchGovernanceWorkflow,
  runActionsLocally,
  phaseEnabled: PHASE_ENABLED,
  notificationsConfig: CONFIG.notifications,
});

/**
 * Persist each applied override to the audit log and send exactly one
 * notification email covering the whole batch. Best-effort on email: a
 * flaky SMTP endpoint must not lose the audit record or crash the pipeline.
 */
async function recordOverrides({ projectId, jobId, org, repo, phase, actor, applied }) {
  if (applied.length === 0) return;
  let emailSent = false;
  try {
    const result = await sendOverrideNotification({ jobId, org, repo, phase, actor, applied });
    emailSent = result.sent === true;
  } catch (err) {
    console.error('Failed to send override notification email:', err.message);
  }
  for (const { issue, justification } of applied) {
    store.addOverride({
      projectId,
      jobId,
      phase,
      issueId: issue.id,
      category: issue.category,
      severity: issue.severity,
      summary: issue.summary,
      file: issue.file,
      line: issue.line,
      justification,
      actorEmail: actor.email,
      actorName: actor.name,
      emailSent,
    });
  }
}

/* ------------------------------------------------------------------ */
/* Pipeline endpoint (streams NDJSON events)                           */
/* ------------------------------------------------------------------ */

const { mountHistoryRoutes } = require('./routes/history');
mountHistoryRoutes(app, {
  store, auth, runningRuns, scheduleIntervals: SCHEDULE_INTERVALS, computeNextRunAt,
});

const { mountSarifRoute } = require('./routes/sarif');
mountSarifRoute(app, { store, runningRuns });

const { mountGithubCheckRoute } = require('./routes/github-pr-status');
mountGithubCheckRoute(app, {
  store, runningRuns, auth, resolveServerGithubToken, ghApiWrite, ghCommentOnPr,
  repoNameRegex: REPO_NAME_REGEX, githubNameRegex: GITHUB_NAME_REGEX,
});


/* ------------------------------------------------------------------ */
/* Dependency license compliance — Black Duck-style red/warning/green   */
/* classification, shown in Ignite Studio's "Dependencies" view and     */
/* exposed standalone via POST /api/dependencies/check for any project  */
/* path (agent/CI use, same convention as /api/pipeline/validate-all).  */
/*                                                                       */
/* Engines, in preference order (each soft-skips to the next if its     */
/* tool isn't installed — same convention as `act`/gitleaks elsewhere): */
/*  1. ORT (OSS Review Toolkit) analyzer, if the `ort` CLI is on PATH — */
/*     resolves actual lockfiles across NPM/Cargo/PyPI/Go/Maven in one  */
/*     pass, the closest local equivalent to a real Black Duck scan.    */
/*  2. Fallback: this file's own manifest parsers (package.json,        */
/*     Cargo.toml, requirements.txt, go.mod, pom.xml) + a per-dependency */
/*     license lookup against deps.dev's public API.                    */
/* Independently of either, `licensee` (if installed) detects the       */
/* project's OWN declared license from its LICENSE file/root content —  */
/* a different question ("what is this repo licensed under") than the   */
/* per-dependency scan ("what are its dependencies licensed under").    */
/* ------------------------------------------------------------------ */

const LICENSE_TIERS = {
  // Full open source — permissive, no reciprocal/attribution-beyond-notice
  // obligations. "Green" per the user's own framing.
  green: new Set([
    'MIT', 'MIT-0', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'BSD-3-Clause-Clear',
    'ISC', '0BSD', 'Unlicense', 'Zlib', 'Python-2.0', 'PostgreSQL', 'CC0-1.0', 'WTFPL',
    'BlueOak-1.0.0', 'BSD-4-Clause', 'X11', 'Artistic-2.0',
    // SIL Open Font License — OSI-approved, permissive (font-specific
    // reciprocal clause only restricts *reselling the font itself* under
    // its own name, not the normal case of bundling it into an app), and
    // extremely common on npm as the license for @fontsource/* packages.
    // Missing here meant every @fontsource dependency was a guaranteed
    // false-positive COMMERCIAL/RISK flag.
    'OFL-1.1', 'OFL-1.0',
  ]),
  // Copyleft/reciprocal open-source licenses — still genuinely open source,
  // but the kind of obligation that pushes many vendors toward a dual
  // "Community Edition (GPL) / Enterprise (commercial)" split. "Warning".
  warning: new Set([
    'GPL-2.0', 'GPL-2.0-only', 'GPL-2.0-or-later', 'GPL-3.0', 'GPL-3.0-only', 'GPL-3.0-or-later',
    'AGPL-3.0', 'AGPL-3.0-only', 'AGPL-3.0-or-later', 'LGPL-2.1', 'LGPL-2.1-only', 'LGPL-2.1-or-later',
    'LGPL-3.0', 'LGPL-3.0-only', 'LGPL-3.0-or-later', 'MPL-1.1', 'MPL-2.0', 'EPL-1.0', 'EPL-2.0',
    'CDDL-1.0', 'CDDL-1.1', 'CeCILL-2.1',
  ]),
  // Source-available but not OSI-approved open source — the "commercial
  // product with the source visible" pattern (SSPL/BUSL/Commons Clause are
  // exactly the licenses behind most vendors' non-open editions). "Red".
  red: new Set([
    'SSPL-1.0', 'BUSL-1.1', 'Commons-Clause', 'UNLICENSED', 'LicenseRef-Proprietary',
    'Elastic-2.0', 'Elastic-1.0',
  ]),
};

// Some ecosystems' declared license strings are non-standard spellings of a
// real SPDX id rather than actually ambiguous — e.g. npm package.json
// `license` fields with typos/variants like "MITClause" or "MIT License".
// Real observed case: @typescript-eslint/parser@8.18.0's own package.json
// literally declares license "MITClause" (a publishing typo), even though
// its LICENSE file is plain MIT — deps.dev can't classify it either and
// reports the generic "non-standard" placeholder (see
// DEPS_DEV_LICENSE_PLACEHOLDERS). Normalizing well-known variants here
// means the fix applies everywhere classifyLicenseTier is called (ORT,
// licensee, deps.dev, and the npm-registry placeholder fallback).
const LICENSE_ALIASES = new Map([
  ['mitclause', 'MIT'], ['mitlicense', 'MIT'], ['themitlicense', 'MIT'],
  ['apache2', 'Apache-2.0'], ['apache20', 'Apache-2.0'], ['apachelicense2.0', 'Apache-2.0'], ['apachelicense', 'Apache-2.0'],
  ['bsd2clause', 'BSD-2-Clause'], ['bsd3clause', 'BSD-3-Clause'],
]);

function normalizeLicenseId(raw) {
  const trimmed = String(raw || '').trim();
  const key = trimmed.toLowerCase().replace(/[\s.\-_]/g, '');
  return LICENSE_ALIASES.get(key) || trimmed;
}

function classifyLicenseTier(licenses) {
  const list = (Array.isArray(licenses) ? licenses : licenses ? [licenses] : [])
    .filter(Boolean).map((l) => normalizeLicenseId(l));
  if (list.length === 0) return { tier: 'red', reason: 'No license identified.' };
  if (list.some((l) => LICENSE_TIERS.red.has(l) || /commercial|proprietary/i.test(l))) {
    return { tier: 'red', reason: `Commercial/restrictive license: ${list.join(', ')}` };
  }
  if (list.some((l) => LICENSE_TIERS.green.has(l))) {
    return { tier: 'green', reason: list.join(', ') };
  }
  if (list.some((l) => LICENSE_TIERS.warning.has(l))) {
    return { tier: 'warning', reason: `Copyleft license: ${list.join(', ')}` };
  }
  return { tier: 'red', reason: `Unrecognized license — treat as risk until reviewed: ${list.join(', ')}` };
}

function bestEffortVersion(raw) {
  const m = String(raw || '').match(/(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?)/);
  return m ? m[1] : null;
}

// pnpm/bun/yarn-workspaces alias protocols: "catalog:dev", "catalog:",
// "workspace:*", "link:../foo", "file:../foo", "portal:../foo", "patch:...".
// None of these name a real published package+version — they're resolved by
// the package manager itself from local workspace/catalog config that isn't
// present in a single manifest file, so there is no license or CVE to look
// up. Without this check every one of them fell through to
// bestEffortVersion's "no digits found" branch and got flagged identically
// to a genuinely-unresolvable git-ref/tag dependency (tier: 'red', a
// blocking issue) - on a pnpm/bun catalog-heavy monorepo that's a false
// positive for every single catalog: entry in every manifest.
const INTERNAL_DEP_REF_RE = /^(workspace|catalog|link|file|portal|patch):/i;
function isInternalDependencyRef(versionRange) {
  return INTERNAL_DEP_REF_RE.test(String(versionRange || '').trim());
}

function parsePackageJsonDeps(content) {
  try {
    const json = JSON.parse(content);
    const deps = { ...(json.dependencies || {}), ...(json.devDependencies || {}) };
    return Object.entries(deps).map(([name, versionRange]) => ({ name, versionRange: String(versionRange) }));
  } catch {
    return [];
  }
}

function parseCargoTomlDeps(content) {
  const deps = [];
  let inDeps = false;
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (/^\[.*\]$/.test(line)) {
      inDeps = /^\[(dependencies|dev-dependencies|build-dependencies)\]$/.test(line);
      continue;
    }
    if (!inDeps || !line || line.startsWith('#')) continue;
    const m = line.match(/^([A-Za-z0-9_-]+)\s*=\s*(.+)$/);
    if (!m) continue;
    const versionMatch = m[2].match(/version\s*=\s*"([^"]+)"/) || m[2].match(/^"([^"]+)"/);
    deps.push({ name: m[1], versionRange: versionMatch ? versionMatch[1] : m[2].trim() });
  }
  return deps;
}

function parseRequirementsTxtDeps(content) {
  return content.split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#') && !l.startsWith('-'))
    .map((l) => {
      const m = l.match(/^([A-Za-z0-9_.-]+)\s*([=<>!~]{1,2}\s*[0-9A-Za-z.*+-]+)?/);
      return m ? { name: m[1], versionRange: (m[2] || '').replace(/\s+/g, '') } : null;
    })
    .filter(Boolean);
}

function parseGoModDeps(content) {
  const deps = [];
  let inRequire = false;
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (/^require\s*\($/.test(line)) { inRequire = true; continue; }
    if (inRequire && line === ')') { inRequire = false; continue; }
    const single = line.match(/^require\s+(\S+)\s+(\S+)/);
    if (single) { deps.push({ name: single[1], versionRange: single[2] }); continue; }
    if (inRequire && !line.startsWith('//')) {
      const m = line.match(/^(\S+)\s+(\S+)/);
      if (m) deps.push({ name: m[1], versionRange: m[2] });
    }
  }
  return deps;
}

function parsePomXmlDeps(content) {
  const deps = [];
  const blocks = content.match(/<dependency>[\s\S]*?<\/dependency>/g) || [];
  for (const block of blocks) {
    const groupId = block.match(/<groupId>([^<]+)<\/groupId>/)?.[1]?.trim();
    const artifactId = block.match(/<artifactId>([^<]+)<\/artifactId>/)?.[1]?.trim();
    const version = block.match(/<version>([^<]+)<\/version>/)?.[1]?.trim();
    if (groupId && artifactId) deps.push({ name: `${groupId}:${artifactId}`, versionRange: version || '' });
  }
  return deps;
}

const STUDIO_MANIFESTS = [
  { file: 'package.json', ecosystem: 'npm', system: 'NPM', parse: parsePackageJsonDeps },
  { file: 'Cargo.toml', ecosystem: 'cargo', system: 'CARGO', parse: parseCargoTomlDeps },
  { file: 'requirements.txt', ecosystem: 'pypi', system: 'PYPI', parse: parseRequirementsTxtDeps },
  { file: 'go.mod', ecosystem: 'go', system: 'GO', parse: parseGoModDeps },
  { file: 'pom.xml', ecosystem: 'maven', system: 'MAVEN', parse: parsePomXmlDeps },
];
const STUDIO_MAX_DEPS_PER_MANIFEST = 60;

const { createSbomCheck } = require('./checks/sbom');
const { generateSbom, generateSbomFallback, syftTooling } = createSbomCheck({
  runTool,
  fsUtils: { walkFiles },
  config: { enabled: SYFT_ENABLED },
  studioManifests: STUDIO_MANIFESTS,
  studioMaxDepsPerManifest: STUDIO_MAX_DEPS_PER_MANIFEST,
});

const { createPackageHallucinationCheck } = require('./checks/package-hallucination');
const { checkPackageHallucination } = createPackageHallucinationCheck({
  fsUtils: { walkFiles },
  studioManifests: STUDIO_MANIFESTS,
  config: { enabled: PACKAGE_HALLUCINATION_ENABLED },
});

const { mountConfigRoutes } = require('./routes/config');
mountConfigRoutes(app, {
  config: CONFIG,
  llmAvailableCached,
  defaultPhaseMeta: DEFAULT_PHASE_META,
  phaseMeta: PHASE_META,
  igniteVersion: IGNITE_VERSION,
});

const { mountToolsStatusRoutes } = require('./routes/tools-status');
mountToolsStatusRoutes(app, {
  toolings: {
    ortTooling, licenseeTooling, gitleaksTooling, trivyTooling, trivyImageTooling,
    checkovTooling, hadolintTooling, syftTooling, cosignTooling, semgrepTooling,
    bearerTooling, jscpdTooling, goclocTooling, spectralTooling, guarddogTooling, codeqlTooling,
    picklescanTooling, oasdiffTooling,
  },
  enabled: {
    gitleaksEnabled: GITLEAKS_ENABLED, trivyEnabled: TRIVY_ENABLED, trivyImageEnabled: TRIVY_IMAGE_ENABLED,
    checkovEnabled: CHECKOV_ENABLED, hadolintEnabled: HADOLINT_ENABLED, syftEnabled: SYFT_ENABLED,
    cosignEnabled: COSIGN_ENABLED, semgrepEnabled: SEMGREP_ENABLED, bearerEnabled: BEARER_ENABLED,
    jscpdEnabled: JSCPD_ENABLED, goclocEnabled: GOCLOC_ENABLED, spectralEnabled: SPECTRAL_ENABLED,
    guarddogEnabled: GUARDDOG_ENABLED, codeqlEnabled: CODEQL_ENABLED, picklescanEnabled: PICKLESCAN_ENABLED,
    oasdiffEnabled: OASDIFF_ENABLED,
  },
});

const { mountStudioRoutes } = require('./routes/studio');
mountStudioRoutes(app, {
  runningRuns,
  reviewDecisions,
  store,
  pendingEffectivations,
  cleanupExpiredEffectivations,
  fsUtils: { walkFiles, looksBinary },
  resolveWithinRoot,
  checks: {
    checkSecrets, checkAiGovernance, checkLlmDeepScan, checkIacSecurity,
    generateSbom, generateLocMetrics, checkFeaturePosture, generateProvenance,
    checkCodeqlCrossFile, runCustomCodeqlQuery,
  },
  overrideEngine: { collectPhase4Issues, collectCodeqlIssues, collectLicenseIssues, collectDependencyVulnerabilityIssues },
  licenseScan: { scanDependencyLicenses, scanProjectLicenseFiles, scanDependencyVulnerabilities },
});

// license lookups are immutable per (system, name, version) — cache for the
// life of the process so re-opening the Dependencies view or re-checking
// the same project never re-issues the same outbound request.
const depsDevCache = new Map();
// One deps.dev call returns both licenses and known-vulnerability advisory
// ids for a (system, name, version) — cached together so the license scan
// and the vulnerability scan never issue two requests for the same package.
async function fetchDepsDevPackageInfo(system, name, version) {
  const key = `${system}:${name}:${version}`;
  if (depsDevCache.has(key)) return depsDevCache.get(key);
  let result;
  try {
    const url = `https://api.deps.dev/v3/systems/${system}/packages/${encodeURIComponent(name)}/versions/${encodeURIComponent(version)}`;
    const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
    if (res.ok) {
      const data = await res.json();
      result = {
        licenses: data.licenses || [],
        advisoryIds: (data.advisoryKeys || []).map((k) => k.id).filter(Boolean),
      };
    } else {
      result = null;
    }
  } catch {
    result = null;
  }
  depsDevCache.set(key, result);
  return result;
}

async function fetchDepsDevLicenses(system, name, version) {
  const info = await fetchDepsDevPackageInfo(system, name, version);
  return info ? info.licenses : null;
}

// deps.dev's own license classifier sometimes can't map a package's
// declared license to an SPDX id and reports one of these placeholder
// strings instead of actually failing the lookup (observed for real:
// @typescript-eslint/parser@8.18.0 comes back as ["non-standard"] even
// though its package.json `license` field and LICENSE file both say plain
// "MIT" — `npm view <pkg>@<version> license` confirms it). Treating a
// placeholder the same as a real-but-unrecognized SPDX id would red-flag
// every package deps.dev punts on, so npm-ecosystem lookups fall back to
// asking the registry directly before giving up.
const DEPS_DEV_LICENSE_PLACEHOLDERS = new Set(['non-standard', 'unknown', 'other', 'none', '']);

function isPlaceholderLicenseList(licenses) {
  const list = (Array.isArray(licenses) ? licenses : licenses ? [licenses] : []).filter(Boolean);
  return list.length > 0 && list.every((l) => DEPS_DEV_LICENSE_PLACEHOLDERS.has(String(l).trim().toLowerCase()));
}

// Fallback for when deps.dev only offers a placeholder: ask the npm
// registry itself for that exact version's declared `license` field
// (registry.npmjs.org mirrors package.json verbatim, so this is the same
// data `npm view <pkg>@<version> license` would show).
async function fetchNpmRegistryLicense(name, version) {
  try {
    const url = `https://registry.npmjs.org/${encodeURIComponent(name).replace(/%40/g, '@')}/${encodeURIComponent(version)}`;
    const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
    if (!res.ok) return null;
    const data = await res.json();
    if (typeof data.license === 'string' && data.license.trim()) return [data.license.trim()];
    if (Array.isArray(data.licenses) && data.licenses.length > 0) {
      return data.licenses.map((l) => (typeof l === 'string' ? l : l?.type)).filter(Boolean);
    }
    return null;
  } catch {
    return null;
  }
}

// npm allows (and many packages use) a `license: "SEE LICENSE IN <file>"`
// declaration — a legitimate SPDX pattern for a license that isn't a
// standard identifier, not a red flag in itself. classifyLicenseTier still
// can't map that string to a tier, so it falls into the generic
// "unrecognized" red bucket unless something actually reads the file it
// points at. This fetches that exact file from the published tarball (via
// unpkg, which serves individual files without downloading the whole
// tarball) and pattern-matches its boilerplate against the handful of
// permissive license texts that account for the overwhelming majority of
// real "SEE LICENSE IN" usage in practice.
const SEE_LICENSE_IN_RE = /^SEE LICENSE IN\s+(.+)$/i;

function detectLicenseTextSpdxId(content) {
  const text = String(content || '');
  if (/permission is hereby granted, free of charge/i.test(text)) return 'MIT';
  if (/apache license/i.test(text) && /version 2\.0/i.test(text)) return 'Apache-2.0';
  if (/redistribution and use in source and binary forms/i.test(text)) {
    return /neither the name/i.test(text) ? 'BSD-3-Clause' : 'BSD-2-Clause';
  }
  return null;
}

async function fetchUnpkgFileText(name, version, filename) {
  try {
    const url = `https://unpkg.com/${encodeURIComponent(name).replace(/%40/g, '@')}@${encodeURIComponent(version)}/${filename.replace(/^\.?\//, '')}`;
    const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
    return res.ok ? await res.text() : null;
  } catch {
    return null;
  }
}

// Resolves a `SEE LICENSE IN <file>` declaration to a real SPDX id/tier by
// reading the referenced file's actual text, instead of leaving it in the
// unresolved "treat as risk until reviewed" bucket forever. Returns null
// (caller keeps the original unresolved classification) when the license
// string isn't this pattern, the file can't be fetched, or its text doesn't
// match a known permissive boilerplate — an unmatched result is still a
// real compliance question for a human, not something to guess green.
async function resolveSeeLicenseInFile(name, version, licenseString) {
  const m = SEE_LICENSE_IN_RE.exec(String(licenseString || '').trim());
  if (!m) return null;
  const filename = m[1].trim();
  const text = await fetchUnpkgFileText(name, version, filename);
  if (!text) return null;
  const spdxId = detectLicenseTextSpdxId(text);
  if (!spdxId) return null;
  const { tier } = classifyLicenseTier(spdxId);
  return { tier, reason: `${spdxId} (declared "SEE LICENSE IN ${filename}", verified by matching that file's text)` };
}

// bestEffortVersion (below) extracts the numeric floor of a manifest's
// version *range* (e.g. "^5.6.0" -> "5.6.0") and looks that up directly —
// which 404s on deps.dev whenever that exact patch was never actually
// published (common: many packages skip an exact ".0" release, or it only
// ever existed as a prerelease/dev build — e.g. real npm history has
// typescript 5.6.0-beta/5.6.0-dev.* then jumps straight to 5.6.1-rc/5.6.2).
// A 404 there means "this literal version string doesn't exist", not
// "this package's license is unknown" — the range still resolves to a
// real, real-licensed version. This resolves the actual highest published
// version satisfying the range as a fallback before giving up.
const depsDevVersionsCache = new Map();
async function fetchDepsDevVersionList(system, name) {
  const key = `${system}:${name}`;
  if (depsDevVersionsCache.has(key)) return depsDevVersionsCache.get(key);
  let result = null;
  try {
    const url = `https://api.deps.dev/v3/systems/${system}/packages/${encodeURIComponent(name)}`;
    const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
    if (res.ok) {
      const data = await res.json();
      result = (data.versions || []).map((v) => v.versionKey?.version).filter(Boolean);
    }
  } catch { /* result stays null — caller treats like any other lookup failure */ }
  depsDevVersionsCache.set(key, result);
  return result;
}

function parseSemver(v) {
  const m = String(v || '').match(/^(\d+)\.(\d+)\.(\d+)/);
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

function compareSemver(a, b) {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

// Deliberately narrow: covers exact pins and npm/cargo-style ^ and ~
// prefixes, which is what package.json/Cargo.toml ranges actually use in
// practice. Anything else (>=, workspace:, git refs, ...) is treated as
// "any published version at or above the floor is acceptable" rather than
// attempting full range-grammar parsing.
function satisfiesVersionRange(version, rawRange) {
  const v = parseSemver(version);
  // rawRange is the manifest's literal range string (e.g. "^5.6.0") — it
  // never itself starts with a digit, so parseSemver alone always misses
  // it (silently making every candidate "satisfy" the range and picking
  // the single highest published version overall regardless of range,
  // observed for real against typescript's actual current release line).
  // bestEffortVersion strips the operator prefix to get the floor first.
  const floor = parseSemver(bestEffortVersion(rawRange));
  if (!v || !floor) return true;
  if (compareSemver(v, floor) < 0) return false;
  const range = String(rawRange || '').trim();
  if (range.startsWith('^')) {
    if (floor[0] > 0) return v[0] === floor[0];
    if (floor[1] > 0) return v[0] === 0 && v[1] === floor[1];
    return v[0] === 0 && v[1] === 0 && v[2] === floor[2];
  }
  if (range.startsWith('~')) return v[0] === floor[0] && v[1] === floor[1];
  if (!/[\^~<>=*x]/i.test(range)) return compareSemver(v, floor) === 0; // exact pin
  return true;
}

async function resolveBestPublishedVersion(system, name, versionRange) {
  const versions = await fetchDepsDevVersionList(system, name);
  if (!versions) return null;
  const stable = versions.filter((v) => parseSemver(v) && !/[-+]/.test(v)); // no prereleases/build metadata
  const matching = stable.filter((v) => satisfiesVersionRange(v, versionRange));
  const pool = matching.length > 0 ? matching : stable;
  if (pool.length === 0) return null;
  pool.sort((a, b) => compareSemver(parseSemver(b), parseSemver(a)));
  return pool[0];
}

// Advisory details (title/CVSS/aliases) keyed by GHSA/advisory id — also
// immutable, also cached for the process lifetime.
const depsDevAdvisoryCache = new Map();
async function fetchDepsDevAdvisory(id) {
  if (depsDevAdvisoryCache.has(id)) return depsDevAdvisoryCache.get(id);
  let result;
  try {
    const res = await fetch(`https://api.deps.dev/v3/advisories/${encodeURIComponent(id)}`, { signal: AbortSignal.timeout(5000) });
    result = res.ok ? await res.json() : null;
  } catch {
    result = null;
  }
  depsDevAdvisoryCache.set(id, result);
  return result;
}

// CVSS v3 base score bands (FIRST.org's own qualitative ratings): >=9
// critical, >=7 high — both block the pipeline. Below that (medium/low) is
// advisory-only. An advisory with no CVSS score at all (deps.dev doesn't
// always have one) is treated as medium rather than assumed harmless.
function classifyVulnerabilitySeverity(cvss3Score) {
  if (typeof cvss3Score === 'number' && cvss3Score >= 7) return 'error';
  return 'warning';
}

// Best-effort 1-based line of a dependency's declaration inside its
// manifest, so a license finding can highlight the exact line in the Studio
// editor instead of a file-level "line ?". Null when not found (ORT-derived
// results never have manifest text to search).
function findManifestDepLine(content, depName, ecosystem) {
  const needle = ecosystem === 'maven'
    ? `<artifactId>${depName.split(':')[1] || depName}<`
    : ecosystem === 'npm'
      ? `"${depName}"`
      : depName;
  const idx = content.split(/\r?\n/).findIndex((l) => l.includes(needle));
  return idx >= 0 ? idx + 1 : null;
}

async function scanDependencyLicensesFallback(root, { skipEcosystems = new Set() } = {}) {
  const manifests = [];
  for await (const file of walkFiles(root)) {
    const spec = STUDIO_MANIFESTS.find((m) => m.file === path.basename(file));
    if (!spec || skipEcosystems.has(spec.ecosystem)) continue;
    const content = await fsp.readFile(file, 'utf8').catch(() => null);
    if (content == null) continue;
    const rawDeps = spec.parse(content).slice(0, STUDIO_MAX_DEPS_PER_MANIFEST);
    const dependencies = await Promise.all(rawDeps.map(async (dep) => {
      const line = findManifestDepLine(content, dep.name, spec.ecosystem);
      if (isInternalDependencyRef(dep.versionRange)) {
        return { name: dep.name, versionRange: dep.versionRange, version: null, line, licenses: [], tier: 'internal', reason: 'Internal workspace/catalog reference, not an external package — nothing to license-check.' };
      }
      const version = bestEffortVersion(dep.versionRange);
      if (!version) {
        return { name: dep.name, versionRange: dep.versionRange, version: null, line, licenses: [], tier: 'red', reason: 'Could not resolve an exact version to check (range/tag/git ref).' };
      }
      let licenses = await fetchDepsDevLicenses(spec.system, dep.name, version);
      let resolvedVersion = version;
      if (licenses === null) {
        // The literal floor version doesn't exist upstream — try the
        // highest real published version the manifest's range actually
        // resolves to before concluding the lookup genuinely failed.
        const better = await resolveBestPublishedVersion(spec.system, dep.name, dep.versionRange);
        if (better && better !== version) {
          const retryLicenses = await fetchDepsDevLicenses(spec.system, dep.name, better);
          if (retryLicenses !== null) { licenses = retryLicenses; resolvedVersion = better; }
        }
      }
      if (licenses === null) {
        return { name: dep.name, versionRange: dep.versionRange, version, line, licenses: [], tier: 'red', reason: 'License lookup failed (package/version not found upstream).' };
      }
      if (spec.system === 'NPM' && isPlaceholderLicenseList(licenses)) {
        const npmLicense = await fetchNpmRegistryLicense(dep.name, resolvedVersion);
        if (npmLicense) licenses = npmLicense;
      }
      let { tier, reason } = classifyLicenseTier(licenses);
      if (spec.system === 'NPM' && tier !== 'green' && Array.isArray(licenses) && licenses.length === 1) {
        const resolved = await resolveSeeLicenseInFile(dep.name, resolvedVersion, licenses[0]);
        if (resolved) ({ tier, reason } = resolved);
      }
      return { name: dep.name, versionRange: dep.versionRange, version: resolvedVersion, line, licenses, tier, reason };
    }));
    manifests.push({ file: path.relative(root, file), ecosystem: spec.ecosystem, dependencies });
  }
  return manifests;
}

// Same manifest-walking/version-resolution as the license scan above, but
// checking each resolved dependency against deps.dev's aggregated OSV/GHSA
// advisory data instead of its license. Only known-CVE/GHSA vulnerabilities
// are ever reported — no static/heuristic guessing about "risky" packages.
async function scanDependencyVulnerabilities(root) {
  const manifests = [];
  for await (const file of walkFiles(root)) {
    const spec = STUDIO_MANIFESTS.find((m) => m.file === path.basename(file));
    if (!spec) continue;
    const content = await fsp.readFile(file, 'utf8').catch(() => null);
    if (content == null) continue;
    const rawDeps = spec.parse(content).slice(0, STUDIO_MAX_DEPS_PER_MANIFEST);
    const dependencies = await Promise.all(rawDeps.map(async (dep) => {
      const line = findManifestDepLine(content, dep.name, spec.ecosystem);
      if (isInternalDependencyRef(dep.versionRange)) {
        return { name: dep.name, versionRange: dep.versionRange, version: null, line, vulnerabilities: [], note: 'Internal workspace/catalog reference, not an external package — nothing to check.' };
      }
      const version = bestEffortVersion(dep.versionRange);
      if (!version) {
        return { name: dep.name, versionRange: dep.versionRange, version: null, line, vulnerabilities: [], note: 'Could not resolve an exact version to check (range/tag/git ref).' };
      }
      let info = await fetchDepsDevPackageInfo(spec.system, dep.name, version);
      let resolvedVersion = version;
      if (info === null) {
        // Same fallback as the license scan: the manifest's literal range
        // floor may never have been published as an exact version.
        const better = await resolveBestPublishedVersion(spec.system, dep.name, dep.versionRange);
        if (better && better !== version) {
          const retryInfo = await fetchDepsDevPackageInfo(spec.system, dep.name, better);
          if (retryInfo !== null) { info = retryInfo; resolvedVersion = better; }
        }
      }
      if (info === null) {
        return { name: dep.name, versionRange: dep.versionRange, version, line, vulnerabilities: [], note: 'Vulnerability lookup failed (package/version not found upstream).' };
      }
      const advisories = await Promise.all(info.advisoryIds.map(fetchDepsDevAdvisory));
      const vulnerabilities = advisories
        .filter(Boolean)
        .map((a) => ({
          id: a.advisoryKey?.id || null,
          title: a.title || null,
          aliases: a.aliases || [],
          cvss3Score: typeof a.cvss3Score === 'number' ? a.cvss3Score : null,
          severity: classifyVulnerabilitySeverity(a.cvss3Score),
          url: a.url || null,
        }));
      return { name: dep.name, versionRange: dep.versionRange, version: resolvedVersion, line, vulnerabilities, note: null };
    }));
    // Only keep manifests/deps that actually have something to report — a
    // vulnerability-free dependency shouldn't clutter the response the way
    // an unclassified license does (that's inherently a risk; no known CVEs
    // isn't).
    const withFindings = dependencies.filter((d) => d.vulnerabilities.length > 0 || d.note);
    if (withFindings.length > 0) {
      manifests.push({ file: path.relative(root, file), ecosystem: spec.ecosystem, dependencies: withFindings });
    }
  }
  return manifests;
}

async function licenseeTooling() {
  try {
    await runTool('licensee', ['version'], os.tmpdir());
    return { ok: true };
  } catch {
    return { ok: false, reason: '`licensee` is not installed (gem install licensee).' };
  }
}

// Detects the PROJECT's OWN declared license (LICENSE file / package
// metadata) — independent of the per-dependency scan below. Soft-fails to
// null (Studio just omits the "Project license" row) if licensee isn't
// installed or finds nothing conclusive.
async function runLicenseeDetect(root, log) {
  const tooling = await licenseeTooling();
  if (!tooling.ok) {
    log?.(`⚠ Project license detection skipped: ${tooling.reason}`);
    return null;
  }
  try {
    const { stdout } = await runTool('licensee', ['detect', '--json', root], root);
    const data = JSON.parse(stdout);
    const best = (data.licenses || [])[0];
    if (!best) return null;
    const { tier, reason } = classifyLicenseTier(best.spdx_id);
    return { spdxId: best.spdx_id, confidence: data.matched_files?.[0]?.attribution ? 100 : (best.similarity ?? null), tier, reason };
  } catch (e) {
    log?.(`⚠ Project license detection failed: ${e.message}`);
    return null;
  }
}

async function ortTooling() {
  try {
    await runTool('ort', ['--version'], os.tmpdir());
    return { ok: true };
  } catch {
    return { ok: false, reason: '`ort` (OSS Review Toolkit) is not installed — falling back to the built-in manifest scan + deps.dev lookup.' };
  }
}

// ORT only populates each project's `definition_file_path` (the manifest
// path we need for per-file issues in Studio) when it can resolve the
// staging root's VCS — on a bare directory (the normal case: a ZIP/folder
// upload, never a git checkout) it comes back empty for every project.
// Best-effort init+commit just so ORT can compute those relative paths;
// swallows any failure (ORT still runs, just without per-file paths) and
// never touches a `.git` the upload already brought with it.
async function ensureGitRootForOrt(root, log) {
  if (await fsp.access(path.join(root, '.git')).then(() => true, () => false)) return;
  try {
    await runTool('git', ['init', '-q'], root);
    await runTool('git', ['add', '-A'], root);
    await runTool('git', [
      '-c', 'user.email=ignite@local', '-c', 'user.name=Ignite',
      'commit', '-q', '-m', 'ignite-ort-scan', '--no-verify',
    ], root);
  } catch (e) {
    log?.(`⚠ Could not stage a throwaway git repo for ORT's path resolution (non-blocking): ${e.message}`);
  }
}

// Runs ORT's Analyzer module, which resolves actual lockfiles (more
// accurate than this file's own regex-based manifest parsers) across every
// ecosystem it supports in one pass. Returns null — never throws — on any
// missing tool, timeout, or unrecognized output shape, so the caller always
// has the lightweight fallback to drop back to; ORT's analyzer-result.json
// schema has changed across versions, so field access here is defensive.
async function runOrtAnalyze(root, log) {
  const tooling = await ortTooling();
  if (!tooling.ok) {
    log?.(`⚠ ORT analyzer skipped: ${tooling.reason}`);
    return null;
  }
  await ensureGitRootForOrt(root, log);
  const outDir = path.join(os.tmpdir(), `ignite-ort-${crypto.randomBytes(8).toString('hex')}`);
  try {
    await fsp.mkdir(outDir, { recursive: true });
    // exit 2 = "found issues at/above severity threshold" (a normal ORT
    // outcome, e.g. commercial/unresolved licenses) — the result JSON is
    // still written; only other exit codes mean the analyzer itself failed.
    await runTool('ort', ['analyze', '-i', root, '-o', outDir, '-f', 'JSON'], root, { allowedExitCodes: [0, 2] });
    const raw = await fsp.readFile(path.join(outDir, 'analyzer-result.json'), 'utf8');
    const data = JSON.parse(raw);
    const packages = data?.analyzer?.result?.packages || data?.result?.packages || [];
    if (!Array.isArray(packages) || packages.length === 0) return null;

    // ORT's `packages` list is every resolved package in the graph — direct
    // AND transitive. Ignite Studio's Dependencies view should mirror what
    // the fallback manifest scanner shows (dependencies/devDependencies
    // declared directly in the manifest), not the full resolved tree, so
    // narrow to just the direct set using the per-ecosystem dependency
    // graph: `dependency_graphs[<Type>].scopes[<scopeName>]` lists each
    // scope's root entries, and each root's `root` field is an index
    // directly into that same graph's `packages` id-string array (verified
    // against a real `ort analyze` run — NOT a node index into `nodes`,
    // despite nodes also wrapping a `{ pkg: <packageIndex> }`). A missing/
    // unrecognized graph for a given ecosystem leaves that ecosystem
    // unfiltered (old flattened behavior) rather than dropping it.
    const dependencyGraphs = data?.analyzer?.result?.dependency_graphs || data?.result?.dependencyGraphs || {};
    const directIdsByType = new Map();
    for (const [type, graph] of Object.entries(dependencyGraphs)) {
      const graphPackages = graph?.packages || [];
      const scopes = graph?.scopes || {};
      const ids = new Set();
      for (const roots of Object.values(scopes)) {
        for (const entry of roots || []) {
          const id = graphPackages[entry?.root];
          if (id) ids.add(id);
        }
      }
      if (ids.size > 0) directIdsByType.set(type, ids);
    }

    // Map each ecosystem to its manifest path via the analyzer's `projects`
    // list — the one place ORT records definition_file_path. When an
    // ecosystem has more than one project (e.g. a monorepo with two
    // package.json's) the path is ambiguous per-package, so that ecosystem
    // falls back to the old synthetic "(ORT: ecosystem)" grouping label
    // instead of guessing wrong.
    const projects = data?.analyzer?.result?.projects || data?.result?.projects || [];
    const pathByEcosystem = new Map();
    for (const proj of projects) {
      const projType = String(proj?.id || '').split(':')[0];
      const defPath = proj?.definition_file_path || proj?.definitionFilePath || '';
      if (!projType || !defPath) continue;
      const ecosystem = projType.toLowerCase();
      if (pathByEcosystem.has(ecosystem) && pathByEcosystem.get(ecosystem) !== defPath) {
        pathByEcosystem.set(ecosystem, null); // ambiguous — more than one manifest
      } else {
        pathByEcosystem.set(ecosystem, defPath);
      }
    }

    const byEcosystem = new Map();
    for (const entry of packages) {
      const pkg = entry.package || entry;
      const id = String(pkg.id || '');
      const [type, , name, version] = id.split(':'); // "Type:Namespace:Name:Version"
      if (!type || !name) continue;
      const directIds = directIdsByType.get(type);
      if (directIds && !directIds.has(id)) continue; // transitive-only — skip
      const declared = pkg.declared_licenses || pkg.declaredLicenses
        || (pkg.declared_licenses_processed?.spdx_expression ? [pkg.declared_licenses_processed.spdx_expression] : [])
        || (pkg.declaredLicensesProcessed?.spdxExpression ? [pkg.declaredLicensesProcessed.spdxExpression] : []);
      const { tier, reason } = classifyLicenseTier(declared);
      const ecosystem = type.toLowerCase();
      if (!byEcosystem.has(ecosystem)) byEcosystem.set(ecosystem, []);
      byEcosystem.get(ecosystem).push({ name, versionRange: version || '', version: version || null, licenses: declared, tier, reason });
    }
    return Promise.all([...byEcosystem.entries()].map(async ([ecosystem, dependencies]) => {
      const realPath = pathByEcosystem.get(ecosystem);
      if (!realPath) return { file: `(ORT: ${ecosystem})`, ecosystem, dependencies };
      // Resolve each dependency's declaration line the same way the
      // deps.dev fallback does, so Studio can highlight the exact line
      // whether the finding came from ORT or the fallback scanner.
      const content = await fsp.readFile(path.join(root, realPath), 'utf8').catch(() => null);
      const withLines = content == null ? dependencies : dependencies.map((dep) => ({
        ...dep,
        line: findManifestDepLine(content, dep.name, ecosystem),
      }));
      return { file: realPath, ecosystem, dependencies: withLines };
    }));
  } catch (e) {
    log?.(`⚠ ORT analyzer failed, falling back to built-in scan: ${e.message}`);
    return null;
  } finally {
    await fsp.rm(outDir, { recursive: true, force: true }).catch(() => {});
  }
}

async function scanDependencyLicenses(root, log) {
  const [projectLicense, ortManifests] = await Promise.all([
    runLicenseeDetect(root, log),
    runOrtAnalyze(root, log),
  ]);
  // ORT resolves per-ecosystem (it needs that ecosystem's lockfile/tooling —
  // e.g. a package-lock.json for NPM, the `cargo`/`python-inspector` binary
  // on PATH) — it's common for it to cover some ecosystems in a repo and not
  // others. Using ORT's results outright for what it *did* resolve, and the
  // built-in deps.dev fallback only for the rest, means one uncovered
  // ecosystem never makes every other manifest's findings disappear.
  const ortEcosystems = new Set((ortManifests || []).map((m) => m.ecosystem));
  const fallbackManifests = await scanDependencyLicensesFallback(root, { skipEcosystems: ortEcosystems });
  const manifests = [...(ortManifests || []), ...fallbackManifests];
  const engine = !ortManifests ? 'fallback' : (fallbackManifests.length > 0 ? 'ort+fallback' : 'ort');
  if (ortManifests && fallbackManifests.length > 0) {
    log?.(`ℹ ORT resolved ${[...ortEcosystems].join(', ')} — falling back to deps.dev for the rest (${fallbackManifests.map((m) => m.ecosystem).join(', ')}).`);
  }
  return { engine, projectLicense, manifests };
}

const LICENSE_FILENAME_RE = /^LICEN[CS]E(\.(txt|md))?$/i;
const LICENSE_SCAN_PATH_SKIP_RE = /^(?:\.claude|\.github)\/skills\//i;

// Dependency-free classification of a LICENSE file's raw text. `licensee`
// (runLicenseeDetect) only ever inspects the project root and needs the gem
// installed — this catches every LICENSE file in the tree (a multi-language
// repo has one per module) purely by pattern-matching, so commercial terms
// are still caught with no external tooling at all.
function classifyLicenseText(content) {
  const commercialMatch = content.match(/commercial|proprietary/i);
  if (!commercialMatch) return null;
  const licenseeMatch = content.match(/^\s*Licensee\s*:\s*(.+)$/im);
  const licensorMatch = content.match(/^\s*Licensor\s*:\s*(.+)$/im);
  const anchor = licenseeMatch || commercialMatch;
  const line = content.slice(0, anchor.index).split(/\r?\n/).length;
  const reason = licenseeMatch
    ? `Commercial license agreement — Licensee: ${licenseeMatch[1].trim()}${licensorMatch ? `, Licensor: ${licensorMatch[1].trim()}` : ''}.`
    : 'Commercial/proprietary license terms detected in LICENSE file.';
  return { tier: 'red', line, reason };
}

// Walks the whole staged tree (not just the root) for LICENSE/LICENCE files
// and flags the commercial/proprietary-looking ones. Complements the
// per-dependency manifest scan above — a manifest can declare only
// permissive/OSS packages while the repo still ships a commercial LICENSE
// file for a vendored or non-package-manager-distributed component.
async function scanProjectLicenseFiles(root) {
  const findings = [];
  for await (const file of walkFiles(root)) {
    if (!LICENSE_FILENAME_RE.test(path.basename(file))) continue;
    const relFile = path.relative(root, file);
    if (LICENSE_SCAN_PATH_SKIP_RE.test(relFile.replace(/\\/g, '/'))) continue;
    const content = await fsp.readFile(file, 'utf8').catch(() => null);
    if (content == null) continue;
    const classified = classifyLicenseText(content);
    if (classified) findings.push({ file: relFile, ...classified });
  }
  return findings;
}

// Runs as part of Phase 3 in every pipeline entry point (interactive
// streaming, validate-all, onboard) — dependency-manifest licenses (via
// scanDependencyLicenses, ORT/licensee if installed else the built-in
// deps.dev fallback) plus the LICENSE-file text scan above, normalized into
// the same addressable-issue shape phase 4's findings use (collectLicenseIssues)
// so commercial/copyleft/unrecognized licenses show up — and gate a run —
// like any other flagged issue, not only in the on-demand Dependencies view.
// Never throws: a deps.dev network hiccup shouldn't fail structure audit.
async function runLicenseComplianceCheck(projectRoot, log) {
  log('Check 5 — dependency & license compliance scan (manifests + LICENSE files)...');
  try {
    const [licenseScan, licenseFileFindings] = await Promise.all([
      scanDependencyLicenses(projectRoot, log),
      scanProjectLicenseFiles(projectRoot),
    ]);
    const licenseIssues = collectLicenseIssues({ manifests: licenseScan.manifests, licenseFiles: licenseFileFindings })
      .map((issue) => ({ ...issue, phase: 3 }));
    if (licenseIssues.length > 0) {
      const blocking = licenseIssues.filter((i) => i.severity === 'error').length;
      log(`⚠ ${licenseIssues.length} license compliance finding(s) (${blocking} commercial/blocking):`);
      licenseIssues.forEach((li) => log(`    ${li.severity === 'error' ? '✗' : '⚠'} ${li.file}${li.line ? ':' + li.line : ''} — ${li.summary}`));
    } else {
      log('✓ Check 5 passed — no commercial/restrictive licenses detected.');
    }
    return licenseIssues;
  } catch (e) {
    log(`⚠ License compliance scan failed (non-blocking): ${e.message}`);
    return [];
  }
}

// Same wiring as runLicenseComplianceCheck immediately above, for
// scanDependencyVulnerabilities' deps.dev-backed CVE/GHSA findings — that
// scanner already existed (Studio's Dependencies view, POST
// /api/dependencies/vulnerabilities, the MCP check_dependency_vulnerabilities
// tool) but never gated a run; this is what makes a known-critical
// dependency vulnerability block onboarding the same way a commercial
// license or a hardcoded secret does. Never throws: a deps.dev network
// hiccup shouldn't fail structure audit.
async function runDependencyVulnerabilityCheck(projectRoot, log) {
  log('Check 6 — dependency vulnerability scan (known CVE/GHSA advisories via deps.dev)...');
  try {
    const manifests = await scanDependencyVulnerabilities(projectRoot);
    const vulnIssues = collectDependencyVulnerabilityIssues({ manifests }).map((issue) => ({ ...issue, phase: 3 }));
    if (vulnIssues.length > 0) {
      const blocking = vulnIssues.filter((i) => i.severity === 'error').length;
      log(`⚠ ${vulnIssues.length} dependency vulnerability finding(s) (${blocking} critical/high — CVSS ≥7):`);
      vulnIssues.forEach((vi) => log(`    ${vi.severity === 'error' ? '✗' : '⚠'} ${vi.file}${vi.line ? ':' + vi.line : ''} — ${vi.summary}`));
    } else {
      log('✓ Check 6 passed — no known vulnerabilities found in resolved dependencies.');
    }
    return vulnIssues;
  } catch (e) {
    log(`⚠ Dependency vulnerability scan failed (non-blocking): ${e.message}`);
    return [];
  }
}

const { mountDependenciesRoutes } = require('./routes/dependencies');
mountDependenciesRoutes(app, { sanitizeAbsoluteProjectPath, scanDependencyLicenses, scanDependencyVulnerabilities });

const { mountReportsRoutes } = require('./routes/reports');
mountReportsRoutes(app, { sanitizeAbsoluteProjectPath, generateSbom, generateLocMetrics, checkFeaturePosture });

const { mountAutoFixRoute } = require('./routes/auto-fix');
mountAutoFixRoute(app, { sanitizeAbsoluteProjectPath, checkDeadCode });

const { mountBaselineRoutes } = require('./routes/baseline');
mountBaselineRoutes(app, { store });

const { mountRuntimeCoverageRoutes } = require('./routes/runtime-coverage');
mountRuntimeCoverageRoutes(app, { store });

const { mountIssuesRoutes } = require('./routes/issues');
mountIssuesRoutes(app, { store, llmAvailableCached, llmComplete });

const { mountReviewGateRoutes } = require('./routes/review-gate');
mountReviewGateRoutes(app, {
  store, auth, reviewDecisions, pendingEffectivations, cleanupExpiredEffectivations,
  resolveActor, validateOverrides, recordOverrides, cloneDirectoryWithoutSymlinks,
  archivePhase6Payload, shipToGitHub, phaseTitles: PHASE_TITLES,
});

const { mountValidateAllRoute } = require('./routes/pipeline-validate');
mountValidateAllRoute(app, {
  store,
  phaseEnabled: PHASE_ENABLED,
  phaseTitles: PHASE_TITLES,
  repoNameRegex: REPO_NAME_REGEX,
  githubNameRegex: GITHUB_NAME_REGEX,
  actEvent: ACT_EVENT,
  sanitizeAbsoluteProjectPath,
  resolveRequestSource,
  stageExistingProject,
  resolveProjectRoot,
  checkEnvFiles,
  checkCodeowners,
  runProjectUnitTests,
  runLicenseComplianceCheck,
  runDependencyVulnerabilityCheck,
  runPhase4Checks,
  validateOverrides,
  resolveActor,
  recordOverrides,
  actTooling,
  fetchGovernanceWorkflow,
  runActionsLocally,
});

const { mountOnboardRoute } = require('./routes/pipeline-onboard');
mountOnboardRoute(app, {
  store,
  auth,
  phaseEnabled: PHASE_ENABLED,
  phaseTitles: PHASE_TITLES,
  repoNameRegex: REPO_NAME_REGEX,
  githubNameRegex: GITHUB_NAME_REGEX,
  actEvent: ACT_EVENT,
  sanitizeAbsoluteProjectPath,
  resolveRequestSource,
  stageExistingProject,
  resolveProjectRoot,
  cloneDirectoryWithoutSymlinks,
  checkEnvFiles,
  checkCodeowners,
  runProjectUnitTests,
  runLicenseComplianceCheck,
  runDependencyVulnerabilityCheck,
  runPhase4Checks,
  validateOverrides,
  resolveActor,
  recordOverrides,
  actTooling,
  fetchGovernanceWorkflow,
  runActionsLocally,
  archivePhase6Payload,
  shipToGitHub,
});

const { mountInteractivePipelineRoute, mountErrorMiddleware } = require('./routes/pipeline-interactive');
mountInteractivePipelineRoute(app, {
  upload,
  store,
  auth,
  phaseEnabled: PHASE_ENABLED,
  phaseTitles: PHASE_TITLES,
  repoNameRegex: REPO_NAME_REGEX,
  githubNameRegex: GITHUB_NAME_REGEX,
  actEvent: ACT_EVENT,
  scoreForIssue,
  resolveRequestSource,
  extractZip,
  stageDirectoryUpload,
  resolveProjectRoot,
  cloneDirectoryWithoutSymlinks,
  runLicenseComplianceCheck,
  runDependencyVulnerabilityCheck,
  checkEnvFiles,
  checkCodeowners,
  runProjectUnitTests,
  runPhase4Checks,
  actTooling,
  fetchGovernanceWorkflow,
  runActionsLocally,
  resolveGovernanceCiLocation,
  filterGovernanceCiFailureLines,
  reviewDecisions,
  validateOverrides,
  recordOverrides,
  archivePhase6Payload,
  shipToGitHub,
  generateFailureInsight,
  sendFailureNotification,
  runningRuns,
  pendingEffectivations,
  cleanupExpiredEffectivations,
});
mountErrorMiddleware(app);

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Ignite (onboarding gatekeeper) running at http://localhost:${PORT}`);
  });

  // Scheduled re-checks on effectivated repos (see sweepScheduledRechecks) —
  // never runs under `require()` (tests, MCP tooling) so it can't fire real
  // `gh`/`git`/email/issue side effects outside the standalone server.
  setInterval(sweepScheduledRechecks, 15 * 60_000).unref();

  // Auto-starts the MCP server (Streamable HTTP transport) as a child
  // process, so `node server.js` / `npm start` is the one command needed —
  // no separate manual `npm run guidelines:mcp:http` step. Only runs here
  // (require.main === module), never when server.js is require()'d (tests,
  // etc.), so the test suite never leaks a spawned child process. Failure
  // to start (e.g. port already in use) is logged but never fatal to the
  // main server — MCP over HTTP is an addition, not a dependency.
  if (CONFIG.mcp.autoStart) {
    const mcpProc = spawn(
      process.execPath,
      [path.join(__dirname, 'mcp-server.js')],
      {
        env: {
          ...process.env,
          MCP_TRANSPORT: 'http',
          MCP_HTTP_PORT: String(CONFIG.mcp.httpPort),
          IGNITE_BASE_URL: `http://localhost:${PORT}`,
        },
        stdio: 'inherit',
      }
    );
    mcpProc.on('error', (err) => {
      console.error(`[mcp] could not start MCP HTTP server: ${err.message}`);
    });
    mcpProc.on('exit', (code, signal) => {
      if (code !== 0 && code !== null) {
        console.error(`[mcp] MCP HTTP server exited with code ${code}${signal ? ` (signal ${signal})` : ''} — the main server keeps running without it.`);
      }
    });
    const shutdownMcp = () => { mcpProc.kill(); };
    process.on('exit', shutdownMcp);
    process.on('SIGINT', () => { shutdownMcp(); process.exit(0); });
    process.on('SIGTERM', () => { shutdownMcp(); process.exit(0); });
  }
}

module.exports = {
  extractZip,
  MAX_EXTRACTED_BYTES,
  checkEnvFiles,
  checkSecrets,
  checkAiGovernance,
  runGitleaksScan,
  loadConfig,
  runProjectUnitTests,
  scanDependencyLicenses,
  runOrtAnalyze,
  runLicenseeDetect,
  scanProjectLicenseFiles,
  resolveGovernanceCiLocation,
  runLicenseComplianceCheck,
  runDependencyVulnerabilityCheck,
  scanDependencyVulnerabilities,
  classifyVulnerabilitySeverity,
  checkIacSecurity,
  runCheckovIacScan,
  runHadolintIacScan,
  checkContainerImageVulnerabilities,
  generateSbom,
  generateProvenance,
  digestProjectTree,
  checkImageProvenance,
  checkSemanticSast,
  checkPiiDataFlow,
  checkCodeDuplication,
  checkFileEncapsulation,
  generateLocMetrics,
  checkApiSchemas,
  checkApiSchemaDrift,
  checkFeaturePosture,
  checkComplianceDocuments,
  DOCUMENT_CATEGORIES,
  checkMaliciousDependencies,
  checkModelArtifactSecurity,
  checkPackageHallucination,
  checkCodeqlCrossFile,
  discoverCodeqlLanguages,
  normalizeWorkflowText,
  checkDeadCode,
  checkComplexityHealth,
  checkCssDeadCode,
  checkBoundaries,
};
