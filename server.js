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
const multer = require('multer');
const nodemailer = require('nodemailer');
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
const {
  collectPhase4Issues, collectLicenseIssues, collectDependencyVulnerabilityIssues, validateOverrides, scoreForIssue,
} = require('./override-engine');

/* ------------------------------------------------------------------ */
/* Configuration: config.json < environment variables                  */
/* ------------------------------------------------------------------ */

function loadConfig() {
  const defaults = {
    port: 3000,
    llm: { url: 'http://localhost:8050', model: 'default', mode: 'warn', maxFiles: 40, chunkChars: 10_000 },
    github: {
      orgs: '',
      bootstrapBranch: 'ignite',
      oauth: { clientId: '', clientSecret: '', redirectUri: '', scope: 'repo' },
    },
    governance: {
      repo: 'ai-governance-poc-2026/devops-governance',
      workflow: 'ai-guardrails-orchestrator.yml',
      event: 'pull_request',
      timeoutMinutes: 30,
    },
    notifications: {
      enabled: false,
      to: '',
      from: 'Ignite Gatekeeper <ignite@localhost>',
      smtp: { host: '', port: 587, secure: false, user: '' },
    },
    auth: {
      mode: 'standalone', // 'standalone' | 'oidc' | 'github'
      allowSelfRegistration: true,
      oidc: { issuer: '', clientId: '', clientSecret: '', redirectUri: '', scope: 'openid email profile' },
    },
    security: {
      // Optional: augments the built-in regex secret scan with gitleaks
      // (https://github.com/gitleaks/gitleaks) when installed. Soft-fails
      // (falls back to regex-only results) if disabled or the binary is
      // missing, so this is safe to leave off in environments without it.
      gitleaks: { enabled: false, binary: 'gitleaks', configPath: '' },
      // Optional: IaC/container misconfiguration scan (Dockerfiles,
      // Terraform, Kubernetes manifests, Helm charts) via Trivy's config
      // scanner (https://github.com/aquasecurity/trivy). Unlike gitleaks,
      // this is on by default — there's no equivalent built-in check to
      // "supplement", so Trivy is the primary source of IaC findings when
      // present. Soft-fails to a small built-in Dockerfile heuristic scan
      // (unpinned base image tag, missing USER) when disabled or missing.
      trivy: { enabled: true, binary: 'trivy' },
      // Optional: supplements trivy's IaC misconfig scan with Checkov's
      // (https://www.checkov.io/) much larger policy set — same relationship
      // gitleaks has to the regex secret scan, merged in and deduped by
      // file/line rather than replacing trivy's findings. On by default —
      // a heavier (Python) dependency than trivy/hadolint, but still a
      // soft-skip (no findings, not a failure) if it isn't installed.
      checkov: { enabled: true, binary: 'checkov' },
      // Optional: supplements trivy/checkov with hadolint's Dockerfile-only
      // rule set (https://github.com/hadolint/hadolint) — a small, fast
      // native binary, so on by default like trivy.
      hadolint: { enabled: true, binary: 'hadolint' },
      // Optional: verifies Sigstore/cosign keyless signatures on every
      // external base image referenced by a Dockerfile FROM (supply-chain
      // provenance), via `cosign verify` (https://github.com/sigstore/cosign).
      // On by default. Note this makes a real network call (registry +
      // Rekor transparency log) per unique image, adding latency and an
      // external-service dependency to every run that references one — set
      // COSIGN_ENABLED=false to opt back out if that's undesirable in your
      // environment. An unsigned/unverifiable image is reported as a
      // warning, never a blocking error — plenty of legitimate base images
      // (e.g. plain `ubuntu`) aren't cosign-signed.
      cosign: { enabled: true, binary: 'cosign', identityRegexp: '.*', issuerRegexp: '.*' },
      // Optional: semantic pattern-matching SAST via Semgrep OSS
      // (https://semgrep.dev) — logical flaws and injection-style sinks
      // beyond what the LLM deep-scan (Phase 4's other security check)
      // covers on its own. `config` is any semgrep --config value (a
      // registry pack like "p/security-audit", "auto", or a local rule
      // file/dir path). On by default; soft-skips (no native fallback —
      // there isn't a meaningful built-in substitute for a semantic rule
      // engine) when disabled or not installed.
      semgrep: { enabled: true, binary: 'semgrep', config: 'p/security-audit' },
      // Optional: sensitive data-flow (PII/GDPR) tracking via Bearer CLI
      // (https://github.com/Bearer/bearer) — traces personal data from
      // source (request params, user objects) to sinks (logs, DB writes,
      // 3rd-party calls) rather than pattern-matching single lines like
      // semgrep. On by default. Needs real git context (it shells out to
      // git for its own bookkeeping) — server.js's ensureGitContextForBearer
      // bootstraps a throwaway one for a fresh ZIP/folder upload
      // automatically, so this isn't something you need to set up.
      bearer: { enabled: true, binary: 'bearer' },
    },
    compliance: {
      // Optional: Compliance & Feature Posture Engine — scans for the
      // *presence* of security/compliance features (SSO, RBAC, audit
      // logging, TLS, backups, encryption at rest, rate limiting), not
      // vulnerabilities. Fully conditioned on Semgrep's presence (shares
      // security.semgrep's binary/tooling probe — same CLI, a separate
      // ruleset and enable flag): runs `semgrep --config=<ruleset>`
      // against ignite-posture-rules.yaml when connected, and soft-falls
      // back to a built-in regex pattern matcher (same category/tier
      // model, narrower coverage) when Semgrep is disabled or missing —
      // this scan never fails a run or blocks the pipeline either way.
      posture: { enabled: true, ruleset: path.join(__dirname, 'ignite-posture-rules.yaml') },
    },
    sbom: {
      // Optional: generates a CycloneDX SBOM for the staged project via
      // Syft (https://github.com/anchore/syft), attached as a downloadable
      // project document. On by default — Syft is a fast, self-contained
      // native binary. Soft-fails to a minimal manifest-derived component
      // list (name/version pairs from package.json/requirements.txt/etc,
      // no dependency graph or standards-format export) when missing, so a
      // run is never blocked on it.
      syft: { enabled: true, binary: 'syft' },
    },
    metrics: {
      // Optional: code-duplication detection via jscpd
      // (https://github.com/kucherenko/jscpd) — flagged clones become
      // 'code-duplication' issues (quality-level, always a warning, never
      // blocking). Off by default. No built-in fallback: duplicate-block
      // detection needs the real tool, so this simply contributes nothing
      // when disabled/missing.
      // minLines/minTokens (jscpd's own defaults) are now passed to the
      // CLI explicitly rather than left implicit, and checkCodeDuplication
      // additionally drops any reported clone shorter than minLines or
      // whose duplicated span is pure punctuation (stray closing
      // brackets/braces) — jscpd's per-clone `lines` count can otherwise
      // undercount a dense, bracket-heavy line that clears minTokens while
      // spanning ~1 real line, surfacing single-line/bracket-only
      // "duplicates" that aren't a meaningful block.
      // ignorePatterns (jscpd's own --ignore glob syntax) excludes two
      // categories that duplication-scan real runs consistently surface as
      // noise, not maintenance risk: (1) generated/design-export content —
      // e.g. Stitch/Figma-to-code static mockups under docs/** — which are
      // independently exported snapshots never meant to share a component
      // tree, so "dedupe this" has no actionable target; (2) test files,
      // where fixture/setup duplication across suites is standard practice
      // (keeps suites independent) rather than logic that could drift.
      // Override per-project via JSCPD_IGNORE (comma-separated globs) if a
      // repo's docs/tests genuinely do contain shippable, dedupe-worthy code.
      jscpd: {
        enabled: false, binary: 'jscpd', minLines: 5, minTokens: 50,
        ignorePatterns: ['docs/**', '**/*.test.*', '**/*.spec.*', '**/__tests__/**'],
      },
      // Optional: precise per-language LOC counts via gocloc
      // (https://github.com/hhatto/gocloc) — purely descriptive, attached
      // as a downloadable project document (same as the SBOM), never
      // produces issues. On by default.
      gocloc: { enabled: true, binary: 'gocloc' },
    },
    api: {
      // Optional: lints OpenAPI/AsyncAPI schema files against Spectral's
      // built-in rulesets (https://github.com/stoplightio/spectral) — org
      // REST/AsyncAPI conventions, not just schema validity. `ruleset` is
      // any spectral --ruleset path/URL; defaults to a small bundled file
      // (spectral-default-ruleset.yaml) extending spectral:oas +
      // spectral:asyncapi. On by default. No built-in fallback: schema
      // linting needs the real rule engine, so this simply contributes
      // nothing when disabled/missing, or when no matching files exist.
      spectral: { enabled: true, binary: 'spectral', ruleset: path.join(__dirname, 'spectral-default-ruleset.yaml') },
    },
    // Optional per-phase title/description/enabled overrides, e.g.:
    //   "phases": [{ "id": 4, "enabled": false }]
    // Matched by id; any phase not listed (or the whole key omitted) keeps
    // its built-in title/description/enabled state exactly as shipped.
    // Phases 1 (input validation), 3 (extraction/structure audit) and 6
    // (provisioning/shipping) can't be disabled — everything downstream
    // depends on them — so an `enabled: false` override on those ids is
    // ignored. Phase 2 (GxP) defaults to disabled: most orgs onboarding
    // through Ignite aren't running a GxP-regulated process, so the
    // declaration + mandatory validation-document UI stays hidden, and the
    // phase itself is never checked, until explicitly turned on.
    phases: [],
    mcp: {
      // Auto-starts mcp-server.js (Streamable HTTP transport) as a child
      // process alongside this one, so MCP clients that want HTTP (rather
      // than spawning their own stdio instance per the editor's own
      // .mcp.json) have somewhere to connect without a separate manual
      // step. Purely additive — stdio-mode MCP (the editor spawning
      // mcp-server.js itself) works exactly as before regardless of this.
      autoStart: true,
      httpPort: 3001,
    },
  };
  // Same override convention as IGNITE_DB_PATH — lets the test suite (see
  // test/helpers.js's withServerEnv) point at an empty fixture file instead
  // of this developer's real, locally-customized config.json, so tests
  // asserting on *default* values stay hermetic regardless of what's
  // actually configured on this machine.
  const configPath = process.env.IGNITE_CONFIG_PATH || path.join(__dirname, 'config.json');
  let fileConfig = {};
  try {
    fileConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  } catch (err) {
    if (err.code !== 'ENOENT') {
      console.error(`${configPath} is invalid (${err.message}) — using defaults.`);
    }
  }
  const merge = (base, over) =>
    Object.fromEntries(
      Object.keys(base).map((k) => [
        k,
        over?.[k] !== undefined && typeof base[k] === 'object' && base[k] !== null
          ? merge(base[k], over[k])
          : over?.[k] !== undefined ? over[k] : base[k],
      ])
    );
  const merged = merge(defaults, fileConfig);
  // `merge` deep-merges plain objects keyed by the *default's* own keys —
  // useless for an empty-by-default array like `phases`, since there are no
  // default keys to walk. Arrays are a replace, not a merge.
  merged.phases = Array.isArray(fileConfig.phases) ? fileConfig.phases : [];
  const smtpPass =
    process.env.NOTIFICATIONS_SMTP_PASS ||
    process.env.SMTP_PASS ||
    process.env.SMTP_PASSWORD ||
    '';
  if (smtpPass) {
    merged.notifications.smtp.pass = smtpPass;
  }
  if (process.env.AUTH_MODE) merged.auth.mode = process.env.AUTH_MODE;
  if (process.env.OIDC_CLIENT_SECRET) merged.auth.oidc.clientSecret = process.env.OIDC_CLIENT_SECRET;
  if (process.env.GITLEAKS_ENABLED !== undefined) {
    merged.security.gitleaks.enabled = String(process.env.GITLEAKS_ENABLED) === 'true';
  }
  if (process.env.GITLEAKS_BINARY) merged.security.gitleaks.binary = process.env.GITLEAKS_BINARY;
  if (process.env.GITLEAKS_CONFIG_PATH) merged.security.gitleaks.configPath = process.env.GITLEAKS_CONFIG_PATH;
  if (process.env.TRIVY_ENABLED !== undefined) {
    merged.security.trivy.enabled = String(process.env.TRIVY_ENABLED) === 'true';
  }
  if (process.env.TRIVY_BINARY) merged.security.trivy.binary = process.env.TRIVY_BINARY;
  if (process.env.CHECKOV_ENABLED !== undefined) {
    merged.security.checkov.enabled = String(process.env.CHECKOV_ENABLED) === 'true';
  }
  if (process.env.CHECKOV_BINARY) merged.security.checkov.binary = process.env.CHECKOV_BINARY;
  if (process.env.HADOLINT_ENABLED !== undefined) {
    merged.security.hadolint.enabled = String(process.env.HADOLINT_ENABLED) === 'true';
  }
  if (process.env.HADOLINT_BINARY) merged.security.hadolint.binary = process.env.HADOLINT_BINARY;
  if (process.env.COSIGN_ENABLED !== undefined) {
    merged.security.cosign.enabled = String(process.env.COSIGN_ENABLED) === 'true';
  }
  if (process.env.COSIGN_BINARY) merged.security.cosign.binary = process.env.COSIGN_BINARY;
  if (process.env.COSIGN_IDENTITY_REGEXP) merged.security.cosign.identityRegexp = process.env.COSIGN_IDENTITY_REGEXP;
  if (process.env.COSIGN_ISSUER_REGEXP) merged.security.cosign.issuerRegexp = process.env.COSIGN_ISSUER_REGEXP;
  if (process.env.SEMGREP_ENABLED !== undefined) {
    merged.security.semgrep.enabled = String(process.env.SEMGREP_ENABLED) === 'true';
  }
  if (process.env.SEMGREP_BINARY) merged.security.semgrep.binary = process.env.SEMGREP_BINARY;
  if (process.env.SEMGREP_CONFIG) merged.security.semgrep.config = process.env.SEMGREP_CONFIG;
  if (process.env.BEARER_ENABLED !== undefined) {
    merged.security.bearer.enabled = String(process.env.BEARER_ENABLED) === 'true';
  }
  if (process.env.BEARER_BINARY) merged.security.bearer.binary = process.env.BEARER_BINARY;
  if (process.env.POSTURE_ENABLED !== undefined) {
    merged.compliance.posture.enabled = String(process.env.POSTURE_ENABLED) === 'true';
  }
  if (process.env.POSTURE_RULESET) merged.compliance.posture.ruleset = process.env.POSTURE_RULESET;
  if (process.env.JSCPD_ENABLED !== undefined) {
    merged.metrics.jscpd.enabled = String(process.env.JSCPD_ENABLED) === 'true';
  }
  if (process.env.JSCPD_BINARY) merged.metrics.jscpd.binary = process.env.JSCPD_BINARY;
  if (process.env.JSCPD_MIN_LINES) merged.metrics.jscpd.minLines = Number(process.env.JSCPD_MIN_LINES);
  if (process.env.JSCPD_MIN_TOKENS) merged.metrics.jscpd.minTokens = Number(process.env.JSCPD_MIN_TOKENS);
  if (process.env.JSCPD_IGNORE !== undefined) {
    merged.metrics.jscpd.ignorePatterns = process.env.JSCPD_IGNORE.split(',').map((p) => p.trim()).filter(Boolean);
  }
  if (process.env.GOCLOC_ENABLED !== undefined) {
    merged.metrics.gocloc.enabled = String(process.env.GOCLOC_ENABLED) === 'true';
  }
  if (process.env.GOCLOC_BINARY) merged.metrics.gocloc.binary = process.env.GOCLOC_BINARY;
  if (process.env.SPECTRAL_ENABLED !== undefined) {
    merged.api.spectral.enabled = String(process.env.SPECTRAL_ENABLED) === 'true';
  }
  if (process.env.SPECTRAL_BINARY) merged.api.spectral.binary = process.env.SPECTRAL_BINARY;
  if (process.env.SPECTRAL_RULESET) merged.api.spectral.ruleset = process.env.SPECTRAL_RULESET;
  if (process.env.SYFT_ENABLED !== undefined) {
    merged.sbom.syft.enabled = String(process.env.SYFT_ENABLED) === 'true';
  }
  if (process.env.SYFT_BINARY) merged.sbom.syft.binary = process.env.SYFT_BINARY;
  if (process.env.MCP_AUTOSTART !== undefined) merged.mcp.autoStart = String(process.env.MCP_AUTOSTART) === 'true';
  if (process.env.MCP_HTTP_PORT) merged.mcp.httpPort = Number(process.env.MCP_HTTP_PORT);
  return merged;
}

const CONFIG = loadConfig();

const store = createDbStore(process.env.IGNITE_DB_PATH || path.join(__dirname, 'ignite.db'));
store.abortStaleRunningProjects();

const PORT = process.env.PORT || CONFIG.port;
const MAX_ZIP_BYTES = 250 * 1024 * 1024; // 250 MB upload cap
const MAX_EXTRACTED_BYTES = 1024 * 1024 * 1024; // zip-bomb guard
const MAX_SCAN_FILE_BYTES = 5 * 1024 * 1024; // skip huge files in text scans

const app = express();
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
  limits: { fileSize: MAX_ZIP_BYTES, files: 5000 },
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
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || CONFIG.llm.openai?.apiKey || '';
const OPENAI_BASE_URL = String(process.env.OPENAI_BASE_URL || CONFIG.llm.openai?.baseUrl || 'https://api.openai.com/v1').replace(/\/+$/, '');
const OPENAI_MODEL = process.env.OPENAI_MODEL || CONFIG.llm.openai?.model || 'gpt-4o-mini';
if (LLM_PROVIDER === 'openai' && !/^https:\/\//i.test(OPENAI_BASE_URL) && !/^http:\/\/(localhost|127\.0\.0\.1)/i.test(OPENAI_BASE_URL)) {
  throw new Error(`OPENAI_BASE_URL must use https (got ${OPENAI_BASE_URL}).`);
}

// Resolves the effective chat-completions endpoint/model/auth for whichever
// provider is configured, so llmChat/llmComplete/llmAvailable don't need to
// know which backend they're talking to.
function llmTarget() {
  if (LLM_PROVIDER === 'openai') {
    return {
      url: `${OPENAI_BASE_URL}/chat/completions`,
      model: OPENAI_MODEL,
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${OPENAI_API_KEY}` },
    };
  }
  return {
    url: `${LLM_SCAN_URL}/v1/chat/completions`,
    model: LLM_SCAN_MODEL,
    headers: { 'Content-Type': 'application/json' },
  };
}

const LLM_SOURCE_EXTS = Object.freeze(new Set([
  '.py', '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs', '.go', '.rb', '.php',
  '.java', '.cs', '.sh', '.yaml', '.yml', '.json', '.sql', '.tf',
])) ;

// Captures the quote char (if any) separately from the value so callers can
// tell a string literal from a bare identifier/property-access reference —
// e.g. `password: clientSecret` or `token = res.data.access_token` are
// variable references (unquoted is only ever code syntax in a source file),
// while `apiKey: 'sk-proj-...'` is an inline literal.
const SECRET_REGEX =
  /(password|aws_secret|api_key|token|private_key)\s*[:=]\s*(['"]?)([a-zA-Z0-9_\-.~]{10,})/i;

// In source code, an unquoted RHS is always identifier/property-access
// syntax (a variable, `process.env.X`, `res.data.access_token`, ...) — never
// a literal. Config/env formats (.env, YAML, INI, ...) have no such quoting
// rule, so unquoted values there can genuinely be inline secrets.
const SECRET_SCAN_CODE_EXTS = Object.freeze(new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py', '.go', '.rb', '.php',
  '.java', '.kt', '.cs', '.c', '.cpp', '.h', '.hpp', '.swift', '.rs', '.scala',
]));

function isLikelySecretValue(quote, ext) {
  return Boolean(quote) || !SECRET_SCAN_CODE_EXTS.has(ext);
}

/* Optional gitleaks-powered secret scan (see CONFIG.security.gitleaks) */
const GITLEAKS_ENABLED = Boolean(CONFIG.security.gitleaks.enabled);
const GITLEAKS_BINARY = String(CONFIG.security.gitleaks.binary || 'gitleaks');
const GITLEAKS_CONFIG_PATH = String(CONFIG.security.gitleaks.configPath || '');

/* Optional trivy-powered IaC/container misconfig scan (see CONFIG.security.trivy) */
const TRIVY_ENABLED = Boolean(CONFIG.security.trivy.enabled);
const TRIVY_BINARY = String(CONFIG.security.trivy.binary || 'trivy');

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

/* Optional semgrep-powered semantic SAST scan (see CONFIG.security.semgrep) */
const SEMGREP_ENABLED = Boolean(CONFIG.security.semgrep.enabled);
const SEMGREP_BINARY = String(CONFIG.security.semgrep.binary || 'semgrep');
const SEMGREP_CONFIG = String(CONFIG.security.semgrep.config || 'p/security-audit');

/* Optional bearer-powered PII/GDPR data-flow scan (see CONFIG.security.bearer) */
const BEARER_ENABLED = Boolean(CONFIG.security.bearer.enabled);
const BEARER_BINARY = String(CONFIG.security.bearer.binary || 'bearer');

/* Optional Compliance & Feature Posture Engine — shares SEMGREP_BINARY (see CONFIG.compliance.posture) */
const POSTURE_ENABLED = Boolean(CONFIG.compliance.posture.enabled);
const POSTURE_RULESET = String(CONFIG.compliance.posture.ruleset || path.join(__dirname, 'ignite-posture-rules.yaml'));

/* Optional jscpd-powered code-duplication scan (see CONFIG.metrics.jscpd) */
const JSCPD_ENABLED = Boolean(CONFIG.metrics.jscpd.enabled);
const JSCPD_BINARY = String(CONFIG.metrics.jscpd.binary || 'jscpd');
const JSCPD_MIN_LINES = Number(CONFIG.metrics.jscpd.minLines) || 5;
const JSCPD_MIN_TOKENS = Number(CONFIG.metrics.jscpd.minTokens) || 50;
const JSCPD_IGNORE_PATTERNS = Array.isArray(CONFIG.metrics.jscpd.ignorePatterns) ? CONFIG.metrics.jscpd.ignorePatterns : [];

/* Optional gocloc-powered LOC metrics (see CONFIG.metrics.gocloc) */
const GOCLOC_ENABLED = Boolean(CONFIG.metrics.gocloc.enabled);
const GOCLOC_BINARY = String(CONFIG.metrics.gocloc.binary || 'gocloc');

/* Optional spectral-powered API schema lint (see CONFIG.api.spectral) */
const SPECTRAL_ENABLED = Boolean(CONFIG.api.spectral.enabled);
const SPECTRAL_BINARY = String(CONFIG.api.spectral.binary || 'spectral');
const SPECTRAL_RULESET = String(CONFIG.api.spectral.ruleset || path.join(__dirname, 'spectral-default-ruleset.yaml'));

const AI_INVOKE_REGEX = /\.(invoke|stream|ainvoke|astream)\(/;

const SKIP_DIRS = Object.freeze(new Set([
  'node_modules',
  '.git',
  '.next',
  'dist',
  'build',
  '__pycache__',
  '.venv',
  'venv',
  'vendor',
  '.idea',
  '.vscode',
])) ;

// Same directory names as SKIP_DIRS, as a regex for external tools that
// take their own exclude pattern (gocloc's --not-match-d, used with
// --fullpath) instead of doing the walk themselves — keeps
// generateLocMetrics's file set in sync with walkFiles's, so a language
// filtered in Studio's LOC Metrics view always has matching entries in the
// Studio file tree built from walkFiles. Must be anchored on '/' on both
// sides (not '^...$') — gocloc matches --not-match-d against the full
// path, so an unanchored-at-both-ends alternation like '^(node_modules|...)$'
// only ever matches a path consisting of nothing but that one directory
// name, never a real nested path like '.../node_modules/pkg/native.c'.
const SKIP_DIRS_REGEX = `(^|/)(${[...SKIP_DIRS].map((d) => d.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})(/|$)`;

const BINARY_EXTENSIONS = Object.freeze(new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.bmp', '.tiff',
  '.pdf', '.zip', '.gz', '.tar', '.bz2', '.7z', '.rar',
  '.woff', '.woff2', '.ttf', '.otf', '.eot',
  '.mp3', '.mp4', '.mov', '.avi', '.mkv', '.wav', '.ogg',
  '.exe', '.dll', '.so', '.dylib', '.bin', '.o', '.a', '.class',
  '.pyc', '.wasm', '.jar', '.db', '.sqlite', '.sqlite3',
])) ;

const GITHUB_NAME_REGEX = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/; // org login rules
const REPO_NAME_REGEX = /^[A-Za-z0-9._-]{1,100}$/;
const SAFE_UPLOAD_SEGMENT_REGEX = /^[^\0/\\]+$/;
const ALLOWED_COMMANDS = Object.freeze(new Set(['git', 'gh', 'act', 'docker', 'gitleaks', 'licensee', 'ort', 'trivy', 'checkov', 'hadolint', 'syft', 'cosign', 'semgrep', 'bearer', 'jscpd', 'gocloc', 'spectral']));

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

function looksBinary(buffer) {
  // NUL byte in the first 8 KB is the classic binary heuristic.
  const slice = buffer.subarray(0, 8192);
  return slice.includes(0);
}

/**
 * Captures a few lines of context around a finding so the review UI can show
 * a code preview with the offending span highlighted, instead of a bare
 * file:line reference.
 */
function buildSnippet(content, lineNumber, { colStart, colEnd, radius = 3 } = {}) {
  if (typeof content !== 'string' || !Number.isInteger(lineNumber) || lineNumber < 1) return null;
  const lines = content.split(/\r?\n/);
  const idx = lineNumber - 1;
  if (idx >= lines.length) return null;

  const start = Math.max(0, idx - radius);
  const end = Math.min(lines.length - 1, idx + radius);
  const code = [];
  for (let i = start; i <= end; i++) code.push({ number: i + 1, text: lines[i] });

  const snippet = { startLine: start + 1, lines: code, highlightLine: lineNumber };
  if (Number.isInteger(colStart) && Number.isInteger(colEnd) && colEnd > colStart) {
    snippet.highlightStart = colStart;
    snippet.highlightEnd = colEnd;
  }
  return snippet;
}

async function* walkFiles(root) {
  const entries = await fsp.readdir(root, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue; // never follow symlinks out of staging
    const full = path.join(root, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      yield* walkFiles(full);
    } else if (entry.isFile()) {
      yield full;
    }
  }
}

function runTool(tool, args, cwd, { env: envOverride = {}, allowedExitCodes = [0] } = {}) {
  return new Promise((resolve, reject) => {
    const safeTool = sanitizeCommand(tool);
    const safeArgs = sanitizeCliArgs(args);
    const safeCwd = sanitizeCwd(cwd);
    const env = sanitizeEnv({ ...process.env, GIT_TERMINAL_PROMPT: '0', ...envOverride });

    const execute = (command) => execFile(
      command,
      safeArgs,
      { cwd: safeCwd, env, timeout: 120_000, maxBuffer: 10 * 1024 * 1024 },
      (err, stdout, stderr) => {
        // ORT's analyzer exits 2 (not 0) whenever it found issues at/above
        // its severity threshold — a normal outcome, not a tool failure —
        // while still writing a complete analyzer-result.json. Callers that
        // need this (runOrtAnalyze) opt in via allowedExitCodes.
        if (err && !allowedExitCodes.includes(err.code)) {
          const detail = (stderr || stdout || err.message || '').trim();
          reject(new Error(`\`${command} ${safeArgs.join(' ')}\` failed: ${detail}`));
        } else {
          resolve({ stdout: stdout.trim(), stderr: stderr.trim() });
        }
      }
    );

    switch (safeTool) {
      case 'git': return execute('git');
      case 'gh': return execute('gh');
      case 'act': return execute('act');
      case 'docker': return execute('docker');
      case 'gitleaks': return execute(GITLEAKS_BINARY);
      case 'licensee': return execute('licensee');
      case 'ort': return execute('ort');
      case 'trivy': return execute(TRIVY_BINARY);
      case 'checkov': return execute(CHECKOV_BINARY);
      case 'hadolint': return execute(HADOLINT_BINARY);
      case 'syft': return execute(SYFT_BINARY);
      case 'cosign': return execute(COSIGN_BINARY);
      case 'semgrep': return execute(SEMGREP_BINARY);
      case 'bearer': return execute(BEARER_BINARY);
      case 'jscpd': return execute(JSCPD_BINARY);
      case 'gocloc': return execute(GOCLOC_BINARY);
      case 'spectral': return execute(SPECTRAL_BINARY);
      default: return reject(new Error(`Unsupported command: ${safeTool}`));
    }
  });
}

function sanitizeCliArg(value, label) {
  const s = String(value ?? '');
  if (!s) throw new Error(`${label} cannot be empty.`);
  if (/\0|\r|\n/.test(s)) throw new Error(`${label} contains illegal control characters.`);
  return s;
}

function sanitizeCommand(cmd) {
  const safeCmd = sanitizeCliArg(cmd, 'Command');
  if (!ALLOWED_COMMANDS.has(safeCmd)) {
    throw new Error(`Command is not allowed: ${safeCmd}`);
  }
  return safeCmd;
}

function sanitizeCliArgs(args) {
  if (!Array.isArray(args)) throw new Error('Command arguments must be an array.');
  return args.map((arg, i) => sanitizeCliArg(arg, `Argument #${i + 1}`));
}

function sanitizeCwd(cwd) {
  const s = String(cwd ?? '').trim();
  if (!s) throw new Error('Working directory is required.');
  if (/\0|\r|\n/.test(s)) throw new Error('Working directory contains illegal control characters.');
  return s;
}

function sanitizeAbsoluteProjectPath(projectPath) {
  const safePath = sanitizeCwd(projectPath);
  if (!path.isAbsolute(safePath)) {
    throw new Error('projectPath must be an absolute path.');
  }
  return path.resolve(safePath);
}

function sanitizeEnv(env) {
  const sanitized = {};
  for (const [key, value] of Object.entries(env || {})) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;
    const str = String(value ?? '');
    if (/\0/.test(str)) continue;
    sanitized[key] = str;
  }
  return sanitized;
}

function sanitizeUploadRelativePath(rawPath) {
  const rel = String(rawPath ?? '').replace(/\\/g, '/').trim();
  if (!rel || rel.includes('\0')) {
    throw new Error(`Invalid path in folder upload: ${JSON.stringify(rawPath)}`);
  }
  if (rel.startsWith('/') || rel.startsWith('~/') || /^[A-Za-z]:\//.test(rel)) {
    throw new Error(`Absolute paths are not allowed in folder upload: ${rel}`);
  }

  const normalized = path.posix.normalize(rel);
  if (normalized === '.' || normalized.startsWith('../') || normalized.includes('/../')) {
    throw new Error(`Blocked path traversal entry in folder upload: ${rel}`);
  }

  for (const segment of normalized.split('/')) {
    if (!segment || segment === '.' || segment === '..') {
      throw new Error(`Invalid path segment in folder upload: ${rel}`);
    }
    if (!SAFE_UPLOAD_SEGMENT_REGEX.test(segment)) {
      throw new Error(`Invalid characters in folder upload path: ${rel}`);
    }
  }
  return normalized;
}

/**
 * Long-running command with live line-by-line output streaming (used for
 * `act`, whose runs take minutes and produce continuous logs).
 */
// eslint-disable-next-line no-control-regex
const ANSI_REGEX = /\x1b\[[0-9;]*[a-zA-Z]/g;
const FAILURE_LINE_REGEX = /❌|::error|error:|fatal:|\bfailure\b/i;

// A non-zero exit code alone ("`act` exited with code 1.") tells you nothing
// about what actually broke — the real cause is buried in the streamed
// stdout/stderr. Pull out every line that looks like an actual failure
// (marked with ❌, "Error:", "fatal:", "Failure -", etc.), deduped, so a
// caller can either summarize it (extractFailureDetail) or report each one
// as its own finding instead of one generic "exited with code N" blob.
function extractFailureLines(lines) {
  const seen = new Set();
  const out = [];
  for (const raw of lines) {
    const l = raw.replace(ANSI_REGEX, '').trim();
    if (l && FAILURE_LINE_REGEX.test(l) && !seen.has(l)) { seen.add(l); out.push(l); }
  }
  return out;
}

function runToolStreaming(tool, args, cwd, onLine, { timeoutMs = 15 * 60_000, env = {} } = {}) {
  return new Promise((resolve, reject) => {
    const safeTool = sanitizeCommand(tool);
    const safeArgs = sanitizeCliArgs(args);
    const safeCwd = sanitizeCwd(cwd);
    const safeEnv = sanitizeEnv({ ...process.env, GIT_TERMINAL_PROMPT: '0', ...env });

    let child;
    let commandLabel;
    switch (safeTool) {
      case 'git':
        commandLabel = 'git';
        child = spawn('git', safeArgs, { cwd: safeCwd, env: safeEnv });
        break;
      case 'gh':
        commandLabel = 'gh';
        child = spawn('gh', safeArgs, { cwd: safeCwd, env: safeEnv });
        break;
      case 'act':
        commandLabel = 'act';
        child = spawn('act', safeArgs, { cwd: safeCwd, env: safeEnv });
        break;
      case 'docker':
        commandLabel = 'docker';
        child = spawn('docker', safeArgs, { cwd: safeCwd, env: safeEnv });
        break;
      default:
        reject(new Error(`Unsupported command: ${safeTool}`));
        return;
    }

    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`\`${commandLabel}\` timed out after ${timeoutMs / 60000} minutes.`));
    }, timeoutMs);

    let pending = { out: '', err: '' };
    const capturedLines = [];
    const feed = (key) => (chunk) => {
      pending[key] += chunk.toString();
      const lines = pending[key].split('\n');
      pending[key] = lines.pop();
      lines.forEach((l) => { if (l.trim()) { capturedLines.push(l); onLine(l); } });
    };
    child.stdout.on('data', feed('out'));
    child.stderr.on('data', feed('err'));
    child.on('error', (err) => { clearTimeout(timer); reject(err); });
    child.on('close', (code) => {
      clearTimeout(timer);
      Object.values(pending).forEach((rest) => { if (rest.trim()) { capturedLines.push(rest); onLine(rest); } });
      if (code === 0) { resolve(); return; }
      const failureLines = extractFailureLines(capturedLines);
      const detail = failureLines.length ? `Cause: ${failureLines.slice(-3).join(' | ')}` : '';
      const err = new Error(`\`${commandLabel}\` exited with code ${code}.${detail ? ` ${detail}` : ''}`);
      err.failureLines = failureLines;
      reject(err);
    });
  });
}

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

      totalBytes += Number(entry.size || 0);
      if (totalBytes > MAX_EXTRACTED_BYTES) {
        throw new Error('Archive exceeds maximum extracted size (possible zip bomb). Aborting.');
      }

      await fsp.mkdir(path.dirname(target), { recursive: true });
      const source = await zip.stream(entry.name);
      await new Promise((resolve, reject) => {
        const sink = fs.createWriteStream(target, { mode: 0o600 });
        source.on('error', reject);
        sink.on('error', reject);
        sink.on('finish', resolve);
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

// .env.example/.sample/.template/.dist/.defaults are the documented-defaults
// convention (see this project's own .env.example) — by design they hold no
// real secrets and are meant to be committed, so they're never flagged.
const ENV_TEMPLATE_SUFFIXES = ['.example', '.sample', '.template', '.dist', '.defaults'];
function isEnvTemplateFile(base) {
  const lower = base.toLowerCase();
  return lower.startsWith('.env') && ENV_TEMPLATE_SUFFIXES.some((suffix) => lower.endsWith(suffix));
}

// Minimal .gitignore matcher: last-matching pattern wins (negation with `!`
// supported), `*`/`**`/`?` handled, `/`-anchored vs anywhere-in-tree patterns
// distinguished. Good enough to recognize the common cases (`.env`, `.env*`)
// without pulling in a full gitignore-semantics dependency.
function gitignorePatternToRegex(rawPattern) {
  let pattern = rawPattern.trim();
  let negate = false;
  if (pattern.startsWith('!')) { negate = true; pattern = pattern.slice(1); }
  const anchored = pattern.startsWith('/');
  if (anchored) pattern = pattern.slice(1);
  if (pattern.endsWith('/')) pattern = pattern.slice(0, -1);
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, ' ')
    .replace(/\*/g, '[^/]*')
    .replace(/ /g, '.*')
    .replace(/\?/g, '[^/]');
  const regex = anchored
    ? new RegExp(`^${escaped}(/.*)?$`)
    : new RegExp(`(^|/)${escaped}(/.*)?$`);
  return { regex, negate };
}

function isGitignored(patterns, relPath) {
  const normalized = relPath.split(path.sep).join('/');
  let ignored = false;
  for (const { regex, negate } of patterns) {
    if (regex.test(normalized)) ignored = !negate;
  }
  return ignored;
}

// Shared by checkEnvFiles and checkSecrets: a file this pipeline will never
// commit/push (because the project's own .gitignore excludes it) poses no
// leak risk through this pipeline, so both checks exempt it the same way.
async function loadGitignorePatterns(root) {
  try {
    const content = await fsp.readFile(path.join(root, '.gitignore'), 'utf8');
    return content
      .split(/\r?\n/)
      .filter((l) => l.trim() && !l.trim().startsWith('#'))
      .map(gitignorePatternToRegex);
  } catch {
    return []; // no .gitignore at the project root — nothing to exempt
  }
}

function hashBuffer(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

/**
 * Per-file scan-result cache, keyed by (org, repo, checkName). Lets Phase 4's
 * checks (secrets/governance/LLM deep-scan) skip re-evaluating a file whose
 * content hash matches what was recorded on the previous run for the same
 * org/repo, reusing its stored findings instead. `cacheKey` is optional
 * ({ org, repo }) — callers with no project identity (e.g. tests) simply get
 * no caching.
 */
function loadFileScanCache(cacheKey, checkName) {
  if (!cacheKey || !cacheKey.org || !cacheKey.repo) return null;
  return store.getFileScanCache(cacheKey.org, cacheKey.repo, checkName);
}

// Replaces the full cache for this (org, repo, checkName) with `entries`, so
// files removed/renamed since the last run don't linger in the DB forever.
function saveFileScanCache(cacheKey, checkName, entries) {
  if (!cacheKey || !cacheKey.org || !cacheKey.repo) return;
  store.replaceFileScanCache(cacheKey.org, cacheKey.repo, checkName, entries);
}

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

async function checkSecrets(root, log, cacheKey) {
  const findings = [];
  let scanned = 0;
  let cacheHits = 0;
  let gitignoredSkipped = 0;
  const gitignorePatterns = await loadGitignorePatterns(root);
  const prevCache = loadFileScanCache(cacheKey, 'secrets');
  const newCacheEntries = [];

  for await (const file of walkFiles(root)) {
    const ext = path.extname(file).toLowerCase();
    if (BINARY_EXTENSIONS.has(ext)) continue;

    const rel = path.relative(root, file);
    if (gitignorePatterns.length > 0 && isGitignored(gitignorePatterns, rel)) {
      gitignoredSkipped++;
      continue;
    }

    const stat = await fsp.stat(file);
    if (stat.size > MAX_SCAN_FILE_BYTES) {
      log(`Skipping oversized file (${(stat.size / 1e6).toFixed(1)} MB): ${path.relative(root, file)}`);
      continue;
    }

    const buffer = await fsp.readFile(file);
    if (looksBinary(buffer)) continue;

    scanned++;
    const hash = hashBuffer(buffer);
    const cached = prevCache && prevCache.get(rel);
    if (cached && cached.hash === hash) {
      cacheHits++;
      findings.push(...cached.findings);
      newCacheEntries.push({ relPath: rel, hash, findings: cached.findings });
      continue;
    }

    const content = buffer.toString('utf8');
    const fileFindings = [];
    const lines = content.split(/\r?\n/);
    lines.forEach((line, i) => {
      const match = line.match(SECRET_REGEX);
      if (match && isLikelySecretValue(match[2], ext)) {
        fileFindings.push({
          file: rel,
          line: i + 1,
          kind: match[1].toLowerCase(),
          code: buildSnippet(content, i + 1, { colStart: match.index, colEnd: match.index + match[0].length }),
        });
      }
    });
    findings.push(...fileFindings);
    newCacheEntries.push({ relPath: rel, hash, findings: fileFindings });
  }

  saveFileScanCache(cacheKey, 'secrets', newCacheEntries);

  if (GITLEAKS_ENABLED) {
    log('Gitleaks enabled — running supplemental secret-detection scan...');
    // gitleaks walks the raw filesystem tree itself (--no-git), so it has no
    // gitignore awareness of its own — filter its findings the same way the
    // regex scan above was filtered.
    const gitleaksFindings = (await runGitleaksScan(root, log)).filter((f) => {
      const ignored = gitignorePatterns.length > 0 && isGitignored(gitignorePatterns, f.file);
      if (ignored) gitignoredSkipped++;
      return !ignored;
    });
    const seen = new Set(findings.map((f) => `${f.file}:${f.line}`));
    let added = 0;
    for (const f of gitleaksFindings) {
      const key = `${f.file}:${f.line}`;
      if (seen.has(key)) continue; // already caught by the regex scan
      seen.add(key);
      findings.push(f);
      added++;
    }
    log(`Gitleaks scan complete — ${gitleaksFindings.length} finding(s), ${added} new.`);
  }

  if (gitignoredSkipped > 0) {
    log(`ℹ ${gitignoredSkipped} gitignored file(s) excluded from credential scan — not blocking.`);
  }
  if (cacheHits > 0) {
    log(`♻ ${cacheHits} file(s) unchanged since the last run for this org/repo — reused cached results.`);
  }

  return { findings, scanned, cacheHits };
}

/**
 * Optional secret-detection pass using gitleaks (https://github.com/gitleaks/gitleaks),
 * when CONFIG.security.gitleaks.enabled is set. Soft-fails (returns no extra
 * findings) if the binary is missing or the scan errors, so a misconfigured
 * or absent install never breaks the pipeline — it just falls back to the
 * built-in regex scan.
 */
async function runGitleaksScan(root, log) {
  const reportPath = path.join(
    os.tmpdir(),
    `ignite-gitleaks-${crypto.randomBytes(8).toString('hex')}.json`
  );
  try {
    const args = ['detect', '--source', root, '--no-git', '--report-format', 'json',
      '--report-path', reportPath, '--exit-code', '0'];
    if (GITLEAKS_CONFIG_PATH) args.push('--config', GITLEAKS_CONFIG_PATH);
    await runTool('gitleaks', args, root);

    let raw;
    try {
      raw = await fsp.readFile(reportPath, 'utf8');
    } catch {
      return []; // no report written (e.g. nothing found on some gitleaks versions)
    }
    const results = raw.trim() ? JSON.parse(raw) : [];
    return await Promise.all(results.map(async (r) => {
      const relFile = path.relative(root, path.resolve(root, r.File || r.file || ''));
      const line = Number.isInteger(r.StartLine) ? r.StartLine : Number(r.startLine) || 0;
      const colStart = Number.isInteger(r.StartColumn) ? r.StartColumn - 1 : undefined;
      const colEnd = Number.isInteger(r.EndColumn) ? r.EndColumn : undefined;
      let code = null;
      try {
        const content = await fsp.readFile(path.join(root, relFile), 'utf8');
        code = buildSnippet(content, line, { colStart, colEnd });
      } catch { /* best-effort only */ }
      return {
        file: relFile,
        line,
        kind: String(r.RuleID || r.ruleID || 'secret').toLowerCase(),
        tool: 'gitleaks',
        code,
      };
    }));
  } catch (e) {
    log(`⚠ gitleaks scan skipped: ${e.message}`);
    return [];
  } finally {
    await fsp.unlink(reportPath).catch(() => {});
  }
}

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

async function checkAiGovernance(root, cacheKey) {
  const findings = [];
  let scanned = 0;
  let cacheHits = 0;
  const prevCache = loadFileScanCache(cacheKey, 'governance');
  const newCacheEntries = [];

  for await (const file of walkFiles(root)) {
    const ext = path.extname(file).toLowerCase();
    if (!['.py', '.js', '.ts'].includes(ext)) continue;

    const buffer = await fsp.readFile(file);
    if (looksBinary(buffer)) continue;

    scanned++;
    const rel = path.relative(root, file);
    const hash = hashBuffer(buffer);
    const cached = prevCache && prevCache.get(rel);
    if (cached && cached.hash === hash) {
      cacheHits++;
      findings.push(...cached.findings);
      newCacheEntries.push({ relPath: rel, hash, findings: cached.findings });
      continue;
    }

    const content = buffer.toString('utf8');
    const fileFindings = [];
    if (!content.includes('recursion_limit')) { // governed — compliant otherwise
      const lines = content.split(/\r?\n/);
      lines.forEach((line, i) => {
        const match = line.match(AI_INVOKE_REGEX);
        if (match) {
          fileFindings.push({
            file: rel,
            line: i + 1,
            snippet: line.trim().slice(0, 120),
            code: buildSnippet(content, i + 1, { colStart: match.index, colEnd: match.index + match[0].length }),
          });
        }
      });
    }
    findings.push(...fileFindings);
    newCacheEntries.push({ relPath: rel, hash, findings: fileFindings });
  }

  saveFileScanCache(cacheKey, 'governance', newCacheEntries);

  return { findings, scanned, cacheHits };
}

/* ------------------------------------------------------------------ */
/* Check 3: local LLM security deep-scan (optional, Ollama-compatible) */
/* ------------------------------------------------------------------ */

const LLM_SECURITY_DEP_PROMPT = `You are a strict application security reviewer. You will receive source files from a project, each preceded by a "===== FILE: <path> =====" header with numbered lines.
Review ONLY for:
1) Security vulnerabilities: injection (SQL/command/template), path traversal, SSRF, insecure deserialization, XSS, broken auth/authz, weak crypto, unsafe eval/exec, prototype pollution, insecure temp files, missing input validation on dangerous sinks.
2) Potentially dangerous dependencies (known risky/malicious/vulnerable packages from dependency manifests/lockfiles). A package flagged only as deprecated/unmaintained, with no known vulnerability, is not "dangerous" on its own — still report it, but see the level rule below.

Coverage rules:
- Do not stop at the first issue. Enumerate all distinct blocking findings in the provided files.
- Never summarize or collapse multiple occurrences of the same problem into a single finding (e.g. never write something like "fix these 10 occurrences" or "occurs throughout the file"). Every single occurrence gets its own finding object with its own exact file and line number, even if the wording is otherwise identical.
- Do not invent package versions. Only recommend a concrete dependency upgrade when the target version is known/published; otherwise recommend replacing the dependency or pinning to the latest available safe version.
- Do not flag SMTP as insecure when secure=false is paired with port 587 (STARTTLS submission mode).
- Do not flag hardcoded SMTP secrets unless a non-empty credential literal is present in code/config.
- Do not flag SSRF for a URL built from a server-side environment variable or config file value. Only flag SSRF when the URL (or host/path component of it) is influenced by request-time user input (query params, body, headers, uploaded file contents).
- Do not flag "API key in headers" or similar as a vulnerability merely because a secret from an environment variable is sent in a request header (e.g. an Authorization: Bearer header built from an API key variable) — that is normal usage. Only flag it if the key is also logged, written to a response, embedded in a URL, or sent over a non-TLS connection.

Classification rules:
- Dependency findings must be category "dependency". Use level "error" only when the package has a known vulnerability, malicious code, or exploit (mention the CVE/advisory if you know it). A package that is merely deprecated/unmaintained with no known vulnerability is level "warning", not "error".
- Exploitable security findings should be category "security" and level "error".

Writing style for the "issue" field:
- Write for a non-technical reader (e.g. a project manager), not a developer. Explain in plain language what could go wrong in the real world and why it matters, without jargon (avoid unexplained terms like "injection", "sanitize", "deserialization", "SSRF" — describe the risk in everyday words instead).
- Keep the "recommendation" field technical and actionable — that one is for the developer who will fix it.

Respond with ONLY a JSON object in this schema:
{"findings":[{"file":"<path>","line":<number>,"category":"security|dependency","level":"error","issue":"<one plain-language sentence, no jargon>","recommendation":"<short actionable technical fix>"}]}
If nothing is found respond {"findings":[]}.`;

const LLM_QUALITY_PROMPT = `You are a senior software engineer performing a code quality and encapsulation review. You will receive source files from a project, each preceded by a "===== FILE: <path> =====" header with numbered lines.
Review ONLY for:
1) Encapsulation improvements (leaky abstractions, exposed mutable internals, missing boundaries, too much coupling).
2) Maintainability/code-quality improvements (complexity hotspots, duplicated logic, poor separation of concerns, fragile API shapes).

Noise-control rules:
- Do not report module-level constants or private closures as encapsulation issues unless they are actually exposed for external mutation.
- Do not suggest broad architectural rewrites when a targeted/local change is sufficient.
- Never summarize or collapse multiple occurrences of the same problem into a single finding (e.g. never write something like "fix these 10 occurrences" or "occurs throughout the file"). Every single occurrence gets its own finding object with its own exact file and line number, even if the wording is otherwise identical.

Classification rules:
- Findings from this pass are advisory and may use level "warning".
- Use category "encapsulation" or "quality".

Writing style for the "issue" field:
- Write for a non-technical reader (e.g. a project manager), not a developer. Explain in plain language what is wrong and why it matters for the project, without jargon.
- Keep the "recommendation" field technical and actionable — that one is for the developer who will fix it.

Respond with ONLY a JSON object in this schema:
{"findings":[{"file":"<path>","line":<number>,"category":"encapsulation|quality","level":"warning","issue":"<one plain-language sentence, no jargon>","recommendation":"<short actionable technical fix>"}]}
If nothing is found respond {"findings":[]}.`;

// Logs every request/response exchanged with the local LLM to stdout (and,
// when a phase `log` callback is given, into the UI's live log too) — so a
// timeout can be traced to the exact call, payload size, and elapsed time.
function traceLlmCall(label, { url, model, timeoutMs, chars }, log) {
  const line = `[llm] → ${label} POST ${url} model=${model} timeout=${timeoutMs}ms payload=${chars} chars`;
  console.log(line);
  if (log) log(line);
  const startedAt = Date.now();
  return (outcome, detail = '') => {
    const elapsed = Date.now() - startedAt;
    const result = `[llm] ← ${label} ${outcome} in ${elapsed}ms${detail ? ' — ' + detail : ''}`;
    console.log(result);
    if (log) log(result);
  };
}

async function llmChat(sourceBlock, systemPrompt, log, label = 'chat') {
  const timeoutMs = 300_000;
  const { url, model, headers } = llmTarget();
  const finish = traceLlmCall(`${label} [${LLM_PROVIDER}]`, { url, model, timeoutMs, chars: sourceBlock.length }, log);
  let res;
  try {
    res = await fetch(url, {
      method: 'POST',
      headers,
      signal: AbortSignal.timeout(timeoutMs),
      body: JSON.stringify({
        model,
        stream: false,
        temperature: 0,
        response_format: { type: 'json_object' },
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: sourceBlock },
        ],
      }),
    });
  } catch (e) {
    finish(e.name === 'TimeoutError' ? 'TIMED OUT' : 'FAILED', e.message);
    throw e;
  }
  if (!res.ok) {
    finish('HTTP ERROR', String(res.status));
    throw new Error(`LLM endpoint returned HTTP ${res.status}`);
  }
  const data = await res.json();
  const text = data.choices?.[0]?.message?.content ?? '';
  finish('OK', `${text.length} chars returned`);
  try {
    const parsed = JSON.parse(text);
    return Array.isArray(parsed.findings) ? parsed.findings : [];
  } catch {
    throw new Error('LLM returned non-JSON output; skipping chunk.');
  }
}

// A dependency finding only earns "error" if the text itself carries
// evidence of an actual vulnerability/malicious code, not just a bare
// deprecation notice — mirrors the LLM_SECURITY_DEP_PROMPT classification
// rule as a code-level backstop.
const DEPENDENCY_VULN_EVIDENCE_RE = /\bcve-\d{4}-\d+|\bcwe-\d+|vulnerab\w*|exploit\w*|malicious|\brce\b|remote code execution|arbitrary code|backdoor|compromis\w*|security advisory|known flaw/i;

function parseSemver(v) {
  const m = String(v || '').trim().match(/^(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

function compareSemver(a, b) {
  for (let i = 0; i < 3; i++) {
    if (a[i] > b[i]) return 1;
    if (a[i] < b[i]) return -1;
  }
  return 0;
}

function getDependencyLineContext(filesByRel, relFile, line) {
  const content = filesByRel.get(relFile);
  if (!content) return null;
  const lines = content.split(/\r?\n/);
  if (line < 1 || line > lines.length) return null;
  return { lineText: lines[line - 1], fileText: content };
}

async function fetchLatestNpmVersion(pkgName, cache) {
  if (cache.has(pkgName)) return cache.get(pkgName);
  try {
    const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(pkgName)}`, {
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) {
      cache.set(pkgName, null);
      return null;
    }
    const data = await res.json();
    const versions = Object.keys(data.versions || {});
    let latest = null;
    for (const v of versions) {
      const sv = parseSemver(v);
      if (!sv) continue;
      if (!latest || compareSemver(sv, latest) > 0) latest = sv;
    }
    const latestText = latest ? `${latest[0]}.${latest[1]}.${latest[2]}` : null;
    cache.set(pkgName, latestText);
    return latestText;
  } catch {
    cache.set(pkgName, null);
    return null;
  }
}

function extractTargetVersion(text) {
  const m = String(text || '').match(/\b(\d+\.\d+\.\d+)\b/);
  return m ? m[1] : null;
}

// Traces identifiers referenced on `lineText` (template-literal interpolations
// and UPPER_SNAKE_CASE names — the near-universal convention for env-derived
// constants) back to a declaration anywhere else in the file, rather than
// requiring `process.env`/`config.` to appear right next to the usage site.
// Env vars are almost always declared once near the top of a file, not beside
// every call site that reads them, so a narrow line-window around the flagged
// line misses the connection entirely.
function isSourcedFromEnvOrConfig(lineText, fileText) {
  const candidates = new Set();
  for (const m of String(lineText || '').matchAll(/\$\{([A-Za-z_$][\w.]*)\}/g)) candidates.add(m[1].split('.')[0]);
  for (const m of String(lineText || '').matchAll(/\b([A-Z][A-Z0-9_]{2,})\b/g)) candidates.add(m[1]);
  for (const name of candidates) {
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const declaredFromEnv = new RegExp(`\\b${escaped}\\b\\s*=[^;\\n]*process\\.env\\.`).test(fileText);
    const declaredFromConfig = new RegExp(`\\{[^}]*\\b${escaped}\\b[^}]*\\}\\s*=\\s*require\\(`).test(fileText)
      || new RegExp(`\\b${escaped}\\b\\s*=[^;\\n]*\\bconfig\\.\\w+`, 'i').test(fileText);
    if (declaredFromEnv || declaredFromConfig) return true;
  }
  return false;
}

async function validateLlmFinding(finding, filesByRel, npmVersionCache, log) {
  const relFile = String(finding.file || '');
  const line = Number.isInteger(finding.line) ? finding.line : 1;
  const ctx = getDependencyLineContext(filesByRel, relFile, line);
  if (!ctx) return null;

  const issue = String(finding.issue || '').toLowerCase();
  const recommendation = String(finding.recommendation || '');
  const lineText = ctx.lineText;
  const fileText = ctx.fileText;

  if (finding.category === 'security') {
    if (issue.includes('smtp password') || issue.includes('hardcoded smtp')) {
      const hasNonEmptyCredential = /(pass|password)\s*[:=]\s*['\"]([^'\"\s]{4,})['\"]/i.test(fileText);
      if (!hasNonEmptyCredential) {
        log(`⚠ Ignored false-positive LLM finding: ${relFile}:${line} (no non-empty SMTP credential literal).`);
        return null;
      }
    }
    if (issue.includes('secure') && issue.includes('smtp') && lineText.includes('"secure": false')) {
      const hasStartTlsSubmission = /"port"\s*:\s*587/.test(fileText);
      if (hasStartTlsSubmission) {
        log(`⚠ Ignored false-positive LLM finding: ${relFile}:${line} (STARTTLS on port 587 is allowed).`);
        return null;
      }
    }

    if ((issue.includes('command injection') || issue.includes('user-supplied command') || issue.includes('child_process'))
      && relFile === 'server.js') {
      const hasCommandAllowlist = /const ALLOWED_COMMANDS = Object\.freeze\(new Set\(\['git', 'gh', 'act', 'docker', 'gitleaks', 'licensee', 'ort', 'trivy', 'checkov', 'hadolint', 'syft', 'cosign', 'semgrep', 'bearer', 'jscpd', 'gocloc', 'spectral'\]\)\);/.test(fileText);
      const hasStrictSanitizers = /sanitizeCommand\(|sanitizeCliArgs\(|sanitizeCwd\(|sanitizeEnv\(/.test(fileText);
      const isRunnerZone = line >= 200 && line <= 360;
      if (hasCommandAllowlist && hasStrictSanitizers && isRunnerZone) {
        log(`⚠ Ignored false-positive LLM finding: ${relFile}:${line} (child_process calls are constrained to fixed allowlisted tools).`);
        return null;
      }
    }

    if ((issue.includes('path traversal') || issue.includes('zip extraction') || issue.includes('folder upload'))
      && relFile === 'server.js') {
      const hasZipGuard = /target !== destDir && !target\.startsWith\(destDir \+ path\.sep\)/.test(fileText);
      const hasFolderGuard = /sanitizeUploadRelativePath\(|Blocked path-traversal entry in folder upload/.test(fileText);
      if (hasZipGuard && hasFolderGuard) {
        log(`⚠ Ignored false-positive LLM finding: ${relFile}:${line} (path traversal guards already enforce staging-root confinement).`);
        return null;
      }
    }

    if (issue.includes('ssrf') || (issue.includes('malicious server') && (issue.includes('redirect') || issue.includes('attacker')))) {
      // Mirrors the LLM_SECURITY_DEP_PROMPT rule the model itself is supposed
      // to follow (server.js LLM_SECURITY_DEP_PROMPT: "Only flag SSRF when the
      // URL ... is influenced by request-time user input"). The model doesn't
      // reliably honor that instruction, so re-check it here. A narrow
      // line-window around the flagged call site isn't enough — env vars are
      // almost always declared once near the top of the file (e.g.
      // `const LLM_API_BASE = process.env.LLM_API_BASE || ...`), far from
      // every call site that uses them — so trace the actual identifier used
      // on the flagged line back to its declaration anywhere in the file.
      const nearLine = ctx.fileText.split(/\r?\n/).slice(Math.max(0, line - 4), line + 2).join('\n');
      const referencesRequestInput = /\breq\.(body|query|params|headers)\b|\brequest\.(body|query|params|headers)\b/.test(nearLine)
        || /\breq\.(body|query|params|headers)\b|\brequest\.(body|query|params|headers)\b/.test(fileText);
      const referencesEnvOrConfig = /process\.env\.\w+|CONFIG\.\w+|config\.\w+/.test(nearLine)
        || isSourcedFromEnvOrConfig(lineText, fileText);
      if (!referencesRequestInput && referencesEnvOrConfig) {
        // A URL sourced purely from .env/config (no request-time input) is
        // never a blocking finding — the .env file is admin-controlled, not
        // attacker-reachable, so at worst this is "validate it anyway"
        // advice, not an exploitable SSRF. Downgrade instead of dropping so
        // it still surfaces for review.
        finding.level = 'warning';
        finding.issue = `${finding.issue} (downgraded: URL is sourced from a server-side .env/config value, not request-time user input, so this isn't directly exploitable — admin-controlled config, review at your discretion.)`;
        log(`⚠ Downgraded LLM finding to warning: ${relFile}:${line} (URL built from server-side env/config, not request-time user input).`);
      }
    }

    if (issue.includes('api key') && (issue.includes('header') || issue.includes('bearer') || issue.includes('expose'))) {
      // Same idea for LLM_SECURITY_DEP_PROMPT's "API key in headers" exception:
      // only a real finding if the key is also logged, echoed in a response,
      // put in a URL, or sent over plain HTTP — not merely used in an
      // Authorization header built from an env var, which is normal usage.
      // Same variable-tracing fix as the SSRF check above.
      const context = ctx.fileText.split(/\r?\n/).slice(Math.max(0, line - 4), line + 4).join('\n');
      const builtFromEnvVar = /Authorization['"]?\s*:\s*`?Bearer[\s$]/i.test(context)
        && (/process\.env\.\w*(KEY|TOKEN|SECRET)\w*/i.test(context) || isSourcedFromEnvOrConfig(lineText, fileText));
      const actuallyLeaked = /console\.(log|error|warn)\([^)]*\b(key|token|authorization|bearer)\b/i.test(context)
        || /res\.(json|send)\([^)]*\b(key|token|authorization|bearer)\b/i.test(context)
        || /http:\/\/[^\s'"]*\$\{?\w*(KEY|TOKEN)/i.test(context);
      if (builtFromEnvVar && !actuallyLeaked) {
        log(`⚠ Ignored false-positive LLM finding: ${relFile}:${line} (API key sent via standard Authorization header from an env var, not logged/echoed/URL-embedded).`);
        return null;
      }
    }

    if (issue.includes('llm_scan_url') && issue.includes('untrusted') && relFile === 'server.js') {
      const hasOriginAllowlist = /trustedOrigins\.has\(parsed\.origin\)/.test(fileText);
      const hasHttpsPolicy = /must use https for non-loopback hosts/.test(fileText);
      if (hasOriginAllowlist && hasHttpsPolicy) {
        log(`⚠ Ignored false-positive LLM finding: ${relFile}:${line} (LLM URL origin allowlist and TLS policy are enforced).`);
        return null;
      }
    }
  }

  if (finding.category === 'dependency') {
    const depMatch = lineText.match(/"([^\"]+)"\s*:\s*"[~^]?\d+\.\d+\.\d+"/);
    const packageName = depMatch?.[1] || null;
    const targetVersion = extractTargetVersion(recommendation);
    if (packageName && targetVersion) {
      const latest = await fetchLatestNpmVersion(packageName, npmVersionCache);
      const target = parseSemver(targetVersion);
      const latestParsed = parseSemver(latest);
      if (target && latestParsed && compareSemver(target, latestParsed) > 0) {
        log(`⚠ Ignored false-positive LLM finding: ${packageName} target ${targetVersion} is not published (latest ${latest}).`);
        return null;
      }
    }
  }

  return finding;
}

async function checkLlmDeepScan(root, log, cacheKey) {
  if (LLM_PROVIDER === 'openai') {
    // OpenAI has no cheap health probe worth spending a request on — just
    // confirm the API key is configured before burning chunks against it.
    if (!OPENAI_API_KEY) {
      return { available: false, reason: 'OPENAI_API_KEY is not set (LLM_PROVIDER=openai).' };
    }
    log(`[llm] provider=openai model=${OPENAI_MODEL} base=${OPENAI_BASE_URL}`);
  } else {
    // Probe the endpoint first so a missing llama.cpp fails soft with a clear message.
    const finishProbe = traceLlmCall('health-probe', { url: `${LLM_SCAN_URL}/health`, model: LLM_SCAN_MODEL, timeoutMs: 3000, chars: 0 }, log);
    try {
      const probe = await fetch(`${LLM_SCAN_URL}/health`, { signal: AbortSignal.timeout(3000) });
      if (!probe.ok) throw new Error(`HTTP ${probe.status}`);
      finishProbe('OK', String(probe.status));
    } catch (e) {
      finishProbe(e.name === 'TimeoutError' ? 'TIMED OUT' : 'FAILED', e.message);
      return { available: false, reason: `No LLM endpoint at ${LLM_SCAN_URL} (${e.message})` };
    }
  }

  // Collect candidate source files, numbered lines, chunked by char budget.
  // Gitignored files (config.json, .env, etc.) are skipped the same way the
  // regex secret scan and gitleaks already skip them — a project's own
  // legitimately-local, never-committed secrets shouldn't get a conflicting
  // "no credential leakage" from Check 2 and a blocking LLM finding for the
  // very same file.
  const gitignorePatterns = await loadGitignorePatterns(root);
  const files = [];
  for await (const file of walkFiles(root)) {
    if (!LLM_SOURCE_EXTS.has(path.extname(file).toLowerCase())) continue;
    const rel = path.relative(root, file);
    if (gitignorePatterns.length > 0 && isGitignored(gitignorePatterns, rel)) continue;
    const buffer = await fsp.readFile(file);
    if (looksBinary(buffer) || buffer.length > 200_000) continue;
    files.push({ rel, content: buffer.toString('utf8'), hash: hashBuffer(buffer) });
    if (files.length >= LLM_MAX_FILES) break;
  }
  if (files.length === 0) return { available: true, findings: [], scanned: 0, cacheHits: 0 };

  // Skip re-sending a file to the (slow, expensive) LLM if its content hash
  // matches what was recorded on the previous run for this org/repo — reuse
  // that file's stored findings instead of re-reviewing unchanged source.
  const prevCache = loadFileScanCache(cacheKey, 'llm');
  const cachedFindings = [];
  const filesToScan = [];
  let cacheHits = 0;
  for (const f of files) {
    const cached = prevCache && prevCache.get(f.rel);
    if (cached && cached.hash === f.hash) {
      cacheHits++;
      cachedFindings.push(...cached.findings);
    } else {
      filesToScan.push(f);
    }
  }

  if (filesToScan.length === 0) {
    log(`♻ All ${files.length} candidate file(s) unchanged since the last run for this org/repo — reusing cached LLM findings, no chunks sent.`);
    return { available: true, findings: cachedFindings, scanned: files.length, cacheHits };
  }

  const chunks = [];
  const chunkFiles = [];
  const filesByRel = new Map();
  let current = '';
  let currentFiles = [];
  for (const f of filesToScan) {
    filesByRel.set(f.rel, f.content);
    const numbered = f.content
      .split(/\r?\n/)
      .map((l, i) => `${i + 1}: ${l}`)
      .join('\n');
    const header = `===== FILE: ${f.rel} =====\n`;
    const body = `${numbered}\n\n`;
    const block = header + body;

    if (block.length > LLM_CHUNK_CHARS) {
      // The file alone doesn't fit one chunk's budget. Split it across
      // several sequential chunks instead of silently truncating it — every
      // line still gets scanned, just across more (smaller, faster) requests.
      if (current) {
        chunks.push(current);
        chunkFiles.push(currentFiles);
        current = '';
        currentFiles = [];
      }
      const sliceLen = Math.max(1000, LLM_CHUNK_CHARS - header.length - 40);
      const totalParts = Math.ceil(body.length / sliceLen);
      for (let part = 0, offset = 0; offset < body.length; part++, offset += sliceLen) {
        chunks.push(`${header}(part ${part + 1}/${totalParts}, continued)\n${body.slice(offset, offset + sliceLen)}`);
        chunkFiles.push([f.rel]);
      }
      continue;
    }

    if (current && current.length + block.length > LLM_CHUNK_CHARS) {
      chunks.push(current);
      chunkFiles.push(currentFiles);
      current = '';
      currentFiles = [];
    }
    current += block;
    currentFiles.push(f.rel);
  }
  if (current) {
    chunks.push(current);
    chunkFiles.push(currentFiles);
  }

  log(`Model: ${LLM_SCAN_MODEL} @ ${LLM_SCAN_URL} — ${filesToScan.length}/${files.length} file(s) changed (${cacheHits} cached, unchanged) in ${chunks.length} chunk(s), 2 review passes (security/dependency + quality/encapsulation)...`);

  const findings = [];
  const npmVersionCache = new Map();
  for (let i = 0; i < chunks.length; i++) {
    log(`Chunk ${i + 1}/${chunks.length} — files: ${chunkFiles[i].join(', ')}\n  security: injection (SQL/command/template), path traversal, SSRF, insecure deserialization, XSS, broken auth/authz, weak crypto, unsafe eval/exec, prototype pollution, insecure temp files, missing input validation\n  dependency: risky/malicious/deprecated-vulnerable packages in manifests/lockfiles\n  encapsulation: leaky abstractions, exposed mutable internals, missing boundaries, excess coupling\n  quality: complexity hotspots, duplicated logic, poor separation of concerns, fragile API shapes`);
    try {
      const chunkFindings = await llmChat(chunks[i], LLM_SECURITY_DEP_PROMPT, log, `chunk ${i + 1}/${chunks.length} security/dependency`);
      for (const f of chunkFindings) {
        if (f && typeof f.file === 'string' && f.issue) {
          const category = ['security', 'dependency', 'encapsulation', 'quality'].includes(f.category)
            ? f.category
            : 'security';
          let level = ['error', 'warning'].includes(f.level) ? f.level : 'warning';
          if (category === 'dependency') {
            // Same backstop reasoning as the SSRF/API-key checks in
            // validateLlmFinding(): the prompt already says a bare
            // "deprecated, no known vuln" notice should be "warning" not
            // "error", but the model doesn't reliably follow that, so
            // re-derive the level here from the finding text itself.
            const hasVulnEvidence = DEPENDENCY_VULN_EVIDENCE_RE.test(f.issue || '') || DEPENDENCY_VULN_EVIDENCE_RE.test(f.recommendation || '');
            level = hasVulnEvidence ? 'error' : 'warning';
          }
          const normalized = {
            file: f.file,
            line: Number.isInteger(f.line) ? f.line : 0,
            category,
            level,
            issue: String(f.issue).slice(0, 300),
            recommendation: String(f.recommendation || '').slice(0, 300),
            code: buildSnippet(filesByRel.get(f.file), Number.isInteger(f.line) ? f.line : 0),
          };
          const validated = await validateLlmFinding(normalized, filesByRel, npmVersionCache, log);
          if (validated) findings.push(validated);
        }
      }
    } catch (e) {
      log(`⚠ Chunk ${i + 1} security/dependency pass skipped: ${e.message}`);
    }

    try {
      const chunkFindings = await llmChat(chunks[i], LLM_QUALITY_PROMPT, log, `chunk ${i + 1}/${chunks.length} quality/encapsulation`);
      for (const f of chunkFindings) {
        if (f && typeof f.file === 'string' && f.issue) {
          const category = ['encapsulation', 'quality'].includes(f.category)
            ? f.category
            : 'quality';
          const lineNum = Number.isInteger(f.line) ? f.line : 0;
          findings.push({
            file: f.file,
            line: lineNum,
            category,
            level: LLM_ADVISORY_LEVEL,
            issue: String(f.issue).slice(0, 300),
            recommendation: String(f.recommendation || '').slice(0, 300),
            code: buildSnippet(filesByRel.get(f.file), lineNum),
          });
        }
      }
    } catch (e) {
      log(`⚠ Chunk ${i + 1} quality/encapsulation pass skipped: ${e.message}`);
    }
  }

  // Persist per-file findings for the files just (re-)scanned, keyed by the
  // "file" string the model itself reported — if that ever diverges from the
  // requested rel path, this file's cache entry simply stays empty and it
  // gets rescanned next run rather than silently losing a real finding.
  const findingsByFile = new Map();
  for (const f of findings) {
    if (!findingsByFile.has(f.file)) findingsByFile.set(f.file, []);
    findingsByFile.get(f.file).push(f);
  }
  const newCacheEntries = filesToScan.map((f) => ({
    relPath: f.rel,
    hash: f.hash,
    findings: findingsByFile.get(f.rel) || [],
  }));
  for (const f of files) {
    const cached = prevCache && prevCache.get(f.rel);
    if (cached && cached.hash === f.hash) {
      newCacheEntries.push({ relPath: f.rel, hash: f.hash, findings: cached.findings });
    }
  }
  saveFileScanCache(cacheKey, 'llm', newCacheEntries);

  if (cacheHits > 0) {
    log(`♻ ${cacheHits} file(s) unchanged since the last run for this org/repo — reused cached LLM findings.`);
  }

  return { available: true, findings: [...cachedFindings, ...findings], scanned: files.length, cacheHits };
}

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

async function fetchGovernanceWorkflow(wfDir, log) {
  log(`Fetching ${GOVERNANCE_WORKFLOW} from ${GOVERNANCE_REPO}@main...`);
  const { stdout } = await runTool('gh', [
    'api',
    `repos/${GOVERNANCE_REPO}/contents/.github/workflows/${GOVERNANCE_WORKFLOW}`,
    '-H', 'Accept: application/vnd.github.raw',
  ], os.tmpdir());
  await fsp.mkdir(wfDir, { recursive: true });
  const wfFile = path.join(wfDir, GOVERNANCE_WORKFLOW);
  const reusableMatches = [...stdout.matchAll(new RegExp(`uses:\\s*${GOVERNANCE_REPO}/\\.github/workflows/([A-Za-z0-9._-]+)@[^\\s]+`, 'g'))];

  let workflowText = normalizeWorkflowText(stdout);

  for (const match of reusableMatches) {
    const filename = match[1];
    if (!filename) continue;
    try {
      const { stdout: reusableText } = await runTool('gh', [
        'api',
        `repos/${GOVERNANCE_REPO}/contents/.github/workflows/${filename}`,
        '-H', 'Accept: application/vnd.github.raw',
      ], os.tmpdir());

      const localReusablePath = path.join(wfDir, filename);
      await fsp.writeFile(localReusablePath, normalizeWorkflowText(reusableText));
      workflowText = workflowText.replace(
        new RegExp(`uses:\\s*${GOVERNANCE_REPO}/\\.github/workflows/${filename}@[^\\s]+`, 'g'),
        `uses: ./.github/workflows/${filename}`
      );
      log(`✓ Localized reusable workflow: ${filename}`);
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
  // Normalize to CommonJS for local `act` compatibility.
  return String(text)
    .replace(/import\s+security\s+from\s+["']eslint-plugin-security["'];?\s*export\s+default\s+\[\s*security\.configs\.recommended\s*\];?/g,
      'const security = require("eslint-plugin-security"); module.exports = [security.configs.recommended];')
    .replace(/echo\s+'import\s+security\s+from\s+"eslint-plugin-security";\s*export\s+default\s+\[\s*security\.configs\.recommended\s*\];'\s*>\s*eslint\.config\.js/g,
      'echo \'const security = require("eslint-plugin-security"); module.exports = [security.configs.recommended];\' > eslint.config.js')
    .replace(/echo\s+"import\s+security\s+from\s+'eslint-plugin-security';\s*export\s+default\s+\[\s*security\.configs\.recommended\s*\];"\s*>\s*eslint\.config\.js/g,
      'echo "const security = require(\"eslint-plugin-security\"); module.exports = [security.configs.recommended];" > eslint.config.js')
    .replace(/npx\s+eslint\s+\.\s+--max-warnings(?:\s+|=)0\b/g, 'npx eslint . --max-warnings 1000');
}

async function gitleaksTooling() {
  try {
    await runTool('gitleaks', ['version'], os.tmpdir());
    return { ok: true };
  } catch {
    return { ok: false, reason: '`gitleaks` is not installed (brew install gitleaks) or not on PATH.' };
  }
}

async function trivyTooling() {
  try {
    await runTool('trivy', ['--version'], os.tmpdir());
    return { ok: true };
  } catch {
    return { ok: false, reason: '`trivy` is not installed (brew install trivy) — falling back to the built-in Dockerfile heuristic scan.' };
  }
}

async function checkovTooling() {
  try {
    await runTool('checkov', ['--version'], os.tmpdir());
    return { ok: true };
  } catch {
    return { ok: false, reason: '`checkov` is not installed (pip install checkov / brew install checkov) — its supplemental findings are simply omitted.' };
  }
}

// Runs trivy's own JSON report through Ignite's finding shape. Returns null
// (never throws) on any tool/parse failure so the caller always has the
// built-in fallback to drop back to.
async function runTrivyIacScan(root, log) {
  const reportPath = path.join(
    os.tmpdir(),
    `ignite-trivy-${crypto.randomBytes(8).toString('hex')}.json`
  );
  try {
    await runTool('trivy', [
      'config', '--format', 'json', '--output', reportPath, '--exit-code', '0', '--quiet', root,
    ], root);
    let raw;
    try {
      raw = await fsp.readFile(reportPath, 'utf8');
    } catch {
      return [];
    }
    const data = raw.trim() ? JSON.parse(raw) : {};
    const results = Array.isArray(data.Results) ? data.Results : [];
    const findings = [];
    for (const result of results) {
      const relFile = path.relative(root, path.resolve(root, result.Target || ''));
      const misconfigs = Array.isArray(result.Misconfigurations) ? result.Misconfigurations : [];
      let content = null;
      try { content = await fsp.readFile(path.join(root, relFile), 'utf8'); } catch { /* best-effort */ }
      for (const m of misconfigs) {
        const line = Number(m.CauseMetadata?.StartLine) || 1;
        findings.push({
          file: relFile,
          line,
          kind: String(m.ID || 'misconfig').toLowerCase(),
          tool: 'trivy',
          severity: String(m.Severity || 'MEDIUM').toLowerCase(),
          message: m.Title || m.Message || 'IaC misconfiguration',
          code: content ? buildSnippet(content, line) : null,
        });
      }
    }
    return findings;
  } catch (e) {
    log?.(`⚠ Trivy IaC scan failed: ${e.message}`);
    return null;
  } finally {
    await fsp.unlink(reportPath).catch(() => {});
  }
}

// checkov's `--output json` shape differs depending on how many IaC
// frameworks it detected in `root`: a single object ({check_type, results})
// when only one, an array of those objects when more than one (e.g. a repo
// with both a Dockerfile and Terraform). Normalized to an array either way.
function normalizeCheckovReport(data) {
  if (Array.isArray(data)) return data;
  if (data && typeof data === 'object' && data.results) return [data];
  return [];
}

// Supplements trivy's findings the same way gitleaks supplements the regex
// secret scan: runs alongside, never replaces. Returns null (never throws)
// on any tool/parse failure.
async function runCheckovIacScan(root, log) {
  try {
    // `-d .` (not the absolute root) with cwd=root: passing checkov an
    // absolute -d target makes it report repo_file_path/file_path as full
    // filesystem-rooted paths (e.g. "/var/folders/.../Dockerfile") instead
    // of paths relative to the scanned dir, which then produces a bogus
    // "relFile" once naively stripped of a leading "/" — caught by a real
    // pipeline run putting the staged project under $TMPDIR.
    const { stdout } = await runTool('checkov', [
      '-d', '.', '--output', 'json', '--compact', '--quiet', '--soft-fail',
    ], root);
    const data = stdout.trim() ? JSON.parse(stdout) : null;
    const reports = normalizeCheckovReport(data);
    const realRoot = await fsp.realpath(root).catch(() => root);
    const findings = [];
    for (const report of reports) {
      const failed = report?.results?.failed_checks;
      if (!Array.isArray(failed)) continue;
      for (const c of failed) {
        const rawPath = String(c.repo_file_path || c.file_path || '');
        if (!rawPath) continue;
        const relFile = path.relative(realRoot, path.resolve(realRoot, rawPath.replace(/^\/+/, '')));
        if (!relFile || relFile.startsWith('..')) continue;
        const line = Number(c.file_line_range?.[0]) || 1;
        let content = null;
        try { content = await fsp.readFile(path.join(root, relFile), 'utf8'); } catch { /* best-effort */ }
        findings.push({
          file: relFile,
          line,
          kind: String(c.check_id || 'misconfig').toLowerCase(),
          tool: 'checkov',
          severity: String(c.severity || 'MEDIUM').toLowerCase(),
          message: c.check_name || 'IaC misconfiguration',
          code: content ? buildSnippet(content, line) : null,
        });
      }
    }
    return findings;
  } catch (e) {
    log?.(`⚠ Checkov supplemental scan failed: ${e.message}`);
    return null;
  }
}

// IaC/container misconfiguration scan (Dockerfiles, Terraform, Kubernetes
// manifests, Helm charts). Trivy is the primary engine — its own file
// discovery covers every recognized IaC file under `root` in one pass, no
// per-file walk needed here unlike checkSecrets/checkAiGovernance. Falls
// back to a small built-in Dockerfile heuristic (unpinned base image tag,
// missing USER) when trivy is disabled or not installed, so a run is never
// blocked on it. Checkov (opt-in) supplements whichever engine ran, merged
// in and deduped by file/line, same relationship gitleaks has to the regex
// secret scan.
async function hadolintTooling() {
  try {
    await runTool('hadolint', ['--version'], os.tmpdir());
    return { ok: true };
  } catch {
    return { ok: false, reason: '`hadolint` is not installed (brew install hadolint) — its supplemental findings are simply omitted.' };
  }
}

const HADOLINT_LEVEL_TO_SEVERITY = { error: 'high', warning: 'medium', info: 'low', style: 'low' };

// hadolint only understands individual Dockerfiles (no directory/whole-repo
// mode like trivy/checkov), so this does its own file discovery — same
// DOCKERFILE_NAME_RE walk the built-in fallback uses — and passes every
// match as a single multi-file invocation (one JSON array back, one process
// spawned regardless of how many Dockerfiles the repo has).
async function runHadolintIacScan(root, log) {
  try {
    const dockerfiles = [];
    for await (const file of walkFiles(root)) {
      if (DOCKERFILE_NAME_RE.test(path.basename(file))) dockerfiles.push(path.relative(root, file));
    }
    if (dockerfiles.length === 0) return [];

    const { stdout } = await runTool('hadolint', ['--format', 'json', ...dockerfiles], root, { allowedExitCodes: [0, 1] });
    const results = stdout.trim() ? JSON.parse(stdout) : [];
    const findings = [];
    for (const r of results) {
      const relFile = String(r.file || '');
      const line = Number(r.line) || 1;
      let content = null;
      try { content = await fsp.readFile(path.join(root, relFile), 'utf8'); } catch { /* best-effort */ }
      findings.push({
        file: relFile,
        line,
        kind: String(r.code || 'dockerfile-lint').toLowerCase(),
        tool: 'hadolint',
        severity: HADOLINT_LEVEL_TO_SEVERITY[r.level] || 'medium',
        message: r.message || 'Dockerfile lint issue',
        code: content ? buildSnippet(content, line) : null,
      });
    }
    return findings;
  } catch (e) {
    log?.(`⚠ Hadolint supplemental scan failed: ${e.message}`);
    return null;
  }
}

async function checkIacSecurity(root, log) {
  const trivyTool = TRIVY_ENABLED ? await trivyTooling() : { ok: false, reason: 'trivy is disabled (security.trivy.enabled=false).' };
  let findings;
  let engine;
  if (!trivyTool.ok) {
    log?.(`⚠ Trivy IaC scan skipped: ${trivyTool.reason}`);
    findings = await checkIacSecurityFallback(root);
    engine = 'fallback';
  } else {
    log?.('Engine: Trivy CLI (External) — scanning Dockerfiles/Terraform/Kubernetes/Helm for misconfigurations...');
    const trivyFindings = await runTrivyIacScan(root, log);
    if (trivyFindings === null) {
      log?.('⚠ Falling back to the built-in Dockerfile heuristic scan.');
      findings = await checkIacSecurityFallback(root);
      engine = 'fallback';
    } else {
      findings = trivyFindings;
      engine = 'trivy';
    }
  }

  if (CHECKOV_ENABLED) {
    const checkovTool = await checkovTooling();
    if (!checkovTool.ok) {
      log?.(`⚠ Checkov supplemental scan skipped: ${checkovTool.reason}`);
    } else {
      log?.('Engine: Checkov CLI (External) — supplementing with additional IaC policy checks...');
      const checkovFindings = await runCheckovIacScan(root, log);
      if (checkovFindings) {
        // Deduped on file+line+rule-id, not just file+line: trivy and
        // checkov draw from different rule catalogs and routinely flag
        // *different* real issues on the same line (e.g. a Dockerfile's
        // FROM line triggers both an unpinned-tag and a root-user rule) —
        // collapsing on line alone would silently drop distinct findings.
        // This only catches true repeats (same tool-neutral rule surfacing
        // twice), which in practice is rare across two different scanners.
        const seen = new Set(findings.map((f) => `${f.file}:${f.line}:${f.kind}`));
        const additional = checkovFindings.filter((f) => !seen.has(`${f.file}:${f.line}:${f.kind}`));
        findings = [...findings, ...additional];
        engine = `${engine}+checkov`;
      }
    }
  }

  if (HADOLINT_ENABLED) {
    const hadolintTool = await hadolintTooling();
    if (!hadolintTool.ok) {
      log?.(`⚠ Hadolint supplemental scan skipped: ${hadolintTool.reason}`);
    } else {
      log?.('Engine: Hadolint CLI (External) — supplementing with Dockerfile-specific lint checks...');
      const hadolintFindings = await runHadolintIacScan(root, log);
      if (hadolintFindings) {
        const seen = new Set(findings.map((f) => `${f.file}:${f.line}:${f.kind}`));
        const additional = hadolintFindings.filter((f) => !seen.has(`${f.file}:${f.line}:${f.kind}`));
        findings = [...findings, ...additional];
        engine = `${engine}+hadolint`;
      }
    }
  }

  return { findings, engine };
}

const DOCKERFILE_NAME_RE = /^Dockerfile(\.[A-Za-z0-9_-]+)?$/;

// Engine: Ignite Built-In Pattern Matcher (Fallback) — used only when trivy
// is unavailable. Deliberately narrow (two well-known Dockerfile smells)
// rather than an attempt to replicate trivy's much larger rule set.
async function checkIacSecurityFallback(root) {
  const findings = [];
  for await (const file of walkFiles(root)) {
    const base = path.basename(file);
    if (!DOCKERFILE_NAME_RE.test(base)) continue;

    const buffer = await fsp.readFile(file);
    if (looksBinary(buffer)) continue;
    const content = buffer.toString('utf8');
    const rel = path.relative(root, file);
    const lines = content.split(/\r?\n/);
    let hasUser = false;
    lines.forEach((line, i) => {
      const fromMatch = line.match(/^\s*FROM\s+(\S+?)(?:\s+AS\s+\S+)?\s*$/i);
      if (fromMatch) {
        const image = fromMatch[1];
        const hasDigest = image.includes('@sha256:');
        const tagMatch = image.match(/:([^@\s]+)$/);
        const isUnpinned = !hasDigest && (!tagMatch || tagMatch[1] === 'latest');
        if (isUnpinned) {
          findings.push({
            file: rel,
            line: i + 1,
            kind: 'unpinned-base-image',
            tool: 'ignite-fallback',
            severity: 'medium',
            message: `Base image "${image}" is not pinned to a fixed tag/digest — resolves to whatever "latest" is at build time.`,
            code: buildSnippet(content, i + 1),
          });
        }
      }
      if (/^\s*USER\s+\S+/i.test(line)) hasUser = true;
    });
    if (!hasUser) {
      findings.push({
        file: rel,
        line: 1,
        kind: 'container-runs-as-root',
        tool: 'ignite-fallback',
        severity: 'medium',
        message: 'No USER instruction — the container runs as root by default.',
        code: buildSnippet(content, 1),
      });
    }
  }
  return findings;
}

async function syftTooling() {
  try {
    await runTool('syft', ['version'], os.tmpdir());
    return { ok: true };
  } catch {
    return { ok: false, reason: '`syft` is not installed (brew install syft) — falling back to a minimal manifest-derived component list (no standards-format SBOM).' };
  }
}

// Best-effort component list built purely from this app's own manifest
// parsers (STUDIO_MANIFESTS — the same ones scanDependencyLicensesFallback
// uses), used only when syft is disabled or not installed. Intentionally
// minimal: name/version pairs per ecosystem, no dependency graph, no CPEs,
// no license metadata — real SBOM generation needs the real tool.
async function generateSbomFallback(root) {
  const components = [];
  for await (const file of walkFiles(root)) {
    const spec = STUDIO_MANIFESTS.find((m) => m.file === path.basename(file));
    if (!spec) continue;
    const content = await fsp.readFile(file, 'utf8').catch(() => null);
    if (content == null) continue;
    const rawDeps = spec.parse(content).slice(0, STUDIO_MAX_DEPS_PER_MANIFEST);
    for (const dep of rawDeps) {
      components.push({ name: dep.name, version: dep.versionRange || null, ecosystem: spec.ecosystem, type: 'library' });
    }
  }
  return { bomFormat: 'ignite-fallback', specVersion: null, components };
}

// Generates a CycloneDX SBOM for the staged project via Syft, which does
// its own multi-ecosystem manifest/lockfile discovery in one pass (same
// relationship trivy has to checkIacSecurityFallback's narrow heuristic).
// Never throws: returns the built-in fallback component list on any
// missing-tool/parse failure, so a run is never blocked on it.
async function generateSbom(root, log) {
  const tooling = SYFT_ENABLED ? await syftTooling() : { ok: false, reason: 'syft is disabled (sbom.syft.enabled=false).' };
  if (!tooling.ok) {
    log?.(`⚠ Syft SBOM generation skipped: ${tooling.reason}`);
    return { engine: 'fallback', sbom: await generateSbomFallback(root) };
  }

  log?.('Engine: Syft CLI (External) — generating a CycloneDX SBOM...');
  const reportPath = path.join(os.tmpdir(), `ignite-syft-${crypto.randomBytes(8).toString('hex')}.json`);
  try {
    await runTool('syft', [root, '-o', `cyclonedx-json=${reportPath}`, '--quiet'], root);
    const raw = await fsp.readFile(reportPath, 'utf8');
    const sbom = JSON.parse(raw);
    return { engine: 'syft', sbom };
  } catch (e) {
    log?.(`⚠ Syft SBOM generation failed, falling back to a minimal component list: ${e.message}`);
    return { engine: 'fallback', sbom: await generateSbomFallback(root) };
  } finally {
    await fsp.unlink(reportPath).catch(() => {});
  }
}

async function cosignTooling() {
  try {
    await runTool('cosign', ['version'], os.tmpdir());
    return { ok: true };
  } catch {
    return { ok: false, reason: '`cosign` is not installed (brew install cosign) — base-image signature verification is skipped.' };
  }
}

// Collects every external base image referenced by FROM in the project's
// Dockerfiles, alongside the exact file/line it came from (for Studio
// addressability). Multi-stage build aliases (`FROM builder` referencing an
// earlier `AS builder` stage) are excluded — they're not external images
// and cosign has nothing to verify against.
async function discoverBaseImages(root) {
  const occurrences = [];
  for await (const file of walkFiles(root)) {
    if (!DOCKERFILE_NAME_RE.test(path.basename(file))) continue;
    const buffer = await fsp.readFile(file);
    if (looksBinary(buffer)) continue;
    const content = buffer.toString('utf8');
    const rel = path.relative(root, file);
    const lines = content.split(/\r?\n/);
    const stageNames = new Set();
    lines.forEach((line, i) => {
      const m = line.match(/^\s*FROM\s+(\S+?)(?:\s+AS\s+(\S+))?\s*$/i);
      if (!m) return;
      const image = m[1];
      if (m[2]) stageNames.add(m[2]);
      if (stageNames.has(image) || image.toLowerCase() === 'scratch') return;
      occurrences.push({ file: rel, line: i + 1, image });
    });
  }
  return occurrences;
}

// Verifies Sigstore/cosign keyless signatures on every unique external base
// image found across the project's Dockerfiles. Each unique image is
// verified once (cosign verify is a real network call to the image
// registry + Rekor transparency log) and the result is fanned back out to
// every file/line occurrence that referenced it. Never throws: any
// tool/network failure is reported as an "unverifiable" finding rather than
// aborting the run.
async function checkImageProvenance(root, log) {
  const tooling = COSIGN_ENABLED ? await cosignTooling() : { ok: false, reason: 'cosign is disabled (security.cosign.enabled=false).' };
  if (!tooling.ok) {
    log?.(`⚠ Cosign base-image signature check skipped: ${tooling.reason}`);
    return { findings: [], engine: 'disabled' };
  }

  const occurrences = await discoverBaseImages(root);
  if (occurrences.length === 0) return { findings: [], engine: 'cosign' };

  log?.('Engine: Cosign CLI (External) — verifying Sigstore signatures on referenced base images...');
  const uniqueImages = [...new Set(occurrences.map((o) => o.image))];
  const verdictByImage = new Map();
  for (const image of uniqueImages) {
    try {
      await runTool('cosign', [
        'verify',
        '--certificate-identity-regexp', COSIGN_IDENTITY_REGEXP,
        '--certificate-oidc-issuer-regexp', COSIGN_ISSUER_REGEXP,
        image,
      ], root, { allowedExitCodes: [0] });
      verdictByImage.set(image, { verified: true });
      log?.(`✓ ${image} — verifiable Sigstore signature.`);
    } catch (e) {
      verdictByImage.set(image, { verified: false, reason: e.message });
      log?.(`⚠ ${image} — no verifiable Sigstore signature: ${e.message}`);
    }
  }

  const findings = [];
  for (const occ of occurrences) {
    const verdict = verdictByImage.get(occ.image);
    if (verdict.verified) continue;
    let content = null;
    try { content = await fsp.readFile(path.join(root, occ.file), 'utf8'); } catch { /* best-effort */ }
    findings.push({
      file: occ.file,
      line: occ.line,
      kind: 'unsigned-base-image',
      tool: 'cosign',
      severity: 'warning',
      message: `Base image "${occ.image}" has no verifiable Sigstore/cosign signature — supply-chain provenance can't be confirmed.`,
      code: content ? buildSnippet(content, occ.line) : null,
    });
  }
  return { findings, engine: 'cosign' };
}

async function semgrepTooling() {
  try {
    const { stdout } = await runTool('semgrep', ['--version'], os.tmpdir());
    return { ok: true, version: stdout.trim() || null, path: SEMGREP_BINARY };
  } catch {
    return { ok: false, reason: '`semgrep` is not installed (brew install semgrep / pip install semgrep) — semantic SAST and posture findings are simply omitted.' };
  }
}

const SEMGREP_SEVERITY_TO_ISSUE = { ERROR: 'error', WARNING: 'warning', INFO: 'warning' };

// "Unsanitized dynamic input in file path" fires from several distinct
// path-traversal rules across p/security-audit's per-language rule packs,
// each carrying its own hand-set severity metadata — so the same message
// text lands as ERROR from one rule/file and WARNING from another with no
// difference in actual confidence. Forced to warning regardless of which
// rule matched or which file it fired in, same rationale (and pattern) as
// BEARER_FORCE_WARNING_TITLES below.
const SEMGREP_FORCE_WARNING_TITLES = [/unsanitized dynamic input in file path/i];

// Semantic pattern-matching SAST via Semgrep OSS, run over the whole staged
// project in one pass (semgrep does its own multi-language file discovery).
// No built-in fallback when disabled/missing — there's no meaningful
// heuristic substitute for a semantic rule engine, so this simply
// contributes nothing rather than pretending to.
// Resolves an external tool's reported file path (which may be absolute
// and either canonical or not, depending on the tool — Spectral
// canonicalizes symlinks like macOS's /tmp -> /private/tmp in its output,
// Semgrep and Checkov generally don't) into a path relative to `root`,
// regardless of which representation `root` itself was given in or which
// representation the tool echoed back. realpath-ing *both* sides before
// diffing is what makes this work either way — canonicalizing only one
// side (an earlier version of this code did, for both the Spectral and
// Semgrep call sites) produces a technically-valid but useless
// "../../../../var/folders/.../root/../../../file" path whenever the two
// sides end up canonicalized inconsistently.
async function relativeToRoot(root, targetPath) {
  const raw = String(targetPath || '');
  const resolved = path.resolve(root, raw);
  const [realRoot, realTarget] = await Promise.all([
    fsp.realpath(root).catch(() => root),
    fsp.realpath(resolved).catch(() => resolved),
  ]);
  return path.relative(realRoot, realTarget);
}

async function checkSemanticSast(root, log) {
  const tooling = SEMGREP_ENABLED ? await semgrepTooling() : { ok: false, reason: 'semgrep is disabled (security.semgrep.enabled=false).' };
  if (!tooling.ok) {
    log?.(`⚠ Semgrep semantic SAST scan skipped: ${tooling.reason}`);
    return { findings: [], engine: 'disabled' };
  }

  log?.(`Engine: Semgrep CLI (External) — running semantic SAST rules (config: ${SEMGREP_CONFIG})...`);
  try {
    const { stdout } = await runTool('semgrep', [
      'scan', '--config', SEMGREP_CONFIG, '--json', '--quiet', '--metrics', 'off', root,
    ], root);
    const data = stdout.trim() ? JSON.parse(stdout) : { results: [] };
    const results = Array.isArray(data.results) ? data.results : [];
    const findings = [];
    for (const r of results) {
      const relFile = await relativeToRoot(root, r.path);
      const line = Number(r.start?.line) || 1;
      let content = null;
      try { content = await fsp.readFile(path.join(root, relFile), 'utf8'); } catch { /* best-effort */ }
      const semgrepSeverity = String(r.extra?.severity || 'WARNING').toUpperCase();
      const message = r.extra?.message || 'Semgrep finding';
      const forcedWarning = SEMGREP_FORCE_WARNING_TITLES.some((re) => re.test(message));
      findings.push({
        file: relFile,
        line,
        kind: String(r.check_id || 'semgrep-finding').toLowerCase(),
        tool: 'semgrep',
        severity: forcedWarning ? 'warning' : (SEMGREP_SEVERITY_TO_ISSUE[semgrepSeverity] || 'warning'),
        message,
        code: content ? buildSnippet(content, line) : null,
      });
    }
    return { findings, engine: 'semgrep' };
  } catch (e) {
    log?.(`⚠ Semgrep semantic SAST scan failed: ${e.message}`);
    return { findings: [], engine: 'disabled' };
  }
}

async function bearerTooling() {
  try {
    await runTool('bearer', ['version'], os.tmpdir());
    return { ok: true };
  } catch {
    return { ok: false, reason: '`bearer` is not installed (brew install bearer/tap/bearer) — PII/data-flow findings are simply omitted.' };
  }
}

// Bearer shells out to git for its own bookkeeping (default branch,
// origin URL) and fails outright without it — unlike ORT, which only wants
// a git root for path resolution and degrades gracefully without one.
// Ensures a throwaway repo (git init/add/commit, same as
// ensureGitRootForOrt) *and* fills in a fake origin + remote-tracking HEAD
// ref, since a fresh ZIP/folder upload has neither. Every step is
// best-effort: if bearer still can't get a git context after this, the
// scan below fails soft (empty findings), same as any other tool failure.
async function ensureGitContextForBearer(root, log) {
  try {
    if (!(await fsp.access(path.join(root, '.git')).then(() => true, () => false))) {
      await runTool('git', ['init', '-q'], root);
      await runTool('git', ['add', '-A'], root);
      await runTool('git', [
        '-c', 'user.email=ignite@local', '-c', 'user.name=Ignite',
        'commit', '-q', '-m', 'ignite-bearer-scan', '--no-verify', '--allow-empty',
      ], root);
    }
    const { stdout: branch } = await runTool('git', ['symbolic-ref', '--short', 'HEAD'], root);
    const branchName = branch.trim() || 'main';
    const hasOrigin = await runTool('git', ['remote', 'get-url', 'origin'], root).then(() => true, () => false);
    if (!hasOrigin) {
      await runTool('git', ['remote', 'add', 'origin', 'https://ignite.local/scratch.git'], root);
    }
    await runTool('git', ['update-ref', `refs/remotes/origin/${branchName}`, `refs/heads/${branchName}`], root);
    await runTool('git', ['symbolic-ref', `refs/remotes/origin/HEAD`, `refs/remotes/origin/${branchName}`], root);
  } catch (e) {
    log?.(`⚠ Could not fully stage a git context for bearer (non-blocking): ${e.message}`);
  }
}

const BEARER_SEVERITY_TO_ISSUE = { critical: 'error', high: 'error', medium: 'warning', low: 'warning', warning: 'warning' };

// Bearer buckets "Unsanitized external input in code generation" and
// "Unsanitized dynamic input in file path" under high/critical by default,
// which blocks a run outright — in practice these rules fire on
// template/config generation and internal file-path assembly helpers
// (job/run-id-based archive names, cache paths, etc.) with no attacker-
// reachable input, so they read as lower-confidence, review-worthy
// findings rather than hard blockers. Forced to warning regardless of
// Bearer's own bucket, or of which file/rule instance fired.
const BEARER_FORCE_WARNING_TITLES = [
  /unsanitized external input in code generation/i,
  /unsanitized dynamic input in file path/i,
];

// Sensitive data-flow (PII/GDPR) SAST via Bearer, which reports findings
// pre-bucketed by severity ({critical:[...], high:[...], ...}) rather than
// a flat array like semgrep/trivy. No built-in fallback when disabled or
// missing — data-flow tracking has no meaningful heuristic substitute.
async function checkPiiDataFlow(root, log) {
  const tooling = BEARER_ENABLED ? await bearerTooling() : { ok: false, reason: 'bearer is disabled (security.bearer.enabled=false).' };
  if (!tooling.ok) {
    log?.(`⚠ Bearer PII/data-flow scan skipped: ${tooling.reason}`);
    return { findings: [], engine: 'disabled' };
  }

  await ensureGitContextForBearer(root, log);
  log?.('Engine: Bearer CLI (External) — tracing sensitive data flows (PII/GDPR)...');
  try {
    const { stdout } = await runTool('bearer', [
      'scan', root, '--format', 'json', '--quiet', '--disable-version-check', '--exit-code', '0',
    ], root);
    const data = stdout.trim() ? JSON.parse(stdout) : {};
    const findings = [];
    for (const [severity, entries] of Object.entries(data)) {
      if (!Array.isArray(entries)) continue;
      for (const e of entries) {
        // `bearer scan` with no --report flag defaults to Bearer's general
        // "security" report — a much broader SAST rule set (path
        // traversal, format-string injection, weak crypto, ...) than just
        // PII/data-flow. Without this filter every one of those generic
        // findings got mislabeled as "pii-dataflow" (a "Unsanitized
        // dynamic input in file path" finding has nothing to do with
        // personal data), which is what this check exists to trace in the
        // first place — only keep findings Bearer itself tags as
        // PII/Personal-Data-relevant via category_groups; the rest is
        // already Semgrep's job (checkSemanticSast) and would just double
        // up as a mislabeled, noisier duplicate here.
        const categoryGroups = Array.isArray(e.category_groups) ? e.category_groups : [];
        const isPii = categoryGroups.some((g) => /pii|personal data/i.test(String(g)));
        if (!isPii) continue;
        const relFile = path.relative(root, path.resolve(root, e.full_filename || e.filename || ''));
        const line = Number(e.line_number) || 1;
        let content = null;
        try { content = await fsp.readFile(path.join(root, relFile), 'utf8'); } catch { /* best-effort */ }
        const title = e.title || 'Sensitive data-flow finding';
        const forcedWarning = BEARER_FORCE_WARNING_TITLES.some((re) => re.test(title));
        findings.push({
          file: relFile,
          line,
          kind: String(e.id || 'pii-dataflow').toLowerCase(),
          tool: 'bearer',
          severity: forcedWarning ? 'warning' : (BEARER_SEVERITY_TO_ISSUE[severity] || 'warning'),
          message: title,
          code: content ? buildSnippet(content, line) : null,
        });
      }
    }
    return { findings, engine: 'bearer' };
  } catch (e) {
    log?.(`⚠ Bearer PII/data-flow scan failed: ${e.message}`);
    return { findings: [], engine: 'disabled' };
  }
}

async function jscpdTooling() {
  try {
    await runTool('jscpd', ['--version'], os.tmpdir());
    return { ok: true };
  } catch {
    return { ok: false, reason: '`jscpd` is not installed (npm install -g jscpd) — duplication findings are simply omitted.' };
  }
}

// Code-duplication scan via jscpd, which does its own multi-language file
// discovery over `root` in one pass. Each clone becomes one finding
// anchored at its first occurrence, referencing the second in the message
// (Studio can only address one file/line per finding). No built-in
// fallback — duplicate-block detection needs the real tool.
async function checkCodeDuplication(root, log) {
  const tooling = JSCPD_ENABLED ? await jscpdTooling() : { ok: false, reason: 'jscpd is disabled (metrics.jscpd.enabled=false).' };
  if (!tooling.ok) {
    log?.(`⚠ jscpd duplication scan skipped: ${tooling.reason}`);
    return { findings: [], engine: 'disabled' };
  }

  log?.('Engine: jscpd CLI (External) — scanning for duplicated code blocks...');
  const outDir = path.join(os.tmpdir(), `ignite-jscpd-${crypto.randomBytes(8).toString('hex')}`);
  try {
    await runTool('jscpd', [
      root, '--reporters', 'json', '--output', outDir, '--silent',
      '--min-lines', String(JSCPD_MIN_LINES), '--min-tokens', String(JSCPD_MIN_TOKENS),
      ...(JSCPD_IGNORE_PATTERNS.length > 0 ? ['--ignore', JSCPD_IGNORE_PATTERNS.join(',')] : []),
    ], root, { allowedExitCodes: [0, 1] });
    const raw = await fsp.readFile(path.join(outDir, 'jscpd-report.json'), 'utf8').catch(() => null);
    if (raw === null) return { findings: [], engine: 'jscpd' };
    const data = JSON.parse(raw);
    const duplicates = Array.isArray(data.duplicates) ? data.duplicates : [];
    const findings = [];
    for (const dup of duplicates) {
      // Defensive guard on top of --min-lines: jscpd's own `lines` count
      // can still undercount for a duplicate that's really just
      // punctuation (a run of closing brackets/braces), so also require
      // the reported span to actually meet the configured minimum here.
      const dupLines = Number(dup.lines) || 0;
      if (dupLines < JSCPD_MIN_LINES) continue;
      const relFile = path.relative(root, path.resolve(root, dup.firstFile?.name || ''));
      const line = Number(dup.firstFile?.startLoc?.line) || 1;
      const endLine = Number(dup.firstFile?.endLoc?.line) || line;
      const otherFile = dup.secondFile?.name || '?';
      const otherLine = Number(dup.secondFile?.startLoc?.line) || 1;
      let content = null;
      try { content = await fsp.readFile(path.join(root, relFile), 'utf8'); } catch { /* best-effort */ }
      // Skip blocks whose duplicated span is nothing but punctuation/
      // whitespace (stray closing braces, brackets, semicolons) — not a
      // meaningful duplicate even if it cleared the token/line thresholds.
      if (content) {
        const spanLines = content.split('\n').slice(line - 1, endLine);
        const meaningful = spanLines.some((l) => /[A-Za-z0-9_]/.test(l));
        if (!meaningful) continue;
      }
      findings.push({
        file: relFile,
        line,
        kind: 'duplicate-code',
        tool: 'jscpd',
        severity: 'warning',
        message: `${dup.lines || 0}-line duplicate block, also found in ${otherFile}:${otherLine}.`,
        code: content ? buildSnippet(content, line) : null,
      });
    }
    return { findings, engine: 'jscpd' };
  } catch (e) {
    log?.(`⚠ jscpd duplication scan failed: ${e.message}`);
    return { findings: [], engine: 'disabled' };
  } finally {
    await fsp.rm(outDir, { recursive: true, force: true }).catch(() => {});
  }
}

async function goclocTooling() {
  try {
    await runTool('gocloc', ['--version'], os.tmpdir());
    return { ok: true };
  } catch {
    return { ok: false, reason: '`gocloc` is not installed (brew install gocloc) — LOC metrics are simply omitted.' };
  }
}

// Precise per-language LOC counts via gocloc, which does its own
// multi-language file discovery over `root` in one pass. Purely
// descriptive — never produces issues — so the caller attaches the result
// as a downloadable project document (same treatment as generateSbom),
// not something collectPhase4Issues touches.
async function generateLocMetrics(root, log) {
  const tooling = GOCLOC_ENABLED ? await goclocTooling() : { ok: false, reason: 'gocloc is disabled (metrics.gocloc.enabled=false).' };
  if (!tooling.ok) {
    log?.(`⚠ gocloc LOC metrics skipped: ${tooling.reason}`);
    return { engine: 'disabled', metrics: null };
  }

  log?.('Engine: gocloc CLI (External) — computing per-language LOC metrics...');
  try {
    // --by-file (rather than gocloc's default per-language-only rollup)
    // so Studio can offer "click a language, see just its files" — the
    // per-language `languages` summary below is aggregated from this same
    // per-file list rather than issuing a second gocloc call.
    const { stdout } = await runTool('gocloc', ['--by-file', '--output-type', 'json', '--fullpath', '--not-match-d', SKIP_DIRS_REGEX, root], root);
    const raw = stdout.trim() ? JSON.parse(stdout) : null;
    if (!raw) return { engine: 'gocloc', metrics: null };
    const files = await Promise.all((raw.files || []).map(async (f) => ({
      file: await relativeToRoot(root, f.name),
      language: f.language,
      code: f.code,
      comment: f.comment,
      blank: f.blank,
    })));
    const byLanguage = new Map();
    for (const f of files) {
      const agg = byLanguage.get(f.language) || { name: f.language, files: 0, code: 0, comment: 0, blank: 0 };
      agg.files++; agg.code += f.code; agg.comment += f.comment; agg.blank += f.blank;
      byLanguage.set(f.language, agg);
    }
    const metrics = { languages: [...byLanguage.values()], total: raw.total, files };
    return { engine: 'gocloc', metrics };
  } catch (e) {
    log?.(`⚠ gocloc LOC metrics failed: ${e.message}`);
    return { engine: 'disabled', metrics: null };
  }
}

async function spectralTooling() {
  try {
    await runTool('spectral', ['--version'], os.tmpdir());
    return { ok: true };
  } catch {
    return { ok: false, reason: '`spectral` is not installed (npm install -g @stoplight/spectral-cli) — API schema lint findings are simply omitted.' };
  }
}

const API_SCHEMA_TOP_LEVEL_RE = /^\s*("?(openapi|swagger|asyncapi)"?\s*:)/m;

// Spectral (unlike trivy/checkov/jscpd) has no directory-scan mode — it
// only lints files explicitly passed on the command line — so this does
// its own discovery: any .yaml/.yml/.json file whose top-level content
// declares openapi/swagger/asyncapi. Cheap content sniff rather than a
// filename convention, since these files are named all sorts of things
// (openapi.yaml, api-spec.json, schema/users.yaml, ...).
async function discoverApiSchemaFiles(root) {
  const files = [];
  for await (const file of walkFiles(root)) {
    const ext = path.extname(file).toLowerCase();
    if (!['.yaml', '.yml', '.json'].includes(ext)) continue;
    const buffer = await fsp.readFile(file).catch(() => null);
    if (!buffer || looksBinary(buffer)) continue;
    const content = buffer.toString('utf8');
    if (API_SCHEMA_TOP_LEVEL_RE.test(content)) files.push(path.relative(root, file));
  }
  return files;
}

const SPECTRAL_SEVERITY_TO_ISSUE = { 0: 'error', 1: 'warning', 2: 'warning', 3: 'warning' };

// Lints every discovered OpenAPI/AsyncAPI file against Spectral's ruleset
// (org REST/AsyncAPI conventions, not just schema validity). No built-in
// fallback when disabled/missing — schema linting needs the real rule
// engine, so this simply contributes nothing rather than pretending to.
async function checkApiSchemas(root, log) {
  const tooling = SPECTRAL_ENABLED ? await spectralTooling() : { ok: false, reason: 'spectral is disabled (api.spectral.enabled=false).' };
  if (!tooling.ok) {
    log?.(`⚠ Spectral API schema lint skipped: ${tooling.reason}`);
    return { findings: [], engine: 'disabled' };
  }

  const relFiles = await discoverApiSchemaFiles(root);
  if (relFiles.length === 0) return { findings: [], engine: 'spectral' };

  log?.(`Engine: Spectral CLI (External) — linting ${relFiles.length} OpenAPI/AsyncAPI file(s)...`);
  try {
    const { stdout } = await runTool('spectral', [
      'lint', ...relFiles, '--ruleset', SPECTRAL_RULESET, '--format', 'json', '-q',
    ], root, { allowedExitCodes: [0, 1] });
    const results = stdout.trim() ? JSON.parse(stdout) : [];
    const findings = [];
    for (const r of results) {
      const relFile = await relativeToRoot(root, r.source);
      const line = (Number(r.range?.start?.line) || 0) + 1; // spectral lines are 0-indexed
      let content = null;
      try { content = await fsp.readFile(path.join(root, relFile), 'utf8'); } catch { /* best-effort */ }
      findings.push({
        file: relFile,
        line,
        kind: String(r.code || 'api-schema-lint').toLowerCase(),
        tool: 'spectral',
        severity: SPECTRAL_SEVERITY_TO_ISSUE[r.severity] || 'warning',
        message: r.message || 'API schema lint finding',
        code: content ? buildSnippet(content, line) : null,
      });
    }
    return { findings, engine: 'spectral' };
  } catch (e) {
    log?.(`⚠ Spectral API schema lint failed: ${e.message}`);
    return { findings: [], engine: 'disabled' };
  }
}

const POSTURE_CATEGORIES = [
  'sso-saml-oidc', 'rbac-abac', 'audit-logging', 'siem-log-forwarding',
  'https-tls', 'backups-dr', 'encryption-at-rest', 'rate-limiting',
  'mfa-2fa', 'secrets-management',
];

// Mirrors ignite-posture-rules.yaml's pattern-regex bodies, narrower in
// coverage (single JS regex per tier vs. Semgrep's proper multi-file
// engine) — used only when Semgrep is disabled or not installed. Keeping
// these in sync with the YAML file is a manual step; a mismatch just means
// the fallback and Semgrep paths disagree on posture for the affected
// category, never a crash either way.
const POSTURE_FALLBACK_PATTERNS = {
  'sso-saml-oidc': {
    weak: /passport-saml|passport-openidconnect|passport-oauth2|org\.springframework\.security\.oauth2|org\.keycloak|keycloak-connect|auth0(-java|-spa-js)?|okta-sdk|okta-auth-js|com\.okta|cognito|microsoft-identity-web|omniauth-saml|omniauth-oauth2|ruby-saml|python3-saml|django-allauth/,
    strong: /new\s+SamlStrategy\(|new\s+OIDCStrategy\(|new\s+Auth0Client\(|new\s+CognitoUserPool\(|OktaAuth\(|@EnableOAuth2Sso|KeycloakInstance\(|Keycloak\(\{|SAML2AuthenticationProvider\(|OidcClient\(/,
  },
  'rbac-abac': {
    weak: /casbin|open-policy-agent|org\.opa|opa-wasm|django-guardian|pundit|cancancan|micronaut-security-annotations/,
    strong: /@PreAuthorize\(|@PostAuthorize\(|@RolesAllowed\(|@Secured\(|@RequireRole|casbin\.NewEnforcer\(|enforcer\.Enforce\(|opa\.Eval\(|requireRole\(|requirePermission\(|checkPermission\(|authorize!\(|can\?\(/,
  },
  'audit-logging': {
    weak: /AuditLogger|AuditEvent|audit_log|AuditingEntityListener|@Audited|django-auditlog|paper_trail|audited\s/,
    strong: /auditLogger\.(log|record|emit)\(|AuditLog\.create\(|logger\.audit\(|audit_log\.(info|record|create)\(|PaperTrail\.request|@Audited\b/,
  },
  'siem-log-forwarding': {
    weak: /winston-syslog|fluent-logger|logstash|@opentelemetry|go\.opentelemetry\.io|SyslogAppender|serilog-sinks-syslog|nlog\.targets\.syslog/,
    strong: /new\s+FluentLogger\(|winston\.transports\.Syslog\(|new\s+LogstashTransport\(|zap\.NewSyslogWriter\(|SyslogAppender\(|OpenTelemetry\.trace\.getTracer\(/,
  },
  'https-tls': {
    weak: /\bhelmet\b|force-ssl|django\.middleware\.security|Rack::SSL|Microsoft\.AspNetCore\.HttpsPolicy/,
    strong: /helmet\.hsts\(|Strict-Transport-Security|forceSSL|SECURE_SSL_REDIRECT\s*=\s*True|app\.UseHsts\(|https\.createServer\(|config\.force_ssl\s*=\s*true/,
  },
  'backups-dr': {
    weak: /pg_dump|pg_basebackup|mongodump|mysqldump|velero|restic\s|borgbackup/,
    strong: /backup_retention_period|BackupRetentionPeriod|RetentionPolicy|CreateDBSnapshot|CreateSnapshot\(/,
  },
  'encryption-at-rest': {
    weak: /aws-sdk.*kms|@aws-sdk\/client-kms|com\.amazonaws\.services\.kms|hashicorp\/vault|com\.google\.cloud\.kms|azure-keyvault/,
    strong: /kms\.encrypt\(|kmsClient\.Encrypt\(|vault\.write\(|createCipheriv\(|Aes\.Encrypt\(|EncryptField\(|Cipher\.getInstance\("AES/,
  },
  'rate-limiting': {
    weak: /express-rate-limit|bucket4j|django-ratelimit|rack-attack|flask-limiter|aspnetcoreratelimit/,
    strong: /rateLimit\(\{|new\s+RateLimiterRedis\(|Bucket4j\.builder\(|RateLimiter\.create\(|@ratelimit\(|Rack::Attack\.throttle\(/,
  },
  'mfa-2fa': {
    weak: /speakeasy|otplib|pyotp|django-otp|devise-two-factor|rotp|com\.warrenstrange\.googleauth|authy/,
    strong: /speakeasy\.totp\.verify\(|totp\.verify\(|pyotp\.TOTP\(|authenticator\.verify\(|GoogleAuthenticator\(\)\.authorize\(|TwoFactorAuthenticationProvider|verifyMfaChallenge\(/,
  },
  'secrets-management': {
    weak: /hashicorp\/vault|node-vault|@aws-sdk\/client-secrets-manager|azure-keyvault-secrets|com\.google\.cloud\.secretmanager|com\.bettercloud\.vault|doppler|python-dotenv-vault/,
    strong: /vault\.read\(|vaultClient\.read\(|secretsManagerClient\.getSecretValue\(|new\s+SecretClient\(|secretmanager\.accessSecretVersion\(|SecretsManagerClient\(\)\.getSecretValue\(/,
  },
};

function emptyPostureReport() {
  const posture = {};
  for (const cat of POSTURE_CATEGORIES) posture[cat] = { status: 'MISSING', matches: [] };
  return posture;
}

// >=1 "strong" (confirmed usage) match => DETECTED. Only "weak" (import/
// dependency-only) matches => PARTIAL. Neither => MISSING.
function classifyPostureMatches(matches) {
  if (matches.some((m) => m.tier === 'strong')) return 'DETECTED';
  if (matches.length > 0) return 'PARTIAL';
  return 'MISSING';
}

// Engine: Ignite Built-In Posture Scanner (Fallback) — used only when
// Semgrep is unavailable. Same weak/strong two-tier model as the Semgrep
// ruleset, just a line-by-line JS regex sweep instead of Semgrep's engine.
async function checkFeaturePostureFallback(root) {
  const posture = emptyPostureReport();
  for await (const file of walkFiles(root)) {
    const ext = path.extname(file).toLowerCase();
    if (BINARY_EXTENSIONS.has(ext)) continue;
    const stat = await fsp.stat(file).catch(() => null);
    if (!stat || stat.size > MAX_SCAN_FILE_BYTES) continue;
    const buffer = await fsp.readFile(file);
    if (looksBinary(buffer)) continue;
    const content = buffer.toString('utf8');
    const rel = path.relative(root, file);
    const lines = content.split(/\r?\n/);
    for (const category of POSTURE_CATEGORIES) {
      const { weak, strong } = POSTURE_FALLBACK_PATTERNS[category];
      lines.forEach((line, i) => {
        const tier = strong.test(line) ? 'strong' : (weak.test(line) ? 'weak' : null);
        if (!tier) return;
        posture[category].matches.push({
          file: rel, line: i + 1, tier, tool: 'ignite-fallback',
          message: `${category} (${tier} signal, built-in fallback — Semgrep not installed)`,
          code: buildSnippet(content, i + 1),
        });
      });
    }
  }
  for (const category of POSTURE_CATEGORIES) {
    posture[category].status = classifyPostureMatches(posture[category].matches);
  }
  return posture;
}

// Compliance & Feature Posture Engine — detects the PRESENCE of security/
// compliance features (SSO, RBAC, audit logging, TLS, backups, encryption
// at rest, rate limiting), not vulnerabilities, so it's classified as
// DETECTED/PARTIAL/MISSING per category rather than error/warning issues.
// Fully conditioned on Semgrep: runs the custom ignite-posture-rules.yaml
// ruleset when connected, engine-attributed as "Semgrep CLI vX.X (External
// Posture Scanner)"; soft-falls back to checkFeaturePostureFallback,
// attributed as "Ignite Built-In Posture Scanner (Fallback)", when
// disabled or not installed. Semgrep and the fallback never both run for
// the same category in this design (one soft-conditions the other, not a
// supplement like checkov/trivy) — the per-(category,file,line,tier) `seen`
// dedup below still guards against Semgrep itself reporting the same
// match twice (observed in practice: overlapping regex spans on one line).
async function checkFeaturePosture(root, log) {
  const tooling = POSTURE_ENABLED ? await semgrepTooling() : { ok: false, reason: 'posture scan is disabled (compliance.posture.enabled=false).' };
  if (!tooling.ok) {
    log?.(`⚠ Semgrep unavailable for posture scan: ${tooling.reason}`);
    log?.('Engine: Ignite Built-In Posture Scanner (Fallback)');
    const posture = await checkFeaturePostureFallback(root);
    return { engine: 'fallback', posture };
  }

  log?.(`Engine: Semgrep CLI v${tooling.version} (External Posture Scanner)`);
  const posture = emptyPostureReport();
  try {
    const { stdout } = await runTool('semgrep', [
      'scan', '--config', POSTURE_RULESET, '--json', '--quiet', '--metrics', 'off', root,
    ], root, { allowedExitCodes: [0, 1] });
    const data = stdout.trim() ? JSON.parse(stdout) : { results: [] };
    const results = Array.isArray(data.results) ? data.results : [];
    const seen = new Set();
    for (const r of results) {
      const category = r.extra?.metadata?.category;
      const tier = r.extra?.metadata?.tier;
      if (!category || !posture[category]) continue;
      const relFile = await relativeToRoot(root, r.path);
      const line = Number(r.start?.line) || 1;
      const key = `${category}:${relFile}:${line}:${tier}`;
      if (seen.has(key)) continue;
      seen.add(key);
      let content = null;
      try { content = await fsp.readFile(path.join(root, relFile), 'utf8'); } catch { /* best-effort */ }
      posture[category].matches.push({
        file: relFile,
        line,
        tier,
        tool: 'semgrep',
        message: r.extra?.message || category,
        code: content ? buildSnippet(content, line) : null,
      });
    }
  } catch (e) {
    log?.(`⚠ Posture scan failed: ${e.message}`);
  }
  for (const category of POSTURE_CATEGORIES) {
    posture[category].status = classifyPostureMatches(posture[category].matches);
  }
  return { engine: 'semgrep', posture };
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

  // act needs the workspace to be a git repo for ref/branch metadata; Phase 5
  // would create one anyway, so initialize it here and reuse it for shipping.
  await runTool('git', ['init', '-b', 'main'], root);
  await runTool('git', ['add', '.'], root);
  await runTool(
    'git',
    ['-c', 'user.name=Onboarding Gatekeeper', '-c', 'user.email=gatekeeper@localhost',
     'commit', '-m', 'chore: initial compliant code drop via onboarding gatekeeper'],
    root
  );

  let token = '';
  try {
    token = (await runTool('gh', ['auth', 'token'], root)).stdout;
  } catch {
    log('⚠ Could not read gh auth token — remote reusable workflows may fail to resolve.');
  }

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

const DEFAULT_TEST_NODE_MAJOR = 22; // oldest LTS with `node:sqlite` and other modern built-ins

async function readPackageJson(root) {
  try {
    return JSON.parse(await fsp.readFile(path.join(root, 'package.json'), 'utf8'));
  } catch {
    return null;
  }
}

function detectNpmTestScript(pkg) {
  const testScript = pkg?.scripts?.test;
  if (!testScript || /\bno test specified\b/.test(testScript)) return null;
  return testScript;
}

// Respects an `engines.node` minimum if the project declares one newer than
// our default, so containers running the test suite have whatever modern
// built-ins (e.g. `node:sqlite`) the project's own code expects.
function resolveTestNodeImage(pkg) {
  const engineNode = pkg?.engines?.node;
  const declaredMajor = engineNode ? parseInt(String(engineNode).match(/(\d+)/)?.[1], 10) : NaN;
  const major = Number.isInteger(declaredMajor) ? Math.max(DEFAULT_TEST_NODE_MAJOR, declaredMajor) : DEFAULT_TEST_NODE_MAJOR;
  return `node:${major}-alpine`;
}

async function fileExists(p) {
  return fsp.stat(p).then(() => true).catch(() => false);
}

// Each detector inspects the staged project root for that language's own
// marker file(s) and, if present, returns the Docker image + shell command
// used to install deps and run its native test suite. A project can match
// more than one (e.g. a Node frontend next to a Go backend) — all matches
// run, in this fixed order, and any one failing fails the phase.
const LANGUAGE_TEST_RUNNERS = [
  {
    language: 'Node.js',
    async detect(root) {
      const pkg = await readPackageJson(root);
      const testScript = detectNpmTestScript(pkg);
      if (!testScript) return null;
      return {
        detail: `npm test script: "${testScript}"`,
        image: resolveTestNodeImage(pkg),
        command: 'npm ci --no-audit --no-fund || npm install --no-audit --no-fund && npm test',
      };
    },
  },
  {
    language: 'Go',
    async detect(root) {
      if (!await fileExists(path.join(root, 'go.mod'))) return null;
      return {
        detail: '`go.mod` found',
        image: 'golang:1.23-alpine',
        command: 'go test ./...',
      };
    },
  },
  {
    language: 'Rust',
    async detect(root) {
      if (!await fileExists(path.join(root, 'Cargo.toml'))) return null;
      return {
        detail: '`Cargo.toml` found',
        image: 'rust:1-slim',
        command: 'cargo test --locked || cargo test',
      };
    },
  },
  {
    language: 'Python',
    async detect(root) {
      const hasProjectFile = await fileExists(path.join(root, 'pyproject.toml'))
        || await fileExists(path.join(root, 'setup.py'))
        || await fileExists(path.join(root, 'requirements.txt'));
      if (!hasProjectFile) return null;
      return {
        detail: 'Python project file found (pyproject.toml/setup.py/requirements.txt)',
        image: 'python:3.12-slim',
        command: [
          'pip install --quiet --no-input --disable-pip-version-check pytest',
          '(test -f requirements.txt && pip install --quiet --no-input --disable-pip-version-check -r requirements.txt || true)',
          '(test -f pyproject.toml -o -f setup.py && pip install --quiet --no-input --disable-pip-version-check -e . || true)',
          'pytest',
        ].join(' && '),
      };
    },
  },
  {
    language: 'Java (Maven)',
    async detect(root) {
      if (!await fileExists(path.join(root, 'pom.xml'))) return null;
      return {
        detail: '`pom.xml` found',
        image: 'maven:3-eclipse-temurin-21',
        command: 'mvn --batch-mode --no-transfer-progress test',
      };
    },
  },
  {
    language: 'Java (Gradle)',
    async detect(root) {
      const hasGradle = await fileExists(path.join(root, 'build.gradle'))
        || await fileExists(path.join(root, 'build.gradle.kts'));
      if (!hasGradle) return null;
      const hasWrapper = await fileExists(path.join(root, 'gradlew'));
      return {
        detail: hasWrapper ? '`build.gradle(.kts)` + gradlew wrapper found' : '`build.gradle(.kts)` found',
        image: 'gradle:8-jdk21',
        command: hasWrapper ? 'chmod +x ./gradlew && ./gradlew test --no-daemon' : 'gradle test --no-daemon',
      };
    },
  },
];

async function runProjectUnitTests(root, log) {
  const matches = [];
  for (const runner of LANGUAGE_TEST_RUNNERS) {
    const match = await runner.detect(root);
    if (match) matches.push({ language: runner.language, ...match });
  }

  if (matches.length === 0) {
    log('No recognized test project (package.json/go.mod/Cargo.toml/pyproject.toml/setup.py/requirements.txt/pom.xml/build.gradle) — skipping unit test run.');
    return { ran: false };
  }

  try {
    await runTool('docker', ['info', '--format', '{{.ServerVersion}}'], os.tmpdir());
  } catch {
    throw new Error('Cannot run project unit tests: Docker daemon is not running (start Docker Desktop).');
  }

  for (const { language, detail, image, command } of matches) {
    log(`Detected ${language} project (${detail}). Running its test suite in an isolated ${image} container (no host access, no network beyond dependency install)...`);
    const args = [
      'run', '--rm',
      '-v', `${root}:/repo`,
      '-w', '/repo',
      image,
      'sh', '-c', command,
    ];
    try {
      await runToolStreaming('docker', args, os.tmpdir(), (line) => log(line.slice(0, 400)), {
        timeoutMs: 10 * 60_000,
      });
    } catch (e) {
      throw new Error(`${language} unit tests failed: ${e.message}`);
    }
    log(`✓ ${language} unit tests passed.`);
  }
  return { ran: true, languages: matches.map((m) => m.language) };
}

/* ------------------------------------------------------------------ */
/* Phase 5: git + gh shipping                                          */
/* ------------------------------------------------------------------ */

async function shipToGitHub(root, org, repo, log, ghToken) {
  if (!ghToken) {
    throw new Error(
      'No GitHub account connected for this request. Connect your own GitHub account ' +
      '(GET /api/auth/github/connect, or the "Connect GitHub" button in the UI) before ' +
      'provisioning a repository — Phase 6 no longer falls back to the server\'s own gh session.'
    );
  }
  const ghEnv = { GH_TOKEN: ghToken };
  const git = (args, cwd = root) => runTool('git', args, cwd, { env: ghEnv });
  const gh = (args, cwd = root) => runTool('gh', args, cwd, { env: ghEnv });

  const safeOrg = sanitizeCliArg(org, 'Organization name');
  const safeRepo = sanitizeCliArg(repo, 'Repository name');
  const fullName = `${safeOrg}/${safeRepo}`;
  const isCreateValidation422 = (msg) => /HTTP 422/i.test(String(msg || ''));
  const repoExistsOnGitHub = async (owner, name) => {
    try {
      await gh(['api', `repos/${owner}/${name}`], root);
      return true;
    } catch {
      return false;
    }
  };

  // Phase 4 may already have initialized and committed the repo for act.
  const alreadyRepo = fs.existsSync(path.join(root, '.git'));
  if (alreadyRepo) {
    log('Reusing repository initialized during the local CI phase.');
  } else {
    log('$ git init -b main');
    await git(['init', '-b', 'main'], root);

    log('$ git add .');
    await git(['add', '.'], root);

    log('$ git commit -m "chore: initial compliant code drop via onboarding gatekeeper"');
    await git(
      [
        '-c', 'user.name=Onboarding Gatekeeper',
        '-c', 'user.email=gatekeeper@localhost',
        'commit',
        '-m', 'chore: initial compliant code drop via onboarding gatekeeper',
      ],
      root
    );
  }

  // Org rulesets with required workflows reject direct pushes to main
  // (GH013): the required workflow must run on GitHub in a PR context.
  // Compliant flow: init main server-side, push a branch, open a PR,
  // arm auto-merge, and watch the required checks.
  // Bootstrap branch (configurable, github.bootstrapBranch): the compliant
  // code lands here first, then PRs into the repo's default branch.
  const ONBOARD_BRANCH =
    process.env.BOOTSTRAP_BRANCH || CONFIG.github.bootstrapBranch || 'ignite';
  const remoteUrl = `https://github.com/${fullName}.git`;
  // gh as credential helper for this job only; no interactive prompts.
  const gitCred = [
    '-c', 'credential.helper=',
    '-c', 'credential.helper=!gh auth git-credential',
    '-c', 'core.askPass=',
  ];
  const gitId = ['-c', 'user.name=Onboarding Gatekeeper', '-c', 'user.email=gatekeeper@localhost'];

  log(`$ gh api POST orgs/${safeOrg}/repos (private, auto_init)`);
  try {
    await gh(['api', '-X', 'POST', `orgs/${safeOrg}/repos`,
      '-f', `name=${safeRepo}`, '-F', 'private=true', '-F', 'auto_init=true'], root);
  } catch (e) {
    if (/404/.test(e.message)) {
      // Personal account, not an organization.
      log(`"${safeOrg}" is not an org — creating under the authenticated user.`);
      try {
        await gh(['api', '-X', 'POST', 'user/repos',
          '-f', `name=${safeRepo}`, '-F', 'private=true', '-F', 'auto_init=true'], root);
      } catch (fallbackErr) {
        if (isCreateValidation422(fallbackErr.message)) {
          const exists = await repoExistsOnGitHub(safeOrg, safeRepo);
          if (exists) {
            log(`Repository ${fullName} already exists — reusing it.`);
          } else {
            throw fallbackErr;
          }
        } else {
          throw fallbackErr;
        }
      }
    } else if (isCreateValidation422(e.message)) {
      const exists = await repoExistsOnGitHub(safeOrg, safeRepo);
      if (exists) {
        log(`Repository ${fullName} already exists — reusing it.`);
      } else {
        throw e;
      }
    } else {
      throw e;
    }
  }

  try {
    await gh(['api', '-X', 'PATCH', `repos/${fullName}`, '-F', 'allow_auto_merge=true'], root);
    log('Enabled auto-merge on the repository.');
  } catch {
    log('⚠ Could not enable auto-merge — the PR will need a manual merge once checks pass.');
  }

  log(`$ git remote add origin "${remoteUrl}"`);
  await git(['remote', 'add', 'origin', remoteUrl], root);

  // Repo initialization is asynchronous — and org rulesets with required
  // workflows can block the creation of main entirely. Wait briefly for it.
  log('$ git fetch origin main');
  let mainExists = false;
  for (let attempt = 1; attempt <= 8; attempt++) {
    try {
      await git([...gitCred, 'fetch', 'origin', 'main'], root);
      mainExists = true;
      break;
    } catch {
      log(`main ref not ready yet (attempt ${attempt}/8) — retrying in 3s...`);
      await new Promise((r) => setTimeout(r, 3000));
    }
  }

  if (mainExists) {
    // Replay our commit on top of GitHub's init commit; on conflicts
    // (e.g. the project ships its own README.md) our version wins.
    log('$ git rebase -X theirs origin/main');
    await git([...gitId, 'rebase', '-X', 'theirs', 'origin/main'], root);
  }

  log(`$ git push -u origin HEAD:${ONBOARD_BRANCH}`);
  await git([...gitCred, 'push', '-u', 'origin', `HEAD:${ONBOARD_BRANCH}`], root);
  const { stdout: sha } = await git(['rev-parse', 'HEAD'], root);

  if (!mainExists) {
    // Try to create main directly from the compliant commit (works in
    // orgs/accounts without a required-workflow ruleset on main).
    log('$ gh api POST git/refs (create main from onboarding commit)');
    try {
      await gh(['api', '-X', 'POST', `repos/${fullName}/git/refs`,
        '-f', 'ref=refs/heads/main', '-f', `sha=${sha}`], root);
      log('✓ main created directly — no ruleset restriction on this repo.');
      await gh(['api', '-X', 'PATCH', `repos/${fullName}`, '-f', 'default_branch=main'], root)
        .then(() => log('✓ Default branch set to main.'))
        .catch(() => log('⚠ Could not set main as the default branch — adjust in repo settings.'));
      log(`✓ Code is live on main.`);
      return { repoUrl: `https://github.com/${fullName}` };
    } catch {
      // Deadlock: the ruleset blocks ALL creation of main (even GitHub's
      // auto-init), but the required workflow can only run on a PR whose
      // base is main. No client-side flow can satisfy it.
      await gh(['api', '-X', 'PATCH', `repos/${fullName}`,
        '-f', `default_branch=${ONBOARD_BRANCH}`], root).catch(() => {});
      log(`⚠ The org ruleset blocks creating "main" in new repos (bootstrap deadlock: the required workflow can only run on a PR, and a PR needs main to exist).`);
      log(`✓ Code shipped to "${ONBOARD_BRANCH}", now the repository's default branch.`);
      log(`⚠ Once an org admin adds a ruleset bypass so main can be bootstrapped, open a PR from "${ONBOARD_BRANCH}" into main.`);
      return { repoUrl: `https://github.com/${fullName}/tree/${ONBOARD_BRANCH}` };
    }
  }

  log('$ gh pr create --base main');
  const { stdout: prOut } = await gh([
    'pr', 'create',
    '--repo', fullName,
    '--base', 'main',
    '--head', ONBOARD_BRANCH,
    '--title', 'chore: initial compliant code drop via onboarding gatekeeper',
    '--body', 'Automated onboarding by Ignite. All local gates passed: structure audit, secret scan, AI governance, LLM deep-scan, and the org governance workflows executed locally via act.',
  ], root);
  const prUrl = (prOut.match(/https:\/\/github\.com\/\S+\/pull\/\d+/) || [prOut])[0];
  log(`✓ Pull request opened: ${prUrl}`);

  try {
    await gh(['pr', 'merge', prUrl, '--auto', '--squash'], root);
    log('✓ Auto-merge armed — the PR merges itself when the required workflow passes.');
  } catch (e) {
    log(`⚠ Auto-merge could not be armed (${e.message}). Merge manually once checks pass.`);
  }

  log('Waiting for the required org workflow to run on GitHub...');
  try {
    await runToolStreaming('gh', ['pr', 'checks', prUrl, '--watch', '--interval', '15'],
      root, (line) => log(line.slice(0, 300)), { timeoutMs: 20 * 60_000, env: ghEnv });
    log('✓ All remote required checks passed — auto-merge will land the PR on main.');
  } catch (e) {
    throw new Error(`Remote governance checks did not pass (${e.message}). PR left open for review: ${prUrl}`);
  }

  return { repoUrl: `https://github.com/${fullName}`, prUrl };
}

async function archivePhase6Payload(root, projectId, log) {
  if (projectId === null) return null;

  const tmpName = `ignite-phase6-payload-${crypto.randomUUID()}.zip`;
  const tmpZip = path.join(os.tmpdir(), tmpName);
  try {
    // Snapshot the exact tracked tree that phase 6 is attempting to push.
    await runTool('git', ['archive', '--format=zip', '-o', tmpZip, 'HEAD'], root);
    const data = await fsp.readFile(tmpZip);
    const size = data.length;
    const docName = `phase6-payload-${new Date().toISOString().replace(/[:]/g, '-')}.zip`;
    store.addUploadDocument(projectId, docName, 'application/zip', size, data);
    log(`📦 Archived phase 6 push payload for inspection: ${docName} (${(size / 1024).toFixed(1)} KB).`);
    return { name: docName, size };
  } catch (e) {
    log(`⚠ Could not archive phase 6 push payload: ${e.message}`);
    return null;
  } finally {
    await fsp.rm(tmpZip, { force: true }).catch(() => {});
  }
}

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

async function llmAvailable() {
  if (LLM_PROVIDER === 'openai') return !!OPENAI_API_KEY;
  try {
    const probe = await fetch(`${LLM_SCAN_URL}/health`, { signal: AbortSignal.timeout(3000) });
    return probe.ok;
  } catch {
    return false;
  }
}

// Short-TTL cache around llmAvailable() — callers (GET /api/config on every
// page load, plus the AI-explain/AI-fix endpoints) don't need a fresh
// health-probe on every single call; a stale-for-at-most-15s "available"
// verdict is harmless since checkLlmDeepScan's own inline health-probe is
// still the actual gate at scan time.
let llmAvailableCache = { value: null, expiresAt: 0 };
async function llmAvailableCached() {
  if (llmAvailableCache.value !== null && Date.now() < llmAvailableCache.expiresAt) {
    return llmAvailableCache.value;
  }
  const value = await llmAvailable();
  llmAvailableCache = { value, expiresAt: Date.now() + 15_000 };
  return value;
}

async function llmComplete(systemPrompt, userContent, { temperature = 0.2, timeoutMs = 120_000, label = 'complete' } = {}) {
  const { url, model, headers } = llmTarget();
  const finish = traceLlmCall(`${label} [${LLM_PROVIDER}]`, { url, model, timeoutMs, chars: userContent.length });
  let res;
  try {
    res = await fetch(url, {
      method: 'POST',
      headers,
      signal: AbortSignal.timeout(timeoutMs),
      body: JSON.stringify({
        model,
        stream: false,
        temperature,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userContent },
        ],
      }),
    });
  } catch (e) {
    finish(e.name === 'TimeoutError' ? 'TIMED OUT' : 'FAILED', e.message);
    return null;
  }
  if (!res.ok) {
    finish('HTTP ERROR', String(res.status));
    return null;
  }
  const data = await res.json();
  const text = (data.choices?.[0]?.message?.content || '').trim();
  finish('OK', `${text.length} chars returned`);
  return text || null;
}

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
/* Per-issue AI explanation (on-demand, cached — see /api/issues/explain) */
/* ------------------------------------------------------------------ */

const ISSUE_EXPLAIN_PROMPT = `You are explaining one single flagged code issue to a non-technical reader (e.g. a project manager), using the exact code snippet shown.
Write 2-4 sentences in plain language with no jargon: what is concretely wrong in THIS snippet, why it matters in the real world, and what should change. Do not just restate the technical summary you were given — actually explain it. Do not discuss anything beyond this one issue.`;

function issueExplanationHash({ category, file, line, summary }) {
  return crypto.createHash('sha256')
    .update(`${category}|${file || ''}|${line || 0}|${summary}`)
    .digest('hex');
}

async function explainIssueForHuman(issue) {
  const codeBlock = Array.isArray(issue.snippet?.lines)
    ? issue.snippet.lines.map((l) => `${l.number}: ${l.text}`).join('\n').slice(0, 4000)
    : '(no code snippet available)';
  const user = `Category: ${issue.category}\nSeverity: ${issue.severity}\nLocation: ${issue.file || 'unknown'}${issue.line ? ':' + issue.line : ''}\nTechnical summary: ${issue.summary}\n\nCode:\n${codeBlock}`;
  return await llmComplete(ISSUE_EXPLAIN_PROMPT, user, { temperature: 0.3, timeoutMs: 60_000, label: `issue-explain ${issue.category}:${issue.file || '?'}:${issue.line || 0}` });
}

/* ------------------------------------------------------------------ */
/* Ignite Studio — AI-suggested fix for one issue (see /api/issues/     */
/* suggest-fix). Suggest-only: never writes anything itself, so there's */
/* exactly one write path (the studio/file PUT the caller applies to    */
/* afterward) to reason about.                                          */
/* ------------------------------------------------------------------ */

const ISSUE_SUGGEST_FIX_PROMPT = `You are a senior software engineer proposing a concrete fix for one single flagged code issue, using the exact numbered code snippet shown.
Propose a corrected replacement for ONLY the exact line range shown in the snippet (from its first to its last numbered line) — do not rewrite the whole file, do not renumber lines, do not add lines outside that range.
Respond with ONLY a JSON object in this schema:
{"explanation":"<1-3 sentences: what changed and why it fixes the issue>","replacement":"<the corrected text for that exact line range, newline-separated, no line-number prefixes>"}
If you cannot safely propose a fix from the snippet alone, respond {"explanation":"<why not>","replacement":null}.`;

function stripJsonFence(text) {
  const trimmed = text.trim();
  const fenced = trimmed.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/i);
  return fenced ? fenced[1] : trimmed;
}

async function suggestFixForIssue(issue) {
  if (!Array.isArray(issue.snippet?.lines) || issue.snippet.lines.length === 0) return null;
  const codeBlock = issue.snippet.lines.map((l) => `${l.number}: ${l.text}`).join('\n').slice(0, 4000);
  const user = `Category: ${issue.category}\nSeverity: ${issue.severity}\nLocation: ${issue.file || 'unknown'}${issue.line ? ':' + issue.line : ''}\nTechnical summary: ${issue.summary}\n\nCode:\n${codeBlock}`;
  const text = await llmComplete(ISSUE_SUGGEST_FIX_PROMPT, user, { temperature: 0.2, timeoutMs: 60_000, label: `issue-suggest-fix ${issue.category}:${issue.file || '?'}:${issue.line || 0}` });
  if (!text) return null;
  let parsed;
  try {
    parsed = JSON.parse(stripJsonFence(text));
  } catch {
    return null;
  }
  if (typeof parsed.replacement !== 'string' && parsed.replacement !== null) return null;
  return {
    explanation: String(parsed.explanation || ''),
    replacement: parsed.replacement,
    startLine: issue.snippet.startLine,
    endLine: issue.snippet.startLine + issue.snippet.lines.length - 1,
  };
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

function buildMailTransport() {
  const { smtp } = CONFIG.notifications;
  if (smtp.host && smtp.user && smtp.pass) {
    return nodemailer.createTransport({
      host: smtp.host,
      port: smtp.port,
      secure: smtp.secure,
      auth: { user: smtp.user, pass: smtp.pass },
    });
  }
  // No SMTP credentials configured — fall back to the local sendmail binary.
  return nodemailer.createTransport({ sendmail: true });
}

function escapeHtmlMail(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function buildFailureEmail({ jobId, org, repo, error, failedPhase, record, insight }) {
  const rows = Object.keys(PHASE_TITLES)
    .map((id) => {
      const ph = record[id] || { state: 'pending', logs: [] };
      const color =
        ph.state === 'success' ? '#059669' :
        ph.state === 'failed' ? '#e11d48' :
        ph.state === 'running' ? '#2563eb' : '#94a3b8';
      return `<tr>
        <td style="padding:6px 12px;border-bottom:1px solid #e2e8f0;">Phase ${id}</td>
        <td style="padding:6px 12px;border-bottom:1px solid #e2e8f0;">${PHASE_TITLES[id]}</td>
        <td style="padding:6px 12px;border-bottom:1px solid #e2e8f0;color:${color};font-weight:600;text-transform:uppercase;">${ph.state}</td>
      </tr>`;
    })
    .join('');

  const failedSections = Object.keys(record)
    .filter((id) => record[id].state === 'failed' && record[id].logs.length > 0)
    .map((id) => `
      <h3 style="margin:24px 0 8px;color:#0f172a;">Phase ${id} — ${PHASE_TITLES[id]} logs</h3>
      <pre style="background:#0f172a;color:#e2e8f0;padding:14px;border-radius:8px;font-size:12px;line-height:1.6;overflow-x:auto;white-space:pre-wrap;">${escapeHtmlMail(record[id].logs.join('\n'))}</pre>`)
    .join('');

  const subject = `[Ignite] ❌ Onboarding failed at Phase ${failedPhase} — ${org}/${repo}`;
  const html = `
  <div style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:720px;margin:0 auto;color:#334155;">
    <h2 style="color:#e11d48;">Ignite onboarding pipeline failed</h2>
    <p><strong>Target:</strong> ${escapeHtmlMail(org)}/${escapeHtmlMail(repo)} (private)<br/>
       <strong>Job:</strong> ${jobId}<br/>
       <strong>Failed at:</strong> Phase ${failedPhase} — ${PHASE_TITLES[failedPhase] || 'Unknown'}<br/>
       <strong>Error:</strong> ${escapeHtmlMail(error)}</p>
    <table style="border-collapse:collapse;width:100%;font-size:14px;">
      <tr style="background:#f1f5f9;">
        <th style="padding:6px 12px;text-align:left;">#</th>
        <th style="padding:6px 12px;text-align:left;">Phase</th>
        <th style="padding:6px 12px;text-align:left;">Status</th>
      </tr>
      ${rows}
    </table>
    ${insight ? `
    <h3 style="margin:24px 0 8px;color:#0f172a;">🤖 AI insight</h3>
    <div style="background:#eff6ff;border:1px solid #bfdbfe;border-radius:8px;padding:14px;font-size:14px;line-height:1.6;white-space:pre-wrap;">${escapeHtmlMail(insight)}</div>` : ''}
    ${failedSections}
    <p style="color:#94a3b8;font-size:12px;margin-top:24px;">Sent by Ignite — staging files were cleaned up. Fix the violations and re-run the pipeline.</p>
  </div>`;

  return { subject, html };
}

async function sendFailureNotification(details) {
  const { enabled, to, from } = CONFIG.notifications;
  if (!enabled || !to) return { sent: false, reason: 'notifications disabled or no recipient configured' };
  const transport = buildMailTransport();
  const { subject, html } = buildFailureEmail(details);
  await transport.sendMail({ from, to, subject, html });
  return { sent: true, to };
}

/* A developer chose to bypass one or more flagged guideline violations.
   Always notify — this is the whole point of the override audit trail. */
function buildOverrideEmail({ jobId, org, repo, phase, actor, applied }) {
  const rows = applied
    .map(
      ({ issue, justification }) => `
      <tr>
        <td style="padding:6px 12px;border-bottom:1px solid #e2e8f0;text-transform:uppercase;font-weight:600;color:${issue.severity === 'error' ? '#e11d48' : '#b45309'};">${escapeHtmlMail(issue.severity)}</td>
        <td style="padding:6px 12px;border-bottom:1px solid #e2e8f0;">${escapeHtmlMail(issue.category)}</td>
        <td style="padding:6px 12px;border-bottom:1px solid #e2e8f0;font-family:monospace;">${escapeHtmlMail(issue.file || '')}${issue.line ? ':' + issue.line : ''}</td>
        <td style="padding:6px 12px;border-bottom:1px solid #e2e8f0;">${escapeHtmlMail(issue.summary)}</td>
        <td style="padding:6px 12px;border-bottom:1px solid #e2e8f0;">${escapeHtmlMail(justification)}</td>
      </tr>`
    )
    .join('');

  const errorCount = applied.filter((a) => a.issue.severity === 'error').length;
  const subject = `[Ignite] ⚠ ${applied.length} guideline override(s) at Phase ${phase} — ${org}/${repo}`;
  const html = `
  <div style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:760px;margin:0 auto;color:#334155;">
    <h2 style="color:#b45309;">A developer overrode flagged guideline check(s)</h2>
    <p><strong>Target:</strong> ${escapeHtmlMail(org)}/${escapeHtmlMail(repo)}<br/>
       <strong>Job:</strong> ${jobId}<br/>
       <strong>Phase:</strong> ${phase} — ${PHASE_TITLES[phase] || 'Unknown'}<br/>
       <strong>Overridden by:</strong> ${escapeHtmlMail(actor.name || actor.email)} (${escapeHtmlMail(actor.email)})<br/>
       <strong>Blocking findings bypassed:</strong> ${errorCount} of ${applied.length}</p>
    <table style="border-collapse:collapse;width:100%;font-size:13px;">
      <tr style="background:#f1f5f9;">
        <th style="padding:6px 12px;text-align:left;">Severity</th>
        <th style="padding:6px 12px;text-align:left;">Category</th>
        <th style="padding:6px 12px;text-align:left;">Location</th>
        <th style="padding:6px 12px;text-align:left;">Finding</th>
        <th style="padding:6px 12px;text-align:left;">Justification</th>
      </tr>
      ${rows}
    </table>
    <p style="color:#94a3b8;font-size:12px;margin-top:24px;">Sent by Ignite — this override is recorded in the project's audit log.</p>
  </div>`;

  return { subject, html };
}

async function sendOverrideNotification(details) {
  const { enabled, to, from } = CONFIG.notifications;
  if (!enabled || !to) return { sent: false, reason: 'notifications disabled or no recipient configured' };
  const transport = buildMailTransport();
  const { subject, html } = buildOverrideEmail(details);
  await transport.sendMail({ from, to, subject, html });
  return { sent: true, to };
}

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

/* Safe subset of config for the frontend. `orgs` accepts a comma-separated
   string or an array; first entry is the default proposal. */
app.get('/api/config', async (req, res) => {
  const raw = CONFIG.github.orgs;
  const orgs = (Array.isArray(raw) ? raw : String(raw).split(','))
    .map((s) => String(s).trim())
    .filter(Boolean);
  // Phase 4 still runs everything else (secrets/AI-governance/IaC/SAST/
  // etc.) with no LLM configured or reachable — only its LLM deep-scan
  // sub-check is skipped — so its displayed name shouldn't claim an "AI"
  // check ran when it didn't. Only swaps the *unmodified* default title;
  // an org that already customized phase 4's title via config.json's
  // `phases` override is left alone.
  const aiAvailable = await llmAvailableCached();
  const defaultPhase4Title = DEFAULT_PHASE_META.find((d) => d.id === 4)?.title;
  const phases = PHASE_META.map((p) => {
    if (p.id !== 4 || aiAvailable || p.title !== defaultPhase4Title) return p;
    return { ...p, title: 'Security & Compliance Scan' };
  });
  res.json({ orgs, phases });
});

// Status of the optional external tools Ignite integrates with but doesn't
// require — each one soft-skips to a built-in fallback when missing, so this
// is purely informational (drives the "connected/disconnected" pills in the
// UI's top-right Tools panel), never gates anything itself.
app.get('/api/tools/status', async (req, res) => {
  const [ort, licensee, gitleaks, trivy, checkov, hadolint, syft, cosign, semgrep, bearer, jscpd, gocloc, spectral] = await Promise.all([
    ortTooling(), licenseeTooling(), gitleaksTooling(), trivyTooling(), checkovTooling(), hadolintTooling(), syftTooling(), cosignTooling(), semgrepTooling(), bearerTooling(), jscpdTooling(), goclocTooling(), spectralTooling(),
  ]);
  res.json({
    ort: { ...ort, enabled: true },
    licensee: { ...licensee, enabled: true },
    gitleaks: { ...gitleaks, enabled: GITLEAKS_ENABLED },
    trivy: { ...trivy, enabled: TRIVY_ENABLED },
    checkov: { ...checkov, enabled: CHECKOV_ENABLED },
    hadolint: { ...hadolint, enabled: HADOLINT_ENABLED },
    syft: { ...syft, enabled: SYFT_ENABLED },
    cosign: { ...cosign, enabled: COSIGN_ENABLED },
    semgrep: { ...semgrep, enabled: SEMGREP_ENABLED },
    bearer: { ...bearer, enabled: BEARER_ENABLED },
    jscpd: { ...jscpd, enabled: JSCPD_ENABLED },
    gocloc: { ...gocloc, enabled: GOCLOC_ENABLED },
    spectral: { ...spectral, enabled: SPECTRAL_ENABLED },
  });
});

/* Onboarding history: project list, per-project steps + documents, and
   document download. Document blobs never leave the DB except via download. */
app.get('/api/projects', (req, res) => {
  res.json(store.listProjects());
});

app.get('/api/projects/:id', (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid project id.' });
  const project = store.getProjectDetails(id);
  if (!project) return res.status(404).json({ error: 'Project not found.' });
  res.json(project);
});

// Flagged issues for one project — same shape whether the run is still in
// progress (read from the live in-memory pipeline state) or long finished
// (read from the `issues` table), so the UI can show the list at any time.
app.get('/api/projects/:id/issues', (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid project id.' });
  if (!store.projectExists(id)) return res.status(404).json({ error: 'Project not found.' });
  res.json({ ok: true, issues: store.getProjectIssues(id) });
});

// Same, but addressable by the in-flight job id while a pipeline is still
// streaming — lets the UI show the issue list mid-run, before Phase 6.
app.get('/api/pipeline/:jobId/issues', (req, res) => {
  const jobId = String(req.params.jobId || '').trim();
  const live = runningRuns.get(jobId);
  if (live) {
    return res.json({ ok: true, running: true, issues: live.allIssues, projectId: live.projectId });
  }
  const projectId = store.getProjectIdByJobId(jobId);
  if (projectId === null) return res.status(404).json({ error: 'Unknown job id.' });
  res.json({ ok: true, running: false, issues: store.getProjectIssues(projectId), projectId });
});

/* ------------------------------------------------------------------ */
/* Ignite Studio — file-tree/editor + rescan. Available in two windows: */
/*  - 'live': the run is still paused at the review gate — projectRoot   */
/*    and sourceBackupDir are both on disk, issues live in runState.    */
/*  - 'kept': the review gate already resolved, but the run didn't ship  */
/*    for real (dry run / user stopped / unresolved findings / CI       */
/*    failure) — sourceBackupDir is the one already kept alive by       */
/*    pendingEffectivations for the "Effectivate" feature (24h TTL,     */
/*    cleared on Effectivate, or gone on server restart); issues live   */
/*    in the DB. A run that DID ship for real gets neither: the code is */
/*    already safely on GitHub, so Studio has nothing to open — fixing  */
/*    it means a normal PR, not reopening a local copy indefinitely.    */
/* ------------------------------------------------------------------ */

const STUDIO_MAX_FILE_BYTES = 500_000; // browser-editor cap, independent of the LLM deep-scan's own per-file cap
function studioNoopLog() {}

function resolveStudioContext(req, res) {
  const jobId = String(req.params.jobId || '').trim();

  const runState = runningRuns.get(jobId);
  if (runState && runState.reviewActive && runState.projectRoot) {
    reviewDecisions.touch(jobId);
    return {
      jobId,
      root: runState.projectRoot,
      backupRoot: runState.sourceBackupDir,
      org: runState.org,
      repo: runState.repo,
      getIssues: () => runState.allIssues,
      replacePhase4: (freshIssues) => {
        const others = runState.allIssues.filter((i) => i.phase !== 4);
        runState.allIssues.length = 0;
        runState.allIssues.push(...others, ...freshIssues);
        runState.persistIssuesSnapshot();
      },
      replaceLicense: (freshIssues) => {
        const others = runState.allIssues.filter((i) => i.category !== 'license-compliance');
        runState.allIssues.length = 0;
        runState.allIssues.push(...others, ...freshIssues);
        runState.persistIssuesSnapshot();
      },
      replaceDependencyVulns: (freshIssues) => {
        const others = runState.allIssues.filter((i) => i.category !== 'dependency-vulnerability');
        runState.allIssues.length = 0;
        runState.allIssues.push(...others, ...freshIssues);
        runState.persistIssuesSnapshot();
      },
    };
  }

  const projectId = store.getProjectIdByJobId(jobId);
  if (projectId !== null) {
    cleanupExpiredEffectivations();
    const kept = pendingEffectivations.get(projectId);
    if (kept) {
      return {
        jobId,
        root: kept.sourceBackupDir,
        backupRoot: kept.sourceBackupDir,
        org: kept.org,
        repo: kept.repo,
        getIssues: () => store.getProjectIssues(projectId),
        replacePhase4: (freshIssues) => {
          const current = store.getProjectIssues(projectId);
          const overriddenIds = new Set(current.filter((i) => i.status === 'overridden').map((i) => i.id));
          const merged = [...current.filter((i) => i.phase !== 4), ...freshIssues];
          store.replaceProjectIssues(projectId, merged, overriddenIds);
        },
        replaceLicense: (freshIssues) => {
          const current = store.getProjectIssues(projectId);
          const overriddenIds = new Set(current.filter((i) => i.status === 'overridden').map((i) => i.id));
          const merged = [...current.filter((i) => i.category !== 'license-compliance'), ...freshIssues];
          store.replaceProjectIssues(projectId, merged, overriddenIds);
        },
        replaceDependencyVulns: (freshIssues) => {
          const current = store.getProjectIssues(projectId);
          const overriddenIds = new Set(current.filter((i) => i.status === 'overridden').map((i) => i.id));
          const merged = [...current.filter((i) => i.category !== 'dependency-vulnerability'), ...freshIssues];
          store.replaceProjectIssues(projectId, merged, overriddenIds);
        },
      };
    }
  }

  res.status(409).json({ error: 'This run\'s source is no longer available (already shipped for real, expired, or unknown job).' });
  return null;
}

app.get('/api/pipeline/:jobId/studio/tree', async (req, res) => {
  const ctx = resolveStudioContext(req, res);
  if (!ctx) return;
  try {
    const files = [];
    for await (const file of walkFiles(ctx.root)) {
      const stat = await fsp.stat(file);
      files.push({ path: path.relative(ctx.root, file), size: stat.size });
    }
    res.json({ ok: true, files });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/pipeline/:jobId/studio/file', async (req, res) => {
  const ctx = resolveStudioContext(req, res);
  if (!ctx) return;
  try {
    const target = resolveWithinRoot(ctx.root, String(req.query.path || ''));
    const buffer = await fsp.readFile(target);
    if (looksBinary(buffer)) return res.status(415).json({ error: 'Binary file — cannot display in Studio.' });
    if (buffer.length > STUDIO_MAX_FILE_BYTES) return res.status(413).json({ error: 'File too large to display in Studio.' });
    res.json({ ok: true, content: buffer.toString('utf8') });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// In 'live' mode, writes to BOTH the live staging tree and the immutable
// sourceBackupDir — Phase 6 always clones the publish workspace from
// sourceBackupDir, never from projectRoot, so a fix written only to
// projectRoot would validate here but silently vanish from what actually
// gets pushed. In 'kept' mode root === backupRoot (only sourceBackupDir is
// still on disk), so it's a single write.
app.put('/api/pipeline/:jobId/studio/file', async (req, res) => {
  const ctx = resolveStudioContext(req, res);
  if (!ctx) return;
  const relPath = String(req.body?.path || '');
  const content = req.body?.content;
  if (typeof content !== 'string') return res.status(400).json({ error: 'content (string) is required.' });
  try {
    const liveTarget = resolveWithinRoot(ctx.root, relPath);
    await fsp.mkdir(path.dirname(liveTarget), { recursive: true });
    await fsp.writeFile(liveTarget, content, 'utf8');
    if (ctx.backupRoot !== ctx.root) {
      const backupTarget = resolveWithinRoot(ctx.backupRoot, relPath);
      await fsp.mkdir(path.dirname(backupTarget), { recursive: true });
      await fsp.writeFile(backupTarget, content, 'utf8');
    }
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// Re-runs the phase-4 checks against the (now-edited) tree and replaces just
// that phase's slice of the run's issue list — the other phases' issues are
// untouched. All three checks are per-file-hash cached (file_scan_cache,
// same {org, repo} key used for the original scan), so re-scanning after
// editing one or two files is cheap: everything else is a cache hit.
app.post('/api/pipeline/:jobId/studio/rescan', async (req, res) => {
  const ctx = resolveStudioContext(req, res);
  if (!ctx) return;
  try {
    const cacheKey = { org: ctx.org, repo: ctx.repo };
    const secrets = await checkSecrets(ctx.root, studioNoopLog, cacheKey);
    const governance = await checkAiGovernance(ctx.root, cacheKey);
    const llm = await checkLlmDeepScan(ctx.root, studioNoopLog, cacheKey);
    const iac = await checkIacSecurity(ctx.root, studioNoopLog);
    const freshIssues = collectPhase4Issues({ secrets, governance, llm, iac }).map((issue) => ({ ...issue, phase: 4 }));

    // License compliance runs alongside the phase 4 checks here too — same
    // scan Phase 3 runs on a fresh upload (manifests via scanDependencyLicenses
    // + every LICENSE file in the tree), so "Rescan" picks up dependency/
    // license changes without needing the separate Dependencies view.
    const licenseScan = await scanDependencyLicenses(ctx.root, studioNoopLog);
    const licenseFileFindings = await scanProjectLicenseFiles(ctx.root);
    const freshLicenseIssues = collectLicenseIssues({ manifests: licenseScan.manifests, licenseFiles: licenseFileFindings })
      .map((issue) => ({ ...issue, phase: 3 }));

    // Same reasoning as license compliance just above — the deps.dev CVE/GHSA
    // scan Phase 3 runs on a fresh upload, so an edit that bumps a vulnerable
    // dependency's version resolves that finding on "Rescan" too.
    const depVulnManifests = await scanDependencyVulnerabilities(ctx.root);
    const freshDependencyVulnIssues = collectDependencyVulnerabilityIssues({ manifests: depVulnManifests })
      .map((issue) => ({ ...issue, phase: 3 }));

    const previousIssues = ctx.getIssues();
    const previousPhase4Ids = new Set(previousIssues.filter((i) => i.phase === 4).map((i) => i.id));
    const previousLicenseIds = new Set(previousIssues.filter((i) => i.category === 'license-compliance').map((i) => i.id));
    const previousDependencyVulnIds = new Set(previousIssues.filter((i) => i.category === 'dependency-vulnerability').map((i) => i.id));
    const freshIds = new Set(freshIssues.map((i) => i.id));
    const freshLicenseIds = new Set(freshLicenseIssues.map((i) => i.id));
    const freshDependencyVulnIds = new Set(freshDependencyVulnIssues.map((i) => i.id));
    const resolvedIds = [
      ...[...previousPhase4Ids].filter((id) => !freshIds.has(id)),
      ...[...previousLicenseIds].filter((id) => !freshLicenseIds.has(id)),
      ...[...previousDependencyVulnIds].filter((id) => !freshDependencyVulnIds.has(id)),
    ];
    const newIds = [
      ...[...freshIds].filter((id) => !previousPhase4Ids.has(id)),
      ...[...freshLicenseIds].filter((id) => !previousLicenseIds.has(id)),
      ...[...freshDependencyVulnIds].filter((id) => !previousDependencyVulnIds.has(id)),
    ];

    ctx.replacePhase4(freshIssues);
    ctx.replaceLicense(freshLicenseIssues);
    ctx.replaceDependencyVulns(freshDependencyVulnIssues);

    res.json({ ok: true, issues: ctx.getIssues(), resolvedIds, newIds });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
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
    const url = `https://registry.npmjs.org/${encodeURIComponent(name).replace('%40', '@')}/${encodeURIComponent(version)}`;
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
      const { tier, reason } = classifyLicenseTier(licenses);
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
    const content = await fsp.readFile(file, 'utf8').catch(() => null);
    if (content == null) continue;
    const classified = classifyLicenseText(content);
    if (classified) findings.push({ file: path.relative(root, file), ...classified });
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

app.get('/api/pipeline/:jobId/studio/dependencies', async (req, res) => {
  const ctx = resolveStudioContext(req, res);
  if (!ctx) return;
  try {
    res.json({ ok: true, ...(await scanDependencyLicenses(ctx.root)) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Studio report views for the three non-issue Phase 4 artifacts (SBOM, LOC
// metrics, compliance posture) — same on-demand-recompute pattern as
// /studio/dependencies above, so Studio can show them live at the review
// gate without waiting for the pipeline to finish and persist a document.
app.get('/api/pipeline/:jobId/studio/sbom', async (req, res) => {
  const ctx = resolveStudioContext(req, res);
  if (!ctx) return;
  try {
    res.json({ ok: true, ...(await generateSbom(ctx.root, studioNoopLog)) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/pipeline/:jobId/studio/loc-metrics', async (req, res) => {
  const ctx = resolveStudioContext(req, res);
  if (!ctx) return;
  try {
    res.json({ ok: true, ...(await generateLocMetrics(ctx.root, studioNoopLog)) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/pipeline/:jobId/studio/posture', async (req, res) => {
  const ctx = resolveStudioContext(req, res);
  if (!ctx) return;
  try {
    res.json({ ok: true, ...(await checkFeaturePosture(ctx.root, studioNoopLog)) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Standalone, job-independent equivalent for agent/CI use — same
// projectPath convention as /api/pipeline/validate-all.
app.post('/api/dependencies/check', async (req, res) => {
  let projectPath;
  try {
    projectPath = sanitizeAbsoluteProjectPath(req.body?.projectPath || '');
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }
  const stat = await fsp.stat(projectPath).catch(() => null);
  if (!stat || !stat.isDirectory()) {
    return res.status(400).json({ error: `projectPath does not exist or is not a directory: ${projectPath}` });
  }
  try {
    res.json({ ok: true, projectPath, ...(await scanDependencyLicenses(projectPath)) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Standalone dependency vulnerability scan (known CVE/GHSA advisories via
// deps.dev) — same projectPath convention as /api/dependencies/check, and
// the endpoint the MCP server's check_dependency_vulnerabilities tool
// proxies to.
app.post('/api/dependencies/vulnerabilities', async (req, res) => {
  let projectPath;
  try {
    projectPath = sanitizeAbsoluteProjectPath(req.body?.projectPath || '');
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }
  const stat = await fsp.stat(projectPath).catch(() => null);
  if (!stat || !stat.isDirectory()) {
    return res.status(400).json({ error: `projectPath does not exist or is not a directory: ${projectPath}` });
  }
  try {
    const manifests = await scanDependencyVulnerabilities(projectPath);
    const counts = { critical: 0, advisory: 0 };
    for (const m of manifests) {
      for (const d of m.dependencies) {
        for (const v of d.vulnerabilities) {
          if (v.severity === 'error') counts.critical++; else counts.advisory++;
        }
      }
    }
    res.json({ ok: true, projectPath, manifests, counts });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// On-demand, non-technical AI explanation of a single flagged issue's code
// snippet (shown as the hover tooltip in the UI). Cached in the DB by a
// stable hash of the issue's identity, so opening the same finding again —
// even in a different run — never re-triggers the LLM call.
// Shared by /api/issues/explain and /api/issues/suggest-fix — both accept
// the same client-supplied issue shape (category/severity/file/line/summary
// + optional snippet) and need it validated/trimmed the same way.
function parseIssueFromBody(body) {
  const category = String(body.category || '').trim();
  const summary = String(body.summary || '').trim();
  if (!category || !summary) return null;
  return {
    category,
    severity: ['error', 'warning'].includes(body.severity) ? body.severity : 'warning',
    file: body.file ? String(body.file).slice(0, 500) : null,
    line: Number.isInteger(body.line) ? body.line : null,
    summary: summary.slice(0, 500),
    snippet: body.snippet && typeof body.snippet === 'object' && Array.isArray(body.snippet.lines)
      ? body.snippet
      : null,
  };
}

app.post('/api/issues/explain', async (req, res) => {
  const issue = parseIssueFromBody(req.body || {});
  if (!issue) return res.status(400).json({ error: 'category and summary are required.' });

  const hash = issueExplanationHash(issue);
  const cached = store.getCachedIssueExplanation(hash);
  if (cached) return res.json({ ok: true, explanation: cached, cached: true });

  if (!(await llmAvailableCached())) {
    return res.json({ ok: true, explanation: null, cached: false, reason: 'AI explanation service unavailable.' });
  }
  try {
    const explanation = await explainIssueForHuman(issue);
    if (explanation) store.cacheIssueExplanation(hash, explanation);
    res.json({ ok: true, explanation, cached: false });
  } catch (e) {
    res.status(502).json({ ok: false, error: e.message });
  }
});

// Ignite Studio: AI-suggested fix for one issue's exact snippet range.
// Suggest-only — never writes to disk itself (see PUT
// /api/pipeline/:jobId/studio/file for the one write path). Not cached like
// /explain — a fix is requested at most a handful of times per session.
app.post('/api/issues/suggest-fix', async (req, res) => {
  const issue = parseIssueFromBody(req.body || {});
  if (!issue) return res.status(400).json({ error: 'category and summary are required.' });
  if (!issue.snippet) return res.status(400).json({ error: 'A code snippet is required to suggest a fix.' });

  if (!(await llmAvailableCached())) {
    return res.json({ ok: true, suggestion: null, reason: 'AI fix suggestion service unavailable.' });
  }
  try {
    const suggestion = await suggestFixForIssue(issue);
    res.json({ ok: true, suggestion });
  } catch (e) {
    res.status(502).json({ ok: false, error: e.message });
  }
});

app.post('/api/pipeline/:jobId/review-decision', (req, res) => {
  const jobId = String(req.params.jobId || '').trim();
  const proceed = req.body?.proceed === true;
  const overrides = Array.isArray(req.body?.overrides) ? req.body.overrides : [];

  let actor = null;
  if (overrides.length > 0) {
    actor = resolveActor(req);
    if (!actor) {
      return res.status(401).json({ error: 'Log in, or provide actor {email,name}, to submit overrides.' });
    }
  }

  const ok = reviewDecisions.resolve(jobId, {
    proceed,
    overrides,
    actor,
    reason: proceed ? 'user-continue' : 'user-stop',
  });
  if (!ok) return res.status(404).json({ error: 'No pending review decision for this job.' });
  res.json({ ok: true });
});

// Turns a completed simulation (dryRun) into the real thing: provisions and
// pushes the exact snapshot that was already validated, without re-running
// phases 1-5. Still hard-gated on any blocking finding that hasn't been
// justified — same rule as the live review gate, just re-checked here
// against the project's current (possibly since-updated) issue list.
app.post('/api/projects/:projectId/effectivate', async (req, res) => {
  const projectId = Number(req.params.projectId);
  if (!Number.isInteger(projectId)) return res.status(400).json({ error: 'Invalid project id.' });

  const ghToken = auth.resolveGithubToken(req);
  if (!ghToken) {
    return res.status(401).json({
      error: req.user
        ? 'Connect your GitHub account before effectivating (GET /api/auth/github/connect).'
        : 'Log in and connect your GitHub account before effectivating.',
    });
  }

  cleanupExpiredEffectivations();
  const pending = pendingEffectivations.get(projectId);
  if (!pending) {
    return res.status(404).json({ error: 'No simulation output available to effectivate for this project (missing, expired, or already effectivated).' });
  }

  const issues = store.getProjectIssues(projectId);
  // Issues already justified at the live review gate (during the
  // simulation itself) are already `status: 'overridden'` in the DB — don't
  // demand a second justification for those here, only for ones still open.
  const stillOpen = issues.filter((i) => i.status !== 'overridden');
  const requestedOverrides = Array.isArray(req.body?.overrides) ? req.body.overrides : [];
  const { ok, unresolvedErrors, applied } = validateOverrides(stillOpen, requestedOverrides);

  if (!ok) {
    return res.status(409).json({
      error: `${unresolvedErrors.length} blocking finding(s) still need to be checked + justified before this simulation can be effectivated.`,
      needsReview: true,
      issues,
    });
  }

  let actor = null;
  if (applied.length > 0) {
    actor = resolveActor(req);
    if (!actor) {
      return res.status(401).json({ error: 'Log in, or provide actor {email,name}, to submit overrides.', needsReview: true, issues });
    }
  }

  const { org, repo, sourceBackupDir } = pending;
  const publishDir = sourceBackupDir + '-effectivate-publish';
  const effectivateLogs = ['Effectivating simulation — provisioning + pushing the previously validated snapshot.'];
  const log = (message) => {
    effectivateLogs.push(message);
    try { store.upsertStep(projectId, 6, PHASE_TITLES[6], 'running', effectivateLogs.join('\n')); } catch { /* best-effort */ }
  };

  try {
    const backupStat = await fsp.stat(sourceBackupDir).catch(() => null);
    if (!backupStat || !backupStat.isDirectory()) {
      pendingEffectivations.delete(projectId);
      return res.status(410).json({ error: 'Simulation snapshot is no longer available (expired or already effectivated). Re-run the simulation to try again.' });
    }

    if (applied.length > 0) {
      const byPhase = new Map();
      for (const item of applied) {
        const p = item.issue.phase;
        if (!byPhase.has(p)) byPhase.set(p, []);
        byPhase.get(p).push(item);
      }
      for (const [p, group] of byPhase) {
        await recordOverrides({ projectId, jobId: `effectivate-${projectId}`, org, repo, phase: p, actor, applied: group });
      }
      store.replaceProjectIssues(projectId, issues, applied.map(({ issue }) => issue.id).concat(
        issues.filter((i) => i.status === 'overridden').map((i) => i.id)
      ));
    }

    await fsp.rm(publishDir, { recursive: true, force: true }).catch(() => {});
    await cloneDirectoryWithoutSymlinks(sourceBackupDir, publishDir);
    await archivePhase6Payload(publishDir, projectId, log);
    const { repoUrl, prUrl } = await shipToGitHub(publishDir, org, repo, log, ghToken);

    store.finishProject('success', null, repoUrl, prUrl || null, projectId);
    effectivateLogs.push(`✓ Effectivated — repository live at ${repoUrl}`);
    store.upsertStep(projectId, 6, PHASE_TITLES[6], 'success', effectivateLogs.join('\n'));
    pendingEffectivations.delete(projectId);
    await fsp.rm(sourceBackupDir, { recursive: true, force: true }).catch(() => {});
    await fsp.rm(publishDir, { recursive: true, force: true }).catch(() => {});
    res.json({ ok: true, repoUrl, prUrl });
  } catch (e) {
    effectivateLogs.push(`✗ Effectivate failed: ${e.message}`);
    store.upsertStep(projectId, 6, PHASE_TITLES[6], 'failed', effectivateLogs.join('\n'));
    res.status(502).json({ error: `Effectivate failed: ${e.message}` });
  }
});

app.post('/api/pipeline/validate-all', async (req, res) => {
  const body = req.body || {};
  const org = String(body.org || 'local-validation').trim();
  const repo = String(body.repo || 'local-project').trim();
  // Phase 2 disabled by config (default) means GxP isn't a concept this
  // Ignite install offers at all — a caller passing gxp:true anyway is
  // ignored rather than honored, matching "hidden and therefore not checked".
  const isGxp = PHASE_ENABLED[2] && body.gxp === true;
  const runLocalCi = body.runLocalCi !== false;
  const warningDecision = String(body.warningDecision || 'continue').toLowerCase();
  const projectPath = sanitizeAbsoluteProjectPath(body.projectPath || process.cwd());
  const gxpLinks = Array.isArray(body.gxpLinks) ? body.gxpLinks : [];
  const requestedOverrides = Array.isArray(body.overrides) ? body.overrides : [];

  const jobId = crypto.randomUUID();
  const stagingDir = path.join(os.tmpdir(), 'gatekeeper-staging', `${jobId}-api-validation`);
  const workflowDir = stagingDir + '-workflows';
  let projectId = null;

  const events = [];
  const record = {};
  const rec = (phase) => (record[phase] ??= { state: 'pending', logs: [] });
  const persistPhase = (phase) => {
    if (projectId === null) return;
    const ph = rec(phase);
    try {
      store.upsertStep(projectId, phase, PHASE_TITLES[phase], ph.state, ph.logs.join('\n'));
    } catch {
      // Live history persistence is best-effort.
    }
  };
  const phaseLog = (phase) => (message) => {
    rec(phase).logs.push(message);
    events.push({ type: 'log', phase, message });
    persistPhase(phase);
  };

  let currentPhase = 1;
  const status = (phase, state, extra = {}) => {
    if (state === 'running') currentPhase = phase;
    rec(phase).state = state;
    events.push({ type: 'status', phase, state, ...extra });
    persistPhase(phase);
  };

  const phaseSummary = () => Object.keys(PHASE_TITLES)
    .map((id) => {
      const ph = record[id] || { state: 'pending', logs: [] };
      return {
        phase: Number(id),
        title: PHASE_TITLES[id],
        state: ph.state,
        logs: ph.logs,
      };
    });

  try {
    status(1, 'running');
    const log1 = phaseLog(1);

    if (!REPO_NAME_REGEX.test(repo) || repo === '.' || repo === '..') {
      throw Object.assign(new Error(`Invalid repository name: "${repo}"`), { phase: 1 });
    }
    if (!GITHUB_NAME_REGEX.test(org) && org !== 'local-validation') {
      throw Object.assign(new Error(`Invalid organization name: "${org}"`), { phase: 1 });
    }

    log1(`Validation job ${jobId}`);
    log1(`Source project path: ${projectPath}`);
    log1(`Target metadata: ${org}/${repo}`);
    log1(`GxP-regulated process: ${isGxp ? 'YES' : 'no'}`);
    projectId = store.createProject(jobId, org, repo, isGxp, resolveRequestSource(req, 'api'));
    for (const id of Object.keys(record)) persistPhase(Number(id));
    status(1, 'success');

    if (!isGxp) {
      phaseLog(2)('Process declared non-GxP — no validation documents required.');
      status(2, 'skipped');
    } else {
      status(2, 'running');
      const logG = phaseLog(2);
      const validLinks = [];
      for (const l of gxpLinks) {
        const url = String(l?.url || '').trim();
        let parsed = null;
        try { parsed = new URL(url); } catch { /* invalid */ }
        if (!parsed || !['http:', 'https:'].includes(parsed.protocol)) {
          throw Object.assign(new Error(`Invalid GxP document link: "${url}" (must be http/https).`), { phase: 2 });
        }
        validLinks.push({ url, name: String(l?.name || '').trim() || parsed.hostname + parsed.pathname });
      }
      if (validLinks.length === 0) {
        throw Object.assign(new Error('GxP process declared but no gxpLinks provided in API payload.'), { phase: 2 });
      }
      logG(`Received ${validLinks.length} GxP document link(s) for validation context.`);
      status(2, 'success');
    }

    status(3, 'running');
    const log2 = phaseLog(3);
    await stageExistingProject(projectPath, stagingDir, log2);
    const projectRoot = await resolveProjectRoot(stagingDir);

    // License compliance runs first — the env-file check and unit tests
    // below throw on failure, and license findings must survive into the
    // combined issue list either way (same ordering as the interactive
    // pipeline). Dependency vulnerability findings ride along right after —
    // same non-throwing, must-survive-a-later-failure reasoning.
    const licenseIssues = [
      ...await runLicenseComplianceCheck(projectRoot, log2),
      ...await runDependencyVulnerabilityCheck(projectRoot, log2),
    ];

    log2('Check 1 — scanning for raw environment files (.env*)...');
    const envCheck = await checkEnvFiles(projectRoot);
    if (envCheck.ignored.length > 0) {
      log2(`ℹ ${envCheck.ignored.length} .env file(s) found but already excluded by this project's .gitignore — not blocking: ${envCheck.ignored.join(', ')}`);
    }
    if (envCheck.blocking.length > 0) {
      log2(`✗ ${envCheck.blocking.length} forbidden environment file(s) found:`);
      envCheck.blocking.forEach((f) => log2(`    ✗ ${f}`));
      throw Object.assign(
        new Error(`Raw environment files detected (${envCheck.blocking.length}). Remove them before validation.`),
        { phase: 3 }
      );
    }
    log2('✓ Check 1 passed — no raw environment files present.');
    await runProjectUnitTests(projectRoot, log2);
    status(3, 'success');

    status(4, 'running');
    const log3 = phaseLog(4);
    let issues = [...licenseIssues];
    if (!PHASE_ENABLED[4]) {
      log3('Skipped — disabled by config (phases: [{ id: 4, enabled: false }]).');
    } else {
      log3('Check 2 — scanning text files for hardcoded credentials...');
      const secrets = await checkSecrets(projectRoot, log3, { org, repo });
      log3(`Scanned ${secrets.scanned} text files.`);
      if (secrets.findings.length > 0) {
        log3(`✗ ${secrets.findings.length} potential credential leak(s):`);
        secrets.findings.forEach((f) => log3(`    ✗ ${f.file}:${f.line} — hardcoded ${f.kind}`));
      } else {
        log3('✓ Check 2 passed — no credential leakage detected.');
      }

      log3('Check 4 — AI governance audit (.py/.js/.ts LangChain/LangGraph calls)...');
      const governance = await checkAiGovernance(projectRoot, { org, repo });
      log3(`Audited ${governance.scanned} source files.`);
      if (governance.findings.length > 0) {
        log3(`✗ ${governance.findings.length} ungoverned AI invocation(s) — missing recursion_limit:`);
        governance.findings.forEach((f) => log3(`    ✗ ${f.file}:${f.line} — ${f.snippet}`));
      } else {
        log3('✓ Check 4 passed — all AI invocations are governed.');
      }

      log3(`Check 3 — local LLM code review (security, dependency, quality, encapsulation; mode: ${LLM_SCAN_MODE})...`);
      const llm = await checkLlmDeepScan(projectRoot, log3, { org, repo });
      if (!llm.available) {
        log3(`⚠ Deep-scan skipped: ${llm.reason}`);
      } else if (llm.findings.length === 0) {
        log3(`✓ Check 3 passed — LLM found no security/dependency errors or quality/encapsulation warnings in ${llm.scanned} files.`);
      } else {
        log3(`LLM reported ${llm.findings.length} finding(s):`);
        llm.findings.forEach((f) =>
          log3(`    ${f.level === 'error' ? '✗' : '⚠'} [${f.level}] [${f.category}] ${f.file}:${f.line} — ${f.issue}${f.recommendation ? ` | fix: ${f.recommendation}` : ''}`)
        );
      }

      log3('Check 5 — IaC/container misconfiguration scan (Dockerfiles/Terraform/Kubernetes/Helm)...');
      const iac = await checkIacSecurity(projectRoot, log3);
      if (iac.findings.length > 0) {
        log3(`✗ ${iac.findings.length} IaC misconfiguration(s) [engine: ${iac.engine}]:`);
        iac.findings.forEach((f) => log3(`    ✗ [${f.severity}] ${f.file}:${f.line} — ${f.message || f.kind}`));
      } else {
        log3(`✓ Check 5 passed — no IaC misconfigurations detected [engine: ${iac.engine}].`);
      }

      log3('Generating SBOM...');
      const { engine: sbomEngine, sbom } = await generateSbom(projectRoot, log3);
      log3(`✓ SBOM generated [engine: ${sbomEngine}] — ${(sbom.components || []).length} component(s).`);
      if (projectId !== null) {
        const sbomBuffer = Buffer.from(JSON.stringify(sbom, null, 2));
        store.addUploadDocument(projectId, `sbom.${sbomEngine === 'syft' ? 'cyclonedx' : 'fallback'}.json`, 'application/json', sbomBuffer.length, sbomBuffer);
      }

      log3('Check 6 — base-image signature/provenance verification (cosign)...');
      const imageProvenance = await checkImageProvenance(projectRoot, log3);
      if (imageProvenance.findings.length > 0) {
        log3(`⚠ ${imageProvenance.findings.length} base image(s) without a verifiable Sigstore signature:`);
        imageProvenance.findings.forEach((f) => log3(`    ⚠ ${f.file}:${f.line} — ${f.message}`));
      } else if (imageProvenance.engine === 'cosign') {
        log3('✓ Check 6 passed — every referenced base image has a verifiable Sigstore signature (or none was referenced).');
      } else {
        log3('✓ Check 6 skipped — cosign disabled or not installed.');
      }

      log3(`Check 7 — semantic SAST (semgrep, config: ${SEMGREP_CONFIG})...`);
      const semanticSast = await checkSemanticSast(projectRoot, log3);
      if (semanticSast.findings.length > 0) {
        log3(`✗ ${semanticSast.findings.length} semantic SAST finding(s):`);
        semanticSast.findings.forEach((f) => log3(`    ${f.severity === 'error' ? '✗' : '⚠'} [${f.severity}] ${f.file}:${f.line} — ${f.message}`));
      } else if (semanticSast.engine === 'semgrep') {
        log3('✓ Check 7 passed — no semantic SAST findings.');
      } else {
        log3('✓ Check 7 skipped — semgrep disabled or not installed.');
      }

      log3('Check 8 — PII/GDPR data-flow scan (bearer)...');
      const piiDataFlow = await checkPiiDataFlow(projectRoot, log3);
      if (piiDataFlow.findings.length > 0) {
        log3(`✗ ${piiDataFlow.findings.length} PII/data-flow finding(s):`);
        piiDataFlow.findings.forEach((f) => log3(`    ${f.severity === 'error' ? '✗' : '⚠'} [${f.severity}] ${f.file}:${f.line} — ${f.message}`));
      } else if (piiDataFlow.engine === 'bearer') {
        log3('✓ Check 8 passed — no PII/data-flow findings.');
      } else {
        log3('✓ Check 8 skipped — bearer disabled or not installed.');
      }

      log3('Check 9 — code duplication scan (jscpd)...');
      const duplication = await checkCodeDuplication(projectRoot, log3);
      if (duplication.findings.length > 0) {
        log3(`⚠ ${duplication.findings.length} duplicate block(s) found:`);
        duplication.findings.forEach((f) => log3(`    ⚠ ${f.file}:${f.line} — ${f.message}`));
      } else if (duplication.engine === 'jscpd') {
        log3('✓ Check 9 passed — no duplicate blocks above jscpd\'s default threshold.');
      } else {
        log3('✓ Check 9 skipped — jscpd disabled or not installed.');
      }

      log3('Computing LOC metrics...');
      const { engine: locEngine, metrics: locMetrics } = await generateLocMetrics(projectRoot, log3);
      if (locMetrics) {
        log3(`✓ LOC metrics computed [engine: ${locEngine}] — ${locMetrics.total?.code ?? 0} lines of code across ${locMetrics.languages?.length ?? 0} language(s).`);
        if (projectId !== null) {
          const locBuffer = Buffer.from(JSON.stringify(locMetrics, null, 2));
          store.addUploadDocument(projectId, 'loc-metrics.json', 'application/json', locBuffer.length, locBuffer);
        }
      }

      log3('Check 10 — API schema lint (spectral, OpenAPI/AsyncAPI)...');
      const apiSchema = await checkApiSchemas(projectRoot, log3);
      if (apiSchema.findings.length > 0) {
        log3(`✗ ${apiSchema.findings.length} API schema lint finding(s):`);
        apiSchema.findings.forEach((f) => log3(`    ${f.severity === 'error' ? '✗' : '⚠'} [${f.severity}] ${f.file}:${f.line} — ${f.message}`));
      } else if (apiSchema.engine === 'spectral') {
        log3('✓ Check 10 passed — no API schema lint findings (or no OpenAPI/AsyncAPI files found).');
      } else {
        log3('✓ Check 10 skipped — spectral disabled or not installed.');
      }

      log3('Check 11 — Compliance & Feature Posture Scan...');
      const { engine: postureEngine, posture } = await checkFeaturePosture(projectRoot, log3);
      for (const category of POSTURE_CATEGORIES) {
        const { status, matches } = posture[category];
        log3(`    ${status === 'DETECTED' ? '✓' : status === 'PARTIAL' ? '⚠' : '·'} ${category}: ${status}${matches.length > 0 ? ` (${matches.length} signal(s))` : ''}`);
      }
      if (projectId !== null) {
        const postureBuffer = Buffer.from(JSON.stringify({ engine: postureEngine, posture }, null, 2));
        store.addUploadDocument(projectId, 'posture-report.json', 'application/json', postureBuffer.length, postureBuffer);
      }

      issues = [...collectPhase4Issues({ secrets, governance, llm, iac, imageProvenance, semanticSast, piiDataFlow, duplication, apiSchema }), ...licenseIssues];
    }
    const errorIssues = issues.filter((i) => i.severity === 'error');
    const warningIssues = issues.filter((i) => i.severity === 'warning');

    // Preserve the pre-override behavior of warningDecision=fail: treat
    // unoverridden warnings as blocking too, in that mode only.
    const issuesRequiringOverride =
      warningDecision === 'continue' ? errorIssues : issues;

    if (issuesRequiringOverride.length > 0) {
      const { ok, unresolvedErrors, applied } = validateOverrides(issuesRequiringOverride, requestedOverrides);
      if (applied.length > 0) {
        const actor = resolveActor(req);
        if (!actor) {
          throw Object.assign(
            new Error('Overrides were submitted but no authenticated user or actor {email,name} was provided — cannot attribute the audit record.'),
            { phase: 4 }
          );
        }
        log3(`⚠ ${applied.length} flagged issue(s) overridden by ${actor.email}:`);
        applied.forEach(({ issue, justification }) => log3(`    ⚠ [override] [${issue.severity}] ${issue.file}:${issue.line} — ${issue.summary} — "${justification}"`));
        await recordOverrides({ projectId, jobId, org, repo, phase: 4, actor, applied });
      }
      if (!ok) {
        log3(`✗ ${unresolvedErrors.length} blocking finding(s) were not overridden:`);
        unresolvedErrors.forEach((issue) =>
          log3(`    ✗ [${issue.category}] ${issue.file ? issue.file + (issue.line ? ':' + issue.line : '') : 'Phase 4'} — ${issue.summary}`)
        );
        throw Object.assign(
          new Error(`Phase 4 has ${unresolvedErrors.length} unresolved blocking finding(s). Submit an override with a justification for each, or fix them.`),
          { phase: 4 }
        );
      }
    }
    status(4, 'success');

    status(5, 'running');
    const log4 = phaseLog(5);
    if (!PHASE_ENABLED[5]) {
      log4('Skipped — disabled by config (phases: [{ id: 5, enabled: false }]).');
      status(5, 'skipped');
    } else if (!runLocalCi) {
      log4('Local CI execution disabled by request (runLocalCi=false).');
      status(5, 'skipped');
    } else {
      const tooling = await actTooling();
      if (!tooling.ok) {
        log4(`⚠ Local CI skipped: ${tooling.reason}`);
        status(5, 'skipped');
      } else {
        const wfFile = await fetchGovernanceWorkflow(workflowDir, log4);
        log4(`Executing org governance workflows locally with act (event: ${ACT_EVENT}).`);
        await runActionsLocally(projectRoot, wfFile, log4);
        log4('✓ All org governance jobs passed locally.');
        status(5, 'success');
      }
    }

    rec(6).state = 'skipped';
    phaseLog(6)('Shipping phase skipped in validate-all mode.');
    status(6, 'skipped');

    if (projectId !== null) {
      store.finishProject('success', null, null, null, projectId);
    }

    return res.json({
      ok: true,
      mode: 'validate-all',
      jobId,
      projectPath,
      phases: phaseSummary(),
      events,
    });
  } catch (err) {
    const phase = err.phase || currentPhase;
    phaseLog(phase)(`✗ ${err.message}`);
    status(phase, 'failed', { error: err.message });
    if (projectId !== null) {
      try { store.finishProject('failed', err.message, null, null, projectId); } catch { /* best-effort */ }
    }
    return res.status(400).json({
      ok: false,
      mode: 'validate-all',
      jobId,
      projectPath,
      error: err.message,
      failedPhase: phase,
      phases: phaseSummary(),
      events,
    });
  } finally {
    await fsp.rm(stagingDir, { recursive: true, force: true }).catch(() => {});
    await fsp.rm(workflowDir, { recursive: true, force: true }).catch(() => {});
  }
});

/**
 * Full onboarding pipeline from a project already on the local filesystem
 * (no multipart upload) — the endpoint for agent/MCP callers that want the
 * real outcome: phases 1-5 exactly as validate-all, and, if everything
 * passes, phase 6 provisioning + push, same as the browser-driven
 * /api/pipeline. Set `dryRun: true` to get validate-all's behavior (skip
 * the push) from this same request shape.
 */
app.post('/api/pipeline/onboard', async (req, res) => {
  const body = req.body || {};
  const org = String(body.org || '').trim();
  const repo = String(body.repo || '').trim();
  // Phase 2 disabled by config (default) means GxP isn't a concept this
  // Ignite install offers at all — a caller passing gxp:true anyway is
  // ignored rather than honored, matching "hidden and therefore not checked".
  const isGxp = PHASE_ENABLED[2] && body.gxp === true;
  const runLocalCi = body.runLocalCi !== false;
  const dryRun = body.dryRun === true;
  const warningDecision = String(body.warningDecision || 'continue').toLowerCase();
  const projectPath = sanitizeAbsoluteProjectPath(body.projectPath || process.cwd());
  const gxpLinks = Array.isArray(body.gxpLinks) ? body.gxpLinks : [];
  const requestedOverrides = Array.isArray(body.overrides) ? body.overrides : [];

  // Provisioning (Phase 6) must run as the actual caller's own GitHub
  // account, not a shared host-level `gh auth login` session — fail fast
  // rather than burning phases 1-5 only to find this out at the finish line.
  const ghToken = dryRun ? null : auth.resolveGithubToken(req);
  if (!dryRun && !ghToken) {
    return res.status(401).json({
      error: req.user
        ? 'Connect your GitHub account before onboarding for real (GET /api/auth/github/connect), or pass dryRun: true.'
        : 'Log in and connect your GitHub account before onboarding for real, or pass dryRun: true.',
    });
  }

  const jobId = crypto.randomUUID();
  const stagingDir = path.join(os.tmpdir(), 'gatekeeper-staging', `${jobId}-onboard`);
  const sourceBackupDir = stagingDir + '-source-backup';
  const publishDir = stagingDir + '-publish';
  const workflowDir = stagingDir + '-workflows';
  let projectId = null;

  const events = [];
  const record = {};
  const rec = (phase) => (record[phase] ??= { state: 'pending', logs: [] });
  const persistPhase = (phase) => {
    if (projectId === null) return;
    const ph = rec(phase);
    try {
      store.upsertStep(projectId, phase, PHASE_TITLES[phase], ph.state, ph.logs.join('\n'));
    } catch {
      // Live history persistence is best-effort.
    }
  };
  const phaseLog = (phase) => (message) => {
    rec(phase).logs.push(message);
    events.push({ type: 'log', phase, message });
    persistPhase(phase);
  };

  let currentPhase = 1;
  const status = (phase, state, extra = {}) => {
    if (state === 'running') currentPhase = phase;
    rec(phase).state = state;
    events.push({ type: 'status', phase, state, ...extra });
    persistPhase(phase);
  };

  const phaseSummary = () => Object.keys(PHASE_TITLES)
    .map((id) => {
      const ph = record[id] || { state: 'pending', logs: [] };
      return {
        phase: Number(id),
        title: PHASE_TITLES[id],
        state: ph.state,
        logs: ph.logs,
      };
    });

  try {
    status(1, 'running');
    const log1 = phaseLog(1);

    if (!GITHUB_NAME_REGEX.test(org)) {
      throw Object.assign(new Error(`Invalid GitHub organization name: "${org}"`), { phase: 1 });
    }
    if (!REPO_NAME_REGEX.test(repo) || repo === '.' || repo === '..') {
      throw Object.assign(new Error(`Invalid repository name: "${repo}"`), { phase: 1 });
    }

    log1(`Onboarding job ${jobId}`);
    log1(`Source project path: ${projectPath}`);
    log1(`Target: ${org}/${repo} (private)`);
    log1(`GxP-regulated process: ${isGxp ? 'YES' : 'no'}`);
    if (dryRun) log1('Simulation mode (dryRun) — phase 6 provisioning/push will be skipped.');
    projectId = store.createProject(jobId, org, repo, isGxp, resolveRequestSource(req, 'api'));
    for (const id of Object.keys(record)) persistPhase(Number(id));
    status(1, 'success');

    if (!isGxp) {
      phaseLog(2)('Process declared non-GxP — no validation documents required.');
      status(2, 'skipped');
    } else {
      status(2, 'running');
      const logG = phaseLog(2);
      const validLinks = [];
      for (const l of gxpLinks) {
        const url = String(l?.url || '').trim();
        let parsed = null;
        try { parsed = new URL(url); } catch { /* invalid */ }
        if (!parsed || !['http:', 'https:'].includes(parsed.protocol)) {
          throw Object.assign(new Error(`Invalid GxP document link: "${url}" (must be http/https).`), { phase: 2 });
        }
        validLinks.push({ url, name: String(l?.name || '').trim() || parsed.hostname + parsed.pathname });
      }
      if (validLinks.length === 0) {
        throw Object.assign(new Error('GxP process declared but no gxpLinks provided in API payload.'), { phase: 2 });
      }
      for (const link of validLinks) {
        store.addLinkDocument(projectId, link.name, link.url);
      }
      logG(`Received ${validLinks.length} GxP document link(s) for validation context.`);
      status(2, 'success');
    }

    status(3, 'running');
    const log2 = phaseLog(3);
    await stageExistingProject(projectPath, stagingDir, log2);
    const projectRoot = await resolveProjectRoot(stagingDir);

    await cloneDirectoryWithoutSymlinks(projectRoot, sourceBackupDir);
    log2('Created immutable source snapshot for final publish phase.');

    // License compliance runs first — same ordering rationale as the
    // interactive and validate-all pipelines: the checks below throw.
    const licenseIssues = [
      ...await runLicenseComplianceCheck(projectRoot, log2),
      ...await runDependencyVulnerabilityCheck(projectRoot, log2),
    ];

    log2('Check 1 — scanning for raw environment files (.env*)...');
    const envCheck = await checkEnvFiles(projectRoot);
    if (envCheck.ignored.length > 0) {
      log2(`ℹ ${envCheck.ignored.length} .env file(s) found but already excluded by this project's .gitignore — not blocking: ${envCheck.ignored.join(', ')}`);
    }
    if (envCheck.blocking.length > 0) {
      log2(`✗ ${envCheck.blocking.length} forbidden environment file(s) found:`);
      envCheck.blocking.forEach((f) => log2(`    ✗ ${f}`));
      throw Object.assign(
        new Error(`Raw environment files detected (${envCheck.blocking.length}). Remove them before onboarding.`),
        { phase: 3 }
      );
    }
    log2('✓ Check 1 passed — no raw environment files present.');
    await runProjectUnitTests(projectRoot, log2);
    status(3, 'success');

    status(4, 'running');
    const log3 = phaseLog(4);
    let issues = [...licenseIssues];
    if (!PHASE_ENABLED[4]) {
      log3('Skipped — disabled by config (phases: [{ id: 4, enabled: false }]).');
    } else {
      log3('Check 2 — scanning text files for hardcoded credentials...');
      const secrets = await checkSecrets(projectRoot, log3, { org, repo });
      log3(`Scanned ${secrets.scanned} text files.`);
      if (secrets.findings.length > 0) {
        log3(`✗ ${secrets.findings.length} potential credential leak(s):`);
        secrets.findings.forEach((f) => log3(`    ✗ ${f.file}:${f.line} — hardcoded ${f.kind}`));
      } else {
        log3('✓ Check 2 passed — no credential leakage detected.');
      }

      log3('Check 4 — AI governance audit (.py/.js/.ts LangChain/LangGraph calls)...');
      const governance = await checkAiGovernance(projectRoot, { org, repo });
      log3(`Audited ${governance.scanned} source files.`);
      if (governance.findings.length > 0) {
        log3(`✗ ${governance.findings.length} ungoverned AI invocation(s) — missing recursion_limit:`);
        governance.findings.forEach((f) => log3(`    ✗ ${f.file}:${f.line} — ${f.snippet}`));
      } else {
        log3('✓ Check 4 passed — all AI invocations are governed.');
      }

      log3(`Check 3 — local LLM code review (security, dependency, quality, encapsulation; mode: ${LLM_SCAN_MODE})...`);
      const llm = await checkLlmDeepScan(projectRoot, log3, { org, repo });
      if (!llm.available) {
        log3(`⚠ Deep-scan skipped: ${llm.reason}`);
      } else if (llm.findings.length === 0) {
        log3(`✓ Check 3 passed — LLM found no security/dependency errors or quality/encapsulation warnings in ${llm.scanned} files.`);
      } else {
        log3(`LLM reported ${llm.findings.length} finding(s):`);
        llm.findings.forEach((f) =>
          log3(`    ${f.level === 'error' ? '✗' : '⚠'} [${f.level}] [${f.category}] ${f.file}:${f.line} — ${f.issue}${f.recommendation ? ` | fix: ${f.recommendation}` : ''}`)
        );
      }

      log3('Check 5 — IaC/container misconfiguration scan (Dockerfiles/Terraform/Kubernetes/Helm)...');
      const iac = await checkIacSecurity(projectRoot, log3);
      if (iac.findings.length > 0) {
        log3(`✗ ${iac.findings.length} IaC misconfiguration(s) [engine: ${iac.engine}]:`);
        iac.findings.forEach((f) => log3(`    ✗ [${f.severity}] ${f.file}:${f.line} — ${f.message || f.kind}`));
      } else {
        log3(`✓ Check 5 passed — no IaC misconfigurations detected [engine: ${iac.engine}].`);
      }

      log3('Generating SBOM...');
      const { engine: sbomEngine, sbom } = await generateSbom(projectRoot, log3);
      log3(`✓ SBOM generated [engine: ${sbomEngine}] — ${(sbom.components || []).length} component(s).`);
      if (projectId !== null) {
        const sbomBuffer = Buffer.from(JSON.stringify(sbom, null, 2));
        store.addUploadDocument(projectId, `sbom.${sbomEngine === 'syft' ? 'cyclonedx' : 'fallback'}.json`, 'application/json', sbomBuffer.length, sbomBuffer);
      }

      log3('Check 6 — base-image signature/provenance verification (cosign)...');
      const imageProvenance = await checkImageProvenance(projectRoot, log3);
      if (imageProvenance.findings.length > 0) {
        log3(`⚠ ${imageProvenance.findings.length} base image(s) without a verifiable Sigstore signature:`);
        imageProvenance.findings.forEach((f) => log3(`    ⚠ ${f.file}:${f.line} — ${f.message}`));
      } else if (imageProvenance.engine === 'cosign') {
        log3('✓ Check 6 passed — every referenced base image has a verifiable Sigstore signature (or none was referenced).');
      } else {
        log3('✓ Check 6 skipped — cosign disabled or not installed.');
      }

      log3(`Check 7 — semantic SAST (semgrep, config: ${SEMGREP_CONFIG})...`);
      const semanticSast = await checkSemanticSast(projectRoot, log3);
      if (semanticSast.findings.length > 0) {
        log3(`✗ ${semanticSast.findings.length} semantic SAST finding(s):`);
        semanticSast.findings.forEach((f) => log3(`    ${f.severity === 'error' ? '✗' : '⚠'} [${f.severity}] ${f.file}:${f.line} — ${f.message}`));
      } else if (semanticSast.engine === 'semgrep') {
        log3('✓ Check 7 passed — no semantic SAST findings.');
      } else {
        log3('✓ Check 7 skipped — semgrep disabled or not installed.');
      }

      log3('Check 8 — PII/GDPR data-flow scan (bearer)...');
      const piiDataFlow = await checkPiiDataFlow(projectRoot, log3);
      if (piiDataFlow.findings.length > 0) {
        log3(`✗ ${piiDataFlow.findings.length} PII/data-flow finding(s):`);
        piiDataFlow.findings.forEach((f) => log3(`    ${f.severity === 'error' ? '✗' : '⚠'} [${f.severity}] ${f.file}:${f.line} — ${f.message}`));
      } else if (piiDataFlow.engine === 'bearer') {
        log3('✓ Check 8 passed — no PII/data-flow findings.');
      } else {
        log3('✓ Check 8 skipped — bearer disabled or not installed.');
      }

      log3('Check 9 — code duplication scan (jscpd)...');
      const duplication = await checkCodeDuplication(projectRoot, log3);
      if (duplication.findings.length > 0) {
        log3(`⚠ ${duplication.findings.length} duplicate block(s) found:`);
        duplication.findings.forEach((f) => log3(`    ⚠ ${f.file}:${f.line} — ${f.message}`));
      } else if (duplication.engine === 'jscpd') {
        log3('✓ Check 9 passed — no duplicate blocks above jscpd\'s default threshold.');
      } else {
        log3('✓ Check 9 skipped — jscpd disabled or not installed.');
      }

      log3('Computing LOC metrics...');
      const { engine: locEngine, metrics: locMetrics } = await generateLocMetrics(projectRoot, log3);
      if (locMetrics) {
        log3(`✓ LOC metrics computed [engine: ${locEngine}] — ${locMetrics.total?.code ?? 0} lines of code across ${locMetrics.languages?.length ?? 0} language(s).`);
        if (projectId !== null) {
          const locBuffer = Buffer.from(JSON.stringify(locMetrics, null, 2));
          store.addUploadDocument(projectId, 'loc-metrics.json', 'application/json', locBuffer.length, locBuffer);
        }
      }

      log3('Check 10 — API schema lint (spectral, OpenAPI/AsyncAPI)...');
      const apiSchema = await checkApiSchemas(projectRoot, log3);
      if (apiSchema.findings.length > 0) {
        log3(`✗ ${apiSchema.findings.length} API schema lint finding(s):`);
        apiSchema.findings.forEach((f) => log3(`    ${f.severity === 'error' ? '✗' : '⚠'} [${f.severity}] ${f.file}:${f.line} — ${f.message}`));
      } else if (apiSchema.engine === 'spectral') {
        log3('✓ Check 10 passed — no API schema lint findings (or no OpenAPI/AsyncAPI files found).');
      } else {
        log3('✓ Check 10 skipped — spectral disabled or not installed.');
      }

      log3('Check 11 — Compliance & Feature Posture Scan...');
      const { engine: postureEngine, posture } = await checkFeaturePosture(projectRoot, log3);
      for (const category of POSTURE_CATEGORIES) {
        const { status, matches } = posture[category];
        log3(`    ${status === 'DETECTED' ? '✓' : status === 'PARTIAL' ? '⚠' : '·'} ${category}: ${status}${matches.length > 0 ? ` (${matches.length} signal(s))` : ''}`);
      }
      if (projectId !== null) {
        const postureBuffer = Buffer.from(JSON.stringify({ engine: postureEngine, posture }, null, 2));
        store.addUploadDocument(projectId, 'posture-report.json', 'application/json', postureBuffer.length, postureBuffer);
      }

      issues = [...collectPhase4Issues({ secrets, governance, llm, iac, imageProvenance, semanticSast, piiDataFlow, duplication, apiSchema }), ...licenseIssues];
    }
    // Persisted as soon as they're known — including the per-file/line
    // detail (file, line, summary, snippet) collectPhase4Issues carries —
    // so this run's "N issues" entry in the recent-projects list is
    // populated even if phase 4's override gate below throws and the run
    // never reaches provisioning. Re-persisted after overrides are applied
    // (see below) so overridden issues flip to status 'overridden' instead
    // of staying 'open'.
    let appliedOverrideIds = [];
    if (projectId !== null) {
      try { store.replaceProjectIssues(projectId, issues, appliedOverrideIds); } catch { /* best-effort */ }
    }
    const errorIssues = issues.filter((i) => i.severity === 'error');

    const issuesRequiringOverride =
      warningDecision === 'continue' ? errorIssues : issues;

    if (issuesRequiringOverride.length > 0) {
      const { ok, unresolvedErrors, applied } = validateOverrides(issuesRequiringOverride, requestedOverrides);
      if (applied.length > 0) {
        const actor = resolveActor(req);
        if (!actor) {
          throw Object.assign(
            new Error('Overrides were submitted but no authenticated user or actor {email,name} was provided — cannot attribute the audit record.'),
            { phase: 4 }
          );
        }
        log3(`⚠ ${applied.length} flagged issue(s) overridden by ${actor.email}:`);
        applied.forEach(({ issue, justification }) => log3(`    ⚠ [override] [${issue.severity}] ${issue.file}:${issue.line} — ${issue.summary} — "${justification}"`));
        await recordOverrides({ projectId, jobId, org, repo, phase: 4, actor, applied });
        appliedOverrideIds = applied.map(({ issue }) => issue.id);
        if (projectId !== null) {
          try { store.replaceProjectIssues(projectId, issues, appliedOverrideIds); } catch { /* best-effort */ }
        }
      }
      if (!ok) {
        log3(`✗ ${unresolvedErrors.length} blocking finding(s) were not overridden:`);
        unresolvedErrors.forEach((issue) =>
          log3(`    ✗ [${issue.category}] ${issue.file ? issue.file + (issue.line ? ':' + issue.line : '') : 'Phase 4'} — ${issue.summary}`)
        );
        throw Object.assign(
          new Error(`Phase 4 has ${unresolvedErrors.length} unresolved blocking finding(s). Submit an override with a justification for each, or fix them.`),
          { phase: 4 }
        );
      }
    }
    status(4, 'success');

    status(5, 'running');
    const log4 = phaseLog(5);
    if (!PHASE_ENABLED[5]) {
      log4('Skipped — disabled by config (phases: [{ id: 5, enabled: false }]).');
      log4('⚠ The org governance workflows will still gate the repo on GitHub after push.');
      status(5, 'skipped');
    } else if (!runLocalCi) {
      log4('Local CI execution disabled by request (runLocalCi=false).');
      status(5, 'skipped');
    } else {
      const tooling = await actTooling();
      if (!tooling.ok) {
        log4(`⚠ Local CI skipped: ${tooling.reason}`);
        log4('⚠ The org governance workflows will still gate the repo on GitHub after push.');
        status(5, 'success');
      } else {
        const wfFile = await fetchGovernanceWorkflow(workflowDir, log4);
        log4(`Executing org governance workflows locally with act (event: ${ACT_EVENT}).`);
        await runActionsLocally(projectRoot, wfFile, log4);
        log4('✓ All org governance jobs passed locally.');
        status(5, 'success');
      }
    }

    let repoUrl = null;
    let prUrl = null;
    if (dryRun) {
      const log5 = phaseLog(6);
      log5('Simulation mode (dryRun) — all checks passed; skipping repository provisioning and push.');
      status(6, 'skipped');
      if (projectId !== null) {
        store.finishProject('success', null, null, null, projectId);
      }
    } else {
      status(6, 'running');
      const log5 = phaseLog(6);

      const backupStat = await fsp.stat(sourceBackupDir).catch(() => null);
      if (!backupStat || !backupStat.isDirectory()) {
        throw Object.assign(new Error('Immutable source snapshot is missing before phase 6.'), { phase: 6 });
      }
      await fsp.rm(publishDir, { recursive: true, force: true }).catch(() => {});
      await cloneDirectoryWithoutSymlinks(sourceBackupDir, publishDir);
      log5('Prepared clean publish workspace from immutable source snapshot.');

      await archivePhase6Payload(publishDir, projectId, log5);

      ({ repoUrl, prUrl } = await shipToGitHub(publishDir, org, repo, log5, ghToken));
      log5(`✓ Repository live at ${repoUrl}`);
      status(6, 'success', { repoUrl, prUrl });

      if (projectId !== null) {
        store.finishProject('success', null, repoUrl, prUrl || null, projectId);
      }
    }

    return res.json({
      ok: true,
      mode: 'onboard',
      dryRun,
      jobId,
      projectPath,
      repoUrl,
      prUrl,
      phases: phaseSummary(),
      events,
    });
  } catch (err) {
    const phase = err.phase || currentPhase;
    phaseLog(phase)(`✗ ${err.message}`);
    status(phase, 'failed', { error: err.message });
    if (projectId !== null) {
      try { store.finishProject('failed', err.message, null, null, projectId); } catch { /* best-effort */ }
    }
    return res.status(400).json({
      ok: false,
      mode: 'onboard',
      dryRun,
      jobId,
      projectPath,
      error: err.message,
      failedPhase: phase,
      phases: phaseSummary(),
      events,
    });
  } finally {
    await fsp.rm(stagingDir, { recursive: true, force: true }).catch(() => {});
    await fsp.rm(sourceBackupDir, { recursive: true, force: true }).catch(() => {});
    await fsp.rm(publishDir, { recursive: true, force: true }).catch(() => {});
    await fsp.rm(workflowDir, { recursive: true, force: true }).catch(() => {});
  }
});

app.delete('/api/projects/:id', (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid project id.' });
  if (!store.projectExists(id)) return res.status(404).json({ error: 'Project not found.' });
  store.deleteProjectById(id);
  res.json({ ok: true });
});

app.delete('/api/projects', (req, res) => {
  store.deleteAllProjects();
  res.json({ ok: true });
});

app.get('/api/documents/:id', (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid document id.' });
  const doc = store.getDocument(id);
  if (!doc) return res.status(404).json({ error: 'Document not found.' });
  if (doc.kind === 'link') return res.redirect(doc.url);
  res.setHeader('Content-Type', doc.mime || 'application/octet-stream');
  res.setHeader(
    'Content-Disposition',
    `attachment; filename*=UTF-8''${encodeURIComponent(doc.name)}`
  );
  res.send(Buffer.from(doc.data));
});

app.post(
  '/api/pipeline',
  upload.fields([
    { name: 'archive', maxCount: 1 },
    { name: 'files', maxCount: 5000 },
    { name: 'gxpDocs', maxCount: 50 },
  ]),
  async (req, res) => {
  res.setHeader('Content-Type', 'application/x-ndjson');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('X-Accel-Buffering', 'no');

  let projectId = null;
  const send = (event) => res.write(JSON.stringify(event) + '\n');
  // Server-side record of every phase's state and logs, for failure emails.
  const record = {};
  const rec = (phase) => (record[phase] ??= { state: 'pending', logs: [] });
  const persistPhase = (phase) => {
    if (projectId === null) return;
    const ph = rec(phase);
    try {
      store.upsertStep(projectId, phase, PHASE_TITLES[phase], ph.state, ph.logs.join('\n'));
    } catch {
      // Live history persistence is best-effort.
    }
  };
  const phaseLog = (phase) => (message) => {
    rec(phase).logs.push(message);
    send({ type: 'log', phase, message });
    persistPhase(phase);
  };
  let currentPhase = 1;
  const status = (phase, state, extra = {}) => {
    if (state === 'running') currentPhase = phase;
    rec(phase).state = state;
    send({ type: 'status', phase, state, ...extra });
    persistPhase(phase);
  };

  const jobId = crypto.randomUUID();
  send({ type: 'job', jobId });
  const stagingDir = path.join(os.tmpdir(), 'gatekeeper-staging', jobId);
  const sourceBackupDir = stagingDir + '-source-backup';
  const publishDir = stagingDir + '-publish';
  // Governance workflow cache lives OUTSIDE the project tree so it is never
  // committed or pushed with the user's code.
  const workflowDir = stagingDir + '-workflows';

  const zipFile = req.files?.archive?.[0] || null;
  const dirFiles = req.files?.files || [];
  const gxpDocFiles = req.files?.gxpDocs || [];
  let relPaths = [];
  try {
    relPaths = JSON.parse(req.body.paths || '[]');
  } catch { /* validated below */ }

  const org = (req.body.org || '').trim();
  const repo = (req.body.repo || '').trim();
  // See the other two pipeline entry points: phase 2 disabled by config
  // (default) means gxp is ignored even if the client sends it.
  const isGxp = PHASE_ENABLED[2] && req.body.gxp === 'true';
  const dryRun = req.body.dryRun === 'true';
  let gxpLinks = [];
  try {
    const parsed = JSON.parse(req.body.gxpLinks || '[]');
    if (Array.isArray(parsed)) gxpLinks = parsed;
  } catch { /* validated in phase 2 */ }

  // Issues/failures accumulate here from every phase instead of aborting the
  // stream immediately. They are only surfaced — and gated — together, right
  // before phase 6 (provisioning/push), so a single run always shows the full
  // picture instead of stopping at the first thing that went wrong.
  const allIssues = [];
  let phase1Ok = false;
  let phase3Ok = false;
  let projectRootReady = false;
  let ghToken = null;
  let projectRoot = null;
  let keepSourceBackupDir = false;
  // Set once the immutable snapshot exists (i.e. structure audit passed) and
  // cleared once the code actually ships for real. Anything that ends the
  // run in between — a dry run, the user stopping at the review gate,
  // unresolved findings, even a governance-CI failure (this app already lets
  // the human override that at the final gate) — leaves a resumable
  // snapshot behind so "Effectivate" can finish the job later instead of
  // forcing a full re-upload + re-scan.
  let snapshotReady = false;
  let shippedForReal = false;

  // projectRoot/sourceBackupDir/reviewActive are filled in once known (see
  // below) — Ignite Studio's routes (registered outside this closure) read
  // them off runningRuns.get(jobId) to browse/edit the live staging tree
  // while, and only while, this run is paused at the review gate.
  const runState = { org, repo, projectId: null, allIssues, projectRoot: null, sourceBackupDir: null, reviewActive: false };
  runningRuns.set(jobId, runState);
  const persistIssuesSnapshot = (overriddenIds) => {
    if (runState.projectId === null) return;
    try { store.replaceProjectIssues(runState.projectId, allIssues, overriddenIds); } catch { /* best-effort */ }
  };
  runState.persistIssuesSnapshot = persistIssuesSnapshot;

  try {
    /* ---------------- Phase 1: input validation ---------------- */
    status(1, 'running');
    const log1 = phaseLog(1);
    try {
      if (!zipFile && dirFiles.length === 0) {
        throw new Error('No ZIP archive or folder upload received.');
      }
      if (dirFiles.length > 0 && !Array.isArray(relPaths)) {
        throw new Error('Folder upload metadata is invalid: paths must be an array.');
      }
      if (!GITHUB_NAME_REGEX.test(org)) {
        throw new Error(`Invalid GitHub organization name: "${org}"`);
      }
      if (!REPO_NAME_REGEX.test(repo) || repo === '.' || repo === '..') {
        throw new Error(`Invalid repository name: "${repo}"`);
      }
      // Provisioning (Phase 6) must run as the actual caller's own GitHub
      // account, not a shared host-level `gh auth login` session — fail
      // fast rather than burning phases 1-5 only to find this out at the
      // finish line. Dry runs never reach Phase 6, so they're exempt.
      if (!dryRun) {
        ghToken = auth.resolveGithubToken(req);
        if (!ghToken) {
          throw new Error(
            req.user
              ? 'Connect your GitHub account before running for real (GET /api/auth/github/connect), or check "Simulation mode".'
              : 'Log in and connect your GitHub account before running for real, or check "Simulation mode".'
          );
        }
      }

      log1(`Job ${jobId}`);
      if (zipFile) {
        log1(`Archive: ${zipFile.originalname} (${(zipFile.size / 1024).toFixed(1)} KB)`);
      } else {
        const totalMb = dirFiles.reduce((sum, f) => sum + f.size, 0) / 1048576;
        log1(`Folder upload: ${dirFiles.length} files (${totalMb.toFixed(1)} MB)`);
      }
      log1(`Target: ${org}/${repo} (private)`);
      log1(`GxP-regulated process: ${isGxp ? 'YES — validation documents are mandatory' : 'no'}`);
      if (dryRun) log1('Simulation mode (dryRun) — phase 6 provisioning/push will be skipped.');
      projectId = store.createProject(jobId, org, repo, isGxp, resolveRequestSource(req, 'ui'));
      runState.projectId = projectId;
      for (const id of Object.keys(record)) persistPhase(Number(id));
      status(1, 'success');
      phase1Ok = true;
    } catch (err) {
      log1(`✗ ${err.message}`);
      status(1, 'failed', { error: err.message });
      allIssues.push({
        id: 'phase1::input-validation', phase: 1, category: 'input-validation',
        severity: 'error', score: scoreForIssue({ category: 'input-validation', severity: 'error' }), summary: err.message, file: null, line: null,
      });
      persistIssuesSnapshot();
    }

    /* ---------------- Phase 2: GxP validation documents ---------------- */
    if (!phase1Ok) {
      phaseLog(2)('Skipped — blocked by Phase 1 failure (no project record to attach documents to).');
      status(2, 'skipped');
    } else if (!isGxp) {
      phaseLog(2)('Process declared non-GxP — no validation documents required.');
      status(2, 'skipped');
    } else {
      status(2, 'running');
      const logG = phaseLog(2);
      try {
        const validLinks = [];
        for (const l of gxpLinks) {
          const url = String(l?.url || '').trim();
          let parsed = null;
          try { parsed = new URL(url); } catch { /* invalid */ }
          if (!parsed || !['http:', 'https:'].includes(parsed.protocol)) {
            throw new Error(`Invalid GxP document link: "${url}" (must be http/https).`);
          }
          validLinks.push({ url, name: String(l?.name || '').trim() || parsed.hostname + parsed.pathname });
        }

        if (gxpDocFiles.length === 0 && validLinks.length === 0) {
          throw new Error('GxP process declared but no validation documents provided. Attach at least one document (upload or link).');
        }

        logG(`Collecting ${gxpDocFiles.length} uploaded document(s) and ${validLinks.length} link(s)...`);
        for (const doc of gxpDocFiles) {
          const data = await fsp.readFile(doc.path);
          store.addUploadDocument(projectId, doc.originalname, doc.mimetype || null, doc.size, data);
          logG(`✓ Archived upload: ${doc.originalname} (${(doc.size / 1024).toFixed(1)} KB)`);
        }
        for (const link of validLinks) {
          store.addLinkDocument(projectId, link.name, link.url);
          logG(`✓ Archived link: ${link.name} → ${link.url}`);
        }
        logG(`✓ ${gxpDocFiles.length + validLinks.length} GxP validation document(s) saved to the database.`);
        status(2, 'success');
      } catch (err) {
        logG(`✗ ${err.message}`);
        status(2, 'failed', { error: err.message });
        allIssues.push({
          id: 'phase2::gxp-documents', phase: 2, category: 'gxp-documents',
          severity: 'error', score: scoreForIssue({ category: 'gxp-documents', severity: 'error' }), summary: err.message, file: null, line: null,
        });
        persistIssuesSnapshot();
      }
    }

    /* ---------------- Phase 3: extraction + structure audit ---------------- */
    status(3, 'running');
    const log2 = phaseLog(3);
    try {
      await fsp.mkdir(stagingDir, { recursive: true });
      log2(`Staging directory: ${stagingDir}`);

      let staged;
      if (zipFile) {
        staged = await extractZip(zipFile.path, stagingDir, log2);
        log2(`Extracted ${staged.fileCount} files (${(staged.totalBytes / 1024).toFixed(1)} KB).`);
      } else {
        staged = await stageDirectoryUpload(dirFiles, relPaths, stagingDir, log2);
        log2(`Staged ${staged.fileCount} files (${(staged.totalBytes / 1024).toFixed(1)} KB) from folder upload.`);
      }

      projectRoot = await resolveProjectRoot(stagingDir);
      if (projectRoot !== stagingDir) {
        log2(`Detected single top-level folder — project root: ${path.basename(projectRoot)}/`);
      }

      await cloneDirectoryWithoutSymlinks(projectRoot, sourceBackupDir);
      log2('Created immutable source snapshot for final publish phase.');
      snapshotReady = true;
      projectRootReady = true;
      runState.projectRoot = projectRoot;
      runState.sourceBackupDir = sourceBackupDir;

      // License compliance runs FIRST inside phase 3 — the env-file check and
      // unit-test run below both throw on failure, and this fixture-style
      // project can fail either while still having license findings the
      // review gate must show. Findings are non-throwing issues, so
      // collecting them before the hard checks loses nothing. Dependency
      // vulnerability findings ride along right after, same reasoning.
      const licenseIssues = [
        ...await runLicenseComplianceCheck(projectRoot, log2),
        ...await runDependencyVulnerabilityCheck(projectRoot, log2),
      ];
      if (licenseIssues.length > 0) {
        allIssues.push(...licenseIssues);
        persistIssuesSnapshot();
      }

      log2('Check 1 — scanning for raw environment files (.env*)...');
      const envCheck = await checkEnvFiles(projectRoot);
      if (envCheck.ignored.length > 0) {
        log2(`ℹ ${envCheck.ignored.length} .env file(s) found but already excluded by this project's .gitignore — not blocking: ${envCheck.ignored.join(', ')}`);
      }
      if (envCheck.blocking.length > 0) {
        log2(`✗ ${envCheck.blocking.length} forbidden environment file(s) found:`);
        envCheck.blocking.forEach((f) => log2(`    ✗ ${f}`));
        throw new Error(`Raw environment files detected (${envCheck.blocking.length}). Remove them and re-upload.`);
      }
      log2('✓ Check 1 passed — no raw environment files present.');
      await runProjectUnitTests(projectRoot, log2);
      status(3, 'success');
      phase3Ok = true;
    } catch (err) {
      log2(`✗ ${err.message}`);
      status(3, 'failed', { error: err.message });
      allIssues.push({
        id: 'phase3::structure-audit', phase: 3, category: 'structure-audit',
        severity: 'error', score: scoreForIssue({ category: 'structure-audit', severity: 'error' }), summary: err.message, file: null, line: null,
      });
      persistIssuesSnapshot();
    }

    /* ---------------- Phase 4: security + AI compliance ---------------- */
    // Gated on the project actually being staged on disk (projectRootReady),
    // not on Phase 3 passing outright — a blocking .env file or failing unit
    // test still leaves a scannable checkout, and this run's whole point is
    // to surface every issue across every phase together, not stop at the
    // first one (see the allIssues comment above).
    if (!projectRootReady) {
      phaseLog(4)('Skipped — blocked by Phase 3 failure (no staged project root to scan).');
      status(4, 'skipped');
    } else if (!PHASE_ENABLED[4]) {
      phaseLog(4)('Skipped — disabled by config (phases: [{ id: 4, enabled: false }]).');
      status(4, 'skipped');
    } else {
      status(4, 'running');
      const log3 = phaseLog(4);
      try {
        log3('Check 2 — scanning text files for hardcoded credentials...');
        const secrets = await checkSecrets(projectRoot, log3, { org, repo });
        log3(`Scanned ${secrets.scanned} text files.`);
        if (secrets.findings.length > 0) {
          log3(`✗ ${secrets.findings.length} potential credential leak(s):`);
          secrets.findings.forEach((f) => log3(`    ✗ ${f.file}:${f.line} — hardcoded ${f.kind}`));
        } else {
          log3('✓ Check 2 passed — no credential leakage detected.');
        }

        log3('Check 4 — AI governance audit (.py/.js/.ts LangChain/LangGraph calls)...');
        const governance = await checkAiGovernance(projectRoot, { org, repo });
        log3(`Audited ${governance.scanned} source files.`);
        if (governance.findings.length > 0) {
          log3(`✗ ${governance.findings.length} ungoverned AI invocation(s) — missing recursion_limit:`);
          governance.findings.forEach((f) => log3(`    ✗ ${f.file}:${f.line} — ${f.snippet}`));
        } else {
          log3('✓ Check 4 passed — all AI invocations are governed.');
        }

        log3(`Check 3 — local LLM code review (security, dependency, quality, encapsulation; mode: ${LLM_SCAN_MODE})...`);
        const llm = await checkLlmDeepScan(projectRoot, log3, { org, repo });
        if (!llm.available) {
          log3(`⚠ Deep-scan skipped: ${llm.reason}`);
        } else if (llm.findings.length === 0) {
          log3(`✓ Check 3 passed — LLM found no security/dependency errors or quality/encapsulation warnings in ${llm.scanned} files.`);
        } else {
          log3(`LLM reported ${llm.findings.length} finding(s):`);
          llm.findings.forEach((f) =>
            log3(`    ${f.level === 'error' ? '✗' : '⚠'} [${f.level}] [${f.category}] ${f.file}:${f.line} — ${f.issue}${f.recommendation ? ` | fix: ${f.recommendation}` : ''}`)
          );
        }

        log3('Check 5 — IaC/container misconfiguration scan (Dockerfiles/Terraform/Kubernetes/Helm)...');
        const iac = await checkIacSecurity(projectRoot, log3);
        if (iac.findings.length > 0) {
          log3(`✗ ${iac.findings.length} IaC misconfiguration(s) [engine: ${iac.engine}]:`);
          iac.findings.forEach((f) => log3(`    ✗ [${f.severity}] ${f.file}:${f.line} — ${f.message || f.kind}`));
        } else {
          log3(`✓ Check 5 passed — no IaC misconfigurations detected [engine: ${iac.engine}].`);
        }

        log3('Generating SBOM...');
        const { engine: sbomEngine, sbom } = await generateSbom(projectRoot, log3);
        log3(`✓ SBOM generated [engine: ${sbomEngine}] — ${(sbom.components || []).length} component(s).`);
        if (projectId !== null) {
          const sbomBuffer = Buffer.from(JSON.stringify(sbom, null, 2));
          store.addUploadDocument(projectId, `sbom.${sbomEngine === 'syft' ? 'cyclonedx' : 'fallback'}.json`, 'application/json', sbomBuffer.length, sbomBuffer);
        }

        log3('Check 6 — base-image signature/provenance verification (cosign)...');
        const imageProvenance = await checkImageProvenance(projectRoot, log3);
        if (imageProvenance.findings.length > 0) {
          log3(`⚠ ${imageProvenance.findings.length} base image(s) without a verifiable Sigstore signature:`);
          imageProvenance.findings.forEach((f) => log3(`    ⚠ ${f.file}:${f.line} — ${f.message}`));
        } else if (imageProvenance.engine === 'cosign') {
          log3('✓ Check 6 passed — every referenced base image has a verifiable Sigstore signature (or none was referenced).');
        } else {
          log3('✓ Check 6 skipped — cosign disabled or not installed.');
        }

        log3(`Check 7 — semantic SAST (semgrep, config: ${SEMGREP_CONFIG})...`);
        const semanticSast = await checkSemanticSast(projectRoot, log3);
        if (semanticSast.findings.length > 0) {
          log3(`✗ ${semanticSast.findings.length} semantic SAST finding(s):`);
          semanticSast.findings.forEach((f) => log3(`    ${f.severity === 'error' ? '✗' : '⚠'} [${f.severity}] ${f.file}:${f.line} — ${f.message}`));
        } else if (semanticSast.engine === 'semgrep') {
          log3('✓ Check 7 passed — no semantic SAST findings.');
        } else {
          log3('✓ Check 7 skipped — semgrep disabled or not installed.');
        }

        log3('Check 8 — PII/GDPR data-flow scan (bearer)...');
        const piiDataFlow = await checkPiiDataFlow(projectRoot, log3);
        if (piiDataFlow.findings.length > 0) {
          log3(`✗ ${piiDataFlow.findings.length} PII/data-flow finding(s):`);
          piiDataFlow.findings.forEach((f) => log3(`    ${f.severity === 'error' ? '✗' : '⚠'} [${f.severity}] ${f.file}:${f.line} — ${f.message}`));
        } else if (piiDataFlow.engine === 'bearer') {
          log3('✓ Check 8 passed — no PII/data-flow findings.');
        } else {
          log3('✓ Check 8 skipped — bearer disabled or not installed.');
        }

        log3('Check 9 — code duplication scan (jscpd)...');
        const duplication = await checkCodeDuplication(projectRoot, log3);
        if (duplication.findings.length > 0) {
          log3(`⚠ ${duplication.findings.length} duplicate block(s) found:`);
          duplication.findings.forEach((f) => log3(`    ⚠ ${f.file}:${f.line} — ${f.message}`));
        } else if (duplication.engine === 'jscpd') {
          log3('✓ Check 9 passed — no duplicate blocks above jscpd\'s default threshold.');
        } else {
          log3('✓ Check 9 skipped — jscpd disabled or not installed.');
        }

        log3('Computing LOC metrics...');
        const { engine: locEngine, metrics: locMetrics } = await generateLocMetrics(projectRoot, log3);
        if (locMetrics) {
          log3(`✓ LOC metrics computed [engine: ${locEngine}] — ${locMetrics.total?.code ?? 0} lines of code across ${locMetrics.languages?.length ?? 0} language(s).`);
          if (projectId !== null) {
            const locBuffer = Buffer.from(JSON.stringify(locMetrics, null, 2));
            store.addUploadDocument(projectId, 'loc-metrics.json', 'application/json', locBuffer.length, locBuffer);
          }
        }

        log3('Check 10 — API schema lint (spectral, OpenAPI/AsyncAPI)...');
        const apiSchema = await checkApiSchemas(projectRoot, log3);
        if (apiSchema.findings.length > 0) {
          log3(`✗ ${apiSchema.findings.length} API schema lint finding(s):`);
          apiSchema.findings.forEach((f) => log3(`    ${f.severity === 'error' ? '✗' : '⚠'} [${f.severity}] ${f.file}:${f.line} — ${f.message}`));
        } else if (apiSchema.engine === 'spectral') {
          log3('✓ Check 10 passed — no API schema lint findings (or no OpenAPI/AsyncAPI files found).');
        } else {
          log3('✓ Check 10 skipped — spectral disabled or not installed.');
        }

        log3('Check 11 — Compliance & Feature Posture Scan...');
        const { engine: postureEngine, posture } = await checkFeaturePosture(projectRoot, log3);
        for (const category of POSTURE_CATEGORIES) {
          const { status, matches } = posture[category];
          log3(`    ${status === 'DETECTED' ? '✓' : status === 'PARTIAL' ? '⚠' : '·'} ${category}: ${status}${matches.length > 0 ? ` (${matches.length} signal(s))` : ''}`);
        }
        if (projectId !== null) {
          const postureBuffer = Buffer.from(JSON.stringify({ engine: postureEngine, posture }, null, 2));
          store.addUploadDocument(projectId, 'posture-report.json', 'application/json', postureBuffer.length, postureBuffer);
        }

        const issues = collectPhase4Issues({ secrets, governance, llm, iac, imageProvenance, semanticSast, piiDataFlow, duplication, apiSchema });
        for (const issue of issues) allIssues.push({ ...issue, phase: 4 });
        const blockingCount = issues.filter((i) => i.severity === 'error').length;
        if (issues.length > 0) {
          log3(`⚠ ${issues.length} flagged issue(s) (${blockingCount} blocking) — will be presented for final review before push.`);
        }
        persistIssuesSnapshot();
        // The scan itself completed cleanly either way — findings (if any)
        // are deferred to the final review gate, not a phase 4 failure — but
        // the client still needs the count to avoid showing a bare "Success"
        // next to a log full of ✗ [error] lines.
        status(4, 'success', { issueCount: issues.length, blockingCount });
      } catch (err) {
        log3(`✗ ${err.message}`);
        status(4, 'failed', { error: err.message });
        allIssues.push({
          id: 'phase4::security-scan', phase: 4, category: 'security-scan',
          severity: 'error', score: scoreForIssue({ category: 'security-scan', severity: 'error' }), summary: err.message, file: null, line: null,
        });
        persistIssuesSnapshot();
      }
    }

    /* ---------------- Phase 5: local GitHub Actions run (act) ---------------- */
    if (!projectRootReady) {
      phaseLog(5)('Skipped — blocked by Phase 3 failure (no staged project root to run CI against).');
      status(5, 'skipped');
    } else if (!PHASE_ENABLED[5]) {
      phaseLog(5)('Skipped — disabled by config (phases: [{ id: 5, enabled: false }]).');
      phaseLog(5)('⚠ The org governance workflows will still gate the repo on GitHub after push.');
      status(5, 'skipped');
    } else {
      status(5, 'running');
      const log4 = phaseLog(5);
      try {
        const tooling = await actTooling();
        if (!tooling.ok) {
          log4(`⚠ Local CI skipped: ${tooling.reason}`);
          log4('⚠ The org governance workflows will still gate the repo on GitHub after push.');
          status(5, 'success');
        } else {
          const wfFile = await fetchGovernanceWorkflow(workflowDir, log4);
          log4(`Executing org governance workflows locally with act (event: ${ACT_EVENT}).`);
          await runActionsLocally(projectRoot, wfFile, log4);
          log4('✓ All org governance jobs passed locally.');
          status(5, 'success');
        }
      } catch (err) {
        log4(`✗ ${err.message}`);
        status(5, 'failed', { error: err.message });
        // `act` (and git/gh/docker) failing only ever surfaces a generic
        // "exited with code N" — worthless as a single finding. When the
        // output actually contained recognizable failure lines (❌, "Error:",
        // "Failure -", ...), report each one as its own issue instead of
        // collapsing them into that one meaningless blob.
        if (Array.isArray(err.failureLines) && err.failureLines.length > 0) {
          const located = [];
          for (let i = 0; i < err.failureLines.length; i++) {
            const failureLine = err.failureLines[i];
            const loc = projectRootReady
              ? await resolveGovernanceCiLocation(projectRoot, failureLine)
              : { file: null, line: null, code: null };
            located.push({ i, summary: failureLine, file: loc.file, line: loc.line, code: loc.code });
          }
          // A flagged issue is only addressable (View code / Studio highlighting,
          // override targeting) if it has a real file AND line — an unresolved
          // location is worthless as an issue card, so those lines are dropped
          // here rather than shown with "unknown" location. The raw failure text
          // is still visible in the phase log above regardless.
          for (const l of filterGovernanceCiFailureLines(located)) {
            if (!l.file || l.line == null) continue;
            allIssues.push({
              id: `phase5::governance-ci::${l.i}`, phase: 5, category: 'governance-ci',
              severity: 'error', score: scoreForIssue({ category: 'governance-ci', severity: 'error' }), summary: l.summary,
              file: l.file, line: l.line, snippet: l.code,
            });
          }
        }
        persistIssuesSnapshot();
      }
    }

    /* ---------------- Final review gate — every issue from every phase, ----
       ---------------- shown together right before provisioning/push. ----- */
    let repoUrl = null;
    let prUrl = null;
    status(6, 'running');
    const log6 = phaseLog(6);

    if (allIssues.length > 0) {
      const errorCount = allIssues.filter((i) => i.severity === 'error').length;
      log6(`⚠ ${allIssues.length} issue(s) accumulated across the run (${errorCount} blocking) — waiting for final review before provisioning/push.`);
      const decisionPromise = reviewDecisions.wait(jobId);
      // Only open for editing while actually paused here — Ignite Studio's
      // file/rescan routes check this and 409 outside this window, so a run
      // still mid-scan (or one that already resolved/timed out) never
      // exposes the staging tree.
      runState.reviewActive = true;
      send({ type: 'review_required', phase: 6, jobId, issues: allIssues });
      const decision = await decisionPromise;
      runState.reviewActive = false;

      const { ok, unresolvedErrors, applied } = validateOverrides(allIssues, decision.overrides || []);
      persistIssuesSnapshot(applied.map(({ issue }) => issue.id));
      if (applied.length > 0) {
        const byPhase = new Map();
        for (const item of applied) {
          const p = item.issue.phase;
          if (!byPhase.has(p)) byPhase.set(p, []);
          byPhase.get(p).push(item);
        }
        for (const [p, group] of byPhase) {
          log6(`⚠ ${group.length} flagged issue(s) from Phase ${p} overridden by ${decision.actor.email}:`);
          group.forEach(({ issue, justification }) =>
            log6(`    ⚠ [override] [${issue.severity}] ${issue.file ? issue.file + (issue.line ? ':' + issue.line : '') : `Phase ${issue.phase}`} — ${issue.summary} — "${justification}"`)
          );
          await recordOverrides({ projectId, jobId, org, repo, phase: p, actor: decision.actor, applied: group });
        }
      }

      if (!decision.proceed) {
        throw Object.assign(
          new Error('Pipeline interrupted by user after reviewing all flagged issues.'),
          { phase: 6 }
        );
      }
      if (!ok) {
        log6(`✗ ${unresolvedErrors.length} blocking finding(s) were not overridden:`);
        unresolvedErrors.forEach((issue) =>
          log6(`    ✗ [Phase ${issue.phase}] [${issue.category}] ${issue.file ? issue.file + (issue.line ? ':' + issue.line : '') : 'unknown location'} — ${issue.summary}`)
        );
        throw Object.assign(
          new Error(`${unresolvedErrors.length} unresolved blocking finding(s) remain across the run. Override each with a justification, or fix them and re-run.`),
          { phase: 6, unresolvedErrors }
        );
      }
      log6('✓ User chose to continue after reviewing all flagged issues.');
    }

    /* ---------------- Phase 6: provisioning + shipping ---------------- */
    if (dryRun) {
      log6(allIssues.length > 0
        ? 'Simulation mode (dryRun) — all flagged issues were fixed or overridden; skipping repository provisioning and push.'
        : 'Simulation mode (dryRun) — all checks passed; skipping repository provisioning and push.');
      log6('The validated snapshot is kept so this run can be effectivated (provisioned + pushed for real) later, still gated on any unresolved blocking findings.');
      status(6, 'skipped');
      if (projectId !== null) {
        store.finishProject('success', null, null, null, projectId);
      }
    } else {
      const backupStat = await fsp.stat(sourceBackupDir).catch(() => null);
      if (!backupStat || !backupStat.isDirectory()) {
        throw Object.assign(new Error('Immutable source snapshot is missing before phase 6 — an earlier phase failed to produce a publishable project.'), { phase: 6 });
      }
      await fsp.rm(publishDir, { recursive: true, force: true }).catch(() => {});
      await cloneDirectoryWithoutSymlinks(sourceBackupDir, publishDir);
      log6('Prepared clean publish workspace from immutable source snapshot.');

      await archivePhase6Payload(publishDir, projectId, log6);

      ({ repoUrl, prUrl } = await shipToGitHub(publishDir, org, repo, log6, ghToken));
      log6(`✓ Repository live at ${repoUrl}`);
      status(6, 'success', { repoUrl, prUrl });
      shippedForReal = true;

      if (projectId !== null) {
        store.finishProject('success', null, repoUrl, prUrl || null, projectId);
      }
    }
    send({ type: 'done', ok: true, dryRun, repoUrl, prUrl, effectivatable: snapshotReady && !shippedForReal, projectId });
  } catch (err) {
    const phase = err.phase || currentPhase;
    phaseLog(phase)(`✗ ${err.message}`);
    status(phase, 'failed', { error: err.message });

    // AI insight: pass the failed step's full log to the local LLM for a
    // user-friendly explanation. Soft-fails if the LLM is unavailable.
    let insight = null;
    send({ type: 'insight', phase, state: 'generating' });
    try {
      insight = await generateFailureInsight(phase, err.message, record, err.unresolvedErrors);
    } catch { /* insight is best-effort */ }
    send(insight
      ? { type: 'insight', phase, state: 'ready', text: insight }
      : { type: 'insight', phase, state: 'unavailable' });

    try {
      const mail = await sendFailureNotification({
        jobId, org, repo, error: err.message, failedPhase: phase, record, insight,
      });
      if (mail.sent) {
        phaseLog(phase)(`📧 Failure report emailed to ${mail.to}.`);
      }
    } catch (mailErr) {
      phaseLog(phase)(`⚠ Could not send failure email: ${mailErr.message}`);
    }

    if (projectId !== null) {
      try { store.finishProject('failed', err.message, null, null, projectId); } catch { /* best-effort */ }
    }
    send({ type: 'done', ok: false, error: err.message, phase, effectivatable: snapshotReady && !shippedForReal, projectId });
  } finally {
    runningRuns.delete(jobId);
    if (snapshotReady && !shippedForReal && projectId !== null) {
      cleanupExpiredEffectivations();
      pendingEffectivations.set(projectId, { org, repo, sourceBackupDir, createdAt: Date.now() });
      keepSourceBackupDir = true;
    }
    // Persist every phase's state and logs for the onboarding history panel.
    if (projectId !== null) {
      try {
        for (const id of Object.keys(PHASE_TITLES)) {
          const ph = record[id] || { state: 'pending', logs: [] };
          store.upsertStep(projectId, Number(id), PHASE_TITLES[id], ph.state, ph.logs.join('\n'));
        }
      } catch (e) {
        console.error(`Could not persist step history for job ${jobId}: ${e.message}`);
      }
    }
    // Forceful cleanup regardless of outcome: staging dir, the uploaded ZIP,
    // and any multer temp files not yet moved into staging. The one exception
    // is the source snapshot of a run that didn't ship for real (dry run,
    // stopped at review, unresolved findings, CI failure) — kept for a later
    // "Effectivate" call — see pendingEffectivations.
    await fsp.rm(stagingDir, { recursive: true, force: true }).catch(() => {});
    if (!keepSourceBackupDir) {
      await fsp.rm(sourceBackupDir, { recursive: true, force: true }).catch(() => {});
    }
    await fsp.rm(publishDir, { recursive: true, force: true }).catch(() => {});
    await fsp.rm(workflowDir, { recursive: true, force: true }).catch(() => {});
    if (zipFile) await fsp.rm(zipFile.path, { force: true }).catch(() => {});
    for (const f of dirFiles) await fsp.rm(f.path, { force: true }).catch(() => {});
    for (const f of gxpDocFiles) await fsp.rm(f.path, { force: true }).catch(() => {});
    res.end();
  }
});

/* Multer / general error handler (e.g. file too large) */
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  res.status(400).json({ error: err.message });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Ignite (onboarding gatekeeper) running at http://localhost:${PORT}`);
  });

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
  scanDependencyVulnerabilities,
  classifyVulnerabilitySeverity,
  checkIacSecurity,
  runCheckovIacScan,
  runHadolintIacScan,
  generateSbom,
  checkImageProvenance,
  checkSemanticSast,
  checkPiiDataFlow,
  checkCodeDuplication,
  generateLocMetrics,
  checkApiSchemas,
  checkFeaturePosture,
};
