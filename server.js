/**
 * Ignite (onboarding gatekeeper) — backend server
 *
 * Pipeline: ZIP upload -> extraction to isolated staging dir -> structure audit
 * (.env* denial) -> secret regex scan -> AI governance audit -> git/gh shipping.
 * Progress is streamed to the client as NDJSON events over a single POST
 * response. Staging directories are force-removed in a `finally` block no
 * matter how the pipeline ends.
 */

require('dotenv').config();

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
const { collectPhase4Issues, validateOverrides, scoreForIssue } = require('./override-engine');

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
    },
  };
  let fileConfig = {};
  try {
    fileConfig = JSON.parse(fs.readFileSync(path.join(__dirname, 'config.json'), 'utf8'));
  } catch (err) {
    if (err.code !== 'ENOENT') {
      console.error(`config.json is invalid (${err.message}) — using defaults.`);
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
const ALLOWED_COMMANDS = Object.freeze(new Set(['git', 'gh', 'act', 'docker', 'gitleaks']));

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

function runTool(tool, args, cwd, { env: envOverride = {} } = {}) {
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
        if (err) {
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
      const target = path.resolve(destDir, entryPath);
      if (target !== destDir && !target.startsWith(destDir + path.sep)) {
        throw new Error(`Blocked path-traversal entry in archive: ${entryPath}`);
      }

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
2) Potentially dangerous dependencies (known risky/malicious/deprecated-vulnerable usage from dependency manifests/lockfiles).

Coverage rules:
- Do not stop at the first issue. Enumerate all distinct blocking findings in the provided files.
- Never summarize or collapse multiple occurrences of the same problem into a single finding (e.g. never write something like "fix these 10 occurrences" or "occurs throughout the file"). Every single occurrence gets its own finding object with its own exact file and line number, even if the wording is otherwise identical.
- Do not invent package versions. Only recommend a concrete dependency upgrade when the target version is known/published; otherwise recommend replacing the dependency or pinning to the latest available safe version.
- Do not flag SMTP as insecure when secure=false is paired with port 587 (STARTTLS submission mode).
- Do not flag hardcoded SMTP secrets unless a non-empty credential literal is present in code/config.

Classification rules:
- Dangerous dependency findings must be category "dependency" and level "error".
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
      const hasCommandAllowlist = /const ALLOWED_COMMANDS = Object\.freeze\(new Set\(\['git', 'gh', 'act', 'docker', 'gitleaks'\]\)\);/.test(fileText);
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
  const files = [];
  for await (const file of walkFiles(root)) {
    if (!LLM_SOURCE_EXTS.has(path.extname(file).toLowerCase())) continue;
    const buffer = await fsp.readFile(file);
    if (looksBinary(buffer) || buffer.length > 200_000) continue;
    files.push({ rel: path.relative(root, file), content: buffer.toString('utf8'), hash: hashBuffer(buffer) });
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
          if (category === 'dependency') level = 'error';
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
  if (!(await llmAvailable())) return null;

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
/* Failure notifications (email)                                       */
/* ------------------------------------------------------------------ */

const PHASE_TITLES = {
  1: 'Input & Metadata Configuration',
  2: 'GxP Validation Documents',
  3: 'Extraction, Structure Audit & Unit Tests',
  4: 'Security & AI Compliance Scan',
  5: 'Org Governance CI (GitHub Actions via act)',
  6: 'Provisioning & Shipping',
};

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
app.get('/api/config', (req, res) => {
  const raw = CONFIG.github.orgs;
  const orgs = (Array.isArray(raw) ? raw : String(raw).split(','))
    .map((s) => String(s).trim())
    .filter(Boolean);
  res.json({ orgs });
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

// On-demand, non-technical AI explanation of a single flagged issue's code
// snippet (shown as the hover tooltip in the UI). Cached in the DB by a
// stable hash of the issue's identity, so opening the same finding again —
// even in a different run — never re-triggers the LLM call.
app.post('/api/issues/explain', async (req, res) => {
  const body = req.body || {};
  const category = String(body.category || '').trim();
  const summary = String(body.summary || '').trim();
  if (!category || !summary) {
    return res.status(400).json({ error: 'category and summary are required.' });
  }
  const issue = {
    category,
    severity: ['error', 'warning'].includes(body.severity) ? body.severity : 'warning',
    file: body.file ? String(body.file).slice(0, 500) : null,
    line: Number.isInteger(body.line) ? body.line : null,
    summary: summary.slice(0, 500),
    snippet: body.snippet && typeof body.snippet === 'object' && Array.isArray(body.snippet.lines)
      ? body.snippet
      : null,
  };

  const hash = issueExplanationHash(issue);
  const cached = store.getCachedIssueExplanation(hash);
  if (cached) return res.json({ ok: true, explanation: cached, cached: true });

  if (!(await llmAvailable())) {
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
  const isGxp = body.gxp === true;
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
    projectId = store.createProject(jobId, org, repo, isGxp);
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

    const issues = collectPhase4Issues({ secrets, governance, llm });
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
    if (!runLocalCi) {
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
  const isGxp = body.gxp === true;
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
    projectId = store.createProject(jobId, org, repo, isGxp);
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

    const issues = collectPhase4Issues({ secrets, governance, llm });
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
    if (!runLocalCi) {
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
  const isGxp = req.body.gxp === 'true';
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

  const runState = { org, repo, projectId: null, allIssues };
  runningRuns.set(jobId, runState);
  const persistIssuesSnapshot = (overriddenIds) => {
    if (runState.projectId === null) return;
    try { store.replaceProjectIssues(runState.projectId, allIssues, overriddenIds); } catch { /* best-effort */ }
  };

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
      projectId = store.createProject(jobId, org, repo, isGxp);
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

        const issues = collectPhase4Issues({ secrets, governance, llm });
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
          err.failureLines.forEach((failureLine, i) => {
            allIssues.push({
              id: `phase5::governance-ci::${i}`, phase: 5, category: 'governance-ci',
              severity: 'error', score: scoreForIssue({ category: 'governance-ci', severity: 'error' }), summary: failureLine, file: null, line: null,
            });
          });
        } else {
          allIssues.push({
            id: 'phase5::governance-ci', phase: 5, category: 'governance-ci',
            severity: 'error', score: scoreForIssue({ category: 'governance-ci', severity: 'error' }), summary: err.message, file: null, line: null,
          });
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
      send({ type: 'review_required', phase: 6, jobId, issues: allIssues });
      const decision = await decisionPromise;

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
}

module.exports = {
  checkEnvFiles,
  checkSecrets,
  checkAiGovernance,
  runGitleaksScan,
  loadConfig,
  runProjectUnitTests,
};
