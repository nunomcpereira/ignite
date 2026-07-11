/**
 * Ignite (onboarding gatekeeper) — backend server
 *
 * Pipeline: ZIP upload -> extraction to isolated staging dir -> structure audit
 * (.env* denial) -> secret regex scan -> AI governance audit -> git/gh shipping.
 * Progress is streamed to the client as NDJSON events over a single POST
 * response. Staging directories are force-removed in a `finally` block no
 * matter how the pipeline ends.
 */

const express = require('express');
const { DatabaseSync } = require('node:sqlite');
const multer = require('multer');
const nodemailer = require('nodemailer');
const StreamZip = require('node-stream-zip');
const { execFile, spawn } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const fsp = require('fs/promises');
const os = require('os');
const path = require('path');

/* ------------------------------------------------------------------ */
/* Configuration: config.json < environment variables                  */
/* ------------------------------------------------------------------ */

function loadConfig() {
  const defaults = {
    port: 3000,
    llm: { url: 'http://localhost:8050', model: 'default', mode: 'warn', maxFiles: 40 },
    github: { orgs: '', bootstrapBranch: 'ignite' },
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
  return merged;
}

const CONFIG = loadConfig();

/* ------------------------------------------------------------------ */
/* Persistence: SQLite (node:sqlite) — onboarding history + documents  */
/* ------------------------------------------------------------------ */

const db = new DatabaseSync(path.join(__dirname, 'ignite.db'));
db.exec(`
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS projects (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id      TEXT UNIQUE NOT NULL,
    org         TEXT NOT NULL,
    repo        TEXT NOT NULL,
    gxp         INTEGER NOT NULL DEFAULT 0,
    status      TEXT NOT NULL DEFAULT 'running',
    error       TEXT,
    repo_url    TEXT,
    pr_url      TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at TEXT
  );
  CREATE TABLE IF NOT EXISTS steps (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    phase      INTEGER NOT NULL,
    title      TEXT NOT NULL,
    state      TEXT NOT NULL,
    logs       TEXT NOT NULL DEFAULT ''
  );
  CREATE TABLE IF NOT EXISTS documents (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL CHECK (kind IN ('upload','link')),
    name       TEXT NOT NULL,
    url        TEXT,
    mime       TEXT,
    size       INTEGER,
    data       BLOB,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

const insertProject = db.prepare(
  'INSERT INTO projects (job_id, org, repo, gxp) VALUES (?, ?, ?, ?)'
);
const finishProject = db.prepare(
  `UPDATE projects SET status = ?, error = ?, repo_url = ?, pr_url = ?, finished_at = datetime('now') WHERE id = ?`
);
const insertStep = db.prepare(
  'INSERT INTO steps (project_id, phase, title, state, logs) VALUES (?, ?, ?, ?, ?)'
);
const insertDocument = db.prepare(
  'INSERT INTO documents (project_id, kind, name, url, mime, size, data) VALUES (?, ?, ?, ?, ?, ?, ?)'
);

const PORT = process.env.PORT || CONFIG.port;
const MAX_ZIP_BYTES = 250 * 1024 * 1024; // 250 MB upload cap
const MAX_EXTRACTED_BYTES = 1024 * 1024 * 1024; // zip-bomb guard
const MAX_SCAN_FILE_BYTES = 5 * 1024 * 1024; // skip huge files in text scans

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const pendingReviewDecisions = new Map();

function waitForReviewDecision(jobId, timeoutMs = 5 * 60_000) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      pendingReviewDecisions.delete(jobId);
      resolve({ proceed: false, reason: 'timeout' });
    }, timeoutMs);
    pendingReviewDecisions.set(jobId, {
      resolve: (decision) => {
        clearTimeout(timer);
        pendingReviewDecisions.delete(jobId);
        resolve(decision);
      },
    });
  });
}

const upload = multer({
  dest: path.join(os.tmpdir(), 'gatekeeper-uploads'),
  limits: { fileSize: MAX_ZIP_BYTES, files: 5000 },
});

/* ------------------------------------------------------------------ */
/* Scan configuration                                                  */
/* ------------------------------------------------------------------ */

/* Local LLM deep-scan (llama.cpp / OpenAI-compatible API) */
const LLM_SCAN_URL = process.env.LLM_SCAN_URL || CONFIG.llm.url;
const LLM_SCAN_MODEL = process.env.LLM_SCAN_MODEL || CONFIG.llm.model;
const LLM_SCAN_MODE = process.env.LLM_SCAN_MODE || CONFIG.llm.mode; // 'warn' | 'block'
const LLM_MAX_FILES = parseInt(process.env.LLM_MAX_FILES || String(CONFIG.llm.maxFiles), 10);
const LLM_CHUNK_CHARS = 24_000; // per-request source budget
const LLM_SOURCE_EXTS = new Set([
  '.py', '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs', '.go', '.rb', '.php',
  '.java', '.cs', '.sh', '.yaml', '.yml', '.json', '.sql', '.tf',
]);

const SECRET_REGEX =
  /(password|aws_secret|api_key|token|private_key)\s*[:=]\s*['" \t]*[a-zA-Z0-9_\-.~]{10,}/i;

const AI_INVOKE_REGEX = /\.(invoke|stream|ainvoke|astream)\(/;

const SKIP_DIRS = new Set([
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
]);

const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.bmp', '.tiff',
  '.pdf', '.zip', '.gz', '.tar', '.bz2', '.7z', '.rar',
  '.woff', '.woff2', '.ttf', '.otf', '.eot',
  '.mp3', '.mp4', '.mov', '.avi', '.mkv', '.wav', '.ogg',
  '.exe', '.dll', '.so', '.dylib', '.bin', '.o', '.a', '.class',
  '.pyc', '.wasm', '.jar', '.db', '.sqlite', '.sqlite3',
]);

const GITHUB_NAME_REGEX = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/; // org login rules
const REPO_NAME_REGEX = /^[A-Za-z0-9._-]{1,100}$/;
const SAFE_UPLOAD_SEGMENT_REGEX = /^[^\0/\\]+$/;

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

function looksBinary(buffer) {
  // NUL byte in the first 8 KB is the classic binary heuristic.
  const slice = buffer.subarray(0, 8192);
  return slice.includes(0);
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

function run(cmd, args, cwd) {
  return new Promise((resolve, reject) => {
    const safeCmd = sanitizeCliArg(cmd, 'Command');
    const safeArgs = Array.isArray(args)
      ? args.map((arg, i) => sanitizeCliArg(arg, `Argument #${i + 1}`))
      : [];
    const env = { ...process.env, GIT_TERMINAL_PROMPT: '0' };
    execFile(safeCmd, safeArgs, { cwd, env, timeout: 120_000, maxBuffer: 10 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        const detail = (stderr || stdout || err.message || '').trim();
        reject(new Error(`\`${safeCmd} ${safeArgs.join(' ')}\` failed: ${detail}`));
      } else {
        resolve({ stdout: stdout.trim(), stderr: stderr.trim() });
      }
    });
  });
}

function sanitizeCliArg(value, label) {
  const s = String(value ?? '');
  if (!s) throw new Error(`${label} cannot be empty.`);
  if (/\0|\r|\n/.test(s)) throw new Error(`${label} contains illegal control characters.`);
  return s;
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
function runStreaming(cmd, args, cwd, onLine, { timeoutMs = 15 * 60_000, env = {} } = {}) {
  return new Promise((resolve, reject) => {
    const safeCmd = sanitizeCliArg(cmd, 'Command');
    const safeArgs = Array.isArray(args)
      ? args.map((arg, i) => sanitizeCliArg(arg, `Argument #${i + 1}`))
      : [];
    const child = spawn(safeCmd, safeArgs, {
      cwd,
      env: { ...process.env, GIT_TERMINAL_PROMPT: '0', ...env },
    });
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`\`${safeCmd}\` timed out after ${timeoutMs / 60000} minutes.`));
    }, timeoutMs);

    let pending = { out: '', err: '' };
    const feed = (key) => (chunk) => {
      pending[key] += chunk.toString();
      const lines = pending[key].split('\n');
      pending[key] = lines.pop();
      lines.forEach((l) => { if (l.trim()) onLine(l); });
    };
    child.stdout.on('data', feed('out'));
    child.stderr.on('data', feed('err'));
    child.on('error', (err) => { clearTimeout(timer); reject(err); });
    child.on('close', (code) => {
      clearTimeout(timer);
      Object.values(pending).forEach((rest) => { if (rest.trim()) onLine(rest); });
      code === 0 ? resolve() : reject(new Error(`\`${safeCmd}\` exited with code ${code}.`));
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

/* ------------------------------------------------------------------ */
/* Checks                                                              */
/* ------------------------------------------------------------------ */

async function checkEnvFiles(root) {
  const offenders = [];
  for await (const file of walkFiles(root)) {
    const base = path.basename(file);
    if (base === '.env' || base.startsWith('.env.')) {
      offenders.push(path.relative(root, file));
    }
  }
  return offenders;
}

async function checkSecrets(root, log) {
  const findings = [];
  let scanned = 0;

  for await (const file of walkFiles(root)) {
    const ext = path.extname(file).toLowerCase();
    if (BINARY_EXTENSIONS.has(ext)) continue;

    const stat = await fsp.stat(file);
    if (stat.size > MAX_SCAN_FILE_BYTES) {
      log(`Skipping oversized file (${(stat.size / 1e6).toFixed(1)} MB): ${path.relative(root, file)}`);
      continue;
    }

    const buffer = await fsp.readFile(file);
    if (looksBinary(buffer)) continue;

    scanned++;
    const lines = buffer.toString('utf8').split(/\r?\n/);
    lines.forEach((line, i) => {
      const match = line.match(SECRET_REGEX);
      if (match) {
        findings.push({
          file: path.relative(root, file),
          line: i + 1,
          kind: match[1].toLowerCase(),
        });
      }
    });
  }

  return { findings, scanned };
}

async function checkAiGovernance(root) {
  const findings = [];
  let scanned = 0;

  for await (const file of walkFiles(root)) {
    const ext = path.extname(file).toLowerCase();
    if (!['.py', '.js', '.ts'].includes(ext)) continue;

    const buffer = await fsp.readFile(file);
    if (looksBinary(buffer)) continue;

    scanned++;
    const content = buffer.toString('utf8');
    if (content.includes('recursion_limit')) continue; // governed — compliant

    const lines = content.split(/\r?\n/);
    lines.forEach((line, i) => {
      if (AI_INVOKE_REGEX.test(line)) {
        findings.push({
          file: path.relative(root, file),
          line: i + 1,
          snippet: line.trim().slice(0, 120),
        });
      }
    });
  }

  return { findings, scanned };
}

/* ------------------------------------------------------------------ */
/* Check 3: local LLM security deep-scan (optional, Ollama-compatible) */
/* ------------------------------------------------------------------ */

const LLM_SECURITY_DEP_PROMPT = `You are a strict application security reviewer. You will receive source files from a project, each preceded by a "===== FILE: <path> =====" header with numbered lines.
Review ONLY for:
1) Security vulnerabilities: injection (SQL/command/template), path traversal, SSRF, insecure deserialization, XSS, broken auth/authz, weak crypto, unsafe eval/exec, prototype pollution, insecure temp files, missing input validation on dangerous sinks.
2) Potentially dangerous dependencies (known risky/malicious/deprecated-vulnerable usage from dependency manifests/lockfiles).

Classification rules:
- Dangerous dependency findings must be category "dependency" and level "error".
- Exploitable security findings should be category "security" and level "error".

Respond with ONLY a JSON object in this schema:
{"findings":[{"file":"<path>","line":<number>,"category":"security|dependency","level":"error","issue":"<one sentence>","recommendation":"<short actionable fix>"}]}
If nothing is found respond {"findings":[]}.`;

const LLM_QUALITY_PROMPT = `You are a senior software engineer performing a code quality and encapsulation review. You will receive source files from a project, each preceded by a "===== FILE: <path> =====" header with numbered lines.
Review ONLY for:
1) Encapsulation improvements (leaky abstractions, exposed mutable internals, missing boundaries, too much coupling).
2) Maintainability/code-quality improvements (complexity hotspots, duplicated logic, poor separation of concerns, fragile API shapes).

Classification rules:
- Findings from this pass are advisory and must be level "warning".
- Use category "encapsulation" or "quality".

Respond with ONLY a JSON object in this schema:
{"findings":[{"file":"<path>","line":<number>,"category":"encapsulation|quality","level":"warning","issue":"<one sentence>","recommendation":"<short actionable fix>"}]}
If nothing is found respond {"findings":[]}.`;

async function llmChat(sourceBlock, systemPrompt) {
  const res = await fetch(`${LLM_SCAN_URL}/v1/chat/completions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    signal: AbortSignal.timeout(300_000),
    body: JSON.stringify({
      model: LLM_SCAN_MODEL,
      stream: false,
      temperature: 0,
      response_format: { type: 'json_object' },
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: sourceBlock },
      ],
    }),
  });
  if (!res.ok) throw new Error(`LLM endpoint returned HTTP ${res.status}`);
  const data = await res.json();
  const text = data.choices?.[0]?.message?.content ?? '';
  try {
    const parsed = JSON.parse(text);
    return Array.isArray(parsed.findings) ? parsed.findings : [];
  } catch {
    throw new Error('LLM returned non-JSON output; skipping chunk.');
  }
}

async function checkLlmDeepScan(root, log) {
  // Probe the endpoint first so a missing llama.cpp fails soft with a clear message.
  try {
    const probe = await fetch(`${LLM_SCAN_URL}/health`, { signal: AbortSignal.timeout(3000) });
    if (!probe.ok) throw new Error(`HTTP ${probe.status}`);
  } catch (e) {
    return { available: false, reason: `No LLM endpoint at ${LLM_SCAN_URL} (${e.message})` };
  }

  // Collect candidate source files, numbered lines, chunked by char budget.
  const files = [];
  for await (const file of walkFiles(root)) {
    if (!LLM_SOURCE_EXTS.has(path.extname(file).toLowerCase())) continue;
    const buffer = await fsp.readFile(file);
    if (looksBinary(buffer) || buffer.length > 200_000) continue;
    files.push({ rel: path.relative(root, file), content: buffer.toString('utf8') });
    if (files.length >= LLM_MAX_FILES) break;
  }
  if (files.length === 0) return { available: true, findings: [], scanned: 0 };

  const chunks = [];
  let current = '';
  for (const f of files) {
    const numbered = f.content
      .split(/\r?\n/)
      .map((l, i) => `${i + 1}: ${l}`)
      .join('\n');
    const block = `===== FILE: ${f.rel} =====\n${numbered}\n\n`;
    if (current && current.length + block.length > LLM_CHUNK_CHARS) {
      chunks.push(current);
      current = '';
    }
    current += block.length > LLM_CHUNK_CHARS ? block.slice(0, LLM_CHUNK_CHARS) : block;
  }
  if (current) chunks.push(current);

  log(`Model: ${LLM_SCAN_MODEL} @ ${LLM_SCAN_URL} — ${files.length} files in ${chunks.length} chunk(s), 2 review passes (security/dependency + quality/encapsulation)...`);

  const findings = [];
  for (let i = 0; i < chunks.length; i++) {
    log(`Analyzing chunk ${i + 1}/${chunks.length} [security/dependency]...`);
    try {
      const chunkFindings = await llmChat(chunks[i], LLM_SECURITY_DEP_PROMPT);
      for (const f of chunkFindings) {
        if (f && typeof f.file === 'string' && f.issue) {
          const category = ['security', 'dependency', 'encapsulation', 'quality'].includes(f.category)
            ? f.category
            : 'security';
          let level = ['error', 'warning'].includes(f.level) ? f.level : 'warning';
          if (category === 'dependency') level = 'error';
          findings.push({
            file: f.file,
            line: Number.isInteger(f.line) ? f.line : 0,
            category,
            level,
            issue: String(f.issue).slice(0, 300),
            recommendation: String(f.recommendation || '').slice(0, 300),
          });
        }
      }
    } catch (e) {
      log(`⚠ Chunk ${i + 1} security/dependency pass skipped: ${e.message}`);
    }

    log(`Analyzing chunk ${i + 1}/${chunks.length} [quality/encapsulation]...`);
    try {
      const chunkFindings = await llmChat(chunks[i], LLM_QUALITY_PROMPT);
      for (const f of chunkFindings) {
        if (f && typeof f.file === 'string' && f.issue) {
          const category = ['encapsulation', 'quality'].includes(f.category)
            ? f.category
            : 'quality';
          findings.push({
            file: f.file,
            line: Number.isInteger(f.line) ? f.line : 0,
            category,
            level: 'warning',
            issue: String(f.issue).slice(0, 300),
            recommendation: String(f.recommendation || '').slice(0, 300),
          });
        }
      }
    } catch (e) {
      log(`⚠ Chunk ${i + 1} quality/encapsulation pass skipped: ${e.message}`);
    }
  }

  return { available: true, findings, scanned: files.length };
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
  const { stdout } = await run('gh', [
    'api',
    `repos/${GOVERNANCE_REPO}/contents/.github/workflows/${GOVERNANCE_WORKFLOW}`,
    '-H', 'Accept: application/vnd.github.raw',
  ], os.tmpdir());
  await fsp.mkdir(wfDir, { recursive: true });
  const wfFile = path.join(wfDir, GOVERNANCE_WORKFLOW);
  await fsp.writeFile(wfFile, stdout);
  log(`✓ Central governance workflow cached (${stdout.length} bytes).`);
  return wfFile;
}

async function actTooling() {
  try {
    await run('act', ['--version'], os.tmpdir());
  } catch {
    return { ok: false, reason: '`act` is not installed (brew install act).' };
  }
  try {
    await run('docker', ['info', '--format', '{{.ServerVersion}}'], os.tmpdir());
  } catch {
    return { ok: false, reason: 'Docker daemon is not running (start Docker Desktop).' };
  }
  return { ok: true };
}

async function runActionsLocally(root, wfFile, log) {
  // act needs the workspace to be a git repo for ref/branch metadata; Phase 5
  // would create one anyway, so initialize it here and reuse it for shipping.
  await run('git', ['init', '-b', 'main'], root);
  await run('git', ['add', '.'], root);
  await run(
    'git',
    ['-c', 'user.name=Onboarding Gatekeeper', '-c', 'user.email=gatekeeper@localhost',
     'commit', '-m', 'chore: initial compliant code drop via onboarding gatekeeper'],
    root
  );

  let token = '';
  try {
    token = (await run('gh', ['auth', 'token'], root)).stdout;
  } catch {
    log('⚠ Could not read gh auth token — remote reusable workflows may fail to resolve.');
  }

  const args = [
    ACT_EVENT,
    '-W', wfFile,
    '-P', 'ubuntu-latest=catthehacker/ubuntu:act-latest',
    '--rm',
  ];
  if (token) args.push('-s', `GITHUB_TOKEN=${token}`);

  log(`$ act ${ACT_EVENT} -W ${path.basename(wfFile)} -P ubuntu-latest=catthehacker/ubuntu:act-latest --rm`);
  log('(first run downloads runner/tool images — may take a few minutes)');
  await runStreaming('act', args, root, (line) => log(line.slice(0, 400)), {
    timeoutMs: ACT_TIMEOUT_MIN * 60_000,
  });
}

/* ------------------------------------------------------------------ */
/* Phase 5: git + gh shipping                                          */
/* ------------------------------------------------------------------ */

async function shipToGitHub(root, org, repo, log) {
  const safeOrg = sanitizeCliArg(org, 'Organization name');
  const safeRepo = sanitizeCliArg(repo, 'Repository name');
  const fullName = `${safeOrg}/${safeRepo}`;

  // Phase 4 may already have initialized and committed the repo for act.
  const alreadyRepo = fs.existsSync(path.join(root, '.git'));
  if (alreadyRepo) {
    log('Reusing repository initialized during the local CI phase.');
  } else {
    log('$ git init -b main');
    await run('git', ['init', '-b', 'main'], root);

    log('$ git add .');
    await run('git', ['add', '.'], root);

    log('$ git commit -m "chore: initial compliant code drop via onboarding gatekeeper"');
    await run(
      'git',
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
    await run('gh', ['api', '-X', 'POST', `orgs/${safeOrg}/repos`,
      '-f', `name=${safeRepo}`, '-F', 'private=true', '-F', 'auto_init=true'], root);
  } catch (e) {
    if (/404/.test(e.message)) {
      // Personal account, not an organization.
      log(`"${safeOrg}" is not an org — creating under the authenticated user.`);
      await run('gh', ['api', '-X', 'POST', 'user/repos',
        '-f', `name=${safeRepo}`, '-F', 'private=true', '-F', 'auto_init=true'], root);
    } else {
      throw e;
    }
  }

  try {
    await run('gh', ['api', '-X', 'PATCH', `repos/${fullName}`, '-F', 'allow_auto_merge=true'], root);
    log('Enabled auto-merge on the repository.');
  } catch {
    log('⚠ Could not enable auto-merge — the PR will need a manual merge once checks pass.');
  }

  log(`$ git remote add origin "${remoteUrl}"`);
  await run('git', ['remote', 'add', 'origin', remoteUrl], root);

  // Repo initialization is asynchronous — and org rulesets with required
  // workflows can block the creation of main entirely. Wait briefly for it.
  log('$ git fetch origin main');
  let mainExists = false;
  for (let attempt = 1; attempt <= 8; attempt++) {
    try {
      await run('git', [...gitCred, 'fetch', 'origin', 'main'], root);
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
    await run('git', [...gitId, 'rebase', '-X', 'theirs', 'origin/main'], root);
  }

  log(`$ git push -u origin HEAD:${ONBOARD_BRANCH}`);
  await run('git', [...gitCred, 'push', '-u', 'origin', `HEAD:${ONBOARD_BRANCH}`], root);
  const { stdout: sha } = await run('git', ['rev-parse', 'HEAD'], root);

  if (!mainExists) {
    // Try to create main directly from the compliant commit (works in
    // orgs/accounts without a required-workflow ruleset on main).
    log('$ gh api POST git/refs (create main from onboarding commit)');
    try {
      await run('gh', ['api', '-X', 'POST', `repos/${fullName}/git/refs`,
        '-f', 'ref=refs/heads/main', '-f', `sha=${sha}`], root);
      log('✓ main created directly — no ruleset restriction on this repo.');
      await run('gh', ['api', '-X', 'PATCH', `repos/${fullName}`, '-f', 'default_branch=main'], root)
        .then(() => log('✓ Default branch set to main.'))
        .catch(() => log('⚠ Could not set main as the default branch — adjust in repo settings.'));
      log(`✓ Code is live on main.`);
      return { repoUrl: `https://github.com/${fullName}` };
    } catch {
      // Deadlock: the ruleset blocks ALL creation of main (even GitHub's
      // auto-init), but the required workflow can only run on a PR whose
      // base is main. No client-side flow can satisfy it.
      await run('gh', ['api', '-X', 'PATCH', `repos/${fullName}`,
        '-f', `default_branch=${ONBOARD_BRANCH}`], root).catch(() => {});
      log(`⚠ The org ruleset blocks creating "main" in new repos (bootstrap deadlock: the required workflow can only run on a PR, and a PR needs main to exist).`);
      log(`✓ Code shipped to "${ONBOARD_BRANCH}", now the repository's default branch.`);
      log(`⚠ Once an org admin adds a ruleset bypass so main can be bootstrapped, open a PR from "${ONBOARD_BRANCH}" into main.`);
      return { repoUrl: `https://github.com/${fullName}/tree/${ONBOARD_BRANCH}` };
    }
  }

  log('$ gh pr create --base main');
  const { stdout: prOut } = await run('gh', [
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
    await run('gh', ['pr', 'merge', prUrl, '--auto', '--squash'], root);
    log('✓ Auto-merge armed — the PR merges itself when the required workflow passes.');
  } catch (e) {
    log(`⚠ Auto-merge could not be armed (${e.message}). Merge manually once checks pass.`);
  }

  log('Waiting for the required org workflow to run on GitHub...');
  try {
    await runStreaming('gh', ['pr', 'checks', prUrl, '--watch', '--interval', '15'],
      root, (line) => log(line.slice(0, 300)), { timeoutMs: 20 * 60_000 });
    log('✓ All remote required checks passed — auto-merge will land the PR on main.');
  } catch (e) {
    throw new Error(`Remote governance checks did not pass (${e.message}). PR left open for review: ${prUrl}`);
  }

  return { repoUrl: `https://github.com/${fullName}`, prUrl };
}

/* ------------------------------------------------------------------ */
/* AI failure insight: explain the failed step in plain language       */
/* ------------------------------------------------------------------ */

const INSIGHT_SYSTEM_PROMPT = `You are a senior DevOps engineer explaining a CI pipeline failure to a developer who did not write the pipeline. You get the raw log of the failed step.
Answer in plain language, no CI jargon, max ~180 words, in exactly this structure:
**What failed:** one sentence naming the concrete check/tool and, when the log shows it, the exact file(s) and line(s).
**Why:** one or two sentences on the root cause found in the log.
**How to fix:** 1-3 short bullet points with the most direct fix.
Never quote long log fragments. If the log shows multiple problems, cover the ones that made the step fail.`;

async function generateFailureInsight(failedPhase, error, record) {
  try {
    const probe = await fetch(`${LLM_SCAN_URL}/health`, { signal: AbortSignal.timeout(3000) });
    if (!probe.ok) return null;
  } catch {
    return null;
  }

  // Full log of the failed phase, keeping the tail if enormous.
  const logs = (record[failedPhase]?.logs || []).join('\n').slice(-18_000);
  const res = await fetch(`${LLM_SCAN_URL}/v1/chat/completions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    signal: AbortSignal.timeout(120_000),
    body: JSON.stringify({
      model: LLM_SCAN_MODEL,
      stream: false,
      temperature: 0.2,
      messages: [
        { role: 'system', content: INSIGHT_SYSTEM_PROMPT },
        {
          role: 'user',
          content: `Pipeline phase ${failedPhase} ("${PHASE_TITLES[failedPhase] || 'Unknown'}") failed.\nReported error: ${error}\n\nFull step log:\n${logs}`,
        },
      ],
    }),
  });
  if (!res.ok) return null;
  const data = await res.json();
  const text = (data.choices?.[0]?.message?.content || '').trim();
  return text || null;
}

/* ------------------------------------------------------------------ */
/* Failure notifications (email)                                       */
/* ------------------------------------------------------------------ */

const PHASE_TITLES = {
  1: 'Input & Metadata Configuration',
  2: 'GxP Validation Documents',
  3: 'Extraction & Structure Audit',
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
  const rows = db.prepare(`
    SELECT p.id, p.org, p.repo, p.gxp, p.status, p.error, p.repo_url, p.pr_url,
           p.created_at, p.finished_at,
           (SELECT COUNT(*) FROM documents d WHERE d.project_id = p.id) AS doc_count
    FROM projects p ORDER BY p.id DESC LIMIT 100
  `).all();
  res.json(rows);
});

app.get('/api/projects/:id', (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid project id.' });
  const project = db.prepare(
    'SELECT id, org, repo, gxp, status, error, repo_url, pr_url, created_at, finished_at FROM projects WHERE id = ?'
  ).get(id);
  if (!project) return res.status(404).json({ error: 'Project not found.' });
  const steps = db.prepare(
    'SELECT phase, title, state, logs FROM steps WHERE project_id = ? ORDER BY phase'
  ).all(id);
  const documents = db.prepare(
    'SELECT id, kind, name, url, mime, size, created_at FROM documents WHERE project_id = ? ORDER BY id'
  ).all(id);
  res.json({ ...project, steps, documents });
});

app.post('/api/pipeline/:jobId/review-decision', (req, res) => {
  const jobId = String(req.params.jobId || '').trim();
  const pending = pendingReviewDecisions.get(jobId);
  if (!pending) return res.status(404).json({ error: 'No pending review decision for this job.' });
  const proceed = req.body?.proceed === true;
  pending.resolve({ proceed, reason: proceed ? 'user-continue' : 'user-stop' });
  res.json({ ok: true });
});

app.delete('/api/projects/:id', (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid project id.' });
  const existing = db.prepare('SELECT id FROM projects WHERE id = ?').get(id);
  if (!existing) return res.status(404).json({ error: 'Project not found.' });
  db.prepare('DELETE FROM documents WHERE project_id = ?').run(id);
  db.prepare('DELETE FROM steps WHERE project_id = ?').run(id);
  db.prepare('DELETE FROM projects WHERE id = ?').run(id);
  res.json({ ok: true });
});

app.delete('/api/projects', (req, res) => {
  db.exec('DELETE FROM documents; DELETE FROM steps; DELETE FROM projects;');
  res.json({ ok: true });
});

app.get('/api/documents/:id', (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid document id.' });
  const doc = db.prepare('SELECT kind, name, url, mime, data FROM documents WHERE id = ?').get(id);
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

  const send = (event) => res.write(JSON.stringify(event) + '\n');
  // Server-side record of every phase's state and logs, for failure emails.
  const record = {};
  const rec = (phase) => (record[phase] ??= { state: 'pending', logs: [] });
  const phaseLog = (phase) => (message) => {
    rec(phase).logs.push(message);
    send({ type: 'log', phase, message });
  };
  let currentPhase = 1;
  const status = (phase, state, extra = {}) => {
    if (state === 'running') currentPhase = phase;
    rec(phase).state = state;
    send({ type: 'status', phase, state, ...extra });
  };

  const jobId = crypto.randomUUID();
  const stagingDir = path.join(os.tmpdir(), 'gatekeeper-staging', jobId);
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
  let gxpLinks = [];
  try {
    const parsed = JSON.parse(req.body.gxpLinks || '[]');
    if (Array.isArray(parsed)) gxpLinks = parsed;
  } catch { /* validated in phase 2 */ }

  let projectId = null;

  try {
    /* ---------------- Phase 1: input validation ---------------- */
    status(1, 'running');
    const log1 = phaseLog(1);

    if (!zipFile && dirFiles.length === 0) {
      throw Object.assign(new Error('No ZIP archive or folder upload received.'), { phase: 1 });
    }
    if (dirFiles.length > 0 && !Array.isArray(relPaths)) {
      throw Object.assign(new Error('Folder upload metadata is invalid: paths must be an array.'), { phase: 1 });
    }
    if (!GITHUB_NAME_REGEX.test(org)) {
      throw Object.assign(new Error(`Invalid GitHub organization name: "${org}"`), { phase: 1 });
    }
    if (!REPO_NAME_REGEX.test(repo) || repo === '.' || repo === '..') {
      throw Object.assign(new Error(`Invalid repository name: "${repo}"`), { phase: 1 });
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
    projectId = Number(insertProject.run(jobId, org, repo, isGxp ? 1 : 0).lastInsertRowid);
    status(1, 'success');

    /* ---------------- Phase 2: GxP validation documents ---------------- */
    if (!isGxp) {
      rec(2).state = 'skipped';
      phaseLog(2)('Process declared non-GxP — no validation documents required.');
      send({ type: 'status', phase: 2, state: 'skipped' });
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

      if (gxpDocFiles.length === 0 && validLinks.length === 0) {
        throw Object.assign(
          new Error('GxP process declared but no validation documents provided. Attach at least one document (upload or link).'),
          { phase: 2 }
        );
      }

      logG(`Collecting ${gxpDocFiles.length} uploaded document(s) and ${validLinks.length} link(s)...`);
      for (const doc of gxpDocFiles) {
        const data = await fsp.readFile(doc.path);
        insertDocument.run(projectId, 'upload', doc.originalname, null, doc.mimetype || null, doc.size, data);
        logG(`✓ Archived upload: ${doc.originalname} (${(doc.size / 1024).toFixed(1)} KB)`);
      }
      for (const link of validLinks) {
        insertDocument.run(projectId, 'link', link.name, link.url, null, null, null);
        logG(`✓ Archived link: ${link.name} → ${link.url}`);
      }
      logG(`✓ ${gxpDocFiles.length + validLinks.length} GxP validation document(s) saved to the database.`);
      status(2, 'success');
    }

    /* ---------------- Phase 3: extraction + structure audit ---------------- */
    status(3, 'running');
    const log2 = phaseLog(3);

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

    const projectRoot = await resolveProjectRoot(stagingDir);
    if (projectRoot !== stagingDir) {
      log2(`Detected single top-level folder — project root: ${path.basename(projectRoot)}/`);
    }

    log2('Check 1 — scanning for raw environment files (.env*)...');
    const envOffenders = await checkEnvFiles(projectRoot);
    if (envOffenders.length > 0) {
      log2(`✗ ${envOffenders.length} forbidden environment file(s) found:`);
      envOffenders.forEach((f) => log2(`    ✗ ${f}`));
      throw Object.assign(
        new Error(`Raw environment files detected (${envOffenders.length}). Remove them and re-upload.`),
        { phase: 3 }
      );
    }
    log2('✓ Check 1 passed — no raw environment files present.');
    status(3, 'success');

    /* ---------------- Phase 4: security + AI compliance ---------------- */
    status(4, 'running');
    const log3 = phaseLog(4);

    log3('Check 2 — scanning text files for hardcoded credentials...');
    const secrets = await checkSecrets(projectRoot, log3);
    log3(`Scanned ${secrets.scanned} text files.`);
    if (secrets.findings.length > 0) {
      log3(`✗ ${secrets.findings.length} potential credential leak(s):`);
      secrets.findings.forEach((f) => log3(`    ✗ ${f.file}:${f.line} — hardcoded ${f.kind}`));
      throw Object.assign(
        new Error(`Hardcoded credentials detected in ${secrets.findings.length} location(s).`),
        { phase: 4 }
      );
    }
    log3('✓ Check 2 passed — no credential leakage detected.');

    log3('Check 4 — AI governance audit (.py/.js/.ts LangChain/LangGraph calls)...');
    const governance = await checkAiGovernance(projectRoot);
    log3(`Audited ${governance.scanned} source files.`);
    if (governance.findings.length > 0) {
      log3(`✗ ${governance.findings.length} ungoverned AI invocation(s) — missing recursion_limit:`);
      governance.findings.forEach((f) => log3(`    ✗ ${f.file}:${f.line} — ${f.snippet}`));
      throw Object.assign(
        new Error(
          `AI invocations without recursion_limit found in ${governance.findings.length} location(s).`
        ),
        { phase: 4 }
      );
    }
    log3('✓ Check 4 passed — all AI invocations are governed.');

    {
      log3(`Check 3 — local LLM code review (security, dependency, quality, encapsulation; mode: ${LLM_SCAN_MODE})...`);
      const llm = await checkLlmDeepScan(projectRoot, log3);
      if (!llm.available) {
        log3(`⚠ Deep-scan skipped: ${llm.reason}`);
      } else if (llm.findings.length === 0) {
        log3(`✓ Check 3 passed — LLM found no security/dependency errors or quality/encapsulation warnings in ${llm.scanned} files.`);
      } else {
        const errors = llm.findings.filter((f) => f.level === 'error');
        const warnings = llm.findings.filter((f) => f.level === 'warning');
        log3(`LLM reported ${llm.findings.length} finding(s):`);
        llm.findings.forEach((f) =>
          log3(`    ${f.level === 'error' ? '✗' : '⚠'} [${f.level}] [${f.category}] ${f.file}:${f.line} — ${f.issue}${f.recommendation ? ` | fix: ${f.recommendation}` : ''}`)
        );

        if (errors.length > 0) {
          throw Object.assign(
            new Error(`LLM review found ${errors.length} blocking error(s).`),
            { phase: 4 }
          );
        }

        if (warnings.length > 0) {
          log3(`⚠ ${warnings.length} warning(s) found — waiting for user decision to continue or interrupt.`);
          const decisionPromise = waitForReviewDecision(jobId);
          send({
            type: 'review_required',
            phase: 4,
            jobId,
            warnings: warnings.map((f) => ({
              file: f.file,
              line: f.line,
              category: f.category,
              issue: f.issue,
              recommendation: f.recommendation,
            })),
          });
          const decision = await decisionPromise;
          if (!decision.proceed) {
            throw Object.assign(
              new Error('Pipeline interrupted by user after LLM review warnings.'),
              { phase: 4 }
            );
          }
          log3('✓ User chose to continue after reviewing warnings.');
        }
      }
    }

    status(4, 'success');

    /* ---------------- Phase 5: local GitHub Actions run (act) ---------------- */
    status(5, 'running');
    const log4 = phaseLog(5);

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

    /* ---------------- Phase 6: provisioning + shipping ---------------- */
    status(6, 'running');
    const log5 = phaseLog(6);

    const { repoUrl, prUrl } = await shipToGitHub(projectRoot, org, repo, log5);
    log5(`✓ Repository live at ${repoUrl}`);
    status(6, 'success', { repoUrl, prUrl });

    if (projectId !== null) {
      finishProject.run('success', null, repoUrl, prUrl || null, projectId);
    }
    send({ type: 'done', ok: true, repoUrl, prUrl });
  } catch (err) {
    const phase = err.phase || currentPhase;
    phaseLog(phase)(`✗ ${err.message}`);
    status(phase, 'failed', { error: err.message });

    // AI insight: pass the failed step's full log to the local LLM for a
    // user-friendly explanation. Soft-fails if the LLM is unavailable.
    let insight = null;
    send({ type: 'insight', phase, state: 'generating' });
    try {
      insight = await generateFailureInsight(phase, err.message, record);
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
      try { finishProject.run('failed', err.message, null, null, projectId); } catch { /* best-effort */ }
    }
    send({ type: 'done', ok: false, error: err.message, phase });
  } finally {
    // Persist every phase's state and logs for the onboarding history panel.
    if (projectId !== null) {
      try {
        for (const id of Object.keys(PHASE_TITLES)) {
          const ph = record[id] || { state: 'pending', logs: [] };
          insertStep.run(projectId, Number(id), PHASE_TITLES[id], ph.state, ph.logs.join('\n'));
        }
      } catch (e) {
        console.error(`Could not persist step history for job ${jobId}: ${e.message}`);
      }
    }
    // Forceful cleanup regardless of outcome: staging dir, the uploaded ZIP,
    // and any multer temp files not yet moved into staging.
    await fsp.rm(stagingDir, { recursive: true, force: true }).catch(() => {});
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

app.listen(PORT, () => {
  console.log(`Ignite (onboarding gatekeeper) running at http://localhost:${PORT}`);
});
