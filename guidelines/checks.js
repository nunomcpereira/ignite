'use strict';

const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const { GUIDELINES } = require('./catalog');

/* Mirrors the detection patterns used by Ignite's onboarding pipeline
 * (server.js) so the same rules apply whether checked locally via this
 * MCP server/API during development, or later during onboarding CI. */

const SECRET_REGEX =
  /(password|aws_secret|api_key|token|private_key)\s*[:=]\s*['" \t]*[a-zA-Z0-9_\-.~]{10,}/i;

// Captures the receiver so a call can be checked against the generic-client
// denylist below before it's ever counted as a finding.
const AI_INVOKE_REGEX = /\b([A-Za-z_$][\w.]*)\.(invoke|stream|ainvoke|astream)\(/;

// `.invoke(`/`.stream(` are common method names far beyond agent frameworks
// (httpx/requests-style HTTP clients, RxJS, generic RPC dispatchers, ...) —
// matching the bare method name alone flags things like
// `await client.stream("POST", url)` in an httpx test as an "ungoverned AI
// invocation", which it isn't. The catalog's own stated scope is
// LangChain/LangGraph-style chains/agents specifically (see catalog.js's
// ai-governance entry: "Pass a recursion_limit (LangGraph/LangChain) or
// equivalent"), so only flag a file that actually references one of those
// frameworks — a plain HTTP client never does.
const AGENT_FRAMEWORK_HINT_REGEX = /\b(langchain|langgraph|autogen|crewai)\b/i;

// Second, independent backstop on top of the file-wide framework hint
// above: even inside a file that genuinely uses LangChain/LangGraph
// elsewhere, an httpx/requests-style HTTP client is commonly named
// `client`/`http`/`session`/etc. and calling `.stream(`/`.invoke(` on
// *that* object is still not an agent invocation — real case hit in
// practice: a hand-rolled OpenAI-compatible streaming client doing
// `async with httpx.AsyncClient(...) as client: ... client.stream(...)`,
// flagged purely because the receiver was named `client`.
const GENERIC_CLIENT_RECEIVER_RE = /^(client|http|httpclient|session|conn|connection|resp|response|req|request)$/i;

// Test files exercise mocked/stubbed AI calls — the runaway-execution risk
// this guideline exists for is a production-runtime concern, not a testing
// one, so test paths are excluded even if they happen to reference an agent
// framework in a fixture/mock.
const TEST_FILE_REGEX = /(^|\/)(tests?|__tests__|spec)\/|(^|\/)(test_[^/]+\.py|[^/]+_test\.py|[^/]+\.(test|spec)\.[jt]sx?)$/i;

const INJECTION_SINK_REGEXES = [
  /\beval\(/,
  /new Function\(/,
  /\bexec\(\s*[`'"]/, // Python os.system/exec / subprocess with shell string literal start
  /child_process\.(exec|execSync)\(/, // shell=true style Node exec (not execFile)
  /\bpickle\.loads?\(/,
  /os\.system\(/,
  /subprocess\.(call|run|Popen)\([^)]*shell\s*=\s*True/,
];

const INSECURE_DESERIALIZATION_REGEXES = [
  /\bpickle\.loads?\(/,
  /yaml\.load\((?!.*Loader\s*=\s*yaml\.SafeLoader)/,
  /vm\.runInNewContext\(/,
];

const PLAINTEXT_HTTP_REGEX = /['"]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^'"]+['"]/;

// A SQL keyword built into a string via interpolation/concatenation rather
// than passed as a bound parameter — the classic injection shape. Matches
// f-strings/template literals with a `{`/`${` interpolation, and `+`-built
// strings, that contain a SQL verb; parameterized queries (`?`, `%s`, `$1`)
// never take this shape, so they're not flagged.
const SQL_INJECTION_REGEXES = [
  /f['"][^'"]*\b(select|insert|update|delete)\b[^'"]*\{/i,
  /`[^`]*\b(select|insert|update|delete)\b[^`]*\$\{/i,
  /['"][^'"]*\b(select|insert|update|delete)\b[^'"]*['"]\s*\+\s*\S/i,
  /\+\s*['"][^'"]*\b(select|insert|update|delete)\b/i,
];

const XSS_SINK_REGEXES = [
  /dangerouslySetInnerHTML/,
  /\.innerHTML\s*=/,
  /document\.write\(/,
  /\{\{.*\|\s*safe\s*\}\}/, // Jinja2 |safe filter disables autoescaping
  /\bMarkup\(/, // Flask/Jinja2 Markup() wrapping — same effect as |safe
];

// Cryptographically broken/deprecated primitives — flagged regardless of
// use case, since there's no correct security use of MD5/SHA-1 for hashing
// or DES/ECB for encryption today (unlike Math.random(), which is fine for
// non-security randomness and would be too noisy to flag unconditionally).
const WEAK_CRYPTO_REGEXES = [
  /crypto\.createHash\(\s*['"](md5|sha1)['"]\s*\)/i,
  /hashlib\.(md5|sha1)\(/i,
  /MessageDigest\.getInstance\(\s*['"](MD5|SHA-?1)['"]\s*\)/i,
  /createCipheriv\(\s*['"]des/i,
  /Cipher\.getInstance\(\s*['"](DES|[^'"]*\/ECB\/)/i,
];

// A request-derived value (req./request.) passed straight in as the URL/
// host argument of an outbound HTTP call - the classic SSRF shape. Scoped
// to the call's first argument only (up to the next comma/paren) to avoid
// flagging a literal URL that merely appends a request value as a query
// param later in the same call.
const SSRF_SINK_REGEXES = [
  /\b(fetch|axios(?:\.\w+)?)\(\s*(req|request)\.[^,)]*\)/i,
  /\brequests\.\w+\(\s*(req|request)\.[^,)]*\)/i,
];

// Explicitly disabling a framework's default-on CSRF protection.
const CSRF_DISABLED_REGEXES = [
  /@csrf_exempt/,
  /skip_before_action\s*:verify_authenticity_token/,
  /csrf\s*:\s*false/i,
];

// A third-party GitHub Actions step pinned to a mutable ref (branch/tag/
// "latest") instead of a full commit SHA. Deliberately not flagged for
// same-repo actions (`uses: ./...`) or actions/* published by GitHub
// itself, which are lower supply-chain risk and commonly left on @vN by
// convention even in security-conscious workflows.
const UNPINNED_GHA_ACTION_REGEX = /uses:\s*(?!\.\/|actions\/)[^@\s]+@(main|master|latest|v?\d+(?:\.\d+)*)\s*$/i;

const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.bmp', '.tiff',
  '.pdf', '.zip', '.gz', '.tar', '.bz2', '.7z', '.rar',
  '.woff', '.woff2', '.ttf', '.otf', '.eot',
  '.mp3', '.mp4', '.mov', '.avi', '.mkv', '.wav', '.ogg',
  '.exe', '.dll', '.so', '.dylib', '.bin', '.o', '.a', '.class',
  '.pyc', '.wasm', '.jar', '.db', '.sqlite', '.sqlite3',
]);

const SKIP_DIRS = new Set([
  'node_modules', '.git', '.next', 'dist', 'build', '__pycache__',
  '.venv', 'venv', 'vendor', '.idea', '.vscode',
]);

const MAX_SCAN_FILE_BYTES = 5 * 1024 * 1024;

function looksBinary(buffer) {
  return buffer.subarray(0, 8192).includes(0);
}

function scanLines(content, regex) {
  const hits = [];
  content.split(/\r?\n/).forEach((line, i) => {
    const match = line.match(regex);
    if (match) hits.push({ line: i + 1, snippet: line.trim().slice(0, 160), match });
  });
  return hits;
}

/* One function per automated guideline (checkId in catalog.js).
 * Signature: (content, relPath) -> Array<{ line, snippet }> */
const CHECKS = {
  aiRecursionLimit(content, relPath) {
    if (TEST_FILE_REGEX.test(String(relPath || ''))) return [];
    if (!AGENT_FRAMEWORK_HINT_REGEX.test(content)) return [];
    if (content.includes('recursion_limit')) return []; // governed — compliant
    return scanLines(content, AI_INVOKE_REGEX).filter((h) => {
      const receiver = h.match[1].split('.').pop();
      return !GENERIC_CLIENT_RECEIVER_RE.test(receiver);
    });
  },

  noHardcodedSecrets(content) {
    return scanLines(content, SECRET_REGEX).map((h) => ({
      line: h.line,
      snippet: h.snippet,
      kind: h.match[1].toLowerCase(),
    }));
  },

  noInjectionSinks(content) {
    const hits = [];
    for (const re of INJECTION_SINK_REGEXES) hits.push(...scanLines(content, re));
    return hits;
  },

  noInsecureDeserialization(content) {
    const hits = [];
    for (const re of INSECURE_DESERIALIZATION_REGEXES) hits.push(...scanLines(content, re));
    return hits;
  },

  noPlaintextHttpEgress(content) {
    return scanLines(content, PLAINTEXT_HTTP_REGEX);
  },

  noSqlInjection(content) {
    const hits = [];
    for (const re of SQL_INJECTION_REGEXES) hits.push(...scanLines(content, re));
    return hits;
  },

  noXssSinks(content) {
    const hits = [];
    for (const re of XSS_SINK_REGEXES) hits.push(...scanLines(content, re));
    return hits;
  },

  noWeakCrypto(content) {
    const hits = [];
    for (const re of WEAK_CRYPTO_REGEXES) hits.push(...scanLines(content, re));
    return hits;
  },

  noSsrfSinks(content) {
    const hits = [];
    for (const re of SSRF_SINK_REGEXES) hits.push(...scanLines(content, re));
    return hits;
  },

  noCsrfDisabled(content) {
    const hits = [];
    for (const re of CSRF_DISABLED_REGEXES) hits.push(...scanLines(content, re));
    return hits;
  },

  // Filename-scoped like noCommittedEnvFiles: only .github/workflows/*.yml,
  // never an arbitrary yaml file that happens to contain a "uses:" line.
  noUnpinnedGhaAction(content, relPath) {
    const normalized = String(relPath || '').replace(/\\/g, '/');
    if (!/(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/.test(normalized)) return [];
    return scanLines(content, UNPINNED_GHA_ACTION_REGEX);
  },

  // Filename-based; content-agnostic.
  noCommittedEnvFiles(_content, relPath) {
    const base = path.basename(relPath);
    if (base === '.env' || base.startsWith('.env.')) {
      return [{ line: 0, snippet: relPath }];
    }
    return [];
  },
};

/**
 * Check a single in-memory file (code snippet or full file) against every
 * automated guideline that applies to its extension.
 * @param {string} content
 * @param {{ path?: string }} opts - path used for extension matching and .env detection
 * @returns {Array<{guidelineId, severity, category, title, file, line, snippet}>}
 */
function checkContent(content, { path: relPath = 'snippet' } = {}) {
  const ext = path.extname(relPath).toLowerCase();
  const violations = [];

  for (const guideline of GUIDELINES) {
    if (!guideline.checkId) continue;
    const fn = CHECKS[guideline.checkId];
    if (!fn) continue;
    if (!guideline.appliesTo.includes('*') && !guideline.appliesTo.includes(ext)) continue;
    const hits = fn(content, relPath);
    for (const hit of hits) {
      violations.push({
        guidelineId: guideline.id,
        category: guideline.category,
        severity: guideline.severity,
        title: guideline.title,
        file: relPath,
        line: hit.line,
        snippet: hit.snippet,
      });
    }
  }
  return violations;
}

async function* walkFiles(root) {
  const entries = await fsp.readdir(root, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue;
    const full = path.join(root, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      yield* walkFiles(full);
    } else if (entry.isFile()) {
      yield full;
    }
  }
}

/**
 * Walk a project directory and apply every automated guideline.
 * @param {string} root - absolute path to the project root
 * @returns {Promise<{violations: Array, scanned: number}>}
 */
async function checkProject(root) {
  const violations = [];
  let scanned = 0;

  for await (const file of walkFiles(root)) {
    const relPath = path.relative(root, file);
    const ext = path.extname(file).toLowerCase();

    // Filename-only guidelines run even on files we won't content-scan.
    violations.push(
      ...CHECKS.noCommittedEnvFiles('', relPath).map((hit) => {
        const g = GUIDELINES.find((x) => x.checkId === 'noCommittedEnvFiles');
        return {
          guidelineId: g.id,
          category: g.category,
          severity: g.severity,
          title: g.title,
          file: relPath,
          line: hit.line,
          snippet: hit.snippet,
        };
      })
    );

    if (BINARY_EXTENSIONS.has(ext)) continue;

    const stat = await fsp.stat(file);
    if (stat.size > MAX_SCAN_FILE_BYTES) continue;

    const buffer = await fsp.readFile(file);
    if (looksBinary(buffer)) continue;

    scanned++;
    const content = buffer.toString('utf8');
    for (const v of checkContent(content, { path: relPath })) {
      if (v.guidelineId === 'no-committed-env-files') continue; // already handled above
      violations.push(v);
    }
  }

  return { violations, scanned };
}

module.exports = { checkContent, checkProject, CHECKS };
