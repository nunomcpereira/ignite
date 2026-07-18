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

const AI_INVOKE_REGEX = /\.(invoke|stream|ainvoke|astream)\(/;

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
  aiRecursionLimit(content) {
    if (content.includes('recursion_limit')) return []; // governed — compliant
    return scanLines(content, AI_INVOKE_REGEX);
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
