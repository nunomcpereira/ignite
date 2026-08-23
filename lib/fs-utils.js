'use strict';

/**
 * Pure filesystem/content helpers shared by Ignite's checks — file
 * discovery, binary detection, code-snippet extraction, and bounded
 * concurrency. No config dependency, no shared mutable state (Phase A of
 * the server.js module split — see
 * /Users/nuno/.claude/plans/cuddly-roaming-pearl.md).
 */

const crypto = require('crypto');
const fsp = require('fs/promises');
const path = require('path');

// .angular is Angular CLI/Vite's own build cache (ng-cli-cache or vite's
// deps_ssr chunks) — bundled, minified copies of third-party dependencies
// (date-fns, firebase, express, ...) re-vendored under the project root,
// not source anyone wrote or would review. Measured on a real 6-workspace
// Angular monorepo: three .angular/cache directories accounted for 592k of
// 950k total scanned lines (62%) — the single largest fixable chunk of
// Phase 4's wall time was every check (semgrep, secrets, CodeQL, ...)
// dutifully scanning the same vendored dependency bundles three times over.
const SKIP_DIRS = Object.freeze(new Set([
  'node_modules',
  '.git',
  '.next',
  '.angular',
  'dist',
  'build',
  '__pycache__',
  '.venv',
  'venv',
  'vendor',
  '.idea',
  '.vscode',
]));

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
]));

const DOCKERFILE_NAME_RE = /^Dockerfile(\.[A-Za-z0-9_-]+)?$/;

// In source code, an unquoted RHS is always identifier/property-access
// syntax (a variable, `process.env.X`, `res.data.access_token`, ...) — never
// a literal. Config/env formats (.env, YAML, INI, ...) have no such quoting
// rule, so unquoted values there can genuinely be inline secrets. Shared by
// checkSecrets (server.js) and checkFileEncapsulation
// (checks/file-encapsulation.js) — both scope to "real source code" files.
const SECRET_SCAN_CODE_EXTS = Object.freeze(new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py', '.go', '.rb', '.php',
  '.java', '.kt', '.cs', '.c', '.cpp', '.h', '.hpp', '.swift', '.rs', '.scala',
]));

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
function buildSnippet(content, lineNumber, { colStart, colEnd, radius = 3, endLine } = {}) {
  if (typeof content !== 'string' || !Number.isInteger(lineNumber) || lineNumber < 1) return null;
  const lines = content.split(/\r?\n/);
  const idx = lineNumber - 1;
  if (idx >= lines.length) return null;

  // A multi-line finding (e.g. a jscpd duplicate block) passes endLine so
  // every affected row gets marked, not just the first — the whole span is
  // the finding, not just where it starts.
  const highlightEndLine = Number.isInteger(endLine) && endLine > lineNumber ? endLine : lineNumber;
  const endIdx = Math.min(lines.length - 1, highlightEndLine - 1);

  const start = Math.max(0, idx - radius);
  const end = Math.min(lines.length - 1, endIdx + radius);
  const code = [];
  for (let i = start; i <= end; i++) code.push({ number: i + 1, text: lines[i] });

  const snippet = { startLine: start + 1, lines: code, highlightLine: lineNumber };
  if (highlightEndLine > lineNumber) snippet.highlightEndLine = highlightEndLine;
  if (Number.isInteger(colStart) && Number.isInteger(colEnd) && colEnd > colStart) {
    snippet.highlightStart = colStart;
    snippet.highlightEnd = colEnd;
  }
  return snippet;
}

// .igniteignore (checks/igniteignore.js) is honored here, at the one choke
// point every check's file discovery already goes through, rather than
// threading an ignore matcher through walkFiles's ~20 call sites — a
// project-root .igniteignore is loaded once per top-level walkFiles(root)
// call (not per recursive descent — see walkDir below, which carries the
// original root and patterns down instead of re-resolving them at every
// directory level) and an ignored directory is pruned before it's ever
// descended into, same as SKIP_DIRS.
async function* walkDir(root, dir, ignorePatterns) {
  const entries = await fsp.readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue; // never follow symlinks out of staging
    const full = path.join(dir, entry.name);
    if (ignorePatterns.length > 0) {
      const rel = path.relative(root, full).split(path.sep).join('/');
      if (isGitignored(ignorePatterns, rel)) continue;
    }
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      yield* walkDir(root, full, ignorePatterns);
    } else if (entry.isFile()) {
      yield full;
    }
  }
}

// walkFiles(root) is called independently by ~10 of Phase 4's built-in
// checks (secrets, provenance, euAiActDocuments, deadCode, cssDeadCode,
// fileEncapsulation, apiSchema discovery, boundaries, igniteIgnore, ...),
// all running concurrently via Promise.all in runPhase4Checks. Each call
// re-walks the same directory tree from scratch with walkDir's sequential,
// unbatched fsp.readdir — on a large repo (measured: ~90-110s per full
// walk on a 59.5k-file monorepo) that's the same expensive tree walk paid
// N times over, competing for the same disk I/O all N times simultaneously.
// Caching the resolved file list per staged root turns those N walks into
// 1: safe because every check that calls walkFiles only reads the tree —
// nothing in a single validate-all/onboard run mutates tracked source
// files while Phase 4 is in flight (Bearer's own git init/commit only
// touches .git, which SKIP_DIRS already excludes from the list). Each
// pipeline run stages a fresh UUID temp dir, so a stale cache entry is
// only a risk across runs that reuse the exact same root path — callers
// must invalidate via invalidateWalkCache(root) once a staged root is torn
// down, or this leaks one array per job for the life of the process.
const walkCache = new Map();

async function computeFileList(root) {
  const ignorePatterns = await loadIgniteIgnorePatterns(root);
  const files = [];
  for await (const file of walkDir(root, root, ignorePatterns)) files.push(file);
  return files;
}

function invalidateWalkCache(root) {
  walkCache.delete(path.resolve(root));
}

async function* walkFiles(root) {
  const key = path.resolve(root);
  let pending = walkCache.get(key);
  if (!pending) {
    pending = computeFileList(root);
    walkCache.set(key, pending);
  }
  yield* await pending;
}

// Runs `mapper` over `items` with at most `limit` in flight at once, but
// resolves to results in the *original* item order regardless of which
// finishes first — checkSecrets/checkAiGovernance's per-file I/O (stat +
// readFile) is otherwise awaited one file at a time even though nothing
// about reading file N depends on file N-1 finishing first, which is pure
// wasted wall time on repos with many small files. Bounded (not
// unbounded Promise.all) so a repo with thousands of files doesn't try to
// open them all as file descriptors simultaneously.
async function mapWithConcurrency(items, limit, mapper) {
  const results = new Array(items.length);
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const i = next++;
      results[i] = await mapper(items[i], i);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

function hashBuffer(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

// Resolves an external tool's reported file path (which may be absolute
// and either canonical or not, depending on the tool — Spectral
// canonicalizes symlinks like macOS's /tmp -> /private/tmp in its output,
// Semgrep and Checkov generally don't) into a path relative to `root`,
// regardless of which representation `root` itself was given in or which
// representation the tool echoed back. realpath-ing *both* sides before
// diffing is what makes this work either way — canonicalizing only one
// side produces a technically-valid but useless
// "../../../../var/folders/.../root/../../../file" path whenever the two
// sides end up canonicalized inconsistently. Shared by every check that
// parses a tool's own JSON report (semgrep, spectral, the posture engine).
async function relativeToRoot(root, targetPath) {
  const raw = String(targetPath || '');
  const resolved = path.resolve(root, raw);
  const [realRoot, realTarget] = await Promise.all([
    fsp.realpath(root).catch(() => root),
    fsp.realpath(resolved).catch(() => resolved),
  ]);
  return path.relative(realRoot, realTarget);
}

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
    .replace(/\*\*|\*|\?/g, (m) => (m === '**' ? '.*' : m === '*' ? '[^/]*' : '[^/]'));
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

// Shared implementation behind loadGitignorePatterns and
// loadIgniteIgnorePatterns — both files use identical .gitignore syntax,
// just for different purposes (exemption from the secret-leak check vs.
// exclusion from every check's file discovery).
async function loadIgnoreFilePatterns(root, filename) {
  try {
    const content = await fsp.readFile(path.join(root, filename), 'utf8');
    return content
      .split(/\r?\n/)
      .filter((l) => l.trim() && !l.trim().startsWith('#'))
      .map(gitignorePatternToRegex);
  } catch {
    return []; // no such file at the project root — nothing to exempt/exclude
  }
}

// Shared by checkEnvFiles (server.js) and checkSecrets (checks/secrets.js):
// a file this pipeline will never commit/push (because the project's own
// .gitignore excludes it) poses no leak risk through this pipeline, so both
// checks exempt it the same way.
async function loadGitignorePatterns(root) {
  return loadIgnoreFilePatterns(root, '.gitignore');
}

// checks/igniteignore.js's counterpart — a project-root .igniteignore
// (same .gitignore syntax) that walkFiles above honors directly, so every
// check that discovers files via walkFiles skips these paths automatically
// with no per-check wiring.
async function loadIgniteIgnorePatterns(root) {
  return loadIgnoreFilePatterns(root, '.igniteignore');
}

module.exports = {
  SKIP_DIRS,
  SKIP_DIRS_REGEX,
  BINARY_EXTENSIONS,
  DOCKERFILE_NAME_RE,
  SECRET_SCAN_CODE_EXTS,
  looksBinary,
  buildSnippet,
  walkFiles,
  invalidateWalkCache,
  mapWithConcurrency,
  hashBuffer,
  relativeToRoot,
  isEnvTemplateFile,
  gitignorePatternToRegex,
  isGitignored,
  loadGitignorePatterns,
  loadIgniteIgnorePatterns,
};
