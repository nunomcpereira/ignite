'use strict';

/**
 * Cross-file static analysis via the CodeQL CLI — the one Phase-4 tool able
 * to trace a vulnerability across file/function boundaries (see the
 * IMPORTANT LIMITATION note on CONFIG.security.semgrep: Semgrep OSS's
 * taint engine is intraprocedural/single-file, so a stored-XSS or IDOR
 * chain spanning a controller, a service layer, and a template sails
 * through it untouched).
 *
 * Deliberately NOT part of runPhase4Checks (server.js) — a CodeQL database
 * build is whole-project and can take minutes per language, which would
 * blow up the fast interactive push-time pipeline every other Phase 4 check
 * is tuned for. This check is only invoked from Ignite's deep-scan path
 * (scheduled runs on already-onboarded repos, or a pre-push gate for a
 * brand-new repo) — see routes/pipeline-deep-scan.js.
 *
 * @param {object} deps
 * @param {Function} deps.runTool - from lib/tool-runner.js's createToolRunner() (used for `codeql version`)
 * @param {Function} deps.runToolStreaming - from lib/tool-runner.js's createToolRunner() (used for the slow `database create`/`database analyze` calls)
 * @param {object} deps.store - db-store.js instance (codeql scan cache)
 * @param {object} deps.fsUtils - lib/fs-utils.js exports (walkFiles, hashBuffer, relativeToRoot)
 * @param {object} deps.config - { enabled, binary, languages, querySuites, threads, ramMB, timeoutMs }
 */
function createCodeqlCrossFileCheck({ runTool, runToolStreaming, store, fsUtils, config }) {
  const fsp = require('fs/promises');
  const path = require('path');
  const os = require('os');
  const crypto = require('crypto');
  const { walkFiles, hashBuffer, relativeToRoot } = fsUtils;

  const CODEQL_ENABLED = Boolean(config.enabled);
  const CODEQL_LANGUAGES = Array.isArray(config.languages) && config.languages.length
    ? config.languages
    : ['javascript', 'python', 'java', 'go'];
  const CODEQL_QUERY_SUITES = config.querySuites || {};
  const CODEQL_THREADS = Number(config.threads) || 0; // 0 = codeql's own default (all cores)
  const CODEQL_RAM_MB = Number(config.ramMB) || 0; // 0 = codeql's own default
  const CODEQL_TIMEOUT_MS = Number(config.timeoutMs) || 20 * 60_000;

  async function codeqlTooling() {
    try {
      const { stdout } = await runTool('codeql', ['version', '--format=json'], os.tmpdir());
      const info = JSON.parse(stdout);
      return { ok: true, version: info.version || null };
    } catch {
      return {
        ok: false,
        reason: '`codeql` CLI is not installed (https://github.com/github/codeql-cli-binaries) — cross-file static analysis (deep scan) is skipped.',
      };
    }
  }

  // Extension → CodeQL language id. Only the languages Ignite ships a query
  // suite for by default (see CONFIG.security.codeql.languages) matter here
  // — a project in an unmapped language simply contributes no CodeQL
  // findings, same per-language soft-skip behavior the rest of Phase 4 uses.
  const EXT_TO_LANGUAGE = {
    '.js': 'javascript', '.jsx': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
    '.ts': 'javascript', '.tsx': 'javascript', // CodeQL's "javascript" extractor also covers TypeScript
    '.py': 'python',
    '.java': 'java',
    '.go': 'go',
  };

  async function discoverCodeqlLanguages(root) {
    const present = new Set();
    for await (const file of walkFiles(root)) {
      const lang = EXT_TO_LANGUAGE[path.extname(file).toLowerCase()];
      if (lang && CODEQL_LANGUAGES.includes(lang)) present.add(lang);
    }
    return [...present].sort();
  }

  // Deterministic hash over every source file CodeQL would extract for a
  // given language (relative path + content hash, sorted) — the cache key
  // for skipping a full database rebuild+analyze when nothing in that
  // language's file set has changed since a prior deep scan of this
  // (org, repo). Mirrors manifest_scan_cache's content-hash approach
  // (checks/malicious-dependencies.js) but aggregated project-wide instead
  // of per-manifest, since a CodeQL database is a whole-project artifact,
  // not a per-file one.
  async function hashFileSet(root, language) {
    const entries = [];
    for await (const file of walkFiles(root)) {
      const lang = EXT_TO_LANGUAGE[path.extname(file).toLowerCase()];
      if (lang !== language) continue;
      const rel = path.relative(root, file);
      const contentHash = hashBuffer(await fsp.readFile(file));
      entries.push(`${rel}:${contentHash}`);
    }
    entries.sort();
    return crypto.createHash('sha256').update(entries.join('\n')).digest('hex');
  }

  // SARIF's codeFlows/threadFlows record every step of a tainted-data path.
  // When the distinct files touched by any single flow's steps number more
  // than one, the finding only exists because CodeQL correlated multiple
  // files — the entire reason this check exists on top of Semgrep's
  // intraprocedural engine. A finding with no multi-file flow (single-
  // location queries, or a taint path that never leaves one file) is still
  // reported — just tagged crossFile:false so the UI/issue list can
  // distinguish "only found by combining multiple files" from "Semgrep
  // could plausibly have caught this too."
  function isCrossFileResult(result) {
    for (const flow of result.codeFlows || []) {
      const files = new Set();
      for (const threadFlow of flow.threadFlows || []) {
        for (const loc of threadFlow.locations || []) {
          const uri = loc.location?.physicalLocation?.artifactLocation?.uri;
          if (uri) files.add(uri);
        }
      }
      if (files.size > 1) return true;
    }
    return false;
  }

  function extractCwe(rule) {
    const tags = Array.isArray(rule?.properties?.tags) ? rule.properties.tags : [];
    for (const tag of tags) {
      const m = String(tag).match(/^external\/cwe\/cwe-(\d+)/i);
      if (m) return `CWE-${m[1]}`;
    }
    return null;
  }

  async function parseSarif(root, sarifPath, language) {
    const raw = await fsp.readFile(sarifPath, 'utf8');
    const sarif = JSON.parse(raw);
    const findings = [];
    for (const run of sarif.runs || []) {
      const rules = new Map();
      for (const rule of run.tool?.driver?.rules || []) rules.set(rule.id, rule);
      for (const result of run.results || []) {
        const rule = rules.get(result.ruleId) || {};
        const loc = result.locations?.[0]?.physicalLocation;
        const uri = loc?.artifactLocation?.uri;
        if (!uri) continue;
        const absPath = path.isAbsolute(uri) ? uri : path.join(root, uri);
        const relFile = await relativeToRoot(root, absPath);
        const line = Number(loc?.region?.startLine) || 1;
        const level = String(result.level || rule.defaultConfiguration?.level || 'warning').toLowerCase();
        const securitySeverity = Number(rule.properties?.['security-severity']);
        const severity = level === 'error' || (Number.isFinite(securitySeverity) && securitySeverity >= 7)
          ? 'error'
          : 'warning';
        findings.push({
          file: relFile,
          line,
          kind: String(result.ruleId || 'codeql-finding').toLowerCase(),
          tool: 'codeql',
          language,
          severity,
          message: result.message?.text || rule.shortDescription?.text || 'CodeQL finding',
          crossFile: isCrossFileResult(result),
          cwe: extractCwe(rule),
        });
      }
    }
    return findings;
  }

  async function runOneLanguage(root, language, log) {
    const suite = CODEQL_QUERY_SUITES[language];
    if (!suite) {
      log?.(`⚠ No CodeQL query suite configured for "${language}" (security.codeql.querySuites) — skipped.`);
      return [];
    }
    const workDir = await fsp.mkdtemp(path.join(os.tmpdir(), `ignite-codeql-${language}-`));
    const dbPath = path.join(workDir, 'db');
    const sarifPath = path.join(workDir, 'results.sarif');
    try {
      log?.(`  → building CodeQL database for ${language}...`);
      await runToolStreaming('codeql', [
        'database', 'create', dbPath,
        `--language=${language}`, `--source-root=${root}`, '--overwrite',
        ...(CODEQL_THREADS ? [`--threads=${CODEQL_THREADS}`] : []),
        ...(CODEQL_RAM_MB ? [`--ram=${CODEQL_RAM_MB}`] : []),
      ], root, () => {}, { timeoutMs: CODEQL_TIMEOUT_MS });

      log?.(`  → analyzing ${language} database (${suite})...`);
      await runToolStreaming('codeql', [
        'database', 'analyze', dbPath, suite,
        '--format=sarif-latest', `--output=${sarifPath}`,
        ...(CODEQL_THREADS ? [`--threads=${CODEQL_THREADS}`] : []),
      ], root, () => {}, { timeoutMs: CODEQL_TIMEOUT_MS });

      return await parseSarif(root, sarifPath, language);
    } finally {
      await fsp.rm(workDir, { recursive: true, force: true });
    }
  }

  /**
   * Cross-file static analysis via CodeQL, one database build+analyze per
   * language detected in the project.
   *
   * @param {string} root - staged project root
   * @param {Function} log
   * @param {{ org?: string|null, repo?: string|null }} [ctx] - identifies
   *   the target repo for the per-language findings cache. A missing
   *   org/repo (no known target yet) just means every language always
   *   rebuilds — no cache hit, no cache write, not an error.
   */
  async function checkCodeqlCrossFile(root, log, ctx = {}) {
    const { org = null, repo = null } = ctx;
    const tooling = CODEQL_ENABLED ? await codeqlTooling() : { ok: false, reason: 'codeql is disabled (security.codeql.enabled=false).' };
    if (!tooling.ok) {
      log?.(`⚠ CodeQL cross-file scan skipped: ${tooling.reason}`);
      return { findings: [], engine: 'disabled', languages: [] };
    }

    const languages = await discoverCodeqlLanguages(root);
    if (languages.length === 0) {
      return { findings: [], engine: 'codeql', languages: [] };
    }

    const findings = [];
    let cacheHits = 0;
    for (const language of languages) {
      const fileSetHash = await hashFileSet(root, language);
      const cached = (org && repo && tooling.version)
        ? store.getCodeqlScanCache(org, repo, language, fileSetHash, tooling.version)
        : null;

      let langFindings;
      if (cached) {
        langFindings = cached;
        cacheHits++;
        log?.(`  ♻ ${language}: unchanged since the last deep scan of ${org}/${repo} — reused cached CodeQL results.`);
      } else {
        try {
          langFindings = await runOneLanguage(root, language, log);
        } catch (e) {
          log?.(`⚠ CodeQL ${language} scan failed: ${e.message}`);
          continue;
        }
        if (org && repo && tooling.version) {
          store.saveCodeqlScanCache(org, repo, language, fileSetHash, tooling.version, langFindings);
        }
      }
      findings.push(...langFindings);
    }
    if (cacheHits > 0) {
      log?.(`♻ ${cacheHits}/${languages.length} language database(s) unchanged since the last deep scan — skipped a full CodeQL rebuild.`);
    }
    return { findings, engine: 'codeql', languages };
  }

  return { checkCodeqlCrossFile, codeqlTooling, discoverCodeqlLanguages };
}

module.exports = { createCodeqlCrossFileCheck };
