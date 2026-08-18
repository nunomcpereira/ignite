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
  // intraprocedural engine. Returns the step list for the flow that
  // touches the most distinct files (usually there's only one codeFlow per
  // result anyway) so Ignite Studio can render the actual chain — source
  // through however many intermediate files to sink — not just flag that
  // one exists. A finding with no multi-file flow (single-location
  // queries, or a taint path that never leaves one file) gets `null`, so
  // the UI/issue list can distinguish "only found by combining multiple
  // files" from "Semgrep could plausibly have caught this too."
  async function extractFlowChain(root, result) {
    let best = null;
    let bestFileCount = -1;
    for (const flow of result.codeFlows || []) {
      const steps = [];
      const filesSeen = new Set();
      for (const threadFlow of flow.threadFlows || []) {
        for (const loc of threadFlow.locations || []) {
          const pl = loc.location?.physicalLocation;
          const uri = pl?.artifactLocation?.uri;
          if (!uri) continue;
          steps.push({
            uri,
            line: Number(pl?.region?.startLine) || 1,
            message: loc.location?.message?.text || null,
          });
          filesSeen.add(uri);
        }
      }
      if (steps.length > 0 && filesSeen.size > bestFileCount) {
        bestFileCount = filesSeen.size;
        best = steps;
      }
    }
    if (!best) return null;

    // Resolve each step to a root-relative path (SARIF's uri is whatever
    // the extractor recorded, not necessarily already relative — same
    // canonicalization gotcha relativeToRoot exists for elsewhere in
    // Ignite), deduping consecutive steps that land on the exact same
    // file+line (a read immediately followed by a use of the same
    // variable at the same location is noise, not a real chain link).
    const resolved = [];
    for (const step of best) {
      const absPath = path.isAbsolute(step.uri) ? step.uri : path.join(root, step.uri);
      const relFile = await relativeToRoot(root, absPath);
      const prev = resolved[resolved.length - 1];
      if (prev && prev.file === relFile && prev.line === step.line) continue;
      resolved.push({ file: relFile, line: step.line, message: step.message });
    }
    return { steps: resolved, fileCount: bestFileCount };
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
        const flow = await extractFlowChain(root, result);
        findings.push({
          file: relFile,
          line,
          kind: String(result.ruleId || 'codeql-finding').toLowerCase(),
          tool: 'codeql',
          language,
          severity,
          message: result.message?.text || rule.shortDescription?.text || 'CodeQL finding',
          crossFile: Boolean(flow && flow.fileCount > 1),
          // Only worth carrying through (and rendering as a "chain" in
          // Studio) when it actually crosses >1 file *and* has more than
          // one step to show — a 1-step "flow" is just the finding's own
          // location again.
          chain: (flow && flow.fileCount > 1 && flow.steps.length > 1) ? flow.steps : null,
          cwe: extractCwe(rule),
        });
      }
    }
    return findings;
  }

  async function runOneLanguage(root, language, log, keepDbDir) {
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
      const createLines = [];
      try {
        await runToolStreaming('codeql', [
          'database', 'create', dbPath,
          `--language=${language}`, `--source-root=${root}`, '--overwrite',
          ...(CODEQL_THREADS ? [`--threads=${CODEQL_THREADS}`] : []),
          ...(CODEQL_RAM_MB ? [`--ram=${CODEQL_RAM_MB}`] : []),
        ], root, (line) => createLines.push(line), { timeoutMs: CODEQL_TIMEOUT_MS });
      } catch (e) {
        // lib/tool-runner.js's own failure-line heuristic (FAILURE_LINE_REGEX)
        // is tuned for `act`/CI-style output and misses CodeQL's own error
        // phrasing ("A fatal error occurred: ..." — no "fatal:" or "error:"
        // substring), so the last captured line is far more likely to be the
        // actually-useful detail than whatever extractFailureLines found.
        throw new Error(`${e.message} Last output: ${createLines.slice(-2).join(' | ') || '(none captured)'}`);
      }

      // Keep this database around (outside workDir, which the `finally`
      // below always wipes) so Studio's ad-hoc query runner
      // (runCustomCodeqlQuery) can query it later without a full rebuild —
      // this is the one distinguishing artifact of an actual `codeql
      // database create` that the SARIF findings alone don't preserve.
      // Best-effort: a failure here shouldn't fail the standing scan.
      if (keepDbDir) {
        try {
          await fsp.rm(keepDbDir, { recursive: true, force: true });
          await fsp.mkdir(path.dirname(keepDbDir), { recursive: true });
          await fsp.cp(dbPath, keepDbDir, { recursive: true });
        } catch (e) {
          log?.(`  ⚠ Could not persist the ${language} database for later ad-hoc querying: ${e.message}`);
        }
      }

      log?.(`  → analyzing ${language} database (${suite})...`);
      const analyzeLines = [];
      try {
        // --download: the CLI bundle ships no query packs of its own (see
        // https://github.com/github/codeql-cli-binaries) — codeql/*-queries
        // is fetched from GitHub's package registry on first use per
        // machine, then cached under ~/.codeql/packages for every run
        // after. Confirmed for real: analyze fails outright with exit code
        // 2 ("Query pack ... cannot be found") without this flag on a
        // machine that has never run a query pack before.
        await runToolStreaming('codeql', [
          'database', 'analyze', dbPath, suite, '--download',
          '--format=sarif-latest', `--output=${sarifPath}`,
          ...(CODEQL_THREADS ? [`--threads=${CODEQL_THREADS}`] : []),
        ], root, (line) => analyzeLines.push(line), { timeoutMs: CODEQL_TIMEOUT_MS });
      } catch (e) {
        throw new Error(`${e.message} Last output: ${analyzeLines.slice(-2).join(' | ') || '(none captured)'}`);
      }

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
   * @param {{ org?: string|null, repo?: string|null, keepDbDir?: string|null }} [ctx] -
   *   org/repo identify the target repo for the per-language findings
   *   cache (a missing org/repo just means every language always rebuilds
   *   — no cache hit, no cache write, not an error). keepDbDir, if given,
   *   is a directory each freshly-built language database is copied into
   *   (as keepDbDir/<language>/db) for runCustomCodeqlQuery to reuse later
   *   — not touched on a cache hit, since the file set (and therefore the
   *   database that would be rebuilt) hasn't changed either.
   */
  async function checkCodeqlCrossFile(root, log, ctx = {}) {
    const { org = null, repo = null, keepDbDir = null } = ctx;
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
          langFindings = await runOneLanguage(root, language, log, keepDbDir ? path.join(keepDbDir, language, 'db') : null);
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

  // `codeql bqrs decode --format=json --entities=all` is the only decode
  // mode that actually carries source locations for entity-typed columns
  // (a bare `select someEntity, "message"` — no .getLocation() needed in
  // the query itself) — verified against the real CLI (2.26.3): plain
  // --format=csv/json render entities as a truncated display `label` only,
  // dropping the url entirely; --entities=all adds
  // `{id, label, url: {uri, startLine, startColumn, endLine, endColumn}}`
  // per entity cell. Non-entity columns (string/number/boolean) come
  // through as bare JSON values, not objects.
  async function parseQueryResultJson(root, json) {
    const select = json['#select'];
    if (!select) return { columns: [], rows: [] };
    const columns = (select.columns || []).map((c, i) => c.name || `col${i + 1}`);
    const rows = [];
    for (const tuple of select.tuples || []) {
      const cells = [];
      let location = null;
      for (const cell of tuple) {
        if (cell && typeof cell === 'object' && 'label' in cell) {
          cells.push(cell.label);
          // First entity cell whose location resolves inside this project
          // (CodeQL library/stdlib stub locations point outside root
          // entirely — e.g. its own bundled externs — and aren't useful
          // to jump to in Studio's file tree).
          if (!location && cell.url?.uri?.startsWith('file://')) {
            const absPath = decodeURIComponent(cell.url.uri.replace('file://', ''));
            if (absPath.startsWith(path.resolve(root) + path.sep)) {
              location = { file: await relativeToRoot(root, absPath), line: Number(cell.url.startLine) || 1 };
            }
          }
        } else {
          cells.push(cell === null || cell === undefined ? '' : String(cell));
        }
      }
      rows.push({ cells, location });
    }
    return { columns, rows };
  }

  /**
   * Runs a user-supplied ad-hoc .ql query against an already-built CodeQL
   * database (see runOneLanguage's keepDbDir) — no findings-cache, no
   * issue persistence, purely exploratory. Scaffolds a throwaway qlpack
   * (a single query file can't compile on its own — it needs a qlpack.yml
   * declaring the language's standard library as a dependency) and shells
   * out to `codeql query run` + `codeql bqrs decode`.
   *
   * @param {{ root: string, dbDir: string, language: string, queryText: string, log?: Function }} args
   * @returns {Promise<{ columns: string[], rows: Array<{cells: string[], location: {file,line}|null}> }>}
   */
  async function runCustomCodeqlQuery({ root, dbDir, language, queryText, log }) {
    const dbStat = await fsp.stat(dbDir).catch(() => null);
    if (!dbStat) {
      throw new Error(`No CodeQL database found for "${language}" — click "Run CodeQL" first to build one.`);
    }
    const workDir = await fsp.mkdtemp(path.join(os.tmpdir(), `ignite-codeql-query-${language}-`));
    const packDir = path.join(workDir, 'pack');
    const queryFile = path.join(packDir, 'query.ql');
    const bqrsPath = path.join(workDir, 'results.bqrs');
    const jsonPath = path.join(workDir, 'results.json');
    try {
      await fsp.mkdir(packDir, { recursive: true });
      await fsp.writeFile(
        path.join(packDir, 'qlpack.yml'),
        `name: ignite/ad-hoc-query\nversion: 0.0.0\ndependencies:\n  codeql/${language}-all: "*"\n`
      );
      await fsp.writeFile(queryFile, queryText);

      log?.(`  → resolving query pack dependencies for ${language}...`);
      const installLines = [];
      try {
        await runToolStreaming('codeql', ['pack', 'install', packDir], packDir, (l) => installLines.push(l), { timeoutMs: 5 * 60_000 });
      } catch (e) {
        throw new Error(`${e.message} Last output: ${installLines.slice(-2).join(' | ') || '(none captured)'}`);
      }

      log?.(`  → running query against the ${language} database...`);
      const runLines = [];
      try {
        await runToolStreaming('codeql', [
          'query', 'run', queryFile, `--database=${dbDir}`, `--output=${bqrsPath}`,
        ], packDir, (l) => runLines.push(l), { timeoutMs: CODEQL_TIMEOUT_MS });
      } catch (e) {
        throw new Error(`${e.message} Last output: ${runLines.slice(-2).join(' | ') || '(none captured)'}`);
      }

      await runTool('codeql', ['bqrs', 'decode', '--format=json', '--entities=all', `--output=${jsonPath}`, bqrsPath], packDir);
      const json = JSON.parse(await fsp.readFile(jsonPath, 'utf8'));
      return await parseQueryResultJson(root, json);
    } finally {
      await fsp.rm(workDir, { recursive: true, force: true });
    }
  }

  return { checkCodeqlCrossFile, codeqlTooling, discoverCodeqlLanguages, runCustomCodeqlQuery };
}

module.exports = { createCodeqlCrossFileCheck };
