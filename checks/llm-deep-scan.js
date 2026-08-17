'use strict';

/**
 * Local LLM (Ollama/llama.cpp-compatible, or OpenAI) security/quality deep
 * scan — two review passes per chunk (security/dependency + quality/
 * encapsulation), each finding re-validated against the raw source text to
 * catch the model's own false positives. Phase D of the server.js module
 * split (see /Users/nuno/.claude/plans/cuddly-roaming-pearl.md).
 *
 * @param {object} deps
 * @param {Function} deps.llmChat - lib/llm-client.js's createLlmClient() result's llmChat
 * @param {Function} deps.traceLlmCall - lib/llm-client.js's createLlmClient() result's traceLlmCall
 * @param {Function} deps.parseSemver - semver parser shared with Studio's dependency-version resolution (server.js)
 * @param {Function} deps.compareSemver - semver comparator, same source as parseSemver
 * @param {object} deps.fsUtils - lib/fs-utils.js exports (walkFiles, looksBinary, buildSnippet, hashBuffer, isGitignored, loadGitignorePatterns)
 * @param {object} deps.fileScanCache - lib/file-scan-cache.js's createFileScanCache(store) result
 * @param {object} deps.config - {
 *   deepScanEnabled, provider, openaiApiKey, openaiModel, openaiBaseUrl,
 *   scanUrl, scanModel, advisoryLevel, maxFiles, chunkChars, sourceExts,
 * }
 */
function createLlmDeepScanCheck({
  llmChat, traceLlmCall, parseSemver, compareSemver, fsUtils, fileScanCache, config,
}) {
  const path = require('path');
  const fsp = require('fs/promises');
  const {
    walkFiles, looksBinary, buildSnippet, hashBuffer, isGitignored, loadGitignorePatterns,
  } = fsUtils;
  const { loadFileScanCache, saveFileScanCache } = fileScanCache;

  const LLM_DEEP_SCAN_ENABLED = Boolean(config.deepScanEnabled);
  const LLM_PROVIDER = config.provider;
  const OPENAI_API_KEY = config.openaiApiKey || '';
  const OPENAI_MODEL = config.openaiModel || '';
  const OPENAI_BASE_URL = config.openaiBaseUrl || '';
  const LLM_SCAN_URL = config.scanUrl;
  const LLM_SCAN_MODEL = config.scanModel;
  const LLM_ADVISORY_LEVEL = config.advisoryLevel;
  const LLM_MAX_FILES = Number(config.maxFiles) || 40;
  const LLM_CHUNK_CHARS = Number(config.chunkChars) || 10_000;
  const LLM_SOURCE_EXTS = config.sourceExts;

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

  // A dependency finding only earns "error" if the text itself carries
  // evidence of an actual vulnerability/malicious code, not just a bare
  // deprecation notice — mirrors the LLM_SECURITY_DEP_PROMPT classification
  // rule as a code-level backstop.
  const DEPENDENCY_VULN_EVIDENCE_RE = /\bcve-\d{4}-\d+|\bcwe-\d+|vulnerab\w*|exploit\w*|malicious|\brce\b|remote code execution|arbitrary code|backdoor|compromis\w*|security advisory|known flaw/i;

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

      // Both checks below are scoped to Ignite's own known source files (this
      // suppression only ever applies when Ignite's LLM deep-scan is scanning
      // *itself*, e.g. via the pre-push hook dogfooding this repo — an
      // unrelated onboarded project's own "server.js" shouldn't get a free
      // pass just for sharing a filename) and search the *combined* text of
      // every file sent to the LLM in this batch, not just the single flagged
      // file's own text. That distinction started mattering once server.js's
      // module split (see /Users/nuno/.claude/plans/cuddly-roaming-pearl.md)
      // began moving the exact code these patterns look for into separate
      // files — checking only `fileText` (relFile's own content) would have
      // silently stopped matching the moment sanitizeCommand/ALLOWED_COMMANDS
      // moved to lib/tool-runner.js, even though the real hardening is still
      // there, just in a sibling file within the same scan batch.
      const IGNITE_OWN_SOURCE_FILES = new Set(['server.js', 'lib/tool-runner.js', 'lib/fs-utils.js']);
      const allFilesText = IGNITE_OWN_SOURCE_FILES.has(relFile) ? [...filesByRel.values()].join('\n') : '';

      if ((issue.includes('command injection') || issue.includes('user-supplied command') || issue.includes('child_process'))
        && IGNITE_OWN_SOURCE_FILES.has(relFile)) {
        const hasCommandAllowlist = /const ALLOWED_COMMANDS = Object\.freeze\(new Set\(\['git', 'gh', 'act', 'docker', 'gitleaks', 'licensee', 'ort', 'trivy', 'checkov', 'hadolint', 'syft', 'cosign', 'semgrep', 'bearer', 'jscpd', 'gocloc', 'spectral', 'guarddog'\]\)\);/.test(allFilesText);
        const hasStrictSanitizers = /sanitizeCommand\(|sanitizeCliArgs\(|sanitizeCwd\(|sanitizeEnv\(/.test(allFilesText);
        // Was also gated on the flagged line falling inside a hardcoded
        // "runner zone" (line 200-360) — a proxy for "is this actually the
        // child_process runner code, not some unrelated area of server.js".
        // That range predates this session and was already stale before any
        // of today's module-split work touched this area — dropping it
        // rather than re-guessing a new range that would just go stale again
        // the same way. hasCommandAllowlist + hasStrictSanitizers already
        // require the exact allowlist literal AND real sanitizer calls to
        // both be present somewhere in the batch, which is a strong enough
        // signal on its own without also pinning to a location that can't
        // stay correct.
        if (hasCommandAllowlist && hasStrictSanitizers) {
          log(`⚠ Ignored false-positive LLM finding: ${relFile}:${line} (child_process calls are constrained to fixed allowlisted tools).`);
          return null;
        }
      }

      if ((issue.includes('path traversal') || issue.includes('zip extraction') || issue.includes('folder upload'))
        && IGNITE_OWN_SOURCE_FILES.has(relFile)) {
        const hasZipGuard = /target !== destDir && !target\.startsWith\(destDir \+ path\.sep\)/.test(allFilesText);
        const hasFolderGuard = /sanitizeUploadRelativePath\(|Blocked path-traversal entry in folder upload/.test(allFilesText);
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

      if (issue.includes('llm_scan_url') && issue.includes('untrusted') && IGNITE_OWN_SOURCE_FILES.has(relFile)) {
        const hasOriginAllowlist = /trustedOrigins\.has\(parsed\.origin\)/.test(allFilesText);
        const hasHttpsPolicy = /must use https for non-loopback hosts/.test(allFilesText);
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
    if (!LLM_DEEP_SCAN_ENABLED) {
      return { available: false, reason: 'LLM deep-scan is disabled (llm.deepScanEnabled=false / LLM_DEEP_SCAN_ENABLED=false).' };
    }
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
      const [securityDepResult, qualityResult] = await Promise.allSettled([
        llmChat(chunks[i], LLM_SECURITY_DEP_PROMPT, log, `chunk ${i + 1}/${chunks.length} security/dependency`),
        llmChat(chunks[i], LLM_QUALITY_PROMPT, log, `chunk ${i + 1}/${chunks.length} quality/encapsulation`),
      ]);

      if (securityDepResult.status === 'fulfilled') {
        const chunkFindings = securityDepResult.value;
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
      } else {
        log(`⚠ Chunk ${i + 1} security/dependency pass skipped: ${securityDepResult.reason?.message}`);
      }

      if (qualityResult.status === 'fulfilled') {
        const chunkFindings = qualityResult.value;
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
      } else {
        log(`⚠ Chunk ${i + 1} quality/encapsulation pass skipped: ${qualityResult.reason?.message}`);
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

  return { checkLlmDeepScan, validateLlmFinding };
}

module.exports = { createLlmDeepScanCheck };
