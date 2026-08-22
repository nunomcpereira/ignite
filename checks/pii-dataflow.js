'use strict';

/**
 * Sensitive data-flow (PII/GDPR) SAST via Bearer. Phase C of the server.js
 * module split (see /Users/nuno/.claude/plans/cuddly-roaming-pearl.md).
 *
 * @param {object} deps
 * @param {Function} deps.runTool - from lib/tool-runner.js's createToolRunner()
 * @param {object} deps.fsUtils - lib/fs-utils.js exports (buildSnippet)
 * @param {object} deps.config - { enabled }
 */
function createPiiDataFlowCheck({ runTool, fsUtils, config }) {
  const fsp = require('fs/promises');
  const path = require('path');
  const os = require('os');
  const { buildSnippet } = fsUtils;

  const BEARER_ENABLED = Boolean(config.enabled);

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
      const hasOrigin = await runTool('git', ['remote', 'get-url', 'origin'], root).then(() => true, () => false);
      if (!hasOrigin) {
        // Only fill in a fake origin + remote-tracking HEAD when there
        // wasn't a real one already — a genuine clone (the pre-push-hook/
        // dogfooding case, or a scheduled re-check's clone) already has an
        // accurate refs/remotes/origin/HEAD pointing at wherever origin's
        // default branch actually is. Overwriting it unconditionally here
        // (as this used to do) would silently reset that ref to match
        // current HEAD on every single scan, destroying the exact signal
        // resolveBearerDiffBase below depends on to tell "fresh upload,
        // nothing to diff against" apart from "real history, safe to diff".
        const { stdout: branch } = await runTool('git', ['symbolic-ref', '--short', 'HEAD'], root);
        const branchName = branch.trim() || 'main';
        await runTool('git', ['remote', 'add', 'origin', 'https://ignite.local/scratch.git'], root);
        await runTool('git', ['update-ref', `refs/remotes/origin/${branchName}`, `refs/heads/${branchName}`], root);
        await runTool('git', ['symbolic-ref', `refs/remotes/origin/HEAD`, `refs/remotes/origin/${branchName}`], root);
      }
    } catch (e) {
      log?.(`⚠ Could not fully stage a git context for bearer (non-blocking): ${e.message}`);
    }
  }

  // Bearer's own `--diff` mode re-analyzes only the files that changed
  // between a base commit and HEAD (verified empirically: ~34s full scan vs
  // ~2.5s for a single-file diff on this repo, with correct new-finding
  // detection) — a real ~13x speedup, but only safe when there's a genuine
  // "before" state to diff against. Diffing a commit against itself (the
  // single-commit repo ensureGitContextForBearer bootstraps for a fresh
  // ZIP/folder upload with no prior git history) silently returns *zero*
  // findings, not "everything", since nothing looks different from itself —
  // using --diff there would make Ignite blind to real PII in a brand-new
  // project. Only reach for --diff when a distinct ancestor commit exists
  // (the pre-push-hook/dogfooding case: local HEAD is genuinely ahead of
  // origin's default branch by the commit(s) being pushed) AND the working
  // tree is clean — bearer's --diff literally `git switch --detach`es
  // between the base and target commits inside the directory it scans, and
  // hard-refuses outright ("uncommitted changes found... commit or stash")
  // if there's anything uncommitted, which checkPiiDataFlow's outer
  // try/catch would otherwise turn into a silent zero-findings "scan",
  // not a fallback to the (slower but safe) full scan. Confirmed both
  // failure modes empirically before writing this guard.
  async function resolveBearerDiffBase(root) {
    try {
      const { stdout: statusOut } = await runTool('git', ['status', '--porcelain'], root);
      if (statusOut.trim()) return null; // dirty working tree — --diff would hard-error

      const { stdout: headOut } = await runTool('git', ['rev-parse', 'HEAD'], root);
      const head = headOut.trim();
      if (!head) return null;

      let base = '';
      try {
        const { stdout } = await runTool('git', ['symbolic-ref', '--quiet', 'refs/remotes/origin/HEAD'], root);
        base = stdout.trim().replace(/^refs\/remotes\//, '');
      } catch { /* origin/HEAD not set — try common default-branch names below */ }
      if (!base) {
        for (const candidate of ['origin/main', 'origin/master']) {
          try {
            await runTool('git', ['rev-parse', '--verify', '--quiet', candidate], root);
            base = candidate;
            break;
          } catch { /* try next candidate */ }
        }
      }
      if (!base) return null;

      const { stdout: baseShaOut } = await runTool('git', ['rev-parse', '--verify', '--quiet', base], root);
      const baseSha = baseShaOut.trim();
      if (!baseSha || baseSha === head) return null; // nothing to diff against

      await runTool('git', ['merge-base', '--is-ancestor', base, 'HEAD'], root); // throws if base isn't a real ancestor of HEAD
      return base;
    } catch {
      return null;
    }
  }

  const BEARER_SEVERITY_TO_ISSUE = { critical: 'error', high: 'error', medium: 'warning', low: 'warning', warning: 'warning' };
  const TEST_PATH_RE = /(^|\/)(tests?|__tests__|specs?|e2e|test-support)(\/|$)|[._-](test|spec)s?\.[^/.]+$/i;
  const DEV_SERVER_FILE_RE = /(?:^|\/)(?:serve-dev|serve-spa)\.mjs$/i;
  const FIREBASE_WEB_API_KEY_RE = /AIza[0-9A-Za-z_-]{20,}/;

  function isLikelyTestOrFixturePath(file) {
    return TEST_PATH_RE.test(String(file || '').replace(/\\/g, '/'));
  }

  function lineAt(content, line) {
    if (typeof content !== 'string') return '';
    const lines = content.split(/\r?\n/);
    return lines[line - 1] || '';
  }

  function isFirebasePublicApiKeyFinding(title, sourceLine, content) {
    if (!/usage of hard-coded secret/i.test(String(title || ''))) return false;
    const line = String(sourceLine || '');
    if (/apiKey/i.test(line) && FIREBASE_WEB_API_KEY_RE.test(line)) return true;
    return /apiKey/i.test(String(content || '')) && FIREBASE_WEB_API_KEY_RE.test(String(content || ''));
  }

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
    const diffBase = await resolveBearerDiffBase(root);
    const args = ['scan', root, '--format', 'json', '--quiet', '--disable-version-check', '--exit-code', '0'];
    if (diffBase) {
      args.push('--diff');
      log?.(`Engine: Bearer CLI (External) — incremental scan (--diff against ${diffBase}, only changed files re-analyzed)...`);
    } else {
      log?.('Engine: Bearer CLI (External) — tracing sensitive data flows (PII/GDPR)...');
    }
    try {
      const { stdout } = await runTool('bearer', args, root);
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
          const sourceLine = lineAt(content, line);
          // Firebase web apiKey values are public identifiers, not auth secrets.
          if (isFirebasePublicApiKeyFinding(title, sourceLine, content)) continue;
          const forcedWarning =
            BEARER_FORCE_WARNING_TITLES.some((re) => re.test(title))
            || (isLikelyTestOrFixturePath(relFile) && /hard-coded secret/i.test(title))
            || (DEV_SERVER_FILE_RE.test(relFile) && /missing secure http server configuration|usage of insecure http connection/i.test(title));
          // Bearer's own rules tag findings with cwe_ids (numeric CWE ids,
          // e.g. [359] for CWE-359 exposure of private info) — pass the
          // first through the same way Semgrep's rule metadata is above.
          const cweId = Array.isArray(e.cwe_ids) ? e.cwe_ids[0] : null;
          findings.push({
            file: relFile,
            line,
            kind: String(e.id || 'pii-dataflow').toLowerCase(),
            tool: 'bearer',
            severity: forcedWarning ? 'warning' : (BEARER_SEVERITY_TO_ISSUE[severity] || 'warning'),
            message: title,
            code: content ? buildSnippet(content, line) : null,
            cwe: cweId ? `CWE-${cweId}` : null,
          });
        }
      }
      return { findings, engine: 'bearer' };
    } catch (e) {
      log?.(`⚠ Bearer PII/data-flow scan failed: ${e.message}`);
      return { findings: [], engine: 'disabled' };
    }
  }

  return { checkPiiDataFlow, bearerTooling, ensureGitContextForBearer, resolveBearerDiffBase };
}

module.exports = { createPiiDataFlowCheck };
