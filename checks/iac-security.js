'use strict';

/**
 * IaC/container misconfiguration scan (Dockerfiles, Terraform, Kubernetes
 * manifests, Helm charts) via Trivy (primary) + Checkov + Hadolint,
 * running concurrently (see the checkIacSecurity comment below for why).
 * Phase C of the server.js module split (see
 * /Users/nuno/.claude/plans/cuddly-roaming-pearl.md).
 *
 * @param {object} deps
 * @param {Function} deps.runTool - from lib/tool-runner.js's createToolRunner()
 * @param {object} deps.fsUtils - lib/fs-utils.js exports (walkFiles, looksBinary, buildSnippet, DOCKERFILE_NAME_RE)
 * @param {object} deps.config - { trivyEnabled, checkovEnabled, hadolintEnabled }
 */
function createIacSecurityCheck({ runTool, fsUtils, config }) {
  const fsp = require('fs/promises');
  const path = require('path');
  const os = require('os');
  const crypto = require('crypto');
  const { walkFiles, looksBinary, buildSnippet, DOCKERFILE_NAME_RE } = fsUtils;

  const TRIVY_ENABLED = Boolean(config.trivyEnabled);
  const CHECKOV_ENABLED = Boolean(config.checkovEnabled);
  const HADOLINT_ENABLED = Boolean(config.hadolintEnabled);

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

  async function hadolintTooling() {
    try {
      await runTool('hadolint', ['--version'], os.tmpdir());
      return { ok: true };
    } catch {
      return { ok: false, reason: '`hadolint` is not installed (brew install hadolint) — its supplemental findings are simply omitted.' };
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

  // Trivy (primary), Checkov, and Hadolint each scan the same static tree
  // completely independently — nothing one produces feeds another, so
  // running them one after another (as this used to) only adds their
  // wall-clock times together for no reason. All three run concurrently;
  // the dedup below is order-independent (a Set rebuilt fresh each merge
  // step), so results are identical to the old sequential version — only
  // faster, never different. Tooling probes are launched up front too,
  // for the same reason.
  async function checkIacSecurity(root, log) {
    const [trivyTool, checkovTool, hadolintTool] = await Promise.all([
      TRIVY_ENABLED ? trivyTooling() : Promise.resolve({ ok: false, reason: 'trivy is disabled (security.trivy.enabled=false).' }),
      CHECKOV_ENABLED ? checkovTooling() : Promise.resolve(null),
      HADOLINT_ENABLED ? hadolintTooling() : Promise.resolve(null),
    ]);

    const trivyPromise = (async () => {
      if (!trivyTool.ok) {
        log?.(`⚠ Trivy IaC scan skipped: ${trivyTool.reason}`);
        return { findings: await checkIacSecurityFallback(root), engine: 'fallback' };
      }
      log?.('Engine: Trivy CLI (External) — scanning Dockerfiles/Terraform/Kubernetes/Helm for misconfigurations...');
      const trivyFindings = await runTrivyIacScan(root, log);
      if (trivyFindings === null) {
        log?.('⚠ Falling back to the built-in Dockerfile heuristic scan.');
        return { findings: await checkIacSecurityFallback(root), engine: 'fallback' };
      }
      return { findings: trivyFindings, engine: 'trivy' };
    })();

    const checkovPromise = CHECKOV_ENABLED ? (async () => {
      if (!checkovTool.ok) {
        log?.(`⚠ Checkov supplemental scan skipped: ${checkovTool.reason}`);
        return null;
      }
      log?.('Engine: Checkov CLI (External) — supplementing with additional IaC policy checks...');
      return runCheckovIacScan(root, log);
    })() : Promise.resolve(null);

    const hadolintPromise = HADOLINT_ENABLED ? (async () => {
      if (!hadolintTool.ok) {
        log?.(`⚠ Hadolint supplemental scan skipped: ${hadolintTool.reason}`);
        return null;
      }
      log?.('Engine: Hadolint CLI (External) — supplementing with Dockerfile-specific lint checks...');
      return runHadolintIacScan(root, log);
    })() : Promise.resolve(null);

    const [{ findings: baseFindings, engine: baseEngine }, checkovFindings, hadolintFindings] =
      await Promise.all([trivyPromise, checkovPromise, hadolintPromise]);

    let findings = baseFindings;
    let engine = baseEngine;

    // Deduped on file+line+rule-id, not just file+line: trivy/checkov/
    // hadolint draw from different rule catalogs and routinely flag
    // *different* real issues on the same line (e.g. a Dockerfile's FROM
    // line triggers both an unpinned-tag and a root-user rule) — collapsing
    // on line alone would silently drop distinct findings. This only catches
    // true repeats (same tool-neutral rule surfacing twice), which in
    // practice is rare across different scanners. Checkov is merged before
    // hadolint (fixed order, independent of which subprocess actually
    // finished first) so `engine`'s suffix ordering matches the old
    // sequential version exactly.
    if (checkovFindings) {
      const seen = new Set(findings.map((f) => `${f.file}:${f.line}:${f.kind}`));
      findings = [...findings, ...checkovFindings.filter((f) => !seen.has(`${f.file}:${f.line}:${f.kind}`))];
      engine = `${engine}+checkov`;
    }
    if (hadolintFindings) {
      const seen = new Set(findings.map((f) => `${f.file}:${f.line}:${f.kind}`));
      findings = [...findings, ...hadolintFindings.filter((f) => !seen.has(`${f.file}:${f.line}:${f.kind}`))];
      engine = `${engine}+hadolint`;
    }

    return { findings, engine };
  }

  return {
    checkIacSecurity, checkIacSecurityFallback, runTrivyIacScan, runCheckovIacScan, runHadolintIacScan,
    trivyTooling, checkovTooling, hadolintTooling,
  };
}

module.exports = { createIacSecurityCheck };
