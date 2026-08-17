'use strict';

/**
 * Builds every discovered Dockerfile and runs `trivy image` against the
 * result, catching OWASP A06 (known-vulnerable packages) baked into a base
 * image's OS/package layer — a gap checks/iac-security.js's `trivy config`
 * can't see, since that only lints the Dockerfile *source*, never what
 * actually ends up installed inside the image. Off by default (the one
 * Phase 4 check that needs a real image build, not just a static read).
 * Phase C of the server.js module split (see
 * /Users/nuno/.claude/plans/cuddly-roaming-pearl.md).
 *
 * @param {object} deps
 * @param {Function} deps.runTool - from lib/tool-runner.js's createToolRunner()
 * @param {Function} deps.runToolStreaming - from lib/tool-runner.js's createToolRunner()
 * @param {object} deps.fsUtils - lib/fs-utils.js exports (walkFiles, DOCKERFILE_NAME_RE)
 * @param {object} deps.config - { enabled, severityThreshold, buildTimeoutMs }
 */
function createContainerImageVulnerabilitiesCheck({ runTool, runToolStreaming, fsUtils, config }) {
  const fsp = require('fs/promises');
  const path = require('path');
  const os = require('os');
  const crypto = require('crypto');
  const { walkFiles, DOCKERFILE_NAME_RE } = fsUtils;

  const TRIVY_IMAGE_ENABLED = Boolean(config.enabled);
  const TRIVY_IMAGE_SEVERITY = String(config.severityThreshold || 'HIGH,CRITICAL');
  const TRIVY_IMAGE_BUILD_TIMEOUT_MS = Number(config.buildTimeoutMs) || 8 * 60_000;

  async function trivyImageTooling() {
    try {
      await runTool('trivy', ['--version'], os.tmpdir());
    } catch {
      return { ok: false, reason: '`trivy` is not installed (brew install trivy).' };
    }
    try {
      await runTool('docker', ['info', '--format', '{{.ServerVersion}}'], os.tmpdir());
    } catch {
      return { ok: false, reason: 'Docker daemon is not running (start Docker Desktop) — needed to build the image before scanning it.' };
    }
    return { ok: true };
  }

  // Never throws: any build/scan failure for one Dockerfile is logged and
  // skipped, so one bad Dockerfile doesn't block findings from the rest,
  // and the whole check soft-skips (returns no findings) rather than
  // failing the run if trivy/Docker aren't available.
  async function checkContainerImageVulnerabilities(root, log) {
    const tool = TRIVY_IMAGE_ENABLED ? await trivyImageTooling() : { ok: false, reason: 'trivyImage is disabled (security.trivyImage.enabled=false).' };
    if (!tool.ok) {
      log?.(`⚠ Container image CVE scan skipped: ${tool.reason}`);
      return { findings: [], engine: 'disabled' };
    }

    const dockerfiles = [];
    for await (const file of walkFiles(root)) {
      if (DOCKERFILE_NAME_RE.test(path.basename(file))) dockerfiles.push(file);
    }
    if (dockerfiles.length === 0) return { findings: [], engine: 'trivy-image' };

    log?.(`Engine: Trivy CLI (External) — building ${dockerfiles.length} Dockerfile(s) and scanning the resulting image(s) for known CVEs...`);
    const findings = [];
    for (const dockerfile of dockerfiles) {
      const relDockerfile = path.relative(root, dockerfile);
      const buildContext = path.dirname(dockerfile);
      const tag = `ignite-trivyscan-${crypto.randomBytes(6).toString('hex')}:latest`;
      const reportPath = path.join(os.tmpdir(), `ignite-trivy-image-${crypto.randomBytes(8).toString('hex')}.json`);
      let built = false;
      try {
        await runToolStreaming(
          'docker',
          ['build', '-f', dockerfile, '-t', tag, buildContext],
          root,
          (line) => log?.(line.slice(0, 400)),
          { timeoutMs: TRIVY_IMAGE_BUILD_TIMEOUT_MS }
        );
        built = true;
        await runTool('trivy', [
          'image', '--format', 'json', '--output', reportPath,
          '--severity', TRIVY_IMAGE_SEVERITY, '--exit-code', '0', '--quiet', tag,
        ], root);
        const raw = await fsp.readFile(reportPath, 'utf8').catch(() => '');
        const data = raw.trim() ? JSON.parse(raw) : {};
        const results = Array.isArray(data.Results) ? data.Results : [];
        for (const result of results) {
          const vulns = Array.isArray(result.Vulnerabilities) ? result.Vulnerabilities : [];
          for (const v of vulns) {
            findings.push({
              file: relDockerfile,
              line: 1,
              kind: String(v.VulnerabilityID || 'cve').toLowerCase(),
              tool: 'trivy-image',
              severity: String(v.Severity || 'MEDIUM').toLowerCase(),
              message: `${v.PkgName || 'package'}@${v.InstalledVersion || '?'}: ${v.Title || v.VulnerabilityID || 'known vulnerability'}${v.FixedVersion ? ` (fixed in ${v.FixedVersion})` : ''}`,
              code: null,
            });
          }
        }
      } catch (e) {
        log?.(`⚠ Container image CVE scan failed for ${relDockerfile}: ${e.message}`);
      } finally {
        await fsp.unlink(reportPath).catch(() => {});
        if (built) await runTool('docker', ['rmi', '-f', tag], root).catch(() => {});
      }
    }
    return { findings, engine: 'trivy-image' };
  }

  return { checkContainerImageVulnerabilities, trivyImageTooling };
}

module.exports = { createContainerImageVulnerabilitiesCheck };
