'use strict';

/**
 * Malicious ML model artifact scan via picklescan
 * (https://github.com/mmaitre314/picklescan). Python's `pickle` format
 * executes arbitrary code on load (`__reduce__`), and it's the on-disk
 * format underneath a wide swath of what "AI-generated code" actually
 * commits: raw `.pkl`/`.pickle` dumps, PyTorch `.pt`/`.pth`/`.bin`
 * checkpoints (a zip archive of pickles), and framework checkpoint files
 * (`.ckpt`). None of Ignite's other scanners open these — Semgrep/CodeQL
 * read source text, Bearer/GuardDog read manifests/source — so a poisoned
 * weight file an AI agent downloaded or committed sails through untouched
 * without this. Deliberately scoped to pickle-based formats only:
 * `.safetensors` and `.onnx` are NOT pickle-based (safetensors is a fixed
 * binary layout with no code execution path; ONNX is protobuf) and are
 * out of scope for this tool by design, not an oversight.
 *
 * @param {object} deps
 * @param {Function} deps.runTool - from lib/tool-runner.js's createToolRunner()
 * @param {object} deps.fsUtils - lib/fs-utils.js exports (walkFiles, relativeToRoot)
 * @param {object} deps.config - { enabled, extensions? }
 */
function createModelArtifactSecurityCheck({ runTool, fsUtils, config }) {
  const path = require('path');
  const os = require('os');
  const { walkFiles, relativeToRoot } = fsUtils;

  const PICKLESCAN_ENABLED = Boolean(config.enabled);
  const MODEL_ARTIFACT_EXTENSIONS = new Set(
    (Array.isArray(config.extensions) && config.extensions.length > 0
      ? config.extensions
      : ['.pkl', '.pickle', '.pt', '.pth', '.ckpt', '.bin']
    ).map((e) => String(e).toLowerCase())
  );

  // picklescan has no --version flag (checked against its README) — probe
  // with --help instead, same "does it run at all" signal every other
  // tooling probe in Ignite is really after.
  async function picklescanTooling() {
    try {
      await runTool('picklescan', ['--help'], os.tmpdir());
      return { ok: true, version: null };
    } catch {
      return { ok: false, reason: '`picklescan` is not installed (pip install picklescan) — malicious model-artifact scanning is skipped.' };
    }
  }

  async function discoverModelArtifacts(root) {
    const files = [];
    for await (const file of walkFiles(root)) {
      if (MODEL_ARTIFACT_EXTENSIONS.has(path.extname(file).toLowerCase())) files.push(file);
    }
    return files;
  }

  // picklescan prints one line per dangerous import, in the shape:
  //   <path>[:<archive-member>]: global import '<module> <name>' FOUND
  // then a "----------- SCAN SUMMARY -----------" footer. No JSON output
  // mode exists (as of the version this was written against), so this
  // parses the plain-text finding lines directly rather than the summary.
  const FINDING_LINE_RE = /^(.+?): global import '([^']+)' FOUND$/;

  async function parsePicklescanOutput(root, stdout) {
    const findings = [];
    for (const line of stdout.split('\n')) {
      const m = FINDING_LINE_RE.exec(line.trim());
      if (!m) continue;
      const [, location, globalImport] = m;
      // location is "<fs-path>" or "<fs-path>:<archive-member>" (the latter
      // for a zip-backed .bin/.pt checkpoint) — only the first segment is a
      // real filesystem path relativeToRoot can resolve; the rest, if any,
      // is kept in the message for context.
      const [fsPath, ...archiveParts] = location.split(':');
      const archiveMember = archiveParts.join(':');
      const relFile = await relativeToRoot(root, fsPath);
      findings.push({
        file: relFile,
        line: null,
        kind: 'malicious-model-artifact',
        tool: 'picklescan',
        severity: 'error',
        message: `Dangerous pickle global import '${globalImport}' FOUND${archiveMember ? ` (in ${archiveMember})` : ''} — code executes on load.`,
      });
    }
    return findings;
  }

  // No built-in fallback: detecting an unsafe pickle global import needs
  // picklescan's real opcode-level pickle parser, not something a regex
  // heuristic over binary bytes could meaningfully approximate.
  async function checkModelArtifactSecurity(root, log) {
    const tooling = PICKLESCAN_ENABLED ? await picklescanTooling() : { ok: false, reason: 'picklescan is disabled (security.picklescan.enabled=false).' };
    if (!tooling.ok) {
      log?.(`⚠ picklescan model-artifact scan skipped: ${tooling.reason}`);
      return { findings: [], engine: 'disabled' };
    }

    const artifacts = await discoverModelArtifacts(root);
    if (artifacts.length === 0) return { findings: [], engine: 'picklescan' };

    log?.(`Engine: picklescan CLI (External) — scanning ${artifacts.length} model artifact(s) for unsafe pickle payloads...`);
    try {
      const { stdout } = await runTool('picklescan', ['--path', root], root, { allowedExitCodes: [0, 1] });
      const findings = await parsePicklescanOutput(root, stdout);
      return { findings, engine: 'picklescan' };
    } catch (e) {
      log?.(`⚠ picklescan model-artifact scan failed: ${e.message}`);
      return { findings: [], engine: 'disabled' };
    }
  }

  return { checkModelArtifactSecurity, picklescanTooling, discoverModelArtifacts };
}

module.exports = { createModelArtifactSecurityCheck };
