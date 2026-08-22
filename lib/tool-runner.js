'use strict';

const path = require('path');
const { execFile, spawn } = require('child_process');

/**
 * External-tool process execution + the sanitizers that guard it — every
 * `git`/`gh`/`trivy`/`semgrep`/etc. invocation across Ignite's checks goes
 * through here. Phase B of the server.js module split (see
 * /Users/nuno/.claude/plans/cuddly-roaming-pearl.md).
 *
 * Factory, not a bare module-level export: `createToolRunner(binaries)`
 * takes each tool's resolved binary path/name (server.js computes these
 * from CONFIG — see the `*_BINARY` constants) as a parameter rather than
 * reading CONFIG itself, so this module has no config-derived state of its
 * own to go stale across test/helpers.js's per-test re-require cycle.
 *
 * @param {object} binaries - { gitleaks, trivy, checkov, hadolint, syft,
 *   cosign, semgrep, bearer, guarddog, jscpd, gocloc, spectral, codeql } —
 *   each a binary name/path string. git/gh/act/docker aren't configurable,
 *   so they aren't parameters here.
 */
function createToolRunner(binaries) {
  const ALLOWED_COMMANDS = Object.freeze(new Set(['git', 'gh', 'act', 'docker', 'gitleaks', 'licensee', 'ort', 'trivy', 'checkov', 'hadolint', 'syft', 'cosign', 'semgrep', 'bearer', 'jscpd', 'gocloc', 'spectral', 'guarddog', 'codeql']));
  const SAFE_UPLOAD_SEGMENT_REGEX = /^[^\0/\\]+$/;

  function sanitizeCliArg(value, label) {
    const s = String(value ?? '');
    if (!s) throw new Error(`${label} cannot be empty.`);
    if (/\0|\r|\n/.test(s)) throw new Error(`${label} contains illegal control characters.`);
    return s;
  }

  function sanitizeCommand(cmd) {
    const safeCmd = sanitizeCliArg(cmd, 'Command');
    if (!ALLOWED_COMMANDS.has(safeCmd)) {
      throw new Error(`Command is not allowed: ${safeCmd}`);
    }
    return safeCmd;
  }

  function sanitizeCliArgs(args) {
    if (!Array.isArray(args)) throw new Error('Command arguments must be an array.');
    return args.map((arg, i) => sanitizeCliArg(arg, `Argument #${i + 1}`));
  }

  function sanitizeCwd(cwd) {
    const s = String(cwd ?? '').trim();
    if (!s) throw new Error('Working directory is required.');
    if (/\0|\r|\n/.test(s)) throw new Error('Working directory contains illegal control characters.');
    return s;
  }

  function sanitizeAbsoluteProjectPath(projectPath) {
    const safePath = sanitizeCwd(projectPath);
    if (!path.isAbsolute(safePath)) {
      throw new Error('projectPath must be an absolute path.');
    }
    return path.resolve(safePath);
  }

  function sanitizeEnv(env) {
    const sanitized = {};
    for (const [key, value] of Object.entries(env || {})) {
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;
      const str = String(value ?? '');
      if (/\0/.test(str)) continue;
      sanitized[key] = str;
    }
    return sanitized;
  }

  function sanitizeUploadRelativePath(rawPath) {
    const rel = String(rawPath ?? '').replace(/\\/g, '/').trim();
    if (!rel || rel.includes('\0')) {
      throw new Error(`Invalid path in folder upload: ${JSON.stringify(rawPath)}`);
    }
    if (rel.startsWith('/') || rel.startsWith('~/') || /^[A-Za-z]:\//.test(rel)) {
      throw new Error(`Absolute paths are not allowed in folder upload: ${rel}`);
    }

    const normalized = path.posix.normalize(rel);
    if (normalized === '.' || normalized.startsWith('../') || normalized.includes('/../')) {
      throw new Error(`Blocked path traversal entry in folder upload: ${rel}`);
    }

    for (const segment of normalized.split('/')) {
      if (!segment || segment === '.' || segment === '..') {
        throw new Error(`Invalid path segment in folder upload: ${rel}`);
      }
      if (!SAFE_UPLOAD_SEGMENT_REGEX.test(segment)) {
        throw new Error(`Invalid characters in folder upload path: ${rel}`);
      }
    }
    return normalized;
  }

  function runTool(tool, args, cwd, { env: envOverride = {}, allowedExitCodes = [0], timeoutMs = 120_000 } = {}) {
    return new Promise((resolve, reject) => {
      const safeTool = sanitizeCommand(tool);
      const safeArgs = sanitizeCliArgs(args);
      const safeCwd = sanitizeCwd(cwd);
      const env = sanitizeEnv({ ...process.env, GIT_TERMINAL_PROMPT: '0', ...envOverride });
      const safeTimeoutMs = Number.isFinite(timeoutMs) && timeoutMs > 0 ? Number(timeoutMs) : 120_000;

      const execute = (command) => execFile(
        command,
        safeArgs,
        { cwd: safeCwd, env, timeout: safeTimeoutMs, maxBuffer: 10 * 1024 * 1024 },
        (err, stdout, stderr) => {
          // ORT's analyzer exits 2 (not 0) whenever it found issues at/above
          // its severity threshold — a normal outcome, not a tool failure —
          // while still writing a complete analyzer-result.json. Callers that
          // need this (runOrtAnalyze) opt in via allowedExitCodes.
          if (err && !allowedExitCodes.includes(err.code)) {
            const detail = (stderr || stdout || err.message || '').trim();
            const timeoutNote = err.killed ? ` (timed out after ${safeTimeoutMs}ms)` : '';
            reject(new Error(`\`${command} ${safeArgs.join(' ')}\` failed${timeoutNote}: ${detail}`));
          } else {
            resolve({ stdout: stdout.trim(), stderr: stderr.trim() });
          }
        }
      );

      switch (safeTool) {
        case 'git': return execute('git');
        case 'gh': return execute('gh');
        case 'act': return execute('act');
        case 'docker': return execute('docker');
        case 'gitleaks': return execute(binaries.gitleaks);
        case 'licensee': return execute('licensee');
        case 'ort': return execute('ort');
        case 'trivy': return execute(binaries.trivy);
        case 'checkov': return execute(binaries.checkov);
        case 'hadolint': return execute(binaries.hadolint);
        case 'syft': return execute(binaries.syft);
        case 'cosign': return execute(binaries.cosign);
        case 'semgrep': return execute(binaries.semgrep);
        case 'bearer': return execute(binaries.bearer);
        case 'guarddog': return execute(binaries.guarddog);
        case 'jscpd': return execute(binaries.jscpd);
        case 'gocloc': return execute(binaries.gocloc);
        case 'spectral': return execute(binaries.spectral);
        case 'codeql': return execute(binaries.codeql);
        default: return reject(new Error(`Unsupported command: ${safeTool}`));
      }
    });
  }

  // eslint-disable-next-line no-control-regex
  const ANSI_REGEX = /\x1b\[[0-9;]*[a-zA-Z]/g;
  const FAILURE_LINE_REGEX = /❌|::error|error:|fatal:|\bfailure\b/i;

  // A non-zero exit code alone ("`act` exited with code 1.") tells you nothing
  // about what actually broke — the real cause is buried in the streamed
  // stdout/stderr. Pull out every line that looks like an actual failure
  // (marked with ❌, "Error:", "fatal:", "Failure -", etc.), deduped, so a
  // caller can either summarize it (extractFailureDetail) or report each one
  // as its own finding instead of one generic "exited with code N" blob.
  function extractFailureLines(lines) {
    const seen = new Set();
    const out = [];
    for (const raw of lines) {
      const l = raw.replace(ANSI_REGEX, '').trim();
      if (l && FAILURE_LINE_REGEX.test(l) && !seen.has(l)) { seen.add(l); out.push(l); }
    }
    return out;
  }

  /**
   * Long-running command with live line-by-line output streaming (used for
   * `act`, whose runs take minutes and produce continuous logs).
   */
  function runToolStreaming(tool, args, cwd, onLine, { timeoutMs = 15 * 60_000, env = {} } = {}) {
    return new Promise((resolve, reject) => {
      const safeTool = sanitizeCommand(tool);
      const safeArgs = sanitizeCliArgs(args);
      const safeCwd = sanitizeCwd(cwd);
      const safeEnv = sanitizeEnv({ ...process.env, GIT_TERMINAL_PROMPT: '0', ...env });

      let child;
      let commandLabel;
      switch (safeTool) {
        case 'git':
          commandLabel = 'git';
          child = spawn('git', safeArgs, { cwd: safeCwd, env: safeEnv });
          break;
        case 'gh':
          commandLabel = 'gh';
          child = spawn('gh', safeArgs, { cwd: safeCwd, env: safeEnv });
          break;
        case 'act':
          commandLabel = 'act';
          child = spawn('act', safeArgs, { cwd: safeCwd, env: safeEnv });
          break;
        case 'docker':
          commandLabel = 'docker';
          child = spawn('docker', safeArgs, { cwd: safeCwd, env: safeEnv });
          break;
        case 'codeql':
          // Unlike git/gh/act/docker, codeql's binary is configurable (see
          // CONFIG.security.codeql.binary) — spawn the resolved path, not a
          // literal, same as runTool's execute(binaries.codeql) above.
          // binaries.codeql resolves from CODEQL_BINARY (config.json's
          // security.codeql.binary or the CODEQL_BINARY env var) - operator/
          // deployer-set deployment configuration, not attacker- or
          // end-user-controllable input. safeArgs/safeCwd/safeEnv are
          // already validated above regardless of which binary is invoked.
          commandLabel = 'codeql';
          child = spawn(binaries.codeql, safeArgs, { cwd: safeCwd, env: safeEnv }); // nosemgrep: javascript.lang.security.detect-child-process.detect-child-process
          break;
        default:
          reject(new Error(`Unsupported command: ${safeTool}`));
          return;
      }

      const timer = setTimeout(() => {
        child.kill('SIGKILL');
        reject(new Error(`\`${commandLabel}\` timed out after ${timeoutMs / 60000} minutes.`));
      }, timeoutMs);

      let pending = { out: '', err: '' };
      const capturedLines = [];
      const feed = (key) => (chunk) => {
        pending[key] += chunk.toString();
        const lines = pending[key].split('\n');
        pending[key] = lines.pop();
        lines.forEach((l) => { if (l.trim()) { capturedLines.push(l); onLine(l); } });
      };
      child.stdout.on('data', feed('out'));
      child.stderr.on('data', feed('err'));
      child.on('error', (err) => { clearTimeout(timer); reject(err); });
      child.on('close', (code) => {
        clearTimeout(timer);
        Object.values(pending).forEach((rest) => { if (rest.trim()) { capturedLines.push(rest); onLine(rest); } });
        if (code === 0) { resolve(); return; }
        const failureLines = extractFailureLines(capturedLines);
        const detail = failureLines.length ? `Cause: ${failureLines.slice(-3).join(' | ')}` : '';
        const err = new Error(`\`${commandLabel}\` exited with code ${code}.${detail ? ` ${detail}` : ''}`);
        err.failureLines = failureLines;
        reject(err);
      });
    });
  }

  return {
    ALLOWED_COMMANDS,
    runTool,
    runToolStreaming,
    extractFailureLines,
    sanitizeCliArg,
    sanitizeCommand,
    sanitizeCliArgs,
    sanitizeCwd,
    sanitizeAbsoluteProjectPath,
    sanitizeEnv,
    sanitizeUploadRelativePath,
  };
}

module.exports = { createToolRunner };
