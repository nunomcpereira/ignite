'use strict';

/**
 * Verifies a project's `.igniteignore` — a project-root file, `.gitignore`
 * syntax (see lib/fs-utils.js's loadIgniteIgnorePatterns), letting a
 * project opt specific paths (generated code, fixture data, a vendored
 * bundle) out of every Ignite check entirely. lib/fs-utils.js's walkFiles
 * — the one choke point virtually every check's file discovery goes
 * through — already honors it directly; this check covers the other half:
 * a `.igniteignore` that exists on disk but was never committed to git is
 * a silent, unreviewable scan bypass (a teammate/reviewer looking at the
 * repo on GitHub has no way to know some paths were never scanned) — the
 * exact thing a compliance gatekeeper exists to prevent. So unlike the
 * built-in codebase-intelligence checks (dead code, complexity/health,
 * ...), this one finding is blocking (`severity: 'error'`), not advisory —
 * overridable like any other blocking finding, but never silent.
 *
 * Deliberately skips this check entirely when the project isn't a git repo
 * yet (a fresh ZIP/folder upload being onboarded for the first time):
 * server.js's own `git init && git add -A && git commit` right before
 * push will include `.igniteignore` in that very first commit, so there's
 * nothing to flag yet — the file can't possibly be "committed" before a
 * repo exists at all.
 */

function createIgniteIgnoreCheck({ runTool, config }) {
  const fsp = require('fs/promises');
  const path = require('path');

  const ENABLED = config.enabled !== false;
  const IGNITEIGNORE_FILENAME = '.igniteignore';

  async function isGitRepo(root) {
    return runTool('git', ['rev-parse', '--is-inside-work-tree'], root).then(() => true, () => false);
  }

  async function isTrackedByGit(root, relFile) {
    return runTool('git', ['ls-files', '--error-unmatch', '--', relFile], root).then(() => true, () => false);
  }

  async function checkIgniteIgnoreCommitted(root, log) {
    if (!ENABLED) {
      log?.('.igniteignore commit check is disabled (ignoreFile.enabled=false).');
      return { findings: [], engine: 'disabled' };
    }

    const igniteIgnorePath = path.join(root, IGNITEIGNORE_FILENAME);
    const exists = await fsp.stat(igniteIgnorePath).then((s) => s.isFile(), () => false);
    if (!exists) return { findings: [], engine: 'built-in' };

    if (!(await isGitRepo(root))) {
      log?.('.igniteignore found, but this project has no git history yet — it will be committed as part of onboarding, so nothing to flag.');
      return { findings: [], engine: 'built-in' };
    }

    if (await isTrackedByGit(root, IGNITEIGNORE_FILENAME)) {
      return { findings: [], engine: 'built-in' };
    }

    const content = await fsp.readFile(igniteIgnorePath, 'utf8').catch(() => '');
    log?.('⚠ .igniteignore exists but is not committed to git — the paths it excludes from scanning are invisible to reviewers.');
    return {
      findings: [{
        file: IGNITEIGNORE_FILENAME,
        line: 1,
        kind: 'igniteignore-not-committed',
        tool: 'ignite-built-in',
        severity: 'error',
        message: `${IGNITEIGNORE_FILENAME} exists but is not tracked by git — it silently excludes paths from every Ignite check with no reviewable record. Commit it (or remove it if it was left over from local testing) before this can pass.`,
        code: content ? content.split(/\r?\n/).slice(0, 10).join('\n') : null,
      }],
      engine: 'built-in',
    };
  }

  return { checkIgniteIgnoreCommitted, IGNITEIGNORE_FILENAME };
}

module.exports = { createIgniteIgnoreCheck };
