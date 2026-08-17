'use strict';

/**
 * Phase 5/6: git + gh shipping — provisions (or reuses) the target GitHub
 * repo, pushes the compliant code, and (when an org ruleset requires it)
 * opens a PR into main with auto-merge armed, watching for the required
 * remote checks. Phase E of the server.js module split (see
 * /Users/nuno/.claude/plans/cuddly-roaming-pearl.md).
 *
 * @param {object} deps
 * @param {Function} deps.runTool - from lib/tool-runner.js's createToolRunner()
 * @param {Function} deps.sanitizeCliArg - from lib/tool-runner.js's createToolRunner()
 * @param {object} deps.githubApi - lib/github-api.js's createGithubApi() result
 *   (ghApiGet, ghApiWrite, ghCreatePr, ghArmAutoMerge, ghWatchPrChecks)
 * @param {object} deps.store - db-store.js instance (addUploadDocument)
 * @param {object} deps.config - { bootstrapBranch, remoteProtocol }
 */
function createShipping({ runTool, sanitizeCliArg, githubApi, store, config }) {
  const fs = require('fs');
  const fsp = require('fs/promises');
  const path = require('path');
  const os = require('os');
  const crypto = require('crypto');
  const { ghApiGet, ghApiWrite, ghCreatePr, ghArmAutoMerge, ghWatchPrChecks } = githubApi;

  async function shipToGitHub(root, org, repo, log, ghToken) {
    if (!ghToken) {
      throw new Error(
        'No GitHub account connected for this request. Connect your own GitHub account ' +
        '(GET /api/auth/github/connect, or the "Connect GitHub" button in the UI) before ' +
        'provisioning a repository — Phase 6 no longer falls back to the server\'s own gh session.'
      );
    }
    const ghEnv = { GH_TOKEN: ghToken };
    const git = (args, cwd = root) => runTool('git', args, cwd, { env: ghEnv });

    const safeOrg = sanitizeCliArg(org, 'Organization name');
    const safeRepo = sanitizeCliArg(repo, 'Repository name');
    const fullName = `${safeOrg}/${safeRepo}`;
    const isCreateValidation422 = (msg) => /HTTP 422/i.test(String(msg || ''));
    const repoExistsOnGitHub = async (owner, name) => {
      try {
        await ghApiGet(`repos/${owner}/${name}`, ghToken);
        return true;
      } catch {
        return false;
      }
    };

    // Phase 4 may already have initialized and committed the repo for act.
    const alreadyRepo = fs.existsSync(path.join(root, '.git'));
    if (alreadyRepo) {
      log('Reusing repository initialized during the local CI phase.');
    } else {
      log('$ git init -b main');
      await git(['init', '-b', 'main'], root);

      log('$ git add .');
      await git(['add', '.'], root);

      log('$ git commit -m "chore: initial compliant code drop via onboarding gatekeeper"');
      await git(
        [
          '-c', 'user.name=Onboarding Gatekeeper',
          '-c', 'user.email=gatekeeper@localhost',
          'commit',
          '-m', 'chore: initial compliant code drop via onboarding gatekeeper',
        ],
        root
      );
    }

    // Org rulesets with required workflows reject direct pushes to main
    // (GH013): the required workflow must run on GitHub in a PR context.
    // Compliant flow: init main server-side, push a branch, open a PR,
    // arm auto-merge, and watch the required checks.
    // Bootstrap branch (configurable, github.bootstrapBranch): the compliant
    // code lands here first, then PRs into the repo's default branch.
    const ONBOARD_BRANCH = String(config.bootstrapBranch || 'ignite');
    const remoteProtocol = String(config.remoteProtocol || 'https').toLowerCase();
    const remoteUrl = remoteProtocol === 'ssh'
      ? `git@github.com:${fullName}.git`
      : `https://github.com/${fullName}.git`;
    // https: gh as credential helper for this job only, no interactive
    // prompts. ssh: no credential helper needed/applicable — auth is whatever
    // SSH key/agent is already configured for github.com on this machine.
    const gitCred = remoteProtocol === 'ssh'
      ? []
      : ['-c', 'credential.helper=', '-c', 'credential.helper=!gh auth git-credential', '-c', 'core.askPass='];
    const gitId = ['-c', 'user.name=Onboarding Gatekeeper', '-c', 'user.email=gatekeeper@localhost'];

    log(`$ gh api POST orgs/${safeOrg}/repos (private, auto_init)`);
    try {
      await ghApiWrite('POST', `orgs/${safeOrg}/repos`, { name: safeRepo, private: true, auto_init: true }, ghToken);
    } catch (e) {
      if (/404/.test(e.message)) {
        // Personal account, not an organization.
        log(`"${safeOrg}" is not an org — creating under the authenticated user.`);
        try {
          await ghApiWrite('POST', 'user/repos', { name: safeRepo, private: true, auto_init: true }, ghToken);
        } catch (fallbackErr) {
          if (isCreateValidation422(fallbackErr.message)) {
            const exists = await repoExistsOnGitHub(safeOrg, safeRepo);
            if (exists) {
              log(`Repository ${fullName} already exists — reusing it.`);
            } else {
              throw fallbackErr;
            }
          } else {
            throw fallbackErr;
          }
        }
      } else if (isCreateValidation422(e.message)) {
        const exists = await repoExistsOnGitHub(safeOrg, safeRepo);
        if (exists) {
          log(`Repository ${fullName} already exists — reusing it.`);
        } else {
          throw e;
        }
      } else {
        throw e;
      }
    }

    try {
      await ghApiWrite('PATCH', `repos/${fullName}`, { allow_auto_merge: true }, ghToken);
      log('Enabled auto-merge on the repository.');
    } catch {
      log('⚠ Could not enable auto-merge — the PR will need a manual merge once checks pass.');
    }

    log(`$ git remote add origin "${remoteUrl}"`);
    await git(['remote', 'add', 'origin', remoteUrl], root);

    // Repo initialization is asynchronous — and org rulesets with required
    // workflows can block the creation of main entirely. Wait briefly for it.
    log('$ git fetch origin main');
    let mainExists = false;
    for (let attempt = 1; attempt <= 8; attempt++) {
      try {
        await git([...gitCred, 'fetch', 'origin', 'main'], root);
        mainExists = true;
        break;
      } catch {
        log(`main ref not ready yet (attempt ${attempt}/8) — retrying in 3s...`);
        await new Promise((r) => setTimeout(r, 3000));
      }
    }

    if (mainExists) {
      // Replay our commit on top of GitHub's init commit; on conflicts
      // (e.g. the project ships its own README.md) our version wins.
      log('$ git rebase -X theirs origin/main');
      await git([...gitId, 'rebase', '-X', 'theirs', 'origin/main'], root);
    }

    log(`$ git push -u origin HEAD:${ONBOARD_BRANCH}`);
    await git([...gitCred, 'push', '-u', 'origin', `HEAD:${ONBOARD_BRANCH}`], root);
    const { stdout: sha } = await git(['rev-parse', 'HEAD'], root);

    if (!mainExists) {
      // Try to create main directly from the compliant commit (works in
      // orgs/accounts without a required-workflow ruleset on main).
      log('$ gh api POST git/refs (create main from onboarding commit)');
      try {
        await ghApiWrite('POST', `repos/${fullName}/git/refs`, { ref: 'refs/heads/main', sha }, ghToken);
        log('✓ main created directly — no ruleset restriction on this repo.');
        await ghApiWrite('PATCH', `repos/${fullName}`, { default_branch: 'main' }, ghToken)
          .then(() => log('✓ Default branch set to main.'))
          .catch(() => log('⚠ Could not set main as the default branch — adjust in repo settings.'));
        log(`✓ Code is live on main.`);
        return { repoUrl: `https://github.com/${fullName}` };
      } catch {
        // Deadlock: the ruleset blocks ALL creation of main (even GitHub's
        // auto-init), but the required workflow can only run on a PR whose
        // base is main. No client-side flow can satisfy it.
        await ghApiWrite('PATCH', `repos/${fullName}`, { default_branch: ONBOARD_BRANCH }, ghToken).catch(() => {});
        log(`⚠ The org ruleset blocks creating "main" in new repos (bootstrap deadlock: the required workflow can only run on a PR, and a PR needs main to exist).`);
        log(`✓ Code shipped to "${ONBOARD_BRANCH}", now the repository's default branch.`);
        log(`⚠ Once an org admin adds a ruleset bypass so main can be bootstrapped, open a PR from "${ONBOARD_BRANCH}" into main.`);
        return { repoUrl: `https://github.com/${fullName}/tree/${ONBOARD_BRANCH}` };
      }
    }

    log('$ gh pr create --base main');
    const { url: prUrl, number: prNumber, nodeId: prNodeId } = await ghCreatePr({
      fullName,
      base: 'main',
      head: ONBOARD_BRANCH,
      title: 'chore: initial compliant code drop via onboarding gatekeeper',
      body: 'Automated onboarding by Ignite. All local gates passed: structure audit, secret scan, AI governance, LLM deep-scan, and the org governance workflows executed locally via act.',
      token: ghToken,
    });
    log(`✓ Pull request opened: ${prUrl}`);

    try {
      await ghArmAutoMerge({ fullName, prUrl, prNumber, prNodeId, token: ghToken });
      log('✓ Auto-merge armed — the PR merges itself when the required workflow passes.');
    } catch (e) {
      log(`⚠ Auto-merge could not be armed (${e.message}). Merge manually once checks pass.`);
    }

    log('Waiting for the required org workflow to run on GitHub...');
    try {
      await ghWatchPrChecks({ fullName, prUrl, prNumber, token: ghToken, log: (l) => log(l), timeoutMs: 20 * 60_000 });
      log('✓ All remote required checks passed — auto-merge will land the PR on main.');
    } catch (e) {
      throw new Error(`Remote governance checks did not pass (${e.message}). PR left open for review: ${prUrl}`);
    }

    return { repoUrl: `https://github.com/${fullName}`, prUrl };
  }

  async function archivePhase6Payload(root, projectId, log) {
    if (projectId === null) return null;

    const tmpName = `ignite-phase6-payload-${crypto.randomUUID()}.zip`;
    const tmpZip = path.join(os.tmpdir(), tmpName);
    try {
      // Snapshot the exact tracked tree that phase 6 is attempting to push.
      await runTool('git', ['archive', '--format=zip', '-o', tmpZip, 'HEAD'], root);
      const data = await fsp.readFile(tmpZip);
      const size = data.length;
      const docName = `phase6-payload-${new Date().toISOString().replace(/[:]/g, '-')}.zip`;
      store.addUploadDocument(projectId, docName, 'application/zip', size, data);
      log(`📦 Archived phase 6 push payload for inspection: ${docName} (${(size / 1024).toFixed(1)} KB).`);
      return { name: docName, size };
    } catch (e) {
      log(`⚠ Could not archive phase 6 push payload: ${e.message}`);
      return null;
    } finally {
      await fsp.rm(tmpZip, { force: true }).catch(() => {});
    }
  }

  return { shipToGitHub, archivePhase6Payload };
}

module.exports = { createShipping };
