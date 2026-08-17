'use strict';

/**
 * GitHub API access without requiring the `gh` CLI binary. `gh` is still the
 * default for the git push transport's credential helper and for `act`'s
 * workflow-token resolution, but every plain GitHub *API* call here (repo
 * creation, refs, PRs, issue filing, cloning, ...) is a soft dependency the
 * same way trivy/semgrep are soft dependencies for their checks: probed
 * once, and transparently replaced with a direct HTTPS call carrying the
 * same token when the binary isn't installed at all. Phase E of the
 * server.js module split (see
 * /Users/nuno/.claude/plans/cuddly-roaming-pearl.md).
 *
 * @param {object} deps
 * @param {Function} deps.runTool - from lib/tool-runner.js's createToolRunner()
 * @param {Function} deps.runToolStreaming - from lib/tool-runner.js's createToolRunner()
 */
function createGithubApi({ runTool, runToolStreaming }) {
  const os = require('os');

  let ghCliAvailable = null;
  async function isGhCliAvailable() {
    if (ghCliAvailable !== null) return ghCliAvailable;
    try {
      await runTool('gh', ['--version'], os.tmpdir());
      ghCliAvailable = true;
    } catch {
      ghCliAvailable = false;
    }
    return ghCliAvailable;
  }

  // Server-level operations (governance workflow fetch, scheduled re-checks)
  // have no per-request connected-user token to fall back on — GH_TOKEN /
  // GITHUB_TOKEN (the same env vars `gh` and GitHub Actions itself recognize)
  // fill that role when gh isn't installed.
  function resolveServerGithubToken() {
    return process.env.GH_TOKEN || process.env.GITHUB_TOKEN || '';
  }

  async function githubApiRequest(token, method, apiPath, { body, accept } = {}) {
    const res = await fetch(`https://api.github.com${apiPath}`, {
      method,
      headers: {
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        Accept: accept || 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(15_000),
    });
    const text = await res.text();
    if (!res.ok) {
      throw new Error(`GitHub API ${method} ${apiPath} failed: HTTP ${res.status} ${text.slice(0, 300)}`);
    }
    if (!text) return null;
    return accept === 'application/vnd.github.raw' ? text : JSON.parse(text);
  }

  async function githubGraphqlRequest(token, query, variables) {
    const data = await githubApiRequest(token, 'POST', '/graphql', { body: { query, variables } });
    if (data.errors) throw new Error(`GitHub GraphQL error: ${JSON.stringify(data.errors)}`);
    return data.data;
  }

  // `gh api -X POST/PATCH path -f k=v -F k=v` <-> REST request with a JSON
  // body — covers every plain `gh api` call site (repo create/patch, ref
  // create, default-branch set, existence checks).
  async function ghApiWrite(method, apiPath, fields, token) {
    if (await isGhCliAvailable()) {
      const args = ['api', '-X', method, apiPath];
      for (const [k, v] of Object.entries(fields || {})) {
        args.push(typeof v === 'boolean' || typeof v === 'number' ? '-F' : '-f', `${k}=${v}`);
      }
      const { stdout } = await runTool('gh', args, os.tmpdir(), { env: { GH_TOKEN: token } });
      return stdout ? JSON.parse(stdout) : null;
    }
    return githubApiRequest(token, method, `/${apiPath}`, { body: fields });
  }

  async function ghApiGet(apiPath, token) {
    if (await isGhCliAvailable()) {
      const { stdout } = await runTool('gh', ['api', apiPath], os.tmpdir(), { env: { GH_TOKEN: token } });
      return stdout ? JSON.parse(stdout) : null;
    }
    return githubApiRequest(token, 'GET', `/${apiPath}`);
  }

  async function ghFetchFileRaw(repoFullName, filePath, token) {
    if (await isGhCliAvailable()) {
      const { stdout } = await runTool('gh', [
        'api', `repos/${repoFullName}/contents/${filePath}`,
        '-H', 'Accept: application/vnd.github.raw',
      ], os.tmpdir());
      return stdout;
    }
    return githubApiRequest(token, 'GET', `/repos/${repoFullName}/contents/${filePath}`, { accept: 'application/vnd.github.raw' });
  }

  async function ghListCommits(repoFullName, filePath, token) {
    if (await isGhCliAvailable()) {
      const { stdout } = await runTool('gh', ['api', `repos/${repoFullName}/commits?path=${filePath}&per_page=1`], os.tmpdir());
      return JSON.parse(stdout);
    }
    return githubApiRequest(token, 'GET', `/repos/${repoFullName}/commits?path=${filePath}&per_page=1`);
  }

  async function ghCreatePr({ fullName, base, head, title, body, token }) {
    if (await isGhCliAvailable()) {
      const { stdout } = await runTool('gh', [
        'pr', 'create', '--repo', fullName, '--base', base, '--head', head, '--title', title, '--body', body,
      ], os.tmpdir(), { env: { GH_TOKEN: token } });
      const url = (stdout.match(/https:\/\/github\.com\/\S+\/pull\/\d+/) || [stdout])[0];
      return { url, number: Number((url.match(/\/pull\/(\d+)/) || [])[1]) || null };
    }
    const pr = await githubApiRequest(token, 'POST', `/repos/${fullName}/pulls`, { body: { title, body, base, head } });
    return { url: pr.html_url, number: pr.number, nodeId: pr.node_id };
  }

  async function ghArmAutoMerge({ fullName, prUrl, prNumber, prNodeId, token }) {
    if (await isGhCliAvailable()) {
      await runTool('gh', ['pr', 'merge', prUrl, '--auto', '--squash'], os.tmpdir(), { env: { GH_TOKEN: token } });
      return;
    }
    let nodeId = prNodeId;
    if (!nodeId) {
      const pr = await githubApiRequest(token, 'GET', `/repos/${fullName}/pulls/${prNumber}`);
      nodeId = pr.node_id;
    }
    await githubGraphqlRequest(
      token,
      'mutation($id: ID!) { enablePullRequestAutoMerge(input: { pullRequestId: $id, mergeMethod: SQUASH }) { clientMutationId } }',
      { id: nodeId }
    );
  }

  // gh's `pr checks --watch` polls GitHub for us; the REST fallback does the
  // same polling loop by hand against the head commit's check-runs.
  async function ghWatchPrChecks({ fullName, prUrl, prNumber, token, log, timeoutMs }) {
    if (await isGhCliAvailable()) {
      await runToolStreaming('gh', ['pr', 'checks', prUrl, '--watch', '--interval', '15'],
        os.tmpdir(), (line) => log(line.slice(0, 300)), { timeoutMs, env: { GH_TOKEN: token } });
      return;
    }
    const pr = await githubApiRequest(token, 'GET', `/repos/${fullName}/pulls/${prNumber}`);
    const sha = pr.head.sha;
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const { check_runs: runs = [] } = await githubApiRequest(token, 'GET', `/repos/${fullName}/commits/${sha}/check-runs`);
      if (runs.length > 0) {
        const pending = runs.filter((r) => r.status !== 'completed');
        if (pending.length === 0) {
          const failed = runs.filter((r) => !['success', 'neutral', 'skipped'].includes(r.conclusion));
          if (failed.length > 0) throw new Error(`${failed.length} check(s) failed: ${failed.map((r) => r.name).join(', ')}`);
          log('✓ All checks completed successfully.');
          return;
        }
        log(`Waiting on ${pending.length} check(s): ${pending.map((r) => r.name).join(', ')}...`);
      } else {
        log('No check-runs reported yet...');
      }
      await new Promise((r) => setTimeout(r, 15_000));
    }
    throw new Error('Timed out waiting for required checks.');
  }

  async function ghCreateIssue({ fullName, title, body, token }) {
    if (await isGhCliAvailable()) {
      await runTool('gh', ['issue', 'create', '--repo', fullName, '--title', title, '--body', body], os.tmpdir());
      return;
    }
    await githubApiRequest(token, 'POST', `/repos/${fullName}/issues`, { body: { title, body } });
  }

  async function ghCloneRepo({ fullName, destDir, token }) {
    if (await isGhCliAvailable()) {
      await runTool('gh', ['repo', 'clone', fullName, destDir, '--', '--depth', '1', '--branch', 'main'], os.tmpdir());
      return;
    }
    if (!token) throw new Error('No GitHub token available (gh not installed, and GH_TOKEN/GITHUB_TOKEN not set) — cannot clone.');
    // http.extraheader is a one-off override for this invocation only — unlike
    // embedding the token in the remote URL, it's never written to the
    // cloned repo's own .git/config, so nothing persists on disk afterward.
    await runTool('git', [
      '-c', `http.extraheader=AUTHORIZATION: bearer ${token}`,
      'clone', '--depth', '1', '--branch', 'main', `https://github.com/${fullName}.git`, destDir,
    ], os.tmpdir());
  }

  return {
    isGhCliAvailable,
    resolveServerGithubToken,
    githubApiRequest,
    githubGraphqlRequest,
    ghApiWrite,
    ghApiGet,
    ghFetchFileRaw,
    ghListCommits,
    ghCreatePr,
    ghArmAutoMerge,
    ghWatchPrChecks,
    ghCreateIssue,
    ghCloneRepo,
  };
}

module.exports = { createGithubApi };
