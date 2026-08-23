'use strict';

/**
 * POST /api/pipeline/:jobId/github-check — posts the result of an already-
 * completed (or still-running) Ignite job back onto the GitHub commit it
 * covers, as a commit status ("ignite/gate": success/failure) plus, when a
 * PR number is given, a single markdown summary comment on that PR. Meant
 * for a CI workflow that already calls `ignite scan`/`validate-all` against
 * a checked-out PR branch and wants the result visible to every reviewer
 * without them opening the Ignite UI — the same issue list the SARIF
 * endpoint (routes/sarif.js) already exposes, just rendered for a human
 * reading a PR instead of a SARIF-consuming tool.
 *
 * Re-posting to the same commit/PR is expected and idempotent from
 * GitHub's side for the status (a new status of the same context replaces
 * the old one in the UI); the PR comment is a new comment each call, same
 * as re-running any CI job that comments on its own PR — callers that only
 * want one comment kept up to date should re-run with the same request and
 * treat GitHub's own comment history as the record.
 *
 * @param {import('express').Express} app
 * @param {object} deps
 * @param {object} deps.store - db-store.js instance
 * @param {Map} deps.runningRuns - server.js's in-flight SSE pipeline job map
 * @param {object} deps.auth - auth.js instance (resolveGithubToken)
 * @param {Function} deps.resolveServerGithubToken
 * @param {Function} deps.ghApiWrite
 * @param {Function} deps.ghCommentOnPr
 * @param {RegExp} deps.repoNameRegex - REPO_NAME_REGEX
 * @param {RegExp} deps.githubNameRegex - GITHUB_NAME_REGEX
 */
function mountGithubCheckRoute(app, {
  store, runningRuns, auth, resolveServerGithubToken, ghApiWrite, ghCommentOnPr,
  repoNameRegex, githubNameRegex,
}) {
  const SHA_REGEX = /^[0-9a-f]{7,40}$/i;
  const MAX_LISTED_ISSUES = 15;

  function buildSummary(issues, jobId) {
    const open = issues.filter((i) => i.status !== 'overridden' && i.status !== 'baselined');
    const errors = open.filter((i) => i.severity === 'error');
    const warnings = open.filter((i) => i.severity === 'warning');
    const overridden = issues.filter((i) => i.status === 'overridden');

    const state = errors.length > 0 ? 'failure' : 'success';
    const description = errors.length > 0
      ? `${errors.length} blocking finding(s), ${warnings.length} warning(s)`
      : `Passed — ${warnings.length} warning(s), ${overridden.length} overridden`;

    const lines = [
      `### ${errors.length > 0 ? '❌ Ignite gate failed' : '✅ Ignite gate passed'}`,
      '',
      `**${errors.length}** blocking · **${warnings.length}** warning · **${overridden.length}** overridden`,
      '',
    ];
    const toList = errors.length > 0 ? errors : warnings;
    if (toList.length > 0) {
      lines.push(`<details${errors.length > 0 ? ' open' : ''}><summary>${toList.length} finding(s)${toList.length > MAX_LISTED_ISSUES ? ` (showing first ${MAX_LISTED_ISSUES})` : ''}</summary>`, '');
      for (const issue of toList.slice(0, MAX_LISTED_ISSUES)) {
        const loc = issue.file ? `\`${issue.file}${issue.line ? ':' + issue.line : ''}\`` : '(project-wide)';
        lines.push(`- **[${issue.category}]** ${loc} — ${issue.summary}`);
      }
      lines.push('', '</details>');
    }
    lines.push('', `_Job \`${jobId}\` — via [Ignite](https://github.com/nunomcpereira/ignite)._`);
    return { state, description: description.slice(0, 140), body: lines.join('\n') };
  }

  app.post('/api/pipeline/:jobId/github-check', async (req, res) => {
    const jobId = String(req.params.jobId || '').trim();
    const body = req.body || {};
    const owner = String(body.owner || '').trim();
    const repo = String(body.repo || '').trim();
    const sha = String(body.sha || '').trim();
    const prNumber = body.prNumber !== undefined ? Number(body.prNumber) : null;

    if (!githubNameRegex.test(owner)) return res.status(400).json({ error: `Invalid GitHub owner/org: "${owner}"` });
    if (!repoNameRegex.test(repo)) return res.status(400).json({ error: `Invalid repository name: "${repo}"` });
    if (!SHA_REGEX.test(sha)) return res.status(400).json({ error: 'sha must be a 7-40 character hex commit SHA.' });
    if (prNumber !== null && (!Number.isInteger(prNumber) || prNumber <= 0)) {
      return res.status(400).json({ error: 'prNumber must be a positive integer when provided.' });
    }

    const live = runningRuns.get(jobId);
    const issues = live
      ? live.allIssues
      : (() => {
          const projectId = store.getProjectIdByJobId(jobId);
          return projectId === null ? null : store.getProjectIssues(projectId);
        })();
    if (issues === null) return res.status(404).json({ error: 'Unknown job id.' });

    const token = auth.resolveGithubToken(req) || resolveServerGithubToken();
    if (!token) {
      return res.status(401).json({ error: 'No GitHub token available — connect a GitHub account, or set GH_TOKEN/GITHUB_TOKEN on the Ignite server.' });
    }

    const fullName = `${owner}/${repo}`;
    const { state, description, body: commentBody } = buildSummary(issues, jobId);

    try {
      await ghApiWrite('POST', `repos/${fullName}/statuses/${sha}`, {
        state,
        description,
        context: 'ignite/gate',
      }, token);
      let commented = false;
      if (prNumber !== null) {
        await ghCommentOnPr({ fullName, prNumber, body: commentBody, token });
        commented = true;
      }
      res.json({ ok: true, state, description, commented });
    } catch (err) {
      res.status(502).json({ error: `Failed to post to GitHub: ${err.message}` });
    }
  });
}

module.exports = { mountGithubCheckRoute };
