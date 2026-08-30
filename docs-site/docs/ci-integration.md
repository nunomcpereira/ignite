---
title: CI integration
sidebar_position: 8
---

# CI integration — surface the gate on the PR, not just the terminal

The [pre-push hook](./pre-push-hook) covers a developer's own machine. Once
a PR is open, the same result should be visible to everyone reviewing it —
a `POST /api/pipeline/validate-all` call is only useful to the person who
ran it unless something posts the outcome somewhere shared.

## Posting a commit status + PR comment

`POST /api/pipeline/:jobId/github-check` takes a completed (or still
in-flight) job id plus the commit it covers, and posts:

- a GitHub commit status (`context: "ignite/gate"`, `success`/`failure`) —
  shows up as a check row on the PR, same as any other CI job
- when `prNumber` is given, a single markdown comment summarizing blocking
  findings/warnings/overrides, using the same issue list `GET
  /api/pipeline/:jobId/sarif` and `GET /api/pipeline/:jobId/issues` already
  expose

```bash
curl -X POST http://ignite.internal:51337/api/pipeline/$JOB_ID/github-check \
  -H 'Content-Type: application/json' \
  -d '{"owner":"my-org","repo":"my-repo","sha":"'"$GITHUB_SHA"'","prNumber":'"$PR_NUMBER"'}'
```

A minimal GitHub Actions workflow, run on a self-hosted runner that can
reach a running Ignite server (Ignite itself never runs as a public SaaS
endpoint — see [How it works](./how-it-works)):

```yaml
name: Ignite gate
on: pull_request

jobs:
  ignite:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4
      - name: Run Ignite
        id: scan
        run: |
          RESPONSE=$(curl -sS -X POST "$IGNITE_BASE_URL/api/pipeline/validate-all" \
            -H 'Content-Type: application/json' \
            -d "{\"projectPath\":\"$GITHUB_WORKSPACE\",\"org\":\"${{ github.repository_owner }}\",\"repo\":\"${{ github.event.repository.name }}\",\"runLocalCi\":false}")
          echo "$RESPONSE" > result.json
          echo "job_id=$(jq -r '.jobId' result.json)" >> "$GITHUB_OUTPUT"
      - name: Post result to the PR
        if: always()
        run: |
          curl -X POST "$IGNITE_BASE_URL/api/pipeline/${{ steps.scan.outputs.job_id }}/github-check" \
            -H 'Content-Type: application/json' \
            -d "{\"owner\":\"${{ github.repository_owner }}\",\"repo\":\"${{ github.event.repository.name }}\",\"sha\":\"${{ github.sha }}\",\"prNumber\":${{ github.event.pull_request.number }}}"
        env:
          IGNITE_BASE_URL: ${{ vars.IGNITE_BASE_URL }}
```

The endpoint needs a GitHub token to post with — either the calling
request's connected-GitHub-account session, or `GH_TOKEN`/`GITHUB_TOKEN`
set on the Ignite server itself for unattended CI callers with no session.
It uses the `gh` CLI when available and falls back to a direct REST call
otherwise, same soft-dependency pattern as every other GitHub API call in
the `ignite-github-api` crate (`rust/crates/github-api`).

Re-running against the same commit/PR is safe: GitHub replaces the old
`ignite/gate` status with the new one, and each call adds one more comment
(no dedup) — for one comment kept current, edit the workflow to reuse a
prior comment id rather than always posting a new one.

## Agent self-fix loop — closing the loop without a human in between

An agent that already calls `check_project`/`onboard_project` (the MCP
tools served by the `mcp-server` binary) or `POST /api/pipeline/validate-all` directly
gets back the same flat `issues[]` list this doc's PR comment is built
from — file, line, category, severity, summary. That's already enough for
an agent to fix its own findings and re-scan without a person relaying
output back and forth:

1. Agent edits code, then calls `validate-all` (or `ignite scan --fast` —
   see [pre-push hook](./pre-push-hook#lightning-mode--skip-the-slow-tools-on-every-push))
   with `changedFiles` set to the files it just touched, to see only
   whether *those* got flagged instead of re-triaging the whole project.
2. On a remaining blocking issue, it reads `issue.file`/`issue.line`/
   `issue.summary`/`issue.snippet` and fixes the source directly, or — for
   a finding that's a false positive or an accepted risk — submits a
   `justification` through the same override path a human would.
3. Repeat until `ok: true`, then either stop (pre-push/CI use) or call
   `effectivate_project` to ship the now-clean snapshot ([the "check
   first, ship later" loop](./mcp-server)).

Nothing here is new API surface — it's the existing `validate-all`/
`onboard_project` response shape, used in a loop instead of a single call.
