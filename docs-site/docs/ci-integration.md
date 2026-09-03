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

## Scheduled re-scans — Dependabot-equivalent continuous coverage

:::info[The schedule is yours to set — Ignite has no built-in scheduler]
Despite the name, `scheduled-rescan` has no scheduler inside it — it's a
one-shot binary that scans every onboarded repo once and exits. "Scheduled"
means *you* run it on a timer from outside Ignite: a cron/systemd job, or a
GitHub Actions `schedule:` trigger (both shown below). Nothing about it is
wired into the Ignite server's own process or started automatically on
onboarding.
:::

Ignite's dependency/CVE checks (Trivy, package-hallucination, GuardDog, and
the rest of Phase 4) only run when a scan is *triggered* — a push, or
someone running the CLI. Unlike Dependabot, nothing re-checks an already
onboarded repo's unchanged code against a CVE disclosed *after* the last
scan. The `scheduled-rescan` binary (`rust/crates/scheduled-rescan`) closes
that gap: it iterates every onboarded `(org, repo)` pair already known to
Ignite (`db-store`'s `projects` table), shallow-clones each one's current
GitHub default branch, runs it through a real `POST
/api/pipeline/validate-all`, and — only if that run actually found
something — posts the result back via the same `POST
/api/pipeline/:jobId/github-check` this page already covers. A clean scan
is a no-op: nothing is posted, it's just logged.

Run it by hand (or from cron/systemd) against a running Ignite server:

```bash
IGNITE_SERVER_URL=http://ignite.internal:51337 \
IGNITE_DB_PATH=/path/to/ignite.db \
GH_TOKEN=$GH_TOKEN \
  ./target/release/scheduled-rescan
```

Or on a GitHub Actions `schedule:` trigger, from a runner that can reach
the Ignite server and has a working directory to clone into:

```yaml
name: Ignite scheduled re-scan

on:
  schedule:
    - cron: "0 6 * * *"  # daily at 06:00 UTC
  workflow_dispatch: {}

jobs:
  rescan:
    runs-on: ubuntu-latest
    steps:
      - name: Run Ignite scheduled-rescan
        env:
          IGNITE_SERVER_URL: ${{ vars.IGNITE_BASE_URL }}
          IGNITE_DB_PATH: ${{ vars.IGNITE_DB_PATH }}
          GH_TOKEN: ${{ secrets.IGNITE_SCHEDULED_RESCAN_TOKEN }}
        run: |
          curl -fsSL https://github.com/<org>/ignite/releases/latest/download/scheduled-rescan -o scheduled-rescan
          chmod +x scheduled-rescan
          ./scheduled-rescan
```

`IGNITE_DB_PATH` needs to point at the *same* database the Ignite server
itself uses (a shared volume, or this job running on the same host) —
`scheduled-rescan` reads project records directly rather than through an
API, the same pattern `scripts/create-api-key` already uses for its own
db access. This job is not wired into anything automatically; it's an
opt-in schedule an operator adds once they want continuous coverage.

Each project's `validate-all` call is bounded by
`IGNITE_SCHEDULED_RESCAN_TIMEOUT_SECS` (default 1800 = 30 min, well past a
typical HTTP client default) — a real full Phase 4 sweep on a large repo
can legitimately run well past 10 minutes.

### Auto-opening a fix PR for what it finds

By default a scheduled re-scan only *reports* a newly-disclosed CVE — it
doesn't propose the fix. Set `IGNITE_SCHEDULED_RESCAN_AUTO_FIX=dry-run` (log
the fix plan, push nothing) or `=apply` (actually push a branch and open a
PR) to chain straight into `auto-fix-pr` for any repo the rescan found
something on, reusing the same clone rather than checking the repo out
twice:

```bash
IGNITE_SERVER_URL=http://ignite.internal:51337 \
IGNITE_DB_PATH=/path/to/ignite.db \
GH_TOKEN=$GH_TOKEN \
IGNITE_SCHEDULED_RESCAN_AUTO_FIX=apply \
  ./target/release/scheduled-rescan
```

Off by default — an existing scheduled deployment's behavior never changes
until this is explicitly set. Deliberately conservative: only a single,
simple version constraint (a bare version, or one `^`/`~`/`==`/`>=`-style
prefix) is auto-bumped, and a fix crossing a semver major version is always
skipped for a human to review, never silently applied — this is the same
`auto-fix-pr` binary (`rust/crates/auto-fix-pr`, runnable standalone against
any repo with `./target/release/auto-fix-pr <org/repo> [--apply]`), just
triggered automatically here instead of by hand.

## Keep GitHub's secret push-protection even without full GHAS

If you're dropping GitHub Advanced Security in favor of Ignite's gate
(this scheduled re-scan, the [branch-protection
enforcement](#branch-protection-enforcement) below, and the pipeline
itself), keep GitHub's *basic secret-scanning push-protection* enabled
regardless. It's the one capability Ignite's post-hoc gitleaks/regex scan
structurally can't replace: push-protection rejects a commit containing a
recognized secret pattern *before* it ever lands on GitHub, at pre-receive
time. Ignite's scan — like any pipeline-stage or scheduled check — only
ever runs *after* a commit already exists somewhere (locally, or already
pushed), so a secret that's pushed and then deleted in a follow-up commit
has still been exposed in git history in the window between.

**Verify this against your actual GitHub bill before treating it as
settled** — whether secret-scanning push-protection is licensed/priced
separately from the rest of GHAS varies by plan and has changed over time;
this doc is flagging it as something to check, not asserting today's
pricing.

## Branch-protection enforcement

Ignite's gate only fires if someone actually routes code through it — a
push, a PR, this scheduled re-scan. GHAS-style enforcement lives at the
GitHub platform level regardless of push path. `enforce-gate-branch-protection`
(`rust/crates/enforce-gate-branch-protection`) closes that gap for the
`ignite/gate` status check specifically: it requires that check (and
blocks direct/admin-bypass pushes) on a given repo's default branch.

```bash
# Prints the exact gh api call(s) it would make — no changes made.
./target/release/enforce-gate-branch-protection my-org/my-repo

# Actually applies it.
./target/release/enforce-gate-branch-protection my-org/my-repo --apply
```

Dry-run by default; this is a deliberate, operator-run tool, not something
wired into any pipeline or schedule.
