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

Run standalone (not through the auto-chain above), `auto-fix-pr` also
supports `--group-by ecosystem` — Dependabot's `groups:` config parity:
instead of opening one PR per dependency, every fix candidate for the same
package manager (and same vulnerability-vs-routine-update kind) is bundled
into a single branch/PR. Useful on a legacy repo with many outdated
dependencies, where the ungrouped default would otherwise open dozens of
PRs in one run. Not wired into the `scheduled-rescan` auto-chain — grouping
changes what a reviewer has to accept/reject as a unit, which stays an
operator's explicit choice rather than a scheduled default.

## Native GitHub UI parity for SARIF and dependency graph

Ignite's own findings and dependency data used to live only in Ignite's UI
— GHAS surfaces the equivalent in GitHub's own Security and Insights tabs.
Two pushes close that gap, both triggered from the same `POST
/api/pipeline/:jobId/github-check` call this page already covers (the
pre-push hook/CI caller that posts the `ignite/gate` commit status) —
that's the one place `(owner, repo, sha)` are already validated together
against a commit guaranteed to already exist on GitHub, which both of
these APIs require:

- **SARIF upload** — the job's findings, reshaped into the same SARIF this
  server already serves at `GET /api/pipeline/:jobId/sarif`, get pushed to
  `POST repos/{owner}/{repo}/code-scanning/sarifs` so they show up under
  the repo's **Security → Code scanning** tab natively, not only in
  Ignite's own UI.
- **Dependency graph submission** — the manifests/dependencies already
  resolved during the scan (the same cached result the Studio Dependencies
  tab reads back) get pushed to `PUT
  repos/{owner}/{repo}/dependency-graph/snapshots` (GitHub's Dependency
  Submission API) so they populate the repo's **Insights → Dependency
  graph** tab the same way a Dependabot-enabled repo's would.

Both are best-effort and non-fatal — a failure is logged and never fails
the gate-status response the caller already got. Each is independently
toggleable in `config.json` (on by default):

```json
"security": {
  "codeScanning": { "enabled": true },
  "dependencyGraph": { "enabled": true }
}
```

Or via env vars: `CODE_SCANNING_ENABLED=false` / `DEPENDENCY_GRAPH_ENABLED=false`.

The `github-check` request body accepts an optional `ref` field (e.g.
`"refs/heads/main"`) for the branch/ref these pushes should attach to —
when omitted, Ignite looks up the repo's current default branch and uses
that.

## Inline PR review suggestions (Copilot Autofix parity)

GitHub's Copilot Autofix posts inline PR review comments carrying a
` ```suggestion ` fenced block, which GitHub's PR diff viewer renders with a
one-click "Commit suggestion" button — a developer never has to leave the
PR to apply the fix. `github-check` now does the same for a narrow,
mechanically-safe class of findings: still-open issues in the same
single-line-editable category set `ignite-fix-pr`'s bulk fix-PR feature
already trusts to auto-edit (currently dependency version bumps).

For each such issue on the PR, Ignite reuses `fix-pr`'s own LLM
fix-computation (no separate suggestion-generation logic), and — for any
result that's a single-line edit — posts one PR review comment via
GitHub's Review Comments API (`POST
repos/{owner}/{repo}/pulls/{pr}/comments`). Each suggestion carries a
hidden marker comment identifying the issue it came from; before posting,
Ignite lists the PR's existing review comments and skips any issue whose
marker is already present, so re-running `github-check` on the same PR
(every push re-posts the gate status) never reposts a suggestion that's
already there.

Best-effort and non-fatal, same as the SARIF/dependency-graph pushes
above — a failure is logged and never fails the gate-status response.
Toggleable in `config.json` (on by default, since the scope is narrow
enough to be safe unattended):

```json
"security": {
  "prSuggestions": { "enabled": true }
}
```

Or via env var: `PR_SUGGESTIONS_ENABLED=false`.

## Inbound alert-dismissal sync (GitHub → Ignite)

The SARIF upload above creates GitHub Code Scanning alerts, and Ignite
already pushes the other way too: `github-check`'s `syncDismissals` dismisses
a GitHub alert automatically once someone justifies the same finding as an
override in Ignite. Left on its own, that's one-directional — a human who
instead dismisses (or reopens) the alert directly in GitHub's **Security →
Code scanning** UI has no way to tell Ignite, so the next gate check keeps
treating the finding as an unapproved open issue.

`POST /api/webhooks/github/code-scanning` closes that gap: register a
webhook on the repo (or org) for `code_scanning_alert` events pointing at
that URL, set a shared secret, and set the same value as
`CODE_SCANNING_INBOUND_WEBHOOK_SECRET` on the Ignite server. A `dismissed`
delivery records a matching Ignite override (justification drawn from
GitHub's own dismissal reason/comment) and immediately flips the issue to
`overridden`; a `reopened` delivery removes that override and flips it back
to `open` — unless a separate, human-entered Ignite override already covers
the same finding, which is left untouched.

Matching a webhook's `alert` back to an Ignite issue uses the same rule-id +
file + line match `syncDismissals` uses in the outbound direction — GitHub's
alert payload doesn't carry Ignite's own issue id.

The endpoint verifies GitHub's `X-Hub-Signature-256` header against the
configured secret and 404s when no secret is set, so an unconfigured
deployment never exposes an unauthenticated write path. There is no
config.json toggle for this — presence of
`CODE_SCANNING_INBOUND_WEBHOOK_SECRET` is the on/off switch, since the
secret itself has to be set for the endpoint to do anything either way.

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

Ignite does close the adjacent, narrower gap — a secret that's *already*
been pushed, then removed in a later commit, sitting exposed in git
history in the meantime. Set `security.gitleaks.scanHistory: true` (or
`GITLEAKS_SCAN_HISTORY=true`) to have the secrets check also run
`gitleaks detect` against full commit history, not just the current
working tree, tagging anything it finds there `gitleaks-history` so it's
distinguishable from a still-present working-tree secret. Off by default
— a full-history scan costs meaningfully more time than a working-tree
scan on a repo with a long history — and a no-op on a checkout with no
`.git` directory (an uploaded ZIP). This still isn't push-protection: it
finds an already-exposed secret after the fact rather than blocking the
push that introduced it, which is exactly why push-protection itself stays
worth keeping regardless.

## Custom secret patterns: playground + retroactive sweep

GHAS lets an org author its own secret-detection regex ("custom
patterns"), try it out against sample text before publishing it, and
optionally sweep existing history for matches. `/api/secret-patterns`
covers the first and third of those:

```bash
# Try a pattern against sample text — no auth, nothing saved.
curl -X POST http://ignite.internal:51337/api/secret-patterns/test \
  -H 'Content-Type: application/json' \
  -d '{"regex": "acme_live_[a-zA-Z0-9]{24}", "sample": "token: acme_live_abcdef0123456789ghijklmn"}'

# Save it once you're happy with it.
curl -X POST http://ignite.internal:51337/api/secret-patterns \
  -H 'Content-Type: application/json' \
  -d '{"name": "Acme internal token", "regex": "acme_live_[a-zA-Z0-9]{24}"}'
# → { "id": 1, "name": "Acme internal token", ... }

# Retroactively sweep a repo's full git history for it.
curl -X POST http://ignite.internal:51337/api/secret-patterns/1/sweep \
  -H 'Content-Type: application/json' -H 'Authorization: Bearer ignite_...' \
  -d '{"owner": "my-org", "repo": "my-repo"}'
```

The sweep clones the repo with **full history** (not the shallow clones
Ignite uses everywhere else) and runs it through the same
`run_gitleaks_history_scan` engine [git-history secret scanning](#keep-githubs-secret-push-protection-even-without-full-ghas)
already uses, with a throwaway gitleaks config carrying just this one
pattern (plus gitleaks' own built-in rules) — answering "would this
pattern, if it had existed from day one, have caught something already
committed and possibly since removed?"

**Not yet wired into live scans**: saving a pattern here doesn't
currently make it apply automatically to every future scan the way a
published GHAS custom pattern does — today this is the test-and-sweep
half, not forward detection. Pair it with a periodic re-sweep (cron) of
your onboarded repos as a stopgap.

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

An org-wide form covers every repo in an org — including ones created
*after* the tool runs — via GitHub's newer Repository Rulesets, rather
than needing to be re-run per repo:

```bash
./target/release/enforce-gate-branch-protection --org my-org --apply
```

### Org ruleset drift detection

Applying the org ruleset once only guarantees policy at that moment — an
org admin can still loosen it afterwards directly in GitHub's own UI
(drop the required `ignite/gate` check, add a bypass actor, delete a
rule), and the one-shot form above has no way to notice until someone
happens to re-run it. `--check-drift` turns it into a continuous check:
it fetches each `--org` target's *current* ruleset, diffs it against
policy, and reports every divergence — read-only by default, or paired
with `--apply` to also reconcile whatever's drifted:

```bash
# Report only — never mutates.
./target/release/enforce-gate-branch-protection --org my-org --check-drift

# Report and reconcile any drift found.
./target/release/enforce-gate-branch-protection --org my-org --check-drift --apply
```

The exit code is what a cron/CI caller actually watches: `0` means every
target org's ruleset already matches policy, `2` means at least one has
drifted (even if `--apply` just fixed it — a caller alerting on drift
wants to know it *happened* this run), `1` means a lookup or apply error.
Run it on a schedule (cron, or a scheduled GitHub Actions workflow the
same way [scheduled re-scans](#scheduled-re-scans--dependabot-equivalent-continuous-coverage)
are) to get continuous enforcement rather than a point-in-time check.

## Private vulnerability reporting

GHAS lets a maintainer privately draft a Security Advisory to coordinate a
fix before public disclosure. Ignite's own [`auto-fix-pr`](#auto-opening-a-fix-pr-for-what-it-finds)
does the opposite by design — it goes straight to a public fix PR the
moment it finds a safe, single-version-bump fix — so it can't cover this
case, and deliberately shouldn't: whether a finding needs private
coordination at all is a judgment call, not something a scan should decide
unattended.

`report-vulnerability` (`rust/crates/report-vulnerability`) is a separate,
always-manual CLI for exactly that judgment call. Same dry-run-by-default
convention as `enforce-gate-branch-protection`:

```bash
# Prints the exact gh api call it would make, plus the JSON body — no changes made.
./target/release/report-vulnerability my-org/my-repo \
  --summary "SQL injection in query builder" \
  --severity high \
  --ecosystem npm \
  --package acme-query-builder \
  --vulnerable-range "< 2.1.0" \
  --patched 2.1.0 \
  --cwe CWE-89

# Actually creates the draft advisory.
./target/release/report-vulnerability my-org/my-repo \
  --summary "SQL injection in query builder" \
  --severity high \
  --ecosystem npm \
  --package acme-query-builder \
  --vulnerable-range "< 2.1.0" \
  --apply
```

`--severity` is one of `critical`/`high`/`medium`/`low`; `--patched`,
`--description`, and repeated `--cwe` flags are optional. On success it
prints the created advisory's GHSA id and URL. Never wired into any
scan/pipeline path — an operator runs it deliberately once they've decided
a finding warrants private coordination.
