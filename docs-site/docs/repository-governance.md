---
title: Repository governance
sidebar_position: 5
---

# Repository governance

Ignite continues to govern a repository after its first onboarding run. The
web console groups that work into **Onboarded Repos**, **Governance**, and
**GitHub Org** so teams can see the current state, direct remediation work,
and retain evidence without treating a one-time scan as a permanent result.

## Review, justify, and repair findings

The **Flagged Issues** view is available from a finished run, history, an
onboarded repository, or an organization scan. Open findings can be justified
from that view with a reason. Ignite records the authenticated actor, time,
and reason in the audit trail; critical overrides can require a second
reviewer according to the configured approval policy.

For a repository already on GitHub, **Generate fix PR** uses the same
AI-assisted suggestion flow as Studio, shows every proposed change for review,
and opens a single PR containing only the selected fixes. Previously justified
findings can be included as acknowledgments, so the PR documents both the
code change and the accepted risk decision.

This is separate from `auto-fix-pr`: the interactive flow is human-started
and can propose fixes for eligible findings; the unattended flow only updates
dependency vulnerabilities with a safe, non-major version bump discovered
during a scheduled rescan.

## Decide who can scan, review, publish and view

Permission grants give a person a right on every repository, on one
organization, or on one repository: `view`, `scan`, `review`, `publish` or
`policy_admin`. Manage them in **Settings (gear icon) → Permission grants**
or through `GET`/`POST /api/policy/grants` and `DELETE /api/policy/grants/:id`.

- A policy admin manages grants at the scope their own `policy_admin` grant
  covers: a global admin manages everything, an organization admin manages
  that organization's grants, a repository admin only that repository's.
- The first admin comes from `config.json`: every email in
  `security.policyAdmins` (`POLICY_ADMINS`) gets a global `policy_admin`
  grant at startup. Removing an email from that list never revokes a grant.
- Every grant and revocation is written to the audit log
  (`policy.grant_created`, `policy.grant_revoked`).
- An API key acts as its owner and can never exceed the owner's grants. A
  key limited to specific scopes can't manage grants at all.

`review` grants always apply (they decide who may approve a critical
override). `scan`, `publish` and `view` only apply once
`security.enforceGrants` (`ENFORCE_GRANTS`) is `true`; it's off by default
so an existing installation behaves exactly as before. With enforcement on:

| Permission | Required for |
|---|---|
| `scan` | `validate-all`, onboard, interactive upload |
| `publish` | real (non-dry-run) onboard and upload, effectivate, applying a fix PR |
| `view` | project and job details, findings, history, evidence; the project list shows only repositories you can view |

A refusal is a `403` with `code: "permission_denied"` (or `grant_required`
when nobody is signed in) and the missing `requiredPermission`. Scans the
server starts itself (organization scans, auto-rescan) aren't affected.

## Teach Ignite which findings are noise

Every finding in Studio has **False positive** / **Real issue** buttons. A
verdict is recorded against the finding's engine and rule
(`POST /api/pipeline/:jobId/issues/:issueId/verdict`) and feeds two things in
**Settings (gear icon) → Rule tuning**:

- **Noisiest rules** — per engine rule: false-positive and real-issue
  verdicts, how many findings people overrode, and how many repositories it
  hits (`GET /api/policy/rule-noise`).
- **AI rule proposals** — **Ask AI for proposals** sends the free-text
  justifications people wrote when overriding findings, grouped by rule, to
  the configured LLM (`llm.provider`), which proposes ignore rules where many
  justifications say the same thing (test fixtures, generated or vendored
  code, a known-safe wrapper). Ignite keeps a proposal only if its regexes
  compile, it isn't a catch-all, and it cites at least two real overrides.
  Each shows its reason, the AI's rationale, the justifications it is based
  on, and how many open findings it matches today. Nothing applies until a
  policy admin accepts it; an accepted proposal works like a `config.json`
  `ignoreRules` entry (matched findings stay visible, acknowledged with the
  rule's reason) and can be disabled again. Accepting, dismissing and
  disabling are audit-logged.

Optionally, `security.fpLearning.enabled` (`FP_LEARNING_ENABLED`, off by
default) stops a rule from blocking in an organization once it has
`minVerdicts` (default 3) false-positive verdicts there and no real-issue
verdict; its findings are still reported, as warnings with a note.

## Acknowledge known false positives by policy

Some findings are benign across a whole organization — for example SAP CPI
packages whose `*_Credential_Name=` lines hold credential *alias names*, not
secrets. Instead of every team justifying the same line in every repository,
an operator declares the exception once in `config.json`'s `ignoreRules`,
scoped by organization, repository, file, and flagged line:

```json
"ignoreRules": {
  "acme-corp": {
    "sap-*": [
      {
        "filePatterns": ["^Preparations? Steps/", "(^|/)parameters\\.prop$"],
        "linePatterns": ["^\\s*[A-Za-z0-9_]*Credential[A-Za-z0-9_]*\\s*=\\s*[A-Za-z0-9_.-]+\\s*$"],
        "categories": ["secret"],
        "reason": "SAP CPI *Credential* parameters hold security-material alias names, not secrets"
      }
    ]
  }
}
```

- Organization and repository keys are case-insensitive and accept `*`
  wildcards (`"*"` for every repository of the org, or every org).
- `filePatterns` are regular expressions matched against the repo-relative
  path; `linePatterns` are matched against the flagged source line itself.
  Leave `linePatterns` empty to cover a whole file; `categories` is optional
  (empty means any category). A rule with neither pattern list, or an invalid
  regex, is skipped and logged, never fatal.
- A matched finding is **not hidden**. It stays in the results, but is
  recorded as acknowledged with the rule's `reason` as its justification
  (actor `ignore-rules@ignite.internal`, origin `config_rule`), so it no
  longer blocks the gate. The repository shows as passing, the Findings
  count still includes it (violet with a ✓ when every finding is
  acknowledged), and Studio and the findings viewer show the reason with an
  **⚙ Org rule** badge.
- Policy acknowledgments are never carried forward on their own: remove or
  narrow a rule and the next scan flags those findings again. Rule changes
  apply after a server restart and take effect on each repository's next
  scan.

Rules apply to Phase 4 findings on every scan path — validate-all (CLI,
pre-push hook, organization scans, scheduled rescans), onboarding, and the
interactive upload. Phase 3 license and dependency findings are not matched.

## Track the repository portfolio

**Onboarded Repos** keeps one current row for every repository Ignite has
scanned. It shows the latest run's open findings and license issues, all
acknowledgments recorded for the repository, recent onboarding and fix PRs,
and the latest scan time.

**GitHub Org** is the backfill and continuous-coverage workspace. Connect an
organization to list its repositories, include archived repositories or forks
when needed, choose the repositories to cover, and start a scan for one or
many of them. The selected set is saved for the automatic-rescan endpoint;
trigger that endpoint from your scheduler, and it only rescans repositories
whose last scan is older than the configured threshold.

![GitHub organization repository portfolio](/img/screenshots/17-org-repository-portfolio.png)

Each organization is a collapsible parent row with its repositories nested
beneath it. Filter chips above the table narrow the list to **Errors** (scan
failed or could not run), **Aborted**, or **Empty** repositories, with a live
count on each. The **Scan queue** panel on the right edge lists running and
waiting scans with the full repository name.

The screen is designed for an organization that already has repositories on
GitHub before Ignite is introduced. A scan started here becomes an ordinary
Ignite run and appears in the existing history and Onboarded Repos views.

## Run remediation as a campaign

The **Governance** workspace has three views:

- **Campaigns** creates a category and minimum-score target with a due date.
  Ignite snapshots the matching open-finding count, then calculates progress
  from the live issue state as fixes and justifications arrive.
- **Compliance** creates a date-bounded audit pack with override totals,
  mean time to resolution, and the current SLA-breach snapshot. The result
  can be downloaded as JSON.
- **Audit Log** filters the tamper-evident event trail by organization,
  repository, event type, severity, and time. It can verify the hash chain,
  download the visible events, and retrieve an attached compressed scan log
  when one is available.

![Governance campaign progress](/img/screenshots/16-governance-campaigns.png)

## Deliver daily evidence

The daily report groups every repository's latest unjustified findings by
organization. Administrators configure its schedule and destinations from the
console's **Settings** menu. Delivery can use email, an HTTPS webhook,
Microsoft Sentinel, and Azure Blob Storage; configuration secrets are stored
server-side and test delivery is available before the schedule is enabled.

Each finding names its owner: the person who last changed the flagged line
(`git blame`), not the repository's latest committer. Reports list it per
finding, and the Microsoft Sentinel payload carries it on every finding plus
an `owners` rollup (findings count, highest score and repositories per
person), so a Logic App can assign or route incidents per owner. Scans of a
shallow clone (organization scans, scheduled rescans) look the line up
through GitHub's blame API; results are cached per file version, so a file
that hasn't changed is never looked up again, and each scan stays within a
configurable share of the GitHub API budget (`blame` in `config.json`).

The reporting endpoints support the same evidence outside the console:

```text
POST /api/reports/daily/run
GET  /api/reports/daily/pdf?org=acme
GET  /api/reports/daily/markdown?org=acme
```

The PDF endpoint creates the same per-organization report as the scheduled
delivery. It uses WeasyPrint when installed (the Docker image includes it),
otherwise Chrome, Chromium, or Edge on the Ignite host. Setting
`dailyReport.pdfBrowserBinary` in `config.json` forces that browser. The Markdown endpoint
exports each repository's open findings in Ignite's
`.ignite/acknowledgments.md` format, ready for an engineer to add a
justification and submit through the normal review path.

### Per-organization report schedules

`orgReports` in `config.json` emails each organization's findings report on
its own cron schedule. The org key matches case-insensitively; a `*` wildcard
key applies to every organization saved in the GitHub Org view that matches it,
and an exact key overrides a wildcard.

```json
"orgReports": {
  "acme":  { "cron": "0 8 * * MON", "recipients": "admins", "to": ["security@acme.com"] },
  "sap-*": { "cron": "0 7 * * 1-5", "recipients": "fixed",  "to": ["sap-dl@acme.com"] },
  "legacy-org": { "enabled": false }
}
```

- `recipients: "admins"` (the default) sends to the organization's GitHub
  owners, using each owner's public profile email. If no owner email can be
  found (the owner list can't be read, or no owner has a public email), the
  report goes to `to` instead.
- `recipients: "fixed"` sends only to the distribution lists in `to`.
- `cron` has 5 fields (`minute hour day-of-month month day-of-week`) or 6 with
  leading seconds, in the server's local time zone. Default: `0 8 * * MON`.

Reading the owner list needs a token that can see organization members: the
GitHub App (with *Members: read*) or `GH_TOKEN`. Email delivery uses the
`notifications` SMTP settings. Schedules are read-only over the API:

```text
GET  /api/org-repos/report-schedules              # every org a schedule applies to, next run, last result
GET  /api/org-repos/report-schedules/acme/recipients   # who would receive it now
POST /api/org-repos/report-schedules/acme/send         # send now, ignoring the cron
```

## Keep GitHub and Ignite aligned

GitHub webhooks can keep the records current between scans: code-scanning and
secret-scanning alert dismissals or reopenings, push-protection bypasses, and
repository creation or transfer events all feed the audit trail and the
repository's issue state. Repository events can also enroll a new repository,
apply the configured organization ruleset, and start its baseline scan.

For setup details, including scheduled rescans, branch protection, native
SARIF/dependency-graph publication, and private advisory handling, see
[CI integration](./ci-integration).
