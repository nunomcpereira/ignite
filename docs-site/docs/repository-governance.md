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

The reporting endpoints support the same evidence outside the console:

```text
POST /api/reports/daily/run
GET  /api/reports/daily/pdf?org=acme
GET  /api/reports/daily/markdown?org=acme
```

The PDF endpoint creates the same per-organization report as the scheduled
delivery. It needs Chrome, Chromium, or Edge on the Ignite host (or
`dailyReport.pdfBrowserBinary` in `config.json`). The Markdown endpoint
exports each repository's open findings in Ignite's
`.ignite/acknowledgments.md` format, ready for an engineer to add a
justification and submit through the normal review path.

## Keep GitHub and Ignite aligned

GitHub webhooks can keep the records current between scans: code-scanning and
secret-scanning alert dismissals or reopenings, push-protection bypasses, and
repository creation or transfer events all feed the audit trail and the
repository's issue state. Repository events can also enroll a new repository,
apply the configured organization ruleset, and start its baseline scan.

For setup details, including scheduled rescans, branch protection, native
SARIF/dependency-graph publication, and private advisory handling, see
[CI integration](./ci-integration).
