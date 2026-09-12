---
title: What's New
sidebar_position: 10
---

# What's new

Ignite has grown from a one-time onboarding gate into an ongoing governance
platform: findings don't just get caught at intake, they're tracked,
cross-checked, and kept in sync with GitHub for the life of the repo.

## Security campaigns

A named, org-wide "burn down every open issue matching this filter by this
date" tracker (`POST /api/campaigns`, Governance nav-rail in the UI). Pick a
category and a minimum severity score, set a target date, and Ignite
snapshots how many currently-open issues match across every onboarded repo.
From then on, progress is always `initial count − live count of issues
still matching`, recomputed on every view — so it never drifts out of sync
with overrides or fixes landing after the campaign was created. Turns "we
should really fix our IaC misconfigurations" into a trackable initiative
with a live progress bar, not a one-off Slack thread.

Pairs with **compliance audit packs**
(`GET /api/compliance/audit-pack?from=...&to=...`): one export bundling
overrides-by-severity, mean-time-to-resolution, and a live SLA-breach
snapshot for any date range — evidence for a SOC 2, ISO 27001, or board
review, generated on demand instead of assembled by hand.

## AI-assisted dependency validation

A **✨ Validate with AI** button on Ignite Studio's Dependencies view
sends the resolved dependency list — name, version, license, compliance
tier, and the reason the automated scanner assigned it — to the configured
LLM to sanity-check the classification. The AI is asked to flag only
entries it's genuinely confident are misclassified (a license the
built-in classifier doesn't recognize yet and defaults to "risk," a
copyleft license miscategorized as permissive, a package/version that
doesn't plausibly exist), and reports back a short summary plus any
flagged package — a second opinion before a license question reaches a
human reviewer as a false alarm.

See [How It Works](./how-it-works#4-studios-other-views--dependencies-sbom-loc-posture)
for where this sits in the Studio dependency view.

## Live GitHub webhook sync

Ignite's own record of a repo now stays current between scans instead of
only reflecting whatever the last scan saw:

- A human **dismissing or reopening** a code-scanning alert, or a
  **secret-scanning alert**, directly in GitHub's UI is reflected in
  Ignite's issue list immediately — the next gate check treats it exactly
  as if the same action had been taken in Ignite.
- A **push-protection bypass** (a developer pushing a recognized secret
  anyway, with a justification) is logged as a critical audit event the
  moment it happens, with an optional auto-filed GitHub issue.
- A **newly created or transferred repository** is enrolled and can be
  automatically protected (org ruleset + baseline scan) with no manual
  onboarding step.

## Active secret verification (multi-cloud)

A gitleaks/built-in secret finding is a syntactically-valid pattern match —
it doesn't tell you whether the credential is still live or already dead.
GHAS's secret-scanning partner program closes that gap by pinging the
issuing provider; Ignite now does the same, off by default. When enabled,
each secret finding is matched against its own provider (by gitleaks' rule
id) and checked read-only against a real endpoint: GitHub (`GET /user`),
AWS (a real SigV4-signed `sts:GetCallerIdentity`), GCP API keys, Slack,
Stripe, OpenAI, Anthropic, npm, and Datadog. A verified-live finding gets
`" — VERIFIED LIVE"` appended to its category so it stands out from a
finding that might already be dead. Every check is non-destructive and
never logs the raw credential value.

Off by default — sending a credential found in scanned code to a
third-party API is an operator's explicit call, not something a static
scan should opt into silently:

```json
"security": {
  "secretVerification": { "enabled": false, "timeoutMs": 5000 }
}
```

Or via env var: `SECRET_VERIFICATION_ENABLED=true`.

Azure and PyPI are deliberately unsupported: Azure Storage keys sign
against a per-customer subdomain with no way to verify a signing
implementation without a real account to test against, and PyPI has no
read-only "check this token" endpoint at all — only the actual
package-upload endpoint, unsafe to probe.

## Transitive dependency reachability

A `dependency-vulnerability` finding for a package that's merely sitting
unused in a lockfile carries the same weight today as one for a package
genuinely wired into the project. Ignite now annotates (never re-scores)
findings with a reachability hint using lightweight, regex-based source
scanning:

- **npm, Python, Rust** — import-level: is the flagged package actually
  imported/referenced anywhere in source? A finding for a package that
  isn't gets `[not directly imported in project source]`.
- **Go** — function-level, one step more precise: Go's own vulndb is the
  only one of these that reliably names the exact vulnerable function(s) in
  the advisory data, so a Go finding can additionally get
  `[vulnerable function(s) not called: X, Y]` when the flagged package is
  imported but the specific vulnerable symbols are never called.

Java/Maven and Rust method-level reachability are deliberately not
attempted — both would require either type inference or an unreliable
artifact-to-package name mapping, and a wrong "not reachable" annotation is
worse than no annotation at all.

## Continued hardening

Alongside the above, this cycle also tightened audit-trail attribution
(actions are now always attributed to the authenticated caller, never a
client-supplied identity field), added authentication checks to a handful
of routes that were missing them, closed a path-traversal gap in the
auto-fix engine, moved GitHub tokens out of visible process arguments, and
fixed a license-classification gap that misreported a well-known
permissive license (PSF-2.0) as commercial risk.
