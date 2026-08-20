---
title: Getting started
sidebar_position: 5
---

# How to start it

## Prerequisites

- **Node.js ≥ 22**
- **git** on `PATH`
- **A way to authenticate to GitHub** — `gh` CLI is the easy path:

  ```bash
  gh auth login
  gh auth status   # must show a logged-in account with repo-create permission
  ```

  but it's a soft dependency, not a hard one — see below.

## Run it

```bash
git clone https://github.com/nunomcpereira/ignite.git
cd ignite
npm install
npm start
# → http://localhost:51337
```

That's it — open `http://localhost:51337`, drop a ZIP or folder onto the drop
zone, and run the pipeline. Every external tool (Trivy, Semgrep, gitleaks,
GuardDog, ...) is an optional soft dependency — Ignite works out of the box
with none of them installed, falling back to a built-in check where one
exists. The local LLM deep-scan needs a llama.cpp-compatible endpoint at
`LLM_SCAN_URL` (default `http://localhost:8050`); if it's unreachable, that
one check is skipped with a warning rather than failing the run.

## Want every check actually running, not falling back?

One script installs all fourteen optional tools (ORT, licensee, gitleaks,
Trivy, Checkov, hadolint, Syft, cosign, Semgrep, Bearer, GuardDog, jscpd,
gocloc, Spectral) plus `act`, instead of copy-pasting `brew`/`npm`/`pip`/`gem`
commands one at a time:

```bash
curl -fsSL https://raw.githubusercontent.com/nunomcpereira/ignite/main/scripts/install-tools.sh | bash
```

Idempotent — safe to re-run any time, it only installs what's still
missing. macOS (Homebrew) is the primary target, matching every install
command in the README exactly; skip an individual tool with
`INSTALL_<TOOL>=false` (e.g. `INSTALL_GUARDDOG=false`). Docker itself isn't
installed for you (it needs its GUI installer) — the script just flags it
if missing, since Phase 5 and the multi-language unit-test runner both
depend on it.

:::danger[Security note]
This server executes `git`/`gh` with the host machine's credentials. Run it
locally or behind authentication — never expose it unauthenticated to a
network.
:::

## Pushing over HTTPS (gh) or SSH

By default Phase 6 pushes over `https://github.com/...`, authenticated
through `gh auth git-credential` using the connected account's token. Set
`GITHUB_REMOTE_PROTOCOL=ssh` to push over `git@github.com:...` instead,
authenticated by whatever SSH key/agent is already configured for
`github.com` on this machine — no git credential helper involved. Either
way, repo creation/auto-merge/ref creation still go through the GitHub
API — SSH replaces the **push transport**, not API auth, so a GitHub token
is required in both modes.

## Don't want `gh` installed at all?

Every plain GitHub API call (repo creation, PR open/auto-merge/checks,
issue filing, cloning) is a soft dependency, same pattern as the scanning
tools: Ignite probes for `gh` once and transparently falls back to calling
the GitHub REST/GraphQL API directly over HTTPS with a token when it's
missing. Per-onboarding-request calls already have a token via the
connected account, no extra config needed. Server-level calls with no
per-request user — fetching the governance workflow, cloning/filing issues
for a scheduled re-check — need `GH_TOKEN` or `GITHUB_TOKEN` set to a
personal access token instead. Combine with `GITHUB_REMOTE_PROTOCOL=ssh`
for a host with no `gh` binary at all.
