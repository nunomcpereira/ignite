# Ignite for VS Code

Runs Ignite's compliance/security pipeline against the currently open workspace folder and surfaces findings natively — Problems panel diagnostics, a Findings tree, a Tools Status tree, and an Output channel — for people who don't want the separate web UI (`public/index.html`).

Thin client only: no scanning logic lives here. Every check runs on a locally running Ignite server (`npm start` in the `ignite` repo root, default `http://localhost:51337`) via `POST /api/pipeline/validate-all`.

## Requirements

- A running Ignite server reachable at `ignite.baseUrl` (default `http://localhost:51337`).
- The workspace folder you have open is what gets scanned — there's no upload/picker flow.

## Commands

- **Ignite: Scan Workspace** — runs phases 1–5 (Phase 5/org-governance-CI only if `ignite.runLocalCi` is on) against the open folder. Results land in the Problems panel, the Findings tree, and the Output channel.
- **Ignite: Install Pre-Push Hook** — installs Ignite's own `hooks/pre-push` script into this repo's git hooks, so `git push` gets the same gate as the manual scan.
- **Ignite: Open Review File** — opens `.ignite-review.md`, the same append-only justification file the pre-push hook reads/writes. Fill in `Acknowledge:` for a blocking finding, rescan (or push) to have it resubmitted as an attributed override.
- **Ignite: Refresh Tools Status** — re-probes the 13 optional external tools (trivy, semgrep, bearer, codeql, …) in the Tools Status tree.

## Settings

| Setting | Default | Notes |
|---|---|---|
| `ignite.baseUrl` | `http://localhost:51337` | Matches `IGNITE_BASE_URL`. |
| `ignite.runLocalCi` | `false` | Phase 5 (act + Docker) — off by default in the extension since it's the slowest phase. |
| `ignite.showOverriddenIssues` | `false` | Show already-acknowledged issues as dimmed diagnostics instead of hiding them. |

## Development

```bash
npm install
npm run watch   # or: npm run compile
```

Press `F5` (or Run → Start Debugging) to launch an Extension Development Host with this extension loaded, against whatever folder you open in it. Requires `npm start` running in the `ignite` repo first.
