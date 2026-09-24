# Ignite for VS Code

Runs Ignite's compliance/security pipeline against the currently open workspace folder and surfaces findings natively — Problems panel diagnostics, a Findings tree, a Tools Status tree, and an Output channel — for people who don't want the separate web UI (`public/index.html`).

Thin client only: no scanning logic lives here. Every check runs on a running Ignite server (`ignite-server`, default `http://localhost:51337`) via `POST /api/pipeline/validate-all`.

## Requirements

- A running Ignite server reachable at `ignite.baseUrl` (default `http://localhost:51337`).
- The workspace folder you have open is what gets scanned — there's no upload/picker flow.

## Install

```bash
./install.sh
```

Builds the extension and installs it into your editor as a real (non-debug) extension via a packaged `.vsix` — works with VS Code, Cursor, or VS Code Insiders, whichever `code`/`code-insiders`/`cursor` CLI is on your PATH (needs "Shell Command: Install 'code' command in PATH" run once from the Command Palette if `code` isn't found). Reload the window afterward to activate it. Rerun `./install.sh` any time to pick up changes — it reinstalls over the previous version.

To build the `.vsix` without installing it (e.g. to hand it to someone else): `npx @vscode/vsce package --allow-missing-repository --skip-license -o ignite-vscode.vsix`, then `code --install-extension ignite-vscode.vsix` on their machine.

## Sidebar

The Ignite activity-bar icon opens three views:

- **Overview** — live connection indicator (latency, auth mode, who the API key signs in as), an editable **server URL** (Save & connect / Test / Reset — no settings.json needed), an **API key** field stored in the OS keychain (VS Code SecretStorage), scan buttons and options, the last scan's result (blocking / warnings / acknowledged, duration), and one-click reports and workspace actions.
- **Findings** — grouped by finding or phase, unresolved and highest-score first, with a blocking-count badge and code-snippet tooltips.
- **Tools Status** — which scanner binaries the server has, installed first.

The status bar item turns red when a scan is blocked and shows `offline` when the server can't be reached (click it to change the URL).

### Getting an API key

Some servers require one (e.g. `/api/tools/status` returns 401 without it).

- **Standalone accounts**: Overview panel → **Sign in & create key**. The extension signs in, creates a key named after this machine, signs out and stores the key in the OS keychain. The password is not saved.
- **OIDC/GitHub sign-in**: **Create a key in the web UI** opens the web UI's **API keys** dialog (`/#api-keys`, also in the account bar). Create a key there, copy it and paste it into the Overview panel.
- **Server admins** can still mint a key for any existing user from the ignite repo root: `cargo run --manifest-path rust/Cargo.toml --bin create-api-key -- you@example.com vscode`.

## Commands

- **Ignite: Configure Server URL…** / **Set API Key…** / **Reconnect to Server** — palette equivalents of the Overview panel's server controls.
- **Ignite: Scan Workspace** — runs phases 1–5 (Phase 5/org-governance-CI only if `ignite.runLocalCi` is on) against the open folder. Results land in the Problems panel, the Findings tree, and the Output channel. Refuses to start a second scan while one is already running, and the reachability probe logs a per-attempt reason (timeout / `ECONNREFUSED` / 5xx body / ...) to the Output channel rather than a flat "isn't reachable" — check there first if a scan won't start.
- **Ignite: Toggle Findings Grouping (Finding / Phase)** — the Findings tree's title-bar icon switches between grouping by phase (original layout) and grouping by finding — every occurrence of the same (category + summary) finding collapsed under one row, unresolved findings sorted first.
- **Ignite: Acknowledge Selected** — right-click a finding group, or select several rows with `Cmd`/`Ctrl`-click, and acknowledge every unresolved occurrence in one prompt (one shared justification), instead of opening the review file and acknowledging each occurrence by hand.
- **Ignite: Install Pre-Push Hook** — installs Ignite's own `hooks/pre-push` script into this repo's git hooks, so `git push` gets the same gate as the manual scan.
- **Ignite: Open Review File** — opens `.ignite/acknowledgments.md`, the same append-only justification file the pre-push hook reads/writes. Fill in `Acknowledge:` for a blocking finding, rescan (or push) to have it resubmitted as an attributed override. Each scan also drops a point-in-time snapshot of every finding at `.ignite/scans/<timestamp>/findings.md`.
- **Ignite: Refresh Tools Status** — re-probes the optional external tools (trivy, semgrep, bearer, codeql, …) in the Tools Status tree.
- **Ignite: Show License Compliance** / **Show SBOM** / **Show LOC Metrics** / **Show Compliance & Feature Posture** — on-demand report panels for the four non-issue Phase 4 artifacts, opened in a webview beside the editor. License compliance reuses the server's existing `POST /api/dependencies/check`; SBOM/LOC/posture call new standalone endpoints (`POST /api/reports/sbom`, `/loc-metrics`, `/posture` — `routes/reports.js` in the repo root) added because the extension only ever calls `validate-all` and has no `jobId`/review-gate state to hang a Studio request off of. Rendered as pretty-printed JSON for v1 (one reused panel per report kind, not a new tab per refresh) — the same underlying data the web UI's Studio buttons render as full tables.

## Settings

| Setting | Default | Notes |
|---|---|---|
| `ignite.baseUrl` | `http://localhost:51337` | Matches `IGNITE_BASE_URL`. Editable from the Overview panel. |
| `ignite.apiKey` | `""` | Plaintext fallback — the Overview panel's keychain-stored key wins over it. |
| `ignite.runLocalCi` | `false` | Phase 5 (act + Docker) — off by default in the extension since it's the slowest phase. |
| `ignite.showOverriddenIssues` | `false` | Show already-acknowledged issues as dimmed diagnostics instead of hiding them. |

## Development

```bash
npm install
npm run watch   # or: npm run compile
```

Press `F5` (or Run → Start Debugging) to launch an Extension Development Host with this extension loaded, against whatever folder you open in it. Requires `ignite-server` running first.

```bash
npm test   # compiles, then runs the node:test suite in dist/*.test.js
```

Unit coverage lives next to the code it tests (e.g. `src/reviewFile.test.ts` for `.ignite/acknowledgments.md` and `.ignite/scans/<timestamp>/findings.md`), not in a separate directory.
