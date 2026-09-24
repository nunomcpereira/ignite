---
title: VS Code extension
sidebar_position: 9
---

# VS Code extension — scan without leaving the editor

A thin-client extension that runs Ignite's `validate-all` pipeline against
the open workspace folder and surfaces findings natively — Problems panel
diagnostics, a Findings tree, a Tools Status tree, and an Output channel —
for people who'd rather not use the web UI. No scanning logic lives in the
extension itself: every check still runs on an Ignite server, either on
your machine or a shared remote one. Works with VS Code, Cursor, or VS Code
Insiders.

## Prerequisites

- A running Ignite server, reachable at the URL configured in
  `ignite.baseUrl` (default `http://localhost:51337`):
  ```bash
  cd rust && cargo build --release -p ignite-server
  IGNITE_CONFIG_DIR=.. ./target/release/ignite-server
  ```
- The `code` (or `code-insiders` / `cursor`) CLI on your `PATH`. If `code`
  isn't found, run **Shell Command: Install 'code' command in PATH** once
  from the Command Palette, then retry.

## Install

Clone the repo (or use an existing checkout) and run the bundled install
script from the `vscode-extension/` directory:

```bash
git clone https://github.com/nunomcpereira/ignite.git
cd ignite/vscode-extension
./install.sh
```

This builds the extension and installs it as a real (non-debug) extension
via a packaged `.vsix` — it detects whichever of `code` / `code-insiders` /
`cursor` is on your `PATH`. **Reload the window** afterward to activate it.
Rerun `./install.sh` any time to pick up a newer version — it reinstalls
over whatever's currently installed.

### Installing a pre-built `.vsix` on another machine

If you already have a packaged `.vsix` (or want to hand one to a teammate
without them cloning the repo), skip the build step:

```bash
code --install-extension ignite-vscode.vsix
```

To produce that `.vsix` yourself from a checkout:

```bash
cd vscode-extension
npx @vscode/vsce package --allow-missing-repository --skip-license -o ignite-vscode.vsix
```

### Installing from within the editor's UI

`code --install-extension` also accepts a local path from the Command
Palette's **Extensions: Install from VSIX...** action — pick the
`ignite-vscode.vsix` file produced above.

## After installing

Open the **Ignite** icon in the activity bar. The **Overview** panel at the
top is the extension's home screen; if your server isn't the default
`http://localhost:51337`, set its URL there (below), then click
**Scan workspace**.

## The Overview panel

![VS Code - Ignite Overview panel with the last scan's result](/img/screenshots/18-vscode-overview.png)

- **Connection** — a green/red dot with the server, its response time and
  auth mode, and who your API key signs in as. When the server can't be
  reached it says why (connection refused, timeout, host not found), and
  the status bar turns into an `offline` shortcut straight back to the
  server settings.
- **Scan** — *Scan workspace*, *Changed files* (full scan, findings limited
  to uncommitted files) and *Folder…* (any folder, even with no workspace
  open; also on right-click in the Explorer as **Ignite: Scan Selected
  Folder**). The panel says whether scans send a path or upload the folder
  (see below).
- **Last scan** — *Passed* / *Blocked* / *Failed* with blocking, warning and
  acknowledged counts, when it ran and how long it took, plus shortcuts to
  the review file, *Generate fix PR* and the Output channel. While a scan
  runs it shows the current phase and elapsed time.
- **Reports** and **Workspace** — license compliance, SBOM, LOC metrics,
  compliance posture, the org daily report, the pre-push hook, the
  acknowledgments file and the scanner tools list, one click each.

### Server URL and API key

![VS Code - server URL and "Sign in & create key"](/img/screenshots/19-vscode-server-and-api-key.png)

Expand **Server** to change the URL (*Save & connect*, *Test* without
saving, *Reset to default*). Input like `localhost:51337` works without
`http://`, and an invalid URL is rejected with the reason. The value is
written to the `ignite.baseUrl` setting for you.

The **API key** is optional unless your server requires sign-in (for
example, it refuses Tools Status or scans without one). It's stored in your
OS keychain, never in `settings.json`, and you can get one without leaving
the editor:

- **Sign in & create key** (standalone Ignite accounts) — enter your Ignite
  email and password. The extension signs in, creates a **30-day** key named
  after this machine, signs out again and keeps only the key. Your password
  is never stored.
- **OIDC / GitHub sign-in** — *Create a key in the web UI* opens the web
  UI's [API keys view](#api-keys-in-the-web-ui); paste the key back into the
  panel.

When a key has expired or been revoked, the panel says so and offers to
create a new one.

### Scanning against a remote server

A server on another machine can't read your disk, so `ignite.scanMode`
(`auto` by default) decides how a scan reaches it:

| Server | What the extension does |
| --- | --- |
| `localhost` / `127.0.0.1` | Sends the folder **path** to `POST /api/pipeline/validate-all` (the server reads it from disk). |
| Anything else | **Uploads** the folder — git-tracked and untracked files, `.gitignore` respected (outside git: skips `node_modules`, `target`, `dist`, …) — to `POST /api/pipeline` as a `dryRun` simulation. It never provisions or pushes. |

In upload mode the extension answers the server's review gate with the
justifications in `.ignite/acknowledgments.md`, then shows the result exactly
like a local scan (Problems panel, Findings tree, review file). Set
`ignite.scanMode` to `path` or `upload` to force one. Uploads are capped at
1250 MB and 100,000 files. For unauthenticated uploads the server needs
`security.allowUnauthenticatedInteractiveDryRun` (or
`ALLOW_UNAUTHENTICATED_INTERACTIVE_DRY_RUN=true`); path scans need
`security.allowUnauthenticatedValidateAll`. If a reverse proxy sits in front
of the server, let it accept large, long-running requests.

## API keys in the web UI

Keys are managed in the web UI under the profile menu (the person icon, top
right) → **API keys**, or at `/#api-keys`:

![Profile menu - API keys link](/img/screenshots/21-profile-api-keys-link.png)

![API keys view - create, list, revoke](/img/screenshots/20-api-keys-view.png)

- **Create** — a label and a lifetime: 1, 7, 30 (default) or 90 days. The
  key is shown once, with its expiry; Ignite stores only its hash.
- **List** — active keys first, with created, last used, expiry and a
  status badge (*Active*, *Expiring soon*, *Expired*, *Revoked*).
- **Revoke** — takes effect on the next request.

These self-service keys always expire. An expired key is refused
everywhere, exactly like a revoked one. Operators can still mint
non-expiring keys for CI on the server host with `create-api-key` (see the
[README](https://github.com/nunomcpereira/ignite#api-keys-headlessagent-auth)).

## Settings

| Setting | Default | |
| --- | --- | --- |
| `ignite.baseUrl` | `http://localhost:51337` | Editable from the Overview panel. |
| `ignite.scanMode` | `auto` | `auto` = path for localhost, upload otherwise; `path` / `upload` force one. |
| `ignite.runLocalCi` | `false` | Phase 5 (act + Docker); path scans only. |
| `ignite.showOverriddenIssues` | `false` | Show acknowledged findings as dimmed diagnostics. |
| `ignite.apiKey` | `""` | Plaintext fallback; a keychain key set from the Overview panel wins over it. |

## Using it

Run **Ignite: Scan Workspace** (or use the Overview panel). See [How it works](./how-it-works#6-or-scan-straight-from-vs-code--no-upload-no-browser)
for what the Findings tree, Problems panel, and other commands do, and the
[extension's own README](https://github.com/nunomcpereira/ignite/tree/main/vscode-extension#readme)
for the full settings/commands reference.

## Uninstall

Command Palette → **Extensions: Show Installed Extensions**, find **Ignite**,
click the gear icon → **Uninstall** (or `code --uninstall-extension ignite.ignite-vscode`).
