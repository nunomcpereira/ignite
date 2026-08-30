---
title: VS Code extension
sidebar_position: 9
---

# VS Code extension — scan without leaving the editor

A thin-client extension that runs Ignite's `validate-all` pipeline against
the open workspace folder and surfaces findings natively — Problems panel
diagnostics, a Findings tree, a Tools Status tree, and an Output channel —
for people who'd rather not use the web UI. No scanning logic lives in the
extension itself: every check still runs on a locally running Ignite
server. Works with VS Code, Cursor, or VS Code Insiders.

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

Point the extension at your Ignite server if it isn't the default (Command
Palette → **Preferences: Open Settings** → search `ignite.baseUrl`), then
run **Ignite: Scan Workspace**. See [How it works](./how-it-works#5-or-scan-straight-from-vs-code--no-upload-no-browser)
for what the Findings tree, Problems panel, and other commands do, and the
[extension's own README](https://github.com/nunomcpereira/ignite/tree/main/vscode-extension#readme)
for the full settings/commands reference.

## Uninstall

Command Palette → **Extensions: Show Installed Extensions**, find **Ignite**,
click the gear icon → **Uninstall** (or `code --uninstall-extension ignite.ignite-vscode`).
