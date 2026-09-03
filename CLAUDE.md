# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Ignite is a compliance gatekeeper for onboarding code into a GitHub org: upload a project (ZIP or folder) via a single-page app, or drive it headlessly (CLI/pre-push hook/MCP), and it runs a multi-phase pipeline — structure audit, secret scan, AI-governance audit, local LLM deep-scan, 20+ Phase 4 security/compliance checks, org governance CI (via `act`), unit tests — provisioning + pushing to GitHub only if every phase passes (or flagged issues are explicitly overridden with justification). Full pipeline/phase/check documentation lives in `README.md` (`../README.md` from `rust/`) and `docs-site/docs/` — read those for the "what does check X actually detect" level of detail; this file covers where things live and how to build/run/test.

## The implementation is 100% Rust — there is no Node code

Everything lives under `rust/` (67 crates). The original Node implementation (`server.js`, `auth.js`, `db-store.js`, `override-engine.js`, `mcp-server.js`, `guidelines-api.js`, `routes/`, `lib/`, `checks/`, `guidelines/`, `bin/`, `test/`) was deleted in `cdf4d9d` (2026-08-30) once the port was structurally complete and its scan-comparison against the Node original (tadone, file:line-exact parity) had already run and passed. The last-known-good Node state is tagged `stable_node_impl` on GitHub if a historical reference is ever needed. `docs-site/`, `vscode-extension/`, and `e2e/` are unaffected (client/tooling, not the server). Don't propose Node commands, `npm`, or Node file paths for anything server-side — there is nothing there to run.

**Crate-to-concept mapping:** almost every `rust/crates/<name>` crate corresponds 1:1 to one Node module/check and says so in its own `lib.rs`/`main.rs` top doc comment (e.g. `ignite-secrets`: "Faithful port of `checks/secrets.js`"). If you're looking for a specific check or subsystem, `grep -rl "Faithful port of" rust/crates/*/src/lib.rs` plus the crate name is almost always faster than guessing — the doc comment names the exact historical Node file for anyone who wants that context, and `rust/MIGRATION_STATUS.md` has a running log of every real behavioral finding/fix made during the port (not just "ported", but where the Rust and Node behavior genuinely diverged and why).

Notable crates:
- **`server`** (bin `ignite-server`) — the axum HTTP server. Routes live in `crates/server/src/routes/*.rs`, one file per endpoint group (`pipeline_validate.rs`, `pipeline_onboard.rs`, `pipeline_interactive.rs`, `sarif.rs`, `github_pr_status.rs`, `studio.rs`, `effectivate.rs`, `baseline.rs`, `runtime_coverage.rs`, `auto_fix.rs`, `issues.rs`, `history.rs`, `config.rs`, `dependencies.rs`, `reports.rs`, `github_annotations.rs`, `tools_status.rs`, `phase_meta.rs`, `job_issues.rs`). Serves the frontend (`../public/`, unchanged single-file SPA) as a fallback static service.
- **`cli`** (bin `ignite`) — `ignite scan [path]`, the CLI wrapper around `POST /api/pipeline/validate-all`.
- **`mcp-server`** (bin `mcp-server`) — MCP tools (`list_guidelines`, `check_guidelines`, `check_project`, `onboard_project`, `resolve_review_decision`, `effectivate_project`, etc.), stdio or HTTP transport.
- **`guidelines-api`** (bin `guidelines-api`) — loopback-only REST equivalent of the MCP guideline tools.
- **`create-api-key`** (bin `create-api-key`) — mints a headless API key for an existing user.
- **`phase4-orchestrator`** — fans out every Phase 4 check concurrently and normalizes results into `override-engine`'s issue shape (the Rust equivalent of `runPhase4Checks`).
- **`override-engine`** — the issue/override model: stable ids, severity scoring, override validation.
- **`db-store`** — the SQLite layer (`ignite.db`).
- **`config`** — `config.json`/env-var loading.
- **`tool-runner`** — every external-tool/`git`/`gh` subprocess invocation, with the same argument-array-only (no shell) sanitization the Node original had via `execFile`.
- **`github-api`** — shared `gh`-CLI-first/token-fallback GitHub operations (clone, PR create, commit status, etc.), used by the server's push path and by the standalone tools below.

## GHAS-bypass hardening (Rust-only, `rust/crates/`)

The pitch for dropping GitHub Advanced Security in favor of Ignite is only true if Ignite actually replaces what GHAS does automatically. Gaps closed so far:
- **`scheduled-rescan`** (`rust/crates/scheduled-rescan`): Dependabot-equivalent continuous coverage. Iterates every onboarded `(org, repo)` in `db-store`'s `projects` table, shallow-clones each one's current GitHub default branch, runs a real `POST /api/pipeline/validate-all` against a running Ignite server, and posts findings back via the existing `POST /api/pipeline/:jobId/github-check` path — only on a non-clean result; a clean scan just logs. HTTP client timeout defaults to 1800s (`IGNITE_SCHEDULED_RESCAN_TIMEOUT_SECS`), sized for real Phase 4 runs (5-16+ min per `rust/MIGRATION_STATUS.md`). Not wired into anything automatically — run by hand/cron/systemd, or a GitHub Actions `schedule:` trigger (example in `docs-site/docs/ci-integration.md`).
- **`auto-fix-pr`** (`rust/crates/auto-fix-pr`): the Dependabot-parity gap `scheduled-rescan` itself leaves open — it detects a newly-disclosed CVE but never proposes the fix the way Dependabot's version-bump PRs do. Standalone CLI, dry-run by default (`--apply` to actually push/open PRs), same convention as `enforce-gate-branch-protection`. For each repo: shallow-clones the default branch, runs the real `dependency-vulnerability` scan (`ignite-dependency-license-scan`), resolves each finding's minimum fixed version via a real OSV.dev API call (deps.dev's own advisory schema, already used by that scan, has no per-package fixed-version field), and opens one PR per safe fix via `ignite-github-api`'s `gh_create_pr`. Deliberately conservative: only single simple version constraints are auto-edited (OR-ranges/wildcards/hyphen-ranges are left for a human), and a fix crossing a semver major version is always skipped, never silently applied. Idempotent via `git ls-remote --heads` on a deterministic per-(ecosystem, dependency, fixed-version) branch name.
- **`enforce-gate-branch-protection`** (`rust/crates/enforce-gate-branch-protection`): standalone CLI, dry-run by default (`--apply` to actually change anything), that requires the `ignite/gate` status check and blocks direct/admin-bypass pushes on a repo's default branch via `gh api` (argument arrays, no shell). Not wired into any pipeline path — an operator runs it deliberately.
- **CodeQL query-suite pinning** (`config.example.json`'s `security.codeql.querySuites`): pinned to explicit query-pack versions instead of an unpinned `security-extended` reference — dropping GHAS means losing GitHub's continuously-updated CodeQL packs, so the ruleset is static until a human re-pins it. `reviewCadenceDays`/`lastReviewedAt` drive a non-blocking server-startup warning (`ignite-config::is_codeql_review_overdue`) when the pin is unset or stale.
- **Doc-only note**: even when dropping the rest of GHAS, keep GitHub's basic secret-scanning push-protection on — it's the one pre-receive capability Ignite's post-hoc scan structurally can't replace (a secret pushed then deleted in a follow-up commit was still exposed in the window between). Flagged as something to verify against the real GitHub bill, not a settled pricing fact. See `docs-site/docs/ci-integration.md`.
- **GitHub Actions workflow security (zizmor)** — added after `ignite-guidelines`' narrow `no-unpinned-gha-action` regex check was found to only cover mutable-ref pinning, not the actually dangerous GHA classes (pwn requests, script injection, over-broad `permissions:`). Crate `rust/crates/gha-security` (`check_gha_security`, `GhaSecurityConfig`) wired into `phase4-orchestrator`'s concurrent fan-out; skips invoking `zizmor` entirely when a repo has no `.github/workflows/*.yml`. Config: `security.zizmor.{enabled,binary}` (`ZIZMOR_ENABLED`/`ZIZMOR_BINARY`), on by default. Issue category `gha-security` (CWE-829, OWASP A08:2021) in `override-engine`. No built-in fallback — needs zizmor's real workflow-expression parser.

## Commands

```bash
cd rust

cargo build --release -p ignite-server
IGNITE_CONFIG_DIR=.. ./target/release/ignite-server     # → http://localhost:51337

cargo test --workspace                                   # every crate's test suite
cargo test -p ignite-secrets                              # single crate
cargo test -p ignite-secrets gitleaks                     # single test by name pattern
cargo clippy --workspace --all-targets

cargo run --bin ignite -- scan [path] [--changed-files a.js,b.py] [--json] [--fast]   # CLI wrapper around validate-all
cargo run --bin mcp-server                                # MCP server, stdio (default) or MCP_TRANSPORT=http
cargo run --bin guidelines-api                             # REST API on 127.0.0.1:8090
cargo run --bin create-api-key -- <email> [label]          # mint a headless API key for an existing user
cargo run --bin scheduled-rescan
cargo run --bin auto-fix-pr -- <org/repo> [--apply]
cargo run --bin enforce-gate-branch-protection -- <org/repo> [--apply]
```

Prerequisites for full pipeline runs: Rust (stable toolchain), `git` on PATH, `gh` CLI authenticated (`gh auth login` / `gh auth status`) with repo-create permission in the target org. Optional: `act` + Docker for Phase 5 org governance CI and for multi-language unit tests (Docker images per language). Everything else — Trivy, Semgrep, gitleaks, GuardDog, Bearer, cosign, Syft, Checkov, hadolint, jscpd, gocloc, Spectral, picklescan, oasdiff, zizmor, CodeQL, ORT, licensee — is a soft dependency: every check soft-skips to a built-in fallback (or contributes nothing) when its tool is absent. `docs-site/docs/getting-started.md` has the one-shot install script (`scripts/install-tools.sh`) for all of them.

Some tests skip a real-binary/real-network end-to-end case via an early `eprintln!("skipping: ...")` + `return` rather than failing when the corresponding tool/Docker/network isn't available — this is expected in most dev environments; the fake-CLI/offline coverage in the same test files still runs regardless.

## Architecture

See `README.md`'s "System Architecture" diagram and "Pipeline Checks" table for the full request-flow/phase breakdown — it's accurate and Rust-only, and more detailed than what belongs here. In short: **three request paths, one set of phase-check functions** — the interactive browser upload (`POST /api/pipeline`, streaming NDJSON), the synchronous headless path used by the pre-push hook/CLI/CI (`POST /api/pipeline/validate-all`, phases 1-5 only, never ships), and the MCP path (a thin proxy from the standalone `mcp-server` binary to the same HTTP API — the MCP process itself never runs `git`/`gh`).

**File lifecycle:** upload → staging directory (per-job UUID, zip-slip/bomb-guarded extraction, isolated under the OS temp dir, `rust/crates/staging`) → scanned in place → pushed from staging → forcefully removed in a `finally`-equivalent regardless of outcome, so no user code lingers on disk.

**Issue/override model** (`rust/crates/override-engine`): raw findings from every Phase 3/4 check are normalized into a flat list of addressable issues, each with a stable id (`<category>::<file>::<line>`) and a 0-10 severity score. Blocking (`severity: error`) issues need a matching override with justification, or a source fix, to pass. Overrides require attribution and are persisted to the audit log.

**Storage** (`rust/crates/db-store`): single SQLite db (`ignite.db`, gitignored) — users, sessions, api_keys, github_connections, projects, overrides, file/CodeQL scan caches, issue baselines, runtime coverage.

**Auth** (`rust/crates/auth` + `server/src/auth*.rs`): pluggable via `AUTH_MODE` — `standalone` (scrypt-hashed accounts, default), `oidc`, or `github`. Headless callers (agents/CI) use an `Authorization: Bearer ignite_<key>` API key instead of a session cookie (`create-api-key` mints one).

## Configuration

Settings live in `config.json` at the repo root (`config.example.json` is the template, `IGNITE_CONFIG_DIR` tells the server where to find it — defaults to cwd); environment variables override individual keys — see `.env.example` for the full list. `config.json` and `.env` are both gitignored and contain this developer's real org name, SMTP creds, etc. — don't commit them.

## White-label branding (`public/branding.config.js`)

`public/index.html` never hardcodes brand values (product name, page title, header logo, support link, the `brand` accent color scale) — it reads them all from `window.IGNITE_BRAND`, defined by `public/branding.config.js` and merged over Ignite's own defaults (`DEFAULT_BRAND` in `index.html`'s `<head>`) so any key left out falls back to current Ignite branding unchanged. To apply a customer's brand, edit **only** `public/branding.config.js` — never edit brand values directly in `index.html`. This keeps the two non-conflicting: upstream feature commits touch `index.html`'s structure/logic, a customer's branding touches only their own file, and `git pull`/merge never sees the same line change on both sides. `branding.config.js` ships checked in with an empty override object (see its own header comment for every available key and an example) — the VS Code extension's own icon/name isn't covered by this and would need a separate per-customer build if ever themed too.

## Internationalization (`public/i18n.js`)

`public/index.html` supports English/French/Portuguese/German for its **static UI chrome only** — buttons, labels, headers, modals, tooltips, placeholders. Server-generated text (phase titles/logs, finding summaries/categories/severities, CWE/OWASP ids, tool output, file paths, URLs, JSON, raw API error messages) is never translated; it comes from the Rust backend and stays exactly as the API sends it. Translations live in `public/i18n.js` (`window.IGNITE_I18N.translations`), keyed by locale then by dotted key (e.g. `upload.title`), with `en` as the source of truth. `index.html` picks up a locale by two conventions — never a hardcoded literal for in-scope UI copy:
- Static markup: a `data-i18n`/`data-i18n-title`/`data-i18n-placeholder` attribute naming the key, applied by `applyStaticTranslations()`.
- JS-rendered (template-literal) markup: an inline `t('some.key', vars?)` call at the render site.

The picker (header, next to the theme toggle) calls `setLocale()`, which persists to `localStorage['ignite-locale']` and re-applies `[data-i18n*]` elements immediately; already-open dynamic panels pick up the new locale the next time their own render logic runs, not retroactively — there's no global re-render-on-locale-change. When adding new UI copy, add the key to `i18n.js`'s `en` table (and ideally fr/pt/de too — a missing key falls back to `en`, then to the raw key itself, so an incomplete translation degrades gracefully rather than breaking).

## Hardening invariants (don't relax without a strong reason)

- Every archive entry's resolved path must stay inside the staging root (zip-slip); symlink entries are skipped and never followed (`rust/crates/staging`).
- Extracted size capped at 4 GB, upload capped at 1 GB (zip-bomb guard).
- Every `git`/`gh`/external-tool invocation goes through `rust/crates/tool-runner`'s `ToolRunner`, which only ever executes as an argument array (`std::process::Command`, no shell); org/repo names are validated against GitHub's naming rules before use in any command.
- Staging directories and uploaded ZIPs are always removed regardless of success or failure.
