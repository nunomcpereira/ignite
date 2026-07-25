# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Ignite is a compliance gatekeeper for onboarding code into a GitHub org. A user uploads a project (ZIP or folder) via a single-page app; the server runs it through a multi-phase pipeline — structure audit, secret scan, AI-governance audit, local LLM deep-scan, org governance CI (via `act`), unit tests — and only provisions + pushes to GitHub if every phase passes (or flagged issues are explicitly overridden with justification).

Almost all backend logic lives in one file: **`server.js`** (~3600 lines). Read it with `grep -n` for the section you need rather than loading it wholesale — it's organized as one long sequence of helper functions followed by route handlers near the bottom.

## Commands

```bash
npm install
npm start                    # → http://localhost:3000
npm test                     # node --test test/*.test.js
node --test test/secrets-scan.test.js              # single test file
node --test test/secrets-scan.test.js -t "gitleaks" # single test by name pattern

npm run guidelines:mcp       # MCP server over stdio (mcp-server.js)
npm run guidelines:mcp:http  # same, MCP_TRANSPORT=http
npm run guidelines:api       # REST API on 127.0.0.1:8090 (guidelines-api.js)
```

Prerequisites for full pipeline runs: Node ≥18, `git` on PATH, `gh` CLI authenticated (`gh auth login` / `gh auth status`) with repo-create permission in the target org. Optional: `act` + Docker for Phase 4 org governance CI and for multi-language unit tests (Docker images per language); `gitleaks` binary for supplemental secret scanning.

Some tests (gitleaks integration, multi-language unit-test-runner tests in `test/unit-tests-multilang.test.js`) skip themselves rather than fail when Docker/gitleaks aren't available — this is expected in most dev environments.

## Architecture

**Pipeline flow (server.js):** multer buffers the upload → zip-slip/bomb-guarded extraction into a per-job UUID staging dir under the OS temp dir → sequential phase checks run in place → if all pass, `git init/add/commit` + `gh repo create --private` + push from staging → staging dir and uploaded ZIP are deleted in a `finally` block regardless of outcome, so no user code lingers on disk.

**Progress transport:** the pipeline endpoint (`POST /api/pipeline`) keeps the HTTP response open and streams newline-delimited JSON events (`log`, `status`, `done`, `review_required`). The frontend (`public/index.html`) consumes this with `fetch` + `ReadableStream` — no WebSocket/polling.

**Three ways to drive the pipeline**, all sharing the same phase-check functions:
1. `POST /api/pipeline` — interactive, streaming NDJSON, used by the browser UI. Supports `dryRun` (skip provisioning/push after all checks pass) and pauses with `review_required` if overridable issues are found.
2. `POST /api/pipeline/validate-all` — synchronous JSON, phases 1-5 only (always skips shipping), takes a local `projectPath` instead of an upload. For agent/CI loops that want pass/fail without a real push.
3. MCP tool `onboard_project` (via `mcp-server.js`) — thin proxy that calls `POST /api/pipeline/onboard` on a running Ignite server; the MCP process itself never touches `git`/`gh`.

**Per-file scan caching:** Phase 4 checks (`checkSecrets`, `checkAiGovernance`, `checkLlmDeepScan` in server.js) are keyed by `{ org, repo }` passed down from the request, and cache per-file findings in the `file_scan_cache` SQLite table (`db-store.js`) keyed by `(org, repo, check_name, rel_path)` + content hash. A cache hit is a full-string match on `org` and `repo` — a typo'd or renamed repo name is a guaranteed full rescan even if the file content is identical to a previous run.

**Issue/override model (`override-engine.js`):** raw findings from secrets/governance/LLM checks are normalized into a flat list of addressable issues (`collectPhase4Issues`), each with a stable id (`<category>::<file>::<line>`) and a 0-10 severity score (`scoreForIssue`, independent of blocking/warning status). Blocking (`severity: "error"`) issues cannot be silently bypassed — they need a matching override with justification, or a source fix. Overrides require attribution (session user, or explicit `{email, name}` actor), trigger an email notification, and are persisted to the audit log (`overrides` table, surfaced per-project in the UI).

**Auth (`auth.js`):** pluggable via `AUTH_MODE` (env) / `auth.mode` (config.json) — `standalone` (local scrypt-hashed accounts, default), `oidc` (delegates to any standards-compliant IdP), or `github` (sign in with GitHub, which also connects that account for push). All modes converge on the same session-cookie + `req.user` shape that override attribution relies on. Auth is not required to browse or run the pipeline — only enforced where attribution matters (submitting an override without a session needs an explicit actor in the body, else `401`).

**Guidelines catalog (`guidelines/catalog.js` + `guidelines/checks.js`):** the same detection patterns Ignite's onboarding pipeline enforces (secret regex, AI-governance `.invoke()`/`.stream()` calls missing `recursion_limit`, injection sinks, insecure deserialization, etc.), exposed as a standalone checks engine so they can be applied during development, not just at onboarding. Consumed by `mcp-server.js` (MCP tools: `list_guidelines`, `get_guideline`, `check_guidelines`, `check_project`, `onboard_project`) and `guidelines-api.js` (REST equivalent, loopback-only by default since `/check-project` reads arbitrary host paths).

**Storage (`db-store.js`):** single SQLite db (`ignite.db`, gitignored) holding users, sessions, github_connections, projects, overrides, and the file_scan_cache — all accessed through prepared statements returned by `createDbStore()`.

**Phase 4 org governance CI:** rather than reimplementing the central org's workflow logic, Ignite fetches the real `ai-guardrails-orchestrator.yml` from the governance repo via `gh api` and runs it locally with `act` against the staged project in Docker — so local pass/fail matches what a real PR would get. Soft-skips with a warning if `act`/Docker are unavailable (the workflows still gate remotely).

## Configuration

Settings live in `config.json` next to `server.js` (`config.example.json` is the template); environment variables override individual keys — see `.env.example` for the full list (LLM scan URL/model/mode, governance repo/workflow, gitleaks toggle, SMTP/notifications, auth mode/OIDC settings, etc.). `config.json` and `.env` are both gitignored and contain this developer's real org name, SMTP creds, etc. — don't commit them.

## Hardening invariants (don't relax without a strong reason)

- Every archive entry's resolved path must stay inside the staging root (zip-slip); symlink entries are skipped and never followed.
- Extracted size capped at 1 GB, upload capped at 250 MB (zip-bomb guard).
- All `git`/`gh` invocations use `execFile` with argument arrays (no shell); org/repo names are validated against GitHub's naming rules before use in any command.
- Staging directories and uploaded ZIPs are always removed in a `finally` block, success or failure.
