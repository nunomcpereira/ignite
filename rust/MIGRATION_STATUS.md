# Rust rewrite — migration status

Last updated: 2026-08-24, after commit `95138e6` (73rd crate).

## Standing directive

Keep converting server.js/lib/checks(etc) to Rust, one crate/route at a
time, faithfully porting behavior with real tests (prefer exercising
real binaries against real installed tools over mocks where practical).
**Do not run a scan-comparison benchmark against the Node implementation
until everything below is converted** — a partial port makes any
timing comparison unfair to one side or the other. This has been asked
for multiple times; respect it.

## Done (73 crates)

- **All 33 Phase 4 checks** + `phase4-orchestrator` tying them together.
- **Phase 1–6 pipeline orchestration**, both entry points:
  - `POST /api/pipeline/validate-all` (phases 1–5, never ships)
  - `POST /api/pipeline/onboard` (phases 1–6, real git/gh push via
    `ignite-shipping`, gated behind `dryRun`)
- **Staging**: zip-slip-guarded extraction, directory copy, symlink-free
  cloning, env/CODEOWNERS checks.
- **License/vulnerability scanning**, including real ORT integration
  (verified against the real `ort` binary).
- **Governance CI** (`act`/Docker), **unit-test-runner** (Docker-sandboxed
  per-language test execution).
- **HTTP server** (`ignite-server`, axum) — 14 of 14 route files have a
  real, tested endpoint *or* are explicitly deferred (see below):
  tools-status, sarif, github-annotations, baseline, runtime-coverage,
  auto-fix, dependencies, reports, github-pr-status, issues, history,
  config, pipeline-validate, pipeline-onboard.
- **CLI** (`ignite-cli`, binary `ignite`) — faithful port of
  `bin/ignite.js`, verified end-to-end against the real server binary.
- **`guidelines-api`** — standalone REST API binary (port 8090), fully
  ported and tested.
- **`mcp-server`** — MCP server using the official `rmcp` crate, all 9
  tools ported, verified with a real stdio JSON-RPC handshake
  (initialize, tools/list, a real tools/call).

Every crate above has real tests; check crates that touch external
tools (ORT, act, gitleaks, semgrep, etc.) were verified against the
actual binaries installed on this machine, not just their
not-installed fallback paths.

## Not done yet

- **`routes/pipeline-interactive.js`** (658 lines) — the browser-driven
  SSE-streaming endpoint with the review-gate pause. This is the
  biggest remaining piece and blocks the two below it.
- **`routes/studio.js`** (410 lines) — file-tree/editor + on-demand
  report views at the review gate. Needs the live-run state
  `pipeline-interactive.js` creates (`runningRuns`, `pendingEffectivations`).
- **`routes/review-gate.js`** (155 lines) — review-decision resolution +
  "Effectivate" (turn a dry-run simulation into a real push). Also
  needs `pipeline-interactive.js`'s state.
- **Session/auth middleware** (`auth.js`'s Express router: OIDC/GitHub
  login, session cookies, `requireAuth`). Nothing ported yet — every
  route that needs a GitHub token currently falls back straight to
  `resolve_server_github_token()` (env var), never a real logged-in
  session. `ignite-auth` (crate 32) has the core hashing/token logic
  ported already; only the route wiring is missing.
- **MCP server's Streamable HTTP transport** (`MCP_TRANSPORT=http` mode)
  — only stdio is ported.
- **`config.json` loading in the server binary** — `ignite-config`
  (crate 2) can parse it, but `ignite-server`'s `AppState` doesn't load
  it yet; phase titles/enabled flags and tool "enabled" flags are
  still hardcoded to match the documented defaults.
- **`scripts/create-api-key.js`** — small standalone script, not ported.
- Known smaller gaps noted inline in doc comments across the routes
  above (GxP document persistence as real files, per-Phase-4-task
  timing breakdown, override email notifications — no SMTP transport
  wired despite `ignite-notifications` having the HTML builders).

## Suggested next step

`pipeline-interactive.js` is the natural next target — it unblocks
`studio.js` and `review-gate.js`, and once it's done the auth/session
layer is the main remaining structural gap before a real scan
comparison is fair to run.
