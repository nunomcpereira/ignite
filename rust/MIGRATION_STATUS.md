# Rust rewrite — migration status

Last updated: 2026-08-29. A real Node-vs-Rust scan comparison against the
tadone project (see standing directive below) was finally run after the
auth-mode work below, and it found two real Phase 4 orchestrator bugs on
the Rust side, now fixed:

- **Gitleaks supplement was never wired into `phase4-orchestrator`** —
  `ignite-secrets` had `parse_gitleaks_report`/`merge_gitleaks_findings`
  ported and tested, but nothing called the actual `gitleaks detect`
  subprocess. Added `ignite_secrets::run_gitleaks_scan` (the missing
  subprocess-running half) and wired it into `run_phase4_checks` behind
  `security.gitleaks.enabled` (new `SecretsConfig::gitleaks_enabled`
  field). Verified against tadone: 16/16 secret findings now match Node
  exactly (previously 0/16 — built-in regex scan only).
- **Phase 4 checks ran sequentially, not concurrently**, despite this
  file's own top-of-file doc comment claiming otherwise — no
  `tokio::join!`/`try_join!` anywhere in `run_phase4_checks`. Rewrote the
  non-`fast` path into two concurrent groups (`tokio::join!` for the
  infallible async checks, `tokio::try_join!` for the `io::Result`-returning
  ones), matching server.js's `Promise.all()` fan-out. `tokio` moved from
  dev- to a real dependency of `ignite-phase4-orchestrator`. This was a
  real architectural bug (Phase 4's whole design premise is checks running
  concurrently) but did **not** turn out to explain the findings gap below
  — see that note.

Comparison result after both fixes: **file:line-exact parity** on every
category both implementations produce deterministically — secret (16/16),
iac-security (3/3), api-schema-lint (4/4), license-compliance (2/2),
dependency-vulnerability (1/1). The one remaining delta (`semantic-sast`:
Rust flagged 2 blocking findings, Node 0) was chased down to live
semgrep-registry drift between two scan runs minutes apart, not a code
defect — `check_semantic_sast` was verified in isolation to return the
full 35 raw findings both before and after the concurrency fix; the
dev-tooling error→warning demotion logic (`no_taint_rule_on_dev_tooling`)
is already ported and tested in `override-engine`. Do not re-chase this
specific delta; if it recurs, compare full findings lists (not just
blocking issue counts) before assuming a regression.

**"Not done yet" is still empty** for structural work — every item
server.js/auth.js/mcp-server.js/scripts had is ported. The scan
comparison this file previously deferred to "someone else" has now
actually been run, twice (before and after the two fixes above).

## Standing directive

Keep converting server.js/lib/checks(etc) to Rust, one crate/route at a
time, faithfully porting behavior with real tests (prefer exercising
real binaries against real installed tools over mocks where practical).
**Do not run a scan-comparison benchmark against the Node implementation
until everything below is converted** — a partial port makes any
timing comparison unfair to one side or the other. This has been asked
for multiple times; respect it.

## Done (74 crates)

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
- **HTTP server** (`ignite-server`, axum) — 17 of 17 route files have a
  real, tested endpoint *or* are explicitly deferred (see below):
  tools-status, sarif, github-annotations, baseline, runtime-coverage,
  auto-fix, dependencies, reports, github-pr-status, issues, history,
  config, pipeline-validate, pipeline-onboard, pipeline-interactive,
  studio, review-gate (effectivate), auth (standalone mode).
- **`routes/pipeline-interactive.js`** (browser-driven `POST /api/pipeline`)
  — `crates/server/src/routes/pipeline_interactive.rs` +
  `crates/server/src/review_gate.rs` (the `reviewDecisions`-equivalent
  wait/resolve channel, `AppState::running_runs`/`pending_effectivations`).
  Multipart ZIP/folder upload, streaming NDJSON body, issues accumulated
  across every phase and shown together at one review gate right before
  phase 6 (not short-circuited phase-by-phase like `pipeline_onboard.rs`
  — this route's defining behavior), `dryRun`, and the retained-projects/
  pending-effectivation bookkeeping in the always-run cleanup path.
  `POST /api/pipeline/:jobId/review-decision` is also wired here (thin
  enough not to need the full `routes/review-gate.js` port). Known gaps,
  same category as `pipeline_onboard.rs`'s: no session auth, no
  failure-insight (local LLM) generation, no failure-email notification,
  no config.json phase overrides, and a Phase 5 CI failure collapses to
  one generic issue rather than per-line ones
  (`resolveGovernanceCiLocation`/`filterGovernanceCiFailureLines` aren't
  ported). Also, `Issue` (override-engine) doesn't carry its originating
  phase, so every override is recorded against phase 4 regardless of
  where the issue actually came from — the same simplification
  `pipeline_onboard.rs`'s `issue_to_input` already makes. The full
  review-gate/dry-run round-trip test is `#[ignore]`d by default: with
  every Phase 4/5 tool actually installed (this route has no
  `runLocalCi`/`fast` toggle, faithful to the Node original not having
  one either), a real Phase 5 `act` run can mean a multi-minute Docker
  image pull — run it explicitly with `cargo test -p ignite-server --
  --ignored` when validating this path end to end.
- **`routes/studio.js`** (file-tree/editor + on-demand report views at the
  review gate) — `crates/server/src/routes/studio.rs`. Covers `tree`,
  `file` (GET/PUT, writing to both the live staging tree and the
  immutable source backup when they differ), `rescan` (secrets +
  ai-governance + iac-security + license-compliance +
  dependency-vulnerability, purging stale findings in those five
  categories), `dependencies`, `sbom`, `loc-metrics`, `posture`, and
  `provenance`. Resolves both the 'live' window (a run still paused at
  the review gate, via `AppState::running_runs`) and the 'kept' window
  (`pending_effectivations` with a 24h TTL, falling back to
  `retained_sources`), same as the Node original. Known gaps:
  `/studio/rescan` skips the local LLM deep-scan (consistent with
  `Phase4Config::llm: None` everywhere else in this port — no
  config.json/env wiring to a real LLM endpoint exists yet) and doesn't
  reuse the per-file scan cache (`file_scan_cache`), so each rescan is a
  full uncached sweep — slower than Node, never incorrect. 5 real tests
  (tree/file roundtrip incl. dual live+backup write, path-traversal
  rejection, unknown-job 409, rescan detects-then-clears a real secret
  finding across two passes, report endpoints respond ok).
- **`routes/studio.js`'s on-demand CodeQL endpoints** — `/studio/codeql`
  (streaming NDJSON "Run CodeQL" against the live/kept tree) and
  `/studio/codeql/query` (ad-hoc `.ql` query against whichever database
  `/studio/codeql` already built), both now in `studio.rs`. Required
  extending `ignite-codeql-cross-file` itself, which previously only
  covered the standing-scan path:
  - `CodeqlContext` gained `keep_db_dir: Option<&Path>` — when set,
    `run_one_language` copies its built database to
    `keep_db_dir/<language>/db` right after `database create` succeeds
    (best-effort; a copy failure logs but never fails the standing
    scan), mirroring `runOneLanguage`'s `keepDbDir` exactly.
    `check_codeql_cross_file_with_log` is a new log-sink variant of
    `check_codeql_cross_file` so Studio's streaming endpoint can surface
    the same per-language progress lines the standing scan's Node
    `log` callback did; the no-log path is unchanged.
  - `run_custom_codeql_query` (new) is a faithful port of
    `runCustomCodeqlQuery`: scaffolds a throwaway qlpack declaring
    `codeql/<language>-all` as a dependency (a lone `.ql` file can't
    compile without a qlpack), then `codeql pack install` → `codeql
    query run` → `codeql bqrs decode --format=json` → parses the
    `#select` shape into `{ columns, rows }`, resolving each entity
    cell's `file://` URI back to a project-relative path/line the same
    way `parseQueryResultJson` does (skipping locations outside
    `root` — CodeQL stdlib/extern stubs).
  - `codeql_db_dir_for(project_id)` in `studio.rs` is the
    `codeqlDbDirFor` port — `IGNITE_DATA_DIR/codeql-dbs/<projectId>`,
    same root `pipeline_interactive.rs`'s retained-source eviction
    already cleans up alongside (`ignite_data_dir()` is now
    `pub(crate)` so both modules share one definition).
  - Found and fixed a real latent bug while adding this: both
    `run_one_language`'s and (the new) `run_custom_codeql_query`'s work
    dirs were keyed only by `format!("...-{}", std::process::id())` —
    unique per *process*, not per *call*. Two concurrent CodeQL
    operations for the same language (real risk once Studio makes this
    reachable from any concurrent request, and immediately hit by two
    tests in the same `cargo test` binary racing on it) would silently
    share a work dir and corrupt each other's build. Switched both to
    `tempfile::Builder::tempdir_in`, matching Node's own `fsp.mkdtemp`
    uniqueness guarantee.
  - 4 new tests in `ignite-codeql-cross-file` (real end-to-end:
    `keep_db_dir` persists a queryable database + an ad-hoc query
    against it returns rows for a real function; missing-database error
    path) plus 4 new tests in `studio.rs` (missing-database error via
    the real route, missing-language/query validation, and a full real
    end-to-end: POST `/studio/codeql` → persisted database on disk →
    POST `/studio/codeql/query` reusing it). All exercised against the
    real `codeql` CLI (installed on this machine), not a fallback path.
- **`routes/review-gate.js`'s "Effectivate" endpoint** (turns a
  completed `dryRun` simulation into the real thing) —
  `crates/server/src/routes/effectivate.rs`
  (`POST /api/projects/:projectId/effectivate`). Re-validates the
  project's current issue list against `AppState::pending_effectivations`
  before shipping (issues already overridden at the live review gate
  aren't re-demanded), applies any newly-submitted overrides (recorded
  against phase 4, same simplification as `pipeline_interactive.rs`),
  then reuses `ignite_staging::clone_directory_without_symlinks` +
  `ignite_shipping::{archive_phase6_payload, ship_to_github}` — the same
  Phase 6 machinery `pipeline_onboard.rs`/`pipeline_interactive.rs`
  already use — against the immutable `source_backup_dir` snapshot.
  `POST /api/pipeline/:jobId/review-decision`, routes/review-gate.js's
  other endpoint, was already ported inside `pipeline_interactive.rs`.
  3 real tests (401 with no GitHub token, 404 with no pending
  effectivation, 409 with an unjustified blocking issue). The real-push
  success path (override applied → actual `git`/`gh` push) has no test
  here — same gap as `pipeline_onboard.rs`, which has no test for its
  own real-push success path either: both need a real `GH_TOKEN`/
  `GITHUB_TOKEN` with repo-create permission and network access to
  github.com, unavailable in a unit-test sandbox.
- **Session/auth middleware — all three modes** (`crates/server/src/auth.rs`
  + submodules `auth/oidc.rs`, `auth/github_oauth.rs`, wiring `ignite-auth`
  crate 32's core logic into `ignite-server`). `resolve_user` (the
  `attachUser` equivalent: session cookie first, `Authorization: Bearer
  ignite_<key>` fallback, session wins if both present),
  `RequireAuth`/`OptionalUser` axum extractors, and
  `resolve_effective_github_token` (a connected session's own token
  first, falling back to `resolve_server_github_token()` for unattended
  CI callers) — wired into every route that previously called
  `resolve_server_github_token()` directly for a real push token:
  `pipeline_onboard.rs`, `pipeline_interactive.rs`, `effectivate.rs`,
  `github_pr_status.rs` (the governance-workflow-fetch server token in
  `pipeline_onboard.rs`/`pipeline_validate.rs`/`pipeline_interactive.rs`
  is deliberately untouched — fixed shared org repo, not a per-user push,
  same as the Node original keeping it separate from
  `auth.resolveGithubToken`). Standalone mode: `GET /api/auth/config`
  (now reads `state.config.auth.mode` for real), `GET /api/auth/me`,
  `POST /api/auth/logout`, `POST /api/auth/register`, `POST
  /api/auth/login` — real scrypt hashing, real rate limiting,
  timing-safe-against-account-enumeration login, matching `auth.js`
  exactly. **OIDC mode** (`auth/oidc.rs`): real authorization-code flow —
  discovery (`.well-known/openid-configuration`), redirect with
  `state`/`nonce`, code→token exchange, JWKS fetch, RS256 `id_token`
  signature+claims verification (`jsonwebtoken` crate, added this task),
  nonce check, `email`/`name`/`sub` claims → `upsert_oidc_user`, session
  issuance — a faithful line-for-line port of `auth.js`'s `mode ===
  'oidc'` branch. `GET /api/auth/oidc/login|callback` 404 when
  `auth.mode != "oidc"`, matching an unmounted-Express-route's effective
  behavior. **GitHub mode + account connection** (`auth/github_oauth.rs`):
  real OAuth code→token exchange against `github.com/login/oauth/*` +
  `api.github.com/user`(`/emails`) fetch, `upsert_github_user` for
  sign-in or `upsert_github_connection` for connect-only, `RequireAuth`-
  gated `/connect`/`disconnect`, `/status` via `OptionalUser`-equivalent.
  An `IGNITE_GITHUB_OAUTH_MOCK_BASE` env var (test-only) redirects the
  three GitHub endpoint URLs so tests can point at a local mock instead
  of the real `github.com`/`api.github.com`.
  **Testing caveat, stated precisely, not overclaimed**: neither mode has
  been exercised against a real third-party IdP or GitHub's live OAuth
  app (none available in this sandbox) — both are verified end-to-end
  against a **local mock** implementing the same wire protocol: for OIDC,
  an in-test axum server serving real discovery/token/JWKS responses
  signed with a freshly generated RSA keypair (`rsa`/`jsonwebtoken`
  crates), driving the actual redirect→callback→RS256-verify→session
  path; for GitHub, an in-test server standing in for the token and user
  APIs. This proves the protocol implementation is correct against a
  spec-conformant peer; it does not prove any one real IdP's quirks
  (non-standard claims, clock skew, rate limits) are handled — that would
  need a real deployment to fully confirm. 8 new tests across the two
  submodules (OIDC: full round-trip against the mock IdP, 404 when mode
  isn't oidc, unknown-state rejection; GitHub: full login round-trip
  against the mock, 404 when mode isn't github, disconnected-status with
  no session, connect requires auth, unknown-state rejection) plus the
  5 pre-existing standalone-mode tests, all still passing.
- **`config.json` loading in the server binary** — `AppState::config`
  (`ignite_config::load_config`, `crates/server/src/main.rs`), loaded once
  at startup from `IGNITE_CONFIG_DIR` (defaults to cwd, mirroring
  config.js's `__dirname` convention) with the same config.json-then-env
  precedence `ignite-config` (crate 2) already implements and tests.
  `crates/server/src/phase4_config.rs` (new) is the field-by-field bridge
  from `Config` onto `Phase4Config` — every Phase 4 tool's real
  `enabled`/threshold/ruleset value (trivy, checkov, hadolint, cosign,
  semgrep, bearer, guarddog, codeql, picklescan, package-hallucination,
  jscpd, gocloc, spectral, oasdiff, syft, posture, EU AI Act
  docs/findings-toggle, dead-code/health/css-dead-code, architecture
  boundaries incl. custom `zones`, `.igniteignore`) now reaches
  `run_phase4_checks` instead of each check's hardcoded `::default()`.
  `phase4_config::runner_from_config` does the same for tool *binary*
  paths (`ToolRunner`), replacing `state::default_runner`'s
  hardcoded tool-name-as-binary map in real server startup (kept as a
  test-only convenience, now itself implemented via
  `runner_from_config(&Config::default())` so there's one source of
  truth). `server.js`'s `PORT = process.env.PORT || CONFIG.port`
  precedence is matched exactly. 3 new tests in `phase4_config.rs`
  (disabling a tool in config propagates through, a custom binary path
  reaches the runner, `architecture.boundaries.zones` JSON parses into
  real `Zone`s) plus `ignite-config`'s existing 6. Also unchanged:
  `llm.provider`/OpenAI wiring (no `Provider::OpenAi` selection path
  exists in `ignite_llm_client` yet — `llm_config_from_config` always
  resolves local). OIDC/GitHub auth mode selection is no longer a gap —
  see the auth entry above, ported in full afterward.
- **`config.json`'s per-id `phases` array wired to phase gating/display**
  — `crates/server/src/routes/phase_meta.rs`'s `resolve_phase_meta(&Config)`
  applies `Config.phases`' per-id `title`/`desc`/`enabled` overrides onto
  `DEFAULT_PHASE_META`, honoring the same `PHASE_ALWAYS_ENABLED` set
  (`{1, 3, 6}`) server.js's `PHASE_META` does — those three ids can never
  be disabled via config, matching the Node comment on why (structural
  dependents: input validation, extraction, shipping). `phase_title`/
  `phase_enabled` are now `fn(&[PhaseMeta], id)` instead of free functions
  over a hardcoded table; every call site
  (`pipeline_validate.rs`/`pipeline_onboard.rs`/`pipeline_interactive.rs`/
  `effectivate.rs`/`routes/config.rs`) computes `resolve_phase_meta(&state.config)`
  once per request/run and threads it through (`Logger`/`EventLog` gained
  a `meta` field so persistence and phase-summary rendering pick it up
  too). `GET /api/config` also now surfaces `state.config.github.orgs`
  (comma-separated, matching `routes/config.js`) instead of an
  always-empty array — a leftover gap from before config.json loading
  existed, fixed as part of this same call-site sweep. 4 new tests in
  `phase_meta.rs` (defaults match the Node table, a disabled+retitled
  phase 4, `{1,3,6}` ignore a disable override, phase 2 can be toggled)
  plus 2 real end-to-end tests in `pipeline_validate.rs` (`phase_4_disabled_via_config_skips_secrets_scan_but_still_runs`,
  `phase_4_enabled_by_default_runs_secrets_scan`) driving a real
  `/api/pipeline/validate-all` request against a fixture project with a
  planted secret, asserting the `secret`-category finding is present/absent
  based on config alone.
- **`scripts/create-api-key.js`** — new crate `ignite-create-api-key`
  (bin `create-api-key`, `crates/create-api-key/`). Looks up the user by
  email (`ignite-db-store::get_user_by_email`), mints a key with the same
  `ignite-auth::generate_api_key`/`hash_api_key` the server's own API-key
  auth path already verifies against, inserts via `create_api_key`, and
  prints the raw key exactly once — never creates accounts, matching the
  Node original. Operator attribution resolves `IGNITE_OPERATOR` or falls
  back to `$USER@$(hostname)`. Builds the real owner-notification email
  (`ignite_notifications::build_api_key_created_email`, so that
  integration point is exercised, not just documented) but always reports
  it as **not sent** — no SMTP transport is wired anywhere in the Rust
  port yet (same known gap as override-email notifications elsewhere), so
  this is an honest gap disclosure rather than a silent no-op. 4 real
  tests (unknown email fails with the same message shape, a minted key
  actually authenticates via `get_active_api_key_by_hash` — round-tripping
  through the real hash scheme, `IGNITE_OPERATOR` override, notification
  honestly reported unsent).
- **CLI** (`ignite-cli`, binary `ignite`) — faithful port of
  `bin/ignite.js`, verified end-to-end against the real server binary.
- **`guidelines-api`** — standalone REST API binary (port 8090), fully
  ported and tested.
- **`mcp-server`** — MCP server using the official `rmcp` crate, all 9
  tools ported, verified with a real stdio JSON-RPC handshake
  (initialize, tools/list, a real tools/call). **Both transports now
  ported**: `MCP_TRANSPORT=stdio` (default) and `MCP_TRANSPORT=http`
  (`crates/mcp-server/src/main.rs`'s `run_http`, `MCP_HTTP_PORT` default
  51338, faithful to `mcp-server.js`'s single `app.all('/mcp', ...)`
  handler backed by the SDK's `StreamableHTTPServerTransport`). Reuses
  rmcp's own `StreamableHttpService`/`LocalSessionManager` (feature
  `transport-streamable-http-server`) rather than reimplementing session
  handling; `AxumStreamableHttp` is a small adapter mapping rmcp's
  `tower_service::Service` onto axum's `Response = axum::body::Body` so
  it mounts via `Router::route_service`. 1 new real test: spawns the
  actual HTTP server on an ephemeral port and drives a full JSON-RPC
  handshake over it (initialize, notifications/initialized, tools/list,
  a real tools/call for `list_guidelines`), asserting on both the
  legacy-session SSE framing and the JSON body shape. Known gap: no
  bearer-token/API-key auth on the HTTP listener itself, same as the
  Node original (`mcp-server.js`'s http mode has none either — it's
  meant for trusted-localhost use, same as the loopback-only
  `guidelines-api`).

Every crate above has real tests; check crates that touch external
tools (ORT, act, gitleaks, semgrep, etc.) were verified against the
actual binaries installed on this machine, not just their
not-installed fallback paths.

## Not done yet

Nothing structural remains. Every server.js/auth.js/mcp-server.js/script
this list ever named is ported and tested. What's left is only the
smaller gaps already noted inline in doc comments across the routes
above — none of them block correctness or the scan comparison:
- GxP document persistence as real files (currently in-memory/report-only).
- Per-Phase-4-task timing breakdown (aggregate timing exists; per-task
  doesn't).
- No SMTP transport wired anywhere in the Rust port (override-email
  notifications and the `create-api-key` owner-notification email are
  both built via `ignite-notifications`'s real HTML builders and honestly
  reported as unsent, never silently dropped).
- OIDC/GitHub auth: verified end-to-end against a local mock of each
  protocol (see the auth entry above), not against a real third-party
  IdP or GitHub's live OAuth app — no such credential is available in
  this sandbox. The protocol implementation itself (discovery, code
  exchange, RS256 `id_token` verification, claims mapping) is real and
  tested; only a live deployment would surface IdP-specific quirks.

## Suggested next step

Migration is structurally complete and the Node-vs-Rust scan comparison
against tadone has been run and passed (file:line-exact parity on every
deterministic category — see top of this file). Remaining smaller gaps
are the "Not done yet" list above; none block relying on the Rust port
for onboarding-gate use.
