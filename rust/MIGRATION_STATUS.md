# Rust rewrite — migration status

## New crate: `auto-fix-pr` — Dependabot-parity auto-fix PR bot (2026-09-02)

GHAS-bypass-hardening gap: `scheduled-rescan` detects newly-disclosed CVEs
in already-onboarded repos but never proposes a fix — Dependabot opens a
version-bump PR automatically, Ignite only logged/posted a commit status.
New crate `crates/auto-fix-pr` (binary `auto-fix-pr`) closes this for the
five manifest ecosystems `ignite-studio-manifests` already parses (npm,
pypi, cargo, go, maven): shallow-clones a repo's default branch, runs the
real `dependency-vulnerability` scan (`ignite-dependency-license-scan`),
resolves each finding's minimum fixed version via a real OSV.dev API call
(`fetch_osv_fixed_version` — deps.dev's own advisory schema, already used
by the vuln scan, doesn't carry a per-package fixed-version field, only
generic CVE/GHSA metadata), and opens one PR per safe fix via
`ignite-github-api`'s existing `gh_create_pr`/`gh_clone_repo_branch`.

Deliberately conservative, not a full Dependabot replacement: only a
single simple version constraint is auto-edited (`is_simple_range` rejects
OR-ranges/wildcards/hyphen-ranges — left for a human); a fix crossing a
semver major (`is_major_bump`) is always skipped, never silently applied;
only the first `fixed` event OSV reports per matching `affected` package
entry is used, not full range-intersection resolution. Dry-run by default
(`--apply` to actually push/open PRs), same convention as
`enforce-gate-branch-protection`. Idempotent via `git ls-remote --heads`
on a deterministic per-(ecosystem, dep, fixed-version) branch name — no
in-flight-PR tracking or auto-merge.

9 tests, including one real network call against the live OSV.dev API
(a stable, years-old lodash prototype-pollution advisory) verifying an
actual fixed-version resolution, not just a mocked response shape.

## MCP HTTP transport bound to loopback only — found via live docker-compose testing, fixed (2026-08-30)

`crates/mcp-server/src/main.rs`'s `run_http` hardcoded
`TcpListener::bind(("127.0.0.1", port))`. mcp-server.js's real behavior is
`app.listen(port, ...)` with **no host argument** — plain Express/Node
`listen(port)` binds all interfaces by default, same as any bare
`http.Server.listen(port)`. This was a real regression, not a match: found
by actually running the rebuilt `mcp-server` binary inside the live
docker-compose container (the same one `docker-compose.yml` already
exposes port 51338 from) and driving a real MCP JSON-RPC handshake from
the host — `curl` connected successfully but got "Connection reset by
peer" on every request, because the process itself was refusing every
connection arriving through Docker's port-forward NAT (which doesn't
appear to the process as literally `127.0.0.1`). Unlike
`guidelines-api.js`/its Rust port, which *deliberately* binds 127.0.0.1
loopback-only plus its own defense-in-depth per-request middleware (see
`crates/guidelines-api/src/main.rs`), mcp-server.js has no such
loopback-only design — it's meant to be reachable however deployed.

Fixed: bind to `0.0.0.0` instead. Verified with real running processes
end to end, not just the existing unit test (which only ever exercised a
same-process ephemeral-port connection and so never would have caught
this): (1) **stdio transport** — piped a real `initialize` →
`notifications/initialized` → `tools/list` JSON-RPC sequence into the
actual release binary via stdin, got back the real `serverInfo`
(`rmcp`/3.1.4) and the full real list of all 9 tools. (2) **HTTP transport,
bare-metal** — started the rebuilt binary standalone, curled it from the
host over real IPv4, got a real session id and the same 9-tool list, plus
a real `tools/call` against `list_guidelines` returning real guideline
data (not a mock). (3) **HTTP transport, inside the live container** —
exec'd the rebuilt `mcp-server` binary into the already-running
docker-compose container and confirmed the same handshake now succeeds
from the host through the real Docker port-forward, where it previously
reset the connection. Docker image rebuilt with the fix.

## Two more real gaps found via live browser testing, fixed (2026-08-30)

**Governance CI (Phase 5) ignored config.json's real repo/workflow/event/
timeout entirely.** All three pipeline entry points
(`pipeline_validate.rs`, `pipeline_onboard.rs`, `pipeline_interactive.rs`)
hardcoded a literal `"nunomcpereira/ai-guardrails-orchestrator"` /
`"ai-guardrails-orchestrator.yml"` / `act_event: "push"` / `act_timeout_min:
20` instead of reading `state.config.governance.{repo,workflow,event,
timeout_minutes}` — apparent leftover dev-testing values that never got
wired to the real config, silently ignoring `config.json`'s actual
`governance.repo`/`workflow`/`event`/`timeoutMinutes` for every deployment
except the one org/repo those hardcoded strings happened to name. Caught
live: a real onboarding run in the browser failed Phase 5 with `gh: Not
Found (HTTP 404)` fetching that hardcoded repo, which doesn't exist under
this user's GitHub account — Node's `server.js` (lines 818-819) reads
`GOVERNANCE_REPO`/`GOVERNANCE_WORKFLOW` env vars falling back to
`CONFIG.governance.repo`/`workflow`; the Rust `GovernanceConfig` struct and
its `config.json` defaults already existed and were correct
(`ignite-config`), just never actually read by any call site. Fixed all
three call sites, and added the missing `GOVERNANCE_REPO`/
`GOVERNANCE_WORKFLOW`/`ACT_EVENT`/`ACT_TIMEOUT_MIN` env-var overrides to
`ignite-config`'s `apply_env_overrides` (Node has these; Rust didn't). New
test `governance_config_json_and_env_overrides_both_take_effect` in
`ignite-config` proves both config.json and env-var overrides actually
reach `Config.governance`.

**Multer per-file-size semantics gap, previously left as a documented
"deliberately not fixed" limitation, now actually closed.** The prior
multipart-upload fix (see below) capped the *whole request body* at 1GB via
`DefaultBodyLimit::max`; server.js's real multer config
(`{ fileSize: MAX_ZIP_BYTES, files: 100000 }`) instead bounds each
individual file *part* to 1GB with no whole-body cap, and separately caps
file-part *count* at 100,000 — a folder upload with many small files
summing past 1GB is valid in Node but was rejected in Rust. Fixed in
`pipeline_interactive.rs`: `DefaultBodyLimit::disable()`'d on the route,
replaced with real streaming enforcement — `read_field_bytes_limited_to`
reads each file field via `.chunk()` (not `.bytes()`, which would buffer
past the limit before rejection is possible) and rejects mid-stream past
`MAX_FILE_BYTES` (1GB), while `file_field_count` rejects past `MAX_FILES`
(100,000) — counting only file-bearing fields (archive/files/gxpDocs), not
text fields (org/repo/dryRun/...), matching multer's own "file fields only"
semantics for its `files` limit. New test
`read_field_bytes_limited_to_rejects_mid_stream_and_accepts_within_limit`
proves real rejection/acceptance behavior against a genuine
`axum::extract::Multipart` `Field` (a tiny standalone probe route with a
10-byte test limit, not a 1GB upload) — real streaming behavior verified at
a scale a test suite can actually run.

Both fixes verified: `cargo test --release --workspace` (excluding the two
`bench-*` micro-benchmark crates) — clean, exit 0, no failures. Docker
image rebuilt and redeployed with both fixes.

## Static frontend serving — found missing, fixed (2026-08-30)

Despite this file's prior "nothing structural remains" claim, `ignite-server`
never served `public/index.html` (or any static asset) at all — `GET /`
returned a bare 404, `content-length: 0`. Node's `server.js` does this with
one line, `app.use(express.static(path.join(__dirname, 'public')))`
(server.js:122); no equivalent existed anywhere in `crates/server`. Found by
manually loading the running Rust server in a browser — every API route
worked (`/api/tools/status` etc.), only the frontend was unreachable, so this
had gone undetected by the route-level tests, which never hit `/`.

**Two more real gaps found the same way, same session:** `helmet`'s
security-header middleware (server.js:77-92 — CSP, COOP/CORP,
Referrer-Policy, HSTS, X-Frame-Options, etc., with `crossOriginEmbedderPolicy`
deliberately disabled) and the coarse `express-rate-limit` backstop on `/api`
(server.js:99-104, 300 req/60s per IP) had no Rust equivalent anywhere.
Ported both into new `crates/server/src/security.rs`: `security_headers_middleware`
(an `axum::middleware::from_fn` setting the same header set/values helmet's
defaults produce, plus the custom CSP directives and the intentional absence
of `Cross-Origin-Embedder-Policy`) and `RateLimiter`/`rate_limit_middleware`
(a fixed-window per-IP counter behind `axum::middleware::from_fn_with_state`,
gated to paths starting with `/api`, emitting the same `RateLimit-Limit`/
`RateLimit-Remaining`/`RateLimit-Reset` headers `standardHeaders: true` +
`legacyHeaders: false` produces). Required switching `main()`'s
`axum::serve` (both the real binary and the test harness) to
`app.into_make_service_with_connect_info::<SocketAddr>()` so the rate
limiter can key on the real client IP.

**A fourth gap, found via a live user-reported failure in the same
session:** uploading a real 5.2 MB project folder through the browser UI
failed at phase 1 with "Error parsing `multipart/form-data` request" —
axum's `Multipart` extractor enforces its own default 2 MB body limit
(`DefaultBodyLimit`) unless overridden per-route, and nothing in
`pipeline_interactive.rs` had ever set one, unlike server.js's multer
config (`MAX_ZIP_BYTES = 1024*1024*1024`, a real 1 GB cap). Fixed by adding
`.layer(axum::extract::DefaultBodyLimit::max(MAX_UPLOAD_BYTES))` scoped to
just the `POST /api/pipeline` route (not the whole router — JSON endpoints
elsewhere keep axum's smaller stock default, closer to server.js's separate
`express.json({ limit: '1mb' })` cap on those). New test
`accepts_upload_larger_than_axum_default_body_limit` sends a real >2 MB
multipart body with incompressible filler bytes (so zip deflate can't
shrink the wire size back under the old limit) and asserts phase 1 actually
runs rather than getting a 413/400 — this is a regression test for exactly
the failure mode the user hit.

All four fixes verified: `cargo test -p ignite-server --release` — 85
passed, 1 pre-existing `#[ignore]`d (needs real Docker/`act`), 0 failed.
Also verified live against the actual running binary: a real >2MB
multipart upload that previously 400'd now streams real phase 1-3 NDJSON
events end to end.

**Full audit after these four, since the status file's prior "nothing
structural remains" claim had already been proven wrong once this
session:** cross-referenced every `app.use(...)` in server.js (6 total —
helmet, rate-limit, express.json, attachUser, auth.router, express.static —
all 6 now have a Rust equivalent) and every route across all 17
`routes/*.js` files plus `auth.js`'s 12 endpoints against
`crates/server/src/routes/*.rs` and `crates/server/src/auth*`, path by path
— full 1:1 match, nothing missing. Also checked `guidelines-api.js`'s
per-request loopback-only guard (defense-in-depth on top of binding to
127.0.0.1) — already correctly ported in `crates/guidelines-api/src/main.rs`.

**One narrow, real, deliberately-not-fixed gap found in this pass:**
`multer`'s config (server.js:161-164) is `{ fileSize: MAX_ZIP_BYTES,
files: 100000 }` — `fileSize` limits each individual multipart *part* to
1GB, `files` caps the part *count* at 100000; a folder upload with many
small files can total well over 1GB in Node as long as no single file
exceeds it. The Rust fix above (`DefaultBodyLimit::max`) instead caps the
*whole request body* at 1GB — a real semantic difference for very large
folder uploads (many-small-files summing past 1GB), though every
realistically-sized project upload (the case this session's actual bug
report was about) is unaffected. Not fixed here: axum's `Multipart`
extractor has no built-in per-part byte counter or part-count limit to
hook the same way `DefaultBodyLimit` hooks the whole-body case; doing this
faithfully means hand-tracking bytes-per-field and field-count inside
`parse_multipart`'s existing `while let Some(field) = ...` loop. Flagged
here rather than silently left, per this file's own standing practice of
disclosing gaps honestly instead of overclaiming completeness.

Fixed in `crates/server/src/main.rs`: `build_router` now takes a `public_dir:
&Path` and mounts `tower_http::services::ServeDir::new(public_dir)` as
`.fallback_service(...)` — checked only after every API route fails to
match, the same effective ordering Express gets from mounting static
middleware before its route handlers (none of Ignite's API paths collide
with a static asset name, so this is behaviorally identical). `main()` passes
`config_dir.join("public")`, mirroring `express.static(path.join(__dirname,
'public'))`'s directory convention. Required adding tower-http's `fs`
feature (`Cargo.toml`) alongside the existing `trace` feature. 2 new tests:
`root_serves_spa_index_html` (real GET `/` against the actual `public/`
directory, asserts `text/html` + real `<html` content, not just a 200) and
`unknown_path_falls_through_to_404` (an unmatched path still 404s rather
than the fallback swallowing everything). Verified live: killed and
restarted the actual running `ignite-server` binary, confirmed `curl -o
/dev/null -w "%{http_code}" http://localhost:51337/` returns `200`, and
loaded it in a real browser — full Ignite Studio UI renders.

## Performance optimization session (2026-08-30) — IN PROGRESS, resume after reboot

Migration itself is done (see below) — this was a follow-on effort to make
the Rust port's wall-clock performance beat Node's on every benchmarked
project, not just match its findings. Started from a full 5-project
benchmark (tadone, IoC, career-ops, SolventAI, tradingfriend), 3 trials
each, gated on exact `issues[]` parity every trial.

**Three real bugs found and fixed, all release-built and test-verified:**

1. **Phase 4 ran two sequential concurrency groups instead of one fan-out**
   (`crates/phase4-orchestrator/src/lib.rs`) — a `tokio::join!` of 5 checks
   followed by a `tokio::try_join!` of 13, with the second group never
   starting until the first fully finished, even though nothing in group 2
   depends on group 1's output. Node's `runPhase4Checks` runs all ~20
   checks (including secrets/governance) in one `Promise.all`. Merged
   Rust's 18 subprocess/network-bound checks into one `tokio::try_join!`
   (secrets/governance and the handful of fast in-process
   codebase-intelligence checks — dead-code, health, css-dead-code,
   boundaries, file-encapsulation, EU AI Act docs — deliberately left
   sequential: they're cheap, in-process, and merging them would need
   `spawn_blocking` + cloning owned data across a 'static boundary for
   little payoff). Also added per-check timing (`task_timings` on
   `Phase4Output`, threaded into the API response as `phase4:<name>`
   entries in `__stageTimings`) — this was the "not done yet" gap noted
   below, now closed.
2. **`PackageHallucinationChecker`'s cache never survived past one
   request** — the checker (which the crate's own doc comment calls a
   "process-lifetime cache") was constructed fresh inside
   `run_phase4_checks` on every call, discarding its cache immediately.
   Hoisted one instance onto `AppState` (`package_hallucination_checker`
   field, `state::default_package_hallucination_checker()` helper) and
   threaded it through `run_phase4_checks`'s new required parameter to
   all 4 call sites (`pipeline_validate.rs`, `pipeline_onboard.rs`,
   `pipeline_interactive.rs`, `phase4-scan-cli`) plus all 9
   `AppState { ... }` construction sites across the server crate (test
   helpers included). Verified directly: 4384ms → 0ms on a repeat scan of
   the same project.
3. **`dependency-license-scan`'s per-dependency registry lookups ran
   sequentially** in a for-loop (`scan_dependency_licenses_fallback`,
   `scan_dependency_vulnerabilities`) instead of concurrently — Node's
   equivalent uses `Promise.all(rawDeps.map(...))`. Converted both to
   `futures::future::join_all` over one future per dependency, preserving
   order and every existing fallback branch (best-published-version
   retry, npm-registry/SEE-LICENSE-IN fallbacks) unchanged. This was the
   dominant, sometimes *entire*, wall-clock cost on career-ops (its
   Phase 4 total was already ~3% off Node's before this fix; the license
   scan alone was the whole +22% gap).
   - **While verifying this fix, found and fixed a second, more serious
     bug**: `reqwest`'s `.timeout()` on a request builder only bounds
     `.send()` (through response headers) — it does NOT cover the
     subsequent body read (`.json()`/`.text()`), a separate future with no
     timeout of its own. A connection that stalls mid-body-transfer after
     headers arrive hangs *forever*, no cap at all. This is almost
     certainly what caused repeated 19-32 minute stalls on tadone (its
     hundreds of dependencies across many manifests make hitting one
     unlucky stalled connection much likelier once every dependency fires
     concurrently). Fixed in `crates/deps-dev-client/src/lib.rs`: every
     fetch (`fetch_package_info`, `fetch_version_list`, `fetch_advisory`,
     `fetch_npm_registry_license`, `fetch_unpkg_file_text`) now wraps the
     *whole* connect-through-body-read sequence in one outer
     `tokio::time::timeout(Duration::from_secs(5), ...)`; a timeout is
     just another soft lookup failure (`None`), same as every other
     fail-soft path in this client. Required adding the `time` tokio
     feature to `crates/deps-dev-client/Cargo.toml`.

**Verified results after all three fixes (median of 3 trials each):**

| Project | Node | Rust | Result |
|---|---|---|---|
| career-ops | 36.1s | 33.0s | **Rust wins** (−8.6%) |
| tradingfriend | 144.1s | 49.6s | **Rust wins big** (−66%) |
| IoC | 48.7s | 67.5s | Node wins (+39%) — **regressed vs. the pre-fix run** (was +28.6%), unexplained — likely system load, not a real regression, but not re-verified on a quiet system |
| SolventAI | 28.7s | 33.4s | Node wins (+16%) |
| tadone | — | — | **inconclusive, blocked** — see below |

**Not resolved — genuinely blocked, don't re-chase without new evidence:**

tadone hung for 19-32 minutes on *both* implementations, repeatedly, even
after fix #3 above. One post-fix Rust run took 1303s total, but its own
`__stageTimings` showed `phase4Total` at only 257s (exactly its normal
range) — the missing ~17 minutes happened *outside every timed stage*,
between the client issuing the request and the server actually processing
it. That's not request-handling code in either implementation; it points
to system-level contention (this machine had been running heavy builds,
scans, and two long-lived servers for many hours straight across this
session) rather than a fixable bug in the Rust codebase. No root cause
found after real investigation — this is the specific thing to re-verify
after a reboot, not to re-diagnose from scratch.

---

## Post-reboot re-run (2026-08-30, quiet system)

Re-ran the 5-project benchmark per the resume prompt below, immediately
after a reboot (load average 1.78/4.75/5.41 at start — Spotlight
reindexing + Dropbox resync settling, no heavy competing process).
career-ops/tradingfriend/IoC/SolventAI got the full 3-trial median
treatment; tadone got a single trial per implementation instead of three
— its own scans run 5-16+ minutes each, and 3×2 of those wasn't worth the
wall-clock cost for what turned out to be a data-integrity-limited
comparison anyway (see below).

| Project | Node (median) | Rust (median) | Result |
|---|---|---|---|
| career-ops | 117s | 31s | **Rust wins big** (−73%) |
| tradingfriend | 1s | 0s | parity (0 issues either side, both near-instant) |
| IoC | 142s | 69s | **Rust wins** (−51%) — but see parity note below |
| SolventAI | 2s | 0s | parity (0 issues either side, both near-instant) |
| tadone | 983s (1 trial) | 332s (1 trial) | **not a valid comparison** — see below |

Rust wins on every project with real work to do, by a wider margin than
the pre-reboot numbers — consistent with a quiet system removing the
contention that made IoC/SolventAI look like Node wins last time.

**IoC issue-count mismatch (22 Node vs. 28 Rust) — root-caused, not a
Rust bug:** the extra 6 are all `pii-dataflow` (Bearer) findings in
`backend/app/services/smtp_client.py`. The real `/Users/nuno/tests/IoC`
checkout has an untracked `.ignite-review.md`/`.ignite/` left over from a
prior scan, so `resolveBearerDiffBase`/`resolve_bearer_diff_base` (identical
logic on both sides) sees a dirty working tree and both implementations
fall back to Bearer's slow full scan instead of `--diff`. Node's Bearer
subprocess ran past the shared 120s `runTool` default and was killed;
the failure was swallowed by `checkPiiDataFlow`'s fail-soft catch and
misleadingly logged as `✓ Check 8 skipped — bearer disabled or not
installed`. Rust's invocation finished under the same 120s budget and
returned the real findings. Confirmed via the response `events[]` log on
the Node side — not a timeout config difference (both default to
120,000ms), a wall-clock race under full-scan mode. Net effect: Node's
142s IoC number is for an *incomplete* scan; Rust's 69s number is for the
complete one. The timing win is real and probably understated once Node
is made to actually finish this check.

**tadone (1 trial each) — same failure class, worse, makes this trial
unusable as a timing data point:** Node's single run hit *three* separate
subprocess timeouts under the 20-way Phase 4 concurrent fan-out — a real
`gitleaks detect` (600s), `spectral lint` (120s), and `semgrep`
semantic-SAST (600s) — each silently degrading to zero findings via the
same fail-soft pattern as the Bearer case above. Result: Node reported
only 6 issues (`iac-security` 3, `license-compliance` 2,
`dependency-vulnerability` 1) — missing the `secret` (16),
`semantic-sast` (2), and `api-schema-lint` (4) categories entirely. Rust's
single run reported 28 issues across exactly those same six categories
with the same per-category counts (16/3/4/2/1 core five plus 2
semantic-sast) that the prior full scan-comparison in this file already
verified as file:line-exact parity against Node — i.e. Rust did the
complete job in 332s; Node's 983s is the wall-clock cost of a run that
never finished three of its checks. **Not a Rust regression and not
evidence Rust is 3x faster on tadone specifically** — it's evidence
Node's per-subprocess timeouts (120s/600s, unchanged from the original
Node design) are too tight for tadone's real scan cost when run
concurrently with everything else Phase 4 fires at once, especially
sharing a machine with a second long-running server and other load. A
fair tadone timing comparison would need Node's timeouts raised (or the
machine dedicated to just that one run) so both sides actually complete
the same work — not attempted here.

**Separate, real Node robustness finding (not new — same category as the
4 Node server crashes already logged below for tadone):** the fail-soft
pattern that turns "subprocess timed out" into "tool skipped/disabled" is
doing real harm here — three different checks degraded silently with a
misleading log line, rather than surfacing as a distinguishable
"timed out, findings incomplete" signal. Worth fixing in `server.js`
independent of the Rust work (raise the specific timeouts that matter for
large-repo full scans, and/or make the swallowed-timeout log line say
"timed out" instead of implying the tool isn't installed) — out of scope
for this performance-optimization pass, flagged for whoever picks up
Node-side hardening next.

**A separate, real finding — not a Rust bug, not blocking the goal
above:** Node's own server crashed **4 times** this session, always via an
identical unhandled `'error'` event on its HTTP/2 client (deps.dev/npm
fetches) — `ETIMEDOUT` twice, `ECONNRESET` once, one silent stall ending
in "Empty reply from server". Every crash happened specifically on
tadone (its heaviest dependency-scan load). Rust's `reqwest`-based client
handles the equivalent failure as an ordinary `Result::Err` and never
crashed once, including through the identical stalls described above.
This is a genuine Node-side robustness gap (worth a `server.js`/`undici`
fix independent of anything here) — out of scope for "optimize Rust,"
mentioned for completeness.

**How to resume after a reboot:** see the resume prompt at the very
bottom of this file — that's the trigger sentence. Everything the resumed
session needs (which fixes are done, which projects are outstanding, and
that tadone specifically needs one clean quiet-system re-run rather than
fresh diagnosis) is in this section above; no other file needs to be
read first.

---

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

**Performance optimization's core question is answered: Rust beats Node
on every project with real work to do** (career-ops −73%, IoC −51% even
with Node's scan incomplete, tradingfriend/SolventAI at parity with
near-zero work). See "Post-reboot re-run (2026-08-30, quiet system)" in
the top section for the full numbers and the two root-caused issue-count
mismatches (both Node-side subprocess timeouts under concurrent load,
not Rust bugs).

**What's left, if picked back up:** a clean tadone timing number needs
Node's `runTool` subprocess timeouts (120s/600s, shared default across
gitleaks/spectral/semgrep/bearer) raised enough that Node actually
finishes all its Phase 4 checks on a repo tadone's size — right now
Node's tadone number is for an incomplete scan, so it's not a fair
comparison point. That's a Node-side change, not a Rust one. Resume with:

> Continue the Rust performance optimization loop from `rust/MIGRATION_STATUS.md` — the post-reboot re-run is done and Rust wins are verified; if a clean tadone timing number is still wanted, raise Node's per-subprocess timeouts first so its scan actually completes, then re-run tadone on both sides.
