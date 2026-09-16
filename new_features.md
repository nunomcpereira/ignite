# Ignite implementation backlog

## Objective

Evolve Ignite from an upload-oriented pipeline into a durable repository governance application. Preserve its Rust backend, scanner integrations, browser/CLI/MCP entry points, Studio, review workflows, GitHub publishing, and continuous monitoring capabilities.

This document translates the architecture review into implementable user stories. It is an implementation specification, not authorization to deploy, publish repositories, send real notifications, or modify production data while testing.

## Instructions for Claude

- Read `CLAUDE.md` and applicable repository instructions before implementation. Inspect current code before each story; the paths below identify starting points, not an exhaustive list of affected files.
- Implement in the dependency order below. Finish each story end to end: schema migration, domain logic, API integration, UI/client integration where required, tests, and documentation.
- Preserve unrelated work. Use additive database migrations and compatibility adapters. Existing installations, historical records, CLI consumers, MCP clients, and integrations must continue working throughout migration.
- Keep Rust and axum. Keep SQLite for the local/single-host deployment. A PostgreSQL migration, distributed broker, Kubernetes deployment, and wholesale replacement of scanner implementations are outside this backlog.
- Do not repurpose `rust/crates/api-schema`: it scans submitted projects' API specifications. Ignite's own API contract needs a distinct module or package.
- Keep branding in `public/branding.config.js` and preserve all four existing UI locales. Never include secrets in events, evidence manifests, browser bundles, fixtures, or logs.
- Preserve archive traversal and size guards, symlink restrictions, subprocess argument-array execution, environment filtering, source isolation, authenticated attribution, and existing approval restrictions.
- Resolve routine implementation choices autonomously. Record material choices and compatibility implications in the relevant documentation. Do not mark a story complete because a placeholder, mock-only implementation, or disconnected endpoint exists.
- Use isolated temporary databases, source trees, fake tools, and fake GitHub/notification services for automated checks. Never scan or publish real customer code as a test side effect.

## Implementation sequence

| Order | Story | Dependencies |
|---|---|---|
| 1 | US-01 Repository, snapshot, and scan identity | None |
| 2 | US-02 Explicit check outcomes and versioned policy | US-01 |
| 3 | US-03 One workflow service for every entry point | US-01, US-02 |
| 4 | US-04 Durable jobs and restart recovery | US-03 |
| 5 | US-05 Reproducible evidence and source retention | US-01, US-02, US-04 |
| 6 | US-06 Safe, idempotent publication | US-04, US-05 |
| 7 | US-07 Stable findings across scans | US-01, US-02 |
| 8 | US-08 Repository-scoped reviews and exceptions | US-04, US-05, US-07 |
| 9 | US-09 Transactional audit and reliable delivery | US-04, US-08 |
| 10 | US-10 Isolated workers and resource scheduling | US-04, US-06 |
| 11 | US-11 Typed frontend and structured progress | US-03, US-04, US-08 |
| 12 | US-12 Task-oriented navigation and accessible themes | US-07, US-08, US-11 |

US-07 may be implemented immediately after US-02. The listed order is a safe default for completing the whole backlog sequentially.

## Shared contracts

These are target concepts; choose idiomatic Rust names and match existing API casing through explicit serialization.

- `Repository`: durable identity, organization, repository name, optional GitHub repository ID, access scope.
- `SourceSnapshot`: repository ID, canonical source digest, optional commit SHA, storage reference, creation time, retention state. Uncommitted uploads must also be supported.
- `ScanRun`: snapshot ID, initiator, source channel, immutable policy version, lifecycle state, timestamps, cancellation intent, idempotency metadata.
- `CheckExecution`: run ID, check ID, attempt, outcome, engine/version, rules/config digest, coverage scope, findings and artifact references, timing, failure reason.
- `PolicyDecision`: run ID, decision (`pass`, `needs_review`, `blocked`, `incomplete`), reasons, required coverage, applicable exceptions, evidence digest. A completed scan is not necessarily a passing scan.
- `RunEvent`: run ID, monotonically increasing sequence, schema version, timestamp, typed payload. Logs are one payload type, not the source of workflow state.
- `Finding` and `FindingObservation`: persistent problem identity and run-specific evidence/location respectively.
- `Exception`: finding/repository scope, evidence scope, requester, justification, reviewer decision, expiry, policy version, audit references.
- `PublicationAttempt`: approved snapshot and decision references, destination, stage, remote identifiers, retry/reconciliation state.

Keep external `jobId` and legacy `projectId` resolvable through a compatibility mapping. Do not invent trustworthy historical versions, digests, identities, or coverage where the old database did not record them; label those values as legacy/unknown.

## US-01 — Separate repository identity from scan execution

**User story:** As a repository owner, I want every upload, rescan, and webhook-triggered assessment attached to the same repository so that I can see its history without treating each scan as a new application.

**Implementation scope**

- Add normalized repository, snapshot, and scan-run tables with foreign keys and indexes.
- Backfill existing project/job records and retain a legacy ID mapping. Prefer GitHub's repository ID when available; use normalized organization/name for legacy matching without merging different organizations.
- Update history, onboarded repositories, schedules, webhooks, documents, and run lookups to use the new model through compatible service methods.
- Preserve raw source channel, original timestamps, issue associations, and existing URLs.

**Acceptance criteria**

- [ ] Two scans of the same repository produce one repository and two runs, each referencing its own snapshot or a safely deduplicated identical snapshot.
- [ ] Different repositories with the same short name remain separate.
- [ ] Historical `projectId` and `jobId` URLs still resolve to the correct run.
- [ ] Enrollment-only records remain distinguishable from actual scans.
- [ ] Migration succeeds on a representative existing database and is safe to rerun; foreign keys remain valid.
- [ ] Repository rename handling preserves history when a stable GitHub repository ID is known.

**Verification:** Migration fixtures for empty and populated databases; duplicate enrollment and rename tests; existing history/onboarded-repository endpoint tests.

**Starting points:** `rust/crates/db-store/src/{schema,projects,types,scheduled}.rs`, `rust/crates/server/src/routes/{history,onboarded_repos,repository_events_webhook}.rs`.

## US-02 — Report coverage separately from findings

**User story:** As a reviewer, I want to know which checks actually ran and which policy was applied so that a clean finding list cannot be mistaken for a complete assessment.

**Implementation scope**

- Introduce a common check result envelope with outcomes `completed`, `not_applicable`, `disabled`, `unavailable`, `failed`, `timed_out`, and `cancelled`.
- Adapt all checks, including Phase 3 tests/licenses and Phase 5 governance CI, to report an explicit outcome. Preserve raw findings and engine-specific evidence.
- Distinguish full engines from fallbacks and describe each engine's actual coverage. A fallback satisfies a requirement only when policy explicitly permits it.
- Persist immutable policy versions containing required checks/capabilities, applicability rules, finding thresholds, exception rules, and permitted degraded behavior.
- Supply a legacy-compatible profile for migrated installations and an explicit strict publication profile. Preserve legacy behavior while displaying incomplete coverage; require deliberate configuration to change an existing installation's gating policy.
- Evaluate findings and coverage in a pure domain function shared by every entry point. Project input cannot weaken an organization-required policy.

**Acceptance criteria**

- [ ] Missing Semgrep, a Semgrep timeout, a disabled check, and a successful check with zero findings yield distinct persisted outcomes.
- [ ] A strict policy requiring an unavailable check yields `incomplete` and prevents publication.
- [ ] A genuinely inapplicable check does not block, with its applicability reason recorded.
- [ ] Advisory findings remain visible without necessarily blocking publication.
- [ ] Changing configuration after a run starts does not alter that run's pinned policy.
- [ ] Browser, CLI, API, and MCP expose equivalent decision and coverage information.
- [ ] Cache hits retain engine/version/scope provenance and do not conceal missing or stale coverage.

**Verification:** Table-driven policy tests covering every outcome, fallback, severity, and exception combination; fake-tool timeout/missing-binary integration tests.

**Starting points:** `rust/crates/phase4-orchestrator`, `rust/crates/pipeline-gate`, `rust/crates/override-engine`, `rust/crates/config`, `rust/crates/unit-test-runner`, `rust/crates/governance-ci`.

## US-03 — Use one application workflow for every client

**User story:** As an operator, I want browser, CLI, API, and MCP scans to enforce the same rules so that the calling interface never changes the governance outcome.

**Implementation scope**

- Extract orchestration into a Rust application service with typed commands such as `StartScan`, `CancelRun`, `SubmitReview`, and `PublishApprovedSnapshot`.
- Centralize phase progression, actor resolution, policy evaluation, persistence, event emission, staging cleanup, and error mapping.
- Keep upload parsing and HTTP response formatting in transport adapters.
- Preserve synchronous validate responses and streaming browser responses as adapters over the same service; MCP remains an API client.
- Keep validation/dry-run incapable of publishing without a separate authorized publication command.

**Acceptance criteria**

- [ ] Equivalent source, policy, and actor inputs produce equivalent checks, findings, and decisions through all supported interfaces.
- [ ] Route modules no longer own independent phase execution loops or copies of policy logic.
- [ ] Existing response fields and status behavior remain compatible; additive fields are documented.
- [ ] Authentication and actor attribution follow one shared rule; unverified body fields cannot authorize reviews or publication.
- [ ] Errors, cancellation, and panics converge on a documented cleanup/recovery path.

**Verification:** Shared workflow fixtures exercised through interactive, validate, onboard, and MCP adapters; regression tests for existing route contracts and dry-run behavior.

**Starting points:** `rust/crates/server/src/routes/pipeline_{validate,onboard,interactive}.rs`, `rust/crates/server/src/routes/pipeline_interactive/`, `rust/crates/pipeline-core`, `rust/crates/mcp-server`.

## US-04 — Resume scans and reviews after restart

**User story:** As a user running a lengthy scan, I want progress and pending review to survive disconnects and server restarts so that I can continue without starting over.

**Implementation scope**

- Persist lifecycle states `queued`, `scanning`, `awaiting_review`, `approved`, `publishing`, `published`, plus terminal `completed` (non-publication scan), `blocked`, `failed`, and `cancelled` states.
- Define and enforce legal transitions. Store the policy decision separately from execution state.
- Add database-backed work claims, expiring leases, heartbeats, bounded retries, and attempt/fencing tokens so a stale worker cannot commit results after its lease is reassigned.
- Resume from completed check checkpoints where evidence remains valid; retry interrupted checks rather than pretending an interrupted process can resume internally.
- Replace review oneshot channels and pending-publication maps as authoritative state with persisted records.
- Persist sequenced events and provide run status plus cursor-based event replay. Keep the existing stream adapter functional.
- Support scoped idempotency keys: same key and payload returns the same run; conflicting payload returns a conflict.

**Acceptance criteria**

- [ ] Browser disconnect does not cancel a scan; explicit cancellation does.
- [ ] Restart during scanning recovers the run without duplicating accepted check results.
- [ ] Restart while awaiting review preserves the source reference, findings, and ability to submit an authorized decision.
- [ ] Two workers cannot both commit the same leased attempt; stale workers are fenced out.
- [ ] Reconnecting with an event cursor replays ordered events without losing transitions; clients tolerate duplicate delivery.
- [ ] A missing required snapshot causes a clear recoverable failure, never a passing decision.
- [ ] Cancellation stops active work and prevents later publication; irreversible publication already completed is reported accurately.

**Verification:** Process restart tests against an isolated persistent database; lease expiry, stale completion, duplicate submission, reconnect, cancellation, and review recovery tests.

**Starting points:** `rust/crates/server/src/{state,review_gate}.rs`, interactive pipeline handlers, `rust/crates/db-store`, `rust/crates/tool-runner`.

## US-05 — Preserve verifiable evidence with explicit retention

**User story:** As an auditor or reviewer, I want a reproducible record of the source, tools, and policy used for a decision so that I can explain an approval later.

**Implementation scope**

- Define canonical snapshot hashing: normalized relative paths, file bytes, and relevant executable modes; exclude tool-generated artifacts and VCS administrative data from source identity under a documented rule.
- Keep canonical source immutable; scanners and Studio edits use derived workspaces. An edit creates a new snapshot and invalidates affected approval/evidence.
- Store a versioned evidence manifest containing source digest, commit SHA when available, policy/config digests, check outcomes/scopes, tool/ruleset versions, cache provenance, timestamps, and artifact digests.
- Make cache validity depend on relevant source/dependency context, engine/rules/config versions, and advisory freshness where applicable. Do not reuse a cached policy decision as if it were fresh scan evidence.
- Implement configurable source/artifact retention with expiry timestamps and an independently scheduled sweeper. Track full, pruned, expired, and missing states explicitly.
- Pin snapshots during active work/review/publication under a documented bounded lease; expose expiry and rescan requirements to clients.
- Retain decision metadata when source expires, according to a separate metadata retention setting. Update README lifecycle claims to match behavior.

**Acceptance criteria**

- [ ] Identical source hashes consistently; meaningful file/content/mode changes alter the digest.
- [ ] Generated scanner output cannot silently change the approved source digest.
- [ ] A Studio edit creates new evidence requirements before publication.
- [ ] Evidence export identifies all actual engines and degraded/skipped checks without exposing secrets or absolute host paths.
- [ ] Cleanup runs even when no new scans arrive, survives restart, and does not delete a legitimately leased artifact.
- [ ] Expired source yields an explicit rescan requirement while historical decision metadata remains viewable.
- [ ] A ruleset/config change or expired vulnerability data invalidates affected cache entries.

**Verification:** Digest determinism and tamper tests; fake-clock retention tests; concurrent cleanup/lease tests; cache invalidation fixtures; export redaction checks.

**Starting points:** `rust/crates/server/src/routes/pipeline_interactive/run.rs`, `rust/crates/db-store/src/{retained_sources,caches}.rs`, `rust/crates/staging`, `rust/crates/provenance`.

## US-06 — Publish exactly the approved snapshot, once

**User story:** As a repository owner, I want publication retries to reconcile safely and publish only reviewed code so that a network failure cannot create duplicate or unapproved results.

**Implementation scope**

- Persist publication intent and stages before remote side effects: destination resolution, repository/branch provisioning, push, optional PR creation, completion.
- Bind publication to the approved snapshot digest, evidence manifest, policy decision, and valid exceptions. Recheck these preconditions at publication time.
- Give publication a stable operation identity and reconcile GitHub state after ambiguous failures. Persist remote repository, commit, branch, and PR identifiers.
- Isolate publishing credentials from scan execution. Preserve existing destination semantics and authorization checks.
- Do not overwrite or delete a preexisting unrelated repository/branch to make a retry succeed.

**Acceptance criteria**

- [ ] Repeating the same publication request returns the existing operation/result.
- [ ] Restart after repository creation or successful push resumes by reconciliation without duplicate repositories or PRs.
- [ ] Source digest mismatch, expired exception, incomplete required coverage, or revoked access prevents publication with an actionable reason.
- [ ] A destination collision fails safely without changing unrelated remote content.
- [ ] Dry-run/validate endpoints never cause remote writes.
- [ ] Successful publication records the actual resulting commit and links it to the approved snapshot.

**Verification:** Fake GitHub fault injection before/after each side effect, concurrent publication requests, digest mismatch, revoked authorization, and destination collision tests.

**Starting points:** `rust/crates/server/src/routes/effectivate.rs`, interactive publication path, `rust/crates/shipping`, `rust/crates/github-api`.

## US-07 — Track findings reliably across scans

**User story:** As a developer, I want existing problems to retain their identity when code moves so that I can distinguish new risks from previously reviewed findings.

**Implementation scope**

- Separate stable finding records from per-run observations, preserving raw scanner IDs, locations, traces, and evidence.
- Version fingerprints. Prefer native stable fingerprints when available; otherwise combine rule identity, repository, normalized location/context or symbol, and relevant discriminators.
- Use ecosystem/package/advisory identity for dependency findings. Avoid treating unrelated rules on the same line as the same finding.
- Use conservative matching for ambiguous code moves; preserve distinct findings rather than automatically transferring exceptions.
- Add lifecycle `open`, `resolved`, `reopened` and per-comparison classification `new`/`existing`. Exceptions are separate dispositions.
- Mark absent findings resolved only when a comparable successful check covered their relevant scope. A failed, disabled, or partial check cannot prove resolution.
- Preserve old issue IDs through compatibility aliases and migrate baselines conservatively.

**Acceptance criteria**

- [ ] Adding blank lines above unchanged code preserves finding identity.
- [ ] Different rules on the same line and different CVEs in the same package remain distinct.
- [ ] Failed or unavailable scanners never mark prior findings fixed.
- [ ] Reintroducing a previously resolved problem produces a reopened observation.
- [ ] Ambiguous matching does not silently inherit approval.
- [ ] History, baselines, SARIF, fix workflows, and legacy issue links resolve consistently.

**Verification:** Multi-run fixtures for line drift, rename, repeated snippets, changed rule identity, dependency upgrades, partial scans, and recurrence.

**Starting points:** `rust/crates/override-engine/src/{model,validation,collect}.rs`, `rust/crates/db-store/src/{issues,baseline}.rs`, `rust/crates/sarif`, `rust/crates/baseline-filter`.

## US-08 — Scope reviews and exceptions to repositories and evidence

**User story:** As a governance administrator, I want repository-scoped review permissions and expiring exceptions so that approvals remain attributable and applicable to the evidence actually reviewed.

**Implementation scope**

- Add explicit permissions for view, scan, review, publish, and policy administration, scoped to repositories/organizations as appropriate.
- Apply the same authorization service to browser sessions and API keys; keys cannot exceed their owner's granted scope.
- Migrate configured approver email lists into equivalent explicit grants without broadening access or removing existing dual-approval requirements.
- Persist requested/approved/rejected/revoked/expired exception states, requester, reviewer, reason, expiry, policy version, and relevant evidence scope.
- Require independent approval where policy mandates it; drafts and AI-generated explanations cannot approve exceptions.
- Reevaluate validity when evidence, policy, permissions, or time changes. Expired/revoked exceptions cannot authorize a later publication.
- Add review queue, decision history, and actionable expiry information to the API and frontend.

**Acceptance criteria**

- [ ] Reviewers cannot approve outside their repository scope or self-approve when independent review is required.
- [ ] Revoked users/keys cannot act through stale sessions or queued commands.
- [ ] An exception records exactly which finding/evidence scope and policy it covers.
- [ ] Material evidence changes invalidate applicability; harmless location drift alone can preserve it under the fingerprint rules.
- [ ] Expiry is enforced server-side even if a browser remains open.
- [ ] AI-generated justification remains an explicitly reviewed draft and never changes approval state by itself.
- [ ] Existing deployments retain equivalent authorized reviewer access after migration.

**Verification:** Authorization matrix, key scope, cross-repository denial, independent-review, evidence change, fake-clock expiry, and migration tests.

**Starting points:** `rust/crates/server/src/{auth,ai_justify}.rs`, `rust/crates/server/src/routes/override_approval.rs`, `rust/crates/db-store/src/{overrides,auth,api_keys}.rs`.

## US-09 — Commit audit records with decisions and retry delivery

**User story:** As an operator, I want governance changes durably audited and external deliveries retried so that an unavailable SIEM does not lose the record of an approval.

**Implementation scope**

- Commit domain state changes, local audit entries, and configured outbound delivery records in the same database transaction.
- Preserve the existing tamper-evident audit chain; serialize chain updates correctly inside transactions.
- Add an outbox worker with per-sink delivery state, stable event ID, timeout, bounded backoff, attempt history, and failed-delivery inspection/retry.
- Use at-least-once delivery and expose a deduplication ID to receivers; do not claim exactly-once delivery to external services.
- Keep sink credentials out of persisted payloads and resolve them from protected configuration.

**Acceptance criteria**

- [ ] A transaction failure leaves neither an unaudited decision nor an audit record for an uncommitted decision.
- [ ] Server restart after commit but before delivery eventually sends the event.
- [ ] One failing sink does not prevent another sink from receiving its delivery.
- [ ] Retries preserve the event ID and surface permanent failures without unbounded tight loops.
- [ ] Existing audit verification succeeds after concurrent decisions and migrations.
- [ ] External outages do not block a decision once its transaction commits.

**Verification:** Transaction rollback tests, restart recovery, fake HTTP sink failures/timeouts, duplicate delivery identifiers, and audit-chain verification under concurrency.

**Starting points:** `rust/crates/server/src/state.rs`, `rust/crates/db-store/src/{audit_events,projects,overrides}.rs`, `rust/crates/audit-log`.

## US-10 — Run scans with controlled resources and isolated credentials

**User story:** As an operator, I want scan workloads isolated and resource-limited so that concurrent submissions cannot exhaust the application server or acquire publication credentials.

**Implementation scope**

- Move scanner execution behind the durable worker interface. Support a local deployment with API and worker processes on one host using SQLite leases.
- Introduce configurable job concurrency and weighted limits for expensive checks, plus CPU, memory, process, disk/output, and wall-time budgets for executable workloads.
- Separate dependency-fetch and execution network requirements; enforce documented network profiles instead of merely logging an isolation claim.
- Keep immutable source read-only and create private writable scratch copies. Preserve shell-command restrictions at host process boundaries.
- Give Docker access only to the worker role; the API and publisher roles do not require the host socket. Treat a Docker-socket worker as privileged infrastructure and document its host boundary accurately.
- Give the publisher only the credentials and source/evidence access it needs; exclude publication/session/notification credentials from scanner environments.
- Cancel descendant processes/containers and release workspaces on timeout, cancellation, and recovery.

**Acceptance criteria**

- [ ] Submitting more jobs than capacity queues excess work while API status/review requests remain responsive.
- [ ] Heavy checks across different jobs respect the configured global budget on the supported single-host deployment.
- [ ] A test workload exceeding a resource limit is terminated and recorded with an explicit outcome.
- [ ] Scanner processes and test containers cannot read publishing credentials from their environment or mounts.
- [ ] Network restrictions are verified by executable fixtures.
- [ ] Cancellation/timeout leaves no tracked descendant container or process running and releases its lease.
- [ ] Local setup and Compose documentation cover worker/publisher roles, shared artifact paths, and restart recovery.

**Verification:** Concurrent fake-job load tests, actual isolated resource/network boundary tests where Docker is available, environment/mount assertions, and descendant cleanup tests. Report unavailable Docker tests as unexecuted, not passed.

**Starting points:** `rust/crates/tool-runner`, `rust/crates/unit-test-runner`, `rust/crates/governance-ci`, `rust/crates/phase4-orchestrator`, `Dockerfile`, `docker-compose.yml`.

## US-11 — Introduce a typed frontend and structured event client

**User story:** As a user, I want consistent live state across scans, reviews, and Studio so that reconnecting or navigating does not leave controls showing stale information.

**Implementation scope**

- Establish a TypeScript component frontend with a reproducible build; use React and Vite as the default implementation choice unless repository constraints discovered during implementation justify a documented alternative.
- Generate client types/API bindings from Ignite-owned Rust request/response schemas. Include a CI drift check; do not manually maintain duplicate domain contracts.
- Consume typed check/lifecycle events with sequence-based deduplication and reconnect replay. Remove log-regex-derived progress.
- Separate server state, URL navigation state, and local form drafts. Use run IDs in cache keys; prevent updates for one run from modifying another run's screen.
- Migrate incrementally with feature parity for upload, dry-run, multi-job tracking, findings, review, Studio editing/rescan, AI assistance, history, repository management, and settings.
- Preserve static hosting through axum, branding configuration, locale fallbacks, and supported authentication modes. Bundle production assets locally, including styles.

**Acceptance criteria**

- [ ] Build/type checking fails when API contract changes are not reflected in the generated client.
- [ ] Progress reflects structured check events even if human log wording changes.
- [ ] Reload/reconnect restores the selected run and review state.
- [ ] Switching between simultaneous jobs never mixes findings, progress, or drafts.
- [ ] Existing end-to-end workflows remain functional after migration.
- [ ] Production UI loads without a runtime Tailwind CDN dependency.
- [ ] All four locales and customer branding remain supported; changing locale updates visible translated components.

**Verification:** Type/build checks, contract drift check, event reducer/reconnect tests, and the existing Playwright suite updated for semantic locators where necessary.

**Starting points:** `public/index.html`, `public/i18n.js`, `public/branding.config.js`, `rust/crates/server/src/main.rs`, `e2e/`, root `package.json`.

## US-12 — Organize the UI around ongoing governance tasks

**User story:** As a developer or reviewer, I want to navigate directly to repositories, outstanding findings, and pending reviews so that ongoing governance work is easy to find after onboarding.

**Implementation scope**

- Introduce primary navigation for Repositories, Scan runs, Findings and remediation, Reviews and exceptions, and Policies and integrations.
- Keep the phase timeline inside run details. Provide repository history, current coverage/decision, finding deltas, and pending actions with contextual links to Studio or publication.
- Clearly label run execution status, policy decision, coverage gaps, and source expiry as separate information.
- Add deep links and URL-backed filters for repository, severity, finding lifecycle, and review status; enforce server-side pagination/filtering for growing lists.
- Replace dark-mode color inversion with semantic CSS tokens for surfaces, text, borders, status, and focus states, preserving brand overrides.
- Maintain keyboard navigation, visible focus, labeled controls, modal focus handling, and screen-reader status announcements. Do not convey outcomes through color alone.

**Acceptance criteria**

- [ ] A reviewer can find pending decisions and inspect evidence without opening an upload flow.
- [ ] A developer can filter new/reopened findings for a repository and open the corresponding source observation.
- [ ] Shared deep links restore the selected repository/run and filters subject to access permissions.
- [ ] A scan with missing required coverage is visibly distinct from a fully assessed passing scan.
- [ ] Light/dark themes render readable native controls, Studio, logs, and dialogs without body-level inversion.
- [ ] Main workflows are keyboard operable and status meaning is available through text.
- [ ] Large history/finding lists paginate without loading the entire dataset into the browser.

**Verification:** Playwright navigation/filter/deep-link tests; keyboard/focus checks; light/dark screenshots for main views, dialogs, Studio, and errors; representative large-list fixtures.

**Starting points:** New frontend from US-11, history/issues/review/config API routes, `public/branding.config.js`, `e2e/`.

## Cross-story completion requirements

- [ ] Update README and relevant `docs-site/docs/` guides for actual API contracts, lifecycle, policy behavior, retention, deployment, recovery, and migration.
- [ ] Update `CLAUDE.md` where module locations, architecture, build commands, or hardening invariants change.
- [ ] Run targeted Rust tests during each story. At integration milestones run `cargo nextest run --workspace` and `cargo clippy --workspace --all-targets` from `rust/`.
- [ ] Run frontend type/build checks and `npm run test:e2e` when UI or shared API behavior changes. Record unavailable external-tool checks separately from passed tests.
- [ ] Demonstrate the full isolated scenario: submit source → scan → disconnect/restart → inspect coverage/findings → edit and rescan → independent review → publish through fake GitHub → retry publication → rescan → expire source while retaining audit/evidence metadata.
- [ ] Demonstrate compatibility against a copy of a legacy database and existing CLI/MCP request fixtures.
- [ ] Remove replaced in-memory authorities, duplicate orchestration paths, and log-derived state once adapters are migrated; do not leave two competing sources of truth.
- [ ] Record completed story IDs, validation results, migration implications, and any remaining limitations in the implementation handoff. An unchecked acceptance criterion remains unfinished work.
