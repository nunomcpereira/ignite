//! SQL schema, migrations, and one-off backfill DDL — split out of lib.rs
//! so the giant DDL string literals don't dominate the crate's main file.

pub(crate) const SCHEMA_SQL: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA busy_timeout = 5000;
CREATE TABLE IF NOT EXISTS projects (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id      TEXT UNIQUE NOT NULL,
  org         TEXT NOT NULL,
  repo        TEXT NOT NULL,
  gxp         INTEGER NOT NULL DEFAULT 0,
  source      TEXT NOT NULL DEFAULT 'ui',
  scan_location TEXT,
  status      TEXT NOT NULL DEFAULT 'running',
  error       TEXT,
  repo_url    TEXT,
  pr_url      TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  finished_at TEXT
);
CREATE TABLE IF NOT EXISTS steps (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  phase      INTEGER NOT NULL,
  title      TEXT NOT NULL,
  state      TEXT NOT NULL,
  logs       TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_steps_project_phase
  ON steps(project_id, phase);
CREATE TABLE IF NOT EXISTS documents (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  kind       TEXT NOT NULL CHECK (kind IN ('upload','link')),
  name       TEXT NOT NULL,
  url        TEXT,
  mime       TEXT,
  size       INTEGER,
  data       BLOB,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  email         TEXT UNIQUE NOT NULL,
  name          TEXT,
  provider      TEXT NOT NULL DEFAULT 'local' CHECK (provider IN ('local','oidc','github')),
  password_hash TEXT,
  external_id   TEXT,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_provider_external
  ON users(provider, external_id);
CREATE TABLE IF NOT EXISTS sessions (
  id         TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS api_keys (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  key_hash      TEXT UNIQUE NOT NULL,
  label         TEXT,
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  created_by    TEXT,
  created_via   TEXT NOT NULL DEFAULT 'cli',
  last_used_at  TEXT,
  revoked_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
CREATE TABLE IF NOT EXISTS overrides (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id   INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  job_id       TEXT NOT NULL,
  phase        INTEGER NOT NULL,
  issue_id     TEXT NOT NULL,
  category     TEXT NOT NULL,
  severity     TEXT NOT NULL,
  summary      TEXT NOT NULL,
  file         TEXT,
  line         INTEGER,
  justification TEXT NOT NULL,
  actor_email  TEXT NOT NULL,
  actor_name   TEXT,
  email_sent   INTEGER NOT NULL DEFAULT 0,
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_overrides_project ON overrides(project_id);
CREATE TABLE IF NOT EXISTS issues (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id   INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  issue_id     TEXT NOT NULL,
  phase        INTEGER,
  category     TEXT NOT NULL,
  severity     TEXT NOT NULL,
  score        INTEGER,
  summary      TEXT NOT NULL,
  file         TEXT,
  line         INTEGER,
  snippet_json TEXT,
  cross_file   INTEGER NOT NULL DEFAULT 0,
  chain_json   TEXT,
  cwe          TEXT,
  owasp        TEXT,
  tool         TEXT,
  references_json TEXT,
  duplicate_ref_json TEXT,
  status       TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','overridden')),
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_issues_project ON issues(project_id);
CREATE TABLE IF NOT EXISTS issue_explanations (
  hash        TEXT PRIMARY KEY,
  explanation TEXT NOT NULL,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS file_scan_cache (
  org          TEXT NOT NULL,
  repo         TEXT NOT NULL,
  check_name   TEXT NOT NULL,
  rel_path     TEXT NOT NULL,
  hash         TEXT NOT NULL,
  findings_json TEXT NOT NULL,
  updated_at   TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (org, repo, check_name, rel_path)
);
CREATE TABLE IF NOT EXISTS manifest_scan_cache (
  tool          TEXT NOT NULL,
  ecosystem     TEXT NOT NULL,
  content_hash  TEXT NOT NULL,
  tool_version  TEXT NOT NULL,
  findings_json TEXT NOT NULL,
  updated_at    TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (tool, ecosystem, content_hash, tool_version)
);
CREATE TABLE IF NOT EXISTS codeql_scan_cache (
  org           TEXT NOT NULL,
  repo          TEXT NOT NULL,
  language      TEXT NOT NULL,
  file_set_hash TEXT NOT NULL,
  tool_version  TEXT NOT NULL,
  findings_json TEXT NOT NULL,
  updated_at    TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (org, repo, language, file_set_hash, tool_version)
);
CREATE TABLE IF NOT EXISTS cosign_verify_cache (
  image             TEXT NOT NULL,
  identity_regexp   TEXT NOT NULL,
  issuer_regexp     TEXT NOT NULL,
  verified          INTEGER NOT NULL,
  reason            TEXT,
  checked_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
  PRIMARY KEY (image, identity_regexp, issuer_regexp)
);
CREATE TABLE IF NOT EXISTS workflow_cache (
  repo         TEXT NOT NULL,
  filename     TEXT NOT NULL,
  commit_sha   TEXT NOT NULL,
  content      TEXT NOT NULL,
  updated_at   TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (repo, filename)
);
CREATE TABLE IF NOT EXISTS retained_sources (
  project_id  INTEGER PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
  dir_path    TEXT NOT NULL,
  retained_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS github_connections (
  user_id      INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  github_login TEXT NOT NULL,
  access_token TEXT NOT NULL,
  scope        TEXT,
  connected_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS issue_baselines (
  org        TEXT NOT NULL,
  repo       TEXT NOT NULL,
  issue_id   TEXT NOT NULL,
  saved_at   TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (org, repo, issue_id)
);
CREATE TABLE IF NOT EXISTS runtime_coverage (
  org         TEXT NOT NULL,
  repo        TEXT NOT NULL,
  rel_path    TEXT NOT NULL,
  hit_count   INTEGER NOT NULL DEFAULT 0,
  covered_pct REAL,
  updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (org, repo, rel_path)
);
CREATE TABLE IF NOT EXISTS pull_requests (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id    INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  kind          TEXT NOT NULL CHECK (kind IN ('onboarding','fix-pr')),
  url           TEXT NOT NULL,
  branch        TEXT,
  files_changed INTEGER,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_pull_requests_project ON pull_requests(project_id);
CREATE TABLE IF NOT EXISTS dependency_scan_cache (
  project_id  INTEGER PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
  scan_json   TEXT NOT NULL,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS issue_first_seen (
  org               TEXT NOT NULL,
  repo              TEXT NOT NULL,
  issue_id          TEXT NOT NULL,
  first_detected_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (org, repo, issue_id)
);
CREATE TABLE IF NOT EXISTS campaigns (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  title               TEXT NOT NULL,
  description         TEXT,
  category            TEXT,
  min_score           INTEGER,
  target_date         TEXT,
  initial_open_count  INTEGER NOT NULL DEFAULT 0,
  created_by          TEXT,
  created_at          TEXT NOT NULL DEFAULT (datetime('now')),
  closed_at           TEXT
);
CREATE TABLE IF NOT EXISTS fix_pr_previews (
  job_id           TEXT PRIMARY KEY,
  total            INTEGER NOT NULL DEFAULT 0,
  completed        INTEGER NOT NULL DEFAULT 0,
  done             INTEGER NOT NULL DEFAULT 0,
  cancelled        INTEGER NOT NULL DEFAULT 0,
  considered_count INTEGER NOT NULL DEFAULT 0,
  reason           TEXT,
  candidates_json  TEXT NOT NULL DEFAULT '[]',
  updated_at       TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS custom_secret_patterns (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT NOT NULL,
  regex       TEXT NOT NULL,
  enabled     INTEGER NOT NULL DEFAULT 1,
  created_by  TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS audit_events (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type    TEXT NOT NULL,
  severity      TEXT NOT NULL,
  summary       TEXT NOT NULL,
  actor         TEXT,
  org           TEXT,
  repo          TEXT,
  metadata_json TEXT,
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  prev_hash     TEXT NOT NULL,
  hash          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit_events(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_events_org_repo ON audit_events(org, repo);
CREATE TABLE IF NOT EXISTS webhook_deliveries (
  delivery_id TEXT PRIMARY KEY,
  seen_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_seen_at ON webhook_deliveries(seen_at);

-- US-01: durable repository identity, separate from any one scan
-- execution. `projects`/`steps`/`issues`/... stay exactly as they were —
-- every historical `jobId`/`projectId` URL still resolves through them
-- unchanged — these three tables sit alongside as the new normalized
-- identity model, backfilled from `projects` by
-- `BACKFILL_REPOSITORY_MODEL_SQL` below and kept live going forward by
-- `repositories.rs`'s `resolve_repository`/`record_scan_run`/
-- `finish_scan_run_for_project`, called from `create_project`/
-- `finish_project` (`projects.rs`).
CREATE TABLE IF NOT EXISTS repositories (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  org            TEXT NOT NULL,
  repo           TEXT NOT NULL,
  github_repo_id TEXT UNIQUE,
  access_scope   TEXT NOT NULL DEFAULT 'standard',
  created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_repositories_org_repo ON repositories(org, repo);
CREATE TABLE IF NOT EXISTS source_snapshots (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  repository_id   INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  source_digest   TEXT NOT NULL,
  commit_sha      TEXT,
  storage_ref     TEXT,
  retention_state TEXT NOT NULL DEFAULT 'unknown',
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_source_snapshots_dedup ON source_snapshots(repository_id, source_digest);
CREATE TABLE IF NOT EXISTS scan_runs (
  id                     INTEGER PRIMARY KEY AUTOINCREMENT,
  legacy_project_id      INTEGER UNIQUE REFERENCES projects(id) ON DELETE CASCADE,
  repository_id          INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  snapshot_id            INTEGER NOT NULL REFERENCES source_snapshots(id) ON DELETE CASCADE,
  initiator              TEXT,
  source_channel         TEXT NOT NULL DEFAULT 'unknown',
  policy_version         TEXT,
  lifecycle_state        TEXT NOT NULL DEFAULT 'queued',
  is_enrollment_only     INTEGER NOT NULL DEFAULT 0,
  cancellation_requested INTEGER NOT NULL DEFAULT 0,
  created_at             TEXT NOT NULL DEFAULT (datetime('now')),
  finished_at            TEXT
);
CREATE INDEX IF NOT EXISTS idx_scan_runs_repository ON scan_runs(repository_id);

-- US-04: persisted lifecycle-state history and the durable "awaiting
-- review" record — see `ignite-run-lifecycle` for the legal-transition
-- rules `lifecycle.rs`'s `transition_scan_run` enforces before writing a
-- row here, and `review_gate.rs` for the two call sites (`wait`/`resolve`)
-- that turn what used to be purely in-memory review-gate state into these
-- rows, so a server restart doesn't erase the fact a review was pending or
-- what it was decided.
CREATE TABLE IF NOT EXISTS scan_run_transitions (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id     INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
  from_state TEXT NOT NULL,
  to_state   TEXT NOT NULL,
  at         TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_scan_run_transitions_run ON scan_run_transitions(run_id);
CREATE TABLE IF NOT EXISTS pending_reviews (
  run_id       INTEGER PRIMARY KEY REFERENCES scan_runs(id) ON DELETE CASCADE,
  project_id   INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  org          TEXT NOT NULL,
  repo         TEXT NOT NULL,
  owner_email  TEXT NOT NULL,
  issues_json  TEXT NOT NULL,
  created_at   TEXT NOT NULL DEFAULT (datetime('now')),
  resolved_at  TEXT,
  decision_json TEXT
);

-- US-02: durable, per-check coverage and the policy conclusion reached
-- from it. Findings remain in `issues`; these rows instead answer the
-- separate question "what actually ran, with which engine and outcome?".
CREATE TABLE IF NOT EXISTS check_executions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
  check_id TEXT NOT NULL,
  attempt INTEGER NOT NULL DEFAULT 1,
  outcome TEXT NOT NULL,
  engine TEXT,
  engine_version TEXT,
  is_fallback INTEGER NOT NULL DEFAULT 0,
  scope TEXT,
  reason TEXT,
  from_cache INTEGER NOT NULL DEFAULT 0,
  duration_ms INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(run_id, check_id, attempt)
);
CREATE INDEX IF NOT EXISTS idx_check_executions_run ON check_executions(run_id);
CREATE TABLE IF NOT EXISTS policy_decisions (
  run_id INTEGER PRIMARY KEY REFERENCES scan_runs(id) ON DELETE CASCADE,
  decision TEXT NOT NULL,
  policy_version TEXT NOT NULL,
  reasons_json TEXT NOT NULL,
  missing_checks_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- US-05: the versioned evidence manifest (source digest, policy/config
-- digests, check coverage, artifact digests — see `ignite-evidence`) for
-- one scan run, plus a bounded lease that protects a retained source
-- directory from the retention sweeper (`retention-sweeper`) while it's
-- still under active review/pending publication. `snapshot_leases` is
-- keyed by `project_id`, not `run_id` — leases exist to protect
-- `retained_sources`' on-disk directory, which is itself still
-- project-id-keyed (see CLAUDE.md's US-01 note: the retained-source path
-- hasn't moved onto the normalized model yet).
CREATE TABLE IF NOT EXISTS evidence_manifests (
  run_id        INTEGER PRIMARY KEY REFERENCES scan_runs(id) ON DELETE CASCADE,
  manifest_json TEXT NOT NULL,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS snapshot_leases (
  project_id  INTEGER PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
  reason      TEXT NOT NULL,
  expires_at  TEXT NOT NULL,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- The full collected stdout/log text for one scan's `scan.completed`
-- audit event, gzip-compressed — an auditor reading the audit log gets a
-- downloadable archive of exactly what the scan printed, not just the
-- one-line summary. `event_id` is the `audit_events.id` this archive
-- belongs to (never a `projects.id`/`scan_runs.id` directly, since the
-- download is reached from the audit log itself, not from a project
-- view — those already have `GET /api/pipeline/:jobId/status`'s
-- `steps[].logs` for the same information without needing to unzip
-- anything).
CREATE TABLE IF NOT EXISTS audit_event_logs (
  event_id   INTEGER PRIMARY KEY REFERENCES audit_events(id) ON DELETE CASCADE,
  gzip_blob  BLOB NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- US-06: publication intent, persisted *before* the remote GitHub side
-- effects it describes (repo create/reuse, push, PR create) rather than
-- only ever being reconstructed from GitHub's own state after the fact.
-- `source_digest` binds a publish to the exact approved snapshot it may
-- publish; `idempotency_key` lets a client-retried request return the
-- original attempt instead of provisioning/pushing a second time.
CREATE TABLE IF NOT EXISTS publication_attempts (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id       INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  run_id           INTEGER REFERENCES scan_runs(id) ON DELETE SET NULL,
  org              TEXT NOT NULL,
  repo             TEXT NOT NULL,
  source_digest    TEXT NOT NULL,
  idempotency_key  TEXT,
  stage            TEXT NOT NULL DEFAULT 'pending',
  repo_url         TEXT,
  commit_sha       TEXT,
  pr_url           TEXT,
  error            TEXT,
  created_at       TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at       TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_publication_attempts_project_digest ON publication_attempts(project_id, source_digest);
CREATE UNIQUE INDEX IF NOT EXISTS idx_publication_attempts_idempotency ON publication_attempts(project_id, idempotency_key) WHERE idempotency_key IS NOT NULL;

-- US-07: stable finding identity, separate from a run's raw per-scan
-- issue list. `fingerprint` is `ignite_override_engine::stable_fingerprint`
-- (content-hashed, tolerant of pure line drift) — the old
-- `category::file::line` id (`legacy_issue_id`) is kept alongside it
-- purely as a compatibility pointer back to the override/SARIF/GitHub-
-- alert id scheme, never as the row's own identity.
CREATE TABLE IF NOT EXISTS findings (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  repository_id     INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  category          TEXT NOT NULL,
  fingerprint       TEXT NOT NULL,
  legacy_issue_id   TEXT NOT NULL,
  tool              TEXT,
  status            TEXT NOT NULL DEFAULT 'open',
  first_seen_run_id INTEGER REFERENCES scan_runs(id) ON DELETE SET NULL,
  first_seen_at     TEXT NOT NULL DEFAULT (datetime('now')),
  last_seen_run_id  INTEGER REFERENCES scan_runs(id) ON DELETE SET NULL,
  last_seen_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_repo_fingerprint ON findings(repository_id, fingerprint);

-- Per-run evidence for a finding: exactly where/how it showed up (or that
-- it was classified `resolved`/`reopened`) on one specific scan, so a
-- finding's history is a real timeline, not just its current state.
CREATE TABLE IF NOT EXISTS finding_observations (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  finding_id     INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  run_id         INTEGER REFERENCES scan_runs(id) ON DELETE SET NULL,
  classification TEXT NOT NULL,
  file           TEXT,
  line           INTEGER,
  severity       TEXT,
  created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_finding_observations_finding ON finding_observations(finding_id);

-- US-08: explicit, repository/org-scoped permission grants — the real
-- authorization model this codebase didn't have (see CLAUDE.md's own gap
-- analysis, `routes/override_approval.rs`'s doc comment). `org`/`repo` both
-- NULL means a global grant; `org` set with `repo` NULL means every
-- repository in that org; both set means exactly that repository. Keyed
-- by `subject_email` (not a `users.id` foreign key) so a grant can be
-- issued before the person's first login creates their `users` row,
-- matching how `security.overrideApproval.approverEmails` already worked.
-- API keys are never granted separately — they resolve to their owning
-- user and therefore can never exceed that user's own grants.
CREATE TABLE IF NOT EXISTS permission_grants (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  subject_email  TEXT NOT NULL,
  permission     TEXT NOT NULL,
  org            TEXT,
  repo           TEXT,
  granted_by     TEXT,
  created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_permission_grants_unique ON permission_grants(subject_email, permission, COALESCE(org, ''), COALESCE(repo, ''));
CREATE INDEX IF NOT EXISTS idx_permission_grants_subject ON permission_grants(subject_email);

-- Small generic key/value store for runtime-toggleable settings that
-- shouldn't need a server restart to change (unlike config.json, which is
-- only ever read at startup) — first user is the GitHub Org view's
-- "auto-rescan" toggle. Deliberately not a dedicated typed table: a
-- boolean UI toggle doesn't warrant its own migration every time one more
-- of these shows up.
CREATE TABLE IF NOT EXISTS app_settings (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"#;

/// Backfills `repositories`/`source_snapshots`/`scan_runs` from every
/// historical `projects` row that doesn't have a `scan_runs` entry yet —
/// runs every startup (same idempotent-via-`WHERE NOT IN`/`NOT EXISTS`
/// posture as [`BACKFILL_ONBOARDING_PRS_SQL`]), so it also repairs any row
/// a future bug or crash left un-mirrored, not just the true one-time
/// historical backfill. A pre-existing project's true source digest was
/// never recorded, so its snapshot gets a synthetic per-project digest
/// (`legacy:project:<id>`) rather than a fabricated one — labeled
/// unknown/legacy, matching this backlog's "do not invent trustworthy
/// historical ... digests" instruction. `is_enrollment_only` is derived
/// from `source = 'repository-event'`, the one and only enrollment-only
/// path that exists today (`repository_events_webhook.rs`).
pub(crate) const BACKFILL_REPOSITORY_MODEL_SQL: &str = r#"
INSERT INTO repositories (org, repo, created_at)
SELECT p.org, p.repo, MIN(p.created_at) FROM projects p
WHERE NOT EXISTS (SELECT 1 FROM repositories r WHERE r.org = p.org AND r.repo = p.repo)
GROUP BY p.org, p.repo;

INSERT INTO source_snapshots (repository_id, source_digest, commit_sha, storage_ref, retention_state, created_at)
SELECT r.id, 'legacy:project:' || p.id, p.source_commit_sha, p.scan_location, 'unknown', p.created_at
FROM projects p
JOIN repositories r ON r.org = p.org AND r.repo = p.repo
WHERE NOT EXISTS (SELECT 1 FROM scan_runs sr WHERE sr.legacy_project_id = p.id);

INSERT INTO scan_runs (legacy_project_id, repository_id, snapshot_id, source_channel, lifecycle_state, is_enrollment_only, created_at, finished_at)
SELECT p.id, r.id, s.id, COALESCE(p.source, 'unknown'),
       CASE
         WHEN p.status = 'success' THEN 'published'
         WHEN p.status = 'failed' THEN 'failed'
         WHEN p.status = 'enrolled' THEN 'completed'
         WHEN p.status IS NULL THEN 'queued'
         ELSE 'scanning'
       END,
       CASE WHEN p.source = 'repository-event' THEN 1 ELSE 0 END,
       p.created_at, p.finished_at
FROM projects p
JOIN repositories r ON r.org = p.org AND r.repo = p.repo
JOIN source_snapshots s ON s.repository_id = r.id AND s.source_digest = 'legacy:project:' || p.id
WHERE NOT EXISTS (SELECT 1 FROM scan_runs sr WHERE sr.legacy_project_id = p.id);
"#;

/// One-time-per-row backfill, safe to re-run every startup: every historical
/// `projects.pr_url` set before the `pull_requests` table existed gets a
/// matching `kind='onboarding'` row, so `list_onboarded_repo_summaries`'s
/// "recent PRs" column has a single source of truth (`pull_requests`)
/// instead of having to union in `projects.pr_url` separately forever.
/// `WHERE NOT IN (...)` makes re-running this a no-op once backfilled.
pub(crate) const BACKFILL_ONBOARDING_PRS_SQL: &str = r#"
INSERT INTO pull_requests (project_id, kind, url, created_at)
SELECT id, 'onboarding', pr_url, COALESCE(finished_at, created_at) FROM projects
WHERE pr_url IS NOT NULL
  AND id NOT IN (SELECT project_id FROM pull_requests WHERE kind = 'onboarding');
"#;

/// One migration: a stable, never-reused version number plus its DDL.
/// `run_migrations` (`store.rs`) records each applied version in
/// `schema_migrations` so a migration runs at most once — unlike the old
/// scheme (every entry re-run on every `open()`, relying on `ALTER TABLE
/// ... ADD COLUMN` being safe to repeat forever), which had no way to
/// express a migration that *isn't* a repeatable additive `ADD COLUMN`
/// (a rename, a drop, a data backfill that must not run twice). Version
/// numbers are assigned in the order migrations were written and must
/// never be reused or reordered — `run_migrations` uses the number itself
/// as the "already applied" key, not the array index.
pub(crate) type Migration = (u32, &'static str);

/// Same forward-compatible-migration dance as the JS original: `ALTER
/// TABLE ... ADD COLUMN` against a table that might already have the
/// column (an existing DB from before this column existed, migrated back
/// when every entry here re-ran unconditionally), swallowing only the
/// "duplicate column" error. `run_migrations` still needs this fallback
/// once, on first run against such a DB, to backfill `schema_migrations`
/// without erroring — new migrations appended after this comment run
/// exactly once and don't need their DDL to tolerate re-application.
pub(crate) const MIGRATIONS: &[Migration] = &[
    (1, "ALTER TABLE issues ADD COLUMN score INTEGER"),
    (2, "ALTER TABLE issues ADD COLUMN cross_file INTEGER NOT NULL DEFAULT 0"),
    (3, "ALTER TABLE issues ADD COLUMN chain_json TEXT"),
    (4, "ALTER TABLE issues ADD COLUMN cwe TEXT"),
    (5, "ALTER TABLE projects ADD COLUMN source TEXT NOT NULL DEFAULT 'ui'"),
    (6, "ALTER TABLE projects ADD COLUMN scan_location TEXT"),
    (7, "ALTER TABLE projects ADD COLUMN schedule_enabled INTEGER NOT NULL DEFAULT 0"),
    (8, "ALTER TABLE projects ADD COLUMN schedule_interval TEXT"),
    (9, "ALTER TABLE projects ADD COLUMN next_scheduled_run_at TEXT"),
    (10, "ALTER TABLE projects ADD COLUMN last_scheduled_run_at TEXT"),
    (11, "ALTER TABLE projects ADD COLUMN last_scheduled_status TEXT"),
    (12, "ALTER TABLE projects ADD COLUMN last_scheduled_error TEXT"),
    (13, "ALTER TABLE api_keys ADD COLUMN created_by TEXT"),
    (14, "ALTER TABLE api_keys ADD COLUMN created_via TEXT NOT NULL DEFAULT 'cli'"),
    (15, "ALTER TABLE projects ADD COLUMN source_commit_sha TEXT"),
    (16, "ALTER TABLE projects ADD COLUMN shipped_commit_sha TEXT"),
    (17, "ALTER TABLE retained_sources ADD COLUMN tier TEXT NOT NULL DEFAULT 'full'"),
    (18, "ALTER TABLE issues ADD COLUMN owasp TEXT"),
    (19, "ALTER TABLE issues ADD COLUMN tool TEXT"),
    (20, "ALTER TABLE issues ADD COLUMN references_json TEXT"),
    (21, "ALTER TABLE issues ADD COLUMN duplicate_ref_json TEXT"),
    (22, "ALTER TABLE dependency_scan_cache ADD COLUMN previous_scan_json TEXT"),
    // Dual-custody approval for critical-severity overrides (see
    // `overrides.rs`'s `add_pending_override`/`approve_override`/
    // `reject_override`) — every pre-existing row (and every row inserted
    // via the ordinary `add_override`) defaults to `'approved'`, so this
    // migration changes nothing about how any existing override already
    // resolves an issue.
    (23, "ALTER TABLE overrides ADD COLUMN status TEXT NOT NULL DEFAULT 'approved'"),
    (24, "ALTER TABLE overrides ADD COLUMN approved_by_email TEXT"),
    (25, "ALTER TABLE overrides ADD COLUMN approved_at TEXT"),
    // Per-check Phase 4 wall-clock timings (`phase4-orchestrator`'s own
    // `task_timings`), so the "Performance" popup can show which check was
    // the bottleneck on a *past* scan, not just a currently-streaming one.
    // JSON array of `{name, ms}`; NULL for every row written before this
    // migration and for any phase other than 4.
    (26, "ALTER TABLE steps ADD COLUMN task_timings_json TEXT"),
    // US-04: scoped idempotency keys — "same key and payload returns the
    // same run; conflicting payload returns a conflict." The partial
    // unique index (SQLite: a `WHERE` clause on the index itself) only
    // constrains rows that actually supplied a key, so every pre-existing
    // row (and every future caller that doesn't pass one) is unaffected.
    (27, "ALTER TABLE scan_runs ADD COLUMN idempotency_key TEXT; ALTER TABLE scan_runs ADD COLUMN idempotency_payload_hash TEXT; CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_runs_idempotency ON scan_runs(repository_id, idempotency_key) WHERE idempotency_key IS NOT NULL;"),
    // US-08: an exception (override) can now carry its own expiry and the
    // policy version it was granted under — both NULL for every
    // pre-existing row (and every row inserted by a caller that doesn't
    // pass one), meaning "never expires" exactly like before this
    // migration, so no existing override's behavior changes.
    (28, "ALTER TABLE overrides ADD COLUMN expires_at TEXT; ALTER TABLE overrides ADD COLUMN policy_version TEXT;"),
    // GitHub Org view: orgs whose repos the hourly auto-rescan sweep keeps
    // fresh (enrolled by "Scan all"), plus the repos the user unchecked in
    // the tree view. Selection is stored as *exclusions* so a repo created
    // in an enrolled org later is included by default, matching the UI's
    // "everything checked by default". Names are stored lowercased (GitHub
    // logins/repo names are case-insensitive).
    (29, "CREATE TABLE IF NOT EXISTS auto_rescan_orgs (org TEXT PRIMARY KEY, added_at TEXT NOT NULL DEFAULT (datetime('now'))); CREATE TABLE IF NOT EXISTS auto_rescan_excluded_repos (org TEXT NOT NULL, repo TEXT NOT NULL, PRIMARY KEY (org, repo));"),
    // GitHub Org view: the orgs the user added in the UI (persisted so the
    // tree survives reloads independent of the config file or of whether
    // "Scan all" was ever clicked). Names stored lowercased.
    (30, "CREATE TABLE IF NOT EXISTS saved_orgs (org TEXT PRIMARY KEY, added_at TEXT NOT NULL DEFAULT (datetime('now')));"),
    (31, "CREATE TABLE IF NOT EXISTS check_executions (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE, check_id TEXT NOT NULL, attempt INTEGER NOT NULL DEFAULT 1, outcome TEXT NOT NULL, engine TEXT, engine_version TEXT, is_fallback INTEGER NOT NULL DEFAULT 0, scope TEXT, reason TEXT, from_cache INTEGER NOT NULL DEFAULT 0, duration_ms INTEGER, created_at TEXT NOT NULL DEFAULT (datetime('now')), UNIQUE(run_id, check_id, attempt)); CREATE INDEX IF NOT EXISTS idx_check_executions_run ON check_executions(run_id); CREATE TABLE IF NOT EXISTS policy_decisions (run_id INTEGER PRIMARY KEY REFERENCES scan_runs(id) ON DELETE CASCADE, decision TEXT NOT NULL, policy_version TEXT NOT NULL, reasons_json TEXT NOT NULL, missing_checks_json TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')));"),
    // Agent-flow gaps: (32) an API key can carry its own GitHub push token,
    // so a headless caller isn't forced to depend on a human's browser
    // OAuth connection or the server's ambient GH_TOKEN; (33) a durable
    // record of a run's "effectivatable" snapshot, so a dry run can still be
    // effectivated after a server restart (previously an in-memory-only map).
    (32, "ALTER TABLE api_keys ADD COLUMN github_token TEXT;"),
    (33, "CREATE TABLE IF NOT EXISTS pending_effectivations (project_id INTEGER PRIMARY KEY, org TEXT NOT NULL, repo TEXT NOT NULL, source_dir TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')), expires_at TEXT NOT NULL);"),
    // How an override reached Ignite: 'session' (a person in the browser, and
    // every pre-existing row), 'api_key' (a headless agent/CI key),
    // 'unauthenticated' (validate-all's opt-in body-actor path) or 'github'
    // (an inbound Security-tab webhook). Recorded so a reviewer can tell an
    // agent-submitted justification from a human one; nothing gates on it.
    (34, "ALTER TABLE overrides ADD COLUMN origin TEXT NOT NULL DEFAULT 'session';"),
];
