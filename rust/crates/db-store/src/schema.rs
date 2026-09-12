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
];
