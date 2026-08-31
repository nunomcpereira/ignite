//! SQLite-backed store — faithful port of `db-store.js`. Same schema
//! (verbatim `CREATE TABLE IF NOT EXISTS`/migration DDL), same accessor
//! surface, same behavior (JSON-serialized findings columns, TTL-bound
//! cosign cache, replace-then-reinsert issue lists, etc).
//!
//! Uses `rusqlite`'s bundled SQLite (no system libsqlite3 dependency,
//! matching Node's own bundled `node:sqlite`) and its built-in prepared-
//! statement cache (`prepare_cached`) instead of a hand-maintained `stmt`
//! map — same effect (each unique SQL string is compiled once and reused),
//! idiomatic for the language rather than a literal structural port.

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Mutex;

const SCHEMA_SQL: &str = r#"
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
"#;

/// Same forward-compatible-migration dance as the JS original: `ALTER
/// TABLE ... ADD COLUMN` against a table that might already have the
/// column (an existing DB from before this column existed), swallowing
/// only the "duplicate column" error.
const MIGRATIONS: &[&str] = &[
    "ALTER TABLE issues ADD COLUMN score INTEGER",
    "ALTER TABLE issues ADD COLUMN cross_file INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE issues ADD COLUMN chain_json TEXT",
    "ALTER TABLE issues ADD COLUMN cwe TEXT",
    "ALTER TABLE projects ADD COLUMN source TEXT NOT NULL DEFAULT 'ui'",
    "ALTER TABLE projects ADD COLUMN scan_location TEXT",
    "ALTER TABLE projects ADD COLUMN schedule_enabled INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE projects ADD COLUMN schedule_interval TEXT",
    "ALTER TABLE projects ADD COLUMN next_scheduled_run_at TEXT",
    "ALTER TABLE projects ADD COLUMN last_scheduled_run_at TEXT",
    "ALTER TABLE projects ADD COLUMN last_scheduled_status TEXT",
    "ALTER TABLE projects ADD COLUMN last_scheduled_error TEXT",
    "ALTER TABLE api_keys ADD COLUMN created_by TEXT",
    "ALTER TABLE api_keys ADD COLUMN created_via TEXT NOT NULL DEFAULT 'cli'",
    "ALTER TABLE projects ADD COLUMN source_commit_sha TEXT",
    "ALTER TABLE projects ADD COLUMN shipped_commit_sha TEXT",
    "ALTER TABLE retained_sources ADD COLUMN tier TEXT NOT NULL DEFAULT 'full'",
];

pub struct DbStore {
    conn: Mutex<Connection>,
}

// --- row types ------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct ProjectListRow {
    pub id: i64,
    pub job_id: String,
    pub org: String,
    pub repo: String,
    pub gxp: bool,
    pub source: String,
    pub scan_location: Option<String>,
    pub status: String,
    pub error: Option<String>,
    pub repo_url: Option<String>,
    pub pr_url: Option<String>,
    pub created_at: String,
    pub finished_at: Option<String>,
    pub doc_count: i64,
    pub issue_count: i64,
    pub retained: bool,
    pub retained_tier: Option<String>,
    pub source_commit_sha: Option<String>,
    pub shipped_commit_sha: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Project {
    pub id: i64,
    pub org: String,
    pub repo: String,
    pub gxp: bool,
    pub source: String,
    pub scan_location: Option<String>,
    pub status: String,
    pub error: Option<String>,
    pub repo_url: Option<String>,
    pub pr_url: Option<String>,
    pub created_at: String,
    pub finished_at: Option<String>,
    pub source_commit_sha: Option<String>,
    pub shipped_commit_sha: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Step {
    pub phase: i64,
    pub title: String,
    pub state: String,
    pub logs: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DocumentSummary {
    pub id: i64,
    pub kind: String,
    pub name: String,
    pub url: Option<String>,
    pub mime: Option<String>,
    pub size: Option<i64>,
    pub created_at: String,
}

pub struct DocumentDownload {
    pub kind: String,
    pub name: String,
    pub url: Option<String>,
    pub mime: Option<String>,
    pub data: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OverrideRow {
    pub id: i64,
    pub phase: i64,
    pub issue_id: String,
    pub category: String,
    pub severity: String,
    pub summary: String,
    pub file: Option<String>,
    pub line: Option<i64>,
    pub justification: String,
    pub actor_email: String,
    pub actor_name: Option<String>,
    pub email_sent: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectDetails {
    #[serde(flatten)]
    pub project: Project,
    pub steps: Vec<Step>,
    pub documents: Vec<DocumentSummary>,
    pub overrides: Vec<OverrideRow>,
}

pub struct AddOverrideArgs<'a> {
    pub project_id: i64,
    pub job_id: &'a str,
    pub phase: i64,
    pub issue_id: &'a str,
    pub category: &'a str,
    pub severity: &'a str,
    pub summary: &'a str,
    pub file: Option<&'a str>,
    pub line: Option<i64>,
    pub justification: &'a str,
    pub actor_email: &'a str,
    pub actor_name: Option<&'a str>,
    pub email_sent: bool,
}

/// Mirrors the loose JS `issue` shape (`{ id, phase, category, severity,
/// score, summary, file, line, snippet, crossFile, chain, cwe }`) passed
/// into `replaceProjectIssues`.
#[derive(Debug, Clone)]
pub struct IssueInput {
    pub id: String,
    pub phase: Option<i64>,
    pub category: String,
    pub severity: String,
    pub score: Option<i64>,
    pub summary: String,
    pub file: Option<String>,
    pub line: Option<i64>,
    pub snippet: Option<serde_json::Value>,
    pub cross_file: bool,
    pub chain: Option<serde_json::Value>,
    pub cwe: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueRow {
    pub id: String,
    pub phase: Option<i64>,
    pub category: String,
    pub severity: String,
    pub score: Option<i64>,
    pub summary: String,
    pub file: Option<String>,
    pub line: Option<i64>,
    pub snippet: Option<serde_json::Value>,
    pub cross_file: bool,
    pub chain: Option<serde_json::Value>,
    pub cwe: Option<String>,
    pub status: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct User {
    pub id: i64,
    pub email: String,
    pub name: Option<String>,
    pub provider: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionRow {
    pub id: String,
    pub expires_at: String,
    pub user_id: i64,
    pub email: String,
    pub name: Option<String>,
    pub provider: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiKeyIdentity {
    pub id: i64,
    pub user_id: i64,
    pub email: String,
    pub name: Option<String>,
    pub provider: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiKeySummary {
    pub id: i64,
    pub label: Option<String>,
    pub created_at: String,
    pub created_by: Option<String>,
    pub created_via: String,
    pub last_used_at: Option<String>,
    pub revoked_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CosignVerifyResult {
    pub verified: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkflowCacheEntry {
    pub commit_sha: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RetainedSourceRow {
    pub project_id: i64,
    pub dir_path: String,
    pub tier: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EffectivatedProject {
    pub id: i64,
    pub org: String,
    pub repo: String,
    pub repo_url: Option<String>,
    pub created_at: String,
    pub schedule_enabled: bool,
    pub schedule_interval: Option<String>,
    pub next_scheduled_run_at: Option<String>,
    pub last_scheduled_run_at: Option<String>,
    pub last_scheduled_status: Option<String>,
    pub last_scheduled_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DueScheduledProject {
    pub id: i64,
    pub org: String,
    pub repo: String,
    pub repo_url: Option<String>,
    pub schedule_interval: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GithubConnection {
    pub user_id: i64,
    pub github_login: String,
    pub access_token: String,
    pub scope: Option<String>,
    pub connected_at: String,
}

#[derive(Debug, Clone)]
pub struct FileScanCacheEntry {
    pub hash: String,
    pub findings: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct FileScanCacheInput {
    pub rel_path: String,
    pub hash: String,
    pub findings: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeCoverageRow {
    pub hit_count: i64,
    pub covered_pct: Option<f64>,
}

#[derive(Debug, Clone)]
pub struct RuntimeCoverageInput {
    pub hit_count: i64,
    pub covered_pct: Option<f64>,
}

impl DbStore {
    pub fn open(db_file: &Path) -> rusqlite::Result<Self> {
        let conn = Connection::open(db_file)?;
        conn.execute_batch(SCHEMA_SQL)?;
        for ddl in MIGRATIONS {
            if let Err(e) = conn.execute_batch(ddl) {
                let msg = e.to_string().to_lowercase();
                if !msg.contains("duplicate column") {
                    return Err(e);
                }
            }
        }
        Ok(DbStore { conn: Mutex::new(conn) })
    }

    // ---------------- projects / steps / documents ----------------

    pub fn create_project(
        &self,
        job_id: &str,
        org: &str,
        repo: &str,
        is_gxp: bool,
        source: &str,
        scan_location: Option<&str>,
    ) -> i64 {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO projects (job_id, org, repo, gxp, source, scan_location) VALUES (?, ?, ?, ?, ?, ?)",
            params![job_id, org, repo, is_gxp as i64, source, scan_location],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    pub fn finish_project(&self, status: &str, error: Option<&str>, repo_url: Option<&str>, pr_url: Option<&str>, project_id: i64) {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE projects SET status = ?, error = ?, repo_url = ?, pr_url = ?, finished_at = datetime('now') WHERE id = ?",
            params![status, error, repo_url, pr_url, project_id],
        )
        .unwrap();
    }

    pub fn add_step(&self, project_id: i64, phase: i64, title: &str, state: &str, logs: &str) {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO steps (project_id, phase, title, state, logs) VALUES (?, ?, ?, ?, ?)",
            params![project_id, phase, title, state, logs],
        )
        .unwrap();
    }

    pub fn upsert_step(&self, project_id: i64, phase: i64, title: &str, state: &str, logs: &str) {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO steps (project_id, phase, title, state, logs)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(project_id, phase)
             DO UPDATE SET title = excluded.title, state = excluded.state, logs = excluded.logs",
            params![project_id, phase, title, state, logs],
        )
        .unwrap();
    }

    pub fn add_upload_document(&self, project_id: i64, name: &str, mime: Option<&str>, size: i64, data: &[u8]) {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO documents (project_id, kind, name, url, mime, size, data) VALUES (?, 'upload', ?, NULL, ?, ?, ?)",
            params![project_id, name, mime, size, data],
        )
        .unwrap();
    }

    pub fn add_link_document(&self, project_id: i64, name: &str, url: &str) {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO documents (project_id, kind, name, url, mime, size, data) VALUES (?, 'link', ?, ?, NULL, NULL, NULL)",
            params![project_id, name, url],
        )
        .unwrap();
    }

    pub fn list_projects(&self) -> Vec<ProjectListRow> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare_cached(
                "SELECT p.id, p.job_id, p.org, p.repo, p.gxp, p.source, p.scan_location, p.status, p.error, p.repo_url, p.pr_url,
                        p.created_at, p.finished_at,
                        (SELECT COUNT(*) FROM documents d WHERE d.project_id = p.id) AS doc_count,
                        (SELECT COUNT(*) FROM issues i WHERE i.project_id = p.id) AS issue_count,
                        (SELECT 1 FROM retained_sources r WHERE r.project_id = p.id) AS retained,
                        (SELECT r.tier FROM retained_sources r WHERE r.project_id = p.id) AS retained_tier,
                        p.source_commit_sha, p.shipped_commit_sha
                 FROM projects p ORDER BY p.id DESC LIMIT 100",
            )
            .unwrap();
        stmt.query_map([], |row| {
            Ok(ProjectListRow {
                id: row.get(0)?,
                job_id: row.get(1)?,
                org: row.get(2)?,
                repo: row.get(3)?,
                gxp: row.get::<_, i64>(4)? != 0,
                source: row.get(5)?,
                scan_location: row.get(6)?,
                status: row.get(7)?,
                error: row.get(8)?,
                repo_url: row.get(9)?,
                pr_url: row.get(10)?,
                created_at: row.get(11)?,
                finished_at: row.get(12)?,
                doc_count: row.get(13)?,
                issue_count: row.get(14)?,
                retained: row.get::<_, Option<i64>>(15)?.unwrap_or(0) != 0,
                retained_tier: row.get(16)?,
                source_commit_sha: row.get(17)?,
                shipped_commit_sha: row.get(18)?,
            })
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
    }

    fn get_project_row(conn: &Connection, project_id: i64) -> Option<Project> {
        conn.query_row(
            "SELECT id, org, repo, gxp, source, scan_location, status, error, repo_url, pr_url, created_at, finished_at, source_commit_sha, shipped_commit_sha FROM projects WHERE id = ?",
            params![project_id],
            |row| {
                Ok(Project {
                    id: row.get(0)?,
                    org: row.get(1)?,
                    repo: row.get(2)?,
                    gxp: row.get::<_, i64>(3)? != 0,
                    source: row.get(4)?,
                    scan_location: row.get(5)?,
                    status: row.get(6)?,
                    error: row.get(7)?,
                    repo_url: row.get(8)?,
                    pr_url: row.get(9)?,
                    created_at: row.get(10)?,
                    finished_at: row.get(11)?,
                    source_commit_sha: row.get(12)?,
                    shipped_commit_sha: row.get(13)?,
                })
            },
        )
        .optional()
        .unwrap()
    }

    pub fn get_project(&self, project_id: i64) -> Option<Project> {
        let conn = self.conn.lock().unwrap();
        Self::get_project_row(&conn, project_id)
    }

    pub fn get_project_details(&self, project_id: i64) -> Option<ProjectDetails> {
        let conn = self.conn.lock().unwrap();
        let project = Self::get_project_row(&conn, project_id)?;

        let mut steps_stmt = conn.prepare_cached("SELECT phase, title, state, logs FROM steps WHERE project_id = ? ORDER BY phase").unwrap();
        let steps = steps_stmt
            .query_map(params![project_id], |row| {
                Ok(Step { phase: row.get(0)?, title: row.get(1)?, state: row.get(2)?, logs: row.get(3)? })
            })
            .unwrap()
            .map(|r| r.unwrap())
            .collect();

        let mut docs_stmt = conn
            .prepare_cached("SELECT id, kind, name, url, mime, size, created_at FROM documents WHERE project_id = ? ORDER BY id")
            .unwrap();
        let documents = docs_stmt
            .query_map(params![project_id], |row| {
                Ok(DocumentSummary {
                    id: row.get(0)?,
                    kind: row.get(1)?,
                    name: row.get(2)?,
                    url: row.get(3)?,
                    mime: row.get(4)?,
                    size: row.get(5)?,
                    created_at: row.get(6)?,
                })
            })
            .unwrap()
            .map(|r| r.unwrap())
            .collect();

        let overrides = Self::get_project_overrides_inner(&conn, project_id);

        Some(ProjectDetails { project, steps, documents, overrides })
    }

    pub fn project_exists(&self, project_id: i64) -> bool {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT id FROM projects WHERE id = ?", params![project_id], |_| Ok(()))
            .optional()
            .unwrap()
            .is_some()
    }

    pub fn delete_project_by_id(&self, project_id: i64) {
        let conn = self.conn.lock().unwrap();
        let project = Self::get_project_row(&conn, project_id);
        conn.execute("DELETE FROM documents WHERE project_id = ?", params![project_id]).unwrap();
        conn.execute("DELETE FROM steps WHERE project_id = ?", params![project_id]).unwrap();
        conn.execute("DELETE FROM overrides WHERE project_id = ?", params![project_id]).unwrap();
        conn.execute("DELETE FROM issues WHERE project_id = ?", params![project_id]).unwrap();
        conn.execute("DELETE FROM retained_sources WHERE project_id = ?", params![project_id]).unwrap();
        conn.execute("DELETE FROM projects WHERE id = ?", params![project_id]).unwrap();
        if let Some(p) = project {
            conn.execute("DELETE FROM file_scan_cache WHERE org = ? AND repo = ?", params![p.org, p.repo]).unwrap();
        }
    }

    pub fn delete_all_projects(&self) {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "DELETE FROM documents; DELETE FROM steps; DELETE FROM overrides; DELETE FROM issues; DELETE FROM retained_sources; DELETE FROM projects; DELETE FROM file_scan_cache;",
        )
        .unwrap();
    }

    pub fn get_document(&self, document_id: i64) -> Option<DocumentDownload> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT kind, name, url, mime, data FROM documents WHERE id = ?",
            params![document_id],
            |row| {
                Ok(DocumentDownload {
                    kind: row.get(0)?,
                    name: row.get(1)?,
                    url: row.get(2)?,
                    mime: row.get(3)?,
                    data: row.get(4)?,
                })
            },
        )
        .optional()
        .unwrap()
    }

    // ---------------- retained sources ----------------

    pub fn retain_project_source(&self, project_id: i64, dir_path: &str, tier: &str) {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO retained_sources (project_id, dir_path, retained_at, tier) VALUES (?, ?, datetime('now'), ?)
             ON CONFLICT(project_id) DO UPDATE SET dir_path = excluded.dir_path, retained_at = excluded.retained_at, tier = excluded.tier",
            params![project_id, dir_path, tier],
        )
        .unwrap();
    }

    pub fn set_retained_source_tier(&self, project_id: i64, tier: &str) {
        let conn = self.conn.lock().unwrap();
        conn.execute("UPDATE retained_sources SET tier = ? WHERE project_id = ?", params![tier, project_id]).unwrap();
    }

    pub fn get_retained_source(&self, project_id: i64) -> Option<String> {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT dir_path FROM retained_sources WHERE project_id = ?", params![project_id], |row| row.get(0))
            .optional()
            .unwrap()
    }

    pub fn list_retained_sources(&self) -> Vec<RetainedSourceRow> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare_cached("SELECT project_id, dir_path, tier FROM retained_sources ORDER BY retained_at DESC").unwrap();
        stmt.query_map([], |row| Ok(RetainedSourceRow { project_id: row.get(0)?, dir_path: row.get(1)?, tier: row.get(2)? }))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    /// Rows beyond the `keep` most recently retained — the caller fs::remove's
    /// each dir_path, then calls delete_retained_source for each project_id.
    pub fn list_evictable_retained_sources(&self, keep: i64) -> Vec<RetainedSourceRow> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare_cached("SELECT project_id, dir_path, tier FROM retained_sources ORDER BY retained_at DESC LIMIT -1 OFFSET ?")
            .unwrap();
        stmt.query_map(params![keep], |row| Ok(RetainedSourceRow { project_id: row.get(0)?, dir_path: row.get(1)?, tier: row.get(2)? }))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    pub fn delete_retained_source(&self, project_id: i64) {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM retained_sources WHERE project_id = ?", params![project_id]).unwrap();
    }

    pub fn set_project_commit_shas(&self, project_id: i64, source_commit_sha: Option<&str>, shipped_commit_sha: Option<&str>) {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE projects SET source_commit_sha = COALESCE(?, source_commit_sha), shipped_commit_sha = COALESCE(?, shipped_commit_sha) WHERE id = ?",
            params![source_commit_sha, shipped_commit_sha, project_id],
        )
        .unwrap();
    }

    // ---------------- auth: users + sessions ----------------

    pub fn create_local_user(&self, email: &str, name: Option<&str>, password_hash: &str) -> i64 {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO users (email, name, provider, password_hash) VALUES (?, ?, 'local', ?)",
            params![email, name, password_hash],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    pub fn upsert_oidc_user(&self, email: &str, name: Option<&str>, external_id: &str) -> User {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO users (email, name, provider, external_id) VALUES (?, ?, 'oidc', ?)
             ON CONFLICT(provider, external_id) DO UPDATE SET email = excluded.email, name = excluded.name",
            params![email, name, external_id],
        )
        .unwrap();
        conn.query_row(
            "SELECT id, email, name, provider, created_at FROM users WHERE provider = 'oidc' AND external_id = ?",
            params![external_id],
            Self::user_from_row,
        )
        .unwrap()
    }

    pub fn upsert_github_user(&self, email: &str, name: Option<&str>, external_id: &str) -> User {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO users (email, name, provider, external_id) VALUES (?, ?, 'github', ?)
             ON CONFLICT(provider, external_id) DO UPDATE SET email = excluded.email, name = excluded.name",
            params![email, name, external_id],
        )
        .unwrap();
        conn.query_row(
            "SELECT id, email, name, provider, created_at FROM users WHERE provider = 'github' AND external_id = ?",
            params![external_id],
            Self::user_from_row,
        )
        .unwrap()
    }

    fn user_from_row(row: &rusqlite::Row) -> rusqlite::Result<User> {
        Ok(User { id: row.get(0)?, email: row.get(1)?, name: row.get(2)?, provider: row.get(3)?, created_at: row.get(4)? })
    }

    pub fn get_user_by_email(&self, email: &str) -> Option<User> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id, email, name, provider, created_at FROM users WHERE email = ?",
            params![email],
            Self::user_from_row,
        )
        .optional()
        .unwrap()
    }

    /// Deliberately separate from `get_user_by_email`/`get_user_by_id`
    /// (which return the serializable `User` — never carries the hash)
    /// so a login check is the only place this ever leaves the DB layer.
    pub fn get_local_user_password_hash(&self, user_id: i64) -> Option<String> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT password_hash FROM users WHERE id = ? AND provider = 'local'",
            params![user_id],
            |row| row.get(0),
        )
        .optional()
        .unwrap()
    }

    pub fn get_user_by_id(&self, user_id: i64) -> Option<User> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id, email, name, provider, created_at FROM users WHERE id = ?",
            params![user_id],
            Self::user_from_row,
        )
        .optional()
        .unwrap()
    }

    pub fn create_session(&self, session_id: &str, user_id: i64, expires_at_iso: &str) {
        let conn = self.conn.lock().unwrap();
        conn.execute("INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)", params![session_id, user_id, expires_at_iso]).unwrap();
    }

    pub fn get_session(&self, session_id: &str) -> Option<SessionRow> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT s.id, s.expires_at, u.id AS user_id, u.email, u.name, u.provider
             FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ?",
            params![session_id],
            |row| {
                Ok(SessionRow {
                    id: row.get(0)?,
                    expires_at: row.get(1)?,
                    user_id: row.get(2)?,
                    email: row.get(3)?,
                    name: row.get(4)?,
                    provider: row.get(5)?,
                })
            },
        )
        .optional()
        .unwrap()
    }

    /// Expired sessions are otherwise harmless (get_session checks
    /// expires_at before trusting a row), so this doesn't need to run
    /// inline on every request.
    pub fn sweep_expired_sessions(&self) {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM sessions WHERE expires_at < datetime('now')", []).unwrap();
    }

    pub fn delete_session(&self, session_id: &str) {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM sessions WHERE id = ?", params![session_id]).unwrap();
    }

    // ---------------- per-file scan cache ----------------

    /// Keyed by (org, repo, check_name) so each check keeps its own cache
    /// — a file unchanged since the previous run of this org/repo gets its
    /// stored findings reused instead of being re-evaluated.
    pub fn get_file_scan_cache(&self, org: &str, repo: &str, check_name: &str) -> HashMap<String, FileScanCacheEntry> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare_cached("SELECT rel_path, hash, findings_json FROM file_scan_cache WHERE org = ? AND repo = ? AND check_name = ?")
            .unwrap();
        stmt.query_map(params![org, repo, check_name], |row| {
            let rel_path: String = row.get(0)?;
            let hash: String = row.get(1)?;
            let findings_json: String = row.get(2)?;
            Ok((rel_path, hash, findings_json))
        })
        .unwrap()
        .map(|r| r.unwrap())
        .map(|(rel_path, hash, findings_json)| {
            (rel_path, FileScanCacheEntry { hash, findings: serde_json::from_str(&findings_json).unwrap() })
        })
        .collect()
    }

    /// Replaces the entire cache for this (org, repo, check_name): files
    /// that no longer exist (deleted/renamed since the last run) are
    /// dropped rather than accumulating forever.
    pub fn replace_file_scan_cache(&self, org: &str, repo: &str, check_name: &str, entries: &[FileScanCacheInput]) {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().unwrap();
        tx.execute("DELETE FROM file_scan_cache WHERE org = ? AND repo = ? AND check_name = ?", params![org, repo, check_name]).unwrap();
        for entry in entries {
            let findings_json = serde_json::to_string(&entry.findings).unwrap();
            tx.execute(
                "INSERT INTO file_scan_cache (org, repo, check_name, rel_path, hash, findings_json) VALUES (?, ?, ?, ?, ?, ?)",
                params![org, repo, check_name, entry.rel_path, entry.hash, findings_json],
            )
            .unwrap();
        }
        tx.commit().unwrap();
    }

    // ---------------- cosign verify cache (TTL-bound) ----------------

    pub fn get_cosign_verify_cache(&self, image: &str, identity_regexp: &str, issuer_regexp: &str, max_age_seconds: i64) -> Option<CosignVerifyResult> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT verified, reason FROM cosign_verify_cache
             WHERE image = ? AND identity_regexp = ? AND issuer_regexp = ?
               AND checked_at >= strftime('%Y-%m-%d %H:%M:%f', 'now', '-' || ? || ' seconds')",
            params![image, identity_regexp, issuer_regexp, max_age_seconds],
            |row| Ok(CosignVerifyResult { verified: row.get::<_, i64>(0)? != 0, reason: row.get(1)? }),
        )
        .optional()
        .unwrap()
    }

    pub fn save_cosign_verify_cache(&self, image: &str, identity_regexp: &str, issuer_regexp: &str, verified: bool, reason: Option<&str>) {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO cosign_verify_cache (image, identity_regexp, issuer_regexp, verified, reason)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(image, identity_regexp, issuer_regexp)
             DO UPDATE SET verified = excluded.verified, reason = excluded.reason, checked_at = strftime('%Y-%m-%d %H:%M:%f', 'now')",
            params![image, identity_regexp, issuer_regexp, verified as i64, reason],
        )
        .unwrap();
    }

    // ---------------- manifest-level tool-result cache ----------------

    pub fn get_manifest_scan_cache(&self, tool: &str, ecosystem: &str, content_hash: &str, tool_version: &str) -> Option<serde_json::Value> {
        let conn = self.conn.lock().unwrap();
        let json: Option<String> = conn
            .query_row(
                "SELECT findings_json FROM manifest_scan_cache WHERE tool = ? AND ecosystem = ? AND content_hash = ? AND tool_version = ?",
                params![tool, ecosystem, content_hash, tool_version],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        json.map(|j| serde_json::from_str(&j).unwrap())
    }

    pub fn save_manifest_scan_cache(&self, tool: &str, ecosystem: &str, content_hash: &str, tool_version: &str, findings: &serde_json::Value) {
        let conn = self.conn.lock().unwrap();
        let json = serde_json::to_string(findings).unwrap();
        conn.execute(
            "INSERT INTO manifest_scan_cache (tool, ecosystem, content_hash, tool_version, findings_json)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(tool, ecosystem, content_hash, tool_version)
             DO UPDATE SET findings_json = excluded.findings_json, updated_at = datetime('now')",
            params![tool, ecosystem, content_hash, tool_version, json],
        )
        .unwrap();
    }

    // ---------------- CodeQL cross-file scan cache ----------------

    pub fn get_codeql_scan_cache(&self, org: &str, repo: &str, language: &str, file_set_hash: &str, tool_version: &str) -> Option<serde_json::Value> {
        let conn = self.conn.lock().unwrap();
        let json: Option<String> = conn
            .query_row(
                "SELECT findings_json FROM codeql_scan_cache WHERE org = ? AND repo = ? AND language = ? AND file_set_hash = ? AND tool_version = ?",
                params![org, repo, language, file_set_hash, tool_version],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        json.map(|j| serde_json::from_str(&j).unwrap())
    }

    pub fn save_codeql_scan_cache(&self, org: &str, repo: &str, language: &str, file_set_hash: &str, tool_version: &str, findings: &serde_json::Value) {
        let conn = self.conn.lock().unwrap();
        let json = serde_json::to_string(findings).unwrap();
        conn.execute(
            "INSERT INTO codeql_scan_cache (org, repo, language, file_set_hash, tool_version, findings_json)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(org, repo, language, file_set_hash, tool_version)
             DO UPDATE SET findings_json = excluded.findings_json, updated_at = datetime('now')",
            params![org, repo, language, file_set_hash, tool_version, json],
        )
        .unwrap();
    }

    // ---------------- governance workflow cache ----------------

    pub fn get_workflow_cache(&self, repo: &str, filename: &str) -> Option<WorkflowCacheEntry> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT commit_sha, content FROM workflow_cache WHERE repo = ? AND filename = ?",
            params![repo, filename],
            |row| Ok(WorkflowCacheEntry { commit_sha: row.get(0)?, content: row.get(1)? }),
        )
        .optional()
        .unwrap()
    }

    pub fn save_workflow_cache(&self, repo: &str, filename: &str, commit_sha: &str, content: &str) {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO workflow_cache (repo, filename, commit_sha, content, updated_at)
             VALUES (?, ?, ?, ?, datetime('now'))
             ON CONFLICT(repo, filename) DO UPDATE SET commit_sha = excluded.commit_sha, content = excluded.content, updated_at = excluded.updated_at",
            params![repo, filename, commit_sha, content],
        )
        .unwrap();
    }

    // ---------------- scheduled re-checks ----------------

    /// "Effectivated" = actually shipped: a successful run that pushed to
    /// a real repo_url, as opposed to a dry run or a validate-all/onboard
    /// call that only ever ran checks.
    pub fn list_effectivated_projects(&self) -> Vec<EffectivatedProject> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare_cached(
                "SELECT id, org, repo, repo_url, created_at,
                        schedule_enabled, schedule_interval, next_scheduled_run_at,
                        last_scheduled_run_at, last_scheduled_status, last_scheduled_error
                 FROM projects WHERE status = 'success' AND repo_url IS NOT NULL ORDER BY id DESC",
            )
            .unwrap();
        stmt.query_map([], |row| {
            Ok(EffectivatedProject {
                id: row.get(0)?,
                org: row.get(1)?,
                repo: row.get(2)?,
                repo_url: row.get(3)?,
                created_at: row.get(4)?,
                schedule_enabled: row.get::<_, i64>(5)? != 0,
                schedule_interval: row.get(6)?,
                next_scheduled_run_at: row.get(7)?,
                last_scheduled_run_at: row.get(8)?,
                last_scheduled_status: row.get(9)?,
                last_scheduled_error: row.get(10)?,
            })
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
    }

    pub fn set_project_schedule(&self, project_id: i64, enabled: bool, interval: Option<&str>, next_run_at_iso: Option<&str>) {
        let conn = self.conn.lock().unwrap();
        let next = if enabled { next_run_at_iso } else { None };
        conn.execute(
            "UPDATE projects SET schedule_enabled = ?, schedule_interval = ?, next_scheduled_run_at = ? WHERE id = ?",
            params![enabled as i64, interval, next, project_id],
        )
        .unwrap();
    }

    pub fn get_due_scheduled_projects(&self, now_iso: &str) -> Vec<DueScheduledProject> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare_cached("SELECT id, org, repo, repo_url, schedule_interval FROM projects WHERE schedule_enabled = 1 AND repo_url IS NOT NULL AND next_scheduled_run_at <= ?")
            .unwrap();
        stmt.query_map(params![now_iso], |row| {
            Ok(DueScheduledProject { id: row.get(0)?, org: row.get(1)?, repo: row.get(2)?, repo_url: row.get(3)?, schedule_interval: row.get(4)? })
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
    }

    pub fn record_scheduled_run_result(&self, project_id: i64, status: &str, error: Option<&str>, next_run_at_iso: Option<&str>) {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE projects SET last_scheduled_run_at = datetime('now'), last_scheduled_status = ?, last_scheduled_error = ?, next_scheduled_run_at = ? WHERE id = ?",
            params![status, error, next_run_at_iso, project_id],
        )
        .unwrap();
    }

    // ---------------- GitHub OAuth connection ----------------

    pub fn upsert_github_connection(&self, user_id: i64, github_login: &str, access_token: &str, scope: Option<&str>) {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO github_connections (user_id, github_login, access_token, scope)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(user_id) DO UPDATE SET github_login = excluded.github_login, access_token = excluded.access_token, scope = excluded.scope, connected_at = datetime('now')",
            params![user_id, github_login, access_token, scope],
        )
        .unwrap();
    }

    pub fn get_github_connection(&self, user_id: i64) -> Option<GithubConnection> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT user_id, github_login, access_token, scope, connected_at FROM github_connections WHERE user_id = ?",
            params![user_id],
            |row| {
                Ok(GithubConnection {
                    user_id: row.get(0)?,
                    github_login: row.get(1)?,
                    access_token: row.get(2)?,
                    scope: row.get(3)?,
                    connected_at: row.get(4)?,
                })
            },
        )
        .optional()
        .unwrap()
    }

    pub fn delete_github_connection(&self, user_id: i64) {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM github_connections WHERE user_id = ?", params![user_id]).unwrap();
    }

    // ---------------- audit log: overrides ----------------

    pub fn add_override(&self, args: AddOverrideArgs) {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO overrides
              (project_id, job_id, phase, issue_id, category, severity, summary, file, line, justification, actor_email, actor_name, email_sent)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                args.project_id, args.job_id, args.phase, args.issue_id, args.category, args.severity,
                args.summary, args.file, args.line, args.justification, args.actor_email, args.actor_name,
                args.email_sent as i64,
            ],
        )
        .unwrap();
    }

    fn get_project_overrides_inner(conn: &Connection, project_id: i64) -> Vec<OverrideRow> {
        let mut stmt = conn
            .prepare_cached(
                "SELECT id, phase, issue_id, category, severity, summary, file, line, justification,
                        actor_email, actor_name, email_sent, created_at
                 FROM overrides WHERE project_id = ? ORDER BY id",
            )
            .unwrap();
        stmt.query_map(params![project_id], |row| {
            Ok(OverrideRow {
                id: row.get(0)?,
                phase: row.get(1)?,
                issue_id: row.get(2)?,
                category: row.get(3)?,
                severity: row.get(4)?,
                summary: row.get(5)?,
                file: row.get(6)?,
                line: row.get(7)?,
                justification: row.get(8)?,
                actor_email: row.get(9)?,
                actor_name: row.get(10)?,
                email_sent: row.get::<_, i64>(11)? != 0,
                created_at: row.get(12)?,
            })
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
    }

    pub fn get_project_overrides(&self, project_id: i64) -> Vec<OverrideRow> {
        let conn = self.conn.lock().unwrap();
        Self::get_project_overrides_inner(&conn, project_id)
    }

    // ---------------- flagged issues ----------------

    /// Called repeatedly as a run progresses — always reflects the latest
    /// known set of issues for the project, so the history/API view is
    /// never stale even if the pipeline dies before finishing.
    pub fn replace_project_issues(&self, project_id: i64, issues: &[IssueInput], overridden_ids: &HashSet<String>) {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().unwrap();
        tx.execute("DELETE FROM issues WHERE project_id = ?", params![project_id]).unwrap();
        for issue in issues {
            let snippet_json = issue.snippet.as_ref().map(|s| serde_json::to_string(s).unwrap());
            let chain_json = issue.chain.as_ref().map(|c| serde_json::to_string(c).unwrap());
            let status = if overridden_ids.contains(&issue.id) { "overridden" } else { "open" };
            tx.execute(
                "INSERT INTO issues (project_id, issue_id, phase, category, severity, score, summary, file, line, snippet_json, cross_file, chain_json, cwe, status)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    project_id, issue.id, issue.phase, issue.category, issue.severity, issue.score,
                    issue.summary, issue.file, issue.line, snippet_json, issue.cross_file as i64, chain_json,
                    issue.cwe, status,
                ],
            )
            .unwrap();
        }
        tx.commit().unwrap();
    }

    pub fn get_project_issues(&self, project_id: i64) -> Vec<IssueRow> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare_cached(
                "SELECT issue_id, phase, category, severity, score, summary, file, line, snippet_json, cross_file, chain_json, cwe, status, created_at
                 FROM issues WHERE project_id = ? ORDER BY id",
            )
            .unwrap();
        stmt.query_map(params![project_id], |row| {
            let snippet_json: Option<String> = row.get(8)?;
            let chain_json: Option<String> = row.get(10)?;
            Ok(IssueRow {
                id: row.get(0)?,
                phase: row.get(1)?,
                category: row.get(2)?,
                severity: row.get(3)?,
                score: row.get(4)?,
                summary: row.get(5)?,
                file: row.get(6)?,
                line: row.get(7)?,
                snippet: snippet_json.map(|s| serde_json::from_str(&s).unwrap()),
                cross_file: row.get::<_, i64>(9)? != 0,
                chain: chain_json.map(|c| serde_json::from_str(&c).unwrap()),
                cwe: row.get(11)?,
                status: row.get(12)?,
                created_at: row.get(13)?,
            })
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
    }

    pub fn get_project_id_by_job_id(&self, job_id: &str) -> Option<i64> {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT id FROM projects WHERE job_id = ?", params![job_id], |row| row.get(0)).optional().unwrap()
    }

    // ---------------- API keys ----------------

    pub fn create_api_key(&self, user_id: i64, key_hash: &str, label: Option<&str>, created_by: Option<&str>, created_via: &str) -> i64 {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO api_keys (user_id, key_hash, label, created_by, created_via) VALUES (?, ?, ?, ?, ?)",
            params![user_id, key_hash, label, created_by, created_via],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    pub fn get_active_api_key_by_hash(&self, key_hash: &str) -> Option<ApiKeyIdentity> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT ak.id, ak.user_id, u.email, u.name, u.provider
             FROM api_keys ak JOIN users u ON u.id = ak.user_id
             WHERE ak.key_hash = ? AND ak.revoked_at IS NULL",
            params![key_hash],
            |row| Ok(ApiKeyIdentity { id: row.get(0)?, user_id: row.get(1)?, email: row.get(2)?, name: row.get(3)?, provider: row.get(4)? }),
        )
        .optional()
        .unwrap()
    }

    pub fn touch_api_key_last_used(&self, id: i64) {
        let conn = self.conn.lock().unwrap();
        conn.execute("UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ?", params![id]).unwrap();
    }

    pub fn list_api_keys_for_user(&self, user_id: i64) -> Vec<ApiKeySummary> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare_cached("SELECT id, label, created_at, created_by, created_via, last_used_at, revoked_at FROM api_keys WHERE user_id = ? ORDER BY id")
            .unwrap();
        stmt.query_map(params![user_id], |row| {
            Ok(ApiKeySummary {
                id: row.get(0)?,
                label: row.get(1)?,
                created_at: row.get(2)?,
                created_by: row.get(3)?,
                created_via: row.get(4)?,
                last_used_at: row.get(5)?,
                revoked_at: row.get(6)?,
            })
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
    }

    pub fn revoke_api_key(&self, id: i64) -> bool {
        let conn = self.conn.lock().unwrap();
        conn.execute("UPDATE api_keys SET revoked_at = datetime('now') WHERE id = ? AND revoked_at IS NULL", params![id]).unwrap() > 0
    }

    // ---------------- cached AI explanations ----------------

    pub fn get_cached_issue_explanation(&self, hash: &str) -> Option<String> {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT explanation FROM issue_explanations WHERE hash = ?", params![hash], |row| row.get(0))
            .optional()
            .unwrap()
    }

    pub fn cache_issue_explanation(&self, hash: &str, explanation: &str) {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO issue_explanations (hash, explanation) VALUES (?, ?)
             ON CONFLICT(hash) DO UPDATE SET explanation = excluded.explanation",
            params![hash, explanation],
        )
        .unwrap();
    }

    /// Projects/steps left in 'running' happen only when the process died
    /// mid-pipeline — nothing will ever finish them, so on every startup
    /// we sweep them into a terminal 'aborted' state instead of leaving
    /// stale spinners in the history panel forever.
    pub fn abort_stale_running_projects(&self) {
        const ABORTED_ERROR: &str = "Server restarted while onboarding was still in progress.";
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE projects SET status = 'aborted', error = COALESCE(error, ?1), finished_at = datetime('now') WHERE status = 'running'",
            params![ABORTED_ERROR],
        )
        .unwrap();
        conn.execute(
            "UPDATE steps SET state = 'failed', logs = logs || char(10) || '✗ ' || ?1
             WHERE state = 'running' AND project_id IN (SELECT id FROM projects WHERE error = ?1)",
            params![ABORTED_ERROR],
        )
        .unwrap();
    }

    // ---------------- baseline/diff adoption mode ----------------

    pub fn save_baseline(&self, org: &str, repo: &str, issue_ids: &[String]) -> usize {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().unwrap();
        tx.execute("DELETE FROM issue_baselines WHERE org = ? AND repo = ?", params![org, repo]).unwrap();
        for id in issue_ids {
            tx.execute("INSERT OR IGNORE INTO issue_baselines (org, repo, issue_id) VALUES (?, ?, ?)", params![org, repo, id]).unwrap();
        }
        tx.commit().unwrap();
        issue_ids.len()
    }

    pub fn clear_baseline(&self, org: &str, repo: &str) -> usize {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM issue_baselines WHERE org = ? AND repo = ?", params![org, repo]).unwrap()
    }

    pub fn get_baseline_issue_ids(&self, org: &str, repo: &str) -> HashSet<String> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare_cached("SELECT issue_id FROM issue_baselines WHERE org = ? AND repo = ?").unwrap();
        stmt.query_map(params![org, repo], |row| row.get(0)).unwrap().map(|r: rusqlite::Result<String>| r.unwrap()).collect()
    }

    // ---------------- runtime coverage ingestion ----------------

    pub fn ingest_runtime_coverage(&self, org: &str, repo: &str, file_stats: &HashMap<String, RuntimeCoverageInput>) -> usize {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().unwrap();
        for (rel_path, stats) in file_stats {
            tx.execute(
                "INSERT INTO runtime_coverage (org, repo, rel_path, hit_count, covered_pct, updated_at)
                 VALUES (?, ?, ?, ?, ?, datetime('now'))
                 ON CONFLICT(org, repo, rel_path) DO UPDATE SET hit_count = excluded.hit_count, covered_pct = excluded.covered_pct, updated_at = excluded.updated_at",
                params![org, repo, rel_path, stats.hit_count, stats.covered_pct],
            )
            .unwrap();
        }
        tx.commit().unwrap();
        file_stats.len()
    }

    pub fn get_runtime_coverage_for_file(&self, org: &str, repo: &str, rel_path: &str) -> Option<RuntimeCoverageRow> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT hit_count, covered_pct FROM runtime_coverage WHERE org = ? AND repo = ? AND rel_path = ?",
            params![org, repo, rel_path],
            |row| Ok(RuntimeCoverageRow { hit_count: row.get(0)?, covered_pct: row.get(1)? }),
        )
        .optional()
        .unwrap()
    }

    pub fn get_runtime_coverage_map(&self, org: &str, repo: &str) -> HashMap<String, RuntimeCoverageRow> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare_cached("SELECT rel_path, hit_count, covered_pct FROM runtime_coverage WHERE org = ? AND repo = ?").unwrap();
        stmt.query_map(params![org, repo], |row| {
            let rel_path: String = row.get(0)?;
            Ok((rel_path, RuntimeCoverageRow { hit_count: row.get(1)?, covered_pct: row.get(2)? }))
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
    }

    pub fn clear_runtime_coverage(&self, org: &str, repo: &str) -> usize {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM runtime_coverage WHERE org = ? AND repo = ?", params![org, repo]).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn open_test_db() -> (tempfile::TempDir, DbStore) {
        let dir = tempdir().unwrap();
        let store = DbStore::open(&dir.path().join("test.db")).unwrap();
        (dir, store)
    }

    #[test]
    fn create_and_fetch_project_round_trips() {
        let (_dir, store) = open_test_db();
        let id = store.create_project("job-1", "acme", "widgets", false, "ui", None);
        let project = store.get_project(id).unwrap();
        assert_eq!(project.org, "acme");
        assert_eq!(project.repo, "widgets");
        assert_eq!(project.status, "running");
        assert!(!project.gxp);
    }

    #[test]
    fn finish_project_updates_status_and_timestamps() {
        let (_dir, store) = open_test_db();
        let id = store.create_project("job-2", "acme", "widgets", false, "ui", None);
        store.finish_project("success", None, Some("https://github.com/acme/widgets"), None, id);
        let project = store.get_project(id).unwrap();
        assert_eq!(project.status, "success");
        assert_eq!(project.repo_url.as_deref(), Some("https://github.com/acme/widgets"));
        assert!(project.finished_at.is_some());
    }

    #[test]
    fn set_project_commit_shas_coalesces_and_does_not_clobber() {
        let (_dir, store) = open_test_db();
        let id = store.create_project("job-commit", "acme", "widgets", false, "ui", None);
        store.set_project_commit_shas(id, Some("abc123"), None);
        let project = store.get_project(id).unwrap();
        assert_eq!(project.source_commit_sha.as_deref(), Some("abc123"));
        assert_eq!(project.shipped_commit_sha, None);

        store.set_project_commit_shas(id, None, Some("def456"));
        let project = store.get_project(id).unwrap();
        assert_eq!(project.source_commit_sha.as_deref(), Some("abc123"));
        assert_eq!(project.shipped_commit_sha.as_deref(), Some("def456"));
    }

    #[test]
    fn retain_project_source_defaults_full_and_updates_tier() {
        let (_dir, store) = open_test_db();
        let id = store.create_project("job-retain", "acme", "widgets", false, "ui", None);
        store.retain_project_source(id, "/tmp/retained/1", "full");
        let rows = store.list_retained_sources();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].tier, "full");

        store.set_retained_source_tier(id, "pruned");
        let rows = store.list_retained_sources();
        assert_eq!(rows[0].tier, "pruned");
    }

    #[test]
    fn list_evictable_retained_sources_respects_keep_across_tiers() {
        let (_dir, store) = open_test_db();
        for i in 0..12 {
            let id = store.create_project(&format!("job-evict-{i}"), "acme", "widgets", false, "ui", None);
            let tier = if i < 5 { "full" } else { "pruned" };
            store.retain_project_source(id, &format!("/tmp/retained/{i}"), tier);
        }
        let evictable = store.list_evictable_retained_sources(10);
        assert_eq!(evictable.len(), 2, "expected exactly 2 rows beyond the 10 most recently retained");
    }

    #[test]
    fn upsert_step_updates_in_place_on_conflict() {
        let (_dir, store) = open_test_db();
        let id = store.create_project("job-3", "acme", "widgets", false, "ui", None);
        store.upsert_step(id, 4, "Security Scan", "running", "log line 1");
        store.upsert_step(id, 4, "Security Scan", "success", "log line 1\nlog line 2");
        let details = store.get_project_details(id).unwrap();
        assert_eq!(details.steps.len(), 1);
        assert_eq!(details.steps[0].state, "success");
        assert_eq!(details.steps[0].logs, "log line 1\nlog line 2");
    }

    #[test]
    fn delete_project_by_id_also_clears_file_scan_cache_for_its_repo() {
        let (_dir, store) = open_test_db();
        let id = store.create_project("job-4", "acme", "widgets", false, "ui", None);
        store.replace_file_scan_cache(
            "acme",
            "widgets",
            "secrets",
            &[FileScanCacheInput { rel_path: "a.js".into(), hash: "h1".into(), findings: serde_json::json!([]) }],
        );
        store.delete_project_by_id(id);
        assert!(!store.project_exists(id));
        assert!(store.get_file_scan_cache("acme", "widgets", "secrets").is_empty());
    }

    #[test]
    fn replace_project_issues_marks_overridden_status_and_round_trips_json_columns() {
        let (_dir, store) = open_test_db();
        let id = store.create_project("job-5", "acme", "widgets", false, "ui", None);
        let issues = vec![
            IssueInput {
                id: "secret::a.js::3".into(),
                phase: Some(4),
                category: "secret".into(),
                severity: "error".into(),
                score: Some(8),
                summary: "hardcoded key".into(),
                file: Some("a.js".into()),
                line: Some(3),
                snippet: Some(serde_json::json!({"startLine": 1, "lines": []})),
                cross_file: false,
                chain: None,
                cwe: Some("CWE-798".into()),
            },
            IssueInput {
                id: "codeql-sast::b.js::10".into(),
                phase: Some(4),
                category: "codeql-sast".into(),
                severity: "error".into(),
                score: Some(9),
                summary: "taint flow".into(),
                file: Some("b.js".into()),
                line: Some(10),
                snippet: None,
                cross_file: true,
                chain: Some(serde_json::json!([{"file": "a.js", "line": 1}])),
                cwe: None,
            },
        ];
        let mut overridden = HashSet::new();
        overridden.insert("secret::a.js::3".to_string());
        store.replace_project_issues(id, &issues, &overridden);

        let rows = store.get_project_issues(id);
        assert_eq!(rows.len(), 2);
        let secret = rows.iter().find(|r| r.id == "secret::a.js::3").unwrap();
        assert_eq!(secret.status, "overridden");
        assert!(secret.snippet.is_some());
        let codeql = rows.iter().find(|r| r.id == "codeql-sast::b.js::10").unwrap();
        assert_eq!(codeql.status, "open");
        assert!(codeql.cross_file);
        assert!(codeql.chain.is_some());

        // The frontend (public/index.html) reads issue.crossFile, not
        // issue.cross_file - the API-facing JSON must use camelCase.
        let json = serde_json::to_value(codeql).unwrap();
        assert_eq!(json["crossFile"], serde_json::json!(true));
        assert!(json.get("cross_file").is_none());
    }

    #[test]
    fn cosign_verify_cache_respects_ttl() {
        let (_dir, store) = open_test_db();
        store.save_cosign_verify_cache("nginx:latest", ".*", ".*", true, None);
        assert!(store.get_cosign_verify_cache("nginx:latest", ".*", ".*", 3600).is_some());
        // Same reasoning as the JS suite's own TTL test: a max_age_seconds
        // of 0 means "must have been checked in the last 0 seconds",
        // which a row written even a moment ago can't satisfy.
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(store.get_cosign_verify_cache("nginx:latest", ".*", ".*", 0).is_none());
    }

    #[test]
    fn baseline_round_trips_and_clears() {
        let (_dir, store) = open_test_db();
        let saved = store.save_baseline("acme", "widgets", &["a".into(), "b".into()]);
        assert_eq!(saved, 2);
        let ids = store.get_baseline_issue_ids("acme", "widgets");
        assert_eq!(ids.len(), 2);
        assert!(ids.contains("a"));
        let cleared = store.clear_baseline("acme", "widgets");
        assert_eq!(cleared, 2);
        assert!(store.get_baseline_issue_ids("acme", "widgets").is_empty());
    }

    #[test]
    fn runtime_coverage_ingest_and_map() {
        let (_dir, store) = open_test_db();
        let mut stats = HashMap::new();
        stats.insert("src/a.js".to_string(), RuntimeCoverageInput { hit_count: 5, covered_pct: Some(80.0) });
        let count = store.ingest_runtime_coverage("acme", "widgets", &stats);
        assert_eq!(count, 1);
        let row = store.get_runtime_coverage_for_file("acme", "widgets", "src/a.js").unwrap();
        assert_eq!(row.hit_count, 5);
        assert_eq!(row.covered_pct, Some(80.0));
        let map = store.get_runtime_coverage_map("acme", "widgets");
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn api_key_lifecycle_create_lookup_revoke() {
        let (_dir, store) = open_test_db();
        let user_id = store.create_local_user("dev@example.com", Some("Dev"), "hash");
        let key_id = store.create_api_key(user_id, "sha256hash", Some("laptop"), Some("dev@example.com"), "cli");
        let identity = store.get_active_api_key_by_hash("sha256hash").unwrap();
        assert_eq!(identity.user_id, user_id);
        assert!(store.revoke_api_key(key_id));
        assert!(store.get_active_api_key_by_hash("sha256hash").is_none());
    }

    #[test]
    fn abort_stale_running_projects_marks_running_as_aborted() {
        let (_dir, store) = open_test_db();
        let id = store.create_project("job-6", "acme", "widgets", false, "ui", None);
        store.upsert_step(id, 4, "Security Scan", "running", "in progress");
        store.abort_stale_running_projects();
        let project = store.get_project(id).unwrap();
        assert_eq!(project.status, "aborted");
        assert!(project.error.is_some());
        let details = store.get_project_details(id).unwrap();
        assert_eq!(details.steps[0].state, "failed");
        assert!(details.steps[0].logs.contains("Server restarted"));
    }

    #[test]
    fn migrations_are_idempotent_across_two_opens_of_the_same_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.db");
        {
            let store = DbStore::open(&path).unwrap();
            store.create_project("job-7", "acme", "widgets", false, "ui", None);
        }
        // Reopening the same on-disk DB re-runs schema + migrations against
        // already-existing tables/columns — must not error.
        let store2 = DbStore::open(&path).unwrap();
        assert_eq!(store2.list_projects().len(), 1);
    }
}
