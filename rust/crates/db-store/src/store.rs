//! The `DbStore` handle itself and its constructor — every domain's
//! accessor methods (projects, auth, caches, ...) are `impl DbStore`
//! blocks in their own module, all operating on this one shared
//! connection.

use crate::schema::{BACKFILL_ONBOARDING_PRS_SQL, BACKFILL_REPOSITORY_MODEL_SQL, MIGRATIONS, SCHEMA_SQL};
use parking_lot::Mutex;
use rusqlite::Connection;
use std::path::Path;

pub struct DbStore {
    pub(crate) conn: Mutex<Connection>,
}

impl DbStore {
    pub fn open(db_file: &Path) -> rusqlite::Result<Self> {
        let conn = Connection::open(db_file)?;
        // SQLite disables foreign-key enforcement by default on every new
        // connection (a per-connection setting, not a database-file one —
        // must be set here, not just once at schema-creation time).
        // Without it, none of the schema's `ON DELETE CASCADE` clauses
        // actually fire: deleting a project leaves its `pull_requests`/
        // `dependency_scan_cache` rows (the latter holding large JSON
        // blobs) orphaned instead of cascaded away.
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        conn.execute_batch(SCHEMA_SQL)?;
        run_migrations(&conn)?;
        conn.execute_batch(BACKFILL_ONBOARDING_PRS_SQL)?;
        conn.execute_batch(BACKFILL_REPOSITORY_MODEL_SQL)?;
        Ok(DbStore { conn: Mutex::new(conn) })
    }
}

/// Applies every not-yet-applied entry in `schema::MIGRATIONS`, recording
/// each one's version in `schema_migrations` so it never runs twice.
///
/// A DB created before `schema_migrations` existed has already applied
/// every migration up to whatever version this codebase was at when it
/// was created/last opened — but has no row saying so. For those, the
/// first `ALTER TABLE ... ADD COLUMN` against an already-existing column
/// fails with "duplicate column"; that one case is still swallowed here
/// (matching the old behavior) and the version is recorded anyway, so the
/// backfill happens exactly once and every migration after it goes back
/// to normal exactly-once semantics.
fn run_migrations(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version    INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        );",
    )?;
    for (version, ddl) in MIGRATIONS {
        let already_applied: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = ?)", [version], |row| row.get(0))?;
        if already_applied {
            continue;
        }
        if let Err(e) = conn.execute_batch(ddl) {
            let msg = e.to_string().to_lowercase();
            if !msg.contains("duplicate column") {
                return Err(e);
            }
        }
        conn.execute("INSERT INTO schema_migrations (version) VALUES (?)", [version])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression test: `BACKFILL_REPOSITORY_MODEL_SQL` used to
    /// `SELECT DISTINCT p.org, p.repo, p.created_at` — deduping on all
    /// three columns instead of just `(org, repo)`, so a repository
    /// scanned more than once (any real rescan — the common case, not an
    /// edge case) produced one "distinct" row per differing
    /// `created_at`, and the second `INSERT` into `repositories`
    /// violated its `UNIQUE(org, repo)` index. `DbStore::open` propagated
    /// that as an unhandled `rusqlite::Error`, which panicked at
    /// `main.rs`'s `.expect("failed to open db")` on server startup —
    /// this reproduces it directly against `open()` without needing a
    /// real server process.
    #[test]
    fn opening_a_db_with_multiple_projects_for_the_same_repo_does_not_panic() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        {
            // Raw inserts (not `create_project`, which already live-mirrors
            // into `repositories`/`scan_runs` on every call — that path
            // never had this bug) simulate a real pre-US-01 database:
            // `projects` rows exist with no corresponding `repositories`/
            // `scan_runs` rows yet, and — the part that actually triggers
            // the bug — two rows for the *same* `(org, repo)` with
            // different `created_at` timestamps, exactly what a repo
            // scanned more than once produces.
            let db = DbStore::open(&db_path).unwrap();
            let conn = db.conn.lock();
            conn.execute("INSERT INTO projects (job_id, org, repo, created_at) VALUES ('job-1', 'acme', 'widgets', '2026-01-01 00:00:00')", []).unwrap();
            conn.execute("INSERT INTO projects (job_id, org, repo, created_at) VALUES ('job-2', 'acme', 'widgets', '2026-01-02 00:00:00')", []).unwrap();
            conn.execute("DELETE FROM repositories", []).unwrap();
            conn.execute("DELETE FROM scan_runs", []).unwrap();
            conn.execute("DELETE FROM source_snapshots", []).unwrap();
        }

        // Re-opening re-runs `BACKFILL_REPOSITORY_MODEL_SQL` against the
        // now-populated (and repositories-table-emptied) `projects` table
        // — this must not panic, and must produce exactly one repository
        // shared by both scan runs, not one repository row per distinct
        // `created_at`.
        let db = DbStore::open(&db_path).unwrap();
        let repo = db.get_repository_by_org_repo("acme", "widgets").unwrap();
        let runs = db.list_scan_runs_for_repository(repo.id);
        assert_eq!(runs.len(), 2, "both projects must resolve to the same repository, as two separate scan runs");
    }
}
