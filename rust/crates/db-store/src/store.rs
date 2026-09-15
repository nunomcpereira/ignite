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
