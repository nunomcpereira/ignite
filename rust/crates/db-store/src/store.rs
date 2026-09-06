//! The `DbStore` handle itself and its constructor — every domain's
//! accessor methods (projects, auth, caches, ...) are `impl DbStore`
//! blocks in their own module, all operating on this one shared
//! connection.

use crate::schema::{BACKFILL_ONBOARDING_PRS_SQL, MIGRATIONS, SCHEMA_SQL};
use parking_lot::Mutex;
use rusqlite::Connection;
use std::path::Path;

pub struct DbStore {
    pub(crate) conn: Mutex<Connection>,
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
        conn.execute_batch(BACKFILL_ONBOARDING_PRS_SQL)?;
        Ok(DbStore { conn: Mutex::new(conn) })
    }
}
