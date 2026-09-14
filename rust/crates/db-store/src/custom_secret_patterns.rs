//! Custom secret patterns: operator-authored regex rules (GHAS "custom
//! pattern" parity), backing `/api/secret-patterns`. Storage only — the
//! actual pattern-testing/gitleaks-config-building logic lives in
//! `ignite-secrets` (`test_pattern_against_sample`,
//! `build_gitleaks_config_for_patterns`), which stays decoupled from this
//! crate the same way every other check crate does.
//!
//! `impl DbStore` block — one of several per-domain files this crate's
//! accessor methods are split across (see `lib.rs`'s module list).

use crate::store::DbStore;
use crate::types::CustomSecretPatternRow;
use rusqlite::params;

impl DbStore {
    // ---------------- custom secret patterns ----------------

    pub fn create_custom_secret_pattern(&self, name: &str, regex: &str, created_by: Option<&str>) -> rusqlite::Result<i64> {
        let conn = self.conn.lock();
        conn.execute("INSERT INTO custom_secret_patterns (name, regex, created_by) VALUES (?, ?, ?)", params![name, regex, created_by])?;
        Ok(conn.last_insert_rowid())
    }

    fn row_from(row: &rusqlite::Row) -> rusqlite::Result<CustomSecretPatternRow> {
        Ok(CustomSecretPatternRow { id: row.get(0)?, name: row.get(1)?, regex: row.get(2)?, enabled: row.get::<_, i64>(3)? != 0, created_by: row.get(4)?, created_at: row.get(5)? })
    }

    pub fn get_custom_secret_pattern(&self, id: i64) -> Option<CustomSecretPatternRow> {
        let conn = self.conn.lock();
        conn.query_row("SELECT id, name, regex, enabled, created_by, created_at FROM custom_secret_patterns WHERE id = ?", params![id], Self::row_from).ok()
    }

    fn list_custom_secret_patterns_by_query(conn: &rusqlite::Connection, sql: &str) -> Vec<CustomSecretPatternRow> {
        let Ok(mut stmt) = conn.prepare_cached(sql) else { return vec![] };
        let rows: Vec<CustomSecretPatternRow> = match stmt.query_map([], Self::row_from) {
            Ok(mapped) => mapped.filter_map(|r| r.ok()).collect(),
            Err(_) => vec![],
        };
        rows
    }

    pub fn list_custom_secret_patterns(&self) -> Vec<CustomSecretPatternRow> {
        let conn = self.conn.lock();
        Self::list_custom_secret_patterns_by_query(&conn, "SELECT id, name, regex, enabled, created_by, created_at FROM custom_secret_patterns ORDER BY created_at DESC")
    }

    /// Just the `enabled` ones — what a live scan (working-tree or
    /// history) actually feeds into `build_gitleaks_config_for_patterns`;
    /// a disabled pattern still exists (kept for its playground/sweep
    /// history) but never runs against real code until re-enabled.
    pub fn list_enabled_custom_secret_patterns(&self) -> Vec<CustomSecretPatternRow> {
        let conn = self.conn.lock();
        Self::list_custom_secret_patterns_by_query(&conn, "SELECT id, name, regex, enabled, created_by, created_at FROM custom_secret_patterns WHERE enabled = 1 ORDER BY created_at DESC")
    }

    pub fn set_custom_secret_pattern_enabled(&self, id: i64, enabled: bool) -> bool {
        let conn = self.conn.lock();
        conn.execute("UPDATE custom_secret_patterns SET enabled = ? WHERE id = ?", params![enabled as i64, id]).unwrap_or(0) > 0
    }

    pub fn delete_custom_secret_pattern(&self, id: i64) -> bool {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM custom_secret_patterns WHERE id = ?", params![id]).unwrap_or(0) > 0
    }
}

