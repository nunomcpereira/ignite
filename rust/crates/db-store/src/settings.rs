//! `app_settings` — the small generic key/value store for runtime-
//! toggleable settings (see `schema.rs`'s own doc comment on the table).

use crate::store::DbStore;
use rusqlite::{params, OptionalExtension};

impl DbStore {
    pub fn get_setting(&self, key: &str) -> Option<String> {
        let conn = self.conn.lock();
        conn.query_row("SELECT value FROM app_settings WHERE key = ?", params![key], |row| row.get(0)).optional().unwrap()
    }

    pub fn set_setting(&self, key: &str, value: &str) {
        let conn = self.conn.lock();
        conn.execute("INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, datetime('now')) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at", params![key, value]).unwrap();
    }

    pub fn get_bool_setting(&self, key: &str, default: bool) -> bool {
        self.get_setting(key).map(|v| v == "true").unwrap_or(default)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_setting_defaults_to_none_when_unset() {
        let dir = tempfile::tempdir().unwrap();
        let db = DbStore::open(&dir.path().join("test.db")).unwrap();
        assert_eq!(db.get_setting("auto_rescan_enabled"), None);
        assert!(!db.get_bool_setting("auto_rescan_enabled", false));
    }

    #[test]
    fn set_setting_then_get_round_trips_and_upserts() {
        let dir = tempfile::tempdir().unwrap();
        let db = DbStore::open(&dir.path().join("test.db")).unwrap();
        db.set_setting("auto_rescan_enabled", "true");
        assert_eq!(db.get_setting("auto_rescan_enabled"), Some("true".to_string()));
        assert!(db.get_bool_setting("auto_rescan_enabled", false));

        db.set_setting("auto_rescan_enabled", "false");
        assert_eq!(db.get_setting("auto_rescan_enabled"), Some("false".to_string()));
        assert!(!db.get_bool_setting("auto_rescan_enabled", true));
    }
}
