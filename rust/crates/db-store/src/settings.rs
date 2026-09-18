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

    /// Enrolls `org` in the auto-rescan sweep with exactly `excluded_repos`
    /// unchecked (everything else in the org is swept), replacing any
    /// earlier selection for that org. Atomic.
    pub fn set_auto_rescan_org_selection(&self, org: &str, excluded_repos: &[String]) {
        let org = org.to_ascii_lowercase();
        let mut conn = self.conn.lock();
        let tx = conn.transaction().unwrap();
        tx.execute("INSERT OR IGNORE INTO auto_rescan_orgs (org) VALUES (?)", params![org]).unwrap();
        tx.execute("DELETE FROM auto_rescan_excluded_repos WHERE org = ?", params![org]).unwrap();
        for repo in excluded_repos {
            tx.execute("INSERT OR IGNORE INTO auto_rescan_excluded_repos (org, repo) VALUES (?, ?)", params![org, repo.to_ascii_lowercase()]).unwrap();
        }
        tx.commit().unwrap();
    }

    /// Adds `org` to the GitHub Org view's saved list (idempotent).
    pub fn save_org(&self, org: &str) {
        self.conn.lock().execute("INSERT OR IGNORE INTO saved_orgs (org) VALUES (?)", params![org.to_ascii_lowercase()]).unwrap();
    }

    /// Removes `org` from the saved list. Returns whether it was saved.
    pub fn unsave_org(&self, org: &str) -> bool {
        self.conn.lock().execute("DELETE FROM saved_orgs WHERE org = ?", params![org.to_ascii_lowercase()]).unwrap() > 0
    }

    /// Every org saved in the GitHub Org view, oldest first.
    pub fn list_saved_orgs(&self) -> Vec<String> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT org FROM saved_orgs ORDER BY added_at, org").unwrap();
        let orgs: Vec<String> = stmt.query_map([], |row| row.get(0)).unwrap().filter_map(Result::ok).collect();
        orgs
    }

    /// Removes `org` (and its exclusions) from the sweep. Returns whether it was enrolled.
    pub fn unenroll_auto_rescan_org(&self, org: &str) -> bool {
        let org = org.to_ascii_lowercase();
        let conn = self.conn.lock();
        conn.execute("DELETE FROM auto_rescan_excluded_repos WHERE org = ?", params![org]).unwrap();
        conn.execute("DELETE FROM auto_rescan_orgs WHERE org = ?", params![org]).unwrap() > 0
    }

    /// Whether the sweep should scan `org/repo`: org enrolled and repo not unchecked.
    pub fn is_auto_rescan_repo_selected(&self, org: &str, repo: &str) -> bool {
        let (org, repo) = (org.to_ascii_lowercase(), repo.to_ascii_lowercase());
        let conn = self.conn.lock();
        let enrolled = conn.query_row("SELECT 1 FROM auto_rescan_orgs WHERE org = ?", params![org], |_| Ok(())).optional().unwrap().is_some();
        enrolled && conn.query_row("SELECT 1 FROM auto_rescan_excluded_repos WHERE org = ? AND repo = ?", params![org, repo], |_| Ok(())).optional().unwrap().is_none()
    }

    /// Every enrolled org with its unchecked (excluded) repos, sorted.
    pub fn list_auto_rescan_selection(&self) -> Vec<(String, Vec<String>)> {
        let conn = self.conn.lock();
        let orgs: Vec<String> = conn.prepare("SELECT org FROM auto_rescan_orgs ORDER BY org").unwrap().query_map([], |row| row.get(0)).unwrap().filter_map(Result::ok).collect();
        orgs.into_iter()
            .map(|org| {
                let excluded: Vec<String> = conn
                    .prepare("SELECT repo FROM auto_rescan_excluded_repos WHERE org = ? ORDER BY repo")
                    .unwrap()
                    .query_map(params![org], |row| row.get(0))
                    .unwrap()
                    .filter_map(Result::ok)
                    .collect();
                (org, excluded)
            })
            .collect()
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

    #[test]
    fn saved_orgs_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let db = DbStore::open(&dir.path().join("test.db")).unwrap();
        assert!(db.list_saved_orgs().is_empty());
        db.save_org("Acme");
        db.save_org("acme");
        db.save_org("beta");
        assert_eq!(db.list_saved_orgs(), vec!["acme".to_string(), "beta".to_string()]);
        assert!(db.unsave_org("ACME"));
        assert!(!db.unsave_org("acme"));
        assert_eq!(db.list_saved_orgs(), vec!["beta".to_string()]);
    }

    #[test]
    fn auto_rescan_selection_round_trips_replaces_and_unenrolls() {
        let dir = tempfile::tempdir().unwrap();
        let db = DbStore::open(&dir.path().join("test.db")).unwrap();
        assert!(db.list_auto_rescan_selection().is_empty());
        assert!(!db.is_auto_rescan_repo_selected("acme", "web"));

        db.set_auto_rescan_org_selection("Acme", &["Legacy".to_string(), "docs".to_string()]);
        db.set_auto_rescan_org_selection("beta", &[]);
        assert_eq!(db.list_auto_rescan_selection(), vec![("acme".to_string(), vec!["docs".to_string(), "legacy".to_string()]), ("beta".to_string(), vec![])]);
        assert!(db.is_auto_rescan_repo_selected("ACME", "web"));
        assert!(!db.is_auto_rescan_repo_selected("acme", "LEGACY"));
        assert!(!db.is_auto_rescan_repo_selected("gamma", "web"));

        // A later selection replaces (not merges with) the earlier one.
        db.set_auto_rescan_org_selection("acme", &["web".to_string()]);
        assert!(db.is_auto_rescan_repo_selected("acme", "legacy"));
        assert!(!db.is_auto_rescan_repo_selected("acme", "web"));

        assert!(db.unenroll_auto_rescan_org("Acme"));
        assert!(!db.unenroll_auto_rescan_org("acme"));
        assert!(!db.is_auto_rescan_repo_selected("acme", "legacy"));
        db.set_auto_rescan_org_selection("acme", &[]);
        assert!(db.is_auto_rescan_repo_selected("acme", "web"), "unenrolling must have cleared the old exclusions");
    }
}
