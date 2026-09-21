//! Headless API key issuance/lookup/revocation.
//!
//! `impl DbStore` block — one of several per-domain files this crate's
//! accessor methods are split across (see `lib.rs`'s module list).

use crate::store::DbStore;
use crate::types::*;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use rusqlite::{params, OptionalExtension};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// `touch_api_key_last_used` runs on every single request authenticated
/// with an API key — under moderate concurrency that's an exclusive
/// SQLite write transaction per request, serializing traffic behind one
/// row update. `last_used_at` only needs to be accurate to within a few
/// minutes for its actual purpose (an operator eyeballing "is this key
/// still in use"), so a real write is skipped whenever a recent one
/// already landed for the same key.
static LAST_TOUCHED: Lazy<Mutex<HashMap<i64, Instant>>> = Lazy::new(|| Mutex::new(HashMap::new()));
const TOUCH_DEBOUNCE: Duration = Duration::from_secs(5 * 60);

/// What an API key can be limited to. A key with no `scopes` is unrestricted.
///
/// - `scan`: run pipelines (validate-all, onboard/interactive dry runs)
/// - `override`: submit, approve or reject overrides
/// - `publish`: push to GitHub (real onboard, effectivate, fix-PR apply)
pub const API_KEY_SCOPES: &[&str] = &["scan", "override", "publish"];

/// Parses a comma-separated scope list (`"scan,override"`), lowercasing,
/// de-duplicating and rejecting unknown or empty input, so a typo can never
/// silently mint a key that is less restricted than intended.
pub fn parse_api_key_scopes(raw: &str) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for part in raw.split(',') {
        let scope = part.trim().to_lowercase();
        if scope.is_empty() {
            continue;
        }
        if !API_KEY_SCOPES.contains(&scope.as_str()) {
            return Err(format!("Unknown scope \"{scope}\". Valid scopes: {}.", API_KEY_SCOPES.join(", ")));
        }
        if !out.contains(&scope) {
            out.push(scope);
        }
    }
    if out.is_empty() {
        return Err(format!("No scopes given. Valid scopes: {}.", API_KEY_SCOPES.join(", ")));
    }
    Ok(out)
}

impl DbStore {
    // ---------------- API keys ----------------

    /// Limits a key to the given scopes (`None` = unrestricted again).
    pub fn set_api_key_scopes(&self, id: i64, scopes: Option<&[String]>) {
        let joined = scopes.map(|s| s.join(","));
        let conn = self.conn.lock();
        if let Err(e) = conn.execute("UPDATE api_keys SET scopes = ? WHERE id = ?", params![joined, id]) {
            tracing::error!("set_api_key_scopes failed for key {id}: {e}");
        }
    }

    /// `None` when there is no active key with this hash; `Some(None)` for an
    /// active, unrestricted key; `Some(Some(scopes))` for a restricted one.
    pub fn get_active_api_key_scopes(&self, key_hash: &str) -> Option<Option<Vec<String>>> {
        let conn = self.conn.lock();
        let row: Option<Option<String>> = conn
            .query_row("SELECT scopes FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL", params![key_hash], |row| row.get(0))
            .optional()
            .unwrap_or(None);
        row.map(|scopes| scopes.filter(|s| !s.is_empty()).map(|s| s.split(',').map(str::to_string).collect()))
    }

    pub fn create_api_key(&self, user_id: i64, key_hash: &str, label: Option<&str>, created_by: Option<&str>, created_via: &str) -> i64 {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO api_keys (user_id, key_hash, label, created_by, created_via) VALUES (?, ?, ?, ?, ?)",
            params![user_id, key_hash, label, created_by, created_via],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    /// Binds a GitHub push token to one API key, so a headless caller using
    /// that key can publish without a browser-connected OAuth account or the
    /// server's ambient `GH_TOKEN`. Stored the same way
    /// `github_connections.access_token` is (plaintext in `ignite.db`).
    /// `None` clears it.
    pub fn set_api_key_github_token(&self, id: i64, token: Option<&str>) {
        let conn = self.conn.lock();
        if let Err(e) = conn.execute("UPDATE api_keys SET github_token = ? WHERE id = ?", params![token, id]) {
            tracing::error!("set_api_key_github_token failed for key {id}: {e}");
        }
    }

    /// The GitHub token bound to an active (non-revoked) key, if any. An
    /// empty stored value reads as `None`.
    pub fn get_active_api_key_github_token(&self, key_hash: &str) -> Option<String> {
        let conn = self.conn.lock();
        let token: Option<String> = conn
            .query_row("SELECT github_token FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL", params![key_hash], |row| row.get(0))
            .optional()
            .unwrap_or(None)
            .flatten();
        token.filter(|t| !t.is_empty())
    }

    pub fn get_active_api_key_by_hash(&self, key_hash: &str) -> Option<ApiKeyIdentity> {
        let conn = self.conn.lock();
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
        {
            let mut last_touched = LAST_TOUCHED.lock();
            if let Some(at) = last_touched.get(&id) {
                if at.elapsed() < TOUCH_DEBOUNCE {
                    return;
                }
            }
            last_touched.insert(id, Instant::now());
        }
        let conn = self.conn.lock();
        if let Err(e) = conn.execute("UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ?", params![id]) {
            tracing::error!("touch_api_key_last_used failed for key {id}: {e}");
        }
    }

    pub fn list_api_keys_for_user(&self, user_id: i64) -> Vec<ApiKeySummary> {
        let conn = self.conn.lock();
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

    /// Scoped to `user_id` so a caller can only ever revoke their own key —
    /// an id-only revoke would let any authenticated caller revoke any
    /// other user's key the moment this is wired to an endpoint, since
    /// `api_keys.id` is a small sequential integer with no other guard.
    pub fn revoke_api_key(&self, id: i64, user_id: i64) -> bool {
        let conn = self.conn.lock();
        conn.execute("UPDATE api_keys SET revoked_at = datetime('now') WHERE id = ? AND user_id = ? AND revoked_at IS NULL", params![id, user_id]).unwrap() > 0
    }

}

#[cfg(test)]
mod scope_tests {
    use super::*;

    #[test]
    fn scopes_parse_normalise_and_reject_typos() {
        assert_eq!(parse_api_key_scopes("scan, Override ,scan").unwrap(), vec!["scan", "override"]);
        assert!(parse_api_key_scopes("scan,publsh").unwrap_err().contains("publsh"));
        assert!(parse_api_key_scopes("").is_err());
        assert!(parse_api_key_scopes(" , ").is_err());
    }

    #[test]
    fn a_keys_scopes_round_trip_and_null_means_unrestricted() {
        let dir = tempfile::tempdir().unwrap();
        let db = DbStore::open(&dir.path().join("test.db")).unwrap();
        let uid = db.create_local_user("a@example.com", None, "unused-hash").unwrap();
        let key_id = db.create_api_key(uid, "hash-1", None, None, "test");

        assert_eq!(db.get_active_api_key_scopes("hash-1"), Some(None), "a new key is unrestricted");
        assert_eq!(db.get_active_api_key_scopes("nope"), None, "no such key");

        db.set_api_key_scopes(key_id, Some(&["scan".to_string(), "override".to_string()]));
        assert_eq!(db.get_active_api_key_scopes("hash-1"), Some(Some(vec!["scan".to_string(), "override".to_string()])));

        db.set_api_key_scopes(key_id, None);
        assert_eq!(db.get_active_api_key_scopes("hash-1"), Some(None));

        db.set_api_key_scopes(key_id, Some(&["scan".to_string()]));
        assert!(db.revoke_api_key(key_id, uid));
        assert_eq!(db.get_active_api_key_scopes("hash-1"), None, "a revoked key has no active scopes");
    }
}

#[cfg(test)]
mod github_token_tests {
    use crate::store::DbStore;

    fn open_test_db() -> (DbStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = DbStore::open(&dir.path().join("test.db")).unwrap();
        (db, dir)
    }

    #[test]
    fn a_key_bound_github_token_is_returned_only_for_an_active_key() {
        let (db, _dir) = open_test_db();
        let user_id = db.create_local_user("agent@example.com", Some("Agent"), "unused-hash").unwrap();
        let key_id = db.create_api_key(user_id, "hash-1", None, None, "test");
        assert_eq!(db.get_active_api_key_github_token("hash-1"), None, "no token bound yet");

        db.set_api_key_github_token(key_id, Some("ghp_agent"));
        assert_eq!(db.get_active_api_key_github_token("hash-1").as_deref(), Some("ghp_agent"));
        assert_eq!(db.get_active_api_key_github_token("some-other-hash"), None);

        db.set_api_key_github_token(key_id, Some(""));
        assert_eq!(db.get_active_api_key_github_token("hash-1"), None, "an empty token reads as unbound");

        db.set_api_key_github_token(key_id, Some("ghp_agent"));
        assert!(db.revoke_api_key(key_id, user_id));
        assert_eq!(db.get_active_api_key_github_token("hash-1"), None, "a revoked key must not yield its token");
    }
}
