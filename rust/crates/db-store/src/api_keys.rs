//! Headless API key issuance/lookup/revocation.
//!
//! `impl DbStore` block — one of several per-domain files this crate's
//! accessor methods are split across (see `lib.rs`'s module list).

use crate::store::DbStore;
use crate::types::*;
use rusqlite::{params, OptionalExtension};

impl DbStore {
    // ---------------- API keys ----------------

    pub fn create_api_key(&self, user_id: i64, key_hash: &str, label: Option<&str>, created_by: Option<&str>, created_via: &str) -> i64 {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO api_keys (user_id, key_hash, label, created_by, created_via) VALUES (?, ?, ?, ?, ?)",
            params![user_id, key_hash, label, created_by, created_via],
        )
        .unwrap();
        conn.last_insert_rowid()
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
        let conn = self.conn.lock();
        conn.execute("UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ?", params![id]).unwrap();
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

    pub fn revoke_api_key(&self, id: i64) -> bool {
        let conn = self.conn.lock();
        conn.execute("UPDATE api_keys SET revoked_at = datetime('now') WHERE id = ? AND revoked_at IS NULL", params![id]).unwrap() > 0
    }

}
