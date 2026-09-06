//! GitHub OAuth connection storage (per-user access token + scope).
//!
//! `impl DbStore` block — one of several per-domain files this crate's
//! accessor methods are split across (see `lib.rs`'s module list).

use crate::store::DbStore;
use crate::types::*;
use rusqlite::{params, OptionalExtension};

impl DbStore {
    // ---------------- GitHub OAuth connection ----------------

    pub fn upsert_github_connection(&self, user_id: i64, github_login: &str, access_token: &str, scope: Option<&str>) {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO github_connections (user_id, github_login, access_token, scope)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(user_id) DO UPDATE SET github_login = excluded.github_login, access_token = excluded.access_token, scope = excluded.scope, connected_at = datetime('now')",
            params![user_id, github_login, access_token, scope],
        )
        .unwrap();
    }

    pub fn get_github_connection(&self, user_id: i64) -> Option<GithubConnection> {
        let conn = self.conn.lock();
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
        let conn = self.conn.lock();
        conn.execute("DELETE FROM github_connections WHERE user_id = ?", params![user_id]).unwrap();
    }

}
