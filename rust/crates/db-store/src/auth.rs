//! Local/OIDC/GitHub user accounts and session tokens.
//!
//! `impl DbStore` block — one of several per-domain files this crate's
//! accessor methods are split across (see `lib.rs`'s module list).

use crate::store::DbStore;
use crate::types::*;
use rusqlite::{params, OptionalExtension};

impl DbStore {
    // ---------------- auth: users + sessions ----------------

    pub fn create_local_user(&self, email: &str, name: Option<&str>, password_hash: &str) -> i64 {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO users (email, name, provider, password_hash) VALUES (?, ?, 'local', ?)",
            params![email, name, password_hash],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    pub fn upsert_oidc_user(&self, email: &str, name: Option<&str>, external_id: &str) -> User {
        let conn = self.conn.lock();
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
        let conn = self.conn.lock();
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
        let conn = self.conn.lock();
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
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT password_hash FROM users WHERE id = ? AND provider = 'local'",
            params![user_id],
            |row| row.get(0),
        )
        .optional()
        .unwrap()
    }

    pub fn get_user_by_id(&self, user_id: i64) -> Option<User> {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT id, email, name, provider, created_at FROM users WHERE id = ?",
            params![user_id],
            Self::user_from_row,
        )
        .optional()
        .unwrap()
    }

    pub fn create_session(&self, session_id: &str, user_id: i64, expires_at_iso: &str) {
        let conn = self.conn.lock();
        conn.execute("INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)", params![session_id, user_id, expires_at_iso]).unwrap();
    }

    pub fn get_session(&self, session_id: &str) -> Option<SessionRow> {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT s.id, s.expires_at, u.id AS user_id, u.email, u.name, u.provider
             FROM sessions s JOIN users u ON u.id = s.user_id
             WHERE s.id = ? AND s.expires_at >= datetime('now')",
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

    pub fn sweep_expired_sessions(&self) {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM sessions WHERE expires_at < datetime('now')", []).unwrap();
    }

    pub fn delete_session(&self, session_id: &str) {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM sessions WHERE id = ?", params![session_id]).unwrap();
    }

}
