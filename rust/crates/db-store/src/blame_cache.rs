//! Per-file git blame ranges, keyed by the file's blob SHA (see migration
//! 38). A file's blame at an unchanged blob is reused across scans, so a
//! rescan only asks GitHub's rate-limited blame API about files that
//! actually changed.
//!
//! `impl DbStore` block — one of several per-domain files this crate's
//! accessor methods are split across (see `lib.rs`'s module list).

use crate::store::DbStore;
use rusqlite::{params, OptionalExtension};

/// Rows not read for this long are dropped by `prune_blame_cache`.
const BLAME_CACHE_MAX_IDLE_DAYS: u32 = 90;

impl DbStore {
    /// Cached blame ranges JSON for `(org, repo, path, blob_sha)`, marking
    /// the row as used. Org/repo are matched case-insensitively.
    pub fn get_blame_cache(&self, org: &str, repo: &str, path: &str, blob_sha: &str) -> Option<String> {
        let conn = self.conn.lock();
        let (org, repo) = (org.to_ascii_lowercase(), repo.to_ascii_lowercase());
        let found: Option<String> = conn
            .query_row("SELECT ranges_json FROM blame_cache WHERE org = ? AND repo = ? AND path = ? AND blob_sha = ?", params![org, repo, path, blob_sha], |row| row.get(0))
            .optional()
            .ok()
            .flatten();
        if found.is_some() {
            let _ = conn.execute("UPDATE blame_cache SET last_used_at = datetime('now') WHERE org = ? AND repo = ? AND path = ? AND blob_sha = ?", params![org, repo, path, blob_sha]);
        }
        found
    }

    pub fn put_blame_cache(&self, org: &str, repo: &str, path: &str, blob_sha: &str, ranges_json: &str) {
        let conn = self.conn.lock();
        if let Err(e) = conn.execute(
            "INSERT INTO blame_cache (org, repo, path, blob_sha, ranges_json) VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(org, repo, path, blob_sha) DO UPDATE SET ranges_json = excluded.ranges_json, last_used_at = datetime('now')",
            params![org.to_ascii_lowercase(), repo.to_ascii_lowercase(), path, blob_sha, ranges_json],
        ) {
            tracing::warn!(error = %e, "failed to write blame cache");
        }
    }

    /// Drops rows unused for `BLAME_CACHE_MAX_IDLE_DAYS` (old blobs of files
    /// that have since changed). Returns the number removed.
    pub fn prune_blame_cache(&self) -> usize {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM blame_cache WHERE last_used_at < datetime('now', ?)", params![format!("-{BLAME_CACHE_MAX_IDLE_DAYS} days")]).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use crate::store::DbStore;

    #[test]
    fn round_trips_by_blob_and_matches_org_repo_case_insensitively() {
        let dir = tempfile::tempdir().unwrap();
        let db = DbStore::open(&dir.path().join("t.db")).unwrap();
        assert_eq!(db.get_blame_cache("Acme", "Widgets", "src/a.rs", "b1"), None);
        db.put_blame_cache("Acme", "Widgets", "src/a.rs", "b1", "[1]");
        assert_eq!(db.get_blame_cache("acme", "widgets", "src/a.rs", "b1").as_deref(), Some("[1]"));
        assert_eq!(db.get_blame_cache("acme", "widgets", "src/a.rs", "b2"), None, "a changed blob is a miss");
        db.put_blame_cache("acme", "widgets", "src/a.rs", "b1", "[2]");
        assert_eq!(db.get_blame_cache("acme", "widgets", "src/a.rs", "b1").as_deref(), Some("[2]"));
        assert_eq!(db.prune_blame_cache(), 0, "fresh rows are kept");
    }
}
