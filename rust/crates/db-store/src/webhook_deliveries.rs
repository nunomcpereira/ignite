//! Durable replay-dedup for inbound GitHub webhooks. GitHub's HMAC scheme
//! carries no timestamp or nonce, so tracking `X-GitHub-Delivery` ids is the
//! only defense against a captured, validly-signed payload being replayed —
//! and that tracking has to survive a server restart (deploy, crash, OOM
//! kill) or a restart re-opens the entire dedup window for every delivery
//! received before it.

use crate::store::DbStore;
use rusqlite::params;

impl DbStore {
    /// `true` the first time `delivery_id` is seen (caller should process
    /// the webhook); `false` on every subsequent call with the same id, or
    /// on a DB error (fails closed — a delivery that can't be recorded as
    /// seen is treated as unsafe to process rather than silently let
    /// through).
    pub fn record_webhook_delivery_once(&self, delivery_id: &str) -> bool {
        if delivery_id.is_empty() {
            // No `X-GitHub-Delivery` header at all (a hand-crafted request)
            // — nothing to dedup against, so treat it as not-safe-to-process
            // rather than silently bypassing replay protection.
            return false;
        }
        let conn = self.conn.lock();
        match conn.execute("INSERT OR IGNORE INTO webhook_deliveries (delivery_id) VALUES (?)", params![delivery_id]) {
            Ok(rows_affected) => rows_affected > 0,
            Err(e) => {
                tracing::warn!(error = %e, "failed to record webhook delivery id, rejecting to be safe");
                false
            }
        }
    }

    /// Prunes delivery ids older than `window_days` — called opportunistically
    /// by callers of `record_webhook_delivery_once` so the table doesn't grow
    /// unbounded, without needing a separate scheduled job.
    pub fn prune_old_webhook_deliveries(&self, window_days: i64) -> usize {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM webhook_deliveries WHERE seen_at < datetime('now', ?)", params![format!("-{window_days} days")]).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "failed to prune webhook_deliveries");
            0
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_db() -> DbStore {
        let dir = tempdir().unwrap();
        let db = DbStore::open(&dir.path().join("test.db")).unwrap();
        std::mem::forget(dir);
        db
    }

    #[test]
    fn first_delivery_is_recorded_second_is_rejected() {
        let db = test_db();
        assert!(db.record_webhook_delivery_once("abc-123"));
        assert!(!db.record_webhook_delivery_once("abc-123"));
    }

    #[test]
    fn distinct_deliveries_are_independent() {
        let db = test_db();
        assert!(db.record_webhook_delivery_once("id-1"));
        assert!(db.record_webhook_delivery_once("id-2"));
    }

    #[test]
    fn dedup_survives_a_reopen_of_the_same_db_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.db");
        {
            let db = DbStore::open(&path).unwrap();
            assert!(db.record_webhook_delivery_once("replayed-id"));
        }
        let reopened = DbStore::open(&path).unwrap();
        assert!(!reopened.record_webhook_delivery_once("replayed-id"), "a restart must not reset the dedup window");
    }

    #[test]
    fn prune_removes_only_old_rows() {
        let db = test_db();
        db.record_webhook_delivery_once("fresh");
        {
            let conn = db.conn.lock();
            conn.execute("UPDATE webhook_deliveries SET seen_at = datetime('now', '-30 days') WHERE delivery_id = 'fresh'", []).unwrap();
            conn.execute("INSERT INTO webhook_deliveries (delivery_id) VALUES ('recent')", []).unwrap();
        }
        let pruned = db.prune_old_webhook_deliveries(1);
        assert_eq!(pruned, 1);
        assert!(!db.record_webhook_delivery_once("recent"), "recent row must survive the prune");
        assert!(db.record_webhook_delivery_once("fresh"), "pruned id must be treated as new again");
    }
}
