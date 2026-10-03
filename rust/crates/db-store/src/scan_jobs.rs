//! US-18: the durable side of the server-wide scan queue
//! (`ignite-server`'s `routes/scan_queue.rs`). Every queue entry is mirrored
//! here, so a restart can tell what was waiting or running and re-queue the
//! work that can run again without its original client.
//!
//! A claim is a lease (`lease_owner` = the server process instance,
//! `lease_expires_at` kept fresh by a heartbeat) plus a fencing token
//! (`attempt`, bumped on every claim). Every finish is conditional on the
//! attempt the caller claimed, so a stale worker — one whose lease expired
//! and whose job was re-queued and claimed again — can never overwrite the
//! newer attempt's outcome.

use crate::store::DbStore;
use rusqlite::{params, OptionalExtension};

/// One `scan_jobs` row.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanJobRow {
    pub id: String,
    /// `org_scan`, `validate_all`, `onboard` or `upload`.
    pub kind: String,
    /// `user` or `background`.
    pub lane: String,
    pub org: Option<String>,
    pub repo: Option<String>,
    pub source: String,
    pub actor: Option<String>,
    /// What's needed to run it again (never a credential); `None` when the
    /// job can only run with its original client attached.
    pub payload_json: Option<String>,
    /// `waiting`, `running`, `done`, `failed` or `removed`.
    pub state: String,
    pub seq: i64,
    pub attempt: i64,
    pub lease_owner: Option<String>,
    pub restarts: i64,
    pub last_error: Option<String>,
}

pub struct NewScanJob<'a> {
    pub id: &'a str,
    pub kind: &'a str,
    pub lane: &'a str,
    pub org: Option<&'a str>,
    pub repo: Option<&'a str>,
    pub source: &'a str,
    pub actor: Option<&'a str>,
    pub payload_json: Option<&'a str>,
    pub seq: i64,
}

const COLUMNS: &str = "id, kind, lane, org, repo, source, actor, payload_json, state, seq, attempt, lease_owner, restarts, last_error";

fn row_from(r: &rusqlite::Row) -> rusqlite::Result<ScanJobRow> {
    Ok(ScanJobRow {
        id: r.get(0)?,
        kind: r.get(1)?,
        lane: r.get(2)?,
        org: r.get(3)?,
        repo: r.get(4)?,
        source: r.get(5)?,
        actor: r.get(6)?,
        payload_json: r.get(7)?,
        state: r.get(8)?,
        seq: r.get(9)?,
        attempt: r.get(10)?,
        lease_owner: r.get(11)?,
        restarts: r.get(12)?,
        last_error: r.get(13)?,
    })
}

impl DbStore {
    pub fn insert_scan_job(&self, job: &NewScanJob<'_>) {
        let conn = self.conn.lock();
        if let Err(e) = conn.execute(
            "INSERT INTO scan_jobs (id, kind, lane, org, repo, source, actor, payload_json, state, seq) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'waiting', ?)",
            params![job.id, job.kind, job.lane, job.org, job.repo, job.source, job.actor, job.payload_json, job.seq],
        ) {
            tracing::error!("insert_scan_job({}) failed: {e}", job.id);
        }
    }

    pub fn get_scan_job(&self, id: &str) -> Option<ScanJobRow> {
        let conn = self.conn.lock();
        conn.query_row(&format!("SELECT {COLUMNS} FROM scan_jobs WHERE id = ?"), params![id], row_from).optional().unwrap_or(None)
    }

    /// Persists a waiting entry's position within its lane.
    pub fn set_scan_job_seq(&self, id: &str, seq: i64) {
        let conn = self.conn.lock();
        let _ = conn.execute("UPDATE scan_jobs SET seq = ? WHERE id = ? AND state = 'waiting'", params![seq, id]);
    }

    /// Claims a waiting job for `owner` with a lease of `ttl_secs`. Returns
    /// the new attempt number (the fencing token), or `None` when the job
    /// isn't waiting any more.
    pub fn claim_scan_job(&self, id: &str, owner: &str, ttl_secs: i64) -> Option<i64> {
        let conn = self.conn.lock();
        conn.query_row(
            "UPDATE scan_jobs SET state = 'running', attempt = attempt + 1, lease_owner = ?, lease_expires_at = datetime('now', ?), started_at = datetime('now')
             WHERE id = ? AND state = 'waiting' RETURNING attempt",
            params![owner, format!("+{ttl_secs} seconds"), id],
            |r| r.get(0),
        )
        .optional()
        .unwrap_or(None)
    }

    /// Extends the lease of every job `owner` is running. Returns how many.
    pub fn heartbeat_scan_jobs(&self, owner: &str, ttl_secs: i64) -> usize {
        let conn = self.conn.lock();
        conn.execute("UPDATE scan_jobs SET lease_expires_at = datetime('now', ?) WHERE state = 'running' AND lease_owner = ?", params![format!("+{ttl_secs} seconds"), owner]).unwrap_or(0)
    }

    /// Records the outcome of `attempt`. `false` when the job has since been
    /// re-claimed (a newer attempt exists) — the stale write is rejected.
    pub fn finish_scan_job(&self, id: &str, attempt: i64, state: &str, error: Option<&str>) -> bool {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE scan_jobs SET state = ?, last_error = ?, finished_at = datetime('now'), lease_owner = NULL, lease_expires_at = NULL WHERE id = ? AND attempt = ? AND state = 'running'",
            params![state, error, id, attempt],
        )
        .map(|n| n == 1)
        .unwrap_or(false)
    }

    /// A waiting job taken out of the queue (or one that can't run again).
    pub fn close_waiting_scan_job(&self, id: &str, state: &str, error: Option<&str>) {
        let conn = self.conn.lock();
        let _ = conn.execute("UPDATE scan_jobs SET state = ?, last_error = ?, finished_at = datetime('now') WHERE id = ? AND state = 'waiting'", params![state, error, id]);
    }

    /// Startup/reaper: running jobs whose lease has expired or belongs to
    /// another (dead) process instance go back to `waiting`, counting the
    /// restart. Returns the re-queued ids.
    pub fn requeue_orphaned_scan_jobs(&self, current_owner: &str, startup: bool) -> Vec<String> {
        let conn = self.conn.lock();
        let sql = if startup {
            "UPDATE scan_jobs SET state = 'waiting', restarts = restarts + 1, lease_owner = NULL, lease_expires_at = NULL
             WHERE state = 'running' AND (lease_owner IS NULL OR lease_owner != ?1 OR lease_expires_at < datetime('now')) RETURNING id"
        } else {
            "UPDATE scan_jobs SET state = 'waiting', restarts = restarts + 1, lease_owner = NULL, lease_expires_at = NULL
             WHERE state = 'running' AND lease_owner != ?1 AND lease_expires_at < datetime('now') RETURNING id"
        };
        let Ok(mut stmt) = conn.prepare(sql) else { return vec![] };
        stmt.query_map(params![current_owner], |r| r.get(0)).map(|rows| rows.filter_map(|r| r.ok()).collect()).unwrap_or_default()
    }

    /// Every waiting job, user lane first, each lane in queue order.
    pub fn list_waiting_scan_jobs(&self) -> Vec<ScanJobRow> {
        let conn = self.conn.lock();
        let Ok(mut stmt) = conn.prepare(&format!("SELECT {COLUMNS} FROM scan_jobs WHERE state = 'waiting' ORDER BY CASE lane WHEN 'user' THEN 0 ELSE 1 END, seq, enqueued_at")) else { return vec![] };
        stmt.query_map([], row_from).map(|rows| rows.filter_map(|r| r.ok()).collect()).unwrap_or_default()
    }

    /// Drops finished jobs older than `keep_days`.
    pub fn prune_scan_jobs(&self, keep_days: i64) {
        let conn = self.conn.lock();
        let _ = conn.execute("DELETE FROM scan_jobs WHERE state IN ('done', 'failed', 'removed') AND finished_at < datetime('now', ?)", params![format!("-{keep_days} days")]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_test_db() -> (DbStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        (DbStore::open(&dir.path().join("t.db")).unwrap(), dir)
    }

    fn job<'a>(id: &'a str, lane: &'a str, seq: i64) -> NewScanJob<'a> {
        NewScanJob { id, kind: "org_scan", lane, org: Some("acme"), repo: Some(id), source: "scan-all", actor: None, payload_json: Some("{}"), seq }
    }

    #[test]
    fn a_stale_worker_cannot_overwrite_a_newer_attempt() {
        let (db, _d) = open_test_db();
        db.insert_scan_job(&job("a", "background", 1));
        let first = db.claim_scan_job("a", "dead-process", 60).unwrap();
        assert_eq!(first, 1);
        assert!(db.claim_scan_job("a", "other", 60).is_none(), "a running job can't be claimed twice");

        // The process dies; the next one re-queues and claims it again.
        assert_eq!(db.requeue_orphaned_scan_jobs("new-process", true), vec!["a".to_string()]);
        let second = db.claim_scan_job("a", "new-process", 60).unwrap();
        assert_eq!(second, 2);
        assert!(!db.finish_scan_job("a", first, "done", None), "the stale attempt's write is rejected");
        assert!(db.finish_scan_job("a", second, "done", None));
        let row = db.get_scan_job("a").unwrap();
        assert_eq!((row.state.as_str(), row.restarts), ("done", 1));
    }

    #[test]
    fn waiting_order_and_lanes_survive_and_only_expired_foreign_leases_are_reaped() {
        let (db, _d) = open_test_db();
        db.insert_scan_job(&job("bg1", "background", 1));
        db.insert_scan_job(&job("u2", "user", 2));
        db.insert_scan_job(&job("u1", "user", 1));
        db.set_scan_job_seq("u1", 0);
        let order: Vec<String> = db.list_waiting_scan_jobs().into_iter().map(|j| j.id).collect();
        assert_eq!(order, vec!["u1", "u2", "bg1"]);

        db.claim_scan_job("u1", "me", 60).unwrap();
        db.claim_scan_job("u2", "someone-else", 60).unwrap();
        assert!(db.requeue_orphaned_scan_jobs("me", false).is_empty(), "live leases are left alone");
        assert_eq!(db.heartbeat_scan_jobs("me", 60), 1);

        db.close_waiting_scan_job("bg1", "removed", None);
        assert!(db.list_waiting_scan_jobs().is_empty());
    }
}
