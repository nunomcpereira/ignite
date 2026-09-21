//! Start-then-poll runs: `POST /api/pipeline/onboard|validate-all` with
//! `async: true` returns a job id at once and the finished response is
//! stored here for `GET /api/pipeline/:jobId/async-result`. `impl DbStore`
//! block, one of several per-domain files (see `lib.rs`'s module list).

use crate::store::DbStore;
use rusqlite::{params, OptionalExtension};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsyncJobRow {
    pub job_id: String,
    pub kind: String,
    /// `None` for a job started without authentication.
    pub owner_user_id: Option<i64>,
    /// `running`, `done` or `failed` (the run itself was lost, e.g. a restart).
    pub state: String,
    /// The HTTP status the equivalent synchronous call would have returned.
    pub http_status: Option<i64>,
    /// The response body, serialized JSON.
    pub result_json: Option<String>,
}

impl DbStore {
    pub fn create_async_job(&self, job_id: &str, kind: &str, owner_user_id: Option<i64>) {
        let conn = self.conn.lock();
        if let Err(e) = conn.execute("INSERT INTO async_jobs (job_id, kind, owner_user_id) VALUES (?, ?, ?)", params![job_id, kind, owner_user_id]) {
            tracing::error!("create_async_job({job_id}) failed: {e}");
        }
    }

    /// Records the finished response. Only a still-`running` job is updated,
    /// so a late finish can't overwrite a result already recorded (e.g. by the
    /// startup sweep).
    pub fn finish_async_job(&self, job_id: &str, http_status: u16, result_json: &str) {
        let conn = self.conn.lock();
        if let Err(e) = conn.execute(
            "UPDATE async_jobs SET state = 'done', http_status = ?, result_json = ?, finished_at = datetime('now') WHERE job_id = ? AND state = 'running'",
            params![http_status as i64, result_json, job_id],
        ) {
            tracing::error!("finish_async_job({job_id}) failed: {e}");
        }
    }

    pub fn get_async_job(&self, job_id: &str) -> Option<AsyncJobRow> {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT job_id, kind, owner_user_id, state, http_status, result_json FROM async_jobs WHERE job_id = ?",
            params![job_id],
            |row| Ok(AsyncJobRow { job_id: row.get(0)?, kind: row.get(1)?, owner_user_id: row.get(2)?, state: row.get(3)?, http_status: row.get(4)?, result_json: row.get(5)? }),
        )
        .optional()
        .unwrap_or(None)
    }

    /// Server startup: a job still `running` belongs to a process that no
    /// longer exists, so it will never finish. Marks each `failed` with an
    /// explicit result instead of leaving a poller waiting forever, and drops
    /// finished jobs older than `keep_days`. Returns how many were failed.
    pub fn fail_unfinished_async_jobs(&self, keep_days: i64) -> usize {
        let conn = self.conn.lock();
        let failed = conn
            .execute(
                "UPDATE async_jobs SET state = 'failed', http_status = 500, finished_at = datetime('now'),
                        result_json = '{\"ok\":false,\"error\":\"The Ignite server restarted while this run was in progress, so it was lost. Re-run it (with the same idempotencyKey, the earlier run is reported instead of a duplicate being started).\",\"code\":\"server_restarted\"}'
                 WHERE state = 'running'",
                [],
            )
            .unwrap_or(0);
        if let Err(e) = conn.execute("DELETE FROM async_jobs WHERE state != 'running' AND created_at < datetime('now', ?)", params![format!("-{keep_days} days")]) {
            tracing::error!("async_jobs prune failed: {e}");
        }
        failed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_test_db() -> (DbStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        (DbStore::open(&dir.path().join("test.db")).unwrap(), dir)
    }

    #[test]
    fn a_job_runs_then_records_its_result_once() {
        let (db, _dir) = open_test_db();
        db.create_async_job("job-1", "onboard", Some(7));
        let running = db.get_async_job("job-1").unwrap();
        assert_eq!((running.state.as_str(), running.owner_user_id, running.http_status), ("running", Some(7), None));

        db.finish_async_job("job-1", 200, r#"{"ok":true}"#);
        let done = db.get_async_job("job-1").unwrap();
        assert_eq!((done.state.as_str(), done.http_status, done.result_json.as_deref()), ("done", Some(200), Some(r#"{"ok":true}"#)));

        db.finish_async_job("job-1", 500, r#"{"ok":false}"#);
        assert_eq!(db.get_async_job("job-1").unwrap().result_json.as_deref(), Some(r#"{"ok":true}"#), "a recorded result is never overwritten");
        assert!(db.get_async_job("nope").is_none());
    }

    #[test]
    fn a_restart_fails_running_jobs_with_an_explicit_result_and_keeps_finished_ones() {
        let (db, _dir) = open_test_db();
        db.create_async_job("lost", "validate-all", None);
        db.create_async_job("finished", "validate-all", None);
        db.finish_async_job("finished", 200, r#"{"ok":true}"#);

        assert_eq!(db.fail_unfinished_async_jobs(7), 1);
        let lost = db.get_async_job("lost").unwrap();
        assert_eq!((lost.state.as_str(), lost.http_status), ("failed", Some(500)));
        let body: serde_json::Value = serde_json::from_str(lost.result_json.as_deref().unwrap()).unwrap();
        assert_eq!(body["code"], "server_restarted");
        assert_eq!(db.get_async_job("finished").unwrap().state, "done");

        // A finish arriving from the dead run's task can't resurrect it.
        db.finish_async_job("lost", 200, r#"{"ok":true}"#);
        assert_eq!(db.get_async_job("lost").unwrap().state, "failed");
    }

    #[test]
    fn old_finished_jobs_are_pruned() {
        let (db, _dir) = open_test_db();
        db.create_async_job("old", "onboard", None);
        db.finish_async_job("old", 200, "{}");
        {
            let conn = db.conn.lock();
            conn.execute("UPDATE async_jobs SET created_at = datetime('now', '-30 days') WHERE job_id = 'old'", []).unwrap();
        }
        db.fail_unfinished_async_jobs(7);
        assert!(db.get_async_job("old").is_none());
    }
}
