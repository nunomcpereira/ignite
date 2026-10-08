//! `scheduler_runs` — last run of each in-process periodic job, so a job
//! runs once per interval across restarts and across server processes
//! sharing this database.

use crate::store::DbStore;
use rusqlite::{params, OptionalExtension};

impl DbStore {
    /// Claims this interval's run of `name` for `owner`: succeeds (and
    /// records now as the last run) only when the job never ran or last
    /// ran at least `interval_secs` ago. Atomic, so two processes ticking
    /// at once can't both win.
    pub fn try_claim_scheduler_run(&self, name: &str, owner: &str, interval_secs: i64) -> bool {
        let conn = self.conn.lock();
        let modifier = format!("-{interval_secs} seconds");
        let n = conn
            .execute(
                "INSERT INTO scheduler_runs (name, last_run_at, owner) VALUES (?1, datetime('now'), ?2)
                 ON CONFLICT(name) DO UPDATE SET last_run_at = datetime('now'), owner = excluded.owner
                 WHERE scheduler_runs.last_run_at <= datetime('now', ?3)",
                params![name, owner, modifier],
            )
            .unwrap();
        n > 0
    }

    /// UTC `YYYY-MM-DD HH:MM:SS` of `name`'s last claimed run.
    pub fn get_scheduler_last_run(&self, name: &str) -> Option<String> {
        let conn = self.conn.lock();
        conn.query_row("SELECT last_run_at FROM scheduler_runs WHERE name = ?", params![name], |row| row.get(0)).optional().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use crate::store::DbStore;

    #[test]
    fn a_run_is_claimed_once_per_interval() {
        let dir = tempfile::tempdir().unwrap();
        let db = DbStore::open(&dir.path().join("t.db")).unwrap();
        assert!(db.get_scheduler_last_run("job").is_none());
        assert!(db.try_claim_scheduler_run("job", "a", 3600));
        assert!(!db.try_claim_scheduler_run("job", "b", 3600), "second claim within the interval loses");
        assert!(db.get_scheduler_last_run("job").is_some());
        assert!(db.try_claim_scheduler_run("job", "b", 0), "interval elapsed: claim succeeds again");
        assert!(db.try_claim_scheduler_run("other", "a", 3600), "jobs are independent");
    }
}
