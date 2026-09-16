//! US-06: safe, idempotent publication — `PublicationAttempt` persistence.
//!
//! `find_or_create_publication_attempt` is the entry point every publish
//! path (currently `routes/effectivate.rs`'s "Effectivate" endpoint, the
//! `PublishApprovedSnapshot` command this backlog describes) calls before
//! doing anything remote. It binds the attempt to the exact source digest
//! being published and, given an idempotency key, makes a retried request
//! resolve to the *same* attempt rather than re-provisioning/re-pushing —
//! "same key and payload returns the same run; conflicting payload
//! returns a conflict", the same contract US-04 already established for
//! `scan_runs.idempotency_key`. `record_publication_stage` is then called
//! before/after each remote side effect (`ignite-shipping`'s
//! `ship_to_github_tracked` invokes it via a callback) so a crash mid-ship
//! leaves a durable record of exactly how far publication got, instead of
//! only ever being reconstructable from GitHub's own state after the
//! fact.

use crate::store::DbStore;
use crate::types::{PublicationAttemptOutcome, PublicationAttemptRow};
use rusqlite::{params, OptionalExtension};

fn row_from(row: &rusqlite::Row) -> rusqlite::Result<PublicationAttemptRow> {
    Ok(PublicationAttemptRow {
        id: row.get(0)?,
        project_id: row.get(1)?,
        run_id: row.get(2)?,
        org: row.get(3)?,
        repo: row.get(4)?,
        source_digest: row.get(5)?,
        idempotency_key: row.get(6)?,
        stage: row.get(7)?,
        repo_url: row.get(8)?,
        commit_sha: row.get(9)?,
        pr_url: row.get(10)?,
        error: row.get(11)?,
        created_at: row.get(12)?,
        updated_at: row.get(13)?,
    })
}

const SELECT_COLUMNS: &str = "id, project_id, run_id, org, repo, source_digest, idempotency_key, stage, repo_url, commit_sha, pr_url, error, created_at, updated_at";

impl DbStore {
    /// Looks up a matching in-flight/completed attempt before creating a
    /// new one — by idempotency key first (when the caller supplied one),
    /// falling back to the source digest alone (so a retried request with
    /// no key still dedupes against the same snapshot rather than shipping
    /// it twice). See the module doc for the conflict/dedupe contract.
    pub fn find_or_create_publication_attempt(&self, project_id: i64, run_id: Option<i64>, org: &str, repo: &str, source_digest: &str, idempotency_key: Option<&str>) -> PublicationAttemptOutcome {
        let conn = self.conn.lock();

        if let Some(key) = idempotency_key {
            let existing: Option<PublicationAttemptRow> = conn
                .query_row(&format!("SELECT {SELECT_COLUMNS} FROM publication_attempts WHERE project_id = ? AND idempotency_key = ?"), params![project_id, key], row_from)
                .optional()
                .unwrap_or(None);
            if let Some(row) = existing {
                return if row.source_digest == source_digest { PublicationAttemptOutcome::Existing(row) } else { PublicationAttemptOutcome::Conflict { existing_digest: row.source_digest } };
            }
        } else if let Some(row) = conn
            .query_row(&format!("SELECT {SELECT_COLUMNS} FROM publication_attempts WHERE project_id = ? AND source_digest = ? ORDER BY id DESC LIMIT 1"), params![project_id, source_digest], row_from)
            .optional()
            .unwrap_or(None)
        {
            return PublicationAttemptOutcome::Existing(row);
        }

        if let Err(e) = conn.execute(
            "INSERT INTO publication_attempts (project_id, run_id, org, repo, source_digest, idempotency_key, stage) VALUES (?, ?, ?, ?, ?, ?, 'pending')",
            params![project_id, run_id, org, repo, source_digest, idempotency_key],
        ) {
            tracing::error!("find_or_create_publication_attempt({project_id}) failed to insert: {e}");
        }
        let id = conn.last_insert_rowid();
        match conn.query_row(&format!("SELECT {SELECT_COLUMNS} FROM publication_attempts WHERE id = ?"), params![id], row_from) {
            Ok(row) => PublicationAttemptOutcome::Created(row),
            Err(e) => {
                tracing::error!("find_or_create_publication_attempt({project_id}) failed to reload inserted row {id}: {e}");
                PublicationAttemptOutcome::Created(PublicationAttemptRow { id, project_id, run_id, org: org.to_string(), repo: repo.to_string(), source_digest: source_digest.to_string(), idempotency_key: idempotency_key.map(str::to_string), stage: "pending".to_string(), repo_url: None, commit_sha: None, pr_url: None, error: None, created_at: String::new(), updated_at: String::new() })
            }
        }
    }

    /// Records a stage transition, called immediately before/after each
    /// remote side effect a real publish performs. `repo_url`/`commit_sha`/
    /// `pr_url` are only ever widened (a `None` here keeps whatever was
    /// already recorded); `error` is set exactly as passed, so a
    /// successful later stage clears an earlier stage's transient error.
    pub fn record_publication_stage(&self, attempt_id: i64, stage: &str, repo_url: Option<&str>, commit_sha: Option<&str>, pr_url: Option<&str>, error: Option<&str>) {
        let conn = self.conn.lock();
        if let Err(e) = conn.execute(
            "UPDATE publication_attempts SET stage = ?, repo_url = COALESCE(?, repo_url), commit_sha = COALESCE(?, commit_sha), pr_url = COALESCE(?, pr_url), error = ?, updated_at = datetime('now') WHERE id = ?",
            params![stage, repo_url, commit_sha, pr_url, error, attempt_id],
        ) {
            tracing::error!("record_publication_stage({attempt_id}, {stage}) failed: {e}");
        }
    }

    pub fn get_publication_attempt(&self, attempt_id: i64) -> Option<PublicationAttemptRow> {
        let conn = self.conn.lock();
        conn.query_row(&format!("SELECT {SELECT_COLUMNS} FROM publication_attempts WHERE id = ?"), params![attempt_id], row_from).optional().unwrap_or(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_test_db() -> (DbStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = DbStore::open(&dir.path().join("test.db")).unwrap();
        (db, dir)
    }

    #[test]
    fn creates_a_new_pending_attempt() {
        let (db, _dir) = open_test_db();
        let project_id = db.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        let outcome = db.find_or_create_publication_attempt(project_id, None, "acme", "widgets", "sha256:abc", None);
        let PublicationAttemptOutcome::Created(row) = outcome else { panic!("expected Created") };
        assert_eq!(row.stage, "pending");
        assert_eq!(row.source_digest, "sha256:abc");
    }

    #[test]
    fn repeating_the_same_digest_with_no_key_returns_the_existing_attempt() {
        let (db, _dir) = open_test_db();
        let project_id = db.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        let PublicationAttemptOutcome::Created(first) = db.find_or_create_publication_attempt(project_id, None, "acme", "widgets", "sha256:abc", None) else { panic!() };
        db.record_publication_stage(first.id, "completed", Some("https://github.com/acme/widgets"), Some("deadbeef"), None, None);

        let outcome = db.find_or_create_publication_attempt(project_id, None, "acme", "widgets", "sha256:abc", None);
        let PublicationAttemptOutcome::Existing(row) = outcome else { panic!("expected Existing") };
        assert_eq!(row.id, first.id);
        assert_eq!(row.stage, "completed");
        assert_eq!(row.repo_url.as_deref(), Some("https://github.com/acme/widgets"));
    }

    #[test]
    fn a_different_digest_gets_its_own_attempt() {
        let (db, _dir) = open_test_db();
        let project_id = db.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        let PublicationAttemptOutcome::Created(first) = db.find_or_create_publication_attempt(project_id, None, "acme", "widgets", "sha256:abc", None) else { panic!() };
        let PublicationAttemptOutcome::Created(second) = db.find_or_create_publication_attempt(project_id, None, "acme", "widgets", "sha256:def", None) else { panic!("expected a second, distinct attempt") };
        assert_ne!(first.id, second.id);
    }

    #[test]
    fn same_idempotency_key_and_digest_returns_the_same_attempt() {
        let (db, _dir) = open_test_db();
        let project_id = db.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        let PublicationAttemptOutcome::Created(first) = db.find_or_create_publication_attempt(project_id, None, "acme", "widgets", "sha256:abc", Some("key-1")) else { panic!() };
        let outcome = db.find_or_create_publication_attempt(project_id, None, "acme", "widgets", "sha256:abc", Some("key-1"));
        let PublicationAttemptOutcome::Existing(row) = outcome else { panic!("expected Existing") };
        assert_eq!(row.id, first.id);
    }

    #[test]
    fn same_idempotency_key_with_a_different_digest_is_a_conflict() {
        let (db, _dir) = open_test_db();
        let project_id = db.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        let PublicationAttemptOutcome::Created(_) = db.find_or_create_publication_attempt(project_id, None, "acme", "widgets", "sha256:abc", Some("key-1")) else { panic!() };
        let outcome = db.find_or_create_publication_attempt(project_id, None, "acme", "widgets", "sha256:different", Some("key-1"));
        assert!(matches!(outcome, PublicationAttemptOutcome::Conflict { existing_digest } if existing_digest == "sha256:abc"));
    }

    #[test]
    fn record_publication_stage_preserves_fields_not_passed_this_call() {
        let (db, _dir) = open_test_db();
        let project_id = db.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        let PublicationAttemptOutcome::Created(attempt) = db.find_or_create_publication_attempt(project_id, None, "acme", "widgets", "sha256:abc", None) else { panic!() };

        db.record_publication_stage(attempt.id, "repo_resolved", Some("https://github.com/acme/widgets"), None, None, None);
        db.record_publication_stage(attempt.id, "pushed", None, Some("deadbeef"), None, None);

        let row = db.get_publication_attempt(attempt.id).unwrap();
        assert_eq!(row.stage, "pushed");
        assert_eq!(row.repo_url.as_deref(), Some("https://github.com/acme/widgets"), "an earlier stage's repo_url must survive a later stage's update");
        assert_eq!(row.commit_sha.as_deref(), Some("deadbeef"));
    }
}
