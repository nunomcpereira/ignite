//! Durable, tamper-evident local audit trail (GxP / 21 CFR Part 11
//! parity). `ignite-audit-log`'s SIEM sinks are opt-in and best-effort by
//! design (a SIEM outage must never affect a gate decision) — which means
//! a deployment with no sink configured, or one that's temporarily
//! unreachable, previously kept no record of its own governance events at
//! all. For a GxP onboarding case, "we streamed it to Splunk" isn't an
//! acceptable answer to "show me the audit trail for this scan": Ignite
//! itself has to hold a durable, complete record regardless of sink
//! config.
//!
//! This module is that record. `AppState::emit_audit_event` and
//! `create-api-key`'s blocking equivalent both call `record_audit_event`
//! unconditionally, before (and independently of) any sink dispatch — see
//! their own doc comments. Every scan's outcome is recorded too, via
//! `finish_project` (`projects.rs`) calling this directly, so "auditable
//! for all scans" holds even for a clean run that never touches
//! overrides/gates/webhooks.
//!
//! Rows are never deleted or edited by any code path in this crate —
//! there is no corresponding prune/delete function here, deliberately.
//! Each row is hash-chained to the one before it
//! (`sha256(prev_hash || event fields)`), so a row edited or removed
//! outside of Ignite's own code (e.g. direct `sqlite3` surgery on
//! `ignite.db`) is detectable via `verify_audit_chain` instead of being
//! silently invisible — the same tamper-evidence property GxP auditors
//! expect from a Part-11-style electronic record, without needing a
//! separate WORM store.

use crate::store::DbStore;
use crate::types::AuditEventRow;
use rusqlite::{params, OptionalExtension};
use sha2::{Digest, Sha256};

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000"; // 64 zeros — sha256's output length, standing in for "no previous row"

fn compute_hash(prev_hash: &str, event_type: &str, severity: &str, summary: &str, actor: Option<&str>, org: Option<&str>, repo: Option<&str>, metadata_json: Option<&str>, created_at: &str) -> String {
    let mut hasher = Sha256::new();
    for field in [prev_hash, event_type, severity, summary, actor.unwrap_or(""), org.unwrap_or(""), repo.unwrap_or(""), metadata_json.unwrap_or(""), created_at] {
        hasher.update(field.as_bytes());
        hasher.update(b"\x1f"); // unit separator, keeps fields from colliding at their boundaries
    }
    format!("{:x}", hasher.finalize())
}

impl DbStore {
    /// Persists one audit event, chaining it to the previous row's hash.
    /// Returns the inserted row id.
    ///
    /// This runs unconditionally on every scan completion, override, gate
    /// resolution, and API-key creation — a `.unwrap()`-triggered panic
    /// here on a transient I/O error (lock contention, disk quota) used
    /// to crash the whole server process and poison the shared connection
    /// mutex for every other in-flight request. `Err` now propagates so
    /// the caller can log and continue instead.
    #[allow(clippy::too_many_arguments)]
    pub fn record_audit_event(&self, event_type: &str, severity: &str, summary: &str, actor: Option<&str>, org: Option<&str>, repo: Option<&str>, metadata_json: Option<&str>) -> rusqlite::Result<i64> {
        let conn = self.conn.lock();
        let prev_hash: String = conn.query_row("SELECT hash FROM audit_events ORDER BY id DESC LIMIT 1", [], |row| row.get(0)).optional()?.unwrap_or_else(|| GENESIS_HASH.to_string());
        let created_at: String = conn.query_row("SELECT datetime('now')", [], |row| row.get(0))?;
        let hash = compute_hash(&prev_hash, event_type, severity, summary, actor, org, repo, metadata_json, &created_at);
        conn.execute(
            "INSERT INTO audit_events (event_type, severity, summary, actor, org, repo, metadata_json, created_at, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![event_type, severity, summary, actor, org, repo, metadata_json, created_at, prev_hash, hash],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Filtered/paginated read for `GET /api/audit-log`. Rows come back
    /// newest-first; pass a previous page's last row `id` as `cursor` to
    /// fetch the next page (`id < cursor`).
    #[allow(clippy::too_many_arguments)]
    pub fn list_audit_events(&self, org: Option<&str>, repo: Option<&str>, event_type: Option<&str>, severity: Option<&str>, from: Option<&str>, to: Option<&str>, cursor: Option<i64>, limit: i64) -> Vec<AuditEventRow> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare_cached(
                "SELECT id, event_type, severity, summary, actor, org, repo, metadata_json, created_at, prev_hash, hash
                 FROM audit_events
                 WHERE (?1 IS NULL OR org = ?1)
                   AND (?2 IS NULL OR repo = ?2)
                   AND (?3 IS NULL OR event_type = ?3)
                   AND (?4 IS NULL OR severity = ?4)
                   AND (?5 IS NULL OR created_at >= ?5)
                   AND (?6 IS NULL OR created_at <= ?6)
                   AND (?7 IS NULL OR id < ?7)
                 ORDER BY id DESC
                 LIMIT ?8",
            )
            .unwrap();
        stmt.query_map(params![org, repo, event_type, severity, from, to, cursor, limit], row_to_audit_event).unwrap().map(|r| r.unwrap()).collect()
    }

    /// Recomputes every row's hash from its stored fields and checks both
    /// that it matches the stored `hash` and that it chains correctly from
    /// the previous row's `hash`. Returns the id of the first row that
    /// fails either check, if any — `Ok(())` means the whole trail is
    /// intact from genesis to the newest row.
    pub fn verify_audit_chain(&self) -> Result<(), i64> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached("SELECT id, event_type, severity, summary, actor, org, repo, metadata_json, created_at, prev_hash, hash FROM audit_events ORDER BY id ASC").unwrap();
        let rows: Vec<AuditEventRow> = stmt.query_map([], row_to_audit_event).unwrap().map(|r| r.unwrap()).collect();

        let mut expected_prev = GENESIS_HASH.to_string();
        for row in &rows {
            if row.prev_hash != expected_prev {
                return Err(row.id);
            }
            let recomputed = compute_hash(&row.prev_hash, &row.event_type, &row.severity, &row.summary, row.actor.as_deref(), row.org.as_deref(), row.repo.as_deref(), row.metadata_json.as_deref(), &row.created_at);
            if recomputed != row.hash {
                return Err(row.id);
            }
            expected_prev = row.hash.clone();
        }
        Ok(())
    }
}

fn row_to_audit_event(row: &rusqlite::Row) -> rusqlite::Result<AuditEventRow> {
    Ok(AuditEventRow {
        id: row.get(0)?,
        event_type: row.get(1)?,
        severity: row.get(2)?,
        summary: row.get(3)?,
        actor: row.get(4)?,
        org: row.get(5)?,
        repo: row.get(6)?,
        metadata_json: row.get(7)?,
        created_at: row.get(8)?,
        prev_hash: row.get(9)?,
        hash: row.get(10)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> DbStore {
        let dir = tempfile::tempdir().unwrap();
        let db = DbStore::open(&dir.path().join("test.db")).unwrap();
        std::mem::forget(dir);
        db
    }

    #[test]
    fn first_event_chains_from_genesis() {
        let db = test_db();
        db.record_audit_event("scan.completed", "info", "clean scan", None, Some("acme"), Some("widgets"), None).unwrap();
        let events = db.list_audit_events(None, None, None, None, None, None, None, 10);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].prev_hash, GENESIS_HASH);
        assert!(db.verify_audit_chain().is_ok());
    }

    #[test]
    fn each_event_chains_to_the_previous_hash() {
        let db = test_db();
        db.record_audit_event("scan.completed", "info", "first", None, None, None, None).unwrap();
        db.record_audit_event("scan.completed", "info", "second", None, None, None, None).unwrap();
        let events = db.list_audit_events(None, None, None, None, None, None, None, 10);
        // newest-first
        assert_eq!(events[0].summary, "second");
        assert_eq!(events[0].prev_hash, events[1].hash);
        assert!(db.verify_audit_chain().is_ok());
    }

    #[test]
    fn tampering_with_a_row_breaks_verification() {
        let db = test_db();
        db.record_audit_event("scan.completed", "info", "first", None, None, None, None).unwrap();
        db.record_audit_event("scan.completed", "info", "second", None, None, None, None).unwrap();
        {
            let conn = db.conn.lock();
            conn.execute("UPDATE audit_events SET summary = 'tampered' WHERE summary = 'first'", []).unwrap();
        }
        assert!(db.verify_audit_chain().is_err());
    }

    #[test]
    fn filters_by_org_and_event_type() {
        let db = test_db();
        db.record_audit_event("gate.push_rejected", "critical", "blocked", None, Some("acme"), Some("widgets"), None).unwrap();
        db.record_audit_event("scan.completed", "info", "clean", None, Some("other"), Some("thing"), None).unwrap();
        let filtered = db.list_audit_events(Some("acme"), None, Some("gate.push_rejected"), None, None, None, None, 10);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].summary, "blocked");
    }
}
