//! US-05: real content-addressed snapshot digests, the persisted evidence
//! manifest, and bounded snapshot leases — `impl DbStore` block, one of
//! several per-domain files (see `lib.rs`'s module list).

use crate::store::DbStore;
use crate::types::{RetainedSourceRow, SnapshotLeaseRow};
use rusqlite::{params, OptionalExtension};

impl DbStore {
    /// Re-points a scan run's snapshot at the *real* content-addressed
    /// digest, once one is computable (after staging, when the actual
    /// source tree exists on disk) — `create_project` itself can only
    /// ever record a synthetic `unknown:project:<id>` placeholder,
    /// because at Phase 1 nothing has been staged yet. Reuses
    /// `create_or_reuse_snapshot`'s existing dedup: two scans of
    /// byte-and-mode-identical source share one `source_snapshots` row,
    /// which is what makes US-01's "two scans of the same repository...
    /// or a safely deduplicated identical snapshot" acceptance criterion
    /// actually true instead of aspirational. Marks the new/reused
    /// snapshot `active` — real, on-disk-backed content, not a legacy
    /// placeholder.
    pub fn finalize_scan_run_snapshot(&self, run_id: i64, repository_id: i64, source_digest: &str, commit_sha: Option<&str>) -> i64 {
        let snapshot_id = self.create_or_reuse_snapshot(repository_id, source_digest, commit_sha, None);
        let conn = self.conn.lock();
        if let Err(e) = conn.execute("UPDATE source_snapshots SET retention_state = 'active' WHERE id = ?", params![snapshot_id]) {
            tracing::error!("finalize_scan_run_snapshot: failed to mark snapshot {snapshot_id} active: {e}");
        }
        if let Err(e) = conn.execute("UPDATE scan_runs SET snapshot_id = ? WHERE id = ?", params![snapshot_id, run_id]) {
            tracing::error!("finalize_scan_run_snapshot({run_id}) failed to update snapshot pointer: {e}");
        }
        snapshot_id
    }

    pub fn save_evidence_manifest(&self, run_id: i64, manifest_json: &str) {
        let conn = self.conn.lock();
        if let Err(e) = conn.execute(
            "INSERT INTO evidence_manifests (run_id, manifest_json) VALUES (?, ?)
             ON CONFLICT(run_id) DO UPDATE SET manifest_json = excluded.manifest_json, created_at = datetime('now')",
            params![run_id, manifest_json],
        ) {
            tracing::error!("save_evidence_manifest({run_id}) failed: {e}");
        }
    }

    /// Called on a Studio edit (`routes/studio.rs`'s `put_file`) — the
    /// manifest's `sourceDigest` described the pre-edit tree, so it must
    /// not be readable as still-current evidence for the edited one.
    pub fn delete_evidence_manifest(&self, run_id: i64) {
        let conn = self.conn.lock();
        if let Err(e) = conn.execute("DELETE FROM evidence_manifests WHERE run_id = ?", params![run_id]) {
            tracing::error!("delete_evidence_manifest({run_id}) failed: {e}");
        }
    }

    pub fn get_evidence_manifest(&self, run_id: i64) -> Option<String> {
        let conn = self.conn.lock();
        conn.query_row("SELECT manifest_json FROM evidence_manifests WHERE run_id = ?", params![run_id], |r| r.get(0)).optional().unwrap_or(None)
    }

    /// Pins a project's retained source directory against the retention
    /// sweeper for `ttl_hours` from now — set when a run enters review or
    /// becomes an un-shipped pending effectivation, so "active work"
    /// always means a bounded, visible window, not an indefinite implicit
    /// hold. Replaces any prior lease for the same project outright (the
    /// newest reason for holding the source wins; leases don't stack).
    /// The expiry is computed in SQL (`datetime('now', '+N hours')`)
    /// rather than formatted in Rust and passed in, so it's always in the
    /// exact `YYYY-MM-DD HH:MM:SS` shape SQLite's own `datetime('now')`
    /// produces — the two must compare correctly as plain text wherever a
    /// lease's freshness is checked ([`Self::get_active_snapshot_lease`],
    /// the retention sweeper's own query), and mixing that with a
    /// Rust-formatted ISO-8601 string (`T` separator, `Z` suffix) would
    /// silently break lexicographic comparison.
    pub fn set_snapshot_lease(&self, project_id: i64, reason: &str, ttl_hours: i64) {
        let conn = self.conn.lock();
        // `{:+}` so a negative `ttl_hours` (a test setting a
        // deliberately-already-expired lease, without needing direct SQL
        // access) formats as `-N hours`, not the SQLite-invalid `+-N
        // hours` a bare `+{ttl_hours}` interpolation would produce.
        if let Err(e) = conn.execute(
            "INSERT INTO snapshot_leases (project_id, reason, expires_at) VALUES (?, ?, datetime('now', ?))
             ON CONFLICT(project_id) DO UPDATE SET reason = excluded.reason, expires_at = excluded.expires_at, created_at = datetime('now')",
            params![project_id, reason, format!("{ttl_hours:+} hours")],
        ) {
            tracing::error!("set_snapshot_lease({project_id}) failed: {e}");
        }
    }

    pub fn clear_snapshot_lease(&self, project_id: i64) {
        let conn = self.conn.lock();
        if let Err(e) = conn.execute("DELETE FROM snapshot_leases WHERE project_id = ?", params![project_id]) {
            tracing::error!("clear_snapshot_lease({project_id}) failed: {e}");
        }
    }

    /// `None` when no lease row exists *or* it has already expired
    /// (compared in SQL against `datetime('now')` so the caller never
    /// needs its own clock to answer "is this still active") — a
    /// stale/expired lease row is inert, not a permanent hold.
    pub fn get_active_snapshot_lease(&self, project_id: i64) -> Option<SnapshotLeaseRow> {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT project_id, reason, expires_at, created_at FROM snapshot_leases WHERE project_id = ? AND expires_at > datetime('now')",
            params![project_id],
            |row| Ok(SnapshotLeaseRow { project_id: row.get(0)?, reason: row.get(1)?, expires_at: row.get(2)?, created_at: row.get(3)? }),
        )
        .optional()
        .unwrap_or(None)
    }

    /// Every `retained_sources` project id with no currently-active
    /// lease — the retention sweeper's own "safe to consider for
    /// eviction" candidate set. Expired/absent leases are excluded from
    /// the join automatically by the same `expires_at > datetime('now')`
    /// condition [`Self::get_active_snapshot_lease`] uses.
    pub fn list_unleased_retained_project_ids(&self) -> Vec<i64> {
        let conn = self.conn.lock();
        let Ok(mut stmt) = conn.prepare_cached(
            "SELECT rs.project_id FROM retained_sources rs
             WHERE NOT EXISTS (SELECT 1 FROM snapshot_leases sl WHERE sl.project_id = rs.project_id AND sl.expires_at > datetime('now'))",
        ) else {
            return vec![];
        };
        stmt.query_map([], |row| row.get(0)).map(|rows| rows.filter_map(|r| r.ok()).collect()).unwrap_or_default()
    }

    /// The retention sweeper's actual eviction candidate set: retained
    /// longer than `max_age_days` *and* currently unleased — combines
    /// [`Self::list_unleased_retained_project_ids`]'s lease check with an
    /// age filter in one query rather than two round trips. The SQLite
    /// modifier is built as `-max_age_days` (signed) rather than a bare
    /// `-{max_age_days}` interpolation so a caller can pass a *negative*
    /// `max_age_days` to mean "cutoff is in the future" — every currently
    /// retained row counts as expired regardless of how recently it was
    /// retained, which is what makes this testable without needing to
    /// backdate a row's `retained_at` from outside this crate.
    pub fn list_expired_unleased_retained_sources(&self, max_age_days: i64) -> Vec<RetainedSourceRow> {
        let conn = self.conn.lock();
        let Ok(mut stmt) = conn.prepare_cached(
            "SELECT rs.project_id, rs.dir_path, rs.tier FROM retained_sources rs
             WHERE rs.retained_at < datetime('now', ?)
             AND NOT EXISTS (SELECT 1 FROM snapshot_leases sl WHERE sl.project_id = rs.project_id AND sl.expires_at > datetime('now'))",
        ) else {
            return vec![];
        };
        stmt.query_map(params![format!("{:+} days", -max_age_days)], |row| Ok(RetainedSourceRow { project_id: row.get(0)?, dir_path: row.get(1)?, tier: row.get(2)? }))
            .map(|rows| rows.filter_map(|r| r.ok()).collect())
            .unwrap_or_default()
    }

    pub fn mark_snapshot_retention_state(&self, run_id: i64, state: &str) {
        let conn = self.conn.lock();
        if let Err(e) = conn.execute(
            "UPDATE source_snapshots SET retention_state = ? WHERE id = (SELECT snapshot_id FROM scan_runs WHERE id = ?)",
            params![state, run_id],
        ) {
            tracing::error!("mark_snapshot_retention_state({run_id}, {state}) failed: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::store::DbStore;

    fn open_test_db() -> (DbStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = DbStore::open(&dir.path().join("test.db")).unwrap();
        (db, dir)
    }

    #[test]
    fn finalize_scan_run_snapshot_dedups_identical_digests_across_runs() {
        let (db, _dir) = open_test_db();
        let p1 = db.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        let p2 = db.create_project("job-2", "acme", "widgets", false, "ui", None).unwrap();
        let run1 = db.get_scan_run_for_legacy_project(p1).unwrap();
        let run2 = db.get_scan_run_for_legacy_project(p2).unwrap();
        let repository_id = db.get_repository_by_org_repo("acme", "widgets").unwrap().id;

        let snap1 = db.finalize_scan_run_snapshot(run1.id, repository_id, "sha256:deadbeef", Some("abc123"));
        let snap2 = db.finalize_scan_run_snapshot(run2.id, repository_id, "sha256:deadbeef", Some("abc123"));
        assert_eq!(snap1, snap2, "two scans of byte-identical source must share one snapshot row");
    }

    #[test]
    fn evidence_manifest_round_trips() {
        let (db, _dir) = open_test_db();
        let project_id = db.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        let run_id = db.get_scan_run_for_legacy_project(project_id).unwrap().id;

        assert!(db.get_evidence_manifest(run_id).is_none());
        db.save_evidence_manifest(run_id, "{\"sourceDigest\":\"sha256:abc\"}");
        assert_eq!(db.get_evidence_manifest(run_id).as_deref(), Some("{\"sourceDigest\":\"sha256:abc\"}"));
    }

    #[test]
    fn snapshot_lease_expiry_makes_it_inactive() {
        let (db, _dir) = open_test_db();
        let project_id = db.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();

        assert!(db.get_active_snapshot_lease(project_id).is_none());
        db.set_snapshot_lease(project_id, "review", 24);
        let lease = db.get_active_snapshot_lease(project_id).unwrap();
        assert_eq!(lease.reason, "review");

        db.set_snapshot_lease(project_id, "review", -24);
        assert!(db.get_active_snapshot_lease(project_id).is_none(), "an expired lease must not read as active");
    }

    #[test]
    fn list_expired_unleased_retained_sources_excludes_leased_and_fresh_rows() {
        let (db, _dir) = open_test_db();
        let p1 = db.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        let p2 = db.create_project("job-2", "acme", "gadgets", false, "ui", None).unwrap();
        let p3 = db.create_project("job-3", "acme", "gizmos", false, "ui", None).unwrap();
        db.retain_project_source(p1, "/tmp/does-not-matter-1", "full"); // fresh, unleased
        db.retain_project_source(p2, "/tmp/does-not-matter-2", "full"); // old, unleased -> candidate
        db.retain_project_source(p3, "/tmp/does-not-matter-3", "full"); // old, leased -> excluded
        {
            let conn = db.conn.lock();
            conn.execute("UPDATE retained_sources SET retained_at = datetime('now', '-100 days') WHERE project_id IN (?, ?)", rusqlite::params![p2, p3]).unwrap();
        }
        db.set_snapshot_lease(p3, "review", 24);

        let candidates: Vec<i64> = db.list_expired_unleased_retained_sources(90).into_iter().map(|r| r.project_id).collect();
        assert_eq!(candidates, vec![p2]);
    }

    #[test]
    fn list_unleased_retained_project_ids_excludes_leased_projects() {
        let (db, _dir) = open_test_db();
        let p1 = db.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        let p2 = db.create_project("job-2", "acme", "gadgets", false, "ui", None).unwrap();
        db.retain_project_source(p1, "/tmp/does-not-matter-1", "full");
        db.retain_project_source(p2, "/tmp/does-not-matter-2", "full");
        db.set_snapshot_lease(p1, "review", 24);

        let unleased = db.list_unleased_retained_project_ids();
        assert!(!unleased.contains(&p1), "a leased project must never be offered up for eviction");
        assert!(unleased.contains(&p2));
    }
}
