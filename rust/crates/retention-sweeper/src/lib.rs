//! US-05: "implement configurable source/artifact retention with expiry
//! timestamps and an independently scheduled sweeper" — the actual sweep
//! logic, split out of `main.rs` so it's callable/testable directly
//! (same convention as `enforce-gate-branch-protection`/`auto-fix-pr`).
//!
//! Deliberately **not** wired into any request path or into a running
//! server's own event loop: `pipeline_interactive/run.rs` already does
//! scan-triggered, rank-based pruning inline after each interactive run
//! (`RETAINED_FULL_KEEP`/`RETAINED_TOTAL_KEEP`), which only ever fires
//! when a new scan happens to arrive. This binary is the other half —
//! independently scheduled (cron/systemd timer/a scheduled GitHub Actions
//! workflow, same posture as `scheduled-rescan`), age-based rather than
//! rank-based, and it runs (and ages things out) even when no new scan
//! ever arrives again for a given project.
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

use ignite_db_store::DbStore;
use ignite_run_lifecycle::RunLifecycleState;

#[derive(Debug, Clone)]
pub struct SweepPlanEntry {
    pub project_id: i64,
    pub dir_path: String,
    pub age_days: i64,
}

#[derive(Debug, Default)]
pub struct SweepReport {
    /// Every candidate found — always populated, `--apply` or not, so a
    /// dry run can report exactly what it *would* have done.
    pub evicted: Vec<SweepPlanEntry>,
    /// Rows whose `dir_path` no longer exists on disk (deleted outside
    /// this tool's own knowledge — manually, or by an older code path) —
    /// marked `missing` on the snapshot but never deleted outright, so
    /// the project's decision metadata stays queryable even though its
    /// source is gone.
    pub marked_missing: Vec<i64>,
}

/// One sweep pass. `max_age_days` is the configurable retention window;
/// `apply` mirrors `enforce-gate-branch-protection`/`auto-fix-pr`'s own
/// dry-run-by-default convention — `false` only ever reports what would
/// happen, `true` actually removes directories and DB rows.
pub fn sweep_once(db: &DbStore, max_age_days: i64, apply: bool) -> SweepReport {
    let mut report = SweepReport::default();

    // Missing-on-disk detection runs regardless of `apply` — it's pure
    // bookkeeping (a `retention_state` label), never a deletion, so there
    // is no "would do" to report instead of doing.
    for row in db.list_retained_sources() {
        if !std::path::Path::new(&row.dir_path).exists() {
            if let Some(run) = db.get_scan_run_for_legacy_project(row.project_id) {
                db.mark_snapshot_retention_state(run.id, "missing");
            }
            report.marked_missing.push(row.project_id);
        }
    }

    for candidate in db.list_expired_unleased_retained_sources(max_age_days) {
        report.evicted.push(SweepPlanEntry { project_id: candidate.project_id, dir_path: candidate.dir_path.clone(), age_days: max_age_days });
        if !apply {
            continue;
        }
        let _ = std::fs::remove_dir_all(&candidate.dir_path);
        ignite_fs_utils::invalidate_walk_cache(std::path::Path::new(&candidate.dir_path));
        if let Some(run) = db.get_scan_run_for_legacy_project(candidate.project_id) {
            db.mark_snapshot_retention_state(run.id, "expired");
            // A run that's still mid-flight (not yet terminal) never
            // reaches here at all — `list_expired_unleased_retained_sources`
            // only returns rows past the retention window, and an active
            // run's project was retained far more recently than that. This
            // transition only ever fires against an already-terminal run
            // (`Completed`/`Published`/`Blocked`/`Failed`), so it's a
            // pure bookkeeping no-op by the time it's reached — logged,
            // never treated as an error, if some future caller manages to
            // race it against a genuinely non-terminal run.
            if let Err(e) = db.transition_scan_run(run.id, RunLifecycleState::Completed) {
                tracing::debug!("sweep_once: transition_scan_run({}) no-op/rejected (expected once terminal): {e}", run.id);
            }
        }
        db.delete_retained_source(candidate.project_id);
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_test_db() -> (DbStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = DbStore::open(&dir.path().join("test.db")).unwrap();
        (db, dir)
    }

    /// A negative `max_age_days` pushes the sweep's cutoff into the
    /// future (see `list_expired_unleased_retained_sources`'s own doc
    /// comment) — every currently retained row reads as "past the
    /// retention window" without needing to backdate a row's
    /// `retained_at` from outside `ignite-db-store` (that field is
    /// crate-private).
    const ALWAYS_EXPIRED: i64 = -100_000;

    #[test]
    fn dry_run_reports_candidates_without_deleting_anything() {
        let (db, work_dir) = open_test_db();
        let project_id = db.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        let retained_dir = work_dir.path().join("retained-1");
        std::fs::create_dir_all(&retained_dir).unwrap();
        db.retain_project_source(project_id, &retained_dir.to_string_lossy(), "full");

        let report = sweep_once(&db, ALWAYS_EXPIRED, false);
        assert_eq!(report.evicted.len(), 1);
        assert_eq!(report.evicted[0].project_id, project_id);
        assert!(retained_dir.exists(), "a dry run must never delete anything on disk");
        assert!(db.get_retained_source(project_id).is_some(), "a dry run must never delete the DB row");
    }

    #[test]
    fn apply_deletes_the_directory_and_the_db_row() {
        let (db, work_dir) = open_test_db();
        let project_id = db.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        let retained_dir = work_dir.path().join("retained-1");
        std::fs::create_dir_all(&retained_dir).unwrap();
        db.retain_project_source(project_id, &retained_dir.to_string_lossy(), "full");

        let report = sweep_once(&db, ALWAYS_EXPIRED, true);
        assert_eq!(report.evicted.len(), 1);
        assert!(!retained_dir.exists());
        assert!(db.get_retained_source(project_id).is_none());
    }

    #[test]
    fn a_leased_project_is_never_swept_even_past_the_retention_window() {
        let (db, work_dir) = open_test_db();
        let project_id = db.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        let retained_dir = work_dir.path().join("retained-1");
        std::fs::create_dir_all(&retained_dir).unwrap();
        db.retain_project_source(project_id, &retained_dir.to_string_lossy(), "full");
        db.set_snapshot_lease(project_id, "awaiting_review", 24);

        let report = sweep_once(&db, ALWAYS_EXPIRED, true);
        assert!(report.evicted.is_empty(), "a project with an active lease must never be evicted, no matter its age");
        assert!(retained_dir.exists());
    }

    #[test]
    fn a_directory_deleted_outside_this_tool_is_marked_missing_not_silently_ignored() {
        let (db, work_dir) = open_test_db();
        let project_id = db.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        // Never actually created on disk — simulates external deletion.
        let missing_dir = work_dir.path().join("gone");
        db.retain_project_source(project_id, &missing_dir.to_string_lossy(), "full");

        let report = sweep_once(&db, 90, true);
        assert_eq!(report.marked_missing, vec![project_id]);
        // Still on record — historical decision metadata stays viewable.
        assert!(db.get_retained_source(project_id).is_some());
    }

    #[test]
    fn a_fresh_retention_is_never_swept() {
        let (db, work_dir) = open_test_db();
        let project_id = db.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        let retained_dir = work_dir.path().join("retained-1");
        std::fs::create_dir_all(&retained_dir).unwrap();
        db.retain_project_source(project_id, &retained_dir.to_string_lossy(), "full");

        let report = sweep_once(&db, 90, true);
        assert!(report.evicted.is_empty());
        assert!(retained_dir.exists());
    }
}
