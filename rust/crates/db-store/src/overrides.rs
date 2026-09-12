//! Override audit log: who justified which issue, and why.
//!
//! `impl DbStore` block — one of several per-domain files this crate's
//! accessor methods are split across (see `lib.rs`'s module list).

use crate::store::DbStore;
use crate::types::*;
use rusqlite::{params, Connection};
use std::collections::HashMap;

/// `overrides.actor_email` sentinel marking a row created by the inbound
/// GitHub code-scanning webhook (`routes/code_scanning_webhook.rs`)
/// rather than Ignite's own human-justified override flow — lets a
/// later "reopened" webhook find and remove exactly the rows it created,
/// without touching a real Ignite override that happens to cover the
/// same issue id.
pub const GITHUB_DISMISSAL_ACTOR_EMAIL: &str = "github-webhook:dismissal-sync";

impl DbStore {
    // ---------------- audit log: overrides ----------------

    pub fn add_override(&self, args: AddOverrideArgs) {
        let conn = self.conn.lock();
        if let Err(e) = conn.execute(
            "INSERT INTO overrides
              (project_id, job_id, phase, issue_id, category, severity, summary, file, line, justification, actor_email, actor_name, email_sent, status)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'approved')",
            params![
                args.project_id, args.job_id, args.phase, args.issue_id, args.category, args.severity,
                args.summary, args.file, args.line, args.justification, args.actor_email, args.actor_name,
                args.email_sent as i64,
            ],
        ) {
            // A transient DB error (lock contention, disk full) must not
            // panic and take the whole server process down with it — the
            // caller already has no way to observe failure here (this
            // returns `()`), so the best available signal is a log line.
            tracing::error!("add_override failed for issue {}: {e}", args.issue_id);
        }
    }

    /// Same shape as [`Self::add_override`], but the row starts life
    /// `status = 'pending'` — dual-custody for critical-severity findings
    /// (`security.overrideApproval`, see `routes/effectivate.rs`/
    /// `routes/pipeline_interactive/run.rs`): the issue this override
    /// targets must stay `open` (still blocking the gate) until a
    /// *different* user calls [`Self::approve_override`]. Returns the new
    /// row's id, so the caller can surface it for a future approve/reject
    /// call.
    /// Returns the new row's id, or `0` (never a real SQLite rowid — those
    /// start at 1) if the insert itself failed, e.g. transient DB lock
    /// contention or a disk error — the caller should treat `0` as
    /// "nothing was recorded" rather than a valid id to look up.
    pub fn add_pending_override(&self, args: AddOverrideArgs) -> i64 {
        let conn = self.conn.lock();
        let result = conn.execute(
            "INSERT INTO overrides
              (project_id, job_id, phase, issue_id, category, severity, summary, file, line, justification, actor_email, actor_name, email_sent, status)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')",
            params![
                args.project_id, args.job_id, args.phase, args.issue_id, args.category, args.severity,
                args.summary, args.file, args.line, args.justification, args.actor_email, args.actor_name,
                args.email_sent as i64,
            ],
        );
        match result {
            Ok(_) => conn.last_insert_rowid(),
            Err(e) => {
                tracing::error!("add_pending_override failed for issue {}: {e}", args.issue_id);
                0
            }
        }
    }

    /// True when `issue_id` already has an `'approved'` override on this
    /// project — the predicate the dual-custody gate actually cares about
    /// (unlike [`Self::issue_has_override`], which also returns `true` for
    /// a still-pending row that must keep blocking the gate).
    pub fn has_approved_override(&self, project_id: i64, issue_id: &str) -> bool {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM overrides WHERE project_id = ? AND issue_id = ? AND status = 'approved')",
            params![project_id, issue_id],
            |row| row.get::<_, i64>(0),
        )
        .unwrap()
            != 0
    }

    /// True when `issue_id` already has a `'pending'` override on this
    /// project — checked before inserting a new pending row so
    /// resubmitting the same justification (e.g. a page refresh) doesn't
    /// pile up duplicate pending rows for one issue.
    pub fn has_pending_override(&self, project_id: i64, issue_id: &str) -> bool {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM overrides WHERE project_id = ? AND issue_id = ? AND status = 'pending')",
            params![project_id, issue_id],
            |row| row.get::<_, i64>(0),
        )
        .unwrap()
            != 0
    }

    /// Every still-`'pending'` override across `project_id` — the queue a
    /// second approver reviews.
    pub fn list_pending_overrides(&self, project_id: i64) -> Vec<PendingOverrideRow> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare_cached(
                "SELECT id, project_id, job_id, issue_id, category, severity, summary, file, line, justification, actor_email, actor_name, created_at
                 FROM overrides WHERE project_id = ? AND status = 'pending' ORDER BY id",
            )
            .unwrap();
        stmt.query_map(params![project_id], |row| {
            Ok(PendingOverrideRow {
                id: row.get(0)?,
                project_id: row.get(1)?,
                job_id: row.get(2)?,
                issue_id: row.get(3)?,
                category: row.get(4)?,
                severity: row.get(5)?,
                summary: row.get(6)?,
                file: row.get(7)?,
                line: row.get(8)?,
                justification: row.get(9)?,
                actor_email: row.get(10)?,
                actor_name: row.get(11)?,
                created_at: row.get(12)?,
            })
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    /// Marks a pending override `'approved'` — the second half of
    /// dual-custody. Fails if `override_id` doesn't exist or doesn't
    /// belong to `project_id` (so an approver route scoped to one project
    /// path can't be used to approve an unrelated project's override by
    /// guessing its id), isn't `'pending'` (already decided, or never
    /// required approval to begin with), or `approver_email` is the same
    /// person who submitted it (the whole point of dual custody is a
    /// *different* reviewer). On
    /// success, returns `(project_id, issue_id)` so the caller can flip
    /// the issue's own status to `"overridden"` via
    /// [`crate::DbStore::set_issue_status`] — this function only ever
    /// touches the `overrides` row itself, never `issues`, so it composes
    /// cleanly with that existing method rather than duplicating it.
    pub fn approve_override(&self, project_id: i64, override_id: i64, approver_email: &str) -> Result<(i64, String), String> {
        let conn = self.conn.lock();
        let (row_project_id, issue_id, actor_email, status): (i64, String, String, String) = conn
            .query_row("SELECT project_id, issue_id, actor_email, status FROM overrides WHERE id = ?", params![override_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
            .map_err(|_| "Override not found.".to_string())?;
        if row_project_id != project_id {
            return Err("Override not found for this project.".to_string());
        }
        if status != "pending" {
            return Err(format!("Override is already {status}, not pending."));
        }
        if actor_email.eq_ignore_ascii_case(approver_email) {
            return Err("A different reviewer must approve this override — you can't approve your own submission.".to_string());
        }
        conn.execute("UPDATE overrides SET status = 'approved', approved_by_email = ?, approved_at = datetime('now') WHERE id = ?", params![approver_email, override_id]).unwrap();
        Ok((project_id, issue_id))
    }

    /// Marks a pending override `'rejected'` — the issue it targeted stays
    /// (or returns to) `open`; the caller is expected to leave the
    /// issue's own status untouched (it was never flipped to
    /// `"overridden"` for a pending row in the first place). Same
    /// not-found/not-pending validation as [`Self::approve_override`], but
    /// no same-reviewer restriction — declining your own submission (or
    /// someone else's, on reflection) is always safe since it never
    /// unblocks anything.
    pub fn reject_override(&self, project_id: i64, override_id: i64, approver_email: &str) -> Result<(i64, String), String> {
        let conn = self.conn.lock();
        let (row_project_id, issue_id, status): (i64, String, String) =
            conn.query_row("SELECT project_id, issue_id, status FROM overrides WHERE id = ?", params![override_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).map_err(|_| "Override not found.".to_string())?;
        if row_project_id != project_id {
            return Err("Override not found for this project.".to_string());
        }
        if status != "pending" {
            return Err(format!("Override is already {status}, not pending."));
        }
        conn.execute("UPDATE overrides SET status = 'rejected', approved_by_email = ?, approved_at = datetime('now') WHERE id = ?", params![approver_email, override_id]).unwrap();
        Ok((project_id, issue_id))
    }

    pub(crate) fn get_project_overrides_inner(conn: &Connection, project_id: i64) -> Vec<OverrideRow> {
        let mut stmt = conn
            .prepare_cached(
                "SELECT id, phase, issue_id, category, severity, summary, file, line, justification,
                        actor_email, actor_name, email_sent, created_at
                 FROM overrides WHERE project_id = ? ORDER BY id",
            )
            .unwrap();
        stmt.query_map(params![project_id], |row| {
            Ok(OverrideRow {
                id: row.get(0)?,
                phase: row.get(1)?,
                issue_id: row.get(2)?,
                category: row.get(3)?,
                severity: row.get(4)?,
                summary: row.get(5)?,
                file: row.get(6)?,
                line: row.get(7)?,
                justification: row.get(8)?,
                actor_email: row.get(9)?,
                actor_name: row.get(10)?,
                email_sent: row.get::<_, i64>(11)? != 0,
                created_at: row.get(12)?,
            })
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    pub fn get_project_overrides(&self, project_id: i64) -> Vec<OverrideRow> {
        let conn = self.conn.lock();
        Self::get_project_overrides_inner(&conn, project_id)
    }

    /// The most recent justification for each issue id previously
    /// overridden on any other scan of the same `(org, repo)` —
    /// `exclude_project_id` is the project row the current scan just
    /// created, so a scan never "carries forward" from itself. Matching is
    /// by exact `issue_id` (`<category>::<file>::<line>`), the same stable
    /// id `override-engine` already produces per finding; unlike the
    /// headless `.ignite/acknowledgments.md` flow, there's no fuzzy
    /// line-shift carry-forward here yet, so an unrelated edit above a
    /// flagged line drops the match same as any other id change would.
    pub fn get_carry_forward_overrides(&self, org: &str, repo: &str, exclude_project_id: i64) -> HashMap<String, OverrideRow> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare_cached(
                "SELECT o.id, o.phase, o.issue_id, o.category, o.severity, o.summary, o.file, o.line, o.justification, o.actor_email, o.actor_name, o.email_sent, o.created_at
                 FROM overrides o
                 INNER JOIN projects p ON o.project_id = p.id
                 WHERE p.org = ? AND p.repo = ? AND p.id != ? AND o.status = 'approved'
                 ORDER BY o.created_at DESC, o.id DESC",
            )
            .unwrap();
        let rows = stmt
            .query_map(params![org, repo, exclude_project_id], |row| {
                Ok(OverrideRow {
                    id: row.get(0)?,
                    phase: row.get(1)?,
                    issue_id: row.get(2)?,
                    category: row.get(3)?,
                    severity: row.get(4)?,
                    summary: row.get(5)?,
                    file: row.get(6)?,
                    line: row.get(7)?,
                    justification: row.get(8)?,
                    actor_email: row.get(9)?,
                    actor_name: row.get(10)?,
                    email_sent: row.get::<_, i64>(11)? != 0,
                    created_at: row.get(12)?,
                })
            })
            .unwrap();
        let mut by_issue_id: HashMap<String, OverrideRow> = HashMap::new();
        for row in rows.flatten() {
            // ORDER BY created_at DESC means the first row seen per
            // issue_id is already the most recent justification.
            by_issue_id.entry(row.issue_id.clone()).or_insert(row);
        }
        by_issue_id
    }

    /// True when `issue_id` already has ANY override row (Ignite's own or
    /// a GitHub-dismissal one) on this project — used after
    /// [`Self::delete_github_dismissal_overrides`] to decide whether a
    /// "reopened" webhook should flip the issue back to `open` or leave it
    /// `overridden` because a separate, real Ignite override still covers it.
    pub fn issue_has_override(&self, project_id: i64, issue_id: &str) -> bool {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM overrides WHERE project_id = ? AND issue_id = ?)",
            params![project_id, issue_id],
            |row| row.get::<_, i64>(0),
        )
        .unwrap()
            != 0
    }

    /// Removes every GitHub-dismissal override row (see
    /// [`GITHUB_DISMISSAL_ACTOR_EMAIL`]) for `issue_id` across every
    /// project ever scanned for `(org, repo)` — plural, not just the
    /// latest project, because [`Self::get_carry_forward_overrides`] reads
    /// across every past project of the repo, so a stale row on an older
    /// project would otherwise get carried forward into the next scan
    /// again right after a human reopened the alert on GitHub. Returns the
    /// number of rows removed.
    pub fn delete_github_dismissal_overrides(&self, org: &str, repo: &str, issue_id: &str) -> usize {
        let conn = self.conn.lock();
        conn.execute(
            "DELETE FROM overrides
              WHERE issue_id = ? AND actor_email = ?
                AND project_id IN (SELECT id FROM projects WHERE org = ? AND repo = ?)",
            params![issue_id, GITHUB_DISMISSAL_ACTOR_EMAIL, org, repo],
        )
        .unwrap()
    }

}
