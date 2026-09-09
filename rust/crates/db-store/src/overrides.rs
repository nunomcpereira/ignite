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
        conn.execute(
            "INSERT INTO overrides
              (project_id, job_id, phase, issue_id, category, severity, summary, file, line, justification, actor_email, actor_name, email_sent)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                args.project_id, args.job_id, args.phase, args.issue_id, args.category, args.severity,
                args.summary, args.file, args.line, args.justification, args.actor_email, args.actor_name,
                args.email_sent as i64,
            ],
        )
        .unwrap();
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
        .map(|r| r.unwrap())
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
                 WHERE p.org = ? AND p.repo = ? AND p.id != ?
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
