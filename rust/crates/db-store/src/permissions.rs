//! US-08: explicit, repository/org-scoped permission grants — replaces
//! the ad hoc "email is in a config allowlist" checks scattered around
//! the server (`routes/override_approval.rs`'s `approverEmails`, chiefly)
//! with a real, queryable, per-repo-capable grant model. Kept
//! deliberately narrow: no `users.role` column, no group/team concept —
//! see the module's own callers for exactly what's wired to it so far.

use crate::store::DbStore;
use crate::types::PermissionGrantRow;
use rusqlite::{params, OptionalExtension};

fn row_from(row: &rusqlite::Row) -> rusqlite::Result<PermissionGrantRow> {
    Ok(PermissionGrantRow { id: row.get(0)?, subject_email: row.get(1)?, permission: row.get(2)?, org: row.get(3)?, repo: row.get(4)?, granted_by: row.get(5)?, created_at: row.get(6)? })
}

const COLUMNS: &str = "id, subject_email, permission, org, repo, granted_by, created_at";

impl DbStore {
    /// Idempotent — granting the same `(subject_email, permission, org,
    /// repo)` twice is a no-op, not a duplicate row (the unique index in
    /// `schema.rs` enforces this; `INSERT OR IGNORE` just avoids treating
    /// the resulting constraint violation as an error to surface).
    pub fn grant_permission(&self, subject_email: &str, permission: &str, org: Option<&str>, repo: Option<&str>, granted_by: Option<&str>) {
        let conn = self.conn.lock();
        if let Err(e) = conn.execute("INSERT OR IGNORE INTO permission_grants (subject_email, permission, org, repo, granted_by) VALUES (?, ?, ?, ?, ?)", params![subject_email.to_ascii_lowercase(), permission, org, repo, granted_by]) {
            tracing::error!("grant_permission({subject_email}, {permission}) failed: {e}");
        }
    }

    pub fn revoke_permission_grant(&self, grant_id: i64) {
        let conn = self.conn.lock();
        if let Err(e) = conn.execute("DELETE FROM permission_grants WHERE id = ?", params![grant_id]) {
            tracing::error!("revoke_permission_grant({grant_id}) failed: {e}");
        }
    }

    /// `true` when `subject_email` holds `permission` at a scope covering
    /// `(org, repo)` — a global grant (`org` and `repo` both NULL on the
    /// row), an org-wide grant (`org` matches, `repo` NULL on the row), or
    /// an exact repo grant (`org` and `repo` both match) all count.
    /// Case-insensitive on the email, exact-match (case-sensitive) on
    /// `org`/`repo` — matching GitHub's own org/repo naming, which this
    /// codebase already treats as case-sensitive everywhere else
    /// (`tool-runner`'s org/repo validation, `repositories` table lookups).
    pub fn has_permission(&self, subject_email: &str, permission: &str, org: &str, repo: &str) -> bool {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM permission_grants
                WHERE subject_email = ? AND permission = ?
                AND (
                    (org IS NULL AND repo IS NULL)
                    OR (org = ? AND repo IS NULL)
                    OR (org = ? AND repo = ?)
                )
            )",
            params![subject_email.to_ascii_lowercase(), permission, org, org, repo],
            |row| row.get(0),
        )
        .unwrap_or(false)
    }

    pub fn list_permission_grants_for_subject(&self, subject_email: &str) -> Vec<PermissionGrantRow> {
        let conn = self.conn.lock();
        let Ok(mut stmt) = conn.prepare(&format!("SELECT {COLUMNS} FROM permission_grants WHERE subject_email = ? ORDER BY id")) else { return vec![] };
        stmt.query_map(params![subject_email.to_ascii_lowercase()], row_from).map(|rows| rows.filter_map(|r| r.ok()).collect()).unwrap_or_default()
    }

    pub fn get_permission_grant(&self, grant_id: i64) -> Option<PermissionGrantRow> {
        let conn = self.conn.lock();
        conn.query_row(&format!("SELECT {COLUMNS} FROM permission_grants WHERE id = ?"), params![grant_id], row_from).optional().unwrap_or(None)
    }

    /// US-08's "migrate configured approver email lists into equivalent
    /// explicit grants without broadening access" — called once at server
    /// startup with `security.overrideApproval.approverEmails`. Grants
    /// each configured email a *global* `review` permission (the same
    /// scope the config allowlist already implied — every project,
    /// regardless of org/repo), never anything wider. Idempotent, safe to
    /// call on every startup: already-granted emails are a no-op via
    /// [`Self::grant_permission`]'s own `INSERT OR IGNORE`, and an email
    /// removed from config is deliberately *not* auto-revoked here (an
    /// operator's explicit grant/config edit should never be silently
    /// undone by an unrelated startup) — use
    /// [`Self::revoke_permission_grant`] directly to remove one.
    pub fn sync_configured_approvers_into_grants(&self, approver_emails: &[String]) {
        for email in approver_emails {
            self.grant_permission(email, "review", None, None, Some("config:security.overrideApproval.approverEmails"));
        }
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
    fn a_global_grant_covers_every_org_and_repo() {
        let (db, _dir) = open_test_db();
        db.grant_permission("admin@acme.example", "review", None, None, None);
        assert!(db.has_permission("admin@acme.example", "review", "acme", "widgets"));
        assert!(db.has_permission("admin@acme.example", "review", "other-org", "other-repo"));
    }

    #[test]
    fn an_org_scoped_grant_does_not_cover_a_different_org() {
        let (db, _dir) = open_test_db();
        db.grant_permission("lead@acme.example", "review", Some("acme"), None, None);
        assert!(db.has_permission("lead@acme.example", "review", "acme", "widgets"));
        assert!(db.has_permission("lead@acme.example", "review", "acme", "gadgets"));
        assert!(!db.has_permission("lead@acme.example", "review", "other-org", "widgets"));
    }

    #[test]
    fn a_repo_scoped_grant_does_not_cover_a_sibling_repo() {
        let (db, _dir) = open_test_db();
        db.grant_permission("dev@acme.example", "review", Some("acme"), Some("widgets"), None);
        assert!(db.has_permission("dev@acme.example", "review", "acme", "widgets"));
        assert!(!db.has_permission("dev@acme.example", "review", "acme", "gadgets"));
    }

    #[test]
    fn no_grant_means_no_permission() {
        let (db, _dir) = open_test_db();
        assert!(!db.has_permission("nobody@acme.example", "review", "acme", "widgets"));
    }

    #[test]
    fn granting_is_idempotent() {
        let (db, _dir) = open_test_db();
        db.grant_permission("admin@acme.example", "review", None, None, None);
        db.grant_permission("admin@acme.example", "review", None, None, None);
        assert_eq!(db.list_permission_grants_for_subject("admin@acme.example").len(), 1);
    }

    #[test]
    fn revoking_removes_the_grant() {
        let (db, _dir) = open_test_db();
        db.grant_permission("admin@acme.example", "review", None, None, None);
        let grant = db.list_permission_grants_for_subject("admin@acme.example")[0].clone();
        db.revoke_permission_grant(grant.id);
        assert!(!db.has_permission("admin@acme.example", "review", "acme", "widgets"));
    }

    #[test]
    fn sync_configured_approvers_grants_global_review_permission() {
        let (db, _dir) = open_test_db();
        db.sync_configured_approvers_into_grants(&["Approver@Acme.example".to_string()]);
        assert!(db.has_permission("approver@acme.example", "review", "any-org", "any-repo"), "email matching must be case-insensitive, same as the config allowlist it replaces");
    }
}
