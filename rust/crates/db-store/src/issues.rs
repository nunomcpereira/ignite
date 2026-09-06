//! Flagged-issue persistence (the `issues` table) for one project's scan.
//!
//! `impl DbStore` block — one of several per-domain files this crate's
//! accessor methods are split across (see `lib.rs`'s module list).

use crate::store::DbStore;
use crate::types::*;
use rusqlite::{params, OptionalExtension};
use std::collections::HashSet;

impl DbStore {
    // ---------------- flagged issues ----------------

    /// Called repeatedly as a run progresses — always reflects the latest
    /// known set of issues for the project, so the history/API view is
    /// never stale even if the pipeline dies before finishing.
    pub fn replace_project_issues(&self, project_id: i64, issues: &[IssueInput], overridden_ids: &HashSet<String>) {
        let mut conn = self.conn.lock();
        let tx = conn.transaction().unwrap();
        tx.execute("DELETE FROM issues WHERE project_id = ?", params![project_id]).unwrap();
        for issue in issues {
            let snippet_json = issue.snippet.as_ref().map(|s| serde_json::to_string(s).unwrap());
            let chain_json = issue.chain.as_ref().map(|c| serde_json::to_string(c).unwrap());
            let references_json = issue.references.as_ref().map(|r| serde_json::to_string(r).unwrap());
            let duplicate_ref_json = issue.duplicate_ref.as_ref().map(|d| serde_json::to_string(d).unwrap());
            let status = if overridden_ids.contains(&issue.id) { "overridden" } else { "open" };
            tx.execute(
                "INSERT INTO issues (project_id, issue_id, phase, category, severity, score, summary, file, line, snippet_json, cross_file, chain_json, cwe, owasp, tool, references_json, duplicate_ref_json, status)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    project_id, issue.id, issue.phase, issue.category, issue.severity, issue.score,
                    issue.summary, issue.file, issue.line, snippet_json, issue.cross_file as i64, chain_json,
                    issue.cwe, issue.owasp, issue.tool, references_json, duplicate_ref_json, status,
                ],
            )
            .unwrap();
        }
        tx.commit().unwrap();
    }

    pub fn get_project_issues(&self, project_id: i64) -> Vec<IssueRow> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare_cached(
                "SELECT i.issue_id, i.phase, i.category, i.severity, i.score, i.summary, i.file, i.line, i.snippet_json, i.cross_file, i.chain_json, i.cwe, i.owasp, i.tool, i.references_json, i.duplicate_ref_json, i.status, i.created_at,
                        (SELECT o.justification FROM overrides o WHERE o.project_id = i.project_id AND o.issue_id = i.issue_id ORDER BY o.created_at DESC, o.id DESC LIMIT 1),
                        (SELECT o.actor_email FROM overrides o WHERE o.project_id = i.project_id AND o.issue_id = i.issue_id ORDER BY o.created_at DESC, o.id DESC LIMIT 1),
                        (SELECT o.actor_name FROM overrides o WHERE o.project_id = i.project_id AND o.issue_id = i.issue_id ORDER BY o.created_at DESC, o.id DESC LIMIT 1)
                 FROM issues i WHERE i.project_id = ? ORDER BY i.id",
            )
            .unwrap();
        // Corrupted JSON in a cached column must never panic here: a panic
        // while holding `self.conn.lock()` poisons the mutex and every
        // subsequent DB call on this process fails permanently until
        // restart. Parse failures are logged and degrade to `None`/empty
        // instead — a malformed cached snippet/chain/references blob is
        // recoverable data loss, not a reason to take the whole server down.
        fn parse_or_log<T: serde::de::DeserializeOwned>(field: &str, issue_id: &str, json: Option<String>) -> Option<T> {
            json.and_then(|j| match serde_json::from_str(&j) {
                Ok(v) => Some(v),
                Err(e) => {
                    tracing::warn!(issue_id, field, error = %e, "corrupted JSON column in issues table, dropping field");
                    None
                }
            })
        }
        let rows: Result<Vec<IssueRow>, rusqlite::Error> = stmt
            .query_map(params![project_id], |row| {
                let id: String = row.get(0)?;
                let snippet_json: Option<String> = row.get(8)?;
                let chain_json: Option<String> = row.get(10)?;
                let references_json: Option<String> = row.get(14)?;
                let duplicate_ref_json: Option<String> = row.get(15)?;
                Ok(IssueRow {
                    phase: row.get(1)?,
                    category: row.get(2)?,
                    severity: row.get(3)?,
                    score: row.get(4)?,
                    summary: row.get(5)?,
                    file: row.get(6)?,
                    line: row.get(7)?,
                    snippet: parse_or_log("snippet", &id, snippet_json),
                    cross_file: row.get::<_, i64>(9)? != 0,
                    chain: parse_or_log("chain", &id, chain_json),
                    cwe: row.get(11)?,
                    owasp: row.get(12)?,
                    tool: row.get(13)?,
                    references: parse_or_log("references", &id, references_json),
                    duplicate_ref: parse_or_log("duplicate_ref", &id, duplicate_ref_json),
                    status: row.get(16)?,
                    created_at: row.get(17)?,
                    justification: row.get(18)?,
                    actor_email: row.get(19)?,
                    actor_name: row.get(20)?,
                    id,
                })
            })
            .and_then(|mapped| mapped.collect());
        match rows {
            Ok(rows) => rows,
            Err(e) => {
                tracing::error!(error = %e, "failed to read project issues");
                Vec::new()
            }
        }
    }

    pub fn get_project_id_by_job_id(&self, job_id: &str) -> Option<i64> {
        let conn = self.conn.lock();
        conn.query_row("SELECT id FROM projects WHERE job_id = ?", params![job_id], |row| row.get(0)).optional().unwrap()
    }

}
