//! Learning from triage: per-finding false-positive / real-issue verdicts,
//! per-rule noise statistics, the override justifications people write in
//! free text, and AI-proposed ignore rules an admin accepts or dismisses.
//! An accepted proposal is an ignore rule applied next to `config.json`'s
//! `ignoreRules` (`list_accepted_rule_proposals_for`).

use crate::store::DbStore;
use rusqlite::{params, OptionalExtension};
use serde::Serialize;

/// Override origins that are a person's own words (not system-generated).
const HUMAN_ORIGINS: &str = "('session', 'api_key', 'repo_file')";

pub struct NewVerdict<'a> {
    pub org: &'a str,
    pub repo: &'a str,
    pub fingerprint: &'a str,
    pub issue_id: &'a str,
    pub category: &'a str,
    pub tool: Option<&'a str>,
    pub rule: Option<&'a str>,
    pub file: Option<&'a str>,
    /// `false_positive` or `true_positive`.
    pub verdict: &'a str,
    pub note: Option<&'a str>,
    pub actor_email: &'a str,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VerdictRow {
    pub verdict: String,
    pub note: Option<String>,
    pub actor_email: String,
    pub updated_at: String,
}

/// One engine rule's triage signal.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuleNoiseRow {
    pub tool: Option<String>,
    pub rule: Option<String>,
    pub category: String,
    pub false_positives: i64,
    pub true_positives: i64,
    /// Human overrides (justifications) of this rule's findings.
    pub overrides: i64,
    pub repos: i64,
}

/// An override justification as a person wrote it, with the finding it covered.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct JustificationRow {
    pub override_id: i64,
    pub org: String,
    pub repo: String,
    pub category: String,
    pub tool: Option<String>,
    pub rule: Option<String>,
    pub file: Option<String>,
    pub summary: String,
    pub justification: String,
    pub created_at: String,
}

pub struct NewRuleProposal<'a> {
    pub org: &'a str,
    pub repo: &'a str,
    pub categories: &'a [String],
    pub file_patterns: &'a [String],
    pub line_patterns: &'a [String],
    pub reason: &'a str,
    pub rationale: &'a str,
    pub evidence_override_ids: &'a [i64],
    pub match_count: i64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuleProposalRow {
    pub id: i64,
    /// Org it applies to (`*` = every org).
    pub org: String,
    /// Repo it applies to (`*` = every repo in `org`).
    pub repo: String,
    pub categories: Vec<String>,
    pub file_patterns: Vec<String>,
    pub line_patterns: Vec<String>,
    /// The acknowledgment reason recorded on every finding it matches.
    pub reason: String,
    /// Why the AI proposed it.
    pub rationale: String,
    pub evidence_override_ids: Vec<i64>,
    /// Stored findings it matched when proposed (file/category only).
    pub match_count: i64,
    /// `proposed`, `accepted`, `dismissed` or `disabled`.
    pub status: String,
    pub created_at: String,
    pub decided_by: Option<String>,
    pub decided_at: Option<String>,
}

const PROPOSAL_COLUMNS: &str = "id, org, repo, categories_json, file_patterns_json, line_patterns_json, reason, rationale, evidence_json, match_count, status, created_at, decided_by, decided_at";

fn proposal_from(r: &rusqlite::Row) -> rusqlite::Result<RuleProposalRow> {
    let list = |i: usize| -> rusqlite::Result<Vec<String>> { Ok(serde_json::from_str(&r.get::<_, String>(i)?).unwrap_or_default()) };
    Ok(RuleProposalRow {
        id: r.get(0)?,
        org: r.get(1)?,
        repo: r.get(2)?,
        categories: list(3)?,
        file_patterns: list(4)?,
        line_patterns: list(5)?,
        reason: r.get(6)?,
        rationale: r.get(7)?,
        evidence_override_ids: serde_json::from_str(&r.get::<_, String>(8)?).unwrap_or_default(),
        match_count: r.get(9)?,
        status: r.get(10)?,
        created_at: r.get(11)?,
        decided_by: r.get(12)?,
        decided_at: r.get(13)?,
    })
}

impl DbStore {
    /// Records (or replaces) the verdict on one finding of `org/repo`.
    pub fn upsert_finding_verdict(&self, v: &NewVerdict<'_>) {
        let conn = self.conn.lock();
        if let Err(e) = conn.execute(
            "INSERT INTO finding_verdicts (org, repo, fingerprint, issue_id, category, tool, rule, file, verdict, note, actor_email)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(org, repo, fingerprint) DO UPDATE SET issue_id = excluded.issue_id, verdict = excluded.verdict, note = excluded.note, actor_email = excluded.actor_email, updated_at = datetime('now')",
            params![v.org, v.repo, v.fingerprint, v.issue_id, v.category, v.tool, v.rule, v.file, v.verdict, v.note, v.actor_email],
        ) {
            tracing::error!("upsert_finding_verdict failed: {e}");
        }
    }

    pub fn get_finding_verdict(&self, org: &str, repo: &str, fingerprint: &str) -> Option<VerdictRow> {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT verdict, note, actor_email, updated_at FROM finding_verdicts WHERE org = ? AND repo = ? AND fingerprint = ?",
            params![org, repo, fingerprint],
            |r| Ok(VerdictRow { verdict: r.get(0)?, note: r.get(1)?, actor_email: r.get(2)?, updated_at: r.get(3)? }),
        )
        .optional()
        .unwrap_or(None)
    }

    /// Per-rule verdict and override counts, noisiest first. `org = None`
    /// covers every org.
    pub fn list_rule_noise(&self, org: Option<&str>, limit: i64) -> Vec<RuleNoiseRow> {
        let conn = self.conn.lock();
        let sql = format!(
            "WITH v AS (
               SELECT tool, rule, category, org, repo,
                      SUM(verdict = 'false_positive') AS fp, SUM(verdict = 'true_positive') AS tp, 0 AS ov
               FROM finding_verdicts WHERE (?1 IS NULL OR org = ?1) GROUP BY tool, rule, category, org, repo
             ), o AS (
               SELECT i.tool, i.rule, i.category, p.org, p.repo, 0 AS fp, 0 AS tp, COUNT(DISTINCT o.id) AS ov
               FROM overrides o JOIN projects p ON p.id = o.project_id
               JOIN issues i ON i.project_id = o.project_id AND i.issue_id = o.issue_id
               WHERE o.origin IN {HUMAN_ORIGINS} AND o.status = 'approved' AND (?1 IS NULL OR p.org = ?1)
               GROUP BY i.tool, i.rule, i.category, p.org, p.repo
             )
             SELECT tool, rule, category, SUM(fp), SUM(tp), SUM(ov), COUNT(DISTINCT org || '/' || repo)
             FROM (SELECT * FROM v UNION ALL SELECT * FROM o)
             GROUP BY tool, rule, category
             ORDER BY SUM(fp) DESC, SUM(ov) DESC LIMIT ?2"
        );
        let Ok(mut stmt) = conn.prepare(&sql) else { return vec![] };
        stmt.query_map(params![org, limit], |r| {
            Ok(RuleNoiseRow { tool: r.get(0)?, rule: r.get(1)?, category: r.get(2)?, false_positives: r.get(3)?, true_positives: r.get(4)?, overrides: r.get(5)?, repos: r.get(6)? })
        })
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_default()
    }

    /// `(tool, rule)` pairs in `org` with at least `min` false-positive
    /// verdicts and no real-issue verdict.
    pub fn list_false_positive_rules(&self, org: &str, min: i64) -> Vec<(String, String)> {
        let conn = self.conn.lock();
        let Ok(mut stmt) = conn.prepare(
            "SELECT tool, rule FROM finding_verdicts WHERE org = ? AND tool IS NOT NULL AND rule IS NOT NULL
             GROUP BY tool, rule HAVING SUM(verdict = 'false_positive') >= ? AND SUM(verdict = 'true_positive') = 0",
        ) else {
            return vec![];
        };
        stmt.query_map(params![org, min], |r| Ok((r.get(0)?, r.get(1)?))).map(|rows| rows.filter_map(|r| r.ok()).collect()).unwrap_or_default()
    }

    /// The most recent human override justifications, with the rule/tool of
    /// the finding they covered. `org = None` covers every org.
    pub fn list_override_justifications(&self, org: Option<&str>, limit: i64) -> Vec<JustificationRow> {
        let conn = self.conn.lock();
        let sql = format!(
            "SELECT o.id, p.org, p.repo, o.category, i.tool, i.rule, o.file, o.summary, o.justification, o.created_at
             FROM overrides o JOIN projects p ON p.id = o.project_id
             LEFT JOIN issues i ON i.project_id = o.project_id AND i.issue_id = o.issue_id
             WHERE o.origin IN {HUMAN_ORIGINS} AND o.status = 'approved' AND (?1 IS NULL OR p.org = ?1) AND length(trim(o.justification)) > 0
             ORDER BY o.id DESC LIMIT ?2"
        );
        let Ok(mut stmt) = conn.prepare(&sql) else { return vec![] };
        stmt.query_map(params![org, limit], |r| {
            Ok(JustificationRow { override_id: r.get(0)?, org: r.get(1)?, repo: r.get(2)?, category: r.get(3)?, tool: r.get(4)?, rule: r.get(5)?, file: r.get(6)?, summary: r.get(7)?, justification: r.get(8)?, created_at: r.get(9)? })
        })
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_default()
    }

    /// `(file, category)` of every open issue on each repo's latest scan in
    /// `org` (`None` = all) — what a proposal's file/category patterns are
    /// previewed against.
    pub fn list_latest_open_issue_locations(&self, org: Option<&str>) -> Vec<(String, String, Option<String>, String)> {
        let conn = self.conn.lock();
        let Ok(mut stmt) = conn.prepare(
            "SELECT p.org, p.repo, i.file, i.category FROM issues i JOIN projects p ON p.id = i.project_id
             WHERE i.status = 'open' AND (?1 IS NULL OR p.org = ?1)
               AND p.id = (SELECT MAX(p2.id) FROM projects p2 WHERE p2.org = p.org AND p2.repo = p.repo)",
        ) else {
            return vec![];
        };
        stmt.query_map(params![org], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).map(|rows| rows.filter_map(|r| r.ok()).collect()).unwrap_or_default()
    }

    pub fn insert_rule_proposal(&self, p: &NewRuleProposal<'_>) -> Option<i64> {
        let conn = self.conn.lock();
        let j = |v: &[String]| serde_json::to_string(v).unwrap_or_else(|_| "[]".to_string());
        conn.execute(
            "INSERT INTO rule_proposals (org, repo, categories_json, file_patterns_json, line_patterns_json, reason, rationale, evidence_json, match_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![p.org, p.repo, j(p.categories), j(p.file_patterns), j(p.line_patterns), p.reason, p.rationale, serde_json::to_string(p.evidence_override_ids).unwrap_or_else(|_| "[]".to_string()), p.match_count],
        )
        .ok()
        .map(|_| conn.last_insert_rowid())
    }

    pub fn list_rule_proposals(&self, status: Option<&str>) -> Vec<RuleProposalRow> {
        let conn = self.conn.lock();
        let Ok(mut stmt) = conn.prepare(&format!("SELECT {PROPOSAL_COLUMNS} FROM rule_proposals WHERE (?1 IS NULL OR status = ?1) ORDER BY id DESC")) else { return vec![] };
        stmt.query_map(params![status], proposal_from).map(|rows| rows.filter_map(|r| r.ok()).collect()).unwrap_or_default()
    }

    pub fn get_rule_proposal(&self, id: i64) -> Option<RuleProposalRow> {
        let conn = self.conn.lock();
        conn.query_row(&format!("SELECT {PROPOSAL_COLUMNS} FROM rule_proposals WHERE id = ?"), params![id], proposal_from).optional().unwrap_or(None)
    }

    /// Moves a proposal to `status`, recording who decided.
    pub fn set_rule_proposal_status(&self, id: i64, status: &str, decided_by: &str) -> bool {
        let conn = self.conn.lock();
        conn.execute("UPDATE rule_proposals SET status = ?, decided_by = ?, decided_at = datetime('now') WHERE id = ?", params![status, decided_by, id]).map(|n| n == 1).unwrap_or(false)
    }

    /// Accepted proposals that apply to `org/repo` (exact, case-insensitive,
    /// or `*`).
    pub fn list_accepted_rule_proposals_for(&self, org: &str, repo: &str) -> Vec<RuleProposalRow> {
        self.list_rule_proposals(Some("accepted"))
            .into_iter()
            .filter(|p| (p.org == "*" || p.org.eq_ignore_ascii_case(org)) && (p.repo == "*" || p.repo.eq_ignore_ascii_case(repo)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::IssueInput;
    use std::collections::HashSet;

    fn open_test_db() -> (DbStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        (DbStore::open(&dir.path().join("t.db")).unwrap(), dir)
    }

    fn verdict<'a>(fp: &'a str, v: &'a str) -> NewVerdict<'a> {
        NewVerdict { org: "acme", repo: "w", fingerprint: fp, issue_id: "x", category: "semantic-sast", tool: Some("semgrep"), rule: Some("java.lang.weak-hash"), file: Some("a.java"), verdict: v, note: None, actor_email: "a@x.io" }
    }

    #[test]
    fn verdicts_upsert_and_drive_false_positive_rules() {
        let (db, _d) = open_test_db();
        db.upsert_finding_verdict(&verdict("f1", "false_positive"));
        db.upsert_finding_verdict(&verdict("f2", "false_positive"));
        assert!(db.list_false_positive_rules("acme", 3).is_empty());
        db.upsert_finding_verdict(&verdict("f3", "false_positive"));
        assert_eq!(db.list_false_positive_rules("acme", 3), vec![("semgrep".to_string(), "java.lang.weak-hash".to_string())]);
        db.upsert_finding_verdict(&verdict("f3", "true_positive"));
        assert!(db.list_false_positive_rules("acme", 2).is_empty(), "any real-issue verdict keeps the rule");
        assert_eq!(db.get_finding_verdict("acme", "w", "f3").unwrap().verdict, "true_positive");
        let noise = db.list_rule_noise(Some("acme"), 10);
        assert_eq!((noise[0].false_positives, noise[0].true_positives), (2, 1));
    }

    #[test]
    fn justifications_and_noise_include_human_overrides_with_their_rule() {
        let (db, _d) = open_test_db();
        let pid = db.create_project("job-j", "acme", "w", false, "ui", None).unwrap();
        let input = IssueInput { id: "semantic-sast::test/A.java::3".into(), phase: Some(4), category: "semantic-sast".into(), severity: "error".into(), score: Some(8), summary: "weak hash".into(), file: Some("test/A.java".into()), line: Some(3), snippet: None, cross_file: false, chain: None, cwe: None, owasp: None, tool: Some("semgrep".into()), references: None, duplicate_ref: None, author: None, rule: Some("java.weak-hash".into()) };
        db.replace_project_issues(pid, &[input], &HashSet::new());
        db.add_override_with_origin(crate::types::AddOverrideArgs { project_id: pid, job_id: "job-j", phase: 4, issue_id: "semantic-sast::test/A.java::3", category: "semantic-sast", severity: "error", summary: "weak hash", file: Some("test/A.java"), line: Some(3), justification: "test fixture only, never shipped", actor_email: "dev@x.io", actor_name: None, email_sent: false }, "session");
        db.add_override_with_origin(crate::types::AddOverrideArgs { project_id: pid, job_id: "job-j", phase: 4, issue_id: "semantic-sast::test/A.java::3", category: "semantic-sast", severity: "error", summary: "weak hash", file: Some("test/A.java"), line: Some(3), justification: "carried", actor_email: "carried-forward@ignite.internal", actor_name: None, email_sent: false }, "system");
        let j = db.list_override_justifications(Some("acme"), 10);
        assert_eq!(j.len(), 1, "system overrides aren't anyone's words");
        assert_eq!(j[0].rule.as_deref(), Some("java.weak-hash"));
        let noise = db.list_rule_noise(None, 10);
        assert_eq!(noise[0].overrides, 1);
        assert_eq!(db.list_latest_open_issue_locations(Some("acme")).len(), 1);
    }

    #[test]
    fn accepted_proposals_apply_by_org_and_repo_wildcards() {
        let (db, _d) = open_test_db();
        let cats = vec!["semantic-sast".to_string()];
        let files = vec!["^test/".to_string()];
        let id = db.insert_rule_proposal(&NewRuleProposal { org: "acme", repo: "*", categories: &cats, file_patterns: &files, line_patterns: &[], reason: "test code", rationale: "6 justifications say test-only", evidence_override_ids: &[1, 2], match_count: 4 }).unwrap();
        assert!(db.list_accepted_rule_proposals_for("ACME", "any").is_empty(), "proposed isn't active");
        assert!(db.set_rule_proposal_status(id, "accepted", "admin@x.io"));
        let active = db.list_accepted_rule_proposals_for("ACME", "any");
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].file_patterns, files);
        assert!(db.list_accepted_rule_proposals_for("other", "any").is_empty());
    }
}
