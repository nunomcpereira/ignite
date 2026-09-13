//! Compliance audit packs (SOC2-style evidence export): pure aggregation
//! over data this crate already collects for other GHAS-parity features —
//! `overrides` (who justified what, when — the change-management audit
//! trail an auditor asks for), `issue_first_seen` (already backing [`crate::sla`]'s
//! SLA-breach math), and `campaigns` — no new detection logic, no new
//! scan/check crate. `routes/compliance.rs` is the HTTP-facing aggregator
//! that also folds in `list_onboarded_repo_summaries`'s live SLA snapshot
//! and `list_campaigns`.
//!
//! `impl DbStore` block — one of several per-domain files this crate's
//! accessor methods are split across (see `lib.rs`'s module list).

use crate::store::DbStore;
use rusqlite::params;
use serde::Serialize;

/// One override ("risk acceptance") that fell inside the requested
/// window — the row-level evidence a SOC2/ISO27001 auditor actually asks
/// for: who accepted what risk, when, and why. `days_to_override` is
/// `NULL` when the finding's `issue_first_seen` row is already gone (the
/// repo was fully re-scanned enough times since that the first-seen
/// timestamp aged out of relevance) — the override itself still counts
/// as evidence, it just can't be timed against a first-detected date
/// that's no longer on record.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OverrideAuditRow {
    pub id: i64,
    pub org: String,
    pub repo: String,
    pub issue_id: String,
    pub category: String,
    pub severity: String,
    pub summary: String,
    pub justification: String,
    pub actor_email: String,
    pub actor_name: Option<String>,
    pub created_at: String,
    pub days_to_override: Option<f64>,
}

/// Time-to-override (a defensible remediation-speed proxy: how long a
/// finding sat open before a human formally accepted the risk) bucketed
/// by severity, for one MTTR summary row.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MttrBucket {
    pub severity: String,
    pub override_count: i64,
    pub avg_days_to_override: Option<f64>,
    pub min_days_to_override: Option<f64>,
    pub max_days_to_override: Option<f64>,
}

impl DbStore {
    // ---------------- compliance audit packs ----------------

    /// Every override created within `[from, to]` (inclusive, compared as
    /// strings against `overrides.created_at`'s own `datetime('now')`
    /// format — callers pass matching `"YYYY-MM-DD HH:MM:SS"` bounds),
    /// across every onboarded repo, newest first.
    pub fn list_overrides_in_range(&self, from: &str, to: &str) -> Vec<OverrideAuditRow> {
        let conn = self.conn.lock();
        // `.unwrap()` on statement prep/row decoding used to panic (and
        // take down the Axum worker thread serving the request) on
        // ordinary transient conditions — lock contention during
        // preparation, or a row with an unexpected `NULL` in a
        // non-nullable column. Empty results / dropped rows are the
        // correct degradation for a read-only compliance report, not a
        // crash.
        let Ok(mut stmt) = conn.prepare_cached(
            "SELECT o.id, p.org, p.repo, o.issue_id, o.category, o.severity, o.summary, o.justification,
                    o.actor_email, o.actor_name, o.created_at,
                    CASE WHEN f.first_detected_at IS NULL THEN NULL
                         ELSE julianday(o.created_at) - julianday(f.first_detected_at) END AS days_to_override
             FROM overrides o
             INNER JOIN projects p ON p.id = o.project_id
             LEFT JOIN issue_first_seen f ON f.org = p.org AND f.repo = p.repo AND f.issue_id = o.issue_id
             WHERE o.created_at BETWEEN ?1 AND ?2 AND o.status = 'approved'
             ORDER BY o.created_at DESC",
        ) else {
            return vec![];
        };
        let Ok(rows) = stmt.query_map(params![from, to], |row| {
            Ok(OverrideAuditRow {
                id: row.get(0)?,
                org: row.get(1)?,
                repo: row.get(2)?,
                issue_id: row.get(3)?,
                category: row.get(4)?,
                severity: row.get(5)?,
                summary: row.get(6)?,
                justification: row.get(7)?,
                actor_email: row.get(8)?,
                actor_name: row.get(9)?,
                created_at: row.get(10)?,
                days_to_override: row.get(11)?,
            })
        }) else {
            return vec![];
        };
        rows.filter_map(|r| r.ok()).collect()
    }

    /// [`MttrBucket`] per severity, over the same window/join as
    /// [`list_overrides_in_range`] — an override with no matching
    /// `issue_first_seen` row (see that method's own doc) contributes to
    /// `override_count` but not to the avg/min/max, same as SQL's own
    /// `AVG`/`MIN`/`MAX` already ignore `NULL`s.
    pub fn mttr_by_severity_in_range(&self, from: &str, to: &str) -> Vec<MttrBucket> {
        let conn = self.conn.lock();
        // `MAX(0, ...)` on each per-row duration, not just the aggregate —
        // a pre-seeded override or a system clock adjustment can leave
        // `created_at` earlier than `first_detected_at`, which without
        // clamping produces a negative "days to override" that then drags
        // AVG/MIN into negative, nonsensical MTTR values.
        let Ok(mut stmt) = conn.prepare_cached(
            "SELECT o.severity, COUNT(*),
                    AVG(MAX(0, julianday(o.created_at) - julianday(f.first_detected_at))),
                    MIN(MAX(0, julianday(o.created_at) - julianday(f.first_detected_at))),
                    MAX(MAX(0, julianday(o.created_at) - julianday(f.first_detected_at)))
             FROM overrides o
             INNER JOIN projects p ON p.id = o.project_id
             LEFT JOIN issue_first_seen f ON f.org = p.org AND f.repo = p.repo AND f.issue_id = o.issue_id
             WHERE o.created_at BETWEEN ?1 AND ?2 AND o.status = 'approved'
             GROUP BY o.severity
             ORDER BY o.severity",
        ) else {
            return vec![];
        };
        let rows: Vec<MttrBucket> = match stmt.query_map(params![from, to], |row| {
            Ok(MttrBucket { severity: row.get(0)?, override_count: row.get(1)?, avg_days_to_override: row.get(2)?, min_days_to_override: row.get(3)?, max_days_to_override: row.get(4)? })
        }) {
            Ok(mapped) => mapped.filter_map(|r| r.ok()).collect(),
            Err(_) => vec![],
        };
        rows
    }
}
