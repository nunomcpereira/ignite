//! Security campaigns: a human-named, org-wide "burn down every open issue
//! matching this filter by this date" tracker, backing `GET/POST
//! /api/campaigns`. A campaign is just a saved filter (category + minimum
//! `override-engine` score) plus a snapshot of how many currently-open
//! issues matched it at creation time — burndown progress is then always
//! `initial_open_count - <live count of open issues still matching the
//! filter, across every onboarded repo's latest scan>`, so progress never
//! drifts out of sync with overrides/fixes landing after the campaign was
//! created.
//!
//! `impl DbStore` block — one of several per-domain files this crate's
//! accessor methods are split across (see `lib.rs`'s module list).

use crate::store::DbStore;
use crate::types::CampaignRow;
use rusqlite::params;

// Every onboarded (org, repo)'s most recent project row — the same
// "latest scan per repo" join `list_onboarded_repo_summaries` uses, kept
// here as its own CTE since campaigns aggregate across all repos rather
// than reporting per-repo.
const LATEST_PROJECT_PER_REPO_CTE: &str = "WITH latest AS (SELECT org, repo, MAX(id) AS project_id FROM projects GROUP BY org, repo)";

impl DbStore {
    // ---------------- security campaigns ----------------

    pub fn create_campaign(&self, title: &str, description: Option<&str>, category: Option<&str>, min_score: Option<i64>, target_date: Option<&str>, created_by: Option<&str>) -> i64 {
        let conn = self.conn.lock();
        let initial_open_count: i64 = conn
            .query_row(
                &format!(
                    "{LATEST_PROJECT_PER_REPO_CTE}
                     SELECT COUNT(*) FROM issues i JOIN latest l ON l.project_id = i.project_id
                     WHERE i.status = 'open' AND (?1 IS NULL OR i.category = ?1) AND (?2 IS NULL OR COALESCE(i.score, 0) >= ?2)"
                ),
                params![category, min_score],
                |row| row.get(0),
            )
            .unwrap_or(0);
        if let Err(e) = conn.execute(
            "INSERT INTO campaigns (title, description, category, min_score, target_date, initial_open_count, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)",
            params![title, description, category, min_score, target_date, initial_open_count, created_by],
        ) {
            tracing::error!("create_campaign failed for \"{title}\": {e}");
            return 0;
        }
        conn.last_insert_rowid()
    }

    pub fn close_campaign(&self, id: i64) -> bool {
        let conn = self.conn.lock();
        match conn.execute("UPDATE campaigns SET closed_at = datetime('now') WHERE id = ? AND closed_at IS NULL", params![id]) {
            Ok(n) => n > 0,
            Err(e) => {
                tracing::error!("close_campaign failed for {id}: {e}");
                false
            }
        }
    }

    fn matching_open_count(conn: &rusqlite::Connection, category: &Option<String>, min_score: Option<i64>) -> i64 {
        conn.query_row(
            &format!(
                "{LATEST_PROJECT_PER_REPO_CTE}
                 SELECT COUNT(*) FROM issues i JOIN latest l ON l.project_id = i.project_id
                 WHERE i.status = 'open' AND (?1 IS NULL OR i.category = ?1) AND (?2 IS NULL OR COALESCE(i.score, 0) >= ?2)"
            ),
            params![category, min_score],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    pub fn list_campaigns(&self) -> Vec<CampaignRow> {
        let conn = self.conn.lock();
        struct Raw {
            id: i64,
            title: String,
            description: Option<String>,
            category: Option<String>,
            min_score: Option<i64>,
            target_date: Option<String>,
            initial_open_count: i64,
            created_by: Option<String>,
            created_at: String,
            closed_at: Option<String>,
        }
        let Ok(mut stmt) = conn.prepare_cached("SELECT id, title, description, category, min_score, target_date, initial_open_count, created_by, created_at, closed_at FROM campaigns ORDER BY created_at DESC") else {
            return vec![];
        };
        let rows: Vec<Raw> = match stmt.query_map([], |row| {
            Ok(Raw {
                id: row.get(0)?,
                title: row.get(1)?,
                description: row.get(2)?,
                category: row.get(3)?,
                min_score: row.get(4)?,
                target_date: row.get(5)?,
                initial_open_count: row.get(6)?,
                created_by: row.get(7)?,
                created_at: row.get(8)?,
                closed_at: row.get(9)?,
            })
        }) {
            Ok(mapped) => mapped.filter_map(|r| r.ok()).collect(),
            Err(_) => vec![],
        };

        rows.into_iter()
            .map(|r| {
                let open_count = Self::matching_open_count(&conn, &r.category, r.min_score);
                let resolved_count = (r.initial_open_count - open_count).max(0);
                CampaignRow {
                    id: r.id,
                    title: r.title,
                    description: r.description,
                    category: r.category,
                    min_score: r.min_score,
                    target_date: r.target_date,
                    created_by: r.created_by,
                    created_at: r.created_at,
                    closed_at: r.closed_at,
                    open_count,
                    resolved_count,
                }
            })
            .collect()
    }

    pub fn get_campaign(&self, id: i64) -> Option<CampaignRow> {
        self.list_campaigns().into_iter().find(|c| c.id == id)
    }
}
