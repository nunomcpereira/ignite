//! Baseline/diff adoption mode: freeze a project's issue set as pre-existing.
//!
//! `impl DbStore` block — one of several per-domain files this crate's
//! accessor methods are split across (see `lib.rs`'s module list).

use crate::store::DbStore;
use rusqlite::params;
use std::collections::HashSet;

/// A saved baseline: issue ids plus (US-16) fingerprints. An issue counts as
/// baselined when either matches, so a baseline survives code moving above
/// a finding (its id changes, its fingerprint doesn't) and legacy entries
/// saved before fingerprints existed keep matching by id.
#[derive(Debug, Clone, Default)]
pub struct Baseline {
    pub issue_ids: HashSet<String>,
    pub fingerprints: HashSet<String>,
}

impl Baseline {
    pub fn contains(&self, issue_id: &str, fingerprint: &str) -> bool {
        self.issue_ids.contains(issue_id) || self.fingerprints.contains(fingerprint)
    }

    pub fn len(&self) -> usize {
        self.issue_ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.issue_ids.is_empty()
    }
}

impl DbStore {
    // ---------------- baseline/diff adoption mode ----------------

    /// `Err` (transient lock contention, disk write error, busy timeout)
    /// propagates to the caller instead of panicking — this used to
    /// `.unwrap()` every step, which crashed the whole Axum worker thread
    /// handling the request on any transient database failure.
    pub fn save_baseline(&self, org: &str, repo: &str, issue_ids: &[String]) -> rusqlite::Result<usize> {
        let entries: Vec<(String, Option<String>)> = issue_ids.iter().map(|id| (id.clone(), None)).collect();
        self.save_baseline_entries(org, repo, &entries)
    }

    /// Like [`Self::save_baseline`], with each issue's fingerprint (US-16).
    pub fn save_baseline_entries(&self, org: &str, repo: &str, entries: &[(String, Option<String>)]) -> rusqlite::Result<usize> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM issue_baselines WHERE org = ? AND repo = ?", params![org, repo])?;
        for (id, fingerprint) in entries {
            tx.execute("INSERT OR IGNORE INTO issue_baselines (org, repo, issue_id, fingerprint) VALUES (?, ?, ?, ?)", params![org, repo, id, fingerprint])?;
        }
        tx.commit()?;
        Ok(entries.len())
    }

    /// US-16: fingerprint of each issue id as last stored for `org/repo`
    /// (most recent scan wins), so a baseline saved from a list of issue ids
    /// can carry fingerprints too.
    pub fn latest_issue_fingerprints(&self, org: &str, repo: &str) -> std::collections::HashMap<String, String> {
        let conn = self.conn.lock();
        let Ok(mut stmt) = conn.prepare_cached(
            "SELECT i.issue_id, i.fingerprint FROM issues i JOIN projects p ON p.id = i.project_id
             WHERE p.org = ? AND p.repo = ? AND i.fingerprint IS NOT NULL ORDER BY p.id ASC, i.id ASC",
        ) else {
            return Default::default();
        };
        stmt.query_map(params![org, repo], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))).map(|rows| rows.filter_map(|r| r.ok()).collect()).unwrap_or_default()
    }

    pub fn get_baseline(&self, org: &str, repo: &str) -> rusqlite::Result<Baseline> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached("SELECT issue_id, fingerprint FROM issue_baselines WHERE org = ? AND repo = ?")?;
        let rows: Vec<(String, Option<String>)> = stmt.query_map(params![org, repo], |row| Ok((row.get(0)?, row.get(1)?)))?.collect::<rusqlite::Result<_>>()?;
        let mut baseline = Baseline::default();
        for (id, fingerprint) in rows {
            baseline.issue_ids.insert(id);
            if let Some(fp) = fingerprint {
                baseline.fingerprints.insert(fp);
            }
        }
        Ok(baseline)
    }

    pub fn clear_baseline(&self, org: &str, repo: &str) -> rusqlite::Result<usize> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM issue_baselines WHERE org = ? AND repo = ?", params![org, repo])
    }

    pub fn get_baseline_issue_ids(&self, org: &str, repo: &str) -> rusqlite::Result<HashSet<String>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached("SELECT issue_id FROM issue_baselines WHERE org = ? AND repo = ?")?;
        let result = stmt.query_map(params![org, repo], |row| row.get(0))?.collect();
        result
    }

}
