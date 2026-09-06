//! Runtime coverage ingestion (per-file hit counts from an instrumented test run).
//!
//! `impl DbStore` block — one of several per-domain files this crate's
//! accessor methods are split across (see `lib.rs`'s module list).

use crate::store::DbStore;
use crate::types::*;
use rusqlite::{params, OptionalExtension};
use std::collections::HashMap;

impl DbStore {
    // ---------------- runtime coverage ingestion ----------------

    pub fn ingest_runtime_coverage(&self, org: &str, repo: &str, file_stats: &HashMap<String, RuntimeCoverageInput>) -> usize {
        let mut conn = self.conn.lock();
        let tx = conn.transaction().unwrap();
        for (rel_path, stats) in file_stats {
            tx.execute(
                "INSERT INTO runtime_coverage (org, repo, rel_path, hit_count, covered_pct, updated_at)
                 VALUES (?, ?, ?, ?, ?, datetime('now'))
                 ON CONFLICT(org, repo, rel_path) DO UPDATE SET hit_count = excluded.hit_count, covered_pct = excluded.covered_pct, updated_at = excluded.updated_at",
                params![org, repo, rel_path, stats.hit_count, stats.covered_pct],
            )
            .unwrap();
        }
        tx.commit().unwrap();
        file_stats.len()
    }

    pub fn get_runtime_coverage_for_file(&self, org: &str, repo: &str, rel_path: &str) -> Option<RuntimeCoverageRow> {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT hit_count, covered_pct FROM runtime_coverage WHERE org = ? AND repo = ? AND rel_path = ?",
            params![org, repo, rel_path],
            |row| Ok(RuntimeCoverageRow { hit_count: row.get(0)?, covered_pct: row.get(1)? }),
        )
        .optional()
        .unwrap()
    }

    pub fn get_runtime_coverage_map(&self, org: &str, repo: &str) -> HashMap<String, RuntimeCoverageRow> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached("SELECT rel_path, hit_count, covered_pct FROM runtime_coverage WHERE org = ? AND repo = ?").unwrap();
        stmt.query_map(params![org, repo], |row| {
            let rel_path: String = row.get(0)?;
            Ok((rel_path, RuntimeCoverageRow { hit_count: row.get(1)?, covered_pct: row.get(2)? }))
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
    }

    pub fn clear_runtime_coverage(&self, org: &str, repo: &str) -> usize {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM runtime_coverage WHERE org = ? AND repo = ?", params![org, repo]).unwrap()
    }

}
