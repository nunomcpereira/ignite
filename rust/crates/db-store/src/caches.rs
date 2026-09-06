//! Per-file/manifest/CodeQL/governance-workflow scan-result caches.
//!
//! `impl DbStore` block — one of several per-domain files this crate's
//! accessor methods are split across (see `lib.rs`'s module list).

use crate::store::DbStore;
use crate::types::*;
use rusqlite::{params, OptionalExtension};
use std::collections::HashMap;

impl DbStore {
    // ---------------- per-file scan cache ----------------

    /// Keyed by (org, repo, check_name) so each check keeps its own cache
    /// — a file unchanged since the previous run of this org/repo gets its
    /// stored findings reused instead of being re-evaluated.
    pub fn get_file_scan_cache(&self, org: &str, repo: &str, check_name: &str) -> HashMap<String, FileScanCacheEntry> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare_cached("SELECT rel_path, hash, findings_json FROM file_scan_cache WHERE org = ? AND repo = ? AND check_name = ?")
            .unwrap();
        let rows: Result<Vec<(String, String, String)>, rusqlite::Error> = stmt
            .query_map(params![org, repo, check_name], |row| {
                let rel_path: String = row.get(0)?;
                let hash: String = row.get(1)?;
                let findings_json: String = row.get(2)?;
                Ok((rel_path, hash, findings_json))
            })
            .and_then(|mapped| mapped.collect());
        let rows = match rows {
            Ok(rows) => rows,
            Err(e) => {
                tracing::error!(error = %e, "failed to read file scan cache");
                return HashMap::new();
            }
        };
        // A corrupted findings_json blob just drops that one cache entry
        // (forcing a re-scan of that file) rather than panicking and
        // poisoning the connection mutex for the whole process.
        rows.into_iter()
            .filter_map(|(rel_path, hash, findings_json)| match serde_json::from_str(&findings_json) {
                Ok(findings) => Some((rel_path, FileScanCacheEntry { hash, findings })),
                Err(e) => {
                    tracing::warn!(rel_path, error = %e, "corrupted file scan cache entry, dropping");
                    None
                }
            })
            .collect()
    }

    /// Replaces the entire cache for this (org, repo, check_name): files
    /// that no longer exist (deleted/renamed since the last run) are
    /// dropped rather than accumulating forever.
    pub fn replace_file_scan_cache(&self, org: &str, repo: &str, check_name: &str, entries: &[FileScanCacheInput]) {
        let mut conn = self.conn.lock();
        let tx = conn.transaction().unwrap();
        tx.execute("DELETE FROM file_scan_cache WHERE org = ? AND repo = ? AND check_name = ?", params![org, repo, check_name]).unwrap();
        for entry in entries {
            let findings_json = serde_json::to_string(&entry.findings).unwrap();
            tx.execute(
                "INSERT INTO file_scan_cache (org, repo, check_name, rel_path, hash, findings_json) VALUES (?, ?, ?, ?, ?, ?)",
                params![org, repo, check_name, entry.rel_path, entry.hash, findings_json],
            )
            .unwrap();
        }
        tx.commit().unwrap();
    }

    // ---------------- cosign verify cache (TTL-bound) ----------------

    pub fn get_cosign_verify_cache(&self, image: &str, identity_regexp: &str, issuer_regexp: &str, max_age_seconds: i64) -> Option<CosignVerifyResult> {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT verified, reason FROM cosign_verify_cache
             WHERE image = ? AND identity_regexp = ? AND issuer_regexp = ?
               AND checked_at >= strftime('%Y-%m-%d %H:%M:%f', 'now', '-' || ? || ' seconds')",
            params![image, identity_regexp, issuer_regexp, max_age_seconds],
            |row| Ok(CosignVerifyResult { verified: row.get::<_, i64>(0)? != 0, reason: row.get(1)? }),
        )
        .optional()
        .unwrap()
    }

    pub fn save_cosign_verify_cache(&self, image: &str, identity_regexp: &str, issuer_regexp: &str, verified: bool, reason: Option<&str>) {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO cosign_verify_cache (image, identity_regexp, issuer_regexp, verified, reason)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(image, identity_regexp, issuer_regexp)
             DO UPDATE SET verified = excluded.verified, reason = excluded.reason, checked_at = strftime('%Y-%m-%d %H:%M:%f', 'now')",
            params![image, identity_regexp, issuer_regexp, verified as i64, reason],
        )
        .unwrap();
    }

    // ---------------- manifest-level tool-result cache ----------------

    pub fn get_manifest_scan_cache(&self, tool: &str, ecosystem: &str, content_hash: &str, tool_version: &str) -> Option<serde_json::Value> {
        let conn = self.conn.lock();
        let json: Option<String> = conn
            .query_row(
                "SELECT findings_json FROM manifest_scan_cache WHERE tool = ? AND ecosystem = ? AND content_hash = ? AND tool_version = ?",
                params![tool, ecosystem, content_hash, tool_version],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        json.and_then(|j| match serde_json::from_str(&j) {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::warn!(error = %e, "corrupted manifest scan cache entry, dropping");
                None
            }
        })
    }

    pub fn save_manifest_scan_cache(&self, tool: &str, ecosystem: &str, content_hash: &str, tool_version: &str, findings: &serde_json::Value) {
        let conn = self.conn.lock();
        let json = serde_json::to_string(findings).unwrap();
        conn.execute(
            "INSERT INTO manifest_scan_cache (tool, ecosystem, content_hash, tool_version, findings_json)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(tool, ecosystem, content_hash, tool_version)
             DO UPDATE SET findings_json = excluded.findings_json, updated_at = datetime('now')",
            params![tool, ecosystem, content_hash, tool_version, json],
        )
        .unwrap();
    }

    // ---------------- CodeQL cross-file scan cache ----------------

    pub fn get_codeql_scan_cache(&self, org: &str, repo: &str, language: &str, file_set_hash: &str, tool_version: &str) -> Option<serde_json::Value> {
        let conn = self.conn.lock();
        let json: Option<String> = conn
            .query_row(
                "SELECT findings_json FROM codeql_scan_cache WHERE org = ? AND repo = ? AND language = ? AND file_set_hash = ? AND tool_version = ?",
                params![org, repo, language, file_set_hash, tool_version],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        json.and_then(|j| match serde_json::from_str(&j) {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::warn!(error = %e, "corrupted CodeQL scan cache entry, dropping");
                None
            }
        })
    }

    pub fn save_codeql_scan_cache(&self, org: &str, repo: &str, language: &str, file_set_hash: &str, tool_version: &str, findings: &serde_json::Value) {
        let conn = self.conn.lock();
        let json = serde_json::to_string(findings).unwrap();
        conn.execute(
            "INSERT INTO codeql_scan_cache (org, repo, language, file_set_hash, tool_version, findings_json)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(org, repo, language, file_set_hash, tool_version)
             DO UPDATE SET findings_json = excluded.findings_json, updated_at = datetime('now')",
            params![org, repo, language, file_set_hash, tool_version, json],
        )
        .unwrap();
    }

    // ---------------- governance workflow cache ----------------

    pub fn get_workflow_cache(&self, repo: &str, filename: &str) -> Option<WorkflowCacheEntry> {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT commit_sha, content FROM workflow_cache WHERE repo = ? AND filename = ?",
            params![repo, filename],
            |row| Ok(WorkflowCacheEntry { commit_sha: row.get(0)?, content: row.get(1)? }),
        )
        .optional()
        .unwrap()
    }

    pub fn save_workflow_cache(&self, repo: &str, filename: &str, commit_sha: &str, content: &str) {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO workflow_cache (repo, filename, commit_sha, content, updated_at)
             VALUES (?, ?, ?, ?, datetime('now'))
             ON CONFLICT(repo, filename) DO UPDATE SET commit_sha = excluded.commit_sha, content = excluded.content, updated_at = excluded.updated_at",
            params![repo, filename, commit_sha, content],
        )
        .unwrap();
    }

}
