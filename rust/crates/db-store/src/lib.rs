//! SQLite-backed store — faithful port of `db-store.js`. Same schema
//! (verbatim `CREATE TABLE IF NOT EXISTS`/migration DDL), same accessor
//! surface, same behavior (JSON-serialized findings columns, TTL-bound
//! cosign cache, replace-then-reinsert issue lists, etc).
//!
//! Uses `rusqlite`'s bundled SQLite (no system libsqlite3 dependency,
//! matching Node's own bundled `node:sqlite`) and its built-in prepared-
//! statement cache (`prepare_cached`) instead of a hand-maintained `stmt`
//! map — same effect (each unique SQL string is compiled once and reused),
//! idiomatic for the language rather than a literal structural port.
//!
//! Split into `schema` (DDL/migrations), `types` (row/input/output
//! structs), `store` (the `DbStore` handle + constructor), and one
//! `impl DbStore` file per domain (`projects`, `auth`, `caches`, ...) —
//! every domain still ends up as a method directly on `DbStore`, so
//! nothing outside this crate needs to change; only the internal layout
//! moved.
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

mod ai_explanations;
mod api_keys;
mod audit_events;
mod auth;
mod baseline;
mod caches;
mod dependency_and_fixpr;
mod github;
mod issues;
mod overrides;
mod projects;
mod retained_sources;
mod runtime_coverage;
mod schema;
mod scheduled;
mod sla;
mod store;
mod types;
mod campaigns;
mod compliance;
mod custom_secret_patterns;
mod webhook_deliveries;

pub use overrides::GITHUB_DISMISSAL_ACTOR_EMAIL;
pub use store::DbStore;
pub use types::*;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use tempfile::tempdir;

    fn open_test_db() -> (tempfile::TempDir, DbStore) {
        let dir = tempdir().unwrap();
        let store = DbStore::open(&dir.path().join("test.db")).unwrap();
        (dir, store)
    }

    #[test]
    fn create_and_fetch_project_round_trips() {
        let (_dir, store) = open_test_db();
        let id = store.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        let project = store.get_project(id).unwrap();
        assert_eq!(project.org, "acme");
        assert_eq!(project.repo, "widgets");
        assert_eq!(project.status, "running");
        assert!(!project.gxp);
    }

    #[test]
    fn finish_project_updates_status_and_timestamps() {
        let (_dir, store) = open_test_db();
        let id = store.create_project("job-2", "acme", "widgets", false, "ui", None).unwrap();
        store.finish_project("success", None, Some("https://github.com/acme/widgets"), None, id);
        let project = store.get_project(id).unwrap();
        assert_eq!(project.status, "success");
        assert_eq!(project.repo_url.as_deref(), Some("https://github.com/acme/widgets"));
        assert!(project.finished_at.is_some());
    }

    #[test]
    fn finish_project_with_pr_url_records_an_onboarding_pull_request() {
        let (_dir, store) = open_test_db();
        let id = store.create_project("job-pr", "acme", "widgets", false, "ui", None).unwrap();
        store.finish_project("success", None, Some("https://github.com/acme/widgets"), Some("https://github.com/acme/widgets/pull/1"), id);

        let summaries = store.list_onboarded_repo_summaries(7, 30, 90);
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].recent_prs.len(), 1);
        assert_eq!(summaries[0].recent_prs[0].kind, "onboarding");
        assert_eq!(summaries[0].recent_prs[0].url, "https://github.com/acme/widgets/pull/1");
    }

    #[test]
    fn record_pull_request_adds_a_fix_pr_entry_alongside_onboarding() {
        let (_dir, store) = open_test_db();
        let id = store.create_project("job-fix", "acme", "widgets", false, "ui", None).unwrap();
        store.finish_project("success", None, Some("https://github.com/acme/widgets"), Some("https://github.com/acme/widgets/pull/1"), id);
        store.record_pull_request(id, "fix-pr", "https://github.com/acme/widgets/pull/2", Some("ignite/fix-issues/job-fix"), Some(3));

        let summaries = store.list_onboarded_repo_summaries(7, 30, 90);
        let prs = &summaries[0].recent_prs;
        assert_eq!(prs.len(), 2);
        assert!(prs.iter().any(|p| p.kind == "fix-pr" && p.url == "https://github.com/acme/widgets/pull/2" && p.files_changed == Some(3)));
        assert!(prs.iter().any(|p| p.kind == "onboarding"));
    }

    #[test]
    fn list_onboarded_repo_summaries_uses_latest_run_for_counts_but_full_history_for_acks_and_prs() {
        let (_dir, store) = open_test_db();
        let old_id = store.create_project("job-old", "acme", "widgets", false, "ui", None).unwrap();
        store.add_override(AddOverrideArgs {
            project_id: old_id,
            job_id: "job-old",
            phase: 4,
            issue_id: "license-compliance::pom.xml::1",
            category: "license-compliance",
            severity: "error",
            summary: "commercial dependency",
            file: Some("pom.xml"),
            line: Some(1),
            justification: "reviewed, approved for internal use",
            actor_email: "dev@acme.example",
            actor_name: Some("Dev"),
            email_sent: true,
        });

        let new_id = store.create_project("job-new", "acme", "widgets", false, "ui", None).unwrap();
        store.replace_project_issues(
            new_id,
            &[
                IssueInput { id: "secret::app.py::1".into(), phase: Some(2), category: "secret".into(), severity: "error".into(), score: Some(9), summary: "hardcoded key".into(), file: Some("app.py".into()), line: Some(1), snippet: None, cross_file: false, chain: None, cwe: None, owasp: None, tool: None, references: None, duplicate_ref: None },
                IssueInput { id: "license-compliance::pom.xml::1".into(), phase: Some(3), category: "license-compliance".into(), severity: "error".into(), score: Some(6), summary: "commercial dependency".into(), file: Some("pom.xml".into()), line: Some(1), snippet: None, cross_file: false, chain: None, cwe: None, owasp: None, tool: None, references: None, duplicate_ref: None },
            ],
            &HashSet::new(),
        );

        let summaries = store.list_onboarded_repo_summaries(7, 30, 90);
        assert_eq!(summaries.len(), 1, "same (org, repo) across two runs must collapse to one row");
        let summary = &summaries[0];
        assert_eq!(summary.latest_project_id, new_id, "must key off the latest run, not the first");
        assert_eq!(summary.findings_count, 2, "counts come from the latest run's open issues only");
        assert_eq!(summary.license_problems, 1);
        assert_eq!(summary.acknowledgments.len(), 1, "acknowledgments span every run for the repo, not just the latest");
    }

    #[test]
    fn set_project_commit_shas_coalesces_and_does_not_clobber() {
        let (_dir, store) = open_test_db();
        let id = store.create_project("job-commit", "acme", "widgets", false, "ui", None).unwrap();
        store.set_project_commit_shas(id, Some("abc123"), None);
        let project = store.get_project(id).unwrap();
        assert_eq!(project.source_commit_sha.as_deref(), Some("abc123"));
        assert_eq!(project.shipped_commit_sha, None);

        store.set_project_commit_shas(id, None, Some("def456"));
        let project = store.get_project(id).unwrap();
        assert_eq!(project.source_commit_sha.as_deref(), Some("abc123"));
        assert_eq!(project.shipped_commit_sha.as_deref(), Some("def456"));
    }

    #[test]
    fn retain_project_source_defaults_full_and_updates_tier() {
        let (_dir, store) = open_test_db();
        let id = store.create_project("job-retain", "acme", "widgets", false, "ui", None).unwrap();
        store.retain_project_source(id, "/tmp/retained/1", "full");
        let rows = store.list_retained_sources();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].tier, "full");

        store.set_retained_source_tier(id, "pruned");
        let rows = store.list_retained_sources();
        assert_eq!(rows[0].tier, "pruned");
    }

    #[test]
    fn list_evictable_retained_sources_respects_keep_across_tiers() {
        let (_dir, store) = open_test_db();
        for i in 0..12 {
            let id = store.create_project(&format!("job-evict-{i}"), "acme", "widgets", false, "ui", None).unwrap();
            let tier = if i < 5 { "full" } else { "pruned" };
            store.retain_project_source(id, &format!("/tmp/retained/{i}"), tier);
        }
        let evictable = store.list_evictable_retained_sources(10);
        assert_eq!(evictable.len(), 2, "expected exactly 2 rows beyond the 10 most recently retained");
    }

    #[test]
    fn upsert_step_updates_in_place_on_conflict() {
        let (_dir, store) = open_test_db();
        let id = store.create_project("job-3", "acme", "widgets", false, "ui", None).unwrap();
        store.upsert_step(id, 4, "Security Scan", "running", "log line 1");
        store.upsert_step(id, 4, "Security Scan", "success", "log line 1\nlog line 2");
        let details = store.get_project_details(id).unwrap();
        assert_eq!(details.steps.len(), 1);
        assert_eq!(details.steps[0].state, "success");
        assert_eq!(details.steps[0].logs, "log line 1\nlog line 2");
    }

    #[test]
    fn delete_project_by_id_also_clears_file_scan_cache_for_its_repo() {
        let (_dir, store) = open_test_db();
        let id = store.create_project("job-4", "acme", "widgets", false, "ui", None).unwrap();
        store.replace_file_scan_cache(
            "acme",
            "widgets",
            "secrets",
            &[FileScanCacheInput { rel_path: "a.js".into(), hash: "h1".into(), findings: serde_json::json!([]) }],
        );
        store.delete_project_by_id(id);
        assert!(!store.project_exists(id));
        assert!(store.get_file_scan_cache("acme", "widgets", "secrets").is_empty());
    }

    #[test]
    fn replace_project_issues_marks_overridden_status_and_round_trips_json_columns() {
        let (_dir, store) = open_test_db();
        let id = store.create_project("job-5", "acme", "widgets", false, "ui", None).unwrap();
        let issues = vec![
            IssueInput {
                id: "secret::a.js::3".into(),
                phase: Some(4),
                category: "secret".into(),
                severity: "error".into(),
                score: Some(8),
                summary: "hardcoded key".into(),
                file: Some("a.js".into()),
                line: Some(3),
                snippet: Some(serde_json::json!({"startLine": 1, "lines": []})),
                cross_file: false,
                chain: None,
                cwe: Some("CWE-798".into()),
                owasp: Some("A02:2021 - Cryptographic Failures".into()),
                tool: Some("built-in".into()),
                references: Some(serde_json::json!({"cwe": ["CWE-798"]})),
                duplicate_ref: None,
            },
            IssueInput {
                id: "codeql-sast::b.js::10".into(),
                phase: Some(4),
                category: "codeql-sast".into(),
                severity: "error".into(),
                score: Some(9),
                summary: "taint flow".into(),
                file: Some("b.js".into()),
                line: Some(10),
                snippet: None,
                cross_file: true,
                chain: Some(serde_json::json!([{"file": "a.js", "line": 1}])),
                cwe: None,
                owasp: None,
                tool: Some("codeql".into()),
                references: None,
                duplicate_ref: Some(serde_json::json!({"file": "c.js", "line": 21, "endLine": 29})),
            },
        ];
        let mut overridden = HashSet::new();
        overridden.insert("secret::a.js::3".to_string());
        store.replace_project_issues(id, &issues, &overridden);

        let rows = store.get_project_issues(id);
        assert_eq!(rows.len(), 2);
        let secret = rows.iter().find(|r| r.id == "secret::a.js::3").unwrap();
        assert_eq!(secret.status, "overridden");
        assert!(secret.snippet.is_some());
        assert_eq!(secret.tool.as_deref(), Some("built-in"));
        assert_eq!(secret.owasp.as_deref(), Some("A02:2021 - Cryptographic Failures"));
        assert_eq!(secret.references, Some(serde_json::json!({"cwe": ["CWE-798"]})));
        let codeql = rows.iter().find(|r| r.id == "codeql-sast::b.js::10").unwrap();
        assert_eq!(codeql.status, "open");
        assert!(codeql.cross_file);
        assert!(codeql.chain.is_some());
        assert_eq!(codeql.tool.as_deref(), Some("codeql"));
        assert_eq!(codeql.duplicate_ref, Some(serde_json::json!({"file": "c.js", "line": 21, "endLine": 29})));
        assert_eq!(secret.duplicate_ref, None);

        // The frontend (public/index.html) reads issue.crossFile, not
        // issue.cross_file - the API-facing JSON must use camelCase.
        let json = serde_json::to_value(codeql).unwrap();
        assert_eq!(json["crossFile"], serde_json::json!(true));
        assert!(json.get("cross_file").is_none());
    }

    /// `get_project_issues` must join in the actual override so a
    /// per-issue detail panel (Ignite Studio) can show who justified a
    /// finding and why without a second request — regression coverage for
    /// the gap where an overridden issue's `status` flipped to
    /// "overridden" but `justification`/`actorEmail`/`actorName` stayed
    /// absent, so the UI had nothing to render beyond a generic badge.
    #[test]
    fn get_project_issues_joins_in_the_latest_overrides_justification_and_actor() {
        let (_dir, store) = open_test_db();
        let id = store.create_project("job-8", "acme", "widgets", false, "ui", None).unwrap();
        store.replace_project_issues(
            id,
            &[IssueInput { id: "license-compliance::requirements.txt::0::PyMuPDF".into(), phase: Some(4), category: "license-compliance".into(), severity: "error".into(), score: Some(6), summary: "Unrecognized license".into(), file: Some("requirements.txt".into()), line: Some(9), snippet: None, cross_file: false, chain: None, cwe: None, owasp: None, tool: None, references: None, duplicate_ref: None }],
            &HashSet::new(),
        );
        // Not yet overridden — no justification/actor to show.
        let before = store.get_project_issues(id);
        assert_eq!(before[0].status, "open");
        assert!(before[0].justification.is_none());
        assert!(before[0].actor_email.is_none());

        store.add_override(AddOverrideArgs {
            project_id: id,
            job_id: "job-8",
            phase: 4,
            issue_id: "license-compliance::requirements.txt::0::PyMuPDF",
            category: "license-compliance",
            severity: "error",
            summary: "Unrecognized license",
            file: Some("requirements.txt"),
            line: Some(9),
            justification: "PyMuPDF is AGPL-3.0, a real license the scanner failed to parse.",
            actor_email: "ai-assist@ignite.internal",
            actor_name: Some("Ignite AI Assist"),
            email_sent: false,
        });
        let mut overridden = HashSet::new();
        overridden.insert("license-compliance::requirements.txt::0::PyMuPDF".to_string());
        store.replace_project_issues(
            id,
            &[IssueInput { id: "license-compliance::requirements.txt::0::PyMuPDF".into(), phase: Some(4), category: "license-compliance".into(), severity: "error".into(), score: Some(6), summary: "Unrecognized license".into(), file: Some("requirements.txt".into()), line: Some(9), snippet: None, cross_file: false, chain: None, cwe: None, owasp: None, tool: None, references: None, duplicate_ref: None }],
            &overridden,
        );

        let after = store.get_project_issues(id);
        assert_eq!(after[0].status, "overridden");
        assert_eq!(after[0].justification.as_deref(), Some("PyMuPDF is AGPL-3.0, a real license the scanner failed to parse."));
        assert_eq!(after[0].actor_email.as_deref(), Some("ai-assist@ignite.internal"));
        assert_eq!(after[0].actor_name.as_deref(), Some("Ignite AI Assist"));

        // The API-facing JSON must be camelCase, same convention as every
        // other field on this row.
        let json = serde_json::to_value(&after[0]).unwrap();
        assert_eq!(json["actorEmail"], serde_json::json!("ai-assist@ignite.internal"));
        assert!(json.get("actor_email").is_none());
    }

    #[test]
    fn cosign_verify_cache_respects_ttl() {
        let (_dir, store) = open_test_db();
        store.save_cosign_verify_cache("nginx:latest", ".*", ".*", true, None);
        assert!(store.get_cosign_verify_cache("nginx:latest", ".*", ".*", 3600).is_some());
        // Same reasoning as the JS suite's own TTL test: a max_age_seconds
        // of 0 means "must have been checked in the last 0 seconds",
        // which a row written even a moment ago can't satisfy.
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(store.get_cosign_verify_cache("nginx:latest", ".*", ".*", 0).is_none());
    }

    #[test]
    fn baseline_round_trips_and_clears() {
        let (_dir, store) = open_test_db();
        let saved = store.save_baseline("acme", "widgets", &["a".into(), "b".into()]).unwrap();
        assert_eq!(saved, 2);
        let ids = store.get_baseline_issue_ids("acme", "widgets").unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains("a"));
        let cleared = store.clear_baseline("acme", "widgets").unwrap();
        assert_eq!(cleared, 2);
        assert!(store.get_baseline_issue_ids("acme", "widgets").unwrap().is_empty());
    }

    #[test]
    fn runtime_coverage_ingest_and_map() {
        let (_dir, store) = open_test_db();
        let mut stats = HashMap::new();
        stats.insert("src/a.js".to_string(), RuntimeCoverageInput { hit_count: 5, covered_pct: Some(80.0) });
        let count = store.ingest_runtime_coverage("acme", "widgets", &stats);
        assert_eq!(count, 1);
        let row = store.get_runtime_coverage_for_file("acme", "widgets", "src/a.js").unwrap();
        assert_eq!(row.hit_count, 5);
        assert_eq!(row.covered_pct, Some(80.0));
        let map = store.get_runtime_coverage_map("acme", "widgets");
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn dependency_scan_cache_tracks_the_previous_scan_on_overwrite() {
        let (_dir, store) = open_test_db();
        let project_id = store.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();

        assert!(store.get_dependency_scan_cache(project_id).is_none());
        assert!(store.get_previous_dependency_scan_cache(project_id).is_none());

        let first = serde_json::json!({"manifests": [{"file": "package.json"}]});
        store.save_dependency_scan_cache(project_id, &first);
        assert_eq!(store.get_dependency_scan_cache(project_id), Some(first.clone()));
        assert!(store.get_previous_dependency_scan_cache(project_id).is_none());

        let second = serde_json::json!({"manifests": [{"file": "package.json"}, {"file": "Cargo.toml"}]});
        store.save_dependency_scan_cache(project_id, &second);
        assert_eq!(store.get_dependency_scan_cache(project_id), Some(second));
        assert_eq!(store.get_previous_dependency_scan_cache(project_id), Some(first));
    }

    #[test]
    fn api_key_lifecycle_create_lookup_revoke() {
        let (_dir, store) = open_test_db();
        let user_id = store.create_local_user("dev@example.com", Some("Dev"), "hash").unwrap();
        let key_id = store.create_api_key(user_id, "sha256hash", Some("laptop"), Some("dev@example.com"), "cli");
        let identity = store.get_active_api_key_by_hash("sha256hash").unwrap();
        assert_eq!(identity.user_id, user_id);
        assert!(store.revoke_api_key(key_id, user_id));
        assert!(store.get_active_api_key_by_hash("sha256hash").is_none());
    }

    #[test]
    fn revoke_api_key_refuses_to_revoke_another_users_key() {
        let (_dir, store) = open_test_db();
        let owner_id = store.create_local_user("owner@example.com", Some("Owner"), "hash").unwrap();
        let other_id = store.create_local_user("other@example.com", Some("Other"), "hash").unwrap();
        let key_id = store.create_api_key(owner_id, "sha256hash", Some("laptop"), Some("owner@example.com"), "cli");
        assert!(!store.revoke_api_key(key_id, other_id));
        assert!(store.get_active_api_key_by_hash("sha256hash").is_some());
        assert!(store.revoke_api_key(key_id, owner_id));
        assert!(store.get_active_api_key_by_hash("sha256hash").is_none());
    }

    #[test]
    fn abort_stale_running_projects_marks_running_as_aborted() {
        let (_dir, store) = open_test_db();
        let id = store.create_project("job-6", "acme", "widgets", false, "ui", None).unwrap();
        store.upsert_step(id, 4, "Security Scan", "running", "in progress");
        store.abort_stale_running_projects();
        let project = store.get_project(id).unwrap();
        assert_eq!(project.status, "aborted");
        assert!(project.error.is_some());
        let details = store.get_project_details(id).unwrap();
        assert_eq!(details.steps[0].state, "failed");
        assert!(details.steps[0].logs.contains("Server restarted"));
    }

    #[test]
    fn get_carry_forward_overrides_matches_by_issue_id_across_repeat_scans_of_the_same_repo() {
        let (_dir, store) = open_test_db();
        let old_id = store.create_project("job-old", "acme", "widgets", false, "ui", None).unwrap();
        store.add_override(AddOverrideArgs {
            project_id: old_id,
            job_id: "job-old",
            phase: 4,
            issue_id: "license-compliance::requirements.txt::0::PyMuPDF",
            category: "license-compliance",
            severity: "error",
            summary: "Unrecognized license",
            file: Some("requirements.txt"),
            line: Some(9),
            justification: "PyMuPDF is AGPL-3.0, a real permissive-adjacent license the scanner failed to parse.",
            actor_email: "dev@acme.example",
            actor_name: Some("Dev"),
            email_sent: false,
        });

        // A second scan of a *different* repo must never see the first
        // repo's overrides.
        let other_repo_id = store.create_project("job-other-repo", "acme", "gizmos", false, "ui", None).unwrap();
        let none_for_other_repo = store.get_carry_forward_overrides("acme", "gizmos", other_repo_id);
        assert!(none_for_other_repo.is_empty());

        let new_id = store.create_project("job-new", "acme", "widgets", false, "ui", None).unwrap();
        let carried = store.get_carry_forward_overrides("acme", "widgets", new_id);
        assert_eq!(carried.len(), 1);
        let row = &carried["license-compliance::requirements.txt::0::PyMuPDF"];
        assert!(row.justification.contains("AGPL-3.0"));

        // The current scan's own project id is excluded, so a run doesn't
        // "carry forward" its own just-written overrides.
        let self_id = new_id;
        store.add_override(AddOverrideArgs {
            project_id: self_id,
            job_id: "job-new",
            phase: 4,
            issue_id: "secret::app.js::5",
            category: "secret",
            severity: "error",
            summary: "hardcoded key",
            file: Some("app.js"),
            line: Some(5),
            justification: "test fixture",
            actor_email: "dev@acme.example",
            actor_name: None,
            email_sent: false,
        });
        let carried_excluding_self = store.get_carry_forward_overrides("acme", "widgets", self_id);
        assert!(!carried_excluding_self.contains_key("secret::app.js::5"));
    }

    #[test]
    fn get_latest_project_for_org_repo_returns_the_most_recently_created_project() {
        let (_dir, store) = open_test_db();
        assert!(store.get_latest_project_for_org_repo("acme", "widgets").is_none());
        store.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        let (id2, job_id2) = (store.create_project("job-2", "acme", "widgets", false, "ui", None).unwrap(), "job-2".to_string());
        let (found_id, found_job_id) = store.get_latest_project_for_org_repo("acme", "widgets").unwrap();
        assert_eq!(found_id, id2);
        assert_eq!(found_job_id, job_id2);
    }

    #[test]
    fn github_dismissal_webhook_round_trip_marks_overridden_then_reopens_to_open() {
        let (_dir, store) = open_test_db();
        let project_id = store.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        store.replace_project_issues(
            project_id,
            &[IssueInput { id: "secret::app.js::5".to_string(), phase: Some(4), category: "secret".to_string(), severity: "error".to_string(), score: Some(9), summary: "hardcoded key".to_string(), file: Some("app.js".to_string()), line: Some(5), snippet: None, cross_file: false, chain: None, cwe: None, owasp: None, tool: None, references: None, duplicate_ref: None }],
            &HashSet::new(),
        );
        assert_eq!(store.get_project_issues(project_id)[0].status, "open");

        // Simulate the inbound webhook's "dismissed" handling.
        store.add_override(AddOverrideArgs {
            project_id,
            job_id: "job-1",
            phase: 4,
            issue_id: "secret::app.js::5",
            category: "secret",
            severity: "error",
            summary: "hardcoded key",
            file: Some("app.js"),
            line: Some(5),
            justification: "Dismissed on GitHub: false positive",
            actor_email: overrides::GITHUB_DISMISSAL_ACTOR_EMAIL,
            actor_name: Some("octocat"),
            email_sent: false,
        });
        store.set_issue_status(project_id, "secret::app.js::5", "overridden");
        let issues = store.get_project_issues(project_id);
        assert_eq!(issues[0].status, "overridden");
        assert_eq!(issues[0].actor_email.as_deref(), Some(overrides::GITHUB_DISMISSAL_ACTOR_EMAIL));

        // Simulate the inbound webhook's "reopened" handling.
        let removed = store.delete_github_dismissal_overrides("acme", "widgets", "secret::app.js::5");
        assert_eq!(removed, 1);
        assert!(!store.issue_has_override(project_id, "secret::app.js::5"));
        store.set_issue_status(project_id, "secret::app.js::5", "open");
        assert_eq!(store.get_project_issues(project_id)[0].status, "open");
    }

    #[test]
    fn reopened_webhook_leaves_a_real_ignite_override_untouched() {
        let (_dir, store) = open_test_db();
        let project_id = store.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        store.add_override(AddOverrideArgs {
            project_id,
            job_id: "job-1",
            phase: 4,
            issue_id: "secret::app.js::5",
            category: "secret",
            severity: "error",
            summary: "hardcoded key",
            file: Some("app.js"),
            line: Some(5),
            justification: "justified by a human in Ignite",
            actor_email: "dev@acme.example",
            actor_name: None,
            email_sent: false,
        });
        // A GitHub reopen only ever deletes rows it created itself.
        let removed = store.delete_github_dismissal_overrides("acme", "widgets", "secret::app.js::5");
        assert_eq!(removed, 0);
        assert!(store.issue_has_override(project_id, "secret::app.js::5"));
    }

    #[test]
    fn get_carry_forward_overrides_keeps_only_the_most_recent_justification_per_issue_id() {
        let (_dir, store) = open_test_db();
        let first_id = store.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        store.add_override(AddOverrideArgs {
            project_id: first_id,
            job_id: "job-1",
            phase: 4,
            issue_id: "license-compliance::requirements.txt::0::regex",
            category: "license-compliance",
            severity: "error",
            summary: "Unrecognized license",
            file: Some("requirements.txt"),
            line: Some(14),
            justification: "stale reasoning",
            actor_email: "dev@acme.example",
            actor_name: None,
            email_sent: false,
        });
        let second_id = store.create_project("job-2", "acme", "widgets", false, "ui", None).unwrap();
        store.add_override(AddOverrideArgs {
            project_id: second_id,
            job_id: "job-2",
            phase: 4,
            issue_id: "license-compliance::requirements.txt::0::regex",
            category: "license-compliance",
            severity: "error",
            summary: "Unrecognized license",
            file: Some("requirements.txt"),
            line: Some(14),
            justification: "current reasoning",
            actor_email: "dev@acme.example",
            actor_name: None,
            email_sent: false,
        });

        let third_id = store.create_project("job-3", "acme", "widgets", false, "ui", None).unwrap();
        let carried = store.get_carry_forward_overrides("acme", "widgets", third_id);
        assert_eq!(carried["license-compliance::requirements.txt::0::regex"].justification, "current reasoning");
    }

    #[test]
    fn fix_pr_preview_round_trips_and_survives_a_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.db");
        let candidates = serde_json::json!([{ "issueId": "secret::app.js::5", "file": "app.js" }]);
        {
            let store = DbStore::open(&path).unwrap();
            assert!(store.get_fix_pr_preview("job-1").is_none());
            store.save_fix_pr_preview(&crate::types::SaveFixPrPreviewParams { job_id: "job-1", total: 3, completed: 3, cancelled: false, considered_count: 3, reason: None, candidates: &candidates });
            let row = store.get_fix_pr_preview("job-1").unwrap();
            assert_eq!(row.total, 3);
            assert_eq!(row.completed, 3);
            assert!(!row.cancelled);
            assert_eq!(row.candidates, candidates);
        }
        // Simulates the server-restart case this table exists for: a fresh
        // DbStore handle reopening the same on-disk file must still see
        // the finished job.
        let reopened = DbStore::open(&path).unwrap();
        let row = reopened.get_fix_pr_preview("job-1").unwrap();
        assert_eq!(row.candidates, candidates);
    }

    #[test]
    fn fix_pr_preview_save_overwrites_a_prior_save_for_the_same_job() {
        let (_dir, store) = open_test_db();
        store.save_fix_pr_preview(&crate::types::SaveFixPrPreviewParams { job_id: "job-1", total: 5, completed: 2, cancelled: false, considered_count: 5, reason: None, candidates: &serde_json::json!([]) });
        store.save_fix_pr_preview(&crate::types::SaveFixPrPreviewParams { job_id: "job-1", total: 5, completed: 5, cancelled: true, considered_count: 5, reason: Some("cancelled by user"), candidates: &serde_json::json!([{ "issueId": "a" }]) });
        let row = store.get_fix_pr_preview("job-1").unwrap();
        assert_eq!(row.completed, 5);
        assert!(row.cancelled);
        assert_eq!(row.reason.as_deref(), Some("cancelled by user"));
    }

    #[test]
    fn migrations_are_idempotent_across_two_opens_of_the_same_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.db");
        {
            let store = DbStore::open(&path).unwrap();
            store.create_project("job-7", "acme", "widgets", false, "ui", None).unwrap();
        }
        // Reopening the same on-disk DB re-runs schema + migrations against
        // already-existing tables/columns — must not error.
        let store2 = DbStore::open(&path).unwrap();
        assert_eq!(store2.list_projects().len(), 1);
    }

    #[test]
    fn every_migration_version_is_recorded_exactly_once() {
        let (_dir, store) = open_test_db();
        let conn = store.conn.lock();
        let recorded: i64 = conn.query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| row.get(0)).unwrap();
        assert_eq!(recorded as usize, crate::schema::MIGRATIONS.len());
        for (version, _) in crate::schema::MIGRATIONS {
            let count: i64 = conn.query_row("SELECT COUNT(*) FROM schema_migrations WHERE version = ?", [version], |row| row.get(0)).unwrap();
            assert_eq!(count, 1, "version {version} should be recorded exactly once");
        }
    }

    #[test]
    fn reopening_does_not_reinsert_already_applied_migration_rows() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.db");
        DbStore::open(&path).unwrap();
        let store2 = DbStore::open(&path).unwrap();
        let conn = store2.conn.lock();
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| row.get(0)).unwrap();
        assert_eq!(count as usize, crate::schema::MIGRATIONS.len());
    }

    #[test]
    fn a_pre_existing_db_with_columns_already_applied_but_no_tracking_table_backfills_cleanly() {
        // Simulates a DB created before `schema_migrations` existed: schema
        // + every migration's DDL already applied by hand, but no tracking
        // table yet. `run_migrations` must swallow the resulting "duplicate
        // column" errors once and backfill `schema_migrations`, not fail.
        let dir = tempdir().unwrap();
        let path = dir.path().join("legacy.db");
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(crate::schema::SCHEMA_SQL).unwrap();
            for (_, ddl) in crate::schema::MIGRATIONS {
                // Fresh `SCHEMA_SQL` already declares every column these
                // migrations add (that's how a genuinely pre-versioning DB
                // ended up with them too, over time) — swallow the
                // resulting "duplicate column", same as the old pre-tracking
                // runner always did.
                if let Err(e) = conn.execute_batch(ddl) {
                    assert!(e.to_string().to_lowercase().contains("duplicate column"), "unexpected error: {e}");
                }
            }
            // No schema_migrations table at all — the pre-versioning state.
        }
        let store = DbStore::open(&path).unwrap();
        let conn = store.conn.lock();
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| row.get(0)).unwrap();
        assert_eq!(count as usize, crate::schema::MIGRATIONS.len());
    }

    #[test]
    fn custom_secret_pattern_create_and_get_round_trips_fields() {
        let (_dir, store) = open_test_db();
        let id = store.create_custom_secret_pattern("Internal Token", r"tok_[a-z0-9]{16}", Some("dev@acme.com")).unwrap();
        let row = store.get_custom_secret_pattern(id).unwrap();
        assert_eq!(row.name, "Internal Token");
        assert_eq!(row.regex, r"tok_[a-z0-9]{16}");
        assert!(row.enabled, "a newly-created pattern must default to enabled");
        assert_eq!(row.created_by.as_deref(), Some("dev@acme.com"));
    }

    #[test]
    fn custom_secret_pattern_get_returns_none_for_unknown_id() {
        let (_dir, store) = open_test_db();
        assert!(store.get_custom_secret_pattern(999).is_none());
    }

    #[test]
    fn custom_secret_pattern_disabling_removes_from_enabled_list_but_not_full_list() {
        let (_dir, store) = open_test_db();
        let id = store.create_custom_secret_pattern("Pattern", "a", None).unwrap();
        assert!(store.set_custom_secret_pattern_enabled(id, false));
        assert!(store.list_enabled_custom_secret_patterns().is_empty());
        assert_eq!(store.list_custom_secret_patterns().len(), 1);
        assert!(!store.get_custom_secret_pattern(id).unwrap().enabled);
    }

    #[test]
    fn custom_secret_pattern_set_enabled_returns_false_for_unknown_id() {
        let (_dir, store) = open_test_db();
        assert!(!store.set_custom_secret_pattern_enabled(999, true));
    }

    #[test]
    fn custom_secret_pattern_delete_removes_row_and_reports_whether_one_existed() {
        let (_dir, store) = open_test_db();
        let id = store.create_custom_secret_pattern("Pattern", "a", None).unwrap();
        assert!(store.delete_custom_secret_pattern(id));
        assert!(store.get_custom_secret_pattern(id).is_none());
        assert!(!store.delete_custom_secret_pattern(id), "deleting again must report nothing existed");
    }

    /// Seeds one override + a matching `issue_first_seen` row with
    /// explicit (not `datetime('now')`-default) timestamps, so tests can
    /// assert an exact `days_to_override` — `add_override`/
    /// `replace_project_issues` always stamp "now", which isn't
    /// deterministic enough for that.
    #[allow(clippy::too_many_arguments)]
    fn seed_override_with_timestamps(store: &DbStore, project_id: i64, org: &str, repo: &str, issue_id: &str, severity: &str, first_detected_at: &str, override_created_at: &str) {
        let conn = store.conn.lock();
        conn.execute("INSERT INTO issue_first_seen (org, repo, issue_id, first_detected_at) VALUES (?, ?, ?, ?)", rusqlite::params![org, repo, issue_id, first_detected_at]).unwrap();
        conn.execute(
            "INSERT INTO overrides (project_id, job_id, phase, issue_id, category, severity, summary, justification, actor_email, actor_name, created_at) VALUES (?, 'job-1', 4, ?, 'secret', ?, 'summary', 'justified', 'dev@acme.com', 'Dev', ?)",
            rusqlite::params![project_id, issue_id, severity, override_created_at],
        )
        .unwrap();
    }

    #[test]
    fn compliance_list_overrides_in_range_computes_days_to_override() {
        let (_dir, store) = open_test_db();
        let project_id = store.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        seed_override_with_timestamps(&store, project_id, "acme", "widgets", "secret::a.js::1", "error", "2026-01-01 00:00:00", "2026-01-05 00:00:00");

        let rows = store.list_overrides_in_range("2026-01-01 00:00:00", "2026-01-31 23:59:59");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].org, "acme");
        assert_eq!(rows[0].repo, "widgets");
        assert_eq!(rows[0].days_to_override, Some(4.0));
    }

    #[test]
    fn compliance_list_overrides_in_range_excludes_outside_window() {
        let (_dir, store) = open_test_db();
        let project_id = store.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        seed_override_with_timestamps(&store, project_id, "acme", "widgets", "secret::a.js::1", "error", "2025-12-01 00:00:00", "2025-12-05 00:00:00");

        let rows = store.list_overrides_in_range("2026-01-01 00:00:00", "2026-01-31 23:59:59");
        assert!(rows.is_empty());
    }

    #[test]
    fn compliance_days_to_override_is_null_without_a_first_seen_row() {
        let (_dir, store) = open_test_db();
        let project_id = store.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        // No issue_first_seen row inserted — override exists on its own.
        let conn = store.conn.lock();
        conn.execute(
            "INSERT INTO overrides (project_id, job_id, phase, issue_id, category, severity, summary, justification, actor_email, created_at) VALUES (?, 'job-1', 4, 'secret::b.js::1', 'secret', 'error', 's', 'j', 'dev@acme.com', '2026-01-05 00:00:00')",
            rusqlite::params![project_id],
        )
        .unwrap();
        drop(conn);

        let rows = store.list_overrides_in_range("2026-01-01 00:00:00", "2026-01-31 23:59:59");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].days_to_override, None);
    }

    #[test]
    fn compliance_mttr_by_severity_in_range_aggregates_per_severity() {
        let (_dir, store) = open_test_db();
        let project_id = store.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        seed_override_with_timestamps(&store, project_id, "acme", "widgets", "secret::a.js::1", "error", "2026-01-01 00:00:00", "2026-01-03 00:00:00"); // 2 days
        seed_override_with_timestamps(&store, project_id, "acme", "widgets", "secret::b.js::1", "error", "2026-01-01 00:00:00", "2026-01-07 00:00:00"); // 6 days
        seed_override_with_timestamps(&store, project_id, "acme", "widgets", "secret::c.js::1", "warning", "2026-01-01 00:00:00", "2026-01-02 00:00:00"); // 1 day

        let buckets = store.mttr_by_severity_in_range("2026-01-01 00:00:00", "2026-01-31 23:59:59");
        assert_eq!(buckets.len(), 2);
        let error_bucket = buckets.iter().find(|b| b.severity == "error").unwrap();
        assert_eq!(error_bucket.override_count, 2);
        assert_eq!(error_bucket.avg_days_to_override, Some(4.0));
        assert_eq!(error_bucket.min_days_to_override, Some(2.0));
        assert_eq!(error_bucket.max_days_to_override, Some(6.0));
        let warning_bucket = buckets.iter().find(|b| b.severity == "warning").unwrap();
        assert_eq!(warning_bucket.override_count, 1);
        assert_eq!(warning_bucket.avg_days_to_override, Some(1.0));
    }

    fn pending_args<'a>(project_id: i64, issue_id: &'a str, actor_email: &'a str) -> AddOverrideArgs<'a> {
        AddOverrideArgs { project_id, job_id: "job-1", phase: 4, issue_id, category: "secret", severity: "error", summary: "hardcoded key", file: Some("a.js"), line: Some(1), justification: "under review", actor_email, actor_name: None, email_sent: false }
    }

    #[test]
    fn add_override_defaults_to_approved_status_unlike_add_pending_override() {
        let (_dir, store) = open_test_db();
        let id = store.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        store.add_override(pending_args(id, "secret::a.js::1", "dev@acme.example"));
        assert!(store.has_approved_override(id, "secret::a.js::1"));
        assert!(!store.has_pending_override(id, "secret::a.js::1"));
    }

    #[test]
    fn add_pending_override_is_not_approved_until_approved() {
        let (_dir, store) = open_test_db();
        let id = store.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        let override_id = store.add_pending_override(pending_args(id, "secret::a.js::1", "submitter@acme.example"));
        assert!(store.has_pending_override(id, "secret::a.js::1"));
        assert!(!store.has_approved_override(id, "secret::a.js::1"));
        assert!(store.issue_has_override(id, "secret::a.js::1"), "a pending row still counts for issue_has_override's own purpose (github-dismissal reopen logic)");

        let pending = store.list_pending_overrides(id);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, override_id);
        assert_eq!(pending[0].actor_email, "submitter@acme.example");
    }

    #[test]
    fn approve_override_requires_a_different_reviewer() {
        let (_dir, store) = open_test_db();
        let id = store.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        let override_id = store.add_pending_override(pending_args(id, "secret::a.js::1", "submitter@acme.example"));

        let err = store.approve_override(id, override_id, "submitter@acme.example").unwrap_err();
        assert!(err.contains("different reviewer"), "{err}");
        assert!(store.has_pending_override(id, "secret::a.js::1"), "a rejected self-approval must leave the row pending");

        let (project_id, issue_id) = store.approve_override(id, override_id, "approver@acme.example").unwrap();
        assert_eq!(project_id, id);
        assert_eq!(issue_id, "secret::a.js::1");
        assert!(store.has_approved_override(id, "secret::a.js::1"));
        assert!(!store.has_pending_override(id, "secret::a.js::1"));
    }

    #[test]
    fn approve_override_rejects_an_already_decided_row() {
        let (_dir, store) = open_test_db();
        let id = store.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        let override_id = store.add_pending_override(pending_args(id, "secret::a.js::1", "submitter@acme.example"));
        store.approve_override(id, override_id, "approver@acme.example").unwrap();

        let err = store.approve_override(id, override_id, "someone-else@acme.example").unwrap_err();
        assert!(err.contains("already approved"), "{err}");
    }

    #[test]
    fn reject_override_leaves_the_issue_unapproved() {
        let (_dir, store) = open_test_db();
        let id = store.create_project("job-1", "acme", "widgets", false, "ui", None).unwrap();
        let override_id = store.add_pending_override(pending_args(id, "secret::a.js::1", "submitter@acme.example"));

        let (project_id, issue_id) = store.reject_override(id, override_id, "approver@acme.example").unwrap();
        assert_eq!(project_id, id);
        assert_eq!(issue_id, "secret::a.js::1");
        assert!(!store.has_approved_override(id, "secret::a.js::1"));
        assert!(!store.has_pending_override(id, "secret::a.js::1"));
        assert!(store.list_pending_overrides(id).is_empty());
    }

    #[test]
    fn approve_override_errors_for_an_unknown_id() {
        let (_dir, store) = open_test_db();
        let err = store.approve_override(1, 999, "approver@acme.example").unwrap_err();
        assert!(err.contains("not found"), "{err}");
    }
}
