//! Scheduled re-scan job — the Dependabot-equivalent continuous-coverage
//! gap: Ignite's dependency/CVE checks (Trivy, package-hallucination,
//! GuardDog, and the rest of Phase 4) only run when a scan is *triggered*
//! (a push, or someone running the CLI). Nothing re-checks an already
//! onboarded repo's unchanged code against newly disclosed CVEs the way
//! Dependabot does on a schedule. This binary closes that gap: iterate
//! every project Ignite already knows about, re-run a real scan against
//! each one's current GitHub default branch, and post the result back
//! onto that commit the same way a push-triggered scan would.
//!
//! Deliberately reuses the *full* `POST /api/pipeline/validate-all` sweep
//! rather than inventing a new "dependency-only" mode: Ignite has no
//! selector narrower than the existing `fast` flag (which actually
//! narrows the *wrong* way for this use case — lightning mode drops
//! Trivy/GuardDog/package-hallucination, the exact checks this job cares
//! about, keeping only secrets/governance/file-encapsulation/semgrep). A
//! full run finds strictly more real findings and needs no new server-side
//! API surface, matching this codebase's stated preference (see the
//! `changedFiles` design note in CLAUDE.md) for reusing an existing
//! response shape/view over adding a new endpoint per use case.

use ignite_db_store::{DbStore, ProjectListRow};
use ignite_github_api::GithubApi;
use ignite_tool_runner::ToolRunner;
use serde_json::{json, Value};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RescanTarget {
    pub org: String,
    pub repo: String,
}

/// Every onboarded (org, repo) pair known to Ignite, deduplicated —
/// `list_projects` returns one row per *run*, and a repo that's been
/// re-scanned before (or onboarded, then later re-validated) appears
/// multiple times. Order is stable (most-recently-run first, matching
/// `list_projects`' own `ORDER BY p.id DESC`) but only the first
/// occurrence of each pair is kept.
pub fn dedupe_projects(rows: &[ProjectListRow]) -> Vec<RescanTarget> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for row in rows {
        let target = RescanTarget { org: row.org.clone(), repo: row.repo.clone() };
        if seen.insert(target.clone()) {
            out.push(target);
        }
    }
    out
}

/// "No new findings = no-op, just logs": a validate-all response with an
/// empty `issues` array needs nothing posted back to GitHub — the commit
/// is already clean, and there's no new information to surface. Any
/// non-empty issues array (whether it ends up green or red once
/// overrides/baselines are accounted for) is real information worth a
/// commit status + PR-adjacent visibility, so it's posted.
pub fn should_post_github_check(issues: &[Value]) -> bool {
    !issues.is_empty()
}

#[derive(Debug)]
pub struct RescanOutcome {
    pub org: String,
    pub repo: String,
    pub job_id: Option<String>,
    pub issue_count: usize,
    pub posted: bool,
    pub error: Option<String>,
}

impl RescanOutcome {
    fn failed(org: &str, repo: &str, error: impl Into<String>) -> Self {
        RescanOutcome { org: org.to_string(), repo: repo.to_string(), job_id: None, issue_count: 0, posted: false, error: Some(error.into()) }
    }
}

/// Runs one project through: resolve default branch -> shallow clone ->
/// `POST /api/pipeline/validate-all` against the running Ignite server ->
/// (if any issues came back) `POST /api/pipeline/:jobId/github-check`,
/// reusing exactly the endpoint a push-triggered scan already posts to
/// (`routes/github_pr_status.rs`). Never touches a real GitHub org's
/// settings — only ever a commit status + an optional PR comment on
/// commits that already exist.
pub async fn rescan_one(runner: &ToolRunner, http: &reqwest::Client, server_base: &str, gh_token: &str, target: &RescanTarget) -> RescanOutcome {
    let full_name = format!("{}/{}", target.org, target.repo);
    let api = GithubApi::new(runner);

    let default_branch = match api.default_branch(&full_name, gh_token).await {
        Ok(b) => b,
        Err(e) => return RescanOutcome::failed(&target.org, &target.repo, format!("failed to resolve default branch: {e}")),
    };

    let staging = match tempfile::tempdir() {
        Ok(d) => d,
        Err(e) => return RescanOutcome::failed(&target.org, &target.repo, format!("failed to create staging dir: {e}")),
    };
    let dest = staging.path().join("clone");
    if let Err(e) = api.gh_clone_repo_branch(&full_name, &default_branch, &dest.to_string_lossy(), gh_token).await {
        return RescanOutcome::failed(&target.org, &target.repo, format!("failed to clone {full_name}@{default_branch}: {e}"));
    }

    let sha = match api.head_sha(&full_name, &default_branch, gh_token).await {
        Ok(s) => s,
        Err(e) => return RescanOutcome::failed(&target.org, &target.repo, format!("failed to resolve HEAD sha: {e}")),
    };

    let validate_res = http
        .post(format!("{server_base}/api/pipeline/validate-all"))
        .json(&json!({ "org": target.org, "repo": target.repo, "projectPath": dest.to_string_lossy(), "runLocalCi": false }))
        .send()
        .await;
    let body: Value = match validate_res {
        Ok(res) => match res.json().await {
            Ok(v) => v,
            Err(e) => return RescanOutcome::failed(&target.org, &target.repo, format!("failed to parse validate-all response: {e}")),
        },
        Err(e) => return RescanOutcome::failed(&target.org, &target.repo, format!("validate-all request failed: {e}")),
    };

    let Some(job_id) = body.get("jobId").and_then(|v| v.as_str()).map(str::to_string) else {
        return RescanOutcome::failed(&target.org, &target.repo, format!("validate-all response had no jobId: {body}"));
    };
    let issues = body.get("issues").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let issue_count = issues.len();

    if !should_post_github_check(&issues) {
        return RescanOutcome { org: target.org.clone(), repo: target.repo.clone(), job_id: Some(job_id), issue_count, posted: false, error: None };
    }

    let check_res = http
        .post(format!("{server_base}/api/pipeline/{job_id}/github-check"))
        .json(&json!({ "owner": target.org, "repo": target.repo, "sha": sha }))
        .send()
        .await;
    match check_res {
        Ok(res) if res.status().is_success() => RescanOutcome { org: target.org.clone(), repo: target.repo.clone(), job_id: Some(job_id), issue_count, posted: true, error: None },
        Ok(res) => {
            let status = res.status();
            let text = res.text().await.unwrap_or_default();
            RescanOutcome { org: target.org.clone(), repo: target.repo.clone(), job_id: Some(job_id), issue_count, posted: false, error: Some(format!("github-check returned {status}: {text}")) }
        }
        Err(e) => RescanOutcome { org: target.org.clone(), repo: target.repo.clone(), job_id: Some(job_id), issue_count, posted: false, error: Some(format!("github-check request failed: {e}")) },
    }
}

pub fn default_runner() -> ToolRunner {
    ToolRunner::new(std::collections::HashMap::new())
}

pub fn open_db(db_path: &str) -> Result<DbStore, String> {
    DbStore::open(std::path::Path::new(db_path)).map_err(|e| format!("failed to open db at {db_path}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(org: &str, repo: &str) -> ProjectListRow {
        ProjectListRow {
            id: 1,
            job_id: "job".to_string(),
            org: org.to_string(),
            repo: repo.to_string(),
            gxp: false,
            source: "api".to_string(),
            scan_location: None,
            status: "success".to_string(),
            error: None,
            repo_url: None,
            pr_url: None,
            created_at: String::new(),
            finished_at: None,
            doc_count: 0,
            issue_count: 0,
            retained: false,
            retained_tier: None,
            source_commit_sha: None,
            shipped_commit_sha: None,
        }
    }

    #[test]
    fn dedupe_projects_keeps_first_occurrence_of_each_org_repo_pair() {
        let rows = vec![row("acme", "widgets"), row("acme", "gadgets"), row("acme", "widgets")];
        let out = dedupe_projects(&rows);
        assert_eq!(out, vec![RescanTarget { org: "acme".into(), repo: "widgets".into() }, RescanTarget { org: "acme".into(), repo: "gadgets".into() }]);
    }

    #[test]
    fn dedupe_projects_empty_input() {
        assert!(dedupe_projects(&[]).is_empty());
    }

    #[test]
    fn should_post_github_check_false_when_no_issues() {
        assert!(!should_post_github_check(&[]));
    }

    #[test]
    fn should_post_github_check_true_when_issues_present() {
        assert!(should_post_github_check(&[json!({"category": "secret"})]));
    }

    #[test]
    fn dedupe_projects_reads_real_projects_from_a_live_db() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_db(&dir.path().join("test.db").to_string_lossy()).unwrap();
        db.create_project("job-1", "acme", "widgets", false, "api", None);
        db.create_project("job-2", "acme", "widgets", false, "api", None);
        db.create_project("job-3", "acme", "gadgets", false, "api", None);

        let targets = dedupe_projects(&db.list_projects());
        assert_eq!(targets.len(), 2);
        assert!(targets.contains(&RescanTarget { org: "acme".into(), repo: "widgets".into() }));
        assert!(targets.contains(&RescanTarget { org: "acme".into(), repo: "gadgets".into() }));
    }
}
