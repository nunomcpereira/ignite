//! `org-onboard <org> [<org>...] [--repo <org/repo>...] [--apply] [--scan]`
//!
//! Closes a gap the rest of this codebase's onboarding story assumes away:
//! every onboarding path (upload, pre-push hook, `repository.created`
//! webhook) requires something to *trigger* Ignite against a repo first.
//! An org that migrated hundreds of repos onto GitHub before Ignite
//! existed has none of those triggers — nothing ever ran, so nothing is
//! enrolled, and `scheduled-rescan` (which only ever iterates
//! already-known `projects` rows) has nothing to iterate.
//!
//! This tool closes that gap in two independent steps:
//! 1. **Discovery**: `GET orgs/{org}/repos`, paginated
//!    (`ignite_github_api::GithubApi::gh_list_org_repos`), lists every
//!    repo the connected token can see in each `<org>` target — the
//!    "explore what's actually in the org" half of the request. Archived
//!    and forked repos are excluded by default (`--include-archived`/
//!    `--include-forks` opt back in) since those are rarely what an
//!    operator means by "the repos we migrated".
//! 2. **Enrollment** (`--apply`) inserts a minimal `projects` row for
//!    every discovered repo Ignite doesn't already know about — the exact
//!    same shape `routes/repository_events_webhook.rs`'s zero-touch
//!    enrollment already uses (`status = "enrolled"`, `source =
//!    "org-onboard"`), so a bulk-discovered repo shows up in Onboarded
//!    Repos and becomes visible to `scheduled-rescan`'s own iteration
//!    going forward, identically to one onboarded the normal way.
//!    Dry-run by default (prints what *would* be enrolled), matching this
//!    codebase's standing `auto-fix-pr`/`enforce-gate-branch-protection`
//!    convention for any tool that mutates state.
//! 3. **Forced scan** (`--scan`) runs `ignite_scheduled_rescan::rescan_one`
//!    — the same shallow-clone + `validate-all` + `github-check` sequence
//!    a push-triggered scan already runs — against every target in scope
//!    (every discovered repo, plus any `--repo org/repo` given directly).
//!    Not gated behind `--apply`: a scan+report is exactly what
//!    `scheduled-rescan` itself already does unconditionally, and forcing
//!    a scan on a repo doesn't require that repo to be persistently
//!    enrolled first — `rescan_one` only calls the running server's own
//!    `validate-all`/`github-check` endpoints, no DB write of its own.
//!
//! `--repo <org/repo>` (repeatable) targets a specific repo directly,
//! skipping discovery entirely — the "force a scan on any one of them"
//! half of the request, for when an operator already knows which repo
//! they want without listing the whole org.
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

use ignite_github_api::{is_valid_github_owner, parse_org_repo, GithubApi};
use serde_json::Value;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct OrgOnboardError(String);

impl From<String> for OrgOnboardError {
    fn from(s: String) -> Self {
        OrgOnboardError(s)
    }
}
impl From<&str> for OrgOnboardError {
    fn from(s: &str) -> Self {
        OrgOnboardError(s.to_string())
    }
}

#[derive(Debug, Default)]
pub struct ParsedArgs {
    pub orgs: Vec<String>,
    pub repos: Vec<(String, String)>,
    pub apply: bool,
    pub scan: bool,
    pub include_archived: bool,
    pub include_forks: bool,
}

pub fn parse_args(raw: &[String]) -> Result<ParsedArgs, OrgOnboardError> {
    let mut parsed = ParsedArgs::default();
    let mut i = 0;
    while i < raw.len() {
        match raw[i].as_str() {
            "--apply" => parsed.apply = true,
            "--scan" => parsed.scan = true,
            "--include-archived" => parsed.include_archived = true,
            "--include-forks" => parsed.include_forks = true,
            "--repo" => {
                i += 1;
                let spec = raw.get(i).ok_or("--repo requires a value (org/repo)")?;
                parsed.repos.push(parse_org_repo(spec)?);
            }
            other if other.starts_with("--") => return Err(format!("Unknown flag: {other}").into()),
            other => {
                if !is_valid_github_owner(other) {
                    return Err(format!("Invalid GitHub org name: \"{other}\"").into());
                }
                parsed.orgs.push(other.to_string());
            }
        }
        i += 1;
    }
    if parsed.orgs.is_empty() && parsed.repos.is_empty() {
        return Err("Usage: org-onboard <org> [<org>...] [--repo <org/repo>...] [--apply] [--scan] [--include-archived] [--include-forks]".into());
    }
    Ok(parsed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredRepo {
    pub org: String,
    pub repo: String,
    pub archived: bool,
    pub fork: bool,
    /// `size == 0` (GitHub's own repo-size field, in KB) — a repo with
    /// nothing ever pushed to it. GitHub still reports a `default_branch`
    /// (typically `"main"`) for one of these even though that branch
    /// doesn't exist as a real ref yet, so a naive clone attempt fails
    /// with a generic "remote branch not found" error that reads exactly
    /// like a real access/auth problem. Surfacing this distinctly (known
    /// upfront from the same discovery listing, no extra API call) lets
    /// the UI show "Empty" instead of a scan ever being attempted.
    pub empty: bool,
}

/// Pure filtering step over `gh_list_org_repos`' raw JSON — kept separate
/// from the network call so it's testable without a real GitHub org.
/// A repo missing `name`/`owner.login` (shouldn't happen against a real
/// API response, but a defensively-parsed payload should never panic) is
/// silently skipped rather than failing the whole discovery pass.
pub fn filter_discovered_repos(raw: &[Value], include_archived: bool, include_forks: bool) -> Vec<DiscoveredRepo> {
    raw.iter()
        .filter_map(|r| {
            let repo = r.get("name")?.as_str()?.to_string();
            let org = r.get("owner")?.get("login")?.as_str()?.to_string();
            let archived = r.get("archived").and_then(|v| v.as_bool()).unwrap_or(false);
            let fork = r.get("fork").and_then(|v| v.as_bool()).unwrap_or(false);
            let empty = r.get("size").and_then(|v| v.as_i64()).map(|s| s == 0).unwrap_or(false);
            if archived && !include_archived {
                return None;
            }
            if fork && !include_forks {
                return None;
            }
            Some(DiscoveredRepo { org, repo, archived, fork, empty })
        })
        .collect()
}

pub async fn discover_org(api: &GithubApi<'_>, org: &str, token: &str, include_archived: bool, include_forks: bool) -> Result<Vec<DiscoveredRepo>, ignite_github_api::GithubApiError> {
    let raw = api.gh_list_org_repos(org, token).await?;
    Ok(filter_discovered_repos(&raw, include_archived, include_forks))
}

/// Whether `(org, repo)` is already known to Ignite (any project row ever
/// created for it, enrolled or from a real scan) — the dedup check
/// `--apply` uses so re-running discovery against the same org doesn't
/// insert a second enrollment row every time.
pub fn already_enrolled(db: &ignite_db_store::DbStore, org: &str, repo: &str) -> bool {
    db.get_latest_project_for_org_repo(org, repo).is_some()
}

/// Inserts the same minimal, non-scan `projects` row
/// `routes/repository_events_webhook.rs`'s zero-touch enrollment already
/// uses — `source = "org-onboard"` distinguishes this bulk-discovery path
/// in the audit trail from a webhook-triggered one, `status = "enrolled"`
/// so it never sits at `create_project`'s `"running"` default forever.
pub fn enroll_repo(db: &ignite_db_store::DbStore, org: &str, repo: &str) -> Result<i64, rusqlite::Error> {
    let job_id = format!("org-onboard-{}", uuid::Uuid::new_v4());
    let project_id = db.create_project(&job_id, org, repo, false, "org-onboard", None)?;
    db.set_project_status(project_id, "enrolled");
    Ok(project_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn filter_discovered_repos_excludes_archived_and_forks_by_default() {
        let raw = vec![
            json!({ "name": "widgets", "owner": { "login": "acme" }, "archived": false, "fork": false }),
            json!({ "name": "old-thing", "owner": { "login": "acme" }, "archived": true, "fork": false }),
            json!({ "name": "forked-lib", "owner": { "login": "acme" }, "archived": false, "fork": true }),
        ];
        let out = filter_discovered_repos(&raw, false, false);
        assert_eq!(out, vec![DiscoveredRepo { org: "acme".into(), repo: "widgets".into(), archived: false, fork: false, empty: false }]);
    }

    #[test]
    fn filter_discovered_repos_flags_a_zero_size_repo_as_empty() {
        let raw = vec![json!({ "name": "brand-new", "owner": { "login": "acme" }, "archived": false, "fork": false, "size": 0 })];
        let out = filter_discovered_repos(&raw, false, false);
        assert_eq!(out, vec![DiscoveredRepo { org: "acme".into(), repo: "brand-new".into(), archived: false, fork: false, empty: true }]);
    }

    #[test]
    fn filter_discovered_repos_include_flags_opt_back_in() {
        let raw = vec![
            json!({ "name": "old-thing", "owner": { "login": "acme" }, "archived": true, "fork": false }),
            json!({ "name": "forked-lib", "owner": { "login": "acme" }, "archived": false, "fork": true }),
        ];
        let out = filter_discovered_repos(&raw, true, true);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn filter_discovered_repos_skips_malformed_entries() {
        let raw = vec![json!({ "archived": false }), json!({ "name": "ok", "owner": { "login": "acme" } })];
        let out = filter_discovered_repos(&raw, false, false);
        assert_eq!(out, vec![DiscoveredRepo { org: "acme".into(), repo: "ok".into(), archived: false, fork: false, empty: false }]);
    }

    #[test]
    fn parse_args_requires_at_least_one_target() {
        assert!(parse_args(&[]).is_err());
    }

    #[test]
    fn parse_args_accepts_orgs_and_explicit_repos() {
        let raw = vec!["acme".to_string(), "--repo".to_string(), "other/widgets".to_string(), "--apply".to_string(), "--scan".to_string()];
        let parsed = parse_args(&raw).unwrap();
        assert_eq!(parsed.orgs, vec!["acme".to_string()]);
        assert_eq!(parsed.repos, vec![("other".to_string(), "widgets".to_string())]);
        assert!(parsed.apply);
        assert!(parsed.scan);
    }

    #[test]
    fn parse_args_rejects_invalid_org_name() {
        assert!(parse_args(&["-not-valid".to_string()]).is_err());
    }

    #[test]
    fn already_enrolled_and_enroll_repo_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let db = ignite_db_store::DbStore::open(&dir.path().join("test.db")).unwrap();
        assert!(!already_enrolled(&db, "acme", "widgets"));
        enroll_repo(&db, "acme", "widgets").unwrap();
        assert!(already_enrolled(&db, "acme", "widgets"));
    }
}
