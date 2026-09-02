//! Auto-fix PR bot — the Dependabot-parity gap `scheduled-rescan` leaves
//! open: Ignite's `dependency-vulnerability` check (deps.dev advisories,
//! see `ignite-dependency-license-scan`) *detects* a known-vulnerable
//! dependency but never proposes the fix the way Dependabot's version-bump
//! PRs do. This crate closes that gap for the five manifest ecosystems
//! `ignite-studio-manifests` already parses (npm/pypi/cargo/go/maven):
//! for each vulnerable dependency, look up the advisory's minimum fixed
//! version (OSV.dev — deps.dev's own advisory schema doesn't carry a
//! per-package fixed-version field, only the generic CVE/GHSA metadata
//! `VulnFinding` already captures), bump exactly that one manifest line,
//! and open a PR.
//!
//! **Deliberately conservative, not a full Dependabot replacement:**
//! - Only a single, simple version constraint is auto-edited (a bare
//!   version or one with a `^`/`~`/`==`/`>=`-style prefix). Anything more
//!   complex (OR ranges, wildcards, multiple comparators) is left for a
//!   human — see `is_simple_range`.
//! - A fix that crosses a semver major version is flagged
//!   (`FixCandidate::major_bump`) but never auto-applied — a major bump
//!   can be a real breaking change, which is exactly the kind of judgment
//!   call this tool shouldn't make unattended. `--apply` skips these;
//!   they still show up in the dry-run/plan output for a human to action.
//! - Only the first `fixed` event OSV reports for the matching
//!   `affected` package entry is used, not a full range-intersection
//!   resolution. Good enough to propose *a* correct fix version in the
//!   overwhelming common case (one vulnerable range, one fix); a
//!   multi-range advisory could in principle want a different minimum —
//!   still strictly better than the silence Ignite ships today.
//! - One branch + PR per (manifest file, dependency, fixed version),
//!   matching Dependabot's own per-dependency granularity rather than
//!   bundling a repo's fixes into one PR a reviewer has to accept/reject
//!   as a unit.
//! - Idempotent via branch name alone (`git ls-remote --heads` before
//!   creating): no attempt to auto-merge, close stale fix PRs when a
//!   dependency is later fixed some other way, or track an in-flight
//!   PR's review state. An operator/cron still supervises this the same
//!   way `scheduled-rescan` is supervised.

use ignite_dependency_license_scan::{scan_dependency_vulnerabilities, VulnScanManifest};
use ignite_deps_dev_client::{parse_semver, DepsDevClient};
use ignite_github_api::GithubApi;
use ignite_tool_runner::{RunToolOptions, ToolRunner};
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct FixCandidate {
    pub manifest_file: String,
    pub ecosystem: &'static str,
    pub dep_name: String,
    pub dep_line: usize,
    pub current_range: String,
    pub resolved_version: Option<String>,
    pub fixed_version: String,
    pub advisory_id: String,
    pub summary: String,
    /// Fixed version crosses a semver major from the resolved installed
    /// version — never auto-applied, see the module doc.
    pub major_bump: bool,
}

/// `ignite-studio-manifests`' ecosystem tag -> OSV.dev's own ecosystem
/// name (they don't match: OSV uses "PyPI"/"crates.io"/"Go"/"Maven", not
/// deps.dev's lowercase "pypi"/"cargo"/"go"/"maven").
fn osv_ecosystem(ecosystem: &str) -> Option<&'static str> {
    match ecosystem {
        "npm" => Some("npm"),
        "pypi" => Some("PyPI"),
        "cargo" => Some("crates.io"),
        "go" => Some("Go"),
        "maven" => Some("Maven"),
        _ => None,
    }
}

/// The leading constraint-operator characters a manifest version string
/// can carry (`^1.2.3`, `~=1.2.3`, `==1.2.3`, `>=1.2.3`) — everything
/// after this prefix is expected to be a plain version.
const RANGE_PREFIX_CHARS: &[char] = &['^', '~', '=', '<', '>', '!', ' '];

/// True only for a single simple constraint this tool knows how to bump
/// in place — a bare version, or one prefix-operator plus a plain
/// version. Rejects OR-ranges (`||`, `,`), wildcards (`*`), and
/// hyphen-ranges (`1.0.0 - 2.0.0`) — anything ambiguous is left alone
/// rather than guessed at.
pub fn is_simple_range(range: &str) -> bool {
    if range.is_empty() {
        return false;
    }
    let rest: String = range.chars().skip_while(|c| RANGE_PREFIX_CHARS.contains(c)).collect();
    if rest.is_empty() || rest.contains(['x', 'X', '*']) {
        return false;
    }
    rest.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '+')
}

/// Rebuilds a version constraint at `fixed_version`, preserving whatever
/// leading operator/prefix the original range used (`^1.2.3` -> `^2.0.1`,
/// `==1.2.3` -> `==2.0.1`, bare `1.2.3` -> bare `2.0.1`).
pub fn rewrite_range(old_range: &str, fixed_version: &str) -> String {
    let prefix: String = old_range.chars().take_while(|c| RANGE_PREFIX_CHARS.contains(c)).collect();
    format!("{prefix}{fixed_version}")
}

/// True when `fixed` and `resolved` both parse as semver and their major
/// component differs. Unparseable versions (Go pseudo-versions, some
/// Maven schemes) are never flagged — no false confidence either way, but
/// erring toward "let a human look" only makes sense when we can actually
/// tell there's a major jump.
pub fn is_major_bump(resolved: &str, fixed: &str) -> bool {
    match (parse_semver(resolved), parse_semver(fixed)) {
        (Some((rm, _, _)), Some((fm, _, _))) => rm != fm,
        _ => false,
    }
}

/// Queries OSV.dev directly for `advisory_id`'s full record and returns
/// the first `fixed` version event under the `affected` entry matching
/// `dep_name`/`ecosystem`. deps.dev's own advisory API (already used by
/// `ignite-dependency-license-scan`) proxies a subset of OSV that drops
/// per-package affected/fixed ranges, so this goes to the source.
pub async fn fetch_osv_fixed_version(http: &reqwest::Client, advisory_id: &str, ecosystem: &str, dep_name: &str) -> Option<String> {
    let osv_eco = osv_ecosystem(ecosystem)?;
    let url = format!("https://api.osv.dev/v1/vulns/{}", advisory_id);
    let resp = http.get(&url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body: serde_json::Value = resp.json().await.ok()?;
    let affected = body.get("affected")?.as_array()?;
    for entry in affected {
        let pkg = entry.get("package")?;
        let name_matches = pkg.get("name").and_then(|v| v.as_str()).map(|n| n.eq_ignore_ascii_case(dep_name)).unwrap_or(false);
        let eco_matches = pkg.get("ecosystem").and_then(|v| v.as_str()).map(|e| e.eq_ignore_ascii_case(osv_eco)).unwrap_or(false);
        if !name_matches || !eco_matches {
            continue;
        }
        if let Some(ranges) = entry.get("ranges").and_then(|r| r.as_array()) {
            for range in ranges {
                if let Some(events) = range.get("events").and_then(|e| e.as_array()) {
                    for event in events {
                        if let Some(fixed) = event.get("fixed").and_then(|f| f.as_str()) {
                            return Some(fixed.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

/// Runs the real dependency-vulnerability scan against a checked-out repo
/// and, for every finding whose manifest line is a simple constraint,
/// resolves a proposed fix version via OSV.dev.
pub async fn discover_fix_candidates(root: &Path, deps_client: &DepsDevClient, http: &reqwest::Client) -> Vec<FixCandidate> {
    let manifests: Vec<VulnScanManifest> = scan_dependency_vulnerabilities(root, deps_client).await.unwrap_or_default();
    let mut candidates = Vec::new();

    for manifest in &manifests {
        for dep in &manifest.dependencies {
            let Some(line) = dep.line else { continue };
            if !is_simple_range(&dep.version_range) {
                continue;
            }
            for vuln in &dep.vulnerabilities {
                let Some(advisory_id) = vuln.id.clone().or_else(|| vuln.aliases.first().cloned()) else { continue };
                let Some(fixed_version) = fetch_osv_fixed_version(http, &advisory_id, manifest.ecosystem, &dep.name).await else { continue };
                let major_bump = dep.version.as_deref().map(|resolved| is_major_bump(resolved, &fixed_version)).unwrap_or(false);
                let mut summary = format!("{}@{} -> {fixed_version} ({advisory_id})", dep.name, dep.version.clone().unwrap_or_else(|| dep.version_range.clone()));
                if let Some(title) = &vuln.title {
                    summary.push_str(&format!(": {title}"));
                }
                candidates.push(FixCandidate {
                    manifest_file: manifest.file.clone(),
                    ecosystem: manifest.ecosystem,
                    dep_name: dep.name.clone(),
                    dep_line: line,
                    current_range: dep.version_range.clone(),
                    resolved_version: dep.version.clone(),
                    fixed_version,
                    advisory_id,
                    summary,
                    major_bump,
                });
            }
        }
    }
    candidates
}

/// Deterministic per-fix branch name — doubles as the idempotency key
/// (see `branch_exists_on_remote`): re-running this tool against an
/// unchanged advisory/fix pair always names the same branch.
pub fn branch_name_for(candidate: &FixCandidate) -> String {
    let slug: String = candidate.dep_name.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' }).collect();
    format!("ignite/autofix/{}-{}-{}", candidate.ecosystem, slug, candidate.fixed_version)
}

pub fn pr_title_for(candidate: &FixCandidate) -> String {
    format!("[Ignite auto-fix] bump {} to {} ({})", candidate.dep_name, candidate.fixed_version, candidate.advisory_id)
}

pub fn pr_body_for(candidate: &FixCandidate) -> String {
    format!(
        "Ignite's scheduled dependency-vulnerability scan flagged **{}@{}** in `{}` for a known advisory.\n\n\
         - Advisory: {}\n\
         - Fixed version (per OSV.dev): `{}`\n\
         - Change: `{}` -> `{}`\n\n\
         Opened automatically by `auto-fix-pr` (dry-run reviewed before `--apply`). \
         Verify the bump doesn't break anything before merging — this is a single-line \
         version-constraint edit, not a full compatibility check.\n",
        candidate.dep_name,
        candidate.resolved_version.as_deref().unwrap_or(&candidate.current_range),
        candidate.manifest_file,
        candidate.advisory_id,
        candidate.fixed_version,
        candidate.current_range,
        rewrite_range(&candidate.current_range, &candidate.fixed_version),
    )
}

/// Rewrites `content`'s `dep_line` (1-indexed) by replacing the first
/// occurrence of `old_range` with its bumped equivalent. Returns `None`
/// (never edits) if the line doesn't actually contain `old_range` — a
/// stale line number or a range that changed between scan and edit is a
/// reason to skip, not to guess at the wrong line.
pub fn apply_fix_to_content(content: &str, dep_line: usize, old_range: &str, fixed_version: &str) -> Option<String> {
    if dep_line == 0 {
        return None;
    }
    let mut lines: Vec<&str> = content.split('\n').collect();
    let idx = dep_line - 1;
    let line = lines.get(idx)?;
    if !line.contains(old_range) {
        return None;
    }
    let new_range = rewrite_range(old_range, fixed_version);
    let new_line = line.replacen(old_range, &new_range, 1);
    let owned_line = new_line;
    lines[idx] = &owned_line;
    // `lines[idx]` borrows `owned_line`, which would be dropped at scope
    // end — join immediately instead of returning the borrowed Vec.
    Some(lines.join("\n"))
}

#[derive(Debug)]
pub struct FixOutcome {
    pub candidate_summary: String,
    pub branch: String,
    pub applied: bool,
    pub skipped_reason: Option<String>,
    pub pr_url: Option<String>,
    pub error: Option<String>,
}

/// True if `branch` already exists on `origin` — the idempotency check.
/// Read-only, safe in dry-run.
pub async fn branch_exists_on_remote(runner: &ToolRunner, clone_dir: &str, branch: &str) -> bool {
    match runner.run_tool("git", &["ls-remote".to_string(), "--heads".to_string(), "origin".to_string(), branch.to_string()], clone_dir, RunToolOptions::default()).await {
        Ok(out) => !out.stdout.trim().is_empty(),
        Err(_) => false,
    }
}

/// Applies one fix candidate against an already-cloned `clone_dir`
/// (checked out at `base_branch`): creates/resets a deterministic branch
/// off `base_branch`, edits the one manifest line, commits, and — only
/// when `apply` is true — pushes and opens a PR. Leaves `clone_dir`
/// checked out on `base_branch` again afterward so the caller can process
/// the next candidate against a clean base.
#[allow(clippy::too_many_arguments)]
pub async fn apply_fix(runner: &ToolRunner, github_api: &GithubApi<'_>, full_name: &str, base_branch: &str, clone_dir: &str, candidate: &FixCandidate, token: &str, apply: bool) -> FixOutcome {
    let branch = branch_name_for(candidate);
    let candidate_summary = candidate.summary.clone();

    if candidate.major_bump {
        return FixOutcome { candidate_summary, branch, applied: false, skipped_reason: Some("fix crosses a semver major version — needs manual review".to_string()), pr_url: None, error: None };
    }

    if branch_exists_on_remote(runner, clone_dir, &branch).await {
        return FixOutcome { candidate_summary, branch, applied: false, skipped_reason: Some("branch already exists on origin — fix already proposed".to_string()), pr_url: None, error: None };
    }

    let manifest_path = Path::new(clone_dir).join(&candidate.manifest_file);
    let content = match std::fs::read_to_string(&manifest_path) {
        Ok(c) => c,
        Err(e) => return FixOutcome { candidate_summary, branch, applied: false, skipped_reason: None, pr_url: None, error: Some(format!("failed to read {}: {e}", candidate.manifest_file)) },
    };
    let Some(new_content) = apply_fix_to_content(&content, candidate.dep_line, &candidate.current_range, &candidate.fixed_version) else {
        return FixOutcome { candidate_summary, branch, applied: false, skipped_reason: Some(format!("manifest line {} no longer matches the scanned range — skipping (file changed since scan?)", candidate.dep_line)), pr_url: None, error: None };
    };

    if !apply {
        return FixOutcome { candidate_summary, branch, applied: false, skipped_reason: Some("dry-run — pass --apply to open this PR".to_string()), pr_url: None, error: None };
    }

    let steps: Vec<(&str, Vec<String>)> = vec![("git", vec!["checkout".to_string(), "-B".to_string(), branch.clone(), base_branch.to_string()])];
    for (tool, args) in steps {
        if let Err(e) = runner.run_tool(tool, &args, clone_dir, RunToolOptions::default()).await {
            return FixOutcome { candidate_summary, branch, applied: false, skipped_reason: None, pr_url: None, error: Some(format!("{tool} {}: {e}", args.join(" "))) };
        }
    }

    if let Err(e) = std::fs::write(&manifest_path, new_content) {
        let _ = runner.run_tool("git", &["checkout".to_string(), base_branch.to_string()], clone_dir, RunToolOptions::default()).await;
        return FixOutcome { candidate_summary, branch, applied: false, skipped_reason: None, pr_url: None, error: Some(format!("failed to write {}: {e}", candidate.manifest_file)) };
    }

    let commit_steps: Vec<Vec<String>> = vec![
        vec!["add".to_string(), candidate.manifest_file.clone()],
        vec!["-c".to_string(), "user.email=ignite-bot@localhost".to_string(), "-c".to_string(), "user.name=Ignite Auto-Fix".to_string(), "commit".to_string(), "-m".to_string(), format!("fix({}): bump {} to {} ({})", candidate.ecosystem, candidate.dep_name, candidate.fixed_version, candidate.advisory_id)],
    ];
    for args in commit_steps {
        if let Err(e) = runner.run_tool("git", &args, clone_dir, RunToolOptions::default()).await {
            let _ = runner.run_tool("git", &["checkout".to_string(), base_branch.to_string()], clone_dir, RunToolOptions::default()).await;
            return FixOutcome { candidate_summary, branch, applied: false, skipped_reason: None, pr_url: None, error: Some(format!("git {}: {e}", args.join(" "))) };
        }
    }

    // Same `http.extraheader` convention `GithubApi::gh_clone_repo_branch`'s
    // token-only fallback uses — a one-off override for this invocation
    // only, never written into the clone's own `.git/config` (unlike
    // embedding the token in the remote URL, which would be).
    let push_result = runner
        .run_tool("git", &["-c".to_string(), format!("http.extraheader=AUTHORIZATION: bearer {token}"), "push".to_string(), "origin".to_string(), format!("HEAD:refs/heads/{branch}")], clone_dir, RunToolOptions::default())
        .await;
    // Always return to base_branch before reporting, so the caller can
    // process the next candidate regardless of how this one ended.
    let _ = runner.run_tool("git", &["checkout".to_string(), base_branch.to_string()], clone_dir, RunToolOptions::default()).await;

    if let Err(e) = push_result {
        return FixOutcome { candidate_summary, branch, applied: false, skipped_reason: None, pr_url: None, error: Some(format!("git push: {e}")) };
    }

    match github_api.gh_create_pr(full_name, base_branch, &branch, &pr_title_for(candidate), &pr_body_for(candidate), token).await {
        Ok(pr) => FixOutcome { candidate_summary, branch, applied: true, skipped_reason: None, pr_url: Some(pr.url), error: None },
        Err(e) => FixOutcome { candidate_summary, branch, applied: true, skipped_reason: None, pr_url: None, error: Some(format!("branch pushed but PR creation failed: {e}")) },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_simple_range_accepts_bare_and_prefixed_versions() {
        assert!(is_simple_range("1.2.3"));
        assert!(is_simple_range("^1.2.3"));
        assert!(is_simple_range("~=1.2.3"));
        assert!(is_simple_range("==1.2.3"));
        assert!(is_simple_range(">=1.2.3"));
        assert!(is_simple_range("v1.2.3"));
    }

    #[test]
    fn is_simple_range_rejects_or_ranges_and_wildcards() {
        assert!(!is_simple_range("1.x"));
        assert!(!is_simple_range("^1.0.0 || ^2.0.0"));
        assert!(!is_simple_range("1.0.0, <2.0.0"));
        assert!(!is_simple_range(""));
        assert!(!is_simple_range("1.0.0 - 2.0.0"));
    }

    #[test]
    fn rewrite_range_preserves_prefix() {
        assert_eq!(rewrite_range("^1.2.3", "2.0.1"), "^2.0.1");
        assert_eq!(rewrite_range("==1.2.3", "2.0.1"), "==2.0.1");
        assert_eq!(rewrite_range("1.2.3", "2.0.1"), "2.0.1");
        assert_eq!(rewrite_range(">=1.2.3", "2.0.1"), ">=2.0.1");
    }

    #[test]
    fn is_major_bump_detects_major_version_change() {
        assert!(is_major_bump("1.2.3", "2.0.0"));
        assert!(!is_major_bump("1.2.3", "1.5.0"));
        assert!(!is_major_bump("not-semver", "2.0.0"));
    }

    #[test]
    fn apply_fix_to_content_rewrites_only_the_target_line() {
        let content = "{\n  \"dependencies\": {\n    \"lodash\": \"^4.17.15\",\n    \"other\": \"^1.0.0\"\n  }\n}";
        let out = apply_fix_to_content(content, 3, "^4.17.15", "4.17.21").unwrap();
        assert!(out.contains("\"lodash\": \"^4.17.21\""));
        assert!(out.contains("\"other\": \"^1.0.0\""));
    }

    #[test]
    fn apply_fix_to_content_skips_when_range_no_longer_matches() {
        let content = "lodash==4.17.15\n";
        assert!(apply_fix_to_content(content, 1, "^99.0.0", "4.17.21").is_none());
    }

    #[test]
    fn apply_fix_to_content_skips_invalid_line_number() {
        let content = "lodash==4.17.15\n";
        assert!(apply_fix_to_content(content, 0, "4.17.15", "4.17.21").is_none());
        assert!(apply_fix_to_content(content, 50, "4.17.15", "4.17.21").is_none());
    }

    /// Real network call against the live OSV.dev API — a known GHSA
    /// advisory for `lodash` on npm (prototype pollution, fixed in
    /// 4.17.19) that's been stable for years, so this shouldn't flake on
    /// advisory content changing. Self-skips if the network is
    /// unreachable, same convention as this repo's other real-binary/
    /// real-network integration tests.
    #[tokio::test]
    async fn fetch_osv_fixed_version_resolves_a_real_advisory() {
        let http = reqwest::Client::new();
        let result = fetch_osv_fixed_version(&http, "GHSA-p6mc-m468-83gw", "npm", "lodash").await;
        let Some(fixed) = result else {
            eprintln!("skipping: could not reach OSV.dev (network unavailable in this environment) or advisory shape changed");
            return;
        };
        assert!(parse_semver(&fixed).is_some(), "expected a semver-shaped fixed version, got {fixed}");
    }

    #[test]
    fn branch_name_for_is_deterministic_and_slugified() {
        let candidate = FixCandidate {
            manifest_file: "package.json".to_string(),
            ecosystem: "npm",
            dep_name: "@scope/pkg-name".to_string(),
            dep_line: 3,
            current_range: "^1.0.0".to_string(),
            resolved_version: Some("1.0.0".to_string()),
            fixed_version: "1.2.0".to_string(),
            advisory_id: "GHSA-xxxx".to_string(),
            summary: String::new(),
            major_bump: false,
        };
        let branch = branch_name_for(&candidate);
        assert_eq!(branch, "ignite/autofix/npm--scope-pkg-name-1.2.0");
        assert_eq!(branch, branch_name_for(&candidate));
    }
}
