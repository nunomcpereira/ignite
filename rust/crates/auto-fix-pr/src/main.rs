//! `auto-fix-pr <org/repo> [<org/repo>...] [--apply] [--include-routine-updates]`
//! — closes the Dependabot-parity gap `scheduled-rescan` leaves open:
//! Ignite detects a vulnerable dependency but never proposes the fix. For
//! each repo, shallow-clones its default branch, runs the real
//! dependency-vulnerability scan, resolves each finding's fixed version
//! via OSV.dev, and opens one PR per safe (non-major, simple-constraint)
//! fix.
//!
//! `--include-routine-updates` additionally proposes Dependabot's other
//! half — non-vulnerability version-currency bumps to each dependency's
//! latest stable release (`discover_routine_update_candidates`). Off by
//! default: unlike a security fix, a routine bump has no urgency
//! justifying opening PRs an operator didn't ask for.
//!
//! **Dry-run by default**, same convention as
//! `enforce-gate-branch-protection`: without `--apply` this clones and
//! scans (real, read-only against the repo) but only prints the plan —
//! which branches/PRs it would create — never pushes or opens anything.
//! Pass `--apply` to actually push branches and open PRs.

use ignite_auto_fix_pr::{apply_fix, discover_fix_candidates, discover_routine_update_candidates};
use ignite_deps_dev_client::DepsDevClient;
use ignite_github_api::{parse_org_repo, resolve_server_github_token, GithubApi};
use ignite_tool_runner::ToolRunner;
use std::collections::HashMap;

struct ParsedArgs {
    repos: Vec<(String, String)>,
    apply: bool,
    include_routine_updates: bool,
}

fn parse_args(raw: &[String]) -> Result<ParsedArgs, String> {
    let mut repos = Vec::new();
    let mut apply = false;
    let mut include_routine_updates = false;
    for arg in raw {
        match arg.as_str() {
            "--apply" => apply = true,
            "--include-routine-updates" => include_routine_updates = true,
            other if other.starts_with("--") => return Err(format!("Unknown flag: {other}")),
            other => repos.push(parse_org_repo(other)?),
        }
    }
    if repos.is_empty() {
        return Err("Usage: auto-fix-pr <org/repo> [<org/repo>...] [--apply] [--include-routine-updates]".to_string());
    }
    Ok(ParsedArgs { repos, apply, include_routine_updates })
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let parsed = match parse_args(&args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };

    if !parsed.apply {
        println!("Dry-run (no --apply passed) — will clone, scan, and print the fix plan for each repo, but push nothing and open no PRs.\n");
    }

    let token = resolve_server_github_token();
    let runner = ToolRunner::new(HashMap::new());
    let github_api = GithubApi::new(&runner);
    let deps_client = DepsDevClient::new();
    let http = reqwest::Client::new();

    let mut had_error = false;

    for (org, repo) in &parsed.repos {
        let full_name = format!("{org}/{repo}");
        println!("== {full_name} ==");

        let base_branch = match github_api.default_branch(&full_name, &token).await {
            Ok(b) => b,
            Err(e) => {
                eprintln!("  failed to resolve default branch: {e}");
                had_error = true;
                continue;
            }
        };

        let staging = match tempfile::tempdir() {
            Ok(d) => d,
            Err(e) => {
                eprintln!("  failed to create staging dir: {e}");
                had_error = true;
                continue;
            }
        };
        let clone_dir = staging.path().join("clone");
        if let Err(e) = github_api.gh_clone_repo_branch(&full_name, &base_branch, &clone_dir.to_string_lossy(), &token).await {
            eprintln!("  failed to clone {full_name}@{base_branch}: {e}");
            had_error = true;
            continue;
        }

        let mut candidates = discover_fix_candidates(&clone_dir, &deps_client, &http).await;
        if parsed.include_routine_updates {
            candidates.extend(discover_routine_update_candidates(&clone_dir, &deps_client).await);
        }
        if candidates.is_empty() {
            println!("  no fixable dependency-vulnerability findings{}.", if parsed.include_routine_updates { " or routine updates" } else { "" });
            continue;
        }
        println!("  {} fix candidate(s) found.", candidates.len());

        for candidate in &candidates {
            let outcome = apply_fix(&runner, &github_api, &full_name, &base_branch, &clone_dir.to_string_lossy(), candidate, &token, parsed.apply).await;
            match (&outcome.pr_url, &outcome.skipped_reason, &outcome.error) {
                (Some(url), _, _) => println!("  ✓ {} -> {url}", outcome.candidate_summary),
                (None, Some(reason), _) => println!("  · {} — {reason} (branch: {})", outcome.candidate_summary, outcome.branch),
                (None, None, Some(err)) => {
                    eprintln!("  ✗ {} — {err}", outcome.candidate_summary);
                    had_error = true;
                }
                (None, None, None) => println!("  · {} — planned, branch {}", outcome.candidate_summary, outcome.branch),
            }
        }
    }

    if had_error {
        std::process::exit(1);
    }
}
