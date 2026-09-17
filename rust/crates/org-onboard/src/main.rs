//! Thin CLI wrapper over `ignite_org_onboard`'s library functions — see
//! that crate's `lib.rs` for the full behavior doc (discovery, enrollment,
//! forced scan).
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

use ignite_github_api::GithubApi;
use ignite_org_onboard::{already_enrolled, discover_org, enroll_repo, parse_args};
use ignite_scheduled_rescan::{default_runner, open_db, rescan_one, AutoFixMode, RescanTarget};
use std::collections::HashSet;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let parsed = match parse_args(&raw) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    let runner = default_runner();
    let api = GithubApi::new(&runner);
    let gh_token = ignite_github_api::resolve_server_github_token();

    let db_path = std::env::var("IGNITE_DB_PATH").unwrap_or_else(|_| "ignite.db".to_string());
    let db = match open_db(&db_path) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    if !parsed.apply {
        println!("DRY RUN (pass --apply to actually enroll discovered repos) — no database writes will be made.\n");
    }

    let mut had_error = false;
    // Every repo actually in scope for a forced scan: discovered repos
    // from every `<org>` target, plus any `--repo org/repo` given
    // directly. A `HashSet` collapses the (rare, but possible) case where
    // an explicit `--repo` also turns up via org discovery.
    let mut scan_targets: Vec<RescanTarget> = Vec::new();
    let mut seen = HashSet::new();

    for org in &parsed.orgs {
        println!("Discovering repositories in {org}...");
        let repos = match discover_org(&api, org, &gh_token, parsed.include_archived, parsed.include_forks).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{org}: failed to list repositories: {e}");
                had_error = true;
                continue;
            }
        };
        println!("  found {} repo(s){}", repos.len(), if parsed.include_archived || parsed.include_forks { "" } else { " (excluding archived/forks)" });

        for r in &repos {
            let known = already_enrolled(&db, &r.org, &r.repo);
            if known {
                println!("  {}/{}: already known to Ignite", r.org, r.repo);
            } else if parsed.apply {
                match enroll_repo(&db, &r.org, &r.repo) {
                    Ok(id) => println!("  {}/{}: enrolled (project id {id})", r.org, r.repo),
                    Err(e) => {
                        eprintln!("  {}/{}: failed to enroll: {e}", r.org, r.repo);
                        had_error = true;
                    }
                }
            } else {
                println!("  {}/{}: would be enrolled (--apply to persist)", r.org, r.repo);
            }

            let target = RescanTarget { org: r.org.clone(), repo: r.repo.clone() };
            if seen.insert(target.clone()) {
                scan_targets.push(target);
            }
        }
    }

    for (org, repo) in &parsed.repos {
        let target = RescanTarget { org: org.clone(), repo: repo.clone() };
        if seen.insert(target.clone()) {
            scan_targets.push(target);
        }
    }

    if !parsed.scan {
        println!("\nPass --scan to run a real scan against every repository in scope.");
        if had_error {
            std::process::exit(1);
        }
        return;
    }

    println!("\nForcing a scan against {} repositor(y/ies)...", scan_targets.len());
    let server_base = std::env::var("IGNITE_SERVER_URL").unwrap_or_else(|_| "http://127.0.0.1:51337".to_string());
    let timeout_secs: u64 = std::env::var("IGNITE_SCHEDULED_RESCAN_TIMEOUT_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(1800);
    let http = match reqwest::Client::builder().timeout(std::time::Duration::from_secs(timeout_secs)).build() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to build http client: {e}");
            std::process::exit(1);
        }
    };

    for target in &scan_targets {
        let outcome = rescan_one(&runner, &http, &server_base, &gh_token, target, AutoFixMode::Off).await;
        match &outcome.error {
            Some(e) => {
                eprintln!("{}/{}: FAILED — {e}", outcome.org, outcome.repo);
                had_error = true;
            }
            None if outcome.issue_count == 0 => println!("{}/{}: clean — no findings.", outcome.org, outcome.repo),
            None => println!(
                "{}/{}: {} finding(s), job {} — {}",
                outcome.org,
                outcome.repo,
                outcome.issue_count,
                outcome.job_id.as_deref().unwrap_or("?"),
                if outcome.posted { "commit status updated" } else { "NOT posted (see error)" }
            ),
        }
    }

    if had_error {
        std::process::exit(1);
    }
}
