//! `scheduled-rescan` — run every onboarded project through a real scan
//! against its current GitHub default branch and post the result back as
//! a commit status (+ optional PR comment), the same way a push-triggered
//! scan already does via `POST /api/pipeline/:jobId/github-check`.
//!
//! Runnable standalone (`node scripts/scheduled-rescan.js` in the Node
//! original's design; here, `scheduled-rescan` the binary) for a cron/
//! systemd timer, or on a GitHub Actions `schedule:` trigger — see
//! `docs-site/docs/ci-integration.md`.
//!
//! Requires a running Ignite server at `IGNITE_SERVER_URL` (default
//! `http://127.0.0.1:51337`) — `validate-all`'s `projectPath` is a local
//! filesystem path, so this binary must run somewhere that can reach both
//! the server and a scratch directory it can clone into (typically the
//! same host). `IGNITE_DB_PATH` (default `ignite.db`) is opened read-only
//! in spirit — this binary only ever calls `list_projects`, never writes.
//! `GH_TOKEN`/`GITHUB_TOKEN` authenticates both the clone and (if the `gh`
//! CLI isn't on PATH) the direct GitHub API calls.
//!
//! `IGNITE_SCHEDULED_RESCAN_TIMEOUT_SECS` (default 1800 = 30 min) bounds
//! each project's `validate-all` HTTP call. A real full Phase 4 sweep on a
//! large repo can legitimately take well past 10 minutes — see
//! `rust/MIGRATION_STATUS.md`'s tadone benchmark notes (5-16+ minutes
//! normally, observed stalls to 19-32 minutes under heavy concurrent
//! system load) — so this defaults much higher than a typical HTTP
//! client's timeout to avoid a scheduled sweep spuriously failing on
//! exactly the large/slow repos this job most needs to cover.

use ignite_scheduled_rescan::{default_runner, dedupe_projects, open_db, rescan_one};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let db_path = std::env::var("IGNITE_DB_PATH").unwrap_or_else(|_| "ignite.db".to_string());
    let server_base = std::env::var("IGNITE_SERVER_URL").unwrap_or_else(|_| "http://127.0.0.1:51337".to_string());
    let gh_token = ignite_github_api::resolve_server_github_token();

    let db = match open_db(&db_path) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    let targets = dedupe_projects(&db.list_projects());
    if targets.is_empty() {
        println!("No onboarded projects found — nothing to re-scan.");
        return;
    }
    println!("Re-scanning {} onboarded project(s) against {server_base}...", targets.len());

    let timeout_secs: u64 = std::env::var("IGNITE_SCHEDULED_RESCAN_TIMEOUT_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(1800);
    let runner = default_runner();
    let http = reqwest::Client::builder().timeout(std::time::Duration::from_secs(timeout_secs)).build().expect("failed to build http client");
    let mut had_error = false;

    for target in &targets {
        let outcome = rescan_one(&runner, &http, &server_base, &gh_token, target).await;
        match &outcome.error {
            Some(e) => {
                eprintln!("{}/{}: FAILED — {e}", outcome.org, outcome.repo);
                had_error = true;
            }
            None if outcome.issue_count == 0 => {
                println!("{}/{}: clean — no findings, nothing posted.", outcome.org, outcome.repo);
            }
            None => {
                println!("{}/{}: {} finding(s), posted to job {} — {}", outcome.org, outcome.repo, outcome.issue_count, outcome.job_id.as_deref().unwrap_or("?"), if outcome.posted { "commit status updated" } else { "NOT posted (see error)" });
            }
        }
    }

    if had_error {
        std::process::exit(1);
    }
}
