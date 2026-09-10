//! Thin CLI wrapper over `ignite_enforce_gate_branch_protection`'s library
//! functions — see that crate's `lib.rs` for the full behavior doc
//! (per-repo classic branch protection, org-wide Repository Rulesets,
//! `--check-drift`). Split out so `crates/server`'s zero-touch repo
//! onboarding webhook (`routes/repository_events_webhook.rs`) can call
//! `plan_for_org`/`apply_org_plan` directly instead of shelling out to
//! this binary.

use ignite_enforce_gate_branch_protection::{apply_org_plan, apply_plan, default_runner, parse_args, plan_for_org, plan_for_repo, print_org_plan, print_plan};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let parsed = match parse_args(&raw) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(1);
        }
    };

    let runner = default_runner();

    // `--check-drift`: a dedicated report-first mode, separate from the
    // normal unconditional create-or-update flow below. Exit code is the
    // signal a cron/CI caller actually watches — 0 means every `--org`
    // target's ruleset already matches policy, 2 means at least one has
    // drifted (whether or not `--apply` was also given to reconcile it —
    // a caller alerting on drift wants to know it *happened* this run,
    // not just that it's fixed now), 1 means a lookup/apply error.
    if parsed.check_drift {
        let mut any_drift = false;
        let mut had_error = false;
        for org in &parsed.orgs {
            match plan_for_org(&runner, org).await {
                Ok(plan) => {
                    print_org_plan(&plan);
                    if !plan.drift.is_empty() {
                        any_drift = true;
                        if parsed.apply {
                            match apply_org_plan(&runner, &plan).await {
                                Ok(()) => println!("  reconciled.\n"),
                                Err(e) => {
                                    eprintln!("  FAILED: {e}\n");
                                    had_error = true;
                                }
                            }
                        } else {
                            println!();
                        }
                    } else {
                        println!();
                    }
                }
                Err(e) => {
                    eprintln!("org:{org}: {e}");
                    had_error = true;
                }
            }
        }
        if had_error {
            std::process::exit(1);
        }
        if any_drift {
            eprintln!("Drift detected in at least one org's ruleset — see above.");
            std::process::exit(2);
        }
        println!("No drift detected — every org's ruleset matches policy.");
        return;
    }

    if !parsed.apply {
        println!("DRY RUN (pass --apply to actually call GitHub) — no changes will be made.\n");
    }

    let mut had_error = false;

    for (org, repo) in &parsed.repos {
        match plan_for_repo(&runner, org, repo).await {
            Ok(plan) => {
                print_plan(&plan);
                if parsed.apply {
                    match apply_plan(&runner, &plan).await {
                        Ok(()) => println!("  applied.\n"),
                        Err(e) => {
                            eprintln!("  FAILED: {e}\n");
                            had_error = true;
                        }
                    }
                } else {
                    println!();
                }
            }
            Err(e) => {
                eprintln!("{org}/{repo}: {e}");
                had_error = true;
            }
        }
    }

    for org in &parsed.orgs {
        match plan_for_org(&runner, org).await {
            Ok(plan) => {
                print_org_plan(&plan);
                if parsed.apply {
                    match apply_org_plan(&runner, &plan).await {
                        Ok(()) => println!("  applied.\n"),
                        Err(e) => {
                            eprintln!("  FAILED: {e}\n");
                            had_error = true;
                        }
                    }
                } else {
                    println!();
                }
            }
            Err(e) => {
                eprintln!("org:{org}: {e}");
                had_error = true;
            }
        }
    }

    if had_error {
        std::process::exit(1);
    }
}
