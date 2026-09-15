//! `retention-sweeper` — US-05's independently scheduled cleanup for
//! retained source directories. Same dry-run-by-default/`--apply`
//! convention as `enforce-gate-branch-protection`/`auto-fix-pr`: run by
//! hand, cron, systemd timer, or a scheduled GitHub Actions workflow (see
//! `docs-site/docs/ci-integration.md` for the analogous `scheduled-rescan`
//! example) — never auto-wired into the running server itself.
//!
//! ```text
//! retention-sweeper [--apply] [--max-age-days N]
//! ```
//!
//! `IGNITE_DB_PATH` (default `ignite.db`), `IGNITE_RETENTION_MAX_AGE_DAYS`
//! (default 90, overridden by `--max-age-days`).
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

use ignite_retention_sweeper::sweep_once;

fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let apply = args.iter().any(|a| a == "--apply");
    let max_age_days = args
        .iter()
        .position(|a| a == "--max-age-days")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse::<i64>().ok())
        .or_else(|| std::env::var("IGNITE_RETENTION_MAX_AGE_DAYS").ok().and_then(|v| v.parse::<i64>().ok()))
        .unwrap_or(90);

    let db_path = std::env::var("IGNITE_DB_PATH").unwrap_or_else(|_| "ignite.db".to_string());
    let db = match ignite_db_store::DbStore::open(std::path::Path::new(&db_path)) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("Failed to open {db_path}: {e}");
            std::process::exit(1);
        }
    };

    println!("Retention sweep: max age {max_age_days} day(s){}", if apply { " (applying)" } else { " (dry run — pass --apply to actually delete)" });
    let report = sweep_once(&db, max_age_days, apply);

    if !report.marked_missing.is_empty() {
        println!("{} retained-source row(s) point at a directory no longer on disk — marked `missing`:", report.marked_missing.len());
        for project_id in &report.marked_missing {
            println!("  project {project_id}");
        }
    }

    if report.evicted.is_empty() {
        println!("Nothing past the retention window.");
        return;
    }

    println!("{} retained source(s) past the {max_age_days}-day retention window{}:", report.evicted.len(), if apply { ", evicted" } else { ", would evict" });
    for entry in &report.evicted {
        println!("  project {} — {}", entry.project_id, entry.dir_path);
    }
}
