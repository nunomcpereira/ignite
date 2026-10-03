//! Standalone driver mirroring `validate-all`'s scope for timing
//! comparisons against the Node implementation on a real repo: stages the
//! project (copy, like `stageExistingProject`), runs Phase 3's env-file/
//! CODEOWNERS/license/vulnerability checks concurrently with Phase 4's 33
//! checks, then reports total wall time and combined issue count.
//!
//! Not yet covered (see rust/crates/*/README-equivalent doc comments for
//! each gap): ORT license/dependency resolution (fallback-only for now),
//! the local LLM deep-scan endpoint, org-governance CI via `act`, and any
//! git/gh push path (this tool never ships — it only scans).
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

use std::path::PathBuf;
use std::time::Instant;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let mut args = std::env::args().skip(1);
    let source = args.next().expect("usage: phase4-scan <root> [posture-ruleset] [spectral-ruleset]");
    let ignite_root = args.next().map(PathBuf::from);
    let runner = ignite_phase4_orchestrator::standalone::standalone_runner(true);

    let db_dir = tempfile::tempdir().unwrap();
    let store = ignite_db_store::DbStore::open(&db_dir.path().join("scan.db")).unwrap();

    let t0 = Instant::now();

    // --- staging (mirrors server.js's stageExistingProject + resolveProjectRoot) ---
    let staging_parent = tempfile::tempdir().unwrap();
    let staging_dir = staging_parent.path().join("staged");
    let stage_result = ignite_staging::stage_existing_project(&source, &staging_dir).expect("staging failed");
    let root = ignite_staging::resolve_project_root(&staging_dir).expect("resolve_project_root failed");
    let stage_elapsed = t0.elapsed();

    // --- Phase 3: env-file check (blocking on raw .env* files) ---
    let env_check = ignite_staging::check_env_files(&root).expect("check_env_files failed");
    if !env_check.blocking.is_empty() {
        eprintln!("✗ Raw environment file(s) present: {}", env_check.blocking.join(", "));
        std::process::exit(1);
    }
    let codeowners = ignite_staging::check_codeowners(&root);
    if codeowners.found {
        println!("✓ CODEOWNERS found at {} ({} contact email(s)).", codeowners.path.as_deref().unwrap_or(""), codeowners.emails.len());
    } else {
        println!("ℹ No CODEOWNERS file found.");
    }

    // --- Phase 3 license/dependency scan + Phase 4, concurrently (matches server.js) ---
    let deps_dev_client = ignite_deps_dev_client::DepsDevClient::new();
    let npm_http = reqwest::Client::new();

    let config = ignite_phase4_orchestrator::standalone::standalone_config("bench-org", "bench-repo", ignite_root.as_deref(), Some(PathBuf::from(&source)));

    let hallucination_checker = ignite_package_hallucination::PackageHallucinationChecker::new(ignite_package_hallucination::HttpRegistryChecker::default());
    let (license_issues, vuln_issues, phase4_output) = tokio::join!(
        ignite_dependency_license_scan::run_license_compliance_check(&root, &runner, &deps_dev_client, &npm_http, |l| println!("{l}")),
        ignite_dependency_license_scan::run_dependency_vulnerability_check(&root, &deps_dev_client, |l| println!("{l}")),
        async { ignite_phase4_orchestrator::run_phase4_checks(&root, &runner, &store, &config, &hallucination_checker, &|l: &str| println!("{l}")).await.unwrap() },
    );

    let elapsed = t0.elapsed();

    let total_issues = phase4_output.issues.len() + license_issues.len() + vuln_issues.len();
    println!("---");
    println!("staged:        {} file(s), {:.1} MB ({:.2}s)", stage_result.file_count, stage_result.total_bytes as f64 / 1_048_576.0, stage_elapsed.as_secs_f64());
    println!("phase4 issues: {}", phase4_output.issues.len());
    println!("license issues:{}", license_issues.len());
    println!("vuln issues:   {}", vuln_issues.len());
    println!("TOTAL issues:  {total_issues}");
    println!("sbom doc:      {}", phase4_output.documents.sbom.is_some());
    println!("provenance:    {}", phase4_output.documents.provenance.is_some());
    println!("loc metrics:   {}", phase4_output.documents.loc_metrics.is_some());
    println!("posture:       {}", phase4_output.documents.posture_report.is_some());
    println!("ai-act docs:   {}", phase4_output.documents.ai_act_documents_report.is_some());
    println!("---");
    println!("TOTAL: {:.2}s", elapsed.as_secs_f64());
}
