//! `sast-bench` — scores Ignite's Phase 4 against the OWASP Benchmark for
//! Java (US-13). See the library's doc comment for the scoring rules.
//!
//! ```text
//! sast-bench [--mode full|fallback|both|consensus] [--benchmark-dir <dir>]
//!            [--cache-dir <dir>] [--out-dir <dir>] [--ignite-root <dir>]
//! ```
//!
//! Without `--benchmark-dir`, the Benchmark is fetched at the pinned commit
//! into `--cache-dir` (default `$IGNITE_SAST_BENCH_CACHE`, else
//! `~/.cache/ignite/sast-bench`) — outside this repository, since the
//! Benchmark is GPL-2.0. Writes `sast-bench-results.json` and
//! `sast-bench-scorecard.md` to `--out-dir` (default: current directory).
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

use ignite_sast_bench::{engine_runs, parse_expected_results, render_markdown, blocking_score, score, score_by_tool, score_policies, BenchReport, ModeResult, BENCHMARK_COMMIT, BENCHMARK_REPO, EXPECTED_RESULTS_FILE};
use ignite_tool_runner::{RunToolOptions, ToolRunner};
use std::path::{Path, PathBuf};
use std::time::Instant;

struct Args {
    modes: Vec<&'static str>,
    benchmark_dir: Option<PathBuf>,
    cache_dir: PathBuf,
    out_dir: PathBuf,
    ignite_root: Option<PathBuf>,
}

fn usage() -> ! {
    eprintln!("usage: sast-bench [--mode full|fallback|both|consensus] [--benchmark-dir <dir>] [--cache-dir <dir>] [--out-dir <dir>] [--ignite-root <dir>]");
    std::process::exit(2);
}

fn parse_args() -> Args {
    let default_cache = std::env::var_os("IGNITE_SAST_BENCH_CACHE")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(std::env::temp_dir).join(".cache/ignite/sast-bench"));
    let mut a = Args { modes: vec!["full", "fallback"], benchmark_dir: None, cache_dir: default_cache, out_dir: PathBuf::from("."), ignite_root: None };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut val = || it.next().unwrap_or_else(|| usage());
        match flag.as_str() {
            "--mode" => {
                a.modes = match val().as_str() {
                    "full" => vec!["full"],
                    "fallback" => vec!["fallback"],
                    "both" => vec!["full", "fallback"],
                    // Before/after for engine consensus: the same full scan
                    // with consensus off, then on, through the real pipeline.
                    "consensus" => vec!["full", "full-consensus"],
                    _ => usage(),
                }
            }
            "--benchmark-dir" => a.benchmark_dir = Some(PathBuf::from(val())),
            "--cache-dir" => a.cache_dir = PathBuf::from(val()),
            "--out-dir" => a.out_dir = PathBuf::from(val()),
            "--ignite-root" => a.ignite_root = Some(PathBuf::from(val())),
            "-h" | "--help" => usage(),
            _ => usage(),
        }
    }
    a
}

async fn git(runner: &ToolRunner, cwd: &Path, args: &[&str]) -> Result<String, String> {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    runner
        .run_tool("git", &args, &cwd.to_string_lossy(), RunToolOptions { timeout_ms: Some(15 * 60_000), ..Default::default() })
        .await
        .map(|o| o.stdout.trim().to_string())
        .map_err(|e| e.to_string())
}

/// Shallow-fetches exactly [`BENCHMARK_COMMIT`] into `dir` unless a checkout
/// at that commit is already there.
async fn ensure_benchmark(runner: &ToolRunner, dir: &Path) -> Result<(), String> {
    if dir.join(EXPECTED_RESULTS_FILE).is_file() && git(runner, dir, &["rev-parse", "HEAD"]).await.ok().as_deref() == Some(BENCHMARK_COMMIT) {
        return Ok(());
    }
    if dir.exists() {
        std::fs::remove_dir_all(dir).map_err(|e| format!("clearing stale {}: {e}", dir.display()))?;
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    eprintln!("Fetching OWASP Benchmark {BENCHMARK_COMMIT} into {} …", dir.display());
    git(runner, dir, &["init", "-q"]).await?;
    git(runner, dir, &["remote", "add", "origin", BENCHMARK_REPO]).await?;
    git(runner, dir, &["fetch", "-q", "--depth", "1", "origin", BENCHMARK_COMMIT]).await?;
    git(runner, dir, &["checkout", "-q", "FETCH_HEAD"]).await?;
    Ok(())
}

async fn run_mode(mode: &'static str, benchmark_dir: &Path, ignite_root: Option<&Path>, cases: &[ignite_sast_bench::TestCase]) -> Result<ModeResult, String> {
    let runner = ignite_phase4_orchestrator::standalone::standalone_runner(mode != "fallback");
    let mut config = ignite_phase4_orchestrator::standalone::standalone_config("sast-bench", "benchmark-java", ignite_root, Some(benchmark_dir.to_path_buf()));
    if mode == "full-consensus" {
        config.sast_consensus = Some(ignite_override_engine::ConsensusPolicy::default());
    }
    let db_dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let store = ignite_db_store::DbStore::open(&db_dir.path().join("bench.db")).map_err(|e| e.to_string())?;
    let staging_parent = tempfile::tempdir().map_err(|e| e.to_string())?;
    let staging_dir = staging_parent.path().join("staged");
    ignite_staging::stage_existing_project(&benchmark_dir.to_string_lossy(), &staging_dir).map_err(|e| format!("staging failed: {e}"))?;
    let root = ignite_staging::resolve_project_root(&staging_dir).map_err(|e| e.to_string())?;
    let checker = ignite_package_hallucination::PackageHallucinationChecker::new(ignite_package_hallucination::HttpRegistryChecker::default());

    eprintln!("[{mode}] running Phase 4 …");
    let t0 = Instant::now();
    let output = ignite_phase4_orchestrator::run_phase4_checks(&root, &runner, &store, &config, &checker, &|l: &str| eprintln!("[{mode}] {l}")).await.map_err(|e| e.to_string())?;
    let duration_secs = (t0.elapsed().as_secs_f64() * 10.0).round() / 10.0;
    Ok(ModeResult { mode: mode.to_string(), duration_secs, engines: engine_runs(&output.coverage), scorecard: score(cases, &output.issues), by_tool: score_by_tool(cases, &output.issues), policies: score_policies(cases, &output.issues), blocking: blocking_score(cases, &output.issues) })
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_writer(std::io::stderr).init();
    let args = parse_args();
    let git_runner = ignite_phase4_orchestrator::standalone::standalone_runner(false);

    let benchmark_dir = match &args.benchmark_dir {
        Some(d) => d.clone(),
        None => {
            let d = args.cache_dir.join(format!("BenchmarkJava-{BENCHMARK_COMMIT}"));
            if let Err(e) = ensure_benchmark(&git_runner, &d).await {
                eprintln!("error: could not fetch the OWASP Benchmark: {e}");
                std::process::exit(1);
            }
            d
        }
    };
    let benchmark_commit = git(&git_runner, &benchmark_dir, &["rev-parse", "HEAD"]).await.unwrap_or_else(|_| "unknown".to_string());
    if benchmark_commit != BENCHMARK_COMMIT {
        eprintln!("warning: benchmark checkout is at {benchmark_commit}, not the pinned {BENCHMARK_COMMIT}; scores are not comparable with published ones");
    }
    let csv = match std::fs::read_to_string(benchmark_dir.join(EXPECTED_RESULTS_FILE)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: reading {}: {e}", benchmark_dir.join(EXPECTED_RESULTS_FILE).display());
            std::process::exit(1);
        }
    };
    let cases = match parse_expected_results(&csv) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {EXPECTED_RESULTS_FILE}: {e}");
            std::process::exit(1);
        }
    };

    let ignite_commit = match std::env::current_dir() {
        Ok(cwd) => git(&git_runner, &cwd, &["rev-parse", "HEAD"]).await.ok().filter(|s| !s.is_empty()),
        Err(_) => None,
    };
    let mut modes = Vec::new();
    for mode in &args.modes {
        match run_mode(mode, &benchmark_dir, args.ignite_root.as_deref(), &cases).await {
            Ok(m) => modes.push(m),
            Err(e) => {
                eprintln!("error: {mode} run failed: {e}");
                std::process::exit(1);
            }
        }
    }

    let report = BenchReport {
        benchmark_repo: BENCHMARK_REPO.to_string(),
        benchmark_commit,
        test_cases: cases.len() as u32,
        ignite_commit,
        generated_at: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        modes,
    };
    let json_path = args.out_dir.join("sast-bench-results.json");
    let md_path = args.out_dir.join("sast-bench-scorecard.md");
    let write = |p: &Path, body: String| {
        if let Err(e) = std::fs::write(p, body) {
            eprintln!("error: writing {}: {e}", p.display());
            std::process::exit(1);
        }
    };
    write(&json_path, serde_json::to_string_pretty(&report).unwrap_or_default());
    let mut md = render_markdown(&report);
    if let (Some(before), Some(after)) = (report.modes.iter().find(|m| m.mode == "full"), report.modes.iter().find(|m| m.mode == "full-consensus")) {
        md.push_str(&ignite_sast_bench::render_comparison(before, after));
    }
    write(&md_path, md.clone());
    println!("{md}");
    eprintln!("Wrote {} and {}", json_path.display(), md_path.display());
}
