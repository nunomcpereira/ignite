//! Phase 4 check orchestrator. Faithful port of server.js's
//! `runPhase4Checks`: fans out to every check concurrently, converts each
//! check's own richly-typed result into `override-engine`'s generic
//! `RawFinding`/`CheckResult` shape, and calls `collect_phase4_issues` to
//! produce the final addressable issue list.
//!
//! `FAST_MODE_TASKS` filtering (secrets/governance/semanticSast/
//! fileEncapsulation only) is implemented.
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

use ignite_db_store::DbStore;
use ignite_override_engine::{CheckResult, CodeqlFinding as OeCodeqlFinding, CodeqlResult, Issue, LlmFinding as OeLlmFinding, LlmResult, Phase4Inputs, RawFinding};
use ignite_tool_runner::ToolRunner;
use std::collections::HashMap;
use std::path::Path;

fn snippet_json<T: serde::Serialize>(snippet: &Option<T>) -> Option<serde_json::Value> {
    snippet.as_ref().and_then(|s| serde_json::to_value(s).ok())
}

/// Per-check ceiling on the concurrent Phase 4 fan-out below. With
/// `tokio::join!` (not `try_join!`), total wall time is bounded by the
/// *slowest* single check rather than short-circuiting on the first error
/// — correct for not losing 18 other checks' work to one bad one, but it
/// means one check with an unbounded wait (a network call to an
/// unreachable host that never resets the connection, rather than
/// refusing it outright) can now stall the entire run indefinitely instead
/// of just that one check. Every genuinely fallible check future is
/// wrapped in this so a hang degrades to a timed-out "error" result for
/// that check alone, same as any other check-level failure.
const DEFAULT_CHECK_TIMEOUT_SECS: u64 = 1200;

/// Overridable via `IGNITE_PHASE4_CHECK_TIMEOUT_SECS` — same pattern as
/// `scheduled-rescan`'s `IGNITE_SCHEDULED_RESCAN_TIMEOUT_SECS` — for a
/// deployment where 1200s is too short (a very large monorepo) or too
/// long (a CI job with a tighter overall budget than that per check).
fn check_timeout() -> std::time::Duration {
    let secs = std::env::var("IGNITE_PHASE4_CHECK_TIMEOUT_SECS").ok().and_then(|v| v.parse::<u64>().ok()).filter(|&s| s > 0).unwrap_or(DEFAULT_CHECK_TIMEOUT_SECS);
    std::time::Duration::from_secs(secs)
}

async fn with_timeout<F, T>(name: &'static str, log: &(dyn Fn(&str) + Sync), fut: F) -> std::io::Result<T>
where
    F: std::future::Future<Output = std::io::Result<T>>,
{
    let timeout = check_timeout();
    match tokio::time::timeout(timeout, fut).await {
        Ok(r) => r,
        Err(_) => {
            log(&format!("✗ {name} timed out after {}s — skipping.", timeout.as_secs()));
            Err(std::io::Error::new(std::io::ErrorKind::TimedOut, format!("{name} timed out after {}s", timeout.as_secs())))
        }
    }
}

/// Same timeout guard as `with_timeout`, for the checks whose own result
/// type is infallible (no `io::Result` wrapper) — without this, any one of
/// them hanging (a stuck subprocess: semgrep/bearer/jscpd/`git log`/zizmor)
/// would stall the whole `tokio::join!` fan-out below indefinitely, since
/// only the genuinely-fallible futures were ever wrapped in a timeout.
async fn with_timeout_or<F, T>(name: &'static str, log: &(dyn Fn(&str) + Sync), fut: F, on_timeout: impl FnOnce() -> T) -> T
where
    F: std::future::Future<Output = T>,
{
    let timeout = check_timeout();
    match tokio::time::timeout(timeout, fut).await {
        Ok(r) => r,
        Err(_) => {
            log(&format!("✗ {name} timed out after {}s — skipping.", timeout.as_secs()));
            on_timeout()
        }
    }
}

fn to_oe_codeql_finding(f: &ignite_codeql_cross_file::CodeqlFinding) -> OeCodeqlFinding {
    OeCodeqlFinding {
        file: Some(f.file.clone()),
        line: Some(f.line as i64),
        kind: Some(f.kind.clone()),
        severity: Some(f.severity.clone()),
        message: Some(f.message.clone()),
        snippet: snippet_json(&f.snippet),
        cross_file: f.cross_file,
        chain: snippet_json(&f.chain),
        cwe: f.cwe.clone(),
    }
}

pub struct Phase4Config {
    pub fast: bool,
    pub org: String,
    pub repo: String,
    pub project_id: Option<i64>,
    pub secrets: ignite_secrets::SecretsConfig,
    pub secret_verification: ignite_secret_verifier::SecretVerifierConfig,
    pub llm: Option<ignite_llm_deep_scan::LlmDeepScanConfig>,
    pub iac: ignite_iac_security::IacSecurityConfig,
    pub gha_security: ignite_gha_security::GhaSecurityConfig,
    pub container_image_vulnerabilities: ignite_container_image_vulnerabilities::ContainerImageVulnerabilitiesConfig,
    pub sbom_enabled: bool,
    pub image_provenance: ignite_image_provenance::ImageProvenanceConfig,
    pub semantic_sast: ignite_semantic_sast::SemanticSastConfig,
    pub pii_data_flow: ignite_pii_dataflow::PiiDataFlowConfig,
    pub code_duplication: ignite_code_duplication::CodeDuplicationConfig,
    pub file_encapsulation: ignite_file_encapsulation::FileEncapsulationConfig,
    pub loc_metrics_enabled: bool,
    pub api_schema: ignite_api_schema::ApiSchemaConfig,
    pub api_schema_drift: ignite_api_schema_drift::ApiSchemaDriftConfig,
    pub malicious_dependencies: ignite_malicious_dependencies::MaliciousDependenciesConfig,
    pub model_artifact_security: ignite_model_artifact_security::ModelArtifactSecurityConfig,
    pub package_hallucination_enabled: bool,
    pub feature_posture: ignite_feature_posture::FeaturePostureConfig,
    pub eu_ai_act_documents_enabled: bool,
    pub eu_ai_act_report_as_findings: bool,
    pub dead_code: ignite_dead_code::DeadCodeConfig,
    pub complexity_health: ignite_complexity_health::ComplexityHealthConfig,
    pub css_dead_code: ignite_css_dead_code::CssDeadCodeConfig,
    pub boundaries: ignite_boundaries::BoundariesConfig,
    pub env_var_drift: ignite_env_var_drift::EnvVarDriftConfig,
    pub igniteignore_enabled: bool,
    /// The real, original project directory to check `.igniteignore`'s
    /// git-tracked status against, when it's different from `root` (the
    /// scanned copy `run_phase4_checks` is given). Staging always strips
    /// `.git` out of the copy it makes (`walk_files`'s `SKIP_DIRS`) — for
    /// the CLI/pre-push/onboard headless paths, which stage an existing
    /// local directory that may well be a real git checkout, checking
    /// `root` itself would report every such run as "no git history" even
    /// though the real source right next to it has one. `None` (the
    /// interactive ZIP/folder-upload path, which has no other backing
    /// directory to check) falls back to `root`, which is the correct
    /// "can't verify, so don't assume safe" behavior there.
    pub igniteignore_git_check_root: Option<std::path::PathBuf>,
    pub codeql: ignite_codeql_cross_file::CodeqlConfig,
    /// Precomputed via `ignite_config::is_codeql_review_overdue` from
    /// `security.codeql.{reviewCadenceDays,lastReviewedAt}` — see
    /// `override_engine::CodeqlResult::query_suite_review_overdue`.
    pub codeql_query_suite_review_overdue: bool,
    /// When set, the CodeQL database(s) built for this run's compliance
    /// scan are persisted here instead of discarded — the same directory
    /// Studio's `/studio/codeql/query` and `/studio/callgraph` routes read
    /// from, so a project scanned through the normal pipeline already has
    /// a queryable database the moment Studio opens, with no separate
    /// "Run CodeQL" click needed. `None` (headless/CI validate-all calls
    /// with no project row, and any caller that never persisted a database
    /// before) keeps the old build-and-discard behavior.
    pub keep_codeql_db_dir: Option<std::path::PathBuf>,
}

pub struct Phase4Documents {
    pub sbom: Option<(String, Vec<u8>)>,
    pub provenance: Option<Vec<u8>>,
    pub loc_metrics: Option<Vec<u8>>,
    pub posture_report: Option<Vec<u8>>,
    pub ai_act_documents_report: Option<Vec<u8>>,
}

pub struct Phase4Output {
    pub issues: Vec<Issue>,
    pub documents: Phase4Documents,
    /// Per-check wall time, matching server.js's `__taskTimings` breakdown
    /// (there: one entry per `tasks` array member, pushed inside the single
    /// `Promise.all` fan-out). Empty entries never happen — every check
    /// that runs gets a timing, including the built-in ones outside the
    /// concurrent fan-out.
    pub task_timings: Vec<(&'static str, u64)>,
    /// US-02: one [`ignite_policy::CheckCoverage`] per check that ran (or
    /// was skipped/disabled/unavailable) this Phase 4 pass — see
    /// [`coverage_for_engine`]. Distinct from `issues`: a check with an
    /// empty findings list still gets a `Completed` coverage entry here,
    /// so "found nothing" and "never ran" are never conflated downstream.
    pub coverage: Vec<ignite_policy::CheckCoverage>,
}

/// Maps this codebase's existing `engine: &'static str` convention
/// (already present on ~25 check result structs — `"disabled"`,
/// `"failed"`/`"error"`, `"unconfigured"`, `"fallback"`, or the real tool/
/// `"built-in"` name) onto a [`ignite_policy::CheckCoverage`], with no
/// change needed to any individual check crate. `"fallback"` is the one
/// value that means a *degraded* built-in path was used in place of a
/// full external engine (`sbom`, `feature-posture`) — every other check's
/// own `"built-in"` is its one true native engine, not a degraded
/// substitute for anything, so it's `is_fallback: false`.
/// Every Phase 4 check id *except* `secrets`/`governance`/`semanticSast`/
/// `fileEncapsulation` (`FAST_MODE_TASKS`) — must be kept in sync with the
/// check ids passed to [`coverage_for_engine`]/`coverage.push` in the
/// full-mode path below.
const FULL_MODE_ONLY_CHECKS: &[&str] = &[
    "pii",
    "duplication",
    "locMetrics",
    "igniteIgnore",
    "llm",
    "iac",
    "ghaSecurity",
    "imageVulnerabilities",
    "sbom",
    "provenance",
    "imageProvenance",
    "apiSchema",
    "apiSchemaDrift",
    "maliciousDependencies",
    "modelArtifactSecurity",
    "packageHallucination",
    "posture",
    "codeql",
    "euAiActDocuments",
    "deadCode",
    "health",
    "cssDeadCode",
    "boundaries",
    "envVarDrift",
];

fn coverage_for_engine(check_id: &'static str, engine: &str, finding_count: usize) -> ignite_policy::CheckCoverage {
    use ignite_policy::CheckCoverage;
    match engine {
        "disabled" => CheckCoverage::disabled(check_id),
        "unavailable" => CheckCoverage::unavailable(check_id, "required engine was unavailable"),
        "failed" | "error" => CheckCoverage::failed(check_id, "check returned an error result instead of completing"),
        "timed_out" => CheckCoverage::timed_out(check_id),
        "unconfigured" => CheckCoverage::not_applicable(check_id, "not configured for this project"),
        "fallback" => CheckCoverage::completed(check_id, "built-in-fallback", true),
        other => CheckCoverage::completed(check_id, other, false).with_scope(format!("{finding_count} finding(s)")),
    }
}

fn to_json_bytes<T: serde::Serialize>(v: &T) -> Vec<u8> {
    serde_json::to_vec_pretty(v).unwrap_or_default()
}

/// Times a single fallible check future, matching the wall-clock captured
/// by server.js's per-task `Date.now()` wrapper around each `tasks[i].run`.
/// Also logs a start/done line right as each future is polled/resolves —
/// since every `timed()` call in the `tokio::try_join!` fan-out below runs
/// concurrently, these lines genuinely interleave in real time (unlike a
/// single summary logged after the whole join completes).
/// `summarize` renders what the check actually found (finding count, engine
/// used, or why it was skipped) onto the "done" line — a bare "done (Nms)"
/// with no result summary was the only signal Phase 4's ~20 concurrently-
/// fanned-out checks gave while streaming, unlike secrets/governance/etc.
/// above which already reported a finding count inline.
async fn timed<F, T, S>(name: &'static str, log: &(dyn Fn(&str) + Sync), fut: F, summarize: S) -> (T, u64)
where
    F: std::future::Future<Output = T>,
    S: FnOnce(&T) -> String,
{
    log(&format!("→ {name} starting..."));
    let t0 = std::time::Instant::now();
    let r = fut.await;
    let ms = t0.elapsed().as_millis() as u64;
    log(&format!("✓ {name} done ({ms}ms) — {}", summarize(&r)));
    (r, ms)
}

fn summarize_findings<T>(findings: &[T], engine: &str) -> String {
    format!("{} finding(s) via {engine}", findings.len())
}

pub async fn run_phase4_checks(
    root: &Path,
    runner: &ToolRunner,
    store: &DbStore,
    config: &Phase4Config,
    hallucination_checker: &ignite_package_hallucination::PackageHallucinationChecker<ignite_package_hallucination::HttpRegistryChecker>,
    log: &(dyn Fn(&str) + Sync),
) -> std::io::Result<Phase4Output> {
    let mut task_timings: Vec<(&'static str, u64)> = Vec::new();
    let mut coverage: Vec<ignite_policy::CheckCoverage> = Vec::new();
    let __t0 = std::time::Instant::now();
    log("→ secrets starting...");
    let secrets_cache = store.get_file_scan_cache(&config.org, &config.repo, "secrets");
    let secrets_cache: HashMap<String, ignite_secrets::CachedFileEntry> =
        secrets_cache.into_iter().filter_map(|(k, v)| serde_json::from_value::<ignite_secrets::CachedFileEntry>(v.findings).ok().map(|e| (k, e))).collect();
    let __t_secrets = std::time::Instant::now();
    let (mut secrets_result, secrets_new_cache) = ignite_secrets::check_secrets(root, &config.secrets, &secrets_cache)?;
    coverage.push(ignite_policy::CheckCoverage::completed("secrets", if config.secrets.gitleaks_enabled { "built-in+gitleaks" } else { "built-in" }, false).with_scope(format!("{} file(s) scanned, {} cache hit(s)", secrets_result.scanned, secrets_result.cache_hits)));
    store.replace_file_scan_cache(
        &config.org,
        &config.repo,
        "secrets",
        &secrets_new_cache.iter().map(|(k, v)| ignite_db_store::FileScanCacheInput { rel_path: k.clone(), hash: v.hash.clone(), findings: serde_json::to_value(v).unwrap() }).collect::<Vec<_>>(),
    );
    if config.secrets.gitleaks_enabled {
        // Operator-saved custom secret patterns (`/api/secret-patterns`)
        // previously only ever ran via the playground (one-off, no
        // persistence) or the retroactive `/sweep` endpoint (one pattern,
        // one repo, on demand) — never on the scans that actually gate a
        // push. Merging every *enabled* pattern into the gitleaks config
        // used here closes that gap: a saved pattern now applies to every
        // future working-tree/history scan the same way gitleaks' own
        // built-in rules do, with no extra opt-in beyond "enabled".
        let custom_patterns: Vec<ignite_secrets::CustomSecretPattern> =
            store.list_enabled_custom_secret_patterns().into_iter().map(|p| ignite_secrets::CustomSecretPattern { name: p.name, regex: p.regex }).collect();
        // `root` is the job's own staging directory (UUID-named, always
        // removed after the run regardless of outcome) — writing the merged
        // config as a *sibling* of it, named off that same UUID, gets the
        // same collision-free-across-concurrent-jobs guarantee for free
        // without scanning the config file itself as part of the working
        // tree (it lives next to `root`, not inside it).
        // RAII: the file is removed when `_custom_config_guard` drops at
        // the end of this block's scope, regardless of *how* the scope
        // ends — an early error return, a panic unwinding through here,
        // or the enclosing future being cancelled/timed-out mid-`.await`
        // (which runs local destructors but never reaches code sitting
        // after the `.await` point). The previous explicit
        // `std::fs::remove_file` call at the bottom of this block only
        // ever ran on the normal-completion path, leaking a file
        // containing operator-authored secret-detection regexes on disk
        // in every other case.
        struct TempFileGuard(Option<std::path::PathBuf>);
        impl Drop for TempFileGuard {
            fn drop(&mut self) {
                if let Some(path) = self.0.take() {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
        let mut _custom_config_guard = TempFileGuard(None);
        let custom_config_path: Option<std::path::PathBuf> = if custom_patterns.is_empty() {
            None
        } else {
            let toml = ignite_secrets::build_gitleaks_config_for_patterns(&custom_patterns, config.secrets.gitleaks_config_path.as_deref());
            let file_name = format!("ignite-gitleaks-custom-{}.toml", root.file_name().and_then(|n| n.to_str()).unwrap_or("job"));
            let path = root.parent().unwrap_or(root).join(file_name);
            match std::fs::write(&path, &toml) {
                Ok(()) => {
                    _custom_config_guard.0 = Some(path.clone());
                    Some(path)
                }
                Err(e) => {
                    log(&format!("⚠ failed to write custom secret pattern config ({e}) — scanning with the base gitleaks config only"));
                    None
                }
            }
        };
        let effective_config_path: Option<&Path> = custom_config_path.as_deref().or(config.secrets.gitleaks_config_path.as_deref());

        let gitleaks_raw = ignite_secrets::run_gitleaks_scan(root, runner, effective_config_path).await;
        let gitignore_patterns = ignite_fs_utils::load_gitignore_patterns(root);
        let added = ignite_secrets::merge_gitleaks_findings(&secrets_result.findings, &gitleaks_raw, &gitignore_patterns, &config.secrets.known_public_key_patterns);
        secrets_result.findings.extend(added);

        // Full (non-fast) mode always runs the slow git-history scan, regardless of the
        // config default — fast mode never does, regardless of the config value.
        if config.secrets.gitleaks_scan_history || !config.fast {
            let history_raw = ignite_secrets::run_gitleaks_history_scan(root, runner, effective_config_path).await;
            let history_added = ignite_secrets::merge_gitleaks_history_findings(&secrets_result.findings, &history_raw, &gitignore_patterns, &config.secrets.known_public_key_patterns);
            secrets_result.findings.extend(history_added);
        }
        // Cleanup now happens via `_custom_config_guard`'s `Drop` at the
        // end of this scope, not here.
    }
    let ms_secrets = __t_secrets.elapsed().as_millis() as u64;
    task_timings.push(("secrets", ms_secrets));
    log(&format!("✓ secrets done ({} finding(s), {ms_secrets}ms)", secrets_result.findings.len()));

    // GHAS-parity active token verification (off by default — see
    // `ignite_secret_verifier`'s own module doc for why). Sequential, not
    // fanned out: secret findings are normally few per scan, and this is
    // an already-opt-in, already-slow-by-nature network path, not one
    // worth the extra complexity of concurrent dispatch for.
    let secret_kinds: Vec<String> = if config.secret_verification.enabled {
        let http = reqwest::Client::new();
        let mut kinds = Vec::with_capacity(secrets_result.findings.len());
        for f in &secrets_result.findings {
            let line_text = f.code.as_ref().and_then(|s| s.lines.iter().find(|l| l.number == s.highlight_line)).map(|l| l.text.as_str());
            let mut outcome = match line_text.and_then(|lt| ignite_secret_verifier::extract_secret_value(&f.kind, lt)) {
                Some(value) => ignite_secret_verifier::verify_secret(&http, &config.secret_verification, &f.kind, &value).await,
                None => ignite_secret_verifier::VerificationOutcome::Unsupported,
            };
            // AWS needs both credential halves together (see
            // `ignite_secret_verifier`'s own module doc), which may not
            // both sit on the one highlighted line — fall back to the
            // finding's full multi-line snippet. `verify_secret_pair`
            // itself already no-ops (`Unsupported`) for any non-AWS kind
            // or an unpaired snippet, so this is safe to always attempt
            // whenever the single-value path came back empty.
            if outcome == ignite_secret_verifier::VerificationOutcome::Unsupported {
                if let Some(snippet) = &f.code {
                    let full_text = snippet.lines.iter().map(|l| l.text.as_str()).collect::<Vec<_>>().join("\n");
                    if let Some(pair) = ignite_secret_verifier::extract_aws_credential_pair(&full_text) {
                        outcome = ignite_secret_verifier::verify_secret_pair(&http, &config.secret_verification, &f.kind, &pair).await;
                    }
                }
            }
            if outcome == ignite_secret_verifier::VerificationOutcome::Live {
                log(&format!("✗ VERIFIED LIVE credential: {} at {}:{}", f.kind, f.file, f.line));
                kinds.push(format!("{} — VERIFIED LIVE", f.kind));
            } else {
                kinds.push(f.kind.clone());
            }
        }
        kinds
    } else {
        secrets_result.findings.iter().map(|f| f.kind.clone()).collect()
    };
    let secrets_check = CheckResult {
        findings: secrets_result.findings.iter().zip(secret_kinds.iter()).map(|(f, kind)| RawFinding { file: Some(f.file.clone()), line: Some(f.line as i64), kind: Some(kind.clone()), tool: Some(f.tool.to_string()), code: snippet_json(&f.code), ..Default::default() }).collect(),
        engine: Some("built-in".to_string()),
    };

    log("→ governance starting...");
    let governance_cache = store.get_file_scan_cache(&config.org, &config.repo, "governance");
    let governance_cache: HashMap<String, ignite_ai_governance::CachedFileEntry> =
        governance_cache.into_iter().filter_map(|(k, v)| serde_json::from_value::<ignite_ai_governance::CachedFileEntry>(v.findings).ok().map(|e| (k, e))).collect();
    let __t_governance = std::time::Instant::now();
    let (governance_result, governance_new_cache) = ignite_ai_governance::check_ai_governance(root, &governance_cache)?;
    store.replace_file_scan_cache(
        &config.org,
        &config.repo,
        "governance",
        &governance_new_cache.iter().map(|(k, v)| ignite_db_store::FileScanCacheInput { rel_path: k.clone(), hash: v.hash.clone(), findings: serde_json::to_value(v).unwrap() }).collect::<Vec<_>>(),
    );
    let ms_governance = __t_governance.elapsed().as_millis() as u64;
    coverage.push(ignite_policy::CheckCoverage::completed("governance", "built-in", false).with_duration_ms(ms_governance));
    task_timings.push(("governance", ms_governance));
    log(&format!("✓ governance done ({} finding(s), {ms_governance}ms)", governance_result.findings.len()));
    let governance_check =
        CheckResult { findings: governance_result.findings.iter().map(|f| RawFinding { file: Some(f.file.clone()), line: Some(f.line as i64), raw_snippet_text: Some(f.snippet.clone()), tool: Some("ai-governance".to_string()), code: snippet_json(&f.code), ..Default::default() }).collect(), engine: Some("built-in".to_string()) };

    if config.fast {
        // FAST_MODE_TASKS = secrets, governance, semanticSast, fileEncapsulation
        log("→ semanticSast starting...");
        let __t = std::time::Instant::now();
        // Same timeout guard normal (non-fast) mode already wraps this
        // call in below — without it, a hung Semgrep process stalled the
        // entire fast-mode scan indefinitely, defeating the point of
        // "fast" mode existing at all.
        let semantic_sast_result = with_timeout_or("semanticSast", log, ignite_semantic_sast::check_semantic_sast(root, runner, &config.semantic_sast), || ignite_semantic_sast::SemanticSastResult { findings: vec![], engine: "timed_out" }).await;
        let ms = __t.elapsed().as_millis() as u64;
        task_timings.push(("semanticSast", ms));
        log(&format!("✓ semanticSast done ({} finding(s), {ms}ms)", semantic_sast_result.findings.len()));
        let semantic_sast_check = CheckResult {
            findings: semantic_sast_result
                .findings
                .iter()
                .map(|f| RawFinding { file: Some(f.file.clone()), line: Some(f.line as i64), kind: Some(f.kind.clone()), tool: Some(f.tool.to_string()), severity: Some(f.severity.to_string()), message: Some(f.message.clone()), cwe: f.cwe.clone(), owasp: f.owasp.clone(), code: snippet_json(&f.code), ..Default::default() })
                .collect(),
            engine: Some(semantic_sast_result.engine.to_string()),
        };
        log("→ fileEncapsulation starting...");
        let __t = std::time::Instant::now();
        let file_encapsulation_result = ignite_file_encapsulation::check_file_encapsulation(root, &config.file_encapsulation).unwrap_or_else(|e| {
            log(&format!("✗ fileEncapsulation failed: {e}"));
            ignite_file_encapsulation::FileEncapsulationResult { findings: vec![], engine: "error" }
        });
        let ms = __t.elapsed().as_millis() as u64;
        task_timings.push(("fileEncapsulation", ms));
        log(&format!("✓ fileEncapsulation done ({} finding(s), {ms}ms)", file_encapsulation_result.findings.len()));
        let file_encapsulation_check = CheckResult {
            findings: file_encapsulation_result.findings.iter().map(|f| RawFinding { file: Some(f.file.clone()), line: Some(f.line as i64), kind: Some(f.kind.to_string()), tool: Some(f.tool.to_string()), severity: Some(f.severity.to_string()), message: Some(f.message.clone()), code: snippet_json(&f.code), ..Default::default() }).collect(),
            engine: Some(file_encapsulation_result.engine.to_string()),
        };

        let inputs = Phase4Inputs {
            secrets: secrets_check,
            governance: governance_check,
            llm: None,
            iac: None,
            gha_security: None,
            image_vulnerabilities: None,
            image_provenance: None,
            semantic_sast: Some(semantic_sast_check),
            pii_data_flow: None,
            duplication: None,
            file_encapsulation: Some(file_encapsulation_check),
            api_schema: None,
            api_schema_drift: None,
            malicious_dependencies: None,
            model_artifact_security: None,
            package_hallucination: None,
            codeql: None,
            dead_code: None,
            health: None,
            css_dead_code: None,
            boundaries: None,
            eu_ai_act: None,
            ignite_ignore: None,
            env_var_drift: None,
        };
        let issues = ignite_override_engine::collect_phase4_issues(&inputs);
        task_timings.push(("phase4Total", __t0.elapsed().as_millis() as u64));
        coverage.push(coverage_for_engine("semanticSast", semantic_sast_result.engine, semantic_sast_result.findings.len()));
        coverage.push(coverage_for_engine("fileEncapsulation", file_encapsulation_result.engine, file_encapsulation_result.findings.len()));
        // Every other Phase 4 check simply isn't run in fast mode
        // (`FAST_MODE_TASKS` above) — an operator's own deliberate
        // scope choice, the same "turned off" shape as `Disabled` for any
        // one check, not a failure of any kind.
        for check_id in FULL_MODE_ONLY_CHECKS {
            coverage.push(ignite_policy::CheckCoverage::disabled_with_reason(*check_id, "skipped: fast mode only runs secrets/governance/semanticSast/fileEncapsulation"));
        }
        return Ok(Phase4Output { issues, documents: Phase4Documents { sbom: None, provenance: None, loc_metrics: None, posture_report: None, ai_act_documents_report: None }, task_timings, coverage });
    }

    let http_client = reqwest::Client::new();

    // Every subprocess/network-bound Phase 4 check runs in ONE concurrent
    // fan-out (mirrors server.js's single `Promise.all()` over `activeTasks`
    // exactly). This used to be split into two sequential `tokio::join!`/
    // `tokio::try_join!` groups — group 2 (13 checks, including the slow
    // ones: Bearer, CodeQL, Trivy image build, GuardDog) never started until
    // every check in group 1 had *already* finished, even though nothing in
    // group 2 depends on group 1's output. On a project where every
    // individual check is only a few seconds, that stage-crossing wait was a
    // large fraction of total wall time — a real regression Node's flat
    // fan-out never had.
    //
    // Uses `tokio::join!`, not `try_join!`: with `try_join!`, one transient
    // I/O failure in any single auxiliary check (SBOM generation hitting a
    // permissions error, a manifest scanner failing to open a file) cancels
    // every other in-flight future and aborts the *entire* Phase 4 run —
    // losing every primary security check's already-in-progress or already-
    // completed work over one unrelated check's hiccup. Every future below
    // is therefore infallible: a check that can genuinely error (unlike the
    // already-infallible ones just wrapped in `Ok::<_, io::Error>(...)` for
    // a uniform shape) catches its own error, logs it, and degrades to an
    // empty "error" result for that one check only — everything else in the
    // fan-out still completes and still gets reported.
    let manifests = ignite_package_hallucination::default_manifests();
    let semantic_sast_fut = async {
        with_timeout_or("semanticSast", log, ignite_semantic_sast::check_semantic_sast(root, runner, &config.semantic_sast), || ignite_semantic_sast::SemanticSastResult { findings: vec![], engine: "timed_out" }).await
    };
    let pii_fut = async { with_timeout_or("pii", log, ignite_pii_dataflow::check_pii_data_flow(root, runner, &config.pii_data_flow), || ignite_pii_dataflow::PiiDataFlowResult { findings: vec![], engine: "timed_out" }).await };
    let duplication_fut =
        async { with_timeout_or("duplication", log, ignite_code_duplication::check_code_duplication(root, runner, &config.code_duplication), || ignite_code_duplication::CodeDuplicationResult { findings: vec![], engine: "error" }).await };
    let loc_metrics_fut = async { with_timeout_or("locMetrics", log, ignite_loc_metrics::generate_loc_metrics(root, runner, config.loc_metrics_enabled), || ignite_loc_metrics::LocMetricsResult { engine: "error", metrics: None }).await };
    let igniteignore_check_root = config.igniteignore_git_check_root.as_deref().unwrap_or(root);
    let igniteignore_fut = async {
        with_timeout_or("igniteignore", log, ignite_igniteignore::check_igniteignore_committed(root, igniteignore_check_root, runner, config.igniteignore_enabled), || ignite_igniteignore::IgniteIgnoreResult {
            findings: vec![],
            engine: "error",
        })
        .await
    };
    let gha_security_fut = async { with_timeout_or("ghaSecurity", log, ignite_gha_security::check_gha_security(root, runner, &config.gha_security), || ignite_gha_security::GhaSecurityResult { findings: vec![], engine: "error" }).await };

    // Every future below this point wraps a genuinely fallible check
    // (`std::io::Result<T>`) and must never let that error escape the
    // future — with `tokio::join!` (not `try_join!`) below, an error that
    // did escape would still just vanish into an unused `Result::Err`
    // rather than cancelling its 18 siblings, but catching it here is what
    // lets a per-check "skipped due to error" result actually get reported
    // and folded into `task_timings`/the issue list like every other run.
    let llm_fut = async {
        if let Some(llm_config) = &config.llm {
            match with_timeout("llm", log, ignite_llm_deep_scan::check_llm_deep_scan(root, llm_config, store, &config.org, &config.repo, |_l| {})).await {
                Ok(result) => Some(result),
                Err(e) => {
                    log(&format!("✗ llm failed: {e} — skipping."));
                    None
                }
            }
        } else {
            None
        }
    };
    let provenance_fut = async {
        if config.project_id.is_some() {
            match with_timeout("provenance", log, ignite_provenance::generate_provenance(root, runner, "0.1.0", ignite_provenance::ProvenanceParams { org: Some(&config.org), repo: Some(&config.repo), job_id: None })).await {
                Ok(provenance) => Some(provenance),
                Err(e) => {
                    log(&format!("✗ provenance failed: {e} — skipping."));
                    None
                }
            }
        } else {
            None
        }
    };
    let iac_fut = async {
        match with_timeout("iac", log, ignite_iac_security::check_iac_security(root, runner, &config.iac)).await {
            Ok(r) => r,
            Err(e) => {
                log(&format!("✗ iac failed: {e} — skipping."));
                ignite_iac_security::IacSecurityResult { findings: vec![], engine: "error".to_string() }
            }
        }
    };
    // Only reached in full (non-fast) mode. Unlike the gitleaks git-history
    // scan above (forced on unconditionally here — it's cheap relative to a
    // full run), the trivy image scan does a real `docker build` per
    // Dockerfile plus a full `trivy image` scan of the result, which can
    // run into several minutes per image. That cost is real enough that
    // `security.trivyImage.enabled` (`TRIVY_IMAGE_ENABLED`) is honored as
    // written here instead of being forced on — an operator who wants the
    // full GHAS-parity coverage this check provides opts in explicitly;
    // one who doesn't isn't stuck waiting on it every full run.
    let image_vuln_config = config.container_image_vulnerabilities.clone();
    let image_vuln_fut = async {
        match with_timeout("imageVulnerabilities", log, ignite_container_image_vulnerabilities::check_container_image_vulnerabilities(root, runner, &image_vuln_config)).await {
            Ok(r) => r,
            Err(e) => {
                log(&format!("✗ imageVulnerabilities failed: {e} — skipping."));
                ignite_container_image_vulnerabilities::ContainerImageVulnerabilitiesResult { findings: vec![], engine: "error" }
            }
        }
    };
    let sbom_fut = async {
        match with_timeout("sbom", log, ignite_sbom::generate_sbom(root, runner, config.sbom_enabled, &manifests, 1000)).await {
            Ok(r) => r,
            Err(e) => {
                log(&format!("✗ sbom failed: {e} — skipping."));
                ignite_sbom::SbomResult { engine: "error", sbom: ignite_sbom::SbomOutcome::Fallback(ignite_sbom::FallbackSbom { bom_format: "ignite-fallback", spec_version: None, components: vec![] }) }
            }
        }
    };
    let image_provenance_fut = async {
        match with_timeout("imageProvenance", log, ignite_image_provenance::check_image_provenance(root, runner, &config.image_provenance, Some(store))).await {
            Ok(r) => r,
            Err(e) => {
                log(&format!("✗ imageProvenance failed: {e} — skipping."));
                ignite_image_provenance::ImageProvenanceResult { findings: vec![], engine: "error" }
            }
        }
    };
    let api_schema_fut = async {
        match with_timeout("apiSchema", log, ignite_api_schema::check_api_schemas(root, runner, &config.api_schema)).await {
            Ok(r) => r,
            Err(e) => {
                log(&format!("✗ apiSchema failed: {e} — skipping."));
                ignite_api_schema::ApiSchemaResult { findings: vec![], engine: "error" }
            }
        }
    };
    let api_schema_drift_fut = async {
        match with_timeout("apiSchemaDrift", log, ignite_api_schema_drift::check_api_schema_drift(root, runner, &config.api_schema_drift)).await {
            Ok(r) => r,
            Err(e) => {
                log(&format!("✗ apiSchemaDrift failed: {e} — skipping."));
                ignite_api_schema_drift::ApiSchemaDriftResult { findings: vec![], engine: "error" }
            }
        }
    };
    let malicious_deps_fut = async {
        match with_timeout("maliciousDependencies", log, ignite_malicious_dependencies::check_malicious_dependencies(root, runner, &config.malicious_dependencies, Some(store))).await {
            Ok(r) => r,
            Err(e) => {
                log(&format!("✗ maliciousDependencies failed: {e} — skipping."));
                ignite_malicious_dependencies::MaliciousDependenciesResult { findings: vec![], engine: "error" }
            }
        }
    };
    let model_artifact_fut = async {
        match with_timeout("modelArtifactSecurity", log, ignite_model_artifact_security::check_model_artifact_security(root, runner, &config.model_artifact_security)).await {
            Ok(r) => r,
            Err(e) => {
                log(&format!("✗ modelArtifactSecurity failed: {e} — skipping."));
                ignite_model_artifact_security::ModelArtifactSecurityResult { findings: vec![], engine: "error" }
            }
        }
    };
    let hallucination_fut = async {
        match with_timeout("packageHallucination", log, hallucination_checker.check(root, config.package_hallucination_enabled, &manifests)).await {
            Ok(r) => r,
            Err(e) => {
                log(&format!("✗ packageHallucination failed: {e} — skipping."));
                ignite_package_hallucination::PackageHallucinationResult { findings: vec![], engine: "error", checked_count: 0 }
            }
        }
    };
    let posture_fut = async {
        match with_timeout("posture", log, ignite_feature_posture::check_feature_posture(root, runner, &config.feature_posture)).await {
            Ok(r) => r,
            Err(e) => {
                log(&format!("✗ posture failed: {e} — skipping."));
                ignite_feature_posture::FeaturePostureResult { engine: "error", posture: Default::default() }
            }
        }
    };
    let codeql_fut = async {
        match with_timeout("codeql", log, ignite_codeql_cross_file::check_codeql_cross_file(root, runner, &config.codeql, ignite_codeql_cross_file::CodeqlContext { org: Some(&config.org), repo: Some(&config.repo), store: Some(store), keep_db_dir: config.keep_codeql_db_dir.as_deref() })).await {
            Ok(r) => r,
            Err(e) => {
                log(&format!("✗ codeql failed: {e} — skipping."));
                ignite_codeql_cross_file::CodeqlCrossFileResult { findings: vec![], engine: "error", languages: vec![], failed_languages: vec![] }
            }
        }
    };

    let (
        (semantic_sast_result, ms_semantic_sast),
        (pii_result, ms_pii),
        (duplication_result, ms_duplication),
        (loc_metrics_result, ms_loc_metrics),
        (igniteignore_result, ms_igniteignore),
        (llm_result, ms_llm),
        (iac_result, ms_iac),
        (gha_security_result, ms_gha_security),
        (image_vuln_result, ms_image_vuln),
        (sbom_result, ms_sbom),
        (provenance_result, ms_provenance),
        (image_provenance_result, ms_image_provenance),
        (api_schema_result, ms_api_schema),
        (api_schema_drift_result, ms_api_schema_drift),
        (malicious_deps_result, ms_malicious_deps),
        (model_artifact_result, ms_model_artifact),
        (hallucination_result, ms_hallucination),
        (posture_result, ms_posture),
        (codeql_result, ms_codeql),
    ) = tokio::join!(
        Box::pin(timed("semanticSast", log, semantic_sast_fut, |r| summarize_findings(&r.findings, r.engine))),
        Box::pin(timed("pii", log, pii_fut, |r| summarize_findings(&r.findings, r.engine))),
        Box::pin(timed("duplication", log, duplication_fut, |r| summarize_findings(&r.findings, r.engine))),
        Box::pin(timed("locMetrics", log, loc_metrics_fut, |r| match &r.metrics {
            Some(m) => format!("{} file(s), {} language(s) via {}", m.files.len(), m.languages.len(), r.engine),
            None => "disabled".to_string(),
        })),
        Box::pin(timed("igniteIgnore", log, igniteignore_fut, |r| summarize_findings(&r.findings, r.engine))),
        Box::pin(timed("llm", log, llm_fut, |r| match r {
            Some(x) if x.available => summarize_findings(&x.findings, "llm-deep-scan"),
            Some(_) => "model unavailable, skipped".to_string(),
            None => "disabled".to_string(),
        })),
        Box::pin(timed("iac", log, iac_fut, |r| summarize_findings(&r.findings, &r.engine))),
        Box::pin(timed("ghaSecurity", log, gha_security_fut, |r| summarize_findings(&r.findings, r.engine))),
        Box::pin(timed("imageVulnerabilities", log, image_vuln_fut, |r| summarize_findings(&r.findings, r.engine))),
        Box::pin(timed("sbom", log, sbom_fut, |r| match &r.sbom {
            ignite_sbom::SbomOutcome::Syft(_) => "generated via syft".to_string(),
            ignite_sbom::SbomOutcome::Fallback(f) => format!("{} component(s) via fallback", f.components.len()),
        })),
        Box::pin(timed("provenance", log, provenance_fut, |r| if r.is_some() { "generated".to_string() } else { "skipped (no project id)".to_string() })),
        Box::pin(timed("imageProvenance", log, image_provenance_fut, |r| summarize_findings(&r.findings, r.engine))),
        Box::pin(timed("apiSchema", log, api_schema_fut, |r| summarize_findings(&r.findings, r.engine))),
        Box::pin(timed("apiSchemaDrift", log, api_schema_drift_fut, |r| summarize_findings(&r.findings, r.engine))),
        Box::pin(timed("maliciousDependencies", log, malicious_deps_fut, |r| summarize_findings(&r.findings, r.engine))),
        Box::pin(timed("modelArtifactSecurity", log, model_artifact_fut, |r| summarize_findings(&r.findings, r.engine))),
        Box::pin(timed("packageHallucination", log, hallucination_fut, |r| summarize_findings(&r.findings, r.engine))),
        Box::pin(timed("posture", log, posture_fut, |r| format!("{} categories assessed via {}", r.posture.len(), r.engine))),
        Box::pin(timed("codeql", log, codeql_fut, |r| format!("{} finding(s)", r.findings.len()))),
    );
    task_timings.extend([
        ("semanticSast", ms_semantic_sast),
        ("pii", ms_pii),
        ("duplication", ms_duplication),
        ("locMetrics", ms_loc_metrics),
        ("igniteIgnore", ms_igniteignore),
        ("llm", ms_llm),
        ("iac", ms_iac),
        ("ghaSecurity", ms_gha_security),
        ("imageVulnerabilities", ms_image_vuln),
        ("sbom", ms_sbom),
        ("provenance", ms_provenance),
        ("imageProvenance", ms_image_provenance),
        ("apiSchema", ms_api_schema),
        ("apiSchemaDrift", ms_api_schema_drift),
        ("maliciousDependencies", ms_malicious_deps),
        ("modelArtifactSecurity", ms_model_artifact),
        ("packageHallucination", ms_hallucination),
        ("posture", ms_posture),
        ("codeql", ms_codeql),
    ]);

    coverage.push(coverage_for_engine("semanticSast", semantic_sast_result.engine, semantic_sast_result.findings.len()));
    coverage.push(coverage_for_engine("pii", pii_result.engine, pii_result.findings.len()));
    coverage.push(coverage_for_engine("duplication", duplication_result.engine, duplication_result.findings.len()));
    coverage.push(match &loc_metrics_result.metrics {
        Some(m) => coverage_for_engine("locMetrics", loc_metrics_result.engine, m.files.len()).with_scope(format!("{} language(s)", m.languages.len())),
        None => coverage_for_engine("locMetrics", loc_metrics_result.engine, 0),
    });
    coverage.push(coverage_for_engine("igniteIgnore", igniteignore_result.engine, igniteignore_result.findings.len()));
    coverage.push(match &llm_result {
        None => ignite_policy::CheckCoverage::disabled("llm"),
        Some(x) if !x.available => ignite_policy::CheckCoverage::unavailable("llm", x.reason.clone().unwrap_or_else(|| "model unavailable".to_string())),
        Some(x) => ignite_policy::CheckCoverage::completed("llm", "llm-deep-scan", false).with_scope(format!("{} finding(s)", x.findings.len())),
    });
    coverage.push(coverage_for_engine("iac", &iac_result.engine, iac_result.findings.len()));
    coverage.push(coverage_for_engine("ghaSecurity", gha_security_result.engine, gha_security_result.findings.len()));
    coverage.push(coverage_for_engine("imageVulnerabilities", image_vuln_result.engine, image_vuln_result.findings.len()));
    coverage.push(coverage_for_engine(
        "sbom",
        sbom_result.engine,
        match &sbom_result.sbom {
            ignite_sbom::SbomOutcome::Syft(v) => v.get("components").and_then(|c| c.as_array()).map(|a| a.len()).unwrap_or(0),
            ignite_sbom::SbomOutcome::Fallback(f) => f.components.len(),
        },
    ));
    coverage.push(if provenance_result.is_some() { ignite_policy::CheckCoverage::completed("provenance", "built-in", false) } else { ignite_policy::CheckCoverage::not_applicable("provenance", "no project id") });
    coverage.push(coverage_for_engine("imageProvenance", image_provenance_result.engine, image_provenance_result.findings.len()));
    coverage.push(coverage_for_engine("apiSchema", api_schema_result.engine, api_schema_result.findings.len()));
    coverage.push(coverage_for_engine("apiSchemaDrift", api_schema_drift_result.engine, api_schema_drift_result.findings.len()));
    coverage.push(coverage_for_engine("maliciousDependencies", malicious_deps_result.engine, malicious_deps_result.findings.len()));
    coverage.push(coverage_for_engine("modelArtifactSecurity", model_artifact_result.engine, model_artifact_result.findings.len()));
    coverage.push(coverage_for_engine("packageHallucination", hallucination_result.engine, hallucination_result.findings.len()));
    coverage.push(coverage_for_engine("posture", posture_result.engine, posture_result.posture.len()));
    coverage.push(coverage_for_engine("codeql", codeql_result.engine, codeql_result.findings.len()));

    let llm_check = llm_result.map(|result| LlmResult {
        available: result.available,
        findings: result
            .findings
            .iter()
            .map(|f| OeLlmFinding { category: f.category.clone(), file: Some(f.file.clone()), line: Some(f.line), level: Some(f.level.clone()), issue: Some(f.issue.clone()), recommendation: Some(f.recommendation.clone()), code: snippet_json(&f.code) })
            .collect(),
    });

    let iac_check = Some(CheckResult {
        findings: iac_result.findings.iter().map(|f| RawFinding { file: Some(f.file.clone()), line: Some(f.line as i64), kind: Some(f.kind.clone()), tool: Some(f.tool.to_string()), severity: Some(f.severity.clone()), message: Some(f.message.clone()), code: snippet_json(&f.code), ..Default::default() }).collect(),
        engine: Some(iac_result.engine),
    });

    let gha_security_check = Some(CheckResult {
        findings: gha_security_result.findings.iter().map(|f| RawFinding { file: Some(f.file.clone()), line: Some(f.line as i64), kind: Some(f.kind.clone()), tool: Some(f.tool.to_string()), severity: Some(f.severity.to_string()), message: Some(f.message.clone()), code: snippet_json(&f.code), ..Default::default() }).collect(),
        engine: Some(gha_security_result.engine.to_string()),
    });

    let image_vuln_check = Some(CheckResult {
        findings: image_vuln_result
            .findings
            .iter()
            .map(|f| RawFinding { file: Some(f.file.clone()), line: Some(f.line as i64), kind: Some(f.kind.clone()), tool: Some(f.tool.to_string()), severity: Some(f.severity.clone()), message: Some(f.message.clone()), pkg_name: f.pkg_name.clone(), ..Default::default() })
            .collect(),
        engine: Some(image_vuln_result.engine.to_string()),
    });

    let sbom_doc = if config.project_id.is_some() {
        match &sbom_result.sbom {
            ignite_sbom::SbomOutcome::Syft(v) => Some(("sbom.cyclonedx.json".to_string(), to_json_bytes(v))),
            ignite_sbom::SbomOutcome::Fallback(v) => Some(("sbom.fallback.json".to_string(), to_json_bytes(v))),
        }
    } else {
        None
    };

    let provenance_doc = provenance_result.map(|p| to_json_bytes(&p));

    let image_provenance_check =
        Some(CheckResult { findings: image_provenance_result.findings.iter().map(|f| RawFinding { file: Some(f.file.clone()), line: Some(f.line as i64), kind: Some(f.kind.to_string()), tool: Some(f.tool.to_string()), severity: Some(f.severity.to_string()), message: Some(f.message.clone()), code: snippet_json(&f.code), ..Default::default() }).collect(), engine: Some(image_provenance_result.engine.to_string()) });

    let semantic_sast_check = Some(CheckResult {
        findings: semantic_sast_result
            .findings
            .iter()
            .map(|f| RawFinding { file: Some(f.file.clone()), line: Some(f.line as i64), kind: Some(f.kind.clone()), tool: Some(f.tool.to_string()), severity: Some(f.severity.to_string()), message: Some(f.message.clone()), cwe: f.cwe.clone(), owasp: f.owasp.clone(), code: snippet_json(&f.code), ..Default::default() })
            .collect(),
        engine: Some(semantic_sast_result.engine.to_string()),
    });

    let pii_check = Some(CheckResult {
        findings: pii_result.findings.iter().map(|f| RawFinding { file: Some(f.file.clone()), line: Some(f.line as i64), kind: Some(f.kind.clone()), tool: Some(f.tool.to_string()), severity: Some(f.severity.to_string()), message: Some(f.message.clone()), cwe: f.cwe.clone(), code: snippet_json(&f.code), ..Default::default() }).collect(),
        engine: Some(pii_result.engine.to_string()),
    });

    let duplication_check = Some(CheckResult {
        findings: duplication_result
            .findings
            .iter()
            .map(|f| RawFinding {
                file: Some(f.file.clone()),
                line: Some(f.line as i64),
                kind: Some(f.kind.to_string()),
                tool: Some(f.tool.to_string()),
                severity: Some(f.severity.to_string()),
                message: Some(f.message.clone()),
                duplicate_ref: serde_json::to_value(&f.duplicate_ref).ok(),
                code: snippet_json(&f.code),
                ..Default::default()
            })
            .collect(),
        engine: Some(duplication_result.engine.to_string()),
    });

    log("→ fileEncapsulation starting...");
    let __t = std::time::Instant::now();
    // Every sequential check below used `?`, which aborted the *entire*
    // orchestrator — discarding every already-completed concurrent scan
    // result (CodeQL, Semgrep, gitleaks, IaC, ...) — on a single transient
    // I/O error from one of these six lightweight built-in checks (a
    // locked file, a dangling symlink). Each now degrades to an empty,
    // `engine: "error"`-tagged result and keeps going instead.
    let file_encapsulation_result = ignite_file_encapsulation::check_file_encapsulation(root, &config.file_encapsulation).unwrap_or_else(|e| {
        log(&format!("✗ fileEncapsulation failed: {e}"));
        ignite_file_encapsulation::FileEncapsulationResult { findings: vec![], engine: "error" }
    });
    let ms = __t.elapsed().as_millis() as u64;
    task_timings.push(("fileEncapsulation", ms));
    coverage.push(coverage_for_engine("fileEncapsulation", file_encapsulation_result.engine, file_encapsulation_result.findings.len()));
    log(&format!("✓ fileEncapsulation done ({} finding(s), {ms}ms)", file_encapsulation_result.findings.len()));
    let file_encapsulation_check = Some(CheckResult {
        findings: file_encapsulation_result.findings.iter().map(|f| RawFinding { file: Some(f.file.clone()), line: Some(f.line as i64), kind: Some(f.kind.to_string()), tool: Some(f.tool.to_string()), severity: Some(f.severity.to_string()), message: Some(f.message.clone()), code: snippet_json(&f.code), ..Default::default() }).collect(),
        engine: Some(file_encapsulation_result.engine.to_string()),
    });

    let loc_metrics_doc = if config.project_id.is_some() { loc_metrics_result.metrics.as_ref().map(to_json_bytes) } else { None };

    let api_schema_check = Some(CheckResult {
        findings: api_schema_result.findings.iter().map(|f| RawFinding { file: Some(f.file.clone()), line: Some(f.line as i64), kind: Some(f.kind.clone()), tool: Some(f.tool.to_string()), severity: Some(f.severity.to_string()), message: Some(f.message.clone()), code: snippet_json(&f.code), ..Default::default() }).collect(),
        engine: Some(api_schema_result.engine.to_string()),
    });

    let api_schema_drift_check = Some(CheckResult {
        findings: api_schema_drift_result.findings.iter().map(|f| RawFinding { file: Some(f.file.clone()), line: f.line.map(|l| l as i64), kind: Some(f.kind.clone()), tool: Some(f.tool.to_string()), severity: Some(f.severity.to_string()), message: Some(f.message.clone()), ..Default::default() }).collect(),
        engine: Some(api_schema_drift_result.engine.to_string()),
    });

    let malicious_deps_check = Some(CheckResult {
        findings: malicious_deps_result.findings.iter().map(|f| RawFinding { file: Some(f.file.clone()), line: f.line.map(|l| l as i64), kind: Some(f.kind.to_string()), tool: Some(f.tool.to_string()), severity: Some(f.severity.to_string()), message: Some(f.message.clone()), ..Default::default() }).collect(),
        engine: Some(malicious_deps_result.engine.to_string()),
    });

    let model_artifact_check = Some(CheckResult {
        findings: model_artifact_result.findings.iter().map(|f| RawFinding { file: Some(f.file.clone()), line: f.line.map(|l| l as i64), kind: Some(f.kind.to_string()), tool: Some(f.tool.to_string()), severity: Some(f.severity.to_string()), message: Some(f.message.clone()), ..Default::default() }).collect(),
        engine: Some(model_artifact_result.engine.to_string()),
    });

    let hallucination_check = Some(CheckResult {
        findings: hallucination_result.findings.iter().map(|f| RawFinding { file: Some(f.file.clone()), line: f.line.map(|l| l as i64), kind: Some(f.kind.to_string()), tool: Some(f.tool.to_string()), severity: Some(f.severity.to_string()), message: Some(f.message.clone()), ..Default::default() }).collect(),
        engine: Some(hallucination_result.engine.to_string()),
    });

    let posture_doc = if config.project_id.is_some() { Some(to_json_bytes(&serde_json::json!({ "engine": posture_result.engine, "posture": posture_result.posture }))) } else { None };

    log("→ euAiActDocuments starting...");
    let __t = std::time::Instant::now();
    let ai_act_docs_result = ignite_compliance_documents::check_compliance_documents(root, config.eu_ai_act_documents_enabled).unwrap_or_else(|e| {
        log(&format!("✗ euAiActDocuments failed: {e}"));
        ignite_compliance_documents::ComplianceDocumentsResult { engine: "error", documents: Default::default() }
    });
    let ms = __t.elapsed().as_millis() as u64;
    task_timings.push(("euAiActDocuments", ms));
    coverage.push(coverage_for_engine("euAiActDocuments", ai_act_docs_result.engine, 0));
    log(&format!("✓ euAiActDocuments done ({ms}ms)"));
    let ai_act_docs_doc = if config.project_id.is_some() { Some(to_json_bytes(&serde_json::json!({ "engine": ai_act_docs_result.engine, "documents": ai_act_docs_result.documents }))) } else { None };

    let eu_ai_act_check = if config.eu_ai_act_report_as_findings {
        Some(derive_eu_ai_act_findings(&posture_result.posture, &ai_act_docs_result.documents))
    } else {
        None
    };

    log("→ deadCode starting...");
    let __t = std::time::Instant::now();
    let dead_code_result = ignite_dead_code::check_dead_code(root, &config.dead_code).unwrap_or_else(|e| {
        log(&format!("✗ deadCode failed: {e}"));
        ignite_dead_code::DeadCodeResult { findings: vec![], engine: "error", scanned: 0, reached: 0, entries: 0 }
    });
    let ms = __t.elapsed().as_millis() as u64;
    task_timings.push(("deadCode", ms));
    coverage.push(coverage_for_engine("deadCode", dead_code_result.engine, dead_code_result.findings.len()));
    log(&format!("✓ deadCode done ({} finding(s), {ms}ms)", dead_code_result.findings.len()));
    let dead_code_check = Some(CheckResult {
        findings: dead_code_result.findings.iter().map(|f| RawFinding { file: Some(f.file.clone()), line: Some(f.line as i64), kind: Some(f.kind.clone()), tool: Some(f.tool.to_string()), severity: Some(f.severity.to_string()), message: Some(f.message.clone()), code: snippet_json(&f.code), ..Default::default() }).collect(),
        engine: Some(dead_code_result.engine.to_string()),
    });

    let churn: HashMap<String, u64> = HashMap::new(); // git-churn weighting not yet wired (needs `git log --numstat`)
    let org = config.org.clone();
    let repo = config.repo.clone();
    log("→ health starting...");
    let __t = std::time::Instant::now();
    let health_result = ignite_complexity_health::check_complexity_health(root, &config.complexity_health, &churn, |rel_path| store.get_runtime_coverage_for_file(&org, &repo, rel_path).and_then(|r| r.covered_pct)).unwrap_or_else(|e| {
        log(&format!("✗ health failed: {e}"));
        ignite_complexity_health::ComplexityHealthResult { findings: vec![], engine: "error", metrics: None }
    });
    let ms = __t.elapsed().as_millis() as u64;
    task_timings.push(("health", ms));
    coverage.push(coverage_for_engine("health", health_result.engine, health_result.findings.len()));
    log(&format!("✓ health done ({} finding(s), {ms}ms)", health_result.findings.len()));
    let health_check = Some(CheckResult {
        findings: health_result.findings.iter().map(|f| RawFinding { file: Some(f.file.clone()), line: Some(f.line as i64), kind: Some(f.kind.to_string()), tool: Some(f.tool.to_string()), severity: Some(f.severity.to_string()), message: Some(f.message.clone()), code: snippet_json(&f.code), ..Default::default() }).collect(),
        engine: Some(health_result.engine.to_string()),
    });

    log("→ cssDeadCode starting...");
    let __t = std::time::Instant::now();
    let css_dead_code_result = ignite_css_dead_code::check_css_dead_code(root, &config.css_dead_code).unwrap_or_else(|e| {
        log(&format!("✗ cssDeadCode failed: {e}"));
        ignite_css_dead_code::CssDeadCodeResult { findings: vec![], engine: "error", scanned: None }
    });
    let ms = __t.elapsed().as_millis() as u64;
    task_timings.push(("cssDeadCode", ms));
    coverage.push(coverage_for_engine("cssDeadCode", css_dead_code_result.engine, css_dead_code_result.findings.len()));
    log(&format!("✓ cssDeadCode done ({} finding(s), {ms}ms)", css_dead_code_result.findings.len()));
    let css_dead_code_check = Some(CheckResult {
        findings: css_dead_code_result.findings.iter().map(|f| RawFinding { file: Some(f.file.clone()), line: Some(f.line as i64), kind: Some(f.kind.to_string()), tool: Some(f.tool.to_string()), severity: Some(f.severity.to_string()), message: Some(f.message.clone()), code: snippet_json(&f.code), ..Default::default() }).collect(),
        engine: Some(css_dead_code_result.engine.to_string()),
    });

    log("→ boundaries starting...");
    let __t = std::time::Instant::now();
    let boundaries_result = ignite_boundaries::check_boundaries(root, &config.boundaries).unwrap_or_else(|e| {
        log(&format!("✗ boundaries failed: {e}"));
        ignite_boundaries::BoundariesResult { findings: vec![], engine: "error", zone_count: None }
    });
    let ms = __t.elapsed().as_millis() as u64;
    task_timings.push(("boundaries", ms));
    coverage.push(coverage_for_engine("boundaries", boundaries_result.engine, boundaries_result.findings.len()));
    log(&format!("✓ boundaries done ({} finding(s), {ms}ms)", boundaries_result.findings.len()));
    let boundaries_check = Some(CheckResult {
        findings: boundaries_result.findings.iter().map(|f| RawFinding { file: Some(f.file.clone()), line: Some(f.line as i64), kind: Some(f.kind.to_string()), tool: Some(f.tool.to_string()), severity: Some(f.severity.to_string()), message: Some(f.message.clone()), code: snippet_json(&f.code), ..Default::default() }).collect(),
        engine: Some(boundaries_result.engine.to_string()),
    });

    log("→ envVarDrift starting...");
    let __t = std::time::Instant::now();
    let env_var_drift_result = ignite_env_var_drift::check_env_var_drift(root, &config.env_var_drift).unwrap_or_else(|e| {
        log(&format!("✗ envVarDrift failed: {e}"));
        ignite_env_var_drift::EnvVarDriftResult { findings: vec![], engine: "error", templates: vec![] }
    });
    let ms = __t.elapsed().as_millis() as u64;
    task_timings.push(("envVarDrift", ms));
    coverage.push(match env_var_drift_result.engine {
        "not_applicable" => ignite_policy::CheckCoverage::not_applicable("envVarDrift", "no .env.example/.env.sample/.env.template in the project"),
        "built-in" => ignite_policy::CheckCoverage::completed("envVarDrift", "built-in", false)
            .with_duration_ms(ms)
            .with_scope(format!("{} finding(s) against {}", env_var_drift_result.findings.len(), env_var_drift_result.templates.join(", "))),
        engine => coverage_for_engine("envVarDrift", engine, env_var_drift_result.findings.len()),
    });
    log(&format!("✓ envVarDrift done ({} finding(s), {ms}ms)", env_var_drift_result.findings.len()));
    // `kind` carries the variable name: override-engine uses it as the
    // issue-id discriminator, since two reads can share one line.
    let env_var_drift_check = Some(CheckResult {
        findings: env_var_drift_result.findings.iter().map(|f| RawFinding { file: Some(f.file.clone()), line: Some(f.line as i64), kind: Some(f.var.clone()), tool: Some(f.tool.to_string()), severity: Some(f.severity.to_string()), message: Some(f.message.clone()), code: snippet_json(&f.code), ..Default::default() }).collect(),
        engine: Some(env_var_drift_result.engine.to_string()),
    });

    let igniteignore_check = Some(CheckResult {
        findings: igniteignore_result.findings.iter().map(|f| RawFinding { file: Some(f.file.to_string()), line: Some(f.line as i64), kind: Some(f.kind.to_string()), tool: Some(f.tool.to_string()), severity: Some(f.severity.to_string()), message: Some(f.message.clone()), ..Default::default() }).collect(),
        engine: Some(igniteignore_result.engine.to_string()),
    });

    let codeql_check = Some(CodeqlResult {
        findings: codeql_result.findings.iter().map(to_oe_codeql_finding).collect(),
        failed_languages: codeql_result.failed_languages.clone(),
        query_suite_review_overdue: config.codeql_query_suite_review_overdue,
    });

    let inputs = Phase4Inputs {
        secrets: secrets_check,
        governance: governance_check,
        llm: llm_check,
        iac: iac_check,
        gha_security: gha_security_check,
        image_vulnerabilities: image_vuln_check,
        image_provenance: image_provenance_check,
        semantic_sast: semantic_sast_check,
        pii_data_flow: pii_check,
        duplication: duplication_check,
        file_encapsulation: file_encapsulation_check,
        api_schema: api_schema_check,
        api_schema_drift: api_schema_drift_check,
        malicious_dependencies: malicious_deps_check,
        model_artifact_security: model_artifact_check,
        package_hallucination: hallucination_check,
        codeql: codeql_check,
        dead_code: dead_code_check,
        health: health_check,
        css_dead_code: css_dead_code_check,
        boundaries: boundaries_check,
        eu_ai_act: eu_ai_act_check,
        ignite_ignore: igniteignore_check,
        env_var_drift: env_var_drift_check,
    };
    let issues = ignite_override_engine::collect_phase4_issues(&inputs);
    let _ = http_client;
    let total_ms = __t0.elapsed().as_millis() as u64;
    task_timings.push(("phase4Total", total_ms));
    log(&format!("Phase 4 complete — {} check(s) run, {} issue(s) found ({total_ms}ms total).", task_timings.len().saturating_sub(1), issues.len()));

    Ok(Phase4Output {
        issues,
        documents: Phase4Documents { sbom: sbom_doc, provenance: provenance_doc, loc_metrics: loc_metrics_doc, posture_report: posture_doc, ai_act_documents_report: ai_act_docs_doc },
        task_timings,
        coverage,
    })
}

/// Only called when `eu_ai_act_report_as_findings` is true — turns the
/// three `ai-act-*` posture categories' matches and the doc-presence
/// scan's MISSING categories into the generic findings shape.
fn derive_eu_ai_act_findings(posture: &ignite_feature_posture::PostureReport, documents: &std::collections::BTreeMap<&'static str, ignite_compliance_documents::DocumentCategoryReport>) -> CheckResult {
    let mut findings = Vec::new();
    let posture_kinds: &[(&str, &str)] = &[("ai-act-prohibited-practice", "ai-act-prohibited-practice"), ("ai-act-transparency-disclosure", "ai-act-transparency-disclosure"), ("ai-act-ai-logging", "ai-act-ai-logging")];
    for (category, kind) in posture_kinds {
        if let Some(report) = posture.get(category) {
            for m in &report.matches {
                findings.push(RawFinding { file: Some(m.file.clone()), line: Some(m.line as i64), kind: Some(kind.to_string()), message: Some(m.message.clone()), code: snippet_json(&m.code), ..Default::default() });
            }
        }
    }
    let document_labels: &[(&str, &str)] = &[
        ("risk-management-system", "Risk-management system documentation (Art. 9) not found in this repo."),
        ("technical-documentation", "Annex IV technical documentation (Art. 11) not found in this repo."),
        ("fria", "Fundamental rights impact assessment (Art. 27) not found in this repo."),
        ("training-data-summary", "GPAI training-data summary / model card (Art. 53) not found in this repo."),
        ("post-market-monitoring", "Post-market monitoring plan (Art. 72) not found in this repo."),
    ];
    for (category, message) in document_labels {
        if documents.get(category).map(|d| d.status) == Some("MISSING") {
            findings.push(RawFinding { kind: Some(format!("ai-act-compliance-documents-{category}")), message: Some(message.to_string()), ..Default::default() });
        }
    }
    CheckResult { findings, engine: None }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap as StdHashMap;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn to_oe_codeql_finding_carries_chain_and_cwe_through() {
        let finding = ignite_codeql_cross_file::CodeqlFinding {
            file: "src/fileService.js".to_string(),
            line: 8,
            kind: "js/path-injection".to_string(),
            tool: "codeql".to_string(),
            language: "javascript".to_string(),
            severity: "error".to_string(),
            message: "This path depends on a user-provided value.".to_string(),
            snippet: None,
            cross_file: true,
            chain: Some(vec![
                ignite_codeql_cross_file::FlowStep { file: "src/routes.js".to_string(), line: 7, message: Some("req.query.name".to_string()) },
                ignite_codeql_cross_file::FlowStep { file: "src/fileService.js".to_string(), line: 8, message: Some("fullPath".to_string()) },
            ]),
            cwe: Some("CWE-22".to_string()),
        };
        let oe = to_oe_codeql_finding(&finding);
        assert!(oe.cross_file);
        assert_eq!(oe.cwe.as_deref(), Some("CWE-22"));
        let chain = oe.chain.expect("chain should not be dropped");
        assert_eq!(chain.as_array().unwrap().len(), 2);
        assert_eq!(chain[0]["file"], serde_json::json!("src/routes.js"));
    }

    fn test_config(project_id: Option<i64>) -> Phase4Config {
        Phase4Config {
            fast: false,
            org: "test-org".to_string(),
            repo: "test-repo".to_string(),
            project_id,
            secrets: ignite_secrets::SecretsConfig::default(),
            secret_verification: ignite_secret_verifier::SecretVerifierConfig::default(),
            llm: None,
            iac: ignite_iac_security::IacSecurityConfig { trivy_enabled: false, checkov_enabled: false, hadolint_enabled: false },
            gha_security: ignite_gha_security::GhaSecurityConfig { enabled: false },
            container_image_vulnerabilities: ignite_container_image_vulnerabilities::ContainerImageVulnerabilitiesConfig { enabled: false, ..Default::default() },
            sbom_enabled: false,
            image_provenance: ignite_image_provenance::ImageProvenanceConfig { enabled: false, ..Default::default() },
            semantic_sast: ignite_semantic_sast::SemanticSastConfig { enabled: false, ..Default::default() },
            pii_data_flow: ignite_pii_dataflow::PiiDataFlowConfig { enabled: false },
            code_duplication: ignite_code_duplication::CodeDuplicationConfig { enabled: false, ..Default::default() },
            file_encapsulation: ignite_file_encapsulation::FileEncapsulationConfig { enabled: true, max_lines: 500 },
            loc_metrics_enabled: false,
            api_schema: ignite_api_schema::ApiSchemaConfig { enabled: false, ..Default::default() },
            api_schema_drift: ignite_api_schema_drift::ApiSchemaDriftConfig { enabled: false },
            malicious_dependencies: ignite_malicious_dependencies::MaliciousDependenciesConfig { enabled: false },
            model_artifact_security: ignite_model_artifact_security::ModelArtifactSecurityConfig { enabled: false, ..Default::default() },
            package_hallucination_enabled: false,
            feature_posture: ignite_feature_posture::FeaturePostureConfig { enabled: false, ruleset: String::new(), max_scan_file_bytes: 1_000_000 },
            eu_ai_act_documents_enabled: false,
            eu_ai_act_report_as_findings: false,
            dead_code: ignite_dead_code::DeadCodeConfig { enabled: false },
            complexity_health: ignite_complexity_health::ComplexityHealthConfig::default(),
            css_dead_code: ignite_css_dead_code::CssDeadCodeConfig { enabled: false },
            boundaries: ignite_boundaries::BoundariesConfig { enabled: false, preset: None, zones: vec![] },
            env_var_drift: ignite_env_var_drift::EnvVarDriftConfig { enabled: false },
            igniteignore_enabled: false,
            igniteignore_git_check_root: None,
            codeql: ignite_codeql_cross_file::CodeqlConfig { enabled: false, ..Default::default() },
            codeql_query_suite_review_overdue: false,
            keep_codeql_db_dir: None,
        }
    }

    #[tokio::test]
    async fn everything_disabled_still_runs_secrets_governance_and_builtins() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("app.js"), format!("const password = '{}';\n", "hardcodedsecretvalue1234")).unwrap();

        let db_dir = tempdir().unwrap();
        let store = DbStore::open(&db_dir.path().join("test.db")).unwrap();
        let runner = ToolRunner::new(StdHashMap::new());
        let config = test_config(None);

        let hallucination_checker = ignite_package_hallucination::PackageHallucinationChecker::new(ignite_package_hallucination::HttpRegistryChecker::default());
        let output = run_phase4_checks(root, &runner, &store, &config, &hallucination_checker, &|_m: &str| {}).await.unwrap();
        assert!(output.issues.iter().any(|i| i.category == "secret"));
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[tokio::test]
    async fn gitleaks_supplement_is_merged_into_secret_findings() {
        let runner = ToolRunner::new(StdHashMap::from([("gitleaks", "gitleaks".to_string())]));
        if !ignite_secrets::gitleaks_tooling(&runner).await {
            eprintln!("skipping: gitleaks not installed");
            return;
        }

        let dir = tempdir().unwrap();
        let root = dir.path();
        // A GCP/Firebase web API key under an `apiKey:` property — gitleaks'
        // built-in `gcp-api-key` rule (format + entropy check) catches this;
        // the built-in regex scan (`SECRET_RE`, keyed on
        // `password|aws_secret|api_key|token|private_key`) does not, since
        // the property here is `apiKey` nested under `firebase:`, not a
        // bare `api_key = ...` assignment the regex matches on.
        fs::write(root.join("config.js"), format!("export const environment = {{ firebase: {{ apiKey: '{}' }} }};\n", "AIzaSyDGX6-TCqxyZv3m1avbP8-hZxD2-Zb6bXk")).unwrap();

        let db_dir = tempdir().unwrap();
        let store = DbStore::open(&db_dir.path().join("test.db")).unwrap();
        let mut config = test_config(None);
        config.secrets.gitleaks_enabled = true;

        let hallucination_checker = ignite_package_hallucination::PackageHallucinationChecker::new(ignite_package_hallucination::HttpRegistryChecker::default());
        let output = run_phase4_checks(root, &runner, &store, &config, &hallucination_checker, &|_m: &str| {}).await.unwrap();
        assert!(
            output.issues.iter().any(|i| i.category == "secret" && i.file.as_deref() == Some("config.js")),
            "expected gitleaks-only finding to appear in issues: {:?}",
            output.issues
        );
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[tokio::test]
    async fn enabled_custom_secret_pattern_is_applied_to_the_live_scan() {
        let runner = ToolRunner::new(StdHashMap::from([("gitleaks", "gitleaks".to_string())]));
        if !ignite_secrets::gitleaks_tooling(&runner).await {
            eprintln!("skipping: gitleaks not installed");
            return;
        }

        let dir = tempdir().unwrap();
        let root = dir.path();
        // A made-up token shape no built-in gitleaks rule recognizes —
        // only findable via the operator-authored custom pattern below.
        // Built at runtime rather than as a literal string (same
        // fixture-avoidance convention used throughout this codebase,
        // e.g. secret-verifier's own tests) — org-governance CI's
        // plaintext-token matcher flags any literal matching this shape
        // regardless of authenticity, and unlike Ignite's own override
        // engine that check has no justification/override mechanism at
        // all.
        let fake_token = format!("acme_live_{}", "9f8e7d6c5b4a3210");
        fs::write(root.join("config.js"), format!("export const internalToken = '{fake_token}';\n")).unwrap();

        let db_dir = tempdir().unwrap();
        let store = DbStore::open(&db_dir.path().join("test.db")).unwrap();
        store.create_custom_secret_pattern("Acme Internal Token", r"acme_live_[0-9a-f]{16}", None).unwrap();
        // A disabled pattern must never reach the live scan.
        let disabled_id = store.create_custom_secret_pattern("Should Not Fire", r"never_matches_anything_zzz", None).unwrap();
        store.set_custom_secret_pattern_enabled(disabled_id, false);

        let mut config = test_config(None);
        config.secrets.gitleaks_enabled = true;

        let hallucination_checker = ignite_package_hallucination::PackageHallucinationChecker::new(ignite_package_hallucination::HttpRegistryChecker::default());
        let output = run_phase4_checks(root, &runner, &store, &config, &hallucination_checker, &|_m: &str| {}).await.unwrap();
        assert!(
            output.issues.iter().any(|i| i.category == "secret" && i.file.as_deref() == Some("config.js")),
            "expected the enabled custom pattern to produce a finding via the live scan: {:?}",
            output.issues
        );
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[tokio::test]
    async fn full_mode_forces_gitleaks_history_scan_even_when_config_default_is_off() {
        let runner = ToolRunner::new(StdHashMap::from([("gitleaks", "gitleaks".to_string())]));
        if !ignite_secrets::gitleaks_tooling(&runner).await {
            eprintln!("skipping: gitleaks not installed");
            return;
        }

        let dir = tempdir().unwrap();
        let root = dir.path();
        let git = |args: &[&str]| {
            let status = std::process::Command::new("git").args(args).current_dir(root).status().unwrap();
            assert!(status.success());
        };
        git(&["init", "-q"]);
        git(&["config", "user.email", "test@example.com"]);
        git(&["config", "user.name", "test"]);
        fs::write(root.join("config.js"), format!("export const apiKey = '{}';\n", "AIzaSyDGX6-TCqxyZv3m1avbP8-hZxD2-Zb6bXk")).unwrap();
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "add secret"]);
        fs::remove_file(root.join("config.js")).unwrap();
        fs::write(root.join("config.js"), "export const apiKey = 'removed';\n").unwrap();
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "remove secret"]);

        let db_dir = tempdir().unwrap();
        let store = DbStore::open(&db_dir.path().join("test.db")).unwrap();
        let mut config = test_config(None);
        config.secrets.gitleaks_enabled = true;
        assert!(!config.secrets.gitleaks_scan_history, "test expects the config default to stay off — the orchestrator, not the config, must force this on in full mode");

        let hallucination_checker = ignite_package_hallucination::PackageHallucinationChecker::new(ignite_package_hallucination::HttpRegistryChecker::default());
        let output = run_phase4_checks(root, &runner, &store, &config, &hallucination_checker, &|_m: &str| {}).await.unwrap();
        assert!(
            output.issues.iter().any(|i| i.category == "secret" && i.file.as_deref() == Some("config.js") && i.tool.as_deref() == Some("gitleaks-history")),
            "expected a gitleaks-history finding in full mode despite gitleaks_scan_history defaulting to off: {:?}",
            output.issues
        );

        let mut fast_config = test_config(None);
        fast_config.secrets.gitleaks_enabled = true;
        fast_config.fast = true;
        let fast_output = run_phase4_checks(root, &runner, &store, &fast_config, &hallucination_checker, &|_m: &str| {}).await.unwrap();
        assert!(
            !fast_output.issues.iter().any(|i| i.tool.as_deref() == Some("gitleaks-history")),
            "fast mode must not run the slow git-history scan: {:?}",
            fast_output.issues
        );
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[tokio::test]
    async fn secret_verification_is_off_by_default() {
        let runner = ToolRunner::new(StdHashMap::from([("gitleaks", "gitleaks".to_string())]));
        if !ignite_secrets::gitleaks_tooling(&runner).await {
            eprintln!("skipping: gitleaks not installed");
            return;
        }
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("config.js"), "headers.set(\"Authorization\", \"Bearer ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8\");\n").unwrap();

        let db_dir = tempdir().unwrap();
        let store = DbStore::open(&db_dir.path().join("test.db")).unwrap();
        let mut config = test_config(None);
        config.secrets.gitleaks_enabled = true;
        assert!(!config.secret_verification.enabled, "test expects secret verification to default to off");

        let hallucination_checker = ignite_package_hallucination::PackageHallucinationChecker::new(ignite_package_hallucination::HttpRegistryChecker::default());
        let output = run_phase4_checks(root, &runner, &store, &config, &hallucination_checker, &|_m: &str| {}).await.unwrap();
        let Some(issue) = output.issues.iter().find(|i| i.category == "secret" && i.file.as_deref() == Some("config.js")) else {
            eprintln!("skipping: gitleaks didn't flag the fake github token (rule set may differ)");
            return;
        };
        assert!(!issue.summary.contains("VERIFIED LIVE"), "verification must never run when disabled: {}", issue.summary);
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    /// Real network call against the live GitHub API (verifying a
    /// syntactically-plausible but never-issued token) — self-skips if
    /// gitleaks or the network is unavailable, same convention as this
    /// crate's other real-tool/real-network tests. Proves enabling
    /// verification doesn't mis-flag a dead token as live; the "actually
    /// live" path is covered at the unit level in
    /// `ignite_secret_verifier`'s own tests (no real credential to spare
    /// for an end-to-end "Live" assertion here).
    #[tokio::test]
    async fn secret_verification_when_enabled_never_flags_a_fake_token_as_verified_live() {
        let runner = ToolRunner::new(StdHashMap::from([("gitleaks", "gitleaks".to_string())]));
        if !ignite_secrets::gitleaks_tooling(&runner).await {
            eprintln!("skipping: gitleaks not installed");
            return;
        }
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("config.js"), "headers.set(\"Authorization\", \"Bearer ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8\");\n").unwrap();

        let db_dir = tempdir().unwrap();
        let store = DbStore::open(&db_dir.path().join("test.db")).unwrap();
        let mut config = test_config(None);
        config.secrets.gitleaks_enabled = true;
        config.secret_verification = ignite_secret_verifier::SecretVerifierConfig { enabled: true, timeout_ms: 10_000 };

        let hallucination_checker = ignite_package_hallucination::PackageHallucinationChecker::new(ignite_package_hallucination::HttpRegistryChecker::default());
        let output = run_phase4_checks(root, &runner, &store, &config, &hallucination_checker, &|_m: &str| {}).await.unwrap();
        let Some(issue) = output.issues.iter().find(|i| i.category == "secret" && i.file.as_deref() == Some("config.js")) else {
            eprintln!("skipping: gitleaks didn't flag the fake github token (rule set may differ)");
            return;
        };
        assert!(!issue.summary.contains("VERIFIED LIVE"), "a syntactically fake token must never be reported as verified live: {}", issue.summary);
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[tokio::test]
    async fn fast_mode_only_runs_the_four_fast_tasks() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("app.js"), format!("const password = '{}';\n", "hardcodedsecretvalue1234")).unwrap();

        let db_dir = tempdir().unwrap();
        let store = DbStore::open(&db_dir.path().join("test.db")).unwrap();
        let runner = ToolRunner::new(StdHashMap::new());
        let mut config = test_config(None);
        config.fast = true;

        let hallucination_checker = ignite_package_hallucination::PackageHallucinationChecker::new(ignite_package_hallucination::HttpRegistryChecker::default());
        let output = run_phase4_checks(root, &runner, &store, &config, &hallucination_checker, &|_m: &str| {}).await.unwrap();
        assert!(output.issues.iter().any(|i| i.category == "secret"));
        assert!(output.documents.sbom.is_none());
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[tokio::test]
    async fn no_project_id_skips_document_generation() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("app.js"), "console.log(1);\n").unwrap();

        let db_dir = tempdir().unwrap();
        let store = DbStore::open(&db_dir.path().join("test.db")).unwrap();
        let runner = ToolRunner::new(StdHashMap::new());
        let config = test_config(None);

        let hallucination_checker = ignite_package_hallucination::PackageHallucinationChecker::new(ignite_package_hallucination::HttpRegistryChecker::default());
        let output = run_phase4_checks(root, &runner, &store, &config, &hallucination_checker, &|_m: &str| {}).await.unwrap();
        assert!(output.documents.sbom.is_none());
        assert!(output.documents.provenance.is_none());
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    // ---- characterization: pins what every Phase 4 pass reports as coverage, so
    // ---- giving checks a shared shape can't drop or rename one.

    const ALL_COVERAGE_IDS: [&str; 28] = [
        "apiSchema", "apiSchemaDrift", "boundaries", "codeql", "cssDeadCode", "deadCode", "duplication", "envVarDrift", "euAiActDocuments",
        "fileEncapsulation", "ghaSecurity", "governance", "health", "igniteIgnore", "iac", "imageProvenance", "imageVulnerabilities",
        "llm", "locMetrics", "maliciousDependencies", "modelArtifactSecurity", "packageHallucination", "pii", "posture",
        "provenance", "sbom", "secrets", "semanticSast",
    ];

    async fn coverage_for(config: Phase4Config) -> Vec<ignite_policy::CheckCoverage> {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("app.js"), "console.log(1);\n").unwrap();
        let db_dir = tempdir().unwrap();
        let store = DbStore::open(&db_dir.path().join("test.db")).unwrap();
        let runner = ToolRunner::new(StdHashMap::new());
        let checker = ignite_package_hallucination::PackageHallucinationChecker::new(ignite_package_hallucination::HttpRegistryChecker::default());
        let output = run_phase4_checks(dir.path(), &runner, &store, &config, &checker, &|_m: &str| {}).await.unwrap();
        ignite_fs_utils::invalidate_walk_cache(dir.path());
        output.coverage
    }

    fn sorted_ids(coverage: &[ignite_policy::CheckCoverage]) -> Vec<String> {
        let mut ids: Vec<String> = coverage.iter().map(|c| c.check_id.clone()).collect();
        ids.sort();
        ids
    }

    #[tokio::test]
    async fn a_full_pass_reports_exactly_these_check_ids_once_each() {
        let coverage = coverage_for(test_config(None)).await;
        let mut expected: Vec<String> = ALL_COVERAGE_IDS.iter().map(|s| s.to_string()).collect();
        expected.sort();
        assert_eq!(sorted_ids(&coverage), expected, "a check was added, renamed or dropped: update ALL_COVERAGE_IDS deliberately");
    }

    #[tokio::test]
    async fn a_fast_pass_reports_the_same_ids_with_the_skipped_ones_marked_disabled_by_fast_mode() {
        let mut config = test_config(None);
        config.fast = true;
        let coverage = coverage_for(config).await;
        let mut expected: Vec<String> = ALL_COVERAGE_IDS.iter().map(|s| s.to_string()).collect();
        expected.sort();
        assert_eq!(sorted_ids(&coverage), expected);
        for c in &coverage {
            if FULL_MODE_ONLY_CHECKS.contains(&c.check_id.as_str()) {
                assert_eq!(c.outcome, ignite_policy::CheckOutcome::Disabled, "{}", c.check_id);
                assert!(c.reason.as_deref().unwrap_or("").contains("fast mode"), "{} should say why it was skipped: {:?}", c.check_id, c.reason);
            }
        }
    }

    #[tokio::test]
    async fn every_check_that_did_not_complete_says_why() {
        for fast in [false, true] {
            let mut config = test_config(None);
            config.fast = fast;
            for c in coverage_for(config).await {
                if c.outcome != ignite_policy::CheckOutcome::Completed {
                    assert!(c.reason.as_deref().map(|r| !r.is_empty()).unwrap_or(false), "fast={fast}: {} is {:?} with no reason", c.check_id, c.outcome);
                }
            }
        }
    }

    #[tokio::test]
    async fn env_var_drift_reports_advisory_issues_and_not_applicable_without_a_template() {
        let mut config = test_config(None);
        config.env_var_drift.enabled = true;
        let coverage = coverage_for(test_config(None)).await;
        assert_eq!(coverage.iter().find(|c| c.check_id == "envVarDrift").unwrap().outcome, ignite_policy::CheckOutcome::Disabled);

        let dir = tempdir().unwrap();
        fs::write(dir.path().join("app.js"), "const t = process.env.API_TOKEN;\n").unwrap();
        let db_dir = tempdir().unwrap();
        let store = DbStore::open(&db_dir.path().join("test.db")).unwrap();
        let runner = ToolRunner::new(StdHashMap::new());
        let checker = ignite_package_hallucination::PackageHallucinationChecker::new(ignite_package_hallucination::HttpRegistryChecker::default());

        let output = run_phase4_checks(dir.path(), &runner, &store, &config, &checker, &|_m: &str| {}).await.unwrap();
        ignite_fs_utils::invalidate_walk_cache(dir.path());
        assert_eq!(output.coverage.iter().find(|c| c.check_id == "envVarDrift").unwrap().outcome, ignite_policy::CheckOutcome::NotApplicable);
        assert!(!output.issues.iter().any(|i| i.category == "config-drift"));

        fs::write(dir.path().join(".env.example"), "# OTHER=\n").unwrap();
        let output = run_phase4_checks(dir.path(), &runner, &store, &config, &checker, &|_m: &str| {}).await.unwrap();
        ignite_fs_utils::invalidate_walk_cache(dir.path());
        assert_eq!(output.coverage.iter().find(|c| c.check_id == "envVarDrift").unwrap().outcome, ignite_policy::CheckOutcome::Completed);
        let ids: Vec<&str> = output.issues.iter().filter(|i| i.category == "config-drift").map(|i| i.id.as_str()).collect();
        assert_eq!(ids, vec!["config-drift::app.js::1::API_TOKEN", "config-drift::.env.example::1::OTHER"]);
        assert!(output.issues.iter().filter(|i| i.category == "config-drift").all(|i| i.severity == ignite_override_engine::Severity::Warning));
    }

    #[test]
    fn the_full_mode_only_list_is_the_fast_mode_complement() {
        assert_eq!(FULL_MODE_ONLY_CHECKS.len(), ALL_COVERAGE_IDS.len() - 4, "28 checks, 4 of which (secrets, governance, semanticSast, fileEncapsulation) run in fast mode");
        for fast_task in ["secrets", "governance", "semanticSast", "fileEncapsulation"] {
            assert!(!FULL_MODE_ONLY_CHECKS.contains(&fast_task), "{fast_task}");
        }
    }

    #[test]
    fn engine_strings_map_onto_coverage_outcomes_exactly_like_this() {
        use ignite_policy::CheckOutcome::*;
        let cases: [(&str, ignite_policy::CheckOutcome, bool); 7] = [
            ("disabled", Disabled, false),
            ("unavailable", Unavailable, false),
            ("failed", Failed, false),
            ("error", Failed, false),
            ("timed_out", TimedOut, false),
            ("unconfigured", NotApplicable, false),
            ("fallback", Completed, true),
        ];
        for (engine, outcome, is_fallback) in cases {
            let c = coverage_for_engine("x", engine, 3);
            assert_eq!(c.outcome, outcome, "{engine}");
            assert_eq!(c.is_fallback, is_fallback, "{engine}");
        }
        let real = coverage_for_engine("x", "semgrep", 3);
        assert_eq!(real.outcome, Completed);
        assert_eq!(real.engine.as_deref(), Some("semgrep"));
        assert!(!real.is_fallback);
        assert_eq!(real.scope.as_deref(), Some("3 finding(s)"));
    }
}
