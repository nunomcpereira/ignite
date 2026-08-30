//! Phase 4 check orchestrator. Faithful port of server.js's
//! `runPhase4Checks`: fans out to every check concurrently, converts each
//! check's own richly-typed result into `override-engine`'s generic
//! `RawFinding`/`CheckResult` shape, and calls `collect_phase4_issues` to
//! produce the final addressable issue list.
//!
//! `FAST_MODE_TASKS` filtering (secrets/governance/semanticSast/
//! fileEncapsulation only) is implemented.

use ignite_db_store::DbStore;
use ignite_override_engine::{CheckResult, CodeqlFinding as OeCodeqlFinding, CodeqlResult, Issue, LlmFinding as OeLlmFinding, LlmResult, Phase4Inputs, RawFinding};
use ignite_tool_runner::ToolRunner;
use std::collections::HashMap;
use std::path::Path;

fn snippet_json<T: serde::Serialize>(snippet: &Option<T>) -> Option<serde_json::Value> {
    snippet.as_ref().and_then(|s| serde_json::to_value(s).ok())
}

pub struct Phase4Config {
    pub fast: bool,
    pub org: String,
    pub repo: String,
    pub project_id: Option<i64>,
    pub secrets: ignite_secrets::SecretsConfig,
    pub llm: Option<ignite_llm_deep_scan::LlmDeepScanConfig>,
    pub iac: ignite_iac_security::IacSecurityConfig,
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
    pub igniteignore_enabled: bool,
    pub codeql: ignite_codeql_cross_file::CodeqlConfig,
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
async fn timed<F, T>(name: &'static str, log: &(dyn Fn(&str) + Sync), fut: F) -> std::io::Result<(T, u64)>
where
    F: std::future::Future<Output = std::io::Result<T>>,
{
    log(&format!("→ {name} starting..."));
    let t0 = std::time::Instant::now();
    let r = fut.await?;
    let ms = t0.elapsed().as_millis() as u64;
    log(&format!("✓ {name} done ({ms}ms)"));
    Ok((r, ms))
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
    let __t0 = std::time::Instant::now();
    log("→ secrets starting...");
    let secrets_cache = store.get_file_scan_cache(&config.org, &config.repo, "secrets");
    let secrets_cache: HashMap<String, ignite_secrets::CachedFileEntry> =
        secrets_cache.into_iter().filter_map(|(k, v)| serde_json::from_value::<ignite_secrets::CachedFileEntry>(v.findings).ok().map(|e| (k, e))).collect();
    let __t_secrets = std::time::Instant::now();
    let (mut secrets_result, secrets_new_cache) = ignite_secrets::check_secrets(root, &config.secrets, &secrets_cache)?;
    store.replace_file_scan_cache(
        &config.org,
        &config.repo,
        "secrets",
        &secrets_new_cache.iter().map(|(k, v)| ignite_db_store::FileScanCacheInput { rel_path: k.clone(), hash: v.hash.clone(), findings: serde_json::to_value(v).unwrap() }).collect::<Vec<_>>(),
    );
    if config.secrets.gitleaks_enabled {
        let gitleaks_raw = ignite_secrets::run_gitleaks_scan(root, runner, config.secrets.gitleaks_config_path.as_deref()).await;
        let gitignore_patterns = ignite_fs_utils::load_gitignore_patterns(root);
        let added = ignite_secrets::merge_gitleaks_findings(&secrets_result.findings, &gitleaks_raw, &gitignore_patterns, &config.secrets.known_public_key_patterns);
        secrets_result.findings.extend(added);
    }
    let ms_secrets = __t_secrets.elapsed().as_millis() as u64;
    task_timings.push(("secrets", ms_secrets));
    log(&format!("✓ secrets done ({} finding(s), {ms_secrets}ms)", secrets_result.findings.len()));
    let secrets_check = CheckResult {
        findings: secrets_result.findings.iter().map(|f| RawFinding { file: Some(f.file.clone()), line: Some(f.line as i64), kind: Some(f.kind.clone()), tool: Some(f.tool.to_string()), ..Default::default() }).collect(),
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
    task_timings.push(("governance", ms_governance));
    log(&format!("✓ governance done ({} finding(s), {ms_governance}ms)", governance_result.findings.len()));
    let governance_check =
        CheckResult { findings: governance_result.findings.iter().map(|f| RawFinding { file: Some(f.file.clone()), line: Some(f.line as i64), raw_snippet_text: Some(f.snippet.clone()), ..Default::default() }).collect(), engine: Some("built-in".to_string()) };

    if config.fast {
        // FAST_MODE_TASKS = secrets, governance, semanticSast, fileEncapsulation
        log("→ semanticSast starting...");
        let __t = std::time::Instant::now();
        let semantic_sast_result = ignite_semantic_sast::check_semantic_sast(root, runner, &config.semantic_sast).await;
        let ms = __t.elapsed().as_millis() as u64;
        task_timings.push(("semanticSast", ms));
        log(&format!("✓ semanticSast done ({} finding(s), {ms}ms)", semantic_sast_result.findings.len()));
        let semantic_sast_check = CheckResult {
            findings: semantic_sast_result
                .findings
                .iter()
                .map(|f| RawFinding { file: Some(f.file.clone()), line: Some(f.line as i64), kind: Some(f.kind.clone()), tool: Some(f.tool.to_string()), severity: Some(f.severity.to_string()), message: Some(f.message.clone()), cwe: f.cwe.clone(), owasp: f.owasp.clone(), ..Default::default() })
                .collect(),
            engine: Some(semantic_sast_result.engine.to_string()),
        };
        log("→ fileEncapsulation starting...");
        let __t = std::time::Instant::now();
        let file_encapsulation_result = ignite_file_encapsulation::check_file_encapsulation(root, &config.file_encapsulation)?;
        let ms = __t.elapsed().as_millis() as u64;
        task_timings.push(("fileEncapsulation", ms));
        log(&format!("✓ fileEncapsulation done ({} finding(s), {ms}ms)", file_encapsulation_result.findings.len()));
        let file_encapsulation_check = CheckResult {
            findings: file_encapsulation_result.findings.iter().map(|f| RawFinding { file: Some(f.file.clone()), line: Some(f.line as i64), kind: Some(f.kind.to_string()), tool: Some(f.tool.to_string()), severity: Some(f.severity.to_string()), message: Some(f.message.clone()), ..Default::default() }).collect(),
            engine: Some(file_encapsulation_result.engine.to_string()),
        };

        let inputs = Phase4Inputs {
            secrets: secrets_check,
            governance: governance_check,
            llm: None,
            iac: None,
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
        };
        let issues = ignite_override_engine::collect_phase4_issues(&inputs);
        task_timings.push(("phase4Total", __t0.elapsed().as_millis() as u64));
        return Ok(Phase4Output { issues, documents: Phase4Documents { sbom: None, provenance: None, loc_metrics: None, posture_report: None, ai_act_documents_report: None }, task_timings });
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
    // fan-out never had. Merged into one `tokio::try_join!`; the few
    // previously-infallible checks (semgrep, Bearer, jscpd, gocloc,
    // igniteignore) are wrapped in `Ok::<_, io::Error>(...)` so every branch
    // shares one Result shape, same trick already used for llm/provenance.
    let manifests = ignite_package_hallucination::default_manifests();
    let semantic_sast_fut = async { Ok::<_, std::io::Error>(ignite_semantic_sast::check_semantic_sast(root, runner, &config.semantic_sast).await) };
    let pii_fut = async { Ok::<_, std::io::Error>(ignite_pii_dataflow::check_pii_data_flow(root, runner, &config.pii_data_flow).await) };
    let duplication_fut = async { Ok::<_, std::io::Error>(ignite_code_duplication::check_code_duplication(root, runner, &config.code_duplication).await) };
    let loc_metrics_fut = async { Ok::<_, std::io::Error>(ignite_loc_metrics::generate_loc_metrics(root, runner, config.loc_metrics_enabled).await) };
    let igniteignore_fut = async { Ok::<_, std::io::Error>(ignite_igniteignore::check_igniteignore_committed(root, runner, config.igniteignore_enabled).await) };

    let llm_fut = async {
        if let Some(llm_config) = &config.llm {
            let result = ignite_llm_deep_scan::check_llm_deep_scan(root, llm_config, store, &config.org, &config.repo, |_l| {}).await?;
            Ok::<_, std::io::Error>(Some(result))
        } else {
            Ok(None)
        }
    };
    let provenance_fut = async {
        if config.project_id.is_some() {
            let provenance = ignite_provenance::generate_provenance(root, runner, "0.1.0", ignite_provenance::ProvenanceParams { org: Some(&config.org), repo: Some(&config.repo), job_id: None }).await?;
            Ok::<_, std::io::Error>(Some(provenance))
        } else {
            Ok(None)
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
    ) = tokio::try_join!(
        timed("semanticSast", log, semantic_sast_fut),
        timed("pii", log, pii_fut),
        timed("duplication", log, duplication_fut),
        timed("locMetrics", log, loc_metrics_fut),
        timed("igniteIgnore", log, igniteignore_fut),
        timed("llm", log, llm_fut),
        timed("iac", log, ignite_iac_security::check_iac_security(root, runner, &config.iac)),
        timed("imageVulnerabilities", log, ignite_container_image_vulnerabilities::check_container_image_vulnerabilities(root, runner, &config.container_image_vulnerabilities)),
        timed("sbom", log, ignite_sbom::generate_sbom(root, runner, config.sbom_enabled, &manifests, 1000)),
        timed("provenance", log, provenance_fut),
        timed("imageProvenance", log, ignite_image_provenance::check_image_provenance(root, runner, &config.image_provenance, Some(store))),
        timed("apiSchema", log, ignite_api_schema::check_api_schemas(root, runner, &config.api_schema)),
        timed("apiSchemaDrift", log, ignite_api_schema_drift::check_api_schema_drift(root, runner, &config.api_schema_drift)),
        timed("maliciousDependencies", log, ignite_malicious_dependencies::check_malicious_dependencies(root, runner, &config.malicious_dependencies, Some(store))),
        timed("modelArtifactSecurity", log, ignite_model_artifact_security::check_model_artifact_security(root, runner, &config.model_artifact_security)),
        timed("packageHallucination", log, hallucination_checker.check(root, config.package_hallucination_enabled, &manifests)),
        timed("posture", log, ignite_feature_posture::check_feature_posture(root, runner, &config.feature_posture)),
        timed("codeql", log, ignite_codeql_cross_file::check_codeql_cross_file(root, runner, &config.codeql, ignite_codeql_cross_file::CodeqlContext { org: Some(&config.org), repo: Some(&config.repo), store: Some(store), keep_db_dir: None })),
    )?;
    task_timings.extend([
        ("semanticSast", ms_semantic_sast),
        ("pii", ms_pii),
        ("duplication", ms_duplication),
        ("locMetrics", ms_loc_metrics),
        ("igniteIgnore", ms_igniteignore),
        ("llm", ms_llm),
        ("iac", ms_iac),
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

    let llm_check = llm_result.map(|result| LlmResult {
        available: result.available,
        findings: result
            .findings
            .iter()
            .map(|f| OeLlmFinding { category: f.category.clone(), file: Some(f.file.clone()), line: Some(f.line), level: Some(f.level.clone()), issue: Some(f.issue.clone()), recommendation: Some(f.recommendation.clone()), code: snippet_json(&f.code) })
            .collect(),
    });

    let iac_check = Some(CheckResult {
        findings: iac_result.findings.iter().map(|f| RawFinding { file: Some(f.file.clone()), line: Some(f.line as i64), kind: Some(f.kind.clone()), tool: Some(f.tool.to_string()), severity: Some(f.severity.clone()), message: Some(f.message.clone()), ..Default::default() }).collect(),
        engine: Some(iac_result.engine),
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
        Some(CheckResult { findings: image_provenance_result.findings.iter().map(|f| RawFinding { file: Some(f.file.clone()), line: Some(f.line as i64), kind: Some(f.kind.to_string()), tool: Some(f.tool.to_string()), severity: Some(f.severity.to_string()), message: Some(f.message.clone()), ..Default::default() }).collect(), engine: Some(image_provenance_result.engine.to_string()) });

    let semantic_sast_check = Some(CheckResult {
        findings: semantic_sast_result
            .findings
            .iter()
            .map(|f| RawFinding { file: Some(f.file.clone()), line: Some(f.line as i64), kind: Some(f.kind.clone()), tool: Some(f.tool.to_string()), severity: Some(f.severity.to_string()), message: Some(f.message.clone()), cwe: f.cwe.clone(), owasp: f.owasp.clone(), ..Default::default() })
            .collect(),
        engine: Some(semantic_sast_result.engine.to_string()),
    });

    let pii_check = Some(CheckResult {
        findings: pii_result.findings.iter().map(|f| RawFinding { file: Some(f.file.clone()), line: Some(f.line as i64), kind: Some(f.kind.clone()), tool: Some(f.tool.to_string()), severity: Some(f.severity.to_string()), message: Some(f.message.clone()), cwe: f.cwe.clone(), ..Default::default() }).collect(),
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
                ..Default::default()
            })
            .collect(),
        engine: Some(duplication_result.engine.to_string()),
    });

    log("→ fileEncapsulation starting...");
    let __t = std::time::Instant::now();
    let file_encapsulation_result = ignite_file_encapsulation::check_file_encapsulation(root, &config.file_encapsulation)?;
    let ms = __t.elapsed().as_millis() as u64;
    task_timings.push(("fileEncapsulation", ms));
    log(&format!("✓ fileEncapsulation done ({} finding(s), {ms}ms)", file_encapsulation_result.findings.len()));
    let file_encapsulation_check = Some(CheckResult {
        findings: file_encapsulation_result.findings.iter().map(|f| RawFinding { file: Some(f.file.clone()), line: Some(f.line as i64), kind: Some(f.kind.to_string()), tool: Some(f.tool.to_string()), severity: Some(f.severity.to_string()), message: Some(f.message.clone()), ..Default::default() }).collect(),
        engine: Some(file_encapsulation_result.engine.to_string()),
    });

    let loc_metrics_doc = if config.project_id.is_some() { loc_metrics_result.metrics.as_ref().map(to_json_bytes) } else { None };

    let api_schema_check = Some(CheckResult {
        findings: api_schema_result.findings.iter().map(|f| RawFinding { file: Some(f.file.clone()), line: Some(f.line as i64), kind: Some(f.kind.clone()), tool: Some(f.tool.to_string()), severity: Some(f.severity.to_string()), message: Some(f.message.clone()), ..Default::default() }).collect(),
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
    let ai_act_docs_result = ignite_compliance_documents::check_compliance_documents(root, config.eu_ai_act_documents_enabled)?;
    let ms = __t.elapsed().as_millis() as u64;
    task_timings.push(("euAiActDocuments", ms));
    log(&format!("✓ euAiActDocuments done ({ms}ms)"));
    let ai_act_docs_doc = if config.project_id.is_some() { Some(to_json_bytes(&serde_json::json!({ "engine": ai_act_docs_result.engine, "documents": ai_act_docs_result.documents }))) } else { None };

    let eu_ai_act_check = if config.eu_ai_act_report_as_findings {
        Some(derive_eu_ai_act_findings(&posture_result.posture, &ai_act_docs_result.documents))
    } else {
        None
    };

    log("→ deadCode starting...");
    let __t = std::time::Instant::now();
    let dead_code_result = ignite_dead_code::check_dead_code(root, &config.dead_code)?;
    let ms = __t.elapsed().as_millis() as u64;
    task_timings.push(("deadCode", ms));
    log(&format!("✓ deadCode done ({} finding(s), {ms}ms)", dead_code_result.findings.len()));
    let dead_code_check = Some(CheckResult {
        findings: dead_code_result.findings.iter().map(|f| RawFinding { file: Some(f.file.clone()), line: Some(f.line as i64), kind: Some(f.kind.clone()), tool: Some(f.tool.to_string()), severity: Some(f.severity.to_string()), message: Some(f.message.clone()), ..Default::default() }).collect(),
        engine: Some(dead_code_result.engine.to_string()),
    });

    let churn: HashMap<String, u64> = HashMap::new(); // git-churn weighting not yet wired (needs `git log --numstat`)
    let org = config.org.clone();
    let repo = config.repo.clone();
    log("→ health starting...");
    let __t = std::time::Instant::now();
    let health_result = ignite_complexity_health::check_complexity_health(root, &config.complexity_health, &churn, |rel_path| store.get_runtime_coverage_for_file(&org, &repo, rel_path).and_then(|r| r.covered_pct))?;
    let ms = __t.elapsed().as_millis() as u64;
    task_timings.push(("health", ms));
    log(&format!("✓ health done ({} finding(s), {ms}ms)", health_result.findings.len()));
    let health_check = Some(CheckResult {
        findings: health_result.findings.iter().map(|f| RawFinding { file: Some(f.file.clone()), line: Some(f.line as i64), kind: Some(f.kind.to_string()), tool: Some(f.tool.to_string()), severity: Some(f.severity.to_string()), message: Some(f.message.clone()), ..Default::default() }).collect(),
        engine: Some(health_result.engine.to_string()),
    });

    log("→ cssDeadCode starting...");
    let __t = std::time::Instant::now();
    let css_dead_code_result = ignite_css_dead_code::check_css_dead_code(root, &config.css_dead_code)?;
    let ms = __t.elapsed().as_millis() as u64;
    task_timings.push(("cssDeadCode", ms));
    log(&format!("✓ cssDeadCode done ({} finding(s), {ms}ms)", css_dead_code_result.findings.len()));
    let css_dead_code_check = Some(CheckResult {
        findings: css_dead_code_result.findings.iter().map(|f| RawFinding { file: Some(f.file.clone()), line: Some(f.line as i64), kind: Some(f.kind.to_string()), tool: Some(f.tool.to_string()), severity: Some(f.severity.to_string()), message: Some(f.message.clone()), ..Default::default() }).collect(),
        engine: Some(css_dead_code_result.engine.to_string()),
    });

    log("→ boundaries starting...");
    let __t = std::time::Instant::now();
    let boundaries_result = ignite_boundaries::check_boundaries(root, &config.boundaries)?;
    let ms = __t.elapsed().as_millis() as u64;
    task_timings.push(("boundaries", ms));
    log(&format!("✓ boundaries done ({} finding(s), {ms}ms)", boundaries_result.findings.len()));
    let boundaries_check = Some(CheckResult {
        findings: boundaries_result.findings.iter().map(|f| RawFinding { file: Some(f.file.clone()), line: Some(f.line as i64), kind: Some(f.kind.to_string()), tool: Some(f.tool.to_string()), severity: Some(f.severity.to_string()), message: Some(f.message.clone()), ..Default::default() }).collect(),
        engine: Some(boundaries_result.engine.to_string()),
    });

    let igniteignore_check = Some(CheckResult {
        findings: igniteignore_result.findings.iter().map(|f| RawFinding { file: Some(f.file.to_string()), line: Some(f.line as i64), kind: Some(f.kind.to_string()), tool: Some(f.tool.to_string()), severity: Some(f.severity.to_string()), message: Some(f.message.clone()), ..Default::default() }).collect(),
        engine: Some(igniteignore_result.engine.to_string()),
    });

    let codeql_check = Some(CodeqlResult {
        findings: codeql_result
            .findings
            .iter()
            .map(|f| OeCodeqlFinding { file: Some(f.file.clone()), line: Some(f.line as i64), kind: Some(f.kind.clone()), severity: Some(f.severity.clone()), message: Some(f.message.clone()), snippet: snippet_json(&f.snippet), cross_file: f.cross_file, chain: None, cwe: None })
            .collect(),
    });

    let inputs = Phase4Inputs {
        secrets: secrets_check,
        governance: governance_check,
        llm: llm_check,
        iac: iac_check,
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
            findings.push(RawFinding { kind: Some("ai-act-compliance-documents".to_string()), message: Some(message.to_string()), ..Default::default() });
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

    fn test_config(project_id: Option<i64>) -> Phase4Config {
        Phase4Config {
            fast: false,
            org: "test-org".to_string(),
            repo: "test-repo".to_string(),
            project_id,
            secrets: ignite_secrets::SecretsConfig::default(),
            llm: None,
            iac: ignite_iac_security::IacSecurityConfig { trivy_enabled: false, checkov_enabled: false, hadolint_enabled: false },
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
            igniteignore_enabled: false,
            codeql: ignite_codeql_cross_file::CodeqlConfig { enabled: false, ..Default::default() },
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
}
