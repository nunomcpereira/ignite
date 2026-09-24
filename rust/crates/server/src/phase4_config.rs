//! Maps the loaded `ignite_config::Config` (config.json + env overrides,
//! `AppState::config`) onto `ignite_phase4_orchestrator::Phase4Config` —
//! the one place that used to hardcode every check's `::default()`
//! regardless of what config.json/env actually said. Each check crate
//! keeps its own config struct (a deliberate design already in place
//! before this module existed), so this is a field-by-field bridge, not
//! a new source of truth.
//!
//! A few Phase4Config fields have no config.json analogue at all
//! (`ignite_secrets::SecretsConfig::max_scan_file_bytes`,
//! `ComplexityHealthConfig`'s thresholds beyond `enabled`) — those keep
//! their crate-local defaults, same as before this module existed.

use regex::Regex;

pub fn from_config(cfg: &ignite_config::Config, org: &str, repo: &str, project_id: Option<i64>, fast: bool, igniteignore_git_check_root: Option<std::path::PathBuf>) -> ignite_phase4_orchestrator::Phase4Config {
    let sec = &cfg.security;

    let known_public_key_patterns: Vec<Regex> = sec
        .secrets
        .known_public_key_patterns
        .iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect();
    let gitleaks_config_path = if sec.gitleaks.config_path.is_empty() { None } else { Some(std::path::PathBuf::from(&sec.gitleaks.config_path)) };

    let zones: Vec<ignite_boundaries::Zone> = cfg
        .architecture
        .boundaries
        .zones
        .iter()
        .filter_map(|z| {
            let name = z.get("name")?.as_str()?.to_string();
            let pattern = z.get("pattern")?.as_str()?.to_string();
            let allow = z.get("allow").and_then(|a| a.as_array()).map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
            Some(ignite_boundaries::Zone { name, pattern, allow })
        })
        .collect();
    let boundaries_preset = if cfg.architecture.boundaries.preset.is_empty() { None } else { Some(cfg.architecture.boundaries.preset.clone()) };

    ignite_phase4_orchestrator::Phase4Config {
        fast,
        org: org.to_string(),
        repo: repo.to_string(),
        project_id,
        secrets: ignite_secrets::SecretsConfig {
            known_public_key_patterns,
            max_scan_file_bytes: ignite_secrets::SecretsConfig::default().max_scan_file_bytes,
            gitleaks_config_path,
            gitleaks_enabled: sec.gitleaks.enabled,
            gitleaks_scan_history: sec.gitleaks.scan_history,
        },
        secret_verification: ignite_secret_verifier::SecretVerifierConfig { enabled: sec.secret_verification.enabled, timeout_ms: sec.secret_verification.timeout_ms },
        llm: Some(ignite_llm_deep_scan::LlmDeepScanConfig {
            enabled: cfg.llm.deep_scan_enabled,
            llm: crate::state::llm_config_from_config(cfg),
            advisory_level: if cfg.llm.advisory_level == "warning" { "warning" } else { "info" },
            max_files: cfg.llm.max_files as usize,
            chunk_chars: cfg.llm.chunk_chars as usize,
            source_exts: ignite_llm_deep_scan::default_source_exts(),
        }),
        iac: ignite_iac_security::IacSecurityConfig {
            trivy_enabled: sec.trivy.enabled,
            checkov_enabled: sec.checkov.enabled,
            hadolint_enabled: sec.hadolint.enabled,
        },
        gha_security: ignite_gha_security::GhaSecurityConfig { enabled: sec.zizmor.enabled },
        container_image_vulnerabilities: ignite_container_image_vulnerabilities::ContainerImageVulnerabilitiesConfig {
            enabled: sec.trivy_image.enabled,
            severity_threshold: sec.trivy_image.severity_threshold.clone(),
            build_timeout_ms: sec.trivy_image.build_timeout_ms,
        },
        sbom_enabled: cfg.sbom.syft.enabled,
        image_provenance: ignite_image_provenance::ImageProvenanceConfig {
            enabled: sec.cosign.enabled,
            identity_regexp: sec.cosign.identity_regexp.clone(),
            issuer_regexp: sec.cosign.issuer_regexp.clone(),
            cache_ttl_seconds: sec.cosign.cache_ttl_seconds as i64,
        },
        semantic_sast: ignite_semantic_sast::SemanticSastConfig {
            enabled: sec.semgrep.enabled,
            semgrep_config: sec.semgrep.config.clone(),
            timeout_ms: ignite_semantic_sast::SemanticSastConfig::default().timeout_ms,
        },
        pii_data_flow: ignite_pii_dataflow::PiiDataFlowConfig { enabled: sec.bearer.enabled },
        code_duplication: ignite_code_duplication::CodeDuplicationConfig {
            enabled: cfg.metrics.jscpd.enabled,
            min_lines: cfg.metrics.jscpd.min_lines,
            min_tokens: cfg.metrics.jscpd.min_tokens,
            ignore_patterns: cfg.metrics.jscpd.ignore_patterns.clone(),
        },
        file_encapsulation: ignite_file_encapsulation::FileEncapsulationConfig { enabled: cfg.metrics.file_size.enabled, max_lines: cfg.metrics.file_size.max_lines as usize },
        loc_metrics_enabled: cfg.metrics.gocloc.enabled,
        api_schema: ignite_api_schema::ApiSchemaConfig { enabled: cfg.api.spectral.enabled, ruleset: cfg.api.spectral.ruleset.clone() },
        api_schema_drift: ignite_api_schema_drift::ApiSchemaDriftConfig { enabled: cfg.api.oasdiff.enabled },
        malicious_dependencies: ignite_malicious_dependencies::MaliciousDependenciesConfig { enabled: sec.guarddog.enabled },
        model_artifact_security: ignite_model_artifact_security::ModelArtifactSecurityConfig { enabled: sec.picklescan.enabled, extensions: sec.picklescan.extensions.clone() },
        package_hallucination_enabled: sec.package_hallucination.enabled,
        feature_posture: ignite_feature_posture::FeaturePostureConfig { enabled: cfg.compliance.posture.enabled, ruleset: cfg.compliance.posture.ruleset.clone(), max_scan_file_bytes: 1_000_000 },
        eu_ai_act_documents_enabled: cfg.compliance.eu_ai_act_documents.enabled,
        eu_ai_act_report_as_findings: cfg.compliance.eu_ai_act.report_as_findings,
        dead_code: ignite_dead_code::DeadCodeConfig { enabled: cfg.code_intelligence.dead_code.enabled },
        complexity_health: ignite_complexity_health::ComplexityHealthConfig {
            enabled: cfg.code_intelligence.health.enabled,
            cyclomatic_warn_threshold: cfg.code_intelligence.health.cyclomatic_warn_threshold as i64,
            maintainability_warn_threshold: cfg.code_intelligence.health.maintainability_warn_threshold as i64,
            complexity_density_warn_threshold: cfg.code_intelligence.health.complexity_density_warn_threshold,
            top_hotspots: cfg.code_intelligence.health.top_hotspots as usize,
        },
        css_dead_code: ignite_css_dead_code::CssDeadCodeConfig { enabled: cfg.code_intelligence.css_dead_code.enabled },
        boundaries: ignite_boundaries::BoundariesConfig { enabled: cfg.architecture.boundaries.enabled, preset: boundaries_preset, zones },
        env_var_drift: ignite_env_var_drift::EnvVarDriftConfig { enabled: cfg.code_intelligence.env_var_drift.enabled },
        igniteignore_enabled: cfg.ignore_file.enabled,
        igniteignore_git_check_root,
        codeql: ignite_codeql_cross_file::CodeqlConfig {
            enabled: sec.codeql.enabled,
            languages: sec.codeql.languages.clone(),
            query_suites: sec.codeql.query_suites.clone().into_iter().collect(),
            threads: sec.codeql.threads,
            ram_mb: sec.codeql.ram_mb,
            timeout_ms: sec.codeql.timeout_ms,
        },
        codeql_query_suite_review_overdue: ignite_config::is_codeql_review_overdue(
            sec.codeql.last_reviewed_at.as_deref(),
            sec.codeql.review_cadence_days,
            chrono::Utc::now().date_naive(),
        ),
        // Persist whichever CodeQL database(s) this run builds to the same
        // location Studio's ad-hoc query/call-graph routes read from
        // (`crate::routes::studio::codeql_db_dir_for`), so a project that
        // went through the normal scan already has a queryable database by
        // the time Studio opens — no separate "Run CodeQL" click needed.
        // `None` for a headless/CI call with no project row (there's no
        // Studio session to serve).
        keep_codeql_db_dir: crate::routes::studio::codeql_db_dir_for(project_id),
    }
}

pub fn runner_from_config(cfg: &ignite_config::Config) -> ignite_tool_runner::ToolRunner {
    let sec = &cfg.security;
    let mut binaries: std::collections::HashMap<&'static str, String> = [
        ("trivy", sec.trivy.binary.clone()),
        ("checkov", sec.checkov.binary.clone()),
        ("hadolint", sec.hadolint.binary.clone()),
        ("syft", cfg.sbom.syft.binary.clone()),
        ("cosign", sec.cosign.binary.clone()),
        ("semgrep", sec.semgrep.binary.clone()),
        ("bearer", sec.bearer.binary.clone()),
        ("jscpd", cfg.metrics.jscpd.binary.clone()),
        ("gocloc", cfg.metrics.gocloc.binary.clone()),
        ("spectral", cfg.api.spectral.binary.clone()),
        ("guarddog", sec.guarddog.binary.clone()),
        ("codeql", sec.codeql.binary.clone()),
        ("picklescan", sec.picklescan.binary.clone()),
        ("oasdiff", cfg.api.oasdiff.binary.clone()),
        ("gitleaks", sec.gitleaks.binary.clone()),
        ("zizmor", sec.zizmor.binary.clone()),
        ("rm", "rm".to_string()),
    ]
    .into_iter()
    .collect();
    if let Some(browser) = crate::routes::daily_report::detect_pdf_browser(&cfg.daily_report.pdf_browser_binary) {
        binaries.insert("chrome", browser);
    }
    ignite_tool_runner::ToolRunner::new(binaries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabling_a_tool_in_config_propagates_to_phase4_config() {
        let mut cfg = ignite_config::Config::default();
        cfg.security.semgrep.enabled = false;
        cfg.security.guarddog.enabled = false;
        let phase4 = from_config(&cfg, "org", "repo", None, false, None);
        assert!(!phase4.semantic_sast.enabled);
        assert!(!phase4.malicious_dependencies.enabled);
        // Untouched fields still reflect the (enabled-by-default) config.
        assert!(phase4.iac.trivy_enabled);
    }

    #[test]
    fn custom_binary_path_propagates_to_runner() {
        let mut cfg = ignite_config::Config::default();
        cfg.security.trivy.binary = "/opt/tools/trivy".to_string();
        let runner = runner_from_config(&cfg);
        assert_eq!(runner.binary_for("trivy"), Some("/opt/tools/trivy"));
    }

    #[test]
    fn boundaries_zones_parsed_from_config_json_value() {
        let mut cfg = ignite_config::Config::default();
        cfg.architecture.boundaries.enabled = true;
        cfg.architecture.boundaries.preset = "layered".to_string();
        cfg.architecture.boundaries.zones = vec![serde_json::json!({ "name": "api", "pattern": "src/api/**", "allow": ["core"] })];
        let phase4 = from_config(&cfg, "org", "repo", None, false, None);
        assert!(phase4.boundaries.enabled);
        assert_eq!(phase4.boundaries.preset.as_deref(), Some("layered"));
        assert_eq!(phase4.boundaries.zones.len(), 1);
        assert_eq!(phase4.boundaries.zones[0].name, "api");
    }

    // ---- characterization: pins how each config value reaches its check. The
    // ---- bridge is a hand-written field-by-field copy; deepening it must keep
    // ---- every row of this table true.

    type SetFlag = fn(&mut ignite_config::Config, bool);
    type GetFlag = fn(&ignite_phase4_orchestrator::Phase4Config) -> bool;

    fn flag_table() -> Vec<(&'static str, SetFlag, GetFlag)> {
        vec![
            ("security.gitleaks.enabled", |c, v| c.security.gitleaks.enabled = v, |p| p.secrets.gitleaks_enabled),
            ("security.gitleaks.scanHistory", |c, v| c.security.gitleaks.scan_history = v, |p| p.secrets.gitleaks_scan_history),
            ("security.secretVerification.enabled", |c, v| c.security.secret_verification.enabled = v, |p| p.secret_verification.enabled),
            ("llm.deepScanEnabled", |c, v| c.llm.deep_scan_enabled = v, |p| p.llm.as_ref().unwrap().enabled),
            ("security.trivy.enabled", |c, v| c.security.trivy.enabled = v, |p| p.iac.trivy_enabled),
            ("security.checkov.enabled", |c, v| c.security.checkov.enabled = v, |p| p.iac.checkov_enabled),
            ("security.hadolint.enabled", |c, v| c.security.hadolint.enabled = v, |p| p.iac.hadolint_enabled),
            ("security.zizmor.enabled", |c, v| c.security.zizmor.enabled = v, |p| p.gha_security.enabled),
            ("security.trivyImage.enabled", |c, v| c.security.trivy_image.enabled = v, |p| p.container_image_vulnerabilities.enabled),
            ("sbom.syft.enabled", |c, v| c.sbom.syft.enabled = v, |p| p.sbom_enabled),
            ("security.cosign.enabled", |c, v| c.security.cosign.enabled = v, |p| p.image_provenance.enabled),
            ("security.semgrep.enabled", |c, v| c.security.semgrep.enabled = v, |p| p.semantic_sast.enabled),
            ("security.bearer.enabled", |c, v| c.security.bearer.enabled = v, |p| p.pii_data_flow.enabled),
            ("metrics.jscpd.enabled", |c, v| c.metrics.jscpd.enabled = v, |p| p.code_duplication.enabled),
            ("metrics.fileSize.enabled", |c, v| c.metrics.file_size.enabled = v, |p| p.file_encapsulation.enabled),
            ("metrics.gocloc.enabled", |c, v| c.metrics.gocloc.enabled = v, |p| p.loc_metrics_enabled),
            ("api.spectral.enabled", |c, v| c.api.spectral.enabled = v, |p| p.api_schema.enabled),
            ("api.oasdiff.enabled", |c, v| c.api.oasdiff.enabled = v, |p| p.api_schema_drift.enabled),
            ("security.guarddog.enabled", |c, v| c.security.guarddog.enabled = v, |p| p.malicious_dependencies.enabled),
            ("security.picklescan.enabled", |c, v| c.security.picklescan.enabled = v, |p| p.model_artifact_security.enabled),
            ("security.packageHallucination.enabled", |c, v| c.security.package_hallucination.enabled = v, |p| p.package_hallucination_enabled),
            ("compliance.posture.enabled", |c, v| c.compliance.posture.enabled = v, |p| p.feature_posture.enabled),
            ("compliance.euAiActDocuments.enabled", |c, v| c.compliance.eu_ai_act_documents.enabled = v, |p| p.eu_ai_act_documents_enabled),
            ("compliance.euAiAct.reportAsFindings", |c, v| c.compliance.eu_ai_act.report_as_findings = v, |p| p.eu_ai_act_report_as_findings),
            ("codeIntelligence.deadCode.enabled", |c, v| c.code_intelligence.dead_code.enabled = v, |p| p.dead_code.enabled),
            ("codeIntelligence.health.enabled", |c, v| c.code_intelligence.health.enabled = v, |p| p.complexity_health.enabled),
            ("codeIntelligence.cssDeadCode.enabled", |c, v| c.code_intelligence.css_dead_code.enabled = v, |p| p.css_dead_code.enabled),
            ("codeIntelligence.envVarDrift.enabled", |c, v| c.code_intelligence.env_var_drift.enabled = v, |p| p.env_var_drift.enabled),
            ("architecture.boundaries.enabled", |c, v| c.architecture.boundaries.enabled = v, |p| p.boundaries.enabled),
            ("ignoreFile.enabled", |c, v| c.ignore_file.enabled = v, |p| p.igniteignore_enabled),
            ("security.codeql.enabled", |c, v| c.security.codeql.enabled = v, |p| p.codeql.enabled),
        ]
    }

    #[test]
    fn every_enable_flag_reaches_its_check_in_both_directions() {
        for (name, set, get) in flag_table() {
            for value in [true, false] {
                let mut cfg = ignite_config::Config::default();
                set(&mut cfg, value);
                let p = from_config(&cfg, "acme", "widgets", None, false, None);
                assert_eq!(get(&p), value, "{name} = {value} did not reach its check");
            }
        }
    }

    #[test]
    fn identity_and_mode_pass_straight_through() {
        let cfg = ignite_config::Config::default();
        let p = from_config(&cfg, "acme", "widgets", Some(42), true, None);
        assert_eq!((p.org.as_str(), p.repo.as_str(), p.project_id, p.fast), ("acme", "widgets", Some(42), true));
        let p = from_config(&cfg, "o", "r", None, false, None);
        assert_eq!((p.project_id, p.fast), (None, false));
    }

    #[test]
    fn tunable_values_reach_their_check_unchanged() {
        let mut cfg = ignite_config::Config::default();
        cfg.security.semgrep.config = "p/pinned".to_string();
        cfg.security.secret_verification.timeout_ms = 1234;
        cfg.security.cosign.identity_regexp = "id-re".to_string();
        cfg.security.cosign.issuer_regexp = "iss-re".to_string();
        cfg.security.trivy_image.severity_threshold = "CRITICAL".to_string();
        cfg.metrics.jscpd.min_lines = 33;
        cfg.metrics.jscpd.min_tokens = 77;
        cfg.metrics.file_size.max_lines = 321;
        cfg.api.spectral.ruleset = "rules.yaml".to_string();
        cfg.compliance.posture.ruleset = "posture.yaml".to_string();
        cfg.security.codeql.languages = vec!["go".to_string()];
        cfg.security.codeql.threads = 3;
        let p = from_config(&cfg, "acme", "widgets", None, false, None);
        assert_eq!(p.semantic_sast.semgrep_config, "p/pinned");
        assert_eq!(p.secret_verification.timeout_ms, 1234);
        assert_eq!((p.image_provenance.identity_regexp.as_str(), p.image_provenance.issuer_regexp.as_str()), ("id-re", "iss-re"));
        assert_eq!(p.container_image_vulnerabilities.severity_threshold, "CRITICAL");
        assert_eq!((p.code_duplication.min_lines, p.code_duplication.min_tokens), (33, 77));
        assert_eq!(p.file_encapsulation.max_lines, 321);
        assert_eq!(p.api_schema.ruleset, "rules.yaml");
        assert_eq!(p.feature_posture.ruleset, "posture.yaml");
        assert_eq!(p.codeql.languages, vec!["go".to_string()]);
        assert_eq!(p.codeql.threads, 3);
    }

    #[test]
    fn an_empty_gitleaks_config_path_means_none_and_an_invalid_public_key_pattern_is_dropped() {
        let mut cfg = ignite_config::Config::default();
        cfg.security.gitleaks.config_path = String::new();
        assert!(from_config(&cfg, "a", "b", None, false, None).secrets.gitleaks_config_path.is_none());
        cfg.security.gitleaks.config_path = "/etc/gitleaks.toml".to_string();
        assert_eq!(from_config(&cfg, "a", "b", None, false, None).secrets.gitleaks_config_path, Some(std::path::PathBuf::from("/etc/gitleaks.toml")));
        cfg.security.secrets.known_public_key_patterns = vec!["AIza[0-9A-Za-z_-]{20,}".to_string(), "(unclosed".to_string()];
        let p = from_config(&cfg, "a", "b", None, false, None);
        assert_eq!(p.secrets.known_public_key_patterns.len(), 1, "a bad regex is skipped, never a panic");
    }

    #[test]
    fn the_llm_advisory_level_is_warning_or_info_and_nothing_else() {
        let mut cfg = ignite_config::Config::default();
        cfg.llm.advisory_level = "warning".to_string();
        assert_eq!(from_config(&cfg, "a", "b", None, false, None).llm.unwrap().advisory_level, "warning");
        cfg.llm.advisory_level = "anything-else".to_string();
        assert_eq!(from_config(&cfg, "a", "b", None, false, None).llm.unwrap().advisory_level, "info");
    }
}
