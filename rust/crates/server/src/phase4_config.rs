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

pub fn from_config(cfg: &ignite_config::Config, org: &str, repo: &str, project_id: Option<i64>, fast: bool) -> ignite_phase4_orchestrator::Phase4Config {
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
        },
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
        igniteignore_enabled: cfg.ignore_file.enabled,
        codeql: ignite_codeql_cross_file::CodeqlConfig {
            enabled: sec.codeql.enabled,
            languages: sec.codeql.languages.clone(),
            query_suites: sec.codeql.query_suites.clone().into_iter().collect(),
            threads: sec.codeql.threads,
            ram_mb: sec.codeql.ram_mb,
            timeout_ms: sec.codeql.timeout_ms,
        },
    }
}

pub fn runner_from_config(cfg: &ignite_config::Config) -> ignite_tool_runner::ToolRunner {
    let sec = &cfg.security;
    let binaries: std::collections::HashMap<&'static str, String> = [
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
        let phase4 = from_config(&cfg, "org", "repo", None, false);
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
        let phase4 = from_config(&cfg, "org", "repo", None, false);
        assert!(phase4.boundaries.enabled);
        assert_eq!(phase4.boundaries.preset.as_deref(), Some("layered"));
        assert_eq!(phase4.boundaries.zones.len(), 1);
        assert_eq!(phase4.boundaries.zones[0].name, "api");
    }
}
