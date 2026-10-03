//! Phase 4 config and tool runner for standalone drivers that run outside
//! the server (`phase4-scan`, `sast-bench`), so neither keeps its own copy
//! of the full `Phase4Config` literal. The server builds its config from
//! `config.json` instead (`ignite-server`'s `phase4_config::from_config`);
//! this uses each check crate's own defaults.

use crate::Phase4Config;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// External tools a full Phase 4 run can use. Each one resolves off `PATH`
/// under its own name; a missing one makes its check fall back or skip.
pub const EXTERNAL_TOOLS: &[&str] = &[
    "trivy", "checkov", "hadolint", "syft", "cosign", "semgrep", "bearer", "jscpd", "gocloc", "spectral", "guarddog", "codeql", "picklescan", "oasdiff", "gitleaks", "zizmor", "licensee",
];

/// `external_tools: false` registers none of [`EXTERNAL_TOOLS`], so every
/// check that needs one gets `ToolError::Unsupported` and takes its
/// built-in fallback (or reports itself unavailable) — the same path a
/// deployment without the tool installed takes.
pub fn standalone_runner(external_tools: bool) -> ignite_tool_runner::ToolRunner {
    let mut binaries: HashMap<&'static str, String> = HashMap::new();
    if external_tools {
        for t in EXTERNAL_TOOLS {
            binaries.insert(t, (*t).to_string());
        }
    }
    binaries.insert("rm", "rm".to_string());
    ignite_tool_runner::ToolRunner::new(binaries)
}

/// `ruleset_dir` is the Ignite repo root holding `ignite-posture-rules.yaml`
/// and `spectral-default-ruleset.yaml`; `None` leaves both rulesets empty.
pub fn standalone_config(org: &str, repo: &str, ruleset_dir: Option<&Path>, git_check_root: Option<PathBuf>) -> Phase4Config {
    let ruleset = |name: &str| ruleset_dir.map(|r| r.join(name).to_string_lossy().into_owned()).unwrap_or_default();
    Phase4Config {
        ignore_rules: Vec::new(),
        fast: false,
        org: org.to_string(),
        repo: repo.to_string(),
        project_id: None,
        keep_codeql_db_dir: None,
        secrets: ignite_secrets::SecretsConfig::default(),
        secret_verification: ignite_secret_verifier::SecretVerifierConfig::default(),
        llm: None,
        iac: ignite_iac_security::IacSecurityConfig::default(),
        gha_security: ignite_gha_security::GhaSecurityConfig::default(),
        container_image_vulnerabilities: ignite_container_image_vulnerabilities::ContainerImageVulnerabilitiesConfig::default(),
        sbom_enabled: true,
        image_provenance: ignite_image_provenance::ImageProvenanceConfig::default(),
        semantic_sast: ignite_semantic_sast::SemanticSastConfig::default(),
        pii_data_flow: ignite_pii_dataflow::PiiDataFlowConfig::default(),
        code_duplication: ignite_code_duplication::CodeDuplicationConfig::default(),
        file_encapsulation: ignite_file_encapsulation::FileEncapsulationConfig { enabled: true, max_lines: 1000 },
        loc_metrics_enabled: true,
        api_schema: ignite_api_schema::ApiSchemaConfig { enabled: true, ruleset: ruleset("spectral-default-ruleset.yaml") },
        api_schema_drift: ignite_api_schema_drift::ApiSchemaDriftConfig::default(),
        malicious_dependencies: ignite_malicious_dependencies::MaliciousDependenciesConfig::default(),
        model_artifact_security: ignite_model_artifact_security::ModelArtifactSecurityConfig::default(),
        package_hallucination_enabled: true,
        feature_posture: ignite_feature_posture::FeaturePostureConfig { enabled: true, ruleset: ruleset("ignite-posture-rules.yaml"), max_scan_file_bytes: 1_000_000 },
        eu_ai_act_documents_enabled: true,
        eu_ai_act_report_as_findings: false,
        dead_code: ignite_dead_code::DeadCodeConfig { enabled: true },
        complexity_health: ignite_complexity_health::ComplexityHealthConfig::default(),
        css_dead_code: ignite_css_dead_code::CssDeadCodeConfig { enabled: true },
        boundaries: ignite_boundaries::BoundariesConfig { enabled: false, preset: None, zones: vec![] },
        env_var_drift: ignite_env_var_drift::EnvVarDriftConfig::default(),
        igniteignore_enabled: true,
        igniteignore_git_check_root: git_check_root,
        // The pinned query suites `config.json` ships with — the check
        // crate's own default has none, which would skip every language.
        codeql: ignite_codeql_cross_file::CodeqlConfig { query_suites: ignite_config::CodeqlConfig::default().query_suites.into_iter().collect(), ..Default::default() },
        codeql_query_suite_review_overdue: false,
        sast_consensus: None,
        fp_learning_min_verdicts: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_runner_registers_no_external_tool() {
        let runner = standalone_runner(false);
        for t in EXTERNAL_TOOLS {
            assert!(runner.binary_for(t).is_none(), "{t} should not be registered");
        }
        assert_eq!(standalone_runner(true).binary_for("semgrep"), Some("semgrep"));
    }

    #[test]
    fn rulesets_resolve_under_the_given_dir() {
        let cfg = standalone_config("o", "r", Some(Path::new("/ig")), None);
        assert_eq!(cfg.feature_posture.ruleset, "/ig/ignite-posture-rules.yaml");
        assert!(standalone_config("o", "r", None, None).api_schema.ruleset.is_empty());
    }

    #[test]
    fn codeql_gets_a_query_suite_for_every_default_language() {
        let cfg = standalone_config("o", "r", None, None);
        for lang in &cfg.codeql.languages {
            assert!(cfg.codeql.query_suites.contains_key(lang), "no suite for {lang}");
        }
    }
}
