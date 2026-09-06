//! Turns the raw phase-4 check outputs (secrets / AI-governance / LLM
//! security+quality findings / ...) into a single list of addressable
//! "issues" with stable ids, and validates a set of user-submitted
//! overrides against them. Faithful port of `override-engine.js`.
//!
//! Split into three concerns that used to live in one file: `model` (the
//! data shapes), `scoring` (severity/CWE-OWASP/false-positive heuristics),
//! `collect` (raw findings → `Issue`), and `validation` (the override
//! gate). Everything is re-exported at the crate root so existing callers
//! (`ignite_override_engine::Issue`, `::validate_overrides`, etc.) are
//! unaffected by the split.

mod collect;
mod model;
mod scoring;
mod validation;

pub use collect::*;
pub use model::*;
pub use scoring::*;
pub use validation::*;

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(file: &str, line: i64) -> RawFinding {
        RawFinding { file: Some(file.to_string()), line: Some(line), ..Default::default() }
    }

    #[test]
    fn build_references_sorts_mixed_ids_into_their_own_buckets_and_dedupes() {
        let refs = build_references([
            "GHSA-82w8-qh3p-5jfq",
            "CVE-2026-54283",
            "CVE-2026-48818",
            "CWE-770",
            "CWE-400",
            "PYSEC-2026-249",
            "PYSEC-2026-3037",
            "CVE-2026-54283", // duplicate, should not repeat
        ]);
        assert_eq!(refs.ghsa, vec!["GHSA-82w8-qh3p-5jfq"]);
        assert_eq!(refs.cve, vec!["CVE-2026-54283", "CVE-2026-48818"]);
        assert_eq!(refs.cwe, vec!["CWE-770", "CWE-400"]);
        assert_eq!(refs.pysec, vec!["PYSEC-2026-249", "PYSEC-2026-3037"]);
        assert!(refs.rustsec.is_empty());
        assert!(refs.go.is_empty());
    }

    #[test]
    fn build_references_recognizes_rustsec_and_go_ids() {
        let refs = build_references(["RUSTSEC-2023-0001", "GO-2023-1234", "not-an-advisory-id"]);
        assert_eq!(refs.rustsec, vec!["RUSTSEC-2023-0001"]);
        assert_eq!(refs.go, vec!["GO-2023-1234"]);
        assert!(!refs.is_empty());
        assert!(refs.cve.is_empty() && refs.cwe.is_empty() && refs.ghsa.is_empty() && refs.pysec.is_empty());
    }

    #[test]
    fn issue_json_uses_camel_case_keys_the_frontend_expects() {
        let issue = Issue {
            id: "codeql-sast::src/fileService.js::8".to_string(),
            category: "codeql-sast".to_string(),
            severity: Severity::Error,
            score: 8,
            summary: "This path depends on a user-provided value.".to_string(),
            file: Some("src/fileService.js".to_string()),
            line: Some(8),
            snippet: None,
            cross_file: true,
            chain: None,
            duplicate_ref: Some(serde_json::json!({ "file": "src/routes.js", "line": 6 })),
            cwe: None,
            owasp: None,
            tool: Some("codeql".to_string()),
            references: IssueReferences::default(),
        };
        let json = serde_json::to_value(&issue).unwrap();
        assert_eq!(json["crossFile"], serde_json::json!(true));
        assert_eq!(json["duplicateRef"]["file"], serde_json::json!("src/routes.js"));
        assert!(json.get("cross_file").is_none());
        assert!(json.get("duplicate_ref").is_none());
    }

    #[test]
    fn build_issue_id_uses_discriminator_when_present() {
        let id = build_issue_id(BuildIssueIdArgs { category: "container-image-cve", file: Some("Dockerfile"), line: Some(1), discriminator: Some("CVE-2024-1@openssl") });
        assert_eq!(id, "container-image-cve::Dockerfile::1::CVE-2024-1@openssl");
    }

    #[test]
    fn build_issue_id_defaults_unknown_file_and_zero_line() {
        let id = build_issue_id(BuildIssueIdArgs { category: "quality", file: None, line: None, discriminator: None });
        assert_eq!(id, "quality::unknown::0");
    }

    #[test]
    fn is_likely_test_file_matches_common_conventions() {
        assert!(is_likely_test_file(Some("test/foo.js")));
        assert!(is_likely_test_file(Some("src/foo.test.ts")));
        assert!(is_likely_test_file(Some("src/foo_test.py")));
        assert!(is_likely_test_file(Some("__tests__/bar.js")));
        assert!(!is_likely_test_file(Some("src/foo.js")));
    }

    #[test]
    fn is_likely_dev_only_file_matches_scripts_and_deploy() {
        assert!(is_likely_dev_only_file(Some("scripts/build.js")));
        assert!(is_likely_dev_only_file(Some("e2e/setup.ts")));
        assert!(is_likely_dev_only_file(Some("deploy-staging.js")));
        assert!(!is_likely_dev_only_file(Some("src/app.js")));
    }

    #[test]
    fn score_for_issue_halves_and_floors_for_warnings() {
        assert_eq!(score_for_issue("secret", Severity::Error), 10);
        assert_eq!(score_for_issue("secret", Severity::Warning), 5);
        assert_eq!(score_for_issue("code-duplication", Severity::Warning), 1); // 2/2=1, already floor
        assert_eq!(score_for_issue("unknown-category", Severity::Error), 7);
        // Cross-checked against the real scoreForIssue: the JS fallback
        // base already picks 3 for a warning-severity unknown category,
        // then the outer "halve for warning" rule applies a second time —
        // round(3/2)=2, not 3. A real double-discount, not a bug.
        assert_eq!(score_for_issue("unknown-category", Severity::Warning), 2);
    }

    #[test]
    fn derive_cwe_owasp_precedence_explicit_then_text_then_category() {
        let explicit = CweOwaspHint { cwe: Some("CWE-1".into()), owasp: None };
        assert_eq!(derive_cwe_owasp("secret", "anything", &explicit).cwe, Some("CWE-1".into()));

        let none = CweOwaspHint::default();
        let text_hit = derive_cwe_owasp("quality", "possible SQL injection here", &none);
        assert_eq!(text_hit.cwe, Some("CWE-89".into()));

        let category_fallback = derive_cwe_owasp("secret", "nothing matches text patterns", &none);
        assert_eq!(category_fallback.cwe, Some("CWE-798".into()));

        let no_mapping = derive_cwe_owasp("code-duplication", "duplicate block", &none);
        assert_eq!(no_mapping.cwe, None);
    }

    #[test]
    fn secrets_in_test_files_are_demoted_to_warning() {
        let mut input = Phase4Inputs::default();
        input.secrets.findings.push(RawFinding { kind: Some("api-key".into()), ..finding("test/fixtures/creds.js", 3) });
        input.secrets.findings.push(RawFinding { kind: Some("api-key".into()), ..finding("src/app.js", 10) });
        let issues = collect_phase4_issues(&input);
        let test_issue = issues.iter().find(|i| i.file.as_deref() == Some("test/fixtures/creds.js")).unwrap();
        let real_issue = issues.iter().find(|i| i.file.as_deref() == Some("src/app.js")).unwrap();
        assert_eq!(test_issue.severity, Severity::Warning);
        assert_eq!(real_issue.severity, Severity::Error);
        assert!(test_issue.summary.contains("likely a fixture"));
    }

    #[test]
    fn container_image_cve_discriminator_prevents_collisions_on_same_dockerfile_line() {
        let mut input = Phase4Inputs::default();
        let mut iv = CheckResult::default();
        iv.findings.push(RawFinding { kind: Some("CVE-2024-1".into()), pkg_name: Some("openssl".into()), severity: Some("critical".into()), ..finding("Dockerfile", 1) });
        iv.findings.push(RawFinding { kind: Some("CVE-2024-2".into()), pkg_name: Some("curl".into()), severity: Some("high".into()), ..finding("Dockerfile", 1) });
        input.image_vulnerabilities = Some(iv);
        let issues = collect_phase4_issues(&input);
        assert_eq!(issues.len(), 2);
        assert_ne!(issues[0].id, issues[1].id);
        assert!(issues[0].id.contains("CVE-2024-1@openssl"));
    }

    #[test]
    fn container_image_cve_finding_associates_its_real_cve_id() {
        let mut input = Phase4Inputs::default();
        let mut iv = CheckResult::default();
        iv.findings.push(RawFinding { kind: Some("CVE-2024-1".into()), pkg_name: Some("openssl".into()), severity: Some("critical".into()), ..finding("Dockerfile", 1) });
        input.image_vulnerabilities = Some(iv);
        let issues = collect_phase4_issues(&input);
        assert_eq!(issues[0].references.cve, vec!["CVE-2024-1".to_string()]);
    }

    #[test]
    fn push_simple_findings_ignore_non_advisory_shaped_kind() {
        let mut input = Phase4Inputs::default();
        input.secrets.findings.push(RawFinding { kind: Some("aws_secret_key".into()), severity: Some("error".into()), ..finding("config.js", 3) });
        let issues = collect_phase4_issues(&input);
        assert!(issues[0].references.cve.is_empty());
    }

    #[test]
    fn semantic_sast_command_injection_demoted_on_dev_tooling_path() {
        let mut input = Phase4Inputs::default();
        let mut ss = CheckResult::default();
        ss.findings.push(RawFinding { message: Some("Possible command injection via exec".into()), severity: Some("error".into()), ..finding("scripts/deploy.js", 5) });
        ss.findings.push(RawFinding { message: Some("Possible command injection via exec".into()), severity: Some("error".into()), ..finding("src/handler.js", 5) });
        input.semantic_sast = Some(ss);
        let issues = collect_phase4_issues(&input);
        let dev_tooling = issues.iter().find(|i| i.file.as_deref() == Some("scripts/deploy.js")).unwrap();
        let real_code = issues.iter().find(|i| i.file.as_deref() == Some("src/handler.js")).unwrap();
        assert_eq!(dev_tooling.severity, Severity::Warning);
        assert_eq!(real_code.severity, Severity::Error);
    }

    /// Regression test for the id-collision bug: two distinct findings
    /// from the same check, on the same file:line, with no discriminator
    /// of their own, must not collapse onto one shared id — justifying
    /// one would otherwise silently suppress the other too.
    #[test]
    fn distinct_findings_sharing_a_file_and_line_get_distinct_ids() {
        let mut input = Phase4Inputs::default();
        let mut ss = CheckResult::default();
        ss.findings.push(RawFinding { message: Some("Possible SQL injection".into()), severity: Some("error".into()), ..finding("src/handler.js", 5) });
        ss.findings.push(RawFinding { message: Some("Possible command injection via exec".into()), severity: Some("error".into()), ..finding("src/handler.js", 5) });
        input.semantic_sast = Some(ss);
        let issues = collect_phase4_issues(&input);
        assert_eq!(issues.len(), 2);
        assert_ne!(issues[0].id, issues[1].id);
    }

    /// The overwhelming common case — one finding per file:line — must
    /// keep the plain `category::file::line` id unchanged: only an actual
    /// collision should ever cause an id to grow a discriminator suffix,
    /// or every existing `.ignite/acknowledgments.md` override pinned to
    /// the old id format would silently stop matching.
    #[test]
    fn a_lone_finding_on_its_line_keeps_the_plain_id() {
        let mut input = Phase4Inputs::default();
        let mut ss = CheckResult::default();
        ss.findings.push(RawFinding { message: Some("Possible command injection via exec".into()), severity: Some("error".into()), ..finding("src/handler.js", 5) });
        input.semantic_sast = Some(ss);
        let issues = collect_phase4_issues(&input);
        assert_eq!(issues[0].id, "semantic-sast::src/handler.js::5");
    }

    #[test]
    fn codebase_intelligence_kind_maps_to_the_right_category() {
        let mut input = Phase4Inputs::default();
        let mut dead_code = CheckResult::default();
        dead_code.findings.push(RawFinding { kind: Some("unused-file".into()), message: Some("never imported".into()), ..finding("src/orphan.js", 1) });
        input.dead_code = Some(dead_code);
        let mut health = CheckResult::default();
        health.findings.push(RawFinding { kind: Some("high-complexity".into()), message: Some("too complex".into()), ..finding("src/big.js", 1) });
        input.health = Some(health);
        let issues = collect_phase4_issues(&input);
        assert_eq!(issues.iter().find(|i| i.file.as_deref() == Some("src/orphan.js")).unwrap().category, "dead-code");
        assert_eq!(issues.iter().find(|i| i.file.as_deref() == Some("src/big.js")).unwrap().category, "complexity-health");
        assert!(issues.iter().all(|i| i.severity == Severity::Warning));
    }

    #[test]
    fn checkov_secrets_framework_findings_land_in_secret_not_iac_security() {
        let mut input = Phase4Inputs::default();
        let mut iac = CheckResult::default();
        iac.findings.push(RawFinding {
            kind: Some("ckv_secret_6".into()),
            message: Some("Base64 High Entropy String".into()),
            tool: Some("checkov".into()),
            severity: Some("medium".into()),
            ..finding("parla/app/apphosting.yaml", 3)
        });
        input.iac = Some(iac);
        let issues = collect_phase4_issues(&input);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].category, "secret", "a CKV_SECRET_* finding must not land under iac-security");
        assert_eq!(issues[0].severity, Severity::Error);
        assert_eq!(issues[0].tool.as_deref(), Some("checkov"));
        assert!(issues[0].summary.contains("Base64 High Entropy String"));
    }

    #[test]
    fn checkov_iac_misconfig_findings_still_land_in_iac_security() {
        let mut input = Phase4Inputs::default();
        let mut iac = CheckResult::default();
        iac.findings.push(RawFinding {
            kind: Some("ckv_docker_2".into()),
            message: Some("Ensure that HEALTHCHECK instructions have been added".into()),
            tool: Some("checkov".into()),
            severity: Some("high".into()),
            ..finding("Dockerfile", 1)
        });
        input.iac = Some(iac);
        let issues = collect_phase4_issues(&input);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].category, "iac-security");
    }

    #[test]
    fn ignite_ignore_finding_is_always_blocking() {
        let mut input = Phase4Inputs::default();
        let mut ii = CheckResult::default();
        ii.findings.push(RawFinding { message: Some("not committed".into()), ..finding(".igniteignore", 1) });
        input.ignite_ignore = Some(ii);
        let issues = collect_phase4_issues(&input);
        assert_eq!(issues[0].category, "igniteignore-not-committed");
        assert_eq!(issues[0].severity, Severity::Error);
    }

    #[test]
    fn a_failed_codeql_language_becomes_a_blocking_issue_not_a_silent_pass() {
        let codeql = CodeqlResult { findings: vec![], failed_languages: vec![("java".to_string(), "autobuild.sh exited 1".to_string())], query_suite_review_overdue: false };
        let issues = collect_codeql_issues(&codeql);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].category, "codeql-analysis-failed");
        assert_eq!(issues[0].severity, Severity::Error);
        assert!(issues[0].summary.contains("java"));
        assert!(issues[0].summary.contains("autobuild.sh exited 1"));
    }

    #[test]
    fn an_overdue_query_suite_review_becomes_a_blocking_issue() {
        let codeql = CodeqlResult { findings: vec![], failed_languages: vec![], query_suite_review_overdue: true };
        let issues = collect_codeql_issues(&codeql);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].category, "codeql-query-suite-stale");
        assert_eq!(issues[0].severity, Severity::Error);
    }

    #[test]
    fn no_stale_pin_issue_when_review_is_current() {
        let codeql = CodeqlResult { findings: vec![], failed_languages: vec![], query_suite_review_overdue: false };
        assert!(collect_codeql_issues(&codeql).is_empty());
    }

    #[test]
    fn validate_overrides_blocks_on_unjustified_errors_and_applies_matched_ones() {
        let mut input = Phase4Inputs::default();
        input.secrets.findings.push(RawFinding { kind: Some("api-key".into()), ..finding("src/app.js", 1) });
        let issues = collect_phase4_issues(&input);
        let issue_id = issues[0].id.clone();

        let no_overrides = validate_overrides(&issues, &[]);
        assert!(!no_overrides.ok);
        assert_eq!(no_overrides.unresolved_errors.len(), 1);

        let with_override = validate_overrides(&issues, &[SubmittedOverride { issue_id: issue_id.clone(), justification: "reviewed, it's a test fixture".into(), code: None }]);
        assert!(with_override.ok);
        assert_eq!(with_override.applied.len(), 1);

        let blank_justification = validate_overrides(&issues, &[SubmittedOverride { issue_id, justification: "   ".into(), code: None }]);
        assert!(!blank_justification.ok, "a whitespace-only justification must not count as an override");
    }

    #[test]
    fn collect_license_issues_skips_green_and_internal_tiers() {
        let manifests = vec![LicenseManifest {
            file: "package.json".into(),
            dependencies: vec![
                LicenseDependency { name: "mit-lib".into(), tier: "green".into(), reason: "MIT".into(), ..Default::default() },
                LicenseDependency { name: "gpl-lib".into(), tier: "red".into(), reason: "GPL-3.0 copyleft".into(), ..Default::default() },
            ],
        }];
        let issues = collect_license_issues(&manifests, &[]);
        assert_eq!(issues.len(), 1);
        assert!(issues[0].id.ends_with("::gpl-lib"));
        assert_eq!(issues[0].severity, Severity::Error);
    }

    #[test]
    fn collect_dependency_vulnerability_issues_uses_cwe_alias_when_present() {
        let manifests = vec![VulnManifest {
            file: "package.json".into(),
            dependencies: vec![VulnDependency {
                name: "body-parser".into(),
                version: Some("1.20.2".into()),
                line: Some(12),
                vulnerabilities: vec![VulnerabilityFinding {
                    id: Some("GHSA-qwcr-r2fm-qrc7".into()),
                    title: Some("body-parser vulnerable to DoS".into()),
                    aliases: vec!["CWE-1321".into()],
                    cvss3_score: Some(7.5),
                    severity: Some("error".into()),
                }],
                ..Default::default()
            }],
        }];
        let issues = collect_dependency_vulnerability_issues(&manifests);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].cwe, Some("CWE-1321".into()));
        assert!(issues[0].summary.contains("CVSS 7.5"));
        assert!(issues[0].id.contains("body-parser"));
        assert!(issues[0].id.contains("GHSA-qwcr-r2fm-qrc7"));
    }
}
