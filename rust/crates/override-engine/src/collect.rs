//! Turns every check's raw findings (`RawFinding`/`CodeqlFinding`/license
//! and dependency-vulnerability manifests) into the shared `Issue` shape,
//! applying the per-category severity/false-positive heuristics and the
//! CWE/OWASP tagging pass. This is the "collect" step between a check's
//! own output and the addressable issue list `validation.rs` gates on.

use crate::model::{
    BuildIssueIdArgs, CodeqlResult, CweOwaspHint, Issue, IssueReferences, LicenseFileFinding,
    LicenseManifest, Phase4Inputs, RawFinding, VulnManifest,
};
use crate::model::{build_issue_id, build_references};
use crate::scoring::{derive_cwe_owasp, disambiguate_colliding_ids, is_likely_dev_only_file, is_likely_test_file, score_for_issue};
use crate::model::Severity;
use once_cell::sync::Lazy;
use regex::Regex;

fn snippet_text(snippet: &serde_json::Value) -> String {
    snippet
        .get("lines")
        .and_then(|l| l.as_array())
        .map(|lines| {
            lines
                .iter()
                .filter_map(|l| l.get("text").and_then(|t| t.as_str()))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

static LOW_CONFIDENCE_CODEQL_KIND_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^(js/(?:tainted-format-string|log-injection|path-injection|file-system-race|incomplete-hostname-regexp|bad-tag-filter|incomplete-multi-character-sanitization|regex/missing-regexp-anchor))$").unwrap()
});
static PROJECT_ID_ONLY_CONTEXT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"project\.id").unwrap());
static TAINTED_FORMAT_OR_LOG_INJECTION_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)js/(?:tainted-format-string|log-injection)").unwrap());

/// Turns checkCodeqlCrossFile's raw findings into issue-shaped objects.
/// Factored out of collect_phase4_issues so Ignite Studio's on-demand "Run
/// CodeQL" endpoint can build just this slice without needing every other
/// check's results at hand.
pub fn collect_codeql_issues(codeql: &CodeqlResult) -> Vec<Issue> {
    let failed = codeql.failed_languages.iter().map(|(language, reason)| {
        let category = "codeql-analysis-failed";
        let summary = format!("CodeQL could not analyze {language}: {reason}");
        Issue {
            id: build_issue_id(BuildIssueIdArgs { category, file: None, line: None, discriminator: Some(language) }),
            category: category.to_string(),
            severity: Severity::Error,
            score: score_for_issue(category, Severity::Error),
            summary,
            file: None,
            line: None,
            snippet: None,
            cross_file: false,
            chain: None,
            duplicate_ref: None,
            references: IssueReferences::default(),
            cwe: None,
            owasp: None,
            tool: Some("codeql".to_string()),
        }
    });
    let stale_pin = codeql.query_suite_review_overdue.then(|| {
        let category = "codeql-query-suite-stale";
        Issue {
            id: build_issue_id(BuildIssueIdArgs { category, file: None, line: None, discriminator: None }),
            category: category.to_string(),
            severity: Severity::Error,
            score: score_for_issue(category, Severity::Error),
            summary: "CodeQL's pinned query-suite versions haven't been reviewed within their configured cadence (security.codeql.reviewCadenceDays/lastReviewedAt). Re-verify each pinned version is still current and bump lastReviewedAt.".to_string(),
            file: None,
            line: None,
            snippet: None,
            cross_file: false,
            chain: None,
            duplicate_ref: None,
            references: IssueReferences::default(),
            cwe: None,
            owasp: None,
            tool: Some("codeql".to_string()),
        }
    });
    codeql
        .findings
        .iter()
        .map(|f| {
            let category = "codeql-sast";
            let summary = f.message.clone().or_else(|| f.kind.clone()).unwrap_or_default();
            let dev_or_test_file = is_likely_test_file(f.file.as_deref()) || is_likely_dev_only_file(f.file.as_deref());
            let kind_str = f.kind.as_deref().unwrap_or("");
            let low_confidence_kind = LOW_CONFIDENCE_CODEQL_KIND_RE.is_match(kind_str);
            let project_id_only_context = f.snippet.as_ref().map(|s| PROJECT_ID_ONLY_CONTEXT_RE.is_match(&snippet_text(s))).unwrap_or(false);
            let demote_as_likely_false_positive = (dev_or_test_file && low_confidence_kind)
                || (project_id_only_context && TAINTED_FORMAT_OR_LOG_INJECTION_RE.is_match(kind_str));
            let severity = if f.severity.as_deref() == Some("error") && !demote_as_likely_false_positive {
                Severity::Error
            } else {
                Severity::Warning
            };
            let id = build_issue_id(BuildIssueIdArgs {
                category,
                file: f.file.as_deref(),
                line: f.line,
                discriminator: f.kind.as_deref(),
            });
            let (cwe, owasp) = (f.cwe.clone(), None);
            Issue {
                id,
                category: category.to_string(),
                severity,
                score: score_for_issue(category, severity),
                summary,
                file: f.file.clone(),
                line: f.line,
                snippet: f.snippet.clone(),
                cross_file: f.cross_file,
                chain: f.chain.clone(),
                duplicate_ref: None,
                // Same generic "feed kind through in case it's ever a real
                // advisory id" as push_simple below — harmless no-op today
                // (CodeQL's `kind` is a query rule id like `js/sql-
                // injection`, never CVE/GHSA-shaped), kept consistent so a
                // future CodeQL query that does tag a real CVE isn't
                // silently dropped.
                references: build_references(cwe.iter().chain(f.kind.iter())),
                cwe,
                owasp,
                tool: Some("codeql".to_string()),
            }
        })
        .chain(failed)
        .chain(stale_pin)
        .collect()
}

static CREDENTIAL_TEXT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)hardcoded|credential|api[ _-]?key|password|secret|token").unwrap());
static COMMAND_INJECTION_OR_HTTP_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)command injection|unencrypted request over http").unwrap());
static INSECURE_DEV_HTTP_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)missing secure http server configuration|usage of insecure http connection").unwrap());
static TEST_FIXTURE_SECRET_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)hard-coded secret").unwrap());
static NO_TAINT_OS_COMMAND_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)unsanitized dynamic input in os command").unwrap());
static DEV_TOOLING_MANUAL_SANITIZER_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)manual html sanitization").unwrap());

fn push_simple(
    issues: &mut Vec<Issue>,
    category: &str,
    severity: Severity,
    summary: String,
    f: &RawFinding,
    discriminator: Option<&str>,
) {
    issues.push(Issue {
        id: build_issue_id(BuildIssueIdArgs { category, file: f.file.as_deref(), line: f.line, discriminator }),
        category: category.to_string(),
        severity,
        score: score_for_issue(category, severity),
        summary,
        file: f.file.clone(),
        line: f.line,
        snippet: f.code.clone(),
        cross_file: false,
        chain: None,
        duplicate_ref: f.duplicate_ref.clone(),
        // `f.kind` is usually just a short machine label (a rule/check id),
        // but for a handful of checks (container-image-cve's Trivy
        // VulnerabilityID, most notably) it's the tool's own real
        // CVE/GHSA/PYSEC/RUSTSEC/GO- advisory id — `build_references`
        // already silently drops anything without one of those exact
        // prefixes, so feeding `kind` through it here is a no-op for every
        // other category and free CVE association for the ones that do
        // carry one, with no per-category special-casing needed.
        references: build_references(f.cwe.iter().chain(f.kind.iter())),
        cwe: f.cwe.clone(),
        owasp: f.owasp.clone(),
        tool: f.tool.clone(),
    });
}

fn message_or_kind(f: &RawFinding) -> String {
    f.message.clone().or_else(|| f.kind.clone()).unwrap_or_default()
}

pub fn collect_phase4_issues(input: &Phase4Inputs) -> Vec<Issue> {
    let mut issues = Vec::new();

    for f in &input.secrets.findings {
        let in_test_file = is_likely_test_file(f.file.as_deref());
        let severity = if in_test_file { Severity::Warning } else { Severity::Error };
        let kind = f.kind.as_deref().unwrap_or("");
        let summary = format!(
            "Hardcoded {kind}{}",
            if in_test_file { " (in a test file — likely a fixture, not a real credential)" } else { "" }
        );
        push_simple(&mut issues, "secret", severity, summary, f, None);
    }

    for f in &input.governance.findings {
        let severity = Severity::Error;
        let summary = format!("Ungoverned AI invocation (missing recursion_limit): {}", f.raw_snippet_text.as_deref().unwrap_or(""));
        push_simple(&mut issues, "ai-governance", severity, summary, f, None);
    }

    if let Some(iac) = &input.iac {
        for f in &iac.findings {
            // Checkov runs its default frameworks with no `--framework`
            // filter, which per checkov's own docs includes its bundled
            // `secrets` (detect-secrets-based) scanner alongside IaC
            // misconfig checks — CKV_SECRET_* check ids. Route those into
            // the same `secret` category gitleaks/regex findings use
            // instead of `iac-security`, so a real secret checkov finds
            // isn't hidden from secret-focused triage/overrides under an
            // unrelated category.
            if f.kind.as_deref().unwrap_or("").to_lowercase().starts_with("ckv_secret") {
                let in_test_file = is_likely_test_file(f.file.as_deref());
                let severity = if in_test_file { Severity::Warning } else { Severity::Error };
                let summary = format!(
                    "{}{}",
                    message_or_kind(f),
                    if in_test_file { " (in a test file — likely a fixture, not a real credential)" } else { "" }
                );
                push_simple(&mut issues, "secret", severity, summary, f, None);
                continue;
            }
            let sev = f.severity.as_deref();
            let severity = if sev == Some("critical") || sev == Some("high") { Severity::Error } else { Severity::Warning };
            let mut summary = message_or_kind(f);
            if f.tool.as_deref() == Some("ignite-fallback") {
                summary.push_str(" (built-in fallback check — trivy not installed)");
            }
            push_simple(&mut issues, "iac-security", severity, summary, f, None);
        }
    }

    if let Some(gha) = &input.gha_security {
        for f in &gha.findings {
            let severity = if f.severity.as_deref() == Some("error") { Severity::Error } else { Severity::Warning };
            push_simple(&mut issues, "gha-security", severity, message_or_kind(f), f, None);
        }
    }

    if let Some(iv) = &input.image_vulnerabilities {
        for f in &iv.findings {
            let sev = f.severity.as_deref();
            let severity = if sev == Some("critical") || sev == Some("high") { Severity::Error } else { Severity::Warning };
            // f.kind is the VulnerabilityID — combined with the package name
            // it uniquely identifies this finding even though every
            // whole-image CVE shares the same file:line.
            let discriminator = match (&f.pkg_name, &f.kind) {
                (Some(pkg), Some(kind)) => Some(format!("{kind}@{pkg}")),
                _ => f.kind.clone(),
            };
            push_simple(&mut issues, "container-image-cve", severity, message_or_kind(f), f, discriminator.as_deref());
        }
    }

    if let Some(ip) = &input.image_provenance {
        for f in &ip.findings {
            push_simple(&mut issues, "image-provenance", Severity::Warning, message_or_kind(f), f, None);
        }
    }

    if let Some(ss) = &input.semantic_sast {
        for f in &ss.findings {
            let summary = message_or_kind(f);
            let dev_or_test_file = is_likely_test_file(f.file.as_deref()) || is_likely_dev_only_file(f.file.as_deref());
            let no_taint_rule_on_dev_tooling = dev_or_test_file && COMMAND_INJECTION_OR_HTTP_RE.is_match(&summary);
            let severity = if f.severity.as_deref() == Some("error") && !no_taint_rule_on_dev_tooling { Severity::Error } else { Severity::Warning };
            push_simple(&mut issues, "semantic-sast", severity, summary, f, None);
        }
    }

    if let Some(pdf) = &input.pii_data_flow {
        for f in &pdf.findings {
            let summary = message_or_kind(f);
            let dev_or_test_file = is_likely_test_file(f.file.as_deref()) || is_likely_dev_only_file(f.file.as_deref());
            let insecure_dev_http = dev_or_test_file && INSECURE_DEV_HTTP_RE.is_match(&summary);
            let test_fixture_secret = dev_or_test_file && TEST_FIXTURE_SECRET_RE.is_match(&summary);
            let no_taint_os_command = dev_or_test_file && NO_TAINT_OS_COMMAND_RE.is_match(&summary);
            let dev_tooling_manual_sanitizer = dev_or_test_file && DEV_TOOLING_MANUAL_SANITIZER_RE.is_match(&summary);
            let severity = if f.severity.as_deref() == Some("error")
                && !insecure_dev_http
                && !test_fixture_secret
                && !no_taint_os_command
                && !dev_tooling_manual_sanitizer
            {
                Severity::Error
            } else {
                Severity::Warning
            };
            push_simple(&mut issues, "pii-dataflow", severity, summary, f, None);
        }
    }

    if let Some(dup) = &input.duplication {
        for f in &dup.findings {
            push_simple(&mut issues, "code-duplication", Severity::Warning, message_or_kind(f), f, None);
        }
    }

    if let Some(fe) = &input.file_encapsulation {
        for f in &fe.findings {
            push_simple(&mut issues, "code-structure", Severity::Warning, message_or_kind(f), f, None);
        }
    }

    if let Some(a) = &input.api_schema {
        for f in &a.findings {
            let severity = if f.severity.as_deref() == Some("error") { Severity::Error } else { Severity::Warning };
            push_simple(&mut issues, "api-schema-lint", severity, message_or_kind(f), f, None);
        }
    }

    if let Some(ad) = &input.api_schema_drift {
        for f in &ad.findings {
            let severity = if f.severity.as_deref() == Some("error") { Severity::Error } else { Severity::Warning };
            push_simple(&mut issues, "api-breaking-change", severity, message_or_kind(f), f, f.kind.as_deref());
        }
    }

    if let Some(md) = &input.malicious_dependencies {
        for f in &md.findings {
            push_simple(&mut issues, "malicious-dependency", Severity::Error, message_or_kind(f), f, None);
        }
    }

    if let Some(mas) = &input.model_artifact_security {
        for f in &mas.findings {
            push_simple(&mut issues, "malicious-model-artifact", Severity::Error, message_or_kind(f), f, None);
        }
    }

    if let Some(ph) = &input.package_hallucination {
        for f in &ph.findings {
            push_simple(&mut issues, "package-hallucination", Severity::Warning, message_or_kind(f), f, f.message.as_deref());
        }
    }

    if let Some(codeql) = &input.codeql {
        issues.extend(collect_codeql_issues(codeql));
    }

    if let Some(llm) = &input.llm {
        if llm.available {
            for f in &llm.findings {
                let category = f.category.clone();
                let looks_like_credential = category == "security" && CREDENTIAL_TEXT_RE.is_match(f.issue.as_deref().unwrap_or(""));
                let in_test_file = looks_like_credential && is_likely_test_file(f.file.as_deref());
                let severity = if f.level.as_deref() == Some("error") && !in_test_file { Severity::Error } else { Severity::Warning };
                let mut summary = f.issue.clone().unwrap_or_default();
                if let Some(rec) = &f.recommendation {
                    summary.push_str(&format!(" | fix: {rec}"));
                }
                if in_test_file {
                    summary.push_str(" (in a test file — likely a fixture, not a real credential)");
                }
                issues.push(Issue {
                    id: build_issue_id(BuildIssueIdArgs { category: &category, file: f.file.as_deref(), line: f.line, discriminator: None }),
                    category: category.clone(),
                    severity,
                    score: score_for_issue(&category, severity),
                    summary,
                    file: f.file.clone(),
                    line: f.line,
                    snippet: f.code.clone(),
                    cross_file: false,
                    chain: None,
                    duplicate_ref: None,
                    references: IssueReferences::default(),
                    cwe: None,
                    owasp: None,
                    tool: Some("llm-deep-scan".to_string()),
                });
            }
        }
    }

    // Built-in codebase-intelligence checks, plus the opt-in EU AI Act
    // findings group — every finding here is always advisory ('warning').
    for group in [&input.dead_code, &input.health, &input.css_dead_code, &input.boundaries, &input.eu_ai_act] {
        let Some(group) = group else { continue };
        for f in &group.findings {
            let kind = f.kind.as_deref().unwrap_or("");
            let category = match kind {
                "unused-file" | "unused-export" | "unused-dependency" | "circular-dependency" => "dead-code",
                "high-complexity" | "low-maintainability" => "complexity-health",
                "unused-css-class" => "css-dead-code",
                "boundary-violation" => "architecture-boundary",
                k if k.starts_with("ai-act-") => k,
                _ => "codebase-intelligence",
            };
            issues.push(Issue {
                id: build_issue_id(BuildIssueIdArgs { category, file: f.file.as_deref(), line: f.line, discriminator: f.kind.as_deref() }),
                category: category.to_string(),
                severity: Severity::Warning,
                score: score_for_issue(category, Severity::Warning),
                summary: f.message.clone().unwrap_or_default(),
                file: f.file.clone(),
                line: f.line,
                snippet: f.code.clone(),
                cross_file: false,
                chain: None,
                duplicate_ref: None,
                cwe: None,
                owasp: None,
                tool: f.tool.clone(),
                references: IssueReferences::default(),
            });
        }
    }

    // Unlike the codebase-intelligence group above, .igniteignore-not-
    // committed is blocking (error) — an uncommitted-but-present
    // .igniteignore is a silent scan bypass with no reviewable record.
    if let Some(ii) = &input.ignite_ignore {
        for f in &ii.findings {
            let category = "igniteignore-not-committed";
            issues.push(Issue {
                id: build_issue_id(BuildIssueIdArgs { category, file: f.file.as_deref(), line: f.line, discriminator: f.kind.as_deref() }),
                category: category.to_string(),
                severity: Severity::Error,
                score: score_for_issue(category, Severity::Error),
                summary: f.message.clone().unwrap_or_default(),
                file: f.file.clone(),
                line: f.line,
                snippet: f.code.clone(),
                cross_file: false,
                chain: None,
                duplicate_ref: None,
                cwe: None,
                owasp: None,
                tool: f.tool.clone(),
                references: IssueReferences::default(),
            });
        }
    }

    // CWE/OWASP tagging pass — runs once over every issue rather than at
    // each push site so it applies uniformly regardless of which check the
    // issue came from.
    for issue in &mut issues {
        let hint = CweOwaspHint { cwe: issue.cwe.take(), owasp: issue.owasp.take() };
        let resolved = derive_cwe_owasp(&issue.category, &issue.summary, &hint);
        issue.cwe = resolved.cwe;
        issue.owasp = resolved.owasp;
        // A category-specific push site (dependency-vulnerability, CodeQL)
        // already populated `references` with every alias it found; only
        // backfill from the singular `cwe` here for everything else, so a
        // richer multi-CWE breakdown is never clobbered by this generic pass.
        if issue.references.cwe.is_empty() {
            if let Some(cwe) = &issue.cwe {
                issue.references.cwe.push(cwe.clone());
            }
        }
    }

    disambiguate_colliding_ids(&mut issues);

    issues
}

/// Turns dependency-manifest license findings and raw LICENSE-file findings
/// into the same addressable-issue shape as `collect_phase4_issues`.
pub fn collect_license_issues(manifests: &[LicenseManifest], license_files: &[LicenseFileFinding]) -> Vec<Issue> {
    let mut issues = Vec::new();
    let category = "license-compliance";

    for manifest in manifests {
        for dep in &manifest.dependencies {
            if dep.tier == "green" || dep.tier == "internal" {
                continue;
            }
            let severity = if dep.tier == "red" { Severity::Error } else { Severity::Warning };
            let base_id = build_issue_id(BuildIssueIdArgs { category, file: Some(&manifest.file), line: None, discriminator: None });
            issues.push(Issue {
                id: format!("{base_id}::{}", dep.name),
                category: category.to_string(),
                severity,
                score: score_for_issue(category, severity),
                summary: format!(
                    "{}@{} — {}",
                    dep.name,
                    dep.version.as_deref().or(dep.version_range.as_deref()).unwrap_or("?"),
                    dep.reason
                ),
                file: Some(manifest.file.clone()),
                line: dep.line,
                snippet: None,
                cross_file: false,
                chain: None,
                duplicate_ref: None,
                cwe: None,
                owasp: None,
                tool: None,
                references: IssueReferences::default(),
            });
        }
    }

    for lf in license_files {
        let severity = if lf.tier == "red" { Severity::Error } else { Severity::Warning };
        issues.push(Issue {
            id: build_issue_id(BuildIssueIdArgs { category, file: Some(&lf.file), line: lf.line, discriminator: None }),
            category: category.to_string(),
            severity,
            score: score_for_issue(category, severity),
            summary: lf.reason.clone(),
            file: Some(lf.file.clone()),
            line: lf.line,
            snippet: None,
            cross_file: false,
            chain: None,
            duplicate_ref: None,
            cwe: None,
            owasp: None,
            tool: None,
            references: IssueReferences::default(),
        });
    }

    issues
}

static CWE_ALIAS_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^CWE-\d+$").unwrap());

/// Turns per-dependency CVE/GHSA findings into the same addressable-issue
/// shape as `collect_license_issues`.
pub fn collect_dependency_vulnerability_issues(manifests: &[VulnManifest]) -> Vec<Issue> {
    let mut issues = Vec::new();
    let category = "dependency-vulnerability";

    for manifest in manifests {
        for dep in &manifest.dependencies {
            for vuln in &dep.vulnerabilities {
                let severity = if vuln.severity.as_deref() == Some("error") { Severity::Error } else { Severity::Warning };
                let advisory_id = vuln.id.clone().or_else(|| vuln.aliases.first().cloned()).unwrap_or_else(|| "unknown-advisory".to_string());
                let cwe_alias = vuln.aliases.iter().find(|a| CWE_ALIAS_RE.is_match(a)).cloned();
                let hint = CweOwaspHint { cwe: cwe_alias, owasp: None };
                let resolved = derive_cwe_owasp(category, vuln.title.as_deref().unwrap_or(""), &hint);

                let base_id = build_issue_id(BuildIssueIdArgs { category, file: Some(&manifest.file), line: dep.line, discriminator: None });
                let mut summary = format!(
                    "{}@{} — {}",
                    dep.name,
                    dep.version.as_deref().or(dep.version_range.as_deref()).unwrap_or("?"),
                    advisory_id
                );
                if let Some(title) = &vuln.title {
                    summary.push_str(&format!(": {title}"));
                }
                if let Some(score) = vuln.cvss3_score {
                    summary.push_str(&format!(" (CVSS {score})"));
                }

                issues.push(Issue {
                    id: format!("{base_id}::{}::{}", dep.name, advisory_id),
                    category: category.to_string(),
                    severity,
                    score: score_for_issue(category, severity),
                    summary,
                    file: Some(manifest.file.clone()),
                    line: dep.line,
                    snippet: None,
                    cross_file: false,
                    chain: None,
                    duplicate_ref: None,
                    references: build_references(std::iter::once(advisory_id.as_str()).chain(vuln.aliases.iter().map(|s| s.as_str()))),
                    cwe: resolved.cwe,
                    owasp: resolved.owasp,
                    tool: Some("deps.dev".to_string()),
                });
            }
        }
    }

    issues
}
