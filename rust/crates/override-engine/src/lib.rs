//! Turns the raw phase-4 check outputs (secrets / AI-governance / LLM
//! security+quality findings / ...) into a single list of addressable
//! "issues" with stable ids, and validates a set of user-submitted
//! overrides against them. Faithful port of `override-engine.js`.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
}

pub struct BuildIssueIdArgs<'a> {
    pub category: &'a str,
    pub file: Option<&'a str>,
    pub line: Option<i64>,
    pub discriminator: Option<&'a str>,
}

/// Most categories get one real finding per file+line, so
/// `category::file::line` is already a stable, unique id. A whole-image CVE
/// scan is the exception — every vulnerability is reported against the same
/// nominal Dockerfile:1 (there's no real per-CVE line to point at), so
/// without a discriminator hundreds of distinct CVEs would collapse onto
/// one id and a single blank override would silently blanket all of them,
/// present and future. The discriminator (package + CVE id) keeps each one
/// individually reviewable.
pub fn build_issue_id(args: BuildIssueIdArgs) -> String {
    let base = format!(
        "{}::{}::{}",
        args.category,
        args.file.unwrap_or("unknown"),
        args.line.unwrap_or(0)
    );
    match args.discriminator {
        Some(d) => format!("{base}::{d}"),
        None => base,
    }
}

// A "secret" living under a test directory/filename (test/, tests/,
// __tests__/, spec/, *.test.js, *_test.py, *.spec.ts, ...) is far more
// likely to be a fixture/fake credential than a real leaked one.
static TEST_PATH_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(^|/)(tests?|__tests__|specs?|test-support|test-fixtures|fixtures)(/|$)|[._-](test|spec|fixtures?)s?\.[^/.]+$").unwrap()
});
pub fn is_likely_test_file(file: Option<&str>) -> bool {
    let normalized = file.unwrap_or("").replace('\\', "/");
    TEST_PATH_RE.is_match(&normalized)
}

static DEV_ONLY_PATH_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(^|/)(scripts|e2e|\.devcontainer|tools|tooling|infra|ops|deploy|deployment)(/|$)|(?:^|/)(?:serve-dev|serve-spa|deploy(?:-[\w-]+)?)\.(?:m?js|ts)$").unwrap()
});
pub fn is_likely_dev_only_file(file: Option<&str>) -> bool {
    let normalized = file.unwrap_or("").replace('\\', "/");
    DEV_ONLY_PATH_RE.is_match(&normalized)
}

/// Fixed 0-10 severity score per category, independent of the
/// blocking/warning (error/warning) status — the latter drives override
/// gating, this drives "how bad is this really" for triage.
fn category_scores() -> &'static HashMap<&'static str, i32> {
    static SCORES: Lazy<HashMap<&'static str, i32>> = Lazy::new(|| {
        [
            ("secret", 10), ("ai-governance", 7), ("security", 8), ("dependency", 7),
            ("encapsulation", 3), ("quality", 2), ("structure-audit", 8), ("gxp-documents", 5),
            ("governance-ci", 7), ("input-validation", 4), ("security-scan", 6),
            ("license-compliance", 6), ("iac-security", 6), ("container-image-cve", 8), ("gha-security", 8),
            ("image-provenance", 4), ("semantic-sast", 7), ("pii-dataflow", 7),
            ("code-duplication", 2), ("code-structure", 2), ("api-schema-lint", 4),
            ("api-breaking-change", 6), ("dependency-vulnerability", 8),
            ("malicious-dependency", 9), ("malicious-model-artifact", 10),
            ("package-hallucination", 5), ("codeql-sast", 8), ("codeql-analysis-failed", 8), ("codeql-query-suite-stale", 6),
            ("ai-act-prohibited-practice", 6), ("ai-act-transparency-disclosure", 4),
            ("ai-act-ai-logging", 4), ("ai-act-compliance-documents", 3),
        ]
        .into_iter()
        .collect()
    });
    &SCORES
}

/// Warning-level findings in an otherwise error-scored category (e.g. an
/// LLM 'security' finding demoted to warning) score at half the category's
/// base, floored at 1 so nothing flagged reads as a 0.
pub fn score_for_issue(category: &str, severity: Severity) -> i32 {
    let base = category_scores()
        .get(category)
        .copied()
        .unwrap_or(if severity == Severity::Error { 7 } else { 3 });
    if severity == Severity::Warning {
        ((base as f64) / 2.0).round().max(1.0) as i32
    } else {
        base
    }
}

#[derive(Debug, Clone, Default)]
pub struct CweOwaspHint {
    pub cwe: Option<String>,
    pub owasp: Option<String>,
}

fn category_cwe_owasp() -> &'static HashMap<&'static str, CweOwaspHint> {
    static MAP: Lazy<HashMap<&'static str, CweOwaspHint>> = Lazy::new(|| {
        let e = |cwe: &str, owasp: Option<&str>| CweOwaspHint { cwe: Some(cwe.to_string()), owasp: owasp.map(str::to_string) };
        [
            ("secret", e("CWE-798", Some("A07:2021 - Identification and Authentication Failures"))),
            ("ai-governance", e("CWE-400", Some("A04:2021 - Insecure Design"))),
            ("iac-security", e("CWE-16", Some("A05:2021 - Security Misconfiguration"))),
            ("gha-security", e("CWE-829", Some("A08:2021 - Software and Data Integrity Failures"))),
            ("container-image-cve", e("CWE-1104", Some("A06:2021 - Vulnerable and Outdated Components"))),
            ("image-provenance", e("CWE-345", Some("A08:2021 - Software and Data Integrity Failures"))),
            ("pii-dataflow", e("CWE-359", None)),
            ("malicious-dependency", e("CWE-506", Some("A08:2021 - Software and Data Integrity Failures"))),
            ("malicious-model-artifact", e("CWE-502", Some("A08:2021 - Software and Data Integrity Failures"))),
            ("dependency-vulnerability", e("CWE-1104", Some("A06:2021 - Vulnerable and Outdated Components"))),
            ("structure-audit", e("CWE-540", Some("A05:2021 - Security Misconfiguration"))),
        ]
        .into_iter()
        .collect()
    });
    &MAP
}

/// Applied to free-text summaries (LLM deep-scan findings, which carry no
/// structured CWE of their own) — first pattern to match wins, ordered
/// roughly by specificity.
static TEXT_CWE_OWASP_PATTERNS: Lazy<Vec<(Regex, &'static str, &'static str)>> = Lazy::new(|| {
    vec![
        (Regex::new(r"(?i)sql\s*injection").unwrap(), "CWE-89", "A03:2021 - Injection"),
        (Regex::new(r"(?i)\bxss\b|cross[- ]site\s*script").unwrap(), "CWE-79", "A03:2021 - Injection"),
        (Regex::new(r"(?i)\bssrf\b|server[- ]side\s*request\s*forgery").unwrap(), "CWE-918", "A10:2021 - Server-Side Request Forgery"),
        (Regex::new(r"(?i)path\s*traversal|directory\s*traversal").unwrap(), "CWE-22", "A01:2021 - Broken Access Control"),
        (Regex::new(r"(?i)command\s*injection|\bos\s*command\b").unwrap(), "CWE-78", "A03:2021 - Injection"),
        (Regex::new(r"(?i)template\s*injection").unwrap(), "CWE-1336", "A03:2021 - Injection"),
        (Regex::new(r"(?i)insecure\s*deserializ").unwrap(), "CWE-502", "A08:2021 - Software and Data Integrity Failures"),
        (Regex::new(r"(?i)prototype\s*pollution").unwrap(), "CWE-1321", "A03:2021 - Injection"),
        (Regex::new(r"(?i)weak\s*crypto|broken\s*crypto|insecure\s*random|hardcoded\s*(iv|key)|\becb\s*mode\b").unwrap(), "CWE-327", "A02:2021 - Cryptographic Failures"),
        (Regex::new(r"(?i)hardcoded\s*(password|credential|secret|api[ _-]?key|token)").unwrap(), "CWE-798", "A07:2021 - Identification and Authentication Failures"),
        (Regex::new(r"(?i)\beval\(|unsafe\s*eval|dangerous\s*function").unwrap(), "CWE-95", "A03:2021 - Injection"),
        (Regex::new(r"(?i)broken\s*auth|missing\s*auth|authoriz|access\s*control|\bidor\b").unwrap(), "CWE-284", "A01:2021 - Broken Access Control"),
        (Regex::new(r"(?i)insecure\s*temp(orary)?\s*file").unwrap(), "CWE-377", "A01:2021 - Broken Access Control"),
        (Regex::new(r"(?i)missing\s*input\s*validation|unvalidated\s*input").unwrap(), "CWE-20", "A03:2021 - Injection"),
    ]
});

fn infer_cwe_owasp_from_text(text: &str) -> Option<CweOwaspHint> {
    for (re, cwe, owasp) in TEXT_CWE_OWASP_PATTERNS.iter() {
        if re.is_match(text) {
            return Some(CweOwaspHint { cwe: Some(cwe.to_string()), owasp: Some(owasp.to_string()) });
        }
    }
    None
}

/// Three-tier precedence: (1) explicit per-finding data a tool already
/// reports, (2) a keyword match against the finding's own summary text,
/// (3) a fixed category-level fallback.
pub fn derive_cwe_owasp(category: &str, summary: &str, explicit: &CweOwaspHint) -> CweOwaspHint {
    if explicit.cwe.is_some() || explicit.owasp.is_some() {
        return explicit.clone();
    }
    if let Some(inferred) = infer_cwe_owasp_from_text(summary) {
        return inferred;
    }
    category_cwe_owasp().get(category).cloned().unwrap_or_default()
}

/// Every distinct advisory/weakness identifier that applies to one issue,
/// grouped by database — a single dependency-vulnerability advisory
/// routinely carries more than one of each (an OSV record's `aliases` list
/// can hold several CVE ids and several CWE tags at once, plus its own id
/// cross-referenced under another ecosystem's database), so a single
/// `cwe`/`owasp` string can't represent it. The advisory-id buckets are
/// split per ecosystem database (PyPI's PYSEC, Cargo's RUSTSEC, Go's GO-,
/// and GHSA for everything else, npm/Maven included) since a reviewer
/// looks each one up on a different site.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IssueReferences {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cve: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cwe: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pysec: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rustsec: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub go: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ghsa: Vec<String>,
}

impl IssueReferences {
    pub fn is_empty(&self) -> bool {
        self.cve.is_empty() && self.cwe.is_empty() && self.pysec.is_empty() && self.rustsec.is_empty() && self.go.is_empty() && self.ghsa.is_empty()
    }
}

/// Sorts every id (a primary advisory id plus its OSV `aliases`, in any
/// order/mix) into the right `IssueReferences` bucket by its own prefix —
/// the one piece of the id that's a reliable database signal across every
/// ecosystem deps.dev aggregates. Dedupes and drops anything unrecognized
/// (a bare "GHSA"-less internal id, etc.) rather than inventing a bucket
/// for it.
pub fn build_references<S: AsRef<str>>(ids: impl IntoIterator<Item = S>) -> IssueReferences {
    let mut refs = IssueReferences::default();
    for raw in ids {
        let id = raw.as_ref().trim();
        if id.is_empty() {
            continue;
        }
        let upper = id.to_ascii_uppercase();
        let bucket = if upper.starts_with("CVE-") {
            &mut refs.cve
        } else if upper.starts_with("CWE-") {
            &mut refs.cwe
        } else if upper.starts_with("PYSEC-") {
            &mut refs.pysec
        } else if upper.starts_with("RUSTSEC-") {
            &mut refs.rustsec
        } else if upper.starts_with("GHSA-") {
            &mut refs.ghsa
        } else if upper.starts_with("GO-") {
            &mut refs.go
        } else {
            continue;
        };
        if !bucket.iter().any(|existing| existing == id) {
            bucket.push(id.to_string());
        }
    }
    refs
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Issue {
    pub id: String,
    pub category: String,
    pub severity: Severity,
    pub score: i32,
    pub summary: String,
    pub file: Option<String>,
    pub line: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub cross_file: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duplicate_ref: Option<serde_json::Value>,
    pub cwe: Option<String>,
    pub owasp: Option<String>,
    /// The scanner/tool that actually produced this finding (e.g. "trivy",
    /// "semgrep", "bearer", "codeql", "deps.dev") — surfaced so a reviewer
    /// looking at one finding in isolation (Studio, SARIF, an override
    /// justification) knows which engine to trust/re-run, not just which
    /// category it landed in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Structured, multi-valued breakdown of `cwe`/`owasp` above (kept for
    /// backward compat) plus every CVE/PySec/RustSec/Go/GHSA id that
    /// applies — see `IssueReferences`.
    #[serde(skip_serializing_if = "IssueReferences::is_empty")]
    pub references: IssueReferences,
}

/// One shape covers every check's raw finding here (mirrors the loosely-
/// typed JS finding objects) — the individual check modules aren't ported
/// yet, so this is override-engine's own contract for "whatever a check
/// hands it", not meant to be each check's eventual richer native type.
#[derive(Debug, Clone, Default)]
pub struct RawFinding {
    pub file: Option<String>,
    pub line: Option<i64>,
    /// `f.kind` in the JS original — a short machine-ish label; used as a
    /// message fallback for most categories, and directly (e.g. "Hardcoded
    /// {kind}") for secrets.
    pub kind: Option<String>,
    pub tool: Option<String>,
    /// "error" | "warning" | "critical" | "high" | ... — interpreted
    /// per-category, matching the JS `f.severity === 'critical' || ...`
    /// checks scattered through collect_phase4_issues.
    pub severity: Option<String>,
    pub message: Option<String>,
    /// governance's raw matched-line text (`f.snippet` in JS) — distinct
    /// from `code` below, which is the buildSnippet context block that
    /// becomes the Issue's own `snippet` field.
    pub raw_snippet_text: Option<String>,
    pub code: Option<serde_json::Value>,
    pub cwe: Option<String>,
    pub owasp: Option<String>,
    pub pkg_name: Option<String>,
    pub duplicate_ref: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Default)]
pub struct CheckResult {
    pub findings: Vec<RawFinding>,
    pub engine: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct CodeqlFinding {
    pub file: Option<String>,
    pub line: Option<i64>,
    pub kind: Option<String>,
    pub severity: Option<String>,
    pub message: Option<String>,
    pub snippet: Option<serde_json::Value>,
    pub cross_file: bool,
    pub chain: Option<serde_json::Value>,
    pub cwe: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct CodeqlResult {
    pub findings: Vec<CodeqlFinding>,
    /// Languages whose `codeql database create`/`database analyze` failed
    /// outright (e.g. a Java autobuild dying because no build toolchain is
    /// configured for that path) — as opposed to succeeding with zero
    /// findings. Without this, a failed build and a genuinely clean scan
    /// are indistinguishable in the pipeline's own output: both read as
    /// "codeql done, 0 findings". Each failure becomes its own blocking
    /// issue below so it needs an explicit override/fix instead of quietly
    /// passing.
    pub failed_languages: Vec<(String, String)>,
    /// True when `ignite_config::is_codeql_review_overdue` says the pinned
    /// query-suite versions haven't been reviewed within their configured
    /// cadence. Previously only a non-blocking `tracing::warn!` at server
    /// startup — nothing enforced it, so "review every 90 days" could (and
    /// did, in practice) go unreviewed indefinitely. Escalated to a real,
    /// overridable Phase 4 issue so the same accountability mechanism every
    /// other check gets also applies to keeping the pin itself current.
    pub query_suite_review_overdue: bool,
}

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

#[derive(Debug, Clone, Default)]
pub struct LlmFinding {
    pub category: String,
    pub file: Option<String>,
    pub line: Option<i64>,
    pub level: Option<String>,
    pub issue: Option<String>,
    pub recommendation: Option<String>,
    pub code: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Default)]
pub struct LlmResult {
    pub available: bool,
    pub findings: Vec<LlmFinding>,
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

/// All inputs to `collect_phase4_issues` — every field but `secrets`/
/// `governance` is optional (`None` means that check didn't run, same as
/// the JS version's `if (x) { ... }` guards).
#[derive(Debug, Clone, Default)]
pub struct Phase4Inputs {
    pub secrets: CheckResult,
    pub governance: CheckResult,
    pub llm: Option<LlmResult>,
    pub iac: Option<CheckResult>,
    pub gha_security: Option<CheckResult>,
    pub image_vulnerabilities: Option<CheckResult>,
    pub image_provenance: Option<CheckResult>,
    pub semantic_sast: Option<CheckResult>,
    pub pii_data_flow: Option<CheckResult>,
    pub duplication: Option<CheckResult>,
    pub file_encapsulation: Option<CheckResult>,
    pub api_schema: Option<CheckResult>,
    pub api_schema_drift: Option<CheckResult>,
    pub malicious_dependencies: Option<CheckResult>,
    pub model_artifact_security: Option<CheckResult>,
    pub package_hallucination: Option<CheckResult>,
    pub codeql: Option<CodeqlResult>,
    /// Built-in codebase-intelligence groups — findings' `kind` decides the
    /// actual issue category (see the JS comment on this loop), so these
    /// four (plus the opt-in EU AI Act group) share one code path.
    pub dead_code: Option<CheckResult>,
    pub health: Option<CheckResult>,
    pub css_dead_code: Option<CheckResult>,
    pub boundaries: Option<CheckResult>,
    pub eu_ai_act: Option<CheckResult>,
    pub ignite_ignore: Option<CheckResult>,
}

/// Short, deterministic hex tag derived from a finding's own content — the
/// fallback discriminator for a `push_simple` call site that has no
/// natural one of its own. Without *some* discriminator, every finding a
/// check reports lands on the same `category::file::line` id whenever two
/// distinct findings happen to share a line (a linter or SAST rule firing
/// twice on one line is common), so justifying/overriding one silently
/// suppresses every other finding sharing that id too. Hashing the
/// summary text (the one thing every `push_simple` call always has) keeps
/// the same finding content stable across re-scans — same summary, same
/// id, same override still applies — while two different findings on the
/// same line get different ids.
fn content_discriminator(summary: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    summary.hash(&mut hasher);
    format!("{:08x}", hasher.finish() as u32)
}

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

/// Most `push_simple` call sites pass no discriminator, so their id is
/// just `category::file::line` — fine for the overwhelming common case of
/// one finding per file:line, but two *distinct* findings from the same
/// (or a different) check that happen to land on the same line collide
/// onto that one id. Left alone, justifying/overriding either one
/// silently suppresses the other too, since the override engine has no
/// way to tell them apart.
///
/// Fixed here, at the end of the merge, rather than by having
/// `push_simple` always append a discriminator: doing it unconditionally
/// would change the id of every single-finding-per-line issue too (the
/// overwhelming majority), breaking every existing `.ignite/
/// acknowledgments.md` override that pins an id. Only ids that actually
/// collide are touched, so a colliding pair's justification does need to
/// be re-reviewed (correct — it was silently covering two different
/// findings before), but every other id, and thus every other existing
/// override, is completely unaffected.
fn disambiguate_colliding_ids(issues: &mut [Issue]) {
    let mut counts: HashMap<String, u32> = HashMap::new();
    for issue in issues.iter() {
        *counts.entry(issue.id.clone()).or_insert(0) += 1;
    }
    for issue in issues.iter_mut() {
        if counts.get(&issue.id).copied().unwrap_or(0) > 1 {
            issue.id = format!("{}::{}", issue.id, content_discriminator(&issue.summary));
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct LicenseDependency {
    pub name: String,
    pub version: Option<String>,
    pub version_range: Option<String>,
    pub tier: String,
    pub reason: String,
    pub line: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct LicenseManifest {
    pub file: String,
    pub dependencies: Vec<LicenseDependency>,
}

#[derive(Debug, Clone, Default)]
pub struct LicenseFileFinding {
    pub file: String,
    pub line: Option<i64>,
    pub tier: String,
    pub reason: String,
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

#[derive(Debug, Clone, Default)]
pub struct VulnerabilityFinding {
    pub id: Option<String>,
    pub title: Option<String>,
    pub aliases: Vec<String>,
    pub cvss3_score: Option<f64>,
    pub severity: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct VulnDependency {
    pub name: String,
    pub version: Option<String>,
    pub version_range: Option<String>,
    pub line: Option<i64>,
    pub vulnerabilities: Vec<VulnerabilityFinding>,
}

#[derive(Debug, Clone, Default)]
pub struct VulnManifest {
    pub file: String,
    pub dependencies: Vec<VulnDependency>,
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

#[derive(Debug, Clone)]
pub struct SubmittedOverride {
    pub issue_id: String,
    pub justification: String,
}

pub struct ValidateOverridesResult<'a> {
    pub ok: bool,
    pub unresolved_errors: Vec<&'a Issue>,
    pub applied: Vec<(&'a Issue, String)>,
}

/// `ok = false` when one or more error-severity issues has no matching
/// override with a non-empty justification — the caller must still block
/// in that case.
pub fn validate_overrides<'a>(issues: &'a [Issue], overrides: &[SubmittedOverride]) -> ValidateOverridesResult<'a> {
    let mut override_map: HashMap<&str, &str> = HashMap::new();
    for o in overrides {
        let issue_id = o.issue_id.trim();
        let justification = o.justification.trim();
        if !issue_id.is_empty() && !justification.is_empty() {
            override_map.insert(issue_id, justification);
        }
    }

    let mut applied = Vec::new();
    let mut unresolved_errors = Vec::new();

    for issue in issues {
        if let Some(&justification) = override_map.get(issue.id.as_str()) {
            applied.push((issue, justification.to_string()));
        } else if issue.severity == Severity::Error {
            unresolved_errors.push(issue);
        }
    }

    ValidateOverridesResult { ok: unresolved_errors.is_empty(), unresolved_errors, applied }
}

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
        assert!(refs.is_empty() == false);
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

        let with_override = validate_overrides(&issues, &[SubmittedOverride { issue_id: issue_id.clone(), justification: "reviewed, it's a test fixture".into() }]);
        assert!(with_override.ok);
        assert_eq!(with_override.applied.len(), 1);

        let blank_justification = validate_overrides(&issues, &[SubmittedOverride { issue_id, justification: "   ".into() }]);
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
