//! Severity scoring, CWE/OWASP derivation, and the file-path heuristics
//! (test/dev-only) that several categories use to demote severity — the
//! "how bad is this, and what's it categorized as" policy layer. Consumed
//! by `collect.rs`'s finding-to-issue conversion.

use crate::model::{CweOwaspHint, Issue};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;

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
pub fn score_for_issue(category: &str, severity: crate::model::Severity) -> i32 {
    use crate::model::Severity;
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
pub(crate) fn content_discriminator(summary: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    summary.hash(&mut hasher);
    format!("{:08x}", hasher.finish() as u32)
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
pub(crate) fn disambiguate_colliding_ids(issues: &mut [Issue]) {
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
