//! The data model: issue/finding/input shapes shared by `scoring` and
//! `collect`, plus the id-building scheme they're all keyed by. No scoring
//! or collection logic lives here — see `scoring.rs`/`collect.rs`.

use serde::{Deserialize, Serialize};

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

/// The inverse slice of [`build_issue_id`]'s own format — pulls back out
/// whatever discriminator (if any) was appended after `category::file::line`,
/// so a caller that only has the finished `id` (not the original
/// `BuildIssueIdArgs`) can still compute a same-identity
/// [`stable_fingerprint`] for it. `None` for the overwhelming common case
/// (no collision, so `build_issue_id` never appended anything).
pub fn discriminator_from_issue_id(id: &str) -> Option<String> {
    let mut parts = id.splitn(4, "::");
    parts.next(); // category
    parts.next(); // file
    parts.next(); // line
    parts.next().map(str::to_string)
}

/// US-07: a version-tolerant identity for cross-scan finding tracking,
/// deliberately separate from [`build_issue_id`] — that id (and every
/// override/SARIF fingerprint/GitHub alert match keyed on it) stays
/// exactly as it was, so this is purely additive. Content-hashes
/// `category` + `file` + `discriminator` + the finding's own surrounding
/// snippet text (trimmed, blank lines dropped, so *inserting* blank lines
/// above unchanged code — the concrete acceptance-criterion case —
/// produces the same normalized text and therefore the same fingerprint)
/// instead of the raw line number, which is exactly the value line drift
/// changes. Falls back to `line` only when no snippet is available at
/// all (most Phase 3/advisory-style checks): a strictly weaker but
/// honest identity for those, not a fabricated one.
pub fn stable_fingerprint(category: &str, file: Option<&str>, snippet: Option<&serde_json::Value>, line: Option<i64>, discriminator: Option<&str>) -> String {
    use sha2::{Digest, Sha256};
    let normalized_snippet = snippet.map(|s| normalize_snippet_for_fingerprint(s));
    let mut hasher = Sha256::new();
    hasher.update(category.as_bytes());
    hasher.update(b"\0");
    hasher.update(file.unwrap_or("unknown").as_bytes());
    hasher.update(b"\0");
    hasher.update(discriminator.unwrap_or("").as_bytes());
    hasher.update(b"\0");
    match normalized_snippet.as_deref().filter(|s| !s.is_empty()) {
        Some(text) => hasher.update(text.as_bytes()),
        None => hasher.update(line.unwrap_or(0).to_string().as_bytes()),
    }
    format!("{:x}", hasher.finalize())
}

/// Same `snippet.lines[].text` shape `collect.rs`'s own `snippet_text`
/// reads, but trims each line and drops blank ones — the normalization
/// that makes a pure blank-line insertion above the matched line a no-op
/// for fingerprinting purposes, instead of shifting every subsequent
/// line's text into a different position in the joined string.
fn normalize_snippet_for_fingerprint(snippet: &serde_json::Value) -> String {
    snippet
        .get("lines")
        .and_then(|l| l.as_array())
        .map(|lines| {
            lines
                .iter()
                .filter_map(|l| l.get("text").and_then(|t| t.as_str()))
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

#[derive(Debug, Clone, Default)]
pub struct CweOwaspHint {
    pub cwe: Option<String>,
    pub owasp: Option<String>,
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
    /// `ignite-env-var-drift` — always advisory, category `config-drift`.
    pub env_var_drift: Option<CheckResult>,
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

#[derive(Debug, Clone)]
pub struct SubmittedOverride {
    pub issue_id: String,
    pub justification: String,
    pub code: Option<String>,
}

pub struct ValidateOverridesResult<'a> {
    pub ok: bool,
    pub unresolved_errors: Vec<&'a Issue>,
    pub applied: Vec<(&'a Issue, String)>,
}
