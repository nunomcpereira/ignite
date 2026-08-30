//! Built-in complexity/maintainability health scan. Faithful port of
//! `checks/complexity-health.js`. No external tool: a regex/bracket-depth
//! pass computing cyclomatic/cognitive complexity, a Maintainability
//! Index, a CRAP score, and git-churn-weighted hotspots. Always advisory.
//!
//! Git-churn and per-file runtime-coverage lookup are pure I/O the JS
//! original performs inline (`runTool('git', ...)`, an async DB read) —
//! ported here as pre-computed inputs (`churn`, `coverage_for_file`)
//! instead, keeping this crate synchronous and independently testable; the
//! caller (once the HTTP server layer exists) is responsible for running
//! `git log --name-only` and the runtime-coverage lookup and handing the
//! results in, same data, different wiring point.

use ignite_fs_utils::{build_snippet, looks_binary, walk_files, SnippetOptions};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;

static CODE_EXT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\.(js|jsx|ts|tsx|mjs|cjs|py|go|rb|php|java|kt|cs|c|cpp|h|hpp|swift|rs|scala)$").unwrap());
// The JS original's trailing alternative is `\?(?!\.)` (a bare `?` not
// followed by `.`, to exclude optional-chaining `?.`) - the `regex` crate
// has no lookaround, so this pattern ends in a plain `\?` and
// `count_decisions` below manually drops a lone-`?` match when the next
// character is `.`. `??` still matches its own alternative first (regex's
// leftmost-first alternation order, same as JS), so it isn't
// double-counted as two bare `?`s.
static DECISION_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(if|else\s+if|for|while|case|catch|elif|except)\b|&&|\|\||\?\?|\?").unwrap());
static OPEN_BRACE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"[{(]").unwrap());
static CLOSE_BRACE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"[})]").unwrap());

fn count_decisions(line: &str) -> usize {
    let mut count = 0;
    for m in DECISION_RE.find_iter(line) {
        if m.as_str() == "?" && line[m.end()..].starts_with('.') {
            continue; // optional chaining, not a ternary
        }
        count += 1;
    }
    count
}

pub struct CyclomaticAndCognitive {
    pub cyclomatic: i64,
    pub cognitive: i64,
}

pub fn cyclomatic_and_cognitive(content: &str) -> CyclomaticAndCognitive {
    let mut cyclomatic: i64 = 1;
    let mut cognitive: i64 = 0;
    let mut depth: i64 = 0;
    for line in content.split(['\n']).flat_map(|l| l.strip_suffix('\r').or(Some(l))) {
        let decisions = count_decisions(line) as i64;
        cyclomatic += decisions;
        cognitive += decisions * (1 + depth);
        let opens = OPEN_BRACE_RE.find_iter(line).count() as i64;
        let closes = CLOSE_BRACE_RE.find_iter(line).count() as i64;
        depth = (depth + opens - closes).max(0);
    }
    CyclomaticAndCognitive { cyclomatic, cognitive }
}

/// Ignite's own JS/TS-friendly adaptation (no Halstead Volume without a
/// real parser): `100 - 8*ln(cyclomatic+1) - 6*ln(loc+1)`, clamped to
/// [0,100]. This is the coefficient set actually used in the JS source —
/// its doc comment describes an earlier, different formula
/// (`5.2*ln(density+1) - 0.23*cyclomatic - 16.2*ln(loc+1)`) that the code
/// itself doesn't implement; ported to match the real function, not the
/// stale comment above it.
pub fn maintainability_index(cyclomatic: i64, loc: i64) -> i64 {
    let raw = 100.0 - 8.0 * ((cyclomatic + 1) as f64).ln() - 6.0 * ((loc + 1) as f64).ln();
    raw.round().clamp(0.0, 100.0) as i64
}

pub fn crap_score(cyclomatic: i64, coverage_pct: Option<f64>) -> i64 {
    let cov = coverage_pct.unwrap_or(0.0).clamp(0.0, 100.0) / 100.0;
    (((cyclomatic * cyclomatic) as f64) * (1.0 - cov).powi(3) + cyclomatic as f64).round() as i64
}

/// Parses `git log --name-only --pretty=format: -- .` output into a
/// per-relative-path commit-touch count.
pub fn parse_git_churn(log_output: &str) -> HashMap<String, u64> {
    let mut churn = HashMap::new();
    for line in log_output.split('\n') {
        let f = line.trim();
        if f.is_empty() {
            continue;
        }
        *churn.entry(f.to_string()).or_insert(0) += 1;
    }
    churn
}

#[derive(Debug, Clone, Serialize)]
pub struct ComplexityFinding {
    pub file: String,
    pub line: usize,
    pub kind: &'static str,
    pub tool: &'static str,
    pub severity: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<ignite_fs_utils::Snippet>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HotspotEntry {
    pub file: String,
    pub hotspot: i64,
    pub cyclomatic: i64,
    pub cognitive: i64,
    pub mi: i64,
    pub crap: i64,
    pub churn_count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RefactorTarget {
    pub file: String,
    pub reason: &'static str,
    pub crap: i64,
    pub cyclomatic: i64,
    pub mi: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct HealthMetrics {
    pub file_count: usize,
    pub average_cyclomatic: i64,
    pub average_maintainability: i64,
    pub hotspots: Vec<HotspotEntry>,
    pub refactor_targets: Vec<RefactorTarget>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComplexityHealthResult {
    pub findings: Vec<ComplexityFinding>,
    pub engine: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<HealthMetrics>,
}

pub struct ComplexityHealthConfig {
    pub enabled: bool,
    pub cyclomatic_warn_threshold: i64,
    pub maintainability_warn_threshold: i64,
    pub complexity_density_warn_threshold: f64,
    pub top_hotspots: usize,
}

impl Default for ComplexityHealthConfig {
    fn default() -> Self {
        ComplexityHealthConfig {
            enabled: true,
            cyclomatic_warn_threshold: 20,
            maintainability_warn_threshold: 40,
            complexity_density_warn_threshold: 0.3,
            top_hotspots: 10,
        }
    }
}

struct FileMetrics {
    file: String,
    loc: i64,
    cyclomatic: i64,
    cognitive: i64,
    mi: i64,
    crap: i64,
    coverage: Option<f64>,
    content: String,
    hotspot: i64,
    churn_count: u64,
}

pub fn check_complexity_health(
    root: &Path,
    config: &ComplexityHealthConfig,
    churn: &HashMap<String, u64>,
    coverage_for_file: impl Fn(&str) -> Option<f64>,
) -> std::io::Result<ComplexityHealthResult> {
    if !config.enabled {
        return Ok(ComplexityHealthResult { findings: vec![], engine: "disabled", metrics: None });
    }

    let files = walk_files(root)?;
    let mut per_file: Vec<FileMetrics> = Vec::new();

    for file in &files {
        if !CODE_EXT_RE.is_match(&file.to_string_lossy()) {
            continue;
        }
        let Ok(buffer) = std::fs::read(file) else { continue };
        if looks_binary(&buffer) {
            continue;
        }
        let content = String::from_utf8_lossy(&buffer).into_owned();
        let loc = content.split(['\n']).filter(|l| !l.trim().is_empty()).count() as i64;
        if loc == 0 {
            continue;
        }
        let CyclomaticAndCognitive { cyclomatic, cognitive } = cyclomatic_and_cognitive(&content);
        let mi = maintainability_index(cyclomatic, loc);
        let rel = rel_str(root, file);
        let coverage = coverage_for_file(&rel);
        let crap = crap_score(cyclomatic, coverage);
        per_file.push(FileMetrics {
            file: rel,
            loc,
            cyclomatic,
            cognitive,
            mi,
            crap,
            coverage,
            content,
            hotspot: 0,
            churn_count: 0,
        });
    }

    let max_complexity = per_file.iter().map(|f| f.cyclomatic).max().unwrap_or(1).max(1);
    let max_churn = per_file.iter().map(|f| churn.get(&f.file).copied().unwrap_or(0)).max().unwrap_or(0).max(1);
    for f in &mut per_file {
        let norm_complexity = f.cyclomatic as f64 / max_complexity as f64;
        let file_churn = churn.get(&f.file).copied().unwrap_or(0);
        let norm_churn = file_churn as f64 / max_churn as f64;
        // No real churn signal at all (fresh checkout) -> rank on
        // complexity alone rather than letting an all-zero churn column
        // zero out every hotspot score.
        f.hotspot = if max_churn > 1 || !churn.is_empty() {
            (norm_complexity * norm_churn * 100.0).round() as i64
        } else {
            (norm_complexity * 100.0).round() as i64
        };
        f.churn_count = file_churn;
    }

    let mut findings = Vec::new();
    for f in &per_file {
        let density = f.cyclomatic as f64 / f.loc as f64;
        if f.cyclomatic >= config.cyclomatic_warn_threshold && density >= config.complexity_density_warn_threshold {
            findings.push(ComplexityFinding {
                file: f.file.clone(),
                line: 1,
                kind: "high-complexity",
                tool: "ignite-built-in",
                severity: "warning",
                message: format!(
                    "Cyclomatic complexity {} (cognitive {}) — over the {} threshold past which functions become difficult to test exhaustively. CRAP score {}{}.",
                    f.cyclomatic,
                    f.cognitive,
                    config.cyclomatic_warn_threshold,
                    f.crap,
                    match f.coverage {
                        None => " (no coverage data ingested — treated as 0% for CRAP)".to_string(),
                        Some(c) => format!(" at {c}% coverage"),
                    }
                ),
                code: build_snippet(&f.content, 1, SnippetOptions::default()),
            });
        } else if f.mi < config.maintainability_warn_threshold {
            findings.push(ComplexityFinding {
                file: f.file.clone(),
                line: 1,
                kind: "low-maintainability",
                tool: "ignite-built-in",
                severity: "warning",
                message: format!(
                    "Maintainability Index {}/100 — below the {} threshold (complexity {} over {} lines of code).",
                    f.mi, config.maintainability_warn_threshold, f.cyclomatic, f.loc
                ),
                code: build_snippet(&f.content, 1, SnippetOptions::default()),
            });
        }
    }

    let mut by_hotspot: Vec<&FileMetrics> = per_file.iter().collect();
    by_hotspot.sort_by(|a, b| b.hotspot.cmp(&a.hotspot));
    let hotspots: Vec<HotspotEntry> = by_hotspot
        .iter()
        .take(config.top_hotspots)
        .map(|f| HotspotEntry {
            file: f.file.clone(),
            hotspot: f.hotspot,
            cyclomatic: f.cyclomatic,
            cognitive: f.cognitive,
            mi: f.mi,
            crap: f.crap,
            churn_count: f.churn_count,
        })
        .collect();

    let mut refactor_candidates: Vec<&FileMetrics> = per_file
        .iter()
        .filter(|f| f.cyclomatic >= config.cyclomatic_warn_threshold || f.mi < config.maintainability_warn_threshold || f.crap > 30)
        .collect();
    refactor_candidates.sort_by(|a, b| {
        let score_a = a.crap as f64 + (100 - a.mi) as f64;
        let score_b = b.crap as f64 + (100 - b.mi) as f64;
        score_b.partial_cmp(&score_a).unwrap()
    });
    let refactor_targets: Vec<RefactorTarget> = refactor_candidates
        .iter()
        .take(config.top_hotspots)
        .map(|f| RefactorTarget {
            file: f.file.clone(),
            reason: if f.crap > 30 {
                "untested-complexity"
            } else if f.cyclomatic >= config.cyclomatic_warn_threshold {
                "extract-complex-function"
            } else {
                "reduce-coupling"
            },
            crap: f.crap,
            cyclomatic: f.cyclomatic,
            mi: f.mi,
        })
        .collect();

    let file_count = per_file.len();
    let average_cyclomatic = if file_count > 0 { (per_file.iter().map(|f| f.cyclomatic).sum::<i64>() as f64 / file_count as f64).round() as i64 } else { 0 };
    let average_maintainability = if file_count > 0 { (per_file.iter().map(|f| f.mi).sum::<i64>() as f64 / file_count as f64).round() as i64 } else { 0 };

    Ok(ComplexityHealthResult {
        findings,
        engine: "built-in",
        metrics: Some(HealthMetrics {
            file_count,
            average_cyclomatic,
            average_maintainability,
            hotspots,
            refactor_targets,
        }),
    })
}

fn rel_str(root: &Path, file: &Path) -> String {
    file.strip_prefix(root).unwrap_or(file).to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn no_coverage(_rel: &str) -> Option<f64> {
        None
    }

    #[test]
    fn cyclomatic_and_cognitive_counts_branches_and_weights_by_nesting() {
        let content = "if (a) {\n  if (b) {\n    doThing();\n  }\n}\n";
        let r = cyclomatic_and_cognitive(content);
        assert_eq!(r.cyclomatic, 3); // base 1 + 2 ifs
        // outer if at depth 0 -> +1*1=1; inner if at depth 1 -> +1*2=2; total 3
        assert_eq!(r.cognitive, 3);
    }

    #[test]
    fn cyclomatic_and_cognitive_excludes_optional_chaining_but_counts_ternary() {
        let optional_chaining = "const x = obj?.prop;\n";
        let r1 = cyclomatic_and_cognitive(optional_chaining);
        assert_eq!(r1.cyclomatic, 1); // base only, ?. isn't a decision

        let ternary = "const x = a ? b : c;\n";
        let r2 = cyclomatic_and_cognitive(ternary);
        assert_eq!(r2.cyclomatic, 2); // base 1 + 1 ternary
    }

    #[test]
    fn cyclomatic_and_cognitive_double_question_mark_counts_once_not_twice() {
        let content = "const x = a ?? b;\n";
        let r = cyclomatic_and_cognitive(content);
        assert_eq!(r.cyclomatic, 2); // base 1 + 1 nullish-coalescing, not 2
    }

    #[test]
    fn maintainability_index_clamps_to_0_100_range() {
        // 100 - 8*ln(1) - 6*ln(2) = 100 - 0 - 4.159 = 95.84 -> rounds to 96,
        // not a clean 100 (there's no cyclomatic=0/loc=0 case that hits the
        // upper clamp exactly since loc is guaranteed >=1 by the caller).
        assert_eq!(maintainability_index(0, 1), 96);
        assert!(maintainability_index(200, 5000) >= 0);
    }

    #[test]
    fn crap_score_matches_formula_at_known_points() {
        assert_eq!(crap_score(10, Some(0.0)), 110); // 100*1 + 10
        assert_eq!(crap_score(10, Some(100.0)), 10); // 100*0 + 10
        assert_eq!(crap_score(10, None), 110); // no coverage treated as 0%
    }

    #[test]
    fn parse_git_churn_counts_file_touches_across_commits() {
        let log = "a.js\nb.js\n\na.js\n\na.js\nc.js\n";
        let churn = parse_git_churn(log);
        assert_eq!(churn.get("a.js"), Some(&3));
        assert_eq!(churn.get("b.js"), Some(&1));
        assert_eq!(churn.get("c.js"), Some(&1));
    }

    #[test]
    fn flags_high_complexity_file_over_threshold_and_density() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        // A short, branch-dense file: cyclomatic must clear 20 AND density
        // (cyclomatic/loc) must clear 0.3 — pack many decisions into few lines.
        let mut src = String::new();
        for i in 0..25 {
            src.push_str(&format!("if (a{i}) {{ doThing(); }}\n"));
        }
        fs::write(root.join("big.js"), &src).unwrap();

        let config = ComplexityHealthConfig::default();
        let result = check_complexity_health(root, &config, &HashMap::new(), no_coverage).unwrap();
        let high_complexity: Vec<_> = result.findings.iter().filter(|f| f.kind == "high-complexity").collect();
        assert_eq!(high_complexity.len(), 1);
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn hotspot_ranks_by_complexity_alone_when_no_churn_data() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("simple.js"), "const x = 1;\n").unwrap();
        fs::write(root.join("branchy.js"), "if (a) {}\nif (b) {}\nif (c) {}\n").unwrap();

        let config = ComplexityHealthConfig::default();
        let result = check_complexity_health(root, &config, &HashMap::new(), no_coverage).unwrap();
        let metrics = result.metrics.unwrap();
        let branchy_hotspot = metrics.hotspots.iter().find(|h| h.file == "branchy.js").unwrap();
        let simple_hotspot = metrics.hotspots.iter().find(|h| h.file == "simple.js").unwrap();
        assert!(branchy_hotspot.hotspot > simple_hotspot.hotspot);
        ignite_fs_utils::invalidate_walk_cache(root);
    }

    #[test]
    fn disabled_returns_no_findings() {
        let dir = tempdir().unwrap();
        let result = check_complexity_health(dir.path(), &ComplexityHealthConfig { enabled: false, ..Default::default() }, &HashMap::new(), no_coverage).unwrap();
        assert!(result.findings.is_empty());
        assert_eq!(result.engine, "disabled");
    }
}
